#!/usr/bin/env python3
"""
ServiceNow CMDB -> Qualys CSAM asset sync (create or update, with business info).

Sources (pick one):
  --source api                       ServiceNow Table API (cmdb_ci_server)
  --servers FILE --workstations FILE CMDB CSV exports (either or both)

Flow per CI:
  1. Map the source record to a canonical CI, normalize identity (hostname, FQDN, IPs, serial).
  2. Look up the asset in CSAM (QQL): first by sourceNativeKey (sys_id), then by identity.
     - 0 match  -> create
     - 1 match  -> update (qualysAssetId pinned, so CSAM cannot fork a duplicate)
     - 2+ match -> CONFLICT: skipped and reported, nothing is written
  3. Push through the connector sync API, which upserts using CSAM identification rules.

.env:
    QUALYS_GATEWAY=https://gateway.qg1.apps.qualys.eu
    QUALYS_USER=...
    QUALYS_PASSWORD=...
    QUALYS_CONNECTOR_UUID=...     # custom connector created in CSAM > Connectors
    SNOW_INSTANCE=https://acme.service-now.com   # --source api only
    SNOW_USER=...
    SNOW_PASSWORD=...

Usage:
    python snow_to_qualys_csam.py --servers servers.csv --workstations ws.csv          # dry-run
    python snow_to_qualys_csam.py --servers servers.csv --apply
    python snow_to_qualys_csam.py --source api --query "install_status=1" --apply
"""

import argparse
import csv
import json
import logging
import os
import re
import sys
import uuid
from logging.handlers import RotatingFileHandler
from typing import Iterator, Optional

import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger("snow2csam")
BATCH = 100   # assets per sync call

# ---------------------------------------------------------------------------
# Source -> canonical CI mapping.  canonical_field: source_column
# Canonical fields used downstream: sys_id, name, hostname, fqdn, ip, serial, status,
# environment, company, department, owned_by, managed_by, supported_by, support_group,
# location, plus anything else (kept as custom attribute).
# ---------------------------------------------------------------------------
MAP_SERVERS = {
    "sys_id": "sys_id", "name": "name", "hostname": "host_name", "ip": "ip_address",
    "serial": "serial_number", "status": "install_status", "environment": "used_for",
    "company": "company", "support_group": "support_group", "location": "location",
    "managed_by": "assignment_group", "supported_by": "support_group.manager.email",
    "os": "os", "os_domain": "os_domain", "invoice_recipient": "u_invoice_recipient",
    "dmz": "u_dmz", "hosting_zone": "hosting_zone", "internet_facing": "internet_facing",
    "to_be_decommissioned": "u_to_be_decommissioned", "security_group": "u_security_group",
    "patching_day": "u_patching_day", "patching_slot": "u_patching_slot",
}
MAP_WORKSTATIONS = {
    "sys_id": "sys_id", "name": "name", "hostname": "hostname", "status": "status",
    "department": "department", "environment": "environment", "owned_by": "owner_group",
    "managed_by": "managed_by", "supported_by": "supported_by", "support_group": "support_group",
    "company": "assigned_to.company", "invoice_recipient": "invoiced_entity",
}
MAP_API = {
    "sys_id": "sys_id", "name": "name", "hostname": "host_name", "fqdn": "fqdn", "ip": "ip_address",
    "serial": "serial_number", "status": "install_status", "environment": "used_for",
    "company": "company", "department": "department", "owned_by": "owned_by",
    "managed_by": "managed_by", "supported_by": "supported_by", "support_group": "support_group",
    "location": "location", "os": "os",
}
BUSINESS_FIELDS = {"status", "environment", "company", "department", "owned_by", "managed_by",
                   "supported_by", "support_group", "location"}
IDENTITY_FIELDS = {"sys_id", "name", "hostname", "fqdn", "ip", "serial"}


def setup_logging(path: str, verbose: bool) -> None:
    """Console at INFO (DEBUG with -v), rotating file always at DEBUG."""
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%Y-%m-%d %H:%M:%S")
    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    file = RotatingFileHandler(path, maxBytes=5_000_000, backupCount=5, encoding="utf-8")
    for h in (console, file):
        h.setFormatter(fmt)
        log.addHandler(h)
    log.setLevel(logging.DEBUG)


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
def to_canonical(row: dict, mapping: dict, kind: str) -> dict:
    ci = {k: (row.get(col) or "").strip() for k, col in mapping.items()}
    ci["kind"] = kind
    return ci


def from_csv(path: str, mapping: dict, kind: str) -> Iterator[dict]:
    with open(path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            yield to_canonical(row, mapping, kind)


def from_api(query: str) -> Iterator[dict]:
    base, auth = os.environ["SNOW_INSTANCE"].rstrip("/"), (os.environ["SNOW_USER"], os.environ["SNOW_PASSWORD"])
    offset, limit = 0, 500
    while True:
        r = requests.get(f"{base}/api/now/table/cmdb_ci_server", auth=auth, verify=False, timeout=120, params={
            "sysparm_query": query, "sysparm_fields": ",".join(MAP_API.values()),
            "sysparm_display_value": "true", "sysparm_limit": limit, "sysparm_offset": offset})
        r.raise_for_status()
        rows = r.json().get("result", [])
        for row in rows:
            yield to_canonical(row, MAP_API, "server")
        if len(rows) < limit:
            return
        offset += limit


# ---------------------------------------------------------------------------
# Qualys CSAM (gateway, JWT)
# ---------------------------------------------------------------------------
class Qualys:
    def __init__(self, gateway: str, user: str, password: str, connector_uuid: str):
        self.base, self.connector_uuid = gateway.rstrip("/"), connector_uuid
        self.s = requests.Session()
        self.s.verify = False
        r = self.s.post(f"{self.base}/auth", data={"username": user, "password": password, "token": "true"}, timeout=60)
        r.raise_for_status()
        self.s.headers.update({"Authorization": f"Bearer {r.text.strip()}", "Content-Type": "application/json"})

    def search(self, qql: str) -> list[dict]:
        r = self.s.post(f"{self.base}/rest/2.0/search/am/asset", params={"filter": qql, "pageSize": 50}, timeout=120)
        r.raise_for_status()
        return [a["asset"] for a in r.json().get("assetListData", {}).get("asset", [])]

    def sync(self, assets: list[dict]) -> dict:
        body = {"connectorMetaData": {"requestId": str(uuid.uuid4()), "assetCount": len(assets),
                                      "source": "ServiceNow CMDB", "connectorUuid": self.connector_uuid},
                "assetData": assets}
        r = self.s.post(f"{self.base}/rest/2.0/am/connector/asset/data/sync", json=body, timeout=300)
        r.raise_for_status()
        return r.json()


# ---------------------------------------------------------------------------
# Identity, reconciliation, payload
# ---------------------------------------------------------------------------
def identity(ci: dict) -> dict:
    """Identity attributes CSAM matches on. Hostname lower-cased without domain; empty values dropped."""
    host = (ci.get("hostname") or ci.get("name") or "").lower().split(".")[0]
    fqdn = (ci.get("fqdn") or "").lower()
    if not fqdn and host and ci.get("os_domain"):
        fqdn = f"{host}.{ci['os_domain'].lower()}"
    ident = {
        "sourceNativeKey": ci["sys_id"],
        "hostName": host,
        "fqdn": fqdn,
        "ipAddress": [x for x in re.split(r"[,\s;]+", ci.get("ip", "")) if x],
        "serialNumber": ci.get("serial", ""),
    }
    return {k: v for k, v in ident.items() if v}


def resolve(q: Qualys, ident: dict) -> tuple[str, Optional[str]]:
    """Return ('create'|'update'|'conflict', qualysAssetId)."""
    hits = q.search(f'sourceNativeKey:"{ident["sourceNativeKey"]}"')   # previous sync: strongest key
    if len(hits) == 1:
        return "update", str(hits[0]["assetId"])

    clauses = [f'hardware.serialNumber:"{ident["serialNumber"]}"'] if ident.get("serialNumber") else []
    clauses += [f'asset.fqdn:"{ident["fqdn"]}"'] if ident.get("fqdn") else []
    clauses += [f'asset.hostname:"{ident["hostName"]}"'] if ident.get("hostName") else []
    clauses += [f'interfaces.address:"{ip}"' for ip in ident.get("ipAddress", [])]
    if not clauses:
        return "create", None

    ids = {str(h["assetId"]) for h in q.search(" or ".join(clauses))}
    if len(ids) > 1:   # several CSAM assets share this identity: never guess
        log.warning("CONFLICT %s matches CSAM assets %s", ident, sorted(ids))
        return "conflict", None
    return ("update", ids.pop()) if ids else ("create", None)


def build_asset(ci: dict, ident: dict, qualys_id: Optional[str]) -> dict:
    ident = dict(ident, **({"qualysAssetId": qualys_id} if qualys_id else {}))
    extra = {k: v for k, v in ci.items() if k not in IDENTITY_FIELDS | BUSINESS_FIELDS and v}
    return {
        "identityAttributes": ident,
        "coreAttributes": {
            "hostName": ident.get("hostName"),
            "operatingSystem": ci.get("os") or None,
            "businessInformation": {
                "operationalStatus": ci.get("status") or None,
                "environment": ci.get("environment") or None,
                "company": ci.get("company") or None,
                "department": ci.get("department") or None,
                "ownedBy": ci.get("owned_by") or None,
                "managedBy": ci.get("managed_by") or None,
                "supportedBy": ci.get("supported_by") or None,
                "supportGroup": ci.get("support_group") or None,
            },
            "assignedLocation": {"name": ci["location"]} if ci.get("location") else None,
        },
        "customAttributes": [{"key": f"snow_{k}", "value": v} for k, v in extra.items()],
    }


# ---------------------------------------------------------------------------
def main() -> None:
    load_dotenv()
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--source", choices=["api", "csv"], default="csv")
    p.add_argument("--servers", metavar="CSV", help="CMDB server export")
    p.add_argument("--workstations", metavar="CSV", help="CMDB workstation export")
    p.add_argument("--query", default="install_status=1", help="sysparm_query (--source api)")
    p.add_argument("--apply", action="store_true", help="Write to CSAM (default: dry-run)")
    p.add_argument("--log-file", default="snow_to_qualys_csam.log")
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args()
    setup_logging(a.log_file, a.verbose)

    try:
        q = Qualys(os.environ["QUALYS_GATEWAY"], os.environ["QUALYS_USER"],
                   os.environ["QUALYS_PASSWORD"], os.environ["QUALYS_CONNECTOR_UUID"])
        if a.source == "api":
            cis = from_api(a.query)
        elif a.servers or a.workstations:
            cis = (ci for path, mp, kind in ((a.servers, MAP_SERVERS, "server"), (a.workstations, MAP_WORKSTATIONS, "workstation"))
                   if path for ci in from_csv(path, mp, kind))
        else:
            sys.exit("--source csv requires --servers and/or --workstations")
    except KeyError as k:
        sys.exit(f"Missing variable in .env: {k}")
    log.info("Mode: %s | source: %s", "APPLY" if a.apply else "DRY-RUN", a.source)

    stats = dict.fromkeys(("create", "update", "conflict", "skipped", "error"), 0)
    pending: list[dict] = []

    def flush() -> None:
        if pending and a.apply:
            try:
                resp = q.sync(pending)
                errors = resp.get("assetsError") or {}
                stats["error"] += len(errors)
                log.info("sync %d -> %s%s", len(pending), resp.get("responseCode"),
                         f" | errors: {json.dumps(errors)[:500]}" if errors else "")
            except requests.HTTPError as e:
                stats["error"] += len(pending)
                log.error("sync failed (%d assets): %s %s", len(pending), e, e.response.text[:300])
        pending.clear()

    for ci in cis:
        ident = identity(ci)
        if len(ident) < 2:   # sys_id only: nothing CSAM could match on
            stats["skipped"] += 1
            log.warning("SKIP %s (%s): no usable identity", ci.get("name"), ci["kind"])
            continue
        try:
            action, qid = resolve(q, ident)
        except requests.HTTPError as e:
            stats["error"] += 1
            log.error("lookup failed for %s: %s", ci.get("name"), e)
            continue
        stats[action] += 1
        if action == "conflict":
            continue
        asset = build_asset(ci, ident, qid)
        log.info("%-7s %-12s %-30s qualysAssetId=%s", action.upper(), ci["kind"], ci.get("name"), qid or "-")
        log.debug("payload %s", json.dumps(asset))
        pending.append(asset)
        if len(pending) >= BATCH:
            flush()
    flush()

    log.info("Done: %s", " | ".join(f"{k}={v}" for k, v in stats.items()))
    if stats["conflict"]:
        log.warning("%d CI(s) in conflict: resolve duplicates in CSAM, then re-run", stats["conflict"])


if __name__ == "__main__":
    main()