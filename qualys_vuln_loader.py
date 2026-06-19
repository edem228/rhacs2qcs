#!/usr/bin/env python3
"""
qualys_vuln_loader.py  (EN)
===========================
Takes the vulnerability data produced by qcs_vuln_extract.py (NDJSON or CSV) and
PUSHES it into the Qualys platform.

IMPORTANT — there is no "ingest" API on Qualys Container Security itself: QCS is a
scanner, it emits findings, it does not accept external ones. The Qualys ingestion
point for normalized third-party findings is the ETM connector. This loader targets
it two ways:

  * webhook  (default) -> Generic API Webhook connector:
        POST <gateway>/rest/2.0/am/connector/asset/data/sync
        payload = { connectorMetaData{requestId,assetCount,source,connectorUuid},
                    assetData[ {identityAttributes, coreAttributes, findings} ] }
        Requires a Generic API connector created in ETM (-> CONNECTOR_UUID) and the
        CSAM + ETM subscriptions.

  * s3       -> Generic CSV (AWS S3) connector:
        uploads the CSV to the S3 bucket the connector watches (needs boto3).

  * dryrun   -> builds and writes the payloads locally, sends nothing (safe test).

Each input asset (image or container) becomes one Qualys asset; each (qid, cve) row
becomes one finding. Re-runs are idempotent: hardwareUuid is derived deterministically
from the source-native key (digest / sha), so assets correlate instead of duplicating.

Dependencies: requests   (+ boto3 only for --target s3)

Environment:
    QUALYS_GATEWAY          e.g. https://gateway.qg1.apps.qualys.com
    QUALYS_USERNAME
    QUALYS_PASSWORD
    QUALYS_CONNECTOR_UUID   (webhook target)
    QUALYS_S3_BUCKET        (s3 target)         QUALYS_S3_PREFIX (optional)

Examples:
    # dry run to inspect the payload before sending anything
    python qualys_vuln_loader.py --input qcs_vulns.ndjson --target dryrun

    # push to the ETM webhook connector, 50 assets per request
    python qualys_vuln_loader.py --input qcs_vulns.ndjson \\
        --target webhook --batch-size 50

    # drop the CSV into the ETM S3 CSV connector bucket
    python qualys_vuln_loader.py --input qcs_vulns.csv --target s3
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, List, Optional

try:
    import requests
except ImportError:
    sys.exit("Missing 'requests' module: pip install requests")

LOG = logging.getLogger("qualys_loader")

ASSET_SYNC_PATH = "/rest/2.0/am/connector/asset/data/sync"
TOKEN_TTL = 3 * 60 * 60
RETRY_STATUS = {500, 502, 503, 504}
_UUID_NS = uuid.uuid5(uuid.NAMESPACE_URL, "qualys-etm-loader")

# severity label (extractor) -> Qualys numeric severity (1..5)
_SEV_NUM = {"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}


# --------------------------------------------------------------------------- #
#  Input reading                                                               #
# --------------------------------------------------------------------------- #
def read_rows(path: str) -> Iterator[dict]:
    if path.endswith(".ndjson") or path.endswith(".jsonl"):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)
    elif path.endswith(".csv"):
        with open(path, newline="", encoding="utf-8") as fh:
            yield from csv.DictReader(fh)
    else:
        raise ValueError("Unsupported input: use .ndjson / .jsonl / .csv")


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in ("true", "1", "yes")


def _sev_num(row: dict) -> int:
    raw = row.get("severity")
    try:
        n = int(raw)
        if 1 <= n <= 5:
            return n
    except (TypeError, ValueError):
        pass
    return _SEV_NUM.get(str(row.get("severity_label", "")).upper(), 3)


# --------------------------------------------------------------------------- #
#  Grouping: rows -> assets                                                    #
# --------------------------------------------------------------------------- #
def group_assets(rows: Iterable[dict]) -> Dict[str, dict]:
    """Group detection rows by asset; collect distinct findings + affected software."""
    assets: Dict[str, dict] = {}
    for row in rows:
        native_key = (row.get("image_digest") or row.get("image_sha")
                      or row.get("container_sha") or row.get("synthetic_asset_id"))
        if not native_key:
            continue
        a = assets.get(native_key)
        if a is None:
            a = assets[native_key] = {
                "native_key": native_key,
                "ctx": row,                 # first row carries the shared context
                "findings": {},             # (qid, cve) -> finding row
                "software": {},             # (name, version) -> dict
            }
        cve = (row.get("cve") or "").strip()
        qid = str(row.get("qid") or "").strip()
        fkey = (qid, cve)
        if fkey not in a["findings"]:
            a["findings"][fkey] = row
        pkg = (row.get("package_name") or "", row.get("installed_version") or "")
        if pkg[0] and pkg not in a["software"]:
            a["software"][pkg] = {"name": pkg[0], "version": pkg[1]}
    return assets


# --------------------------------------------------------------------------- #
#  Transform: asset -> Qualys CSAM/ETM schema                                  #
# --------------------------------------------------------------------------- #
def transform_asset(asset: dict) -> dict:
    ctx = asset["ctx"]
    native_key = asset["native_key"]
    hardware_uuid = str(uuid.uuid5(_UUID_NS, native_key))
    is_container = (ctx.get("source_scope") == "containers")
    hostname = ctx.get("hostname") or ctx.get("synthetic_asset_id") or native_key[:32]
    ip = ctx.get("host_ip") or ""

    identity = {
        "qualysAssetId": None,
        "sourceNativeKey": native_key,
        "netBiosName": hostname,
        "hardwareUuid": hardware_uuid,
    }
    if ip:
        identity["ipAddress"] = [ip]

    core = {
        "operatingSystem": ctx.get("operating_system") or "",
        "netBiosName": hostname,
        "isContainer": is_container,
        "softwares": [
            {"name": s["name"], "version": s["version"],
             "isSystemApp": False, "isEnterpriseApp": False}
            for s in asset["software"].values()
        ],
    }
    if ip:
        core["address"] = ip

    findings = []
    for (qid, cve), row in asset["findings"].items():
        fid = cve or f"QID-{qid}"
        finding = {
            "id": fid,
            "name": row.get("title") or cve or fid,
            "category": "VULNERABILITY",
            "severity": _sev_num(row),
            "findingStatus": ("FIXED" if _truthy(row.get("is_exempted"))
                              else "ACTIVE"),
            "findingType": {"vulnerability": {"cveId": cve} if cve
                            else {"qid": qid}},
            # extra context carried as custom attributes (ignored if unsupported)
            "customAttributes": {
                "qid": qid,
                "qdsScore": row.get("qds_score"),
                "cvss3Base": row.get("cvss3_base"),
                "exploitationState": row.get("exploitation_state"),
                "exploitAvailable": _truthy(row.get("exploit_available")),
                "epssProbability": row.get("epss_probability"),
                "epssPercentile": row.get("epss_percentile"),
                "fixedVersion": row.get("fixed_version"),
                "package": row.get("package_name"),
                "installedVersion": row.get("installed_version"),
                "firstFound": row.get("first_found"),
                "lastFound": row.get("last_found"),
                "imageDigest": ctx.get("image_digest"),
                "k8sNamespace": ctx.get("k8s_namespace"),
                "k8sPod": ctx.get("k8s_pod"),
            },
        }
        findings.append(finding)

    return {"identityAttributes": identity,
            "coreAttributes": core,
            "findings": findings}


def build_payload(batch: List[dict], connector_uuid: str, source: str) -> dict:
    return {
        "connectorMetaData": {
            "requestId": str(uuid.uuid4()),
            "assetCount": len(batch),
            "source": source,
            "connectorUuid": connector_uuid,
        },
        "assetData": batch,
    }


# --------------------------------------------------------------------------- #
#  Qualys auth + rate-limit-aware POST                                          #
# --------------------------------------------------------------------------- #
class QualysGateway:
    def __init__(self, gateway: str, username: str, password: str,
                 timeout: int = 90, max_retries: int = 5):
        self.gateway = gateway.rstrip("/")
        self._user, self._pass = username, password
        self.timeout, self.max_retries = timeout, max_retries
        self._session = requests.Session()
        self._token: Optional[str] = None
        self._token_ts = 0.0

    def _authenticate(self) -> None:
        LOG.info("Gateway authentication -> %s/auth", self.gateway)
        resp = self._session.post(
            f"{self.gateway}/auth",
            data={"username": self._user, "password": self._pass, "token": "true"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=self.timeout,
        )
        resp.raise_for_status()
        self._token = self._extract_token(resp)
        self._token_ts = time.time()

    @staticmethod
    def _extract_token(resp: requests.Response) -> str:
        txt = (resp.text or "").strip()
        try:
            j = resp.json()
            if isinstance(j, dict):
                return j.get("access_token") or j.get("token") or txt
        except ValueError:
            pass
        if not txt or txt.count(".") < 2:
            raise RuntimeError("Unexpected auth response (no JWT)")
        return txt

    def _bearer(self) -> str:
        if self._token is None or (time.time() - self._token_ts) > TOKEN_TTL:
            self._authenticate()
        return self._token  # type: ignore[return-value]

    def post_json(self, path: str, payload: dict) -> dict:
        url = f"{self.gateway}{path}"
        attempt = 0
        while True:
            attempt += 1
            headers = {"Authorization": f"Bearer {self._bearer()}",
                       "Content-Type": "application/json"}
            try:
                resp = self._session.post(url, headers=headers, json=payload,
                                          timeout=self.timeout)
            except requests.RequestException as exc:
                if attempt > self.max_retries:
                    raise
                wait = min(2 ** attempt, 30)
                LOG.warning("Network error (%s) — retry in %ss", exc, wait)
                time.sleep(wait)
                continue

            if resp.status_code == 401 and attempt <= self.max_retries:
                self._token = None
                continue
            if resp.status_code == 429:
                wait = int(resp.headers.get("X-RateLimit-ToWait-Sec",
                           resp.headers.get("Retry-After", 60)))
                LOG.warning("Rate limited — waiting %ss", wait)
                time.sleep(wait)
                continue
            if resp.status_code in RETRY_STATUS and attempt <= self.max_retries:
                wait = min(2 ** attempt, 30)
                LOG.warning("HTTP %s — retry in %ss", resp.status_code, wait)
                time.sleep(wait)
                continue

            resp.raise_for_status()
            # proactive throttle if the gateway says no calls remain
            remaining = resp.headers.get("X-RateLimit-Remaining")
            if remaining is not None and remaining.isdigit() and int(remaining) == 0:
                wait = int(resp.headers.get("X-RateLimit-ToWait-Sec", 60))
                LOG.info("No remaining calls — throttling %ss", wait)
                time.sleep(wait)
            return resp.json() if resp.content else {}


# --------------------------------------------------------------------------- #
#  Targets                                                                     #
# --------------------------------------------------------------------------- #
def _batched(items: List[dict], size: int) -> Iterator[List[dict]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


def send_webhook(assets: List[dict], args: argparse.Namespace) -> int:
    gateway = os.environ.get("QUALYS_GATEWAY", args.gateway or "")
    user = os.environ.get("QUALYS_USERNAME", "")
    pwd = os.environ.get("QUALYS_PASSWORD", "")
    conn = os.environ.get("QUALYS_CONNECTOR_UUID", args.connector_uuid or "")
    if not (gateway and user and pwd and conn):
        LOG.error("QUALYS_GATEWAY / USERNAME / PASSWORD / CONNECTOR_UUID required")
        return 2

    gw = QualysGateway(gateway, user, pwd)
    sent = batches = 0
    for batch in _batched(assets, args.batch_size):
        payload = build_payload(batch, conn, args.source_label)
        resp = gw.post_json(ASSET_SYNC_PATH, payload)
        batches += 1
        sent += len(batch)
        LOG.info("Batch %d: pushed %d assets (resp: %s)",
                 batches, len(batch), _short(resp))
    LOG.info("Done: %d assets in %d request(s)", sent, batches)
    return 0


def send_s3(input_path: str, args: argparse.Namespace) -> int:
    bucket = os.environ.get("QUALYS_S3_BUCKET", args.s3_bucket or "")
    prefix = os.environ.get("QUALYS_S3_PREFIX", args.s3_prefix or "")
    if not bucket:
        LOG.error("QUALYS_S3_BUCKET required for --target s3")
        return 2
    try:
        import boto3
    except ImportError:
        LOG.error("boto3 required for --target s3: pip install boto3")
        return 2

    # if NDJSON in, materialize a CSV first; if CSV in, upload as-is
    if input_path.endswith(".csv"):
        upload_path = input_path
    else:
        upload_path = args.out or "qcs_vulns_for_etm.csv"
        rows = list(read_rows(input_path))
        if not rows:
            LOG.warning("No rows to upload")
            return 0
        cols = list(rows[0].keys())
        with open(upload_path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        LOG.info("Wrote %s (%d rows)", upload_path, len(rows))

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    key = f"{prefix.rstrip('/') + '/' if prefix else ''}qcs_vulns_{stamp}.csv"
    boto3.client("s3").upload_file(upload_path, bucket, key)
    LOG.info("Uploaded s3://%s/%s — ETM CSV connector will fetch it", bucket, key)
    return 0


def write_dryrun(assets: List[dict], args: argparse.Namespace) -> int:
    out = args.out or "etm_payloads.ndjson"
    conn = os.environ.get("QUALYS_CONNECTOR_UUID", args.connector_uuid or "DRYRUN-UUID")
    n = 0
    with open(out, "w", encoding="utf-8") as fh:
        for batch in _batched(assets, args.batch_size):
            fh.write(json.dumps(build_payload(batch, conn, args.source_label),
                                ensure_ascii=False) + "\n")
            n += 1
    total_f = sum(len(a["findings"]) for a in assets)
    LOG.info("DRY RUN: %d asset(s), %d finding(s), %d payload(s) -> %s",
             len(assets), total_f, n, out)
    if assets:
        LOG.info("Sample asset:\n%s",
                 json.dumps(assets[0], ensure_ascii=False, indent=2)[:1200])
    return 0


def _short(resp: Any) -> str:
    s = json.dumps(resp, ensure_ascii=False) if isinstance(resp, (dict, list)) else str(resp)
    return s[:160]


# --------------------------------------------------------------------------- #
#  Main                                                                        #
# --------------------------------------------------------------------------- #
def run(args: argparse.Namespace) -> int:
    LOG.info("Reading %s ...", args.input)
    assets_map = group_assets(read_rows(args.input))
    assets = [transform_asset(a) for a in assets_map.values()]
    LOG.info("Prepared %d asset(s) with %d finding(s)",
             len(assets), sum(len(a["findings"]) for a in assets))

    if args.target == "webhook":
        return send_webhook(assets, args)
    if args.target == "s3":
        return send_s3(args.input, args)
    return write_dryrun(assets, args)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Push qcs_vuln_extract output into Qualys ETM (webhook / S3).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--input", required=True, help="NDJSON or CSV from the extractor")
    p.add_argument("--target", choices=["webhook", "s3", "dryrun"], default="dryrun")
    p.add_argument("--gateway", help="Gateway URL (else $QUALYS_GATEWAY)")
    p.add_argument("--connector-uuid", help="ETM Generic API connector UUID")
    p.add_argument("--source-label", default="WEBHOOK",
                   help="connectorMetaData.source value")
    p.add_argument("--batch-size", type=int, default=50,
                   help="Assets per webhook request")
    p.add_argument("--s3-bucket", help="Target S3 bucket (CSV connector)")
    p.add_argument("--s3-prefix", help="S3 key prefix")
    p.add_argument("--out", help="Output file for dryrun / generated CSV")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main() -> None:
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr,
    )
    try:
        sys.exit(run(args))
    except KeyboardInterrupt:
        LOG.warning("Interrupted")
        sys.exit(130)


if __name__ == "__main__":
    main()
