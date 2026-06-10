#!/usr/bin/env python3
"""
prisma_list_vms.py
==================
Lists cloud VM instances (AWS EC2, Azure VM, GCP Compute) from
Prisma Cloud (CSPM) with an extended attribute set (tags, IPs, DNS, OS,
VPC/subnet, security groups, etc.) designed for later ingestion
into Qualys ETM via the Generic CSV connector.

Requirements:
    pip install requests

Environment variables:
    PRISMA_API_URL     e.g. https://api2.eu.prismacloud.io  (*API* URL, not console URL)
    PRISMA_ACCESS_KEY  Service account Access Key ID
    PRISMA_SECRET_KEY  Service account Secret Key

Usage:
    python prisma_list_vms.py --format csv -o vms_etm.csv
    python prisma_list_vms.py --format csv -o vms.csv --tag-keys Environment Owner AppName
    python prisma_list_vms.py --clouds aws --state running --format json -o aws_running.json
    python prisma_list_vms.py --tag Environment=prod --region-filter eu-west
    python prisma_list_vms.py --resource-type database --format csv -o dbs.csv
    python prisma_list_vms.py --rql "config from cloud.resource where api.name = 'aws-ec2-describe-instances' AND json.rule = state.name equals running"
"""

import argparse
import csv
import json
import os
import sys
import time
from typing import Any, Dict, Iterator, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# RQL queries per resource type and per cloud provider.
# Add new entries here to support more resource types over time.
# Only "vm" has rich field normalization; other types use a generic mapping.
RQL_QUERIES = {
    "vm": {
        "aws":   "config from cloud.resource where api.name = 'aws-ec2-describe-instances'",
        "azure": "config from cloud.resource where api.name = 'azure-vm-list'",
        "gcp":   "config from cloud.resource where api.name = 'gcloud-compute-instances-list'",
    },
    "database": {
        "aws":   "config from cloud.resource where api.name = 'aws-rds-describe-db-instances'",
        "azure": "config from cloud.resource where api.name = 'azure-sql-db-list'",
        "gcp":   "config from cloud.resource where api.name = 'gcloud-sql-instances-list'",
    },
    "storage": {
        "aws":   "config from cloud.resource where api.name = 'aws-s3api-get-bucket-acl'",
        "azure": "config from cloud.resource where api.name = 'azure-storage-account-list'",
        "gcp":   "config from cloud.resource where api.name = 'gcloud-storage-buckets-list'",
    },
}

DEFAULT_TIMEOUT = 60
PAGE_LIMIT = 1000
TOKEN_TTL_SECONDS = 480  # JWT lives ~10 min; refresh at 8 min

# Fixed CSV schema (stable columns = stable ETM transform map)
CSV_COLUMNS = [
    "cloud_provider",        # aws | azure | gcp
    "asset_name",            # resource name as seen by Prisma
    "hostname",              # computerName / hostname / short privateDnsName
    "fqdn",                  # full private DNS name when available
    "instance_id",           # native cloud ID (i-xxxx, vmId, GCP numeric id) -> ETM identification key
    "unified_asset_id",      # Prisma RRN / unifiedAssetId (stable internal key)
    "account_id",
    "account_name",
    "region",
    "availability_zone",
    "state",                 # running / stopped / ...
    "instance_type",
    "os",                    # OS family (Linux/Windows or osType)
    "platform_details",
    "architecture",
    "private_ip",            # primary reconciliation anchor (+ instance_id)
    "public_ip",             # exposure signal (layer 1)
    "private_dns",
    "public_dns",
    "mac_address",
    "vpc_id",
    "subnet_id",
    "security_groups",       # "sg-xxx:name|sg-yyy:name"
    "iam_profile",
    "launch_time",
    "network_tags",          # GCP network tags (firewall rule targets)
    "deleted",               # Prisma flag (asset deleted on the cloud side)
    "tags_json",             # all tags/labels as JSON {"k":"v"}
]


class PrismaCloudClient:
    """Minimal Prisma Cloud CSPM API client with JWT token handling/refresh."""

    def __init__(self, api_url: str, access_key: str, secret_key: str):
        self.api_url = api_url.rstrip("/")
        self.access_key = access_key
        self.secret_key = secret_key
        self._token: Optional[str] = None
        self._token_acquired_at: float = 0.0

        self.session = requests.Session()
        retry = Retry(
            total=5,
            backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    def login(self) -> None:
        resp = self.session.post(
            f"{self.api_url}/login",
            json={"username": self.access_key, "password": self.secret_key},
            headers={"Content-Type": "application/json"},
            timeout=DEFAULT_TIMEOUT,
        )
        if resp.status_code == 401:
            sys.exit("[ERROR] Authentication refused (401): check the access key / secret key.")
        resp.raise_for_status()
        self._token = resp.json()["token"]
        self._token_acquired_at = time.time()
        print(f"[INFO] Authenticated on {self.api_url}", file=sys.stderr)

    def _headers(self) -> Dict[str, str]:
        if self._token is None or (time.time() - self._token_acquired_at) > TOKEN_TTL_SECONDS:
            self.login()
        return {"Content-Type": "application/json", "x-redlock-auth": self._token}  # type: ignore[dict-item]

    def search_config(self, query: str) -> Iterator[Dict[str, Any]]:
        """Runs an RQL config query and iterates over all items (full pagination)."""
        payload = {
            "query": query,
            "limit": PAGE_LIMIT,
            "timeRange": {"type": "to_now", "value": "epoch"},
        }
        resp = self.session.post(
            f"{self.api_url}/search/config", json=payload,
            headers=self._headers(), timeout=DEFAULT_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        yield from data.get("items", [])

        next_token = data.get("nextPageToken")
        while next_token:
            resp = self.session.post(
                f"{self.api_url}/search/config/page",
                json={"pageToken": next_token, "limit": PAGE_LIMIT},
                headers=self._headers(), timeout=DEFAULT_TIMEOUT,
            )
            resp.raise_for_status()
            page = resp.json()
            yield from page.get("items", [])
            next_token = page.get("nextPageToken")


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------
def _get_nested(d: Dict[str, Any], *path: str, default: Any = "") -> Any:
    cur: Any = d
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


def _azure_prop(data: Dict[str, Any], *path: str) -> Any:
    """Azure: handles both nested ARM payloads AND Prisma-flattened keys
    of the form "['properties.osProfile'].computerName"."""
    val = _get_nested(data, "properties", *path)
    if val:
        return val
    flat_key = f"['properties.{path[0]}']"
    sub = data.get(flat_key)
    if isinstance(sub, dict):
        return _get_nested(sub, *path[1:]) if len(path) > 1 else sub
    return ""


def _join_sg(groups: List[Dict[str, Any]]) -> str:
    return "|".join(
        f"{g.get('groupId', '')}:{g.get('groupName', '')}" for g in groups or []
    )


# ---------------------------------------------------------------------------
# Per-cloud normalization
# ---------------------------------------------------------------------------
def normalize_aws(item: Dict[str, Any]) -> Dict[str, Any]:
    d = item.get("data", {}) or {}
    tags = {t.get("key", ""): t.get("value", "") for t in d.get("tags", []) or []}
    nics = d.get("networkInterfaces") or []
    private_dns = d.get("privateDnsName", "")
    return {
        "instance_id": d.get("instanceId", ""),
        "hostname": tags.get("Name", "") or private_dns.split(".")[0],
        "fqdn": private_dns,
        "state": _get_nested(d, "state", "name"),
        "instance_type": d.get("instanceType", ""),
        "os": "Windows" if (d.get("platform") or "").lower() == "windows" else "Linux/UNIX",
        "platform_details": d.get("platformDetails", ""),
        "architecture": d.get("architecture", ""),
        "private_ip": d.get("privateIpAddress", ""),
        "public_ip": d.get("publicIpAddress", ""),
        "private_dns": private_dns,
        "public_dns": d.get("publicDnsName", ""),
        "mac_address": nics[0].get("macAddress", "") if nics else "",
        "vpc_id": d.get("vpcId", ""),
        "subnet_id": d.get("subnetId", ""),
        "security_groups": _join_sg(d.get("securityGroups", [])),
        "iam_profile": _get_nested(d, "iamInstanceProfile", "arn"),
        "availability_zone": _get_nested(d, "placement", "availabilityZone"),
        "launch_time": d.get("launchTime", ""),
        "network_tags": "",
        "tags": tags,
    }


def normalize_azure(item: Dict[str, Any]) -> Dict[str, Any]:
    d = item.get("data", {}) or {}
    tags = d.get("tags") or {}
    os_type = _azure_prop(d, "storageProfile", "osDisk", "osType")
    computer_name = _azure_prop(d, "osProfile", "computerName")
    power_state = d.get("powerState", "") or _azure_prop(d, "extended", "instanceView", "powerState", "displayStatus")
    return {
        "instance_id": _azure_prop(d, "vmId") or d.get("id", ""),
        "hostname": computer_name or d.get("name", ""),
        "fqdn": "",
        "state": power_state,
        "instance_type": _azure_prop(d, "hardwareProfile", "vmSize"),
        "os": os_type,
        "platform_details": _get_nested(_azure_prop(d, "storageProfile", "imageReference") or {}, "offer"),
        "architecture": "",
        "private_ip": "",   # requires azure-network-nic-list for reliable data (RQL join possible)
        "public_ip": "",
        "private_dns": "",
        "public_dns": "",
        "mac_address": "",
        "vpc_id": "",
        "subnet_id": "",
        "security_groups": "",
        "iam_profile": "",
        "availability_zone": ",".join(d.get("zones") or []),
        "launch_time": _azure_prop(d, "timeCreated"),
        "network_tags": "",
        "tags": tags,
    }


def normalize_gcp(item: Dict[str, Any]) -> Dict[str, Any]:
    d = item.get("data", {}) or {}
    labels = d.get("labels") or {}
    nics = d.get("networkInterfaces") or []
    private_ip = nics[0].get("networkIP", "") if nics else ""
    public_ip = ""
    if nics and nics[0].get("accessConfigs"):
        public_ip = nics[0]["accessConfigs"][0].get("natIP", "")
    network = nics[0].get("network", "").rsplit("/", 1)[-1] if nics else ""
    subnet = nics[0].get("subnetwork", "").rsplit("/", 1)[-1] if nics else ""
    sa = d.get("serviceAccounts") or []
    return {
        "instance_id": str(d.get("id", "")),
        "hostname": d.get("hostname", "") or d.get("name", ""),
        "fqdn": d.get("hostname", ""),
        "state": d.get("status", ""),
        "instance_type": (d.get("machineType", "") or "").rsplit("/", 1)[-1],
        "os": "",
        "platform_details": "|".join(
            lic.rsplit("/", 1)[-1]
            for disk in (d.get("disks") or [])
            for lic in (disk.get("licenses") or [])
        ),
        "architecture": "",
        "private_ip": private_ip,
        "public_ip": public_ip,
        "private_dns": "",
        "public_dns": "",
        "mac_address": "",
        "vpc_id": network,
        "subnet_id": subnet,
        "security_groups": "",
        "iam_profile": sa[0].get("email", "") if sa else "",
        "availability_zone": (d.get("zone", "") or "").rsplit("/", 1)[-1],
        "launch_time": d.get("creationTimestamp", ""),
        "network_tags": "|".join(_get_nested(d, "tags", "items", default=[]) or []),
        "tags": labels,
    }


NORMALIZERS = {"aws": normalize_aws, "azure": normalize_azure, "gcp": normalize_gcp}


def normalize_generic(item: Dict[str, Any]) -> Dict[str, Any]:
    """Fallback normalization for non-VM resource types (databases, storage, custom RQL):
    fills the common columns and extracts tags/labels in their usual shapes."""
    d = item.get("data", {}) or {}
    raw_tags = d.get("tags") or d.get("labels") or {}
    if isinstance(raw_tags, list):  # AWS-style [{"key": ..., "value": ...}]
        tags = {t.get("key", ""): t.get("value", "") for t in raw_tags}
    elif isinstance(raw_tags, dict):  # Azure/GCP-style {"k": "v"}
        tags = raw_tags
    else:
        tags = {}
    empty = {c: "" for c in CSV_COLUMNS}
    empty.update({
        "instance_id": str(d.get("dbInstanceIdentifier", "") or d.get("id", "") or item.get("id", "")),
        "hostname": d.get("name", "") or item.get("name", ""),
        "state": d.get("status", "") or d.get("dbInstanceStatus", "") or d.get("state", ""),
        "tags": tags,
    })
    # Drop keys handled by normalize_item itself
    for k in ("cloud_provider", "asset_name", "unified_asset_id", "account_id",
              "account_name", "region", "deleted", "tags_json"):
        empty.pop(k, None)
    return empty


def normalize_item(cloud: str, item: Dict[str, Any], tag_keys: List[str],
                   resource_type: str = "vm") -> Dict[str, Any]:
    if resource_type == "vm" and cloud in NORMALIZERS:
        specific = NORMALIZERS[cloud](item)
    else:
        specific = normalize_generic(item)
    tags: Dict[str, str] = specific.pop("tags", {}) or {}

    row = {
        "cloud_provider": cloud,
        "asset_name": item.get("name", ""),
        "unified_asset_id": item.get("rrn", "") or item.get("unifiedAssetId", "") or item.get("id", ""),
        "account_id": item.get("accountId", ""),
        "account_name": item.get("accountName", ""),
        "region": item.get("regionName", "") or item.get("regionId", ""),
        "deleted": str(item.get("deleted", False)).lower(),
        "tags_json": json.dumps(tags, ensure_ascii=False, sort_keys=True),
        **specific,
    }
    # Promote selected tags to dedicated columns (direct mapping in ETM)
    for key in tag_keys:
        row[f"tag_{key}"] = tags.get(key, "")
    return row


# ---------------------------------------------------------------------------
# Client-side filtering
# ---------------------------------------------------------------------------
def matches_filters(row: Dict[str, Any], args: argparse.Namespace) -> bool:
    """Applies optional post-query filters (state, account, region, name, tags).
    All provided filters must match (logical AND). Matching is case-insensitive."""
    if args.state and args.state.lower() not in str(row.get("state", "")).lower():
        return False
    if args.account:
        acct = args.account.lower()
        if acct not in str(row.get("account_id", "")).lower() \
                and acct not in str(row.get("account_name", "")).lower():
            return False
    if args.region_filter and args.region_filter.lower() not in str(row.get("region", "")).lower():
        return False
    if args.name:
        name = args.name.lower()
        if name not in str(row.get("asset_name", "")).lower() \
                and name not in str(row.get("hostname", "")).lower():
            return False
    if args.tag:
        tags = json.loads(row.get("tags_json", "{}") or "{}")
        tags_ci = {k.lower(): str(v).lower() for k, v in tags.items()}
        for tag_filter in args.tag:
            key, _, value = tag_filter.partition("=")
            actual = tags_ci.get(key.lower())
            if actual is None:
                return False
            if value and value.lower() != actual:
                return False
    return True


# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
def write_csv(rows: List[Dict[str, Any]], path: str, tag_keys: List[str]) -> None:
    columns = CSV_COLUMNS + [f"tag_{k}" for k in tag_keys]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    print(f"[INFO] {len(rows)} VMs exported to {path}", file=sys.stderr)


def print_table(rows: List[Dict[str, Any]]) -> None:
    cols = ["cloud_provider", "asset_name", "instance_id", "account_name",
            "region", "state", "private_ip", "public_ip"]
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) if rows else len(c) for c in cols}
    header = "  ".join(c.ljust(widths[c]) for c in cols)
    print(header)
    print("-" * len(header))
    for r in rows:
        print("  ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols))


def main() -> None:
    parser = argparse.ArgumentParser(description="Lists cloud resources from Prisma Cloud (extended attributes)")
    parser.add_argument("--resource-type", choices=list(RQL_QUERIES), default="vm",
                        help="Resource type to fetch (default: vm). Only 'vm' gets full field normalization.")
    parser.add_argument("--rql", help="Custom RQL config query (overrides --resource-type/--clouds), "
                                      "e.g.: \"config from cloud.resource where api.name = 'aws-ec2-describe-instances' "
                                      "AND json.rule = state.name equals running\"")
    parser.add_argument("--clouds", nargs="+", choices=["aws", "azure", "gcp"], default=["aws", "azure", "gcp"])
    parser.add_argument("--state", help="Filter on state, substring match (e.g.: running, stopped)")
    parser.add_argument("--account", help="Filter on account ID or account name (substring)")
    parser.add_argument("--region-filter", help="Filter on region (substring, e.g.: eu-west)")
    parser.add_argument("--name", help="Filter on asset name / hostname (substring)")
    parser.add_argument("--tag", action="append", default=[],
                        help="Filter on tag, repeatable. 'Key' (presence) or 'Key=Value' (exact value), "
                             "e.g.: --tag Environment=prod --tag Owner")
    parser.add_argument("--format", choices=["table", "csv", "json"], default="table")
    parser.add_argument("-o", "--output", help="Output file (required for csv)")
    parser.add_argument("--tag-keys", nargs="*", default=[],
                        help="Tags to promote as dedicated columns, e.g.: --tag-keys Environment Owner AppName")
    parser.add_argument("--include-deleted", action="store_true",
                        help="Include assets flagged as deleted by Prisma (excluded by default)")
    args = parser.parse_args()

    api_url = os.environ.get("PRISMA_API_URL")
    access_key = os.environ.get("PRISMA_ACCESS_KEY")
    secret_key = os.environ.get("PRISMA_SECRET_KEY")
    if not all([api_url, access_key, secret_key]):
        sys.exit("[ERROR] Set PRISMA_API_URL, PRISMA_ACCESS_KEY and PRISMA_SECRET_KEY.")

    client = PrismaCloudClient(api_url, access_key, secret_key)
    client.login()

    # Build the list of (cloud_label, rql_query) to run
    if args.rql:
        queries = [("custom", args.rql)]
    else:
        queries = [(cloud, RQL_QUERIES[args.resource_type][cloud]) for cloud in args.clouds]

    rows: List[Dict[str, Any]] = []
    for cloud, query in queries:
        print(f"[INFO] Querying {cloud.upper()}: {query}", file=sys.stderr)
        count = skipped = filtered = 0
        try:
            for item in client.search_config(query):
                if item.get("deleted") and not args.include_deleted:
                    skipped += 1
                    continue
                row = normalize_item(cloud, item, args.tag_keys, args.resource_type)
                if not matches_filters(row, args):
                    filtered += 1
                    continue
                rows.append(row)
                count += 1
        except requests.HTTPError as exc:
            print(f"[WARN] {cloud} query failed: {exc}", file=sys.stderr)
            continue
        print(f"[INFO] {cloud.upper()}: {count} kept, {filtered} filtered out, {skipped} deleted skipped",
              file=sys.stderr)

    if args.format == "json":
        out = json.dumps(rows, indent=2, ensure_ascii=False)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
            print(f"[INFO] {len(rows)} VMs exported to {args.output}", file=sys.stderr)
        else:
            print(out)
    elif args.format == "csv":
        if not args.output:
            sys.exit("[ERROR] --output is required with --format csv")
        write_csv(rows, args.output, args.tag_keys)
    else:
        print_table(rows)
        print(f"\nTotal: {len(rows)} VMs", file=sys.stderr)


if __name__ == "__main__":
    main()
