#!/usr/bin/env python3
"""
prisma_list_vms.py
==================
Lists IP-bearing cloud compute resources (EC2, Azure VM, Azure Container Instance,
GCP Compute, ...) from Prisma Cloud (CSPM) with an extended attribute set (tags, IPs, DNS, OS,
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
    python prisma_list_vms.py --types "EC2 Instance" "Azure Virtual Machine" --format csv -o vms.csv
    python prisma_list_vms.py --tag Environment=prod --region-filter eu-west
    python prisma_list_vms.py --keep-no-ip --format csv -o all.csv   # also keep resources without IP
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

# "vm" is fetched with ONE RQL query on resource.type, matching the Prisma Cloud
# saved search filter {"resource.type": [...]}. Override the list with --types.
VM_RESOURCE_TYPES = [
    "EC2 Instance",
    "Azure Container Instance",
    "Compute Target Instance",
    "EC2 Classic Instance",
    "ECS Container Instance",
    "Azure Virtual Machine",
]

# resource.type -> normalizer key ("aws"/"azure"/"gcp" = rich VM mapping, "generic" = fallback)
VM_TYPE_NORMALIZER = {
    "EC2 Instance": "aws",
    "EC2 Classic Instance": "aws",
    "Azure Virtual Machine": "azure",
    "Compute Instance": "gcp",
    "Azure Container Instance": "aci",
    "ECS Container Instance": "generic",
    "Compute Target Instance": "generic",
}


# resource.type (UI/Asset Inventory filter) -> api.name (RQL config search).
# The UI "resource.type" attribute is NOT accepted by /search/config on every tenant,
# so we translate it to api.name, which always is. Adjust/extend if a name differs on your tenant
# (check Inventory > Assets > any asset > "API name").
RESOURCE_TYPE_TO_API = {
    "EC2 Instance": "aws-ec2-describe-instances",
    "EC2 Classic Instance": "aws-ec2-describe-instances",         # EC2-Classic retired: same API, deduped
    "ECS Container Instance": "aws-ecs-container-instance",
    "Azure Virtual Machine": "azure-vm-list",
    "Azure Container Instance": "azure-container-instances-container-group",
    "Compute Instance": "gcloud-compute-instances-list",
    "Compute Target Instance": "gcloud-compute-target-instance",
}


def build_api_rqls(resource_types: List[str], clouds: Optional[List[str]] = None) -> List[str]:
    """One RQL per distinct api.name derived from the requested resource.type list."""
    api_names: List[str] = []
    for t in resource_types:
        api = RESOURCE_TYPE_TO_API.get(t)
        if not api:
            print(f"[WARN] No api.name mapping for resource.type '{t}', skipped "
                  f"(add it to RESOURCE_TYPE_TO_API)", file=sys.stderr)
            continue
        prefix = api.split("-", 1)[0]
        cloud = {"aws": "aws", "azure": "azure", "gcloud": "gcp"}.get(prefix, "")
        if clouds and cloud and cloud not in clouds:
            continue
        if api not in api_names:
            api_names.append(api)
    return [f"config from cloud.resource where api.name = '{a}'" for a in api_names]


def build_vm_rql(resource_types: List[str], clouds: Optional[List[str]] = None) -> str:
    types_sql = ", ".join(f"'{t}'" for t in resource_types)
    rql = f"config from cloud.resource where resource.type IN ( {types_sql} )"
    if clouds and set(clouds) != {"aws", "azure", "gcp"}:
        clouds_sql = ", ".join(f"'{c}'" for c in clouds)
        rql += f" AND cloud.type IN ( {clouds_sql} )"
    return rql


# Azure enrichment queries (VM payloads carry no IP: NIC + Public IP objects are joined client-side)
AZURE_NIC_RQL = "config from cloud.resource where api.name = 'azure-network-nic-list'"
AZURE_PIP_RQL = "config from cloud.resource where api.name = 'azure-network-public-ip-address-list'"

DEFAULT_TIMEOUT = 60
PAGE_LIMIT = 1000
TOKEN_TTL_SECONDS = 480  # JWT lives ~10 min; refresh at 8 min

# Fixed CSV schema (stable columns = stable ETM transform map)
CSV_COLUMNS = [
    "cloud_provider",        # aws | azure | gcp
    "resource_type",         # Prisma resource.type (EC2 Instance, Azure Virtual Machine, ...)
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
        if resp.status_code == 400:
            print(f"[ERROR] /search/config 400 for RQL: {query}\n        "
                  f"x-redlock-status={resp.headers.get('x-redlock-status')} body={resp.text[:500]}",
                  file=sys.stderr)
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
        "_azure_id": (d.get("id", "") or "").lower(),  # join key for NIC enrichment
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


def normalize_aci(item: Dict[str, Any]) -> Dict[str, Any]:
    """Azure Container Instance: IP lives in properties.ipAddress.ip (public or private)."""
    d = item.get("data", {}) or {}
    ip_block = _azure_prop(d, "ipAddress") or {}
    ip = _get_nested(ip_block, "ip")
    is_public = (_get_nested(ip_block, "type") or "").lower() == "public"
    return {
        "instance_id": d.get("id", "") or item.get("id", ""),
        "hostname": d.get("name", "") or item.get("name", ""),
        "fqdn": _get_nested(ip_block, "fqdn"),
        "state": _azure_prop(d, "instanceView", "state") or _azure_prop(d, "provisioningState"),
        "instance_type": _azure_prop(d, "sku"),
        "os": _azure_prop(d, "osType"),
        "platform_details": "|".join(c.get("name", "") for c in (_azure_prop(d, "containers") or [])),
        "architecture": "",
        "private_ip": "" if is_public else ip,
        "public_ip": ip if is_public else "",
        "private_dns": "", "public_dns": _get_nested(ip_block, "fqdn"),
        "mac_address": "", "vpc_id": "",
        "subnet_id": "|".join((sn.get("id", "") or "").rsplit("/", 1)[-1] for sn in (_azure_prop(d, "subnetIds") or [])),
        "security_groups": "", "iam_profile": "",
        "availability_zone": ",".join(d.get("zones") or []),
        "launch_time": "", "network_tags": "",
        "tags": d.get("tags") or {},
    }


NORMALIZERS = {"aws": normalize_aws, "azure": normalize_azure, "gcp": normalize_gcp, "aci": normalize_aci}


# ---------------------------------------------------------------------------
# Azure enrichment (NIC / Public IP join)
# ---------------------------------------------------------------------------
def build_azure_ip_index(client: "PrismaCloudClient") -> Dict[str, Dict[str, str]]:
    """Returns {vm_resource_id(lower): {private_ip, public_ip, subnet_id, security_groups, mac_address}}
    by joining azure-network-nic-list with azure-network-public-ip-address-list."""
    pips: Dict[str, str] = {}
    for item in client.search_config(AZURE_PIP_RQL):
        d = item.get("data", {}) or {}
        pips[(d.get("id", "") or "").lower()] = _azure_prop(d, "ipAddress") or ""

    index: Dict[str, Dict[str, str]] = {}
    for item in client.search_config(AZURE_NIC_RQL):
        d = item.get("data", {}) or {}
        vm_id = (_get_nested(_azure_prop(d, "virtualMachine") or {}, "id") or "").lower()
        if not vm_id:
            continue
        entry = index.setdefault(vm_id, {"private_ip": "", "public_ip": "", "subnet_id": "",
                                         "security_groups": "", "mac_address": ""})
        nsg = (_get_nested(_azure_prop(d, "networkSecurityGroup") or {}, "id") or "").rsplit("/", 1)[-1]
        mac = _azure_prop(d, "macAddress") or ""
        for cfg in _azure_prop(d, "ipConfigurations") or []:
            props = cfg.get("properties", {}) or cfg
            priv = props.get("privateIPAddress", "")
            pip_id = (_get_nested(props, "publicIPAddress", "id") or "").lower()
            pub = pips.get(pip_id, "")
            sub = (_get_nested(props, "subnet", "id") or "").rsplit("/", 1)[-1]
            if priv and priv not in entry["private_ip"].split("|"):
                entry["private_ip"] = "|".join(filter(None, [entry["private_ip"], priv]))
            if pub and pub not in entry["public_ip"].split("|"):
                entry["public_ip"] = "|".join(filter(None, [entry["public_ip"], pub]))
            if sub and sub not in entry["subnet_id"].split("|"):
                entry["subnet_id"] = "|".join(filter(None, [entry["subnet_id"], sub]))
        if nsg and nsg not in entry["security_groups"].split("|"):
            entry["security_groups"] = "|".join(filter(None, [entry["security_groups"], nsg]))
        if mac and not entry["mac_address"]:
            entry["mac_address"] = mac
    return index


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
    for k in ("cloud_provider", "resource_type", "asset_name", "unified_asset_id", "account_id",
              "account_name", "region", "deleted", "tags_json"):
        empty.pop(k, None)
    return empty


def normalize_item(cloud: str, item: Dict[str, Any], tag_keys: List[str]) -> Dict[str, Any]:
    # The single resource.type query returns mixed clouds: trust the item's cloudType first.
    cloud = (item.get("cloudType") or cloud or "").lower()
    prisma_type = item.get("resourceType", "")
    key = VM_TYPE_NORMALIZER.get(prisma_type, cloud)
    specific = NORMALIZERS[key](item) if key in NORMALIZERS else normalize_generic(item)
    tags: Dict[str, str] = specific.pop("tags", {}) or {}

    row = {
        "cloud_provider": cloud,
        "resource_type": prisma_type,
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
    cols = ["cloud_provider", "resource_type", "asset_name", "instance_id", "account_name",
            "region", "state", "private_ip", "public_ip"]
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) if rows else len(c) for c in cols}
    header = "  ".join(c.ljust(widths[c]) for c in cols)
    print(header)
    print("-" * len(header))
    for r in rows:
        print("  ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols))


def main() -> None:
    parser = argparse.ArgumentParser(description="Lists cloud resources from Prisma Cloud (extended attributes)")
    parser.add_argument("--types", nargs="+", default=VM_RESOURCE_TYPES, metavar="RESOURCE_TYPE",
                        help="Prisma resource.type values to fetch "
                             "(default: the saved-search list, e.g. 'EC2 Instance' 'Azure Virtual Machine')")
    parser.add_argument("--query-mode", choices=["api", "resource-type"], default="api",
                        help="'api' (default): one RQL per api.name mapped from --types (works everywhere). "
                             "'resource-type': single RQL on resource.type IN (...) (not accepted by all tenants).")
    parser.add_argument("--keep-no-ip", action="store_true",
                        help="Keep resources without any private/public IP (dropped by default)")
    parser.add_argument("--no-azure-enrich", action="store_true",
                        help="Skip the Azure NIC/Public-IP join (faster, but Azure VMs will have no IP)")
    parser.add_argument("--rql", help="Custom RQL config query (overrides --types/--clouds), "
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
    elif args.query_mode == "resource-type":
        queries = [("vm", build_vm_rql(args.types, args.clouds))]
    else:
        queries = [("vm", q) for q in build_api_rqls(args.types, args.clouds)]

    azure_ips: Dict[str, Dict[str, str]] = {}
    if not args.no_azure_enrich and "azure" in args.clouds:
        print("[INFO] Building Azure NIC / Public IP index…", file=sys.stderr)
        try:
            azure_ips = build_azure_ip_index(client)
            print(f"[INFO] Azure index: {len(azure_ips)} VMs with NIC data", file=sys.stderr)
        except requests.HTTPError as exc:
            print(f"[WARN] Azure enrichment failed: {exc}", file=sys.stderr)

    rows: List[Dict[str, Any]] = []
    seen: set = set()
    for cloud, query in queries:
        print(f"[INFO] Querying {cloud.upper()}: {query}", file=sys.stderr)
        count = skipped = filtered = no_ip = 0
        try:
            for item in client.search_config(query):
                if item.get("deleted") and not args.include_deleted:
                    skipped += 1
                    continue
                uid = item.get("rrn") or item.get("unifiedAssetId") or item.get("id")
                if uid in seen:
                    continue
                seen.add(uid)
                row = normalize_item(cloud, item, args.tag_keys)
                azure_id = row.pop("_azure_id", "")
                if azure_id and azure_id in azure_ips:
                    row.update({k: v for k, v in azure_ips[azure_id].items() if v})
                if not args.keep_no_ip and not (row.get("private_ip") or row.get("public_ip")):
                    no_ip += 1
                    continue
                if not matches_filters(row, args):
                    filtered += 1
                    continue
                rows.append(row)
                count += 1
        except requests.HTTPError as exc:
            print(f"[WARN] {cloud} query failed: {exc}", file=sys.stderr)
            continue
        print(f"[INFO] {cloud.upper()}: {count} kept, {no_ip} without IP, {filtered} filtered out, {skipped} deleted skipped",
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