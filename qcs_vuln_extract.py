#!/usr/bin/env python3
"""
qcs_vuln_extract.py
===================
COMPLETE vulnerability extraction from the Qualys Container Security API
(/csapi/v1.3/), normalized into NDJSON + CSV ready to be pushed to Qualys ETM
(Generic CSV connector) — same approach as rhacs_to_etm.py / prisma_to_etm.py.

What it produces, one row per granular detection:
    (image|container)  x  QID  x  CVE  x  affected package
with full inventory context (digest, OS, host/sensor, k8s) and full vuln detail
(CVSS v2/v3, QDS, threatIntel/RTI, RHSA, fixVersion) + a stable dedup key and an
`exploitation_state` derived from the RTI flags.

Flow:
    1. Gateway auth -> bearer JWT (POST <gateway>/auth, valid 4h, auto-refresh)
    2. Enumerate    -> /csapi/v1.3/images   (paginated, optional QQL filter)
    3. Per image    -> /images/{sha}              (digest, OS, host, k8s labels, SBOM)
                       /images/{sha}/vuln?type=ALL   (full vuln detail)
    4. Flatten      -> NDJSON (streamed) + CSV

Single dependency: requests   (pip install requests)

Auth (environment variables):
    QUALYS_GATEWAY   e.g. https://gateway.qg1.apps.qualys.com   (US1 POD)
    QUALYS_USERNAME
    QUALYS_PASSWORD

Examples:
    # all images updated in the last 7 days, ETM-oriented output
    python qcs_vuln_extract.py --filter "image.updated:[now-7d ... now]" --etm

    # running containers only, NDJSON only, 8 worker threads
    python qcs_vuln_extract.py --scope containers \\
        --filter "container.state:RUNNING" --format ndjson --concurrency 8
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, List, Optional

try:
    import requests
except ImportError:
    sys.exit("Missing 'requests' module: pip install requests")

LOG = logging.getLogger("qcs_extract")

API_PREFIX = "/csapi/v1.3"
TOKEN_TTL = 3 * 60 * 60          # refresh the JWT after 3h (real TTL = 4h)
RETRY_STATUS = {429, 500, 502, 503, 504}


# --------------------------------------------------------------------------- #
#  Qualys CS API client                                                        #
# --------------------------------------------------------------------------- #
class QualysCSClient:
    def __init__(self, gateway: str, username: str, password: str,
                 timeout: int = 60, max_retries: int = 5):
        self.gateway = gateway.rstrip("/")
        self._user = username
        self._pass = password
        self.timeout = timeout
        self.max_retries = max_retries
        self._session = requests.Session()
        self._token: Optional[str] = None
        self._token_ts = 0.0
        self._lock = threading.Lock()

    # -- authentication ------------------------------------------------------ #
    def _authenticate(self) -> None:
        url = f"{self.gateway}/auth"
        data = {"username": self._user, "password": self._pass,
                "token": "true", "permissions": "true"}
        LOG.info("Gateway authentication -> %s", url)
        resp = self._session.post(
            url, data=data, timeout=self.timeout,
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "application/json"},
        )
        resp.raise_for_status()
        token = resp.text.strip()
        if not token or token.count(".") < 2:
            raise RuntimeError("Unexpected auth response (no JWT)")
        self._token = token
        self._token_ts = time.time()

    def _ensure_token(self) -> str:
        with self._lock:
            if self._token is None or (time.time() - self._token_ts) > TOKEN_TTL:
                self._authenticate()
            return self._token  # type: ignore[return-value]

    # -- generic request with retries / backoff ------------------------------ #
    def get(self, path: str, params: Optional[dict] = None) -> Any:
        url = f"{self.gateway}{path}"
        attempt = 0
        while True:
            attempt += 1
            token = self._ensure_token()
            try:
                resp = self._session.get(
                    url, params=params, timeout=self.timeout,
                    headers={"Authorization": f"Bearer {token}",
                             "Accept": "application/json"},
                )
            except requests.RequestException as exc:
                if attempt > self.max_retries:
                    raise
                wait = min(2 ** attempt, 30)
                LOG.warning("Network error (%s) — retry in %ss", exc, wait)
                time.sleep(wait)
                continue

            if resp.status_code == 401:           # token expired -> refresh
                with self._lock:
                    self._token = None
                if attempt <= self.max_retries:
                    continue
                resp.raise_for_status()

            if resp.status_code in RETRY_STATUS and attempt <= self.max_retries:
                wait = int(resp.headers.get("Retry-After",
                                            min(2 ** attempt, 30)))
                LOG.warning("HTTP %s on %s — retry in %ss",
                            resp.status_code, path, wait)
                time.sleep(wait)
                continue

            resp.raise_for_status()
            if not resp.content:
                return {}
            return resp.json()

    # -- asset pagination (images / containers) ------------------------------ #
    def paginate(self, scope: str, page_size: int, qql_filter: Optional[str],
                 max_assets: Optional[int]) -> Iterator[dict]:
        path = f"{API_PREFIX}/{scope}"          # /images or /containers
        page = 1
        yielded = 0
        while True:
            params = {"pageNumber": page, "pageSize": page_size,
                      "sort": "updated:desc"}
            if qql_filter:
                params["filter"] = qql_filter
            payload = self.get(path, params)
            rows = _aslist(payload, ("data", "content"))
            if not rows:
                break
            for row in rows:
                yield row
                yielded += 1
                if max_assets and yielded >= max_assets:
                    return
            if len(rows) < page_size:
                break
            page += 1

    def asset_detail(self, scope: str, sha: str) -> dict:
        return self.get(f"{API_PREFIX}/{scope}/{sha}") or {}

    def asset_vulns(self, scope: str, sha: str,
                    apply_exception: bool = False) -> List[dict]:
        payload = self.get(
            f"{API_PREFIX}/{scope}/{sha}/vuln",
            {"type": "ALL", "applyException": str(apply_exception).lower()},
        )
        return _aslist(payload, ("details", "vulnerabilities", "data"))


# --------------------------------------------------------------------------- #
#  Normalization helpers                                                        #
# --------------------------------------------------------------------------- #
def _aslist(payload: Any, keys: Iterable[str]) -> List[dict]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for k in keys:
            v = payload.get(k)
            if isinstance(v, list):
                return v
    return []


def _epoch_to_iso(value: Any) -> str:
    """Qualys often returns epoch millis as strings. Output ISO8601 UTC."""
    if value in (None, "", 0, "0"):
        return ""
    try:
        ms = int(value)
        # seconds vs milliseconds heuristic
        if ms > 10_000_000_000:
            ms //= 1000
        return datetime.fromtimestamp(ms, tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OSError):
        return str(value)


def _first(host_field: Any, key: str) -> str:
    """host may be a list, a dict, or null depending on the endpoint."""
    if isinstance(host_field, list) and host_field:
        host_field = host_field[0]
    if isinstance(host_field, dict):
        return str(host_field.get(key) or "")
    return ""


def _k8s_from_labels(labels: Any) -> Dict[str, str]:
    """Extract namespace / pod from a container's label[] {key,value} array."""
    out = {"k8s_namespace": "", "k8s_pod": ""}
    if isinstance(labels, list):
        for lb in labels:
            if not isinstance(lb, dict):
                continue
            k, v = lb.get("key", ""), lb.get("value", "")
            if k == "io.kubernetes.pod.namespace":
                out["k8s_namespace"] = v
            elif k == "io.kubernetes.pod.name":
                out["k8s_pod"] = v
    return out


_TI_FIELDS = [
    "activeAttacks", "zeroDay", "publicExploit", "easyExploit", "exploitKit",
    "malware", "denialOfService", "highLateralMovement", "highDataLoss",
    "noPatch", "ransomware",
]


def _threat_intel(ti: Any) -> Dict[str, Any]:
    ti = ti if isinstance(ti, dict) else {}
    flat = {f"ti_{_snake(k)}": bool(ti.get(k)) for k in _TI_FIELDS}
    flat["exploitation_state"] = _exploitation_state(ti)
    flat["exploit_available"] = any(
        bool(ti.get(k)) for k in
        ("activeAttacks", "publicExploit", "exploitKit", "malware", "ransomware")
    )
    return flat


def _exploitation_state(ti: dict) -> str:
    """Map the Qualys RTI flags to an exploitation state (ETM logic)."""
    if ti.get("activeAttacks") or ti.get("malware") or ti.get("ransomware"):
        return "ACTIVE"
    if ti.get("exploitKit"):
        return "WEAPONIZED"
    if ti.get("publicExploit"):
        return "POC"
    if ti.get("zeroDay"):
        return "ZERODAY"
    return "NONE"


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


_SEV_LABEL = {1: "INFO", 2: "LOW", 3: "MEDIUM", 4: "HIGH", 5: "CRITICAL"}


def _rhsa(vendor_data: Any, cve: str) -> Dict[str, Any]:
    """Extract RHSA info (id, vendor severity, per-CVE cvss3) when present."""
    out = {"rhsa_id": "", "rhsa_severity": "",
           "cve_vendor_severity": "", "cve_vendor_cvss3": ""}
    vd = vendor_data if isinstance(vendor_data, dict) else {}
    rhsa = vd.get("rhsa") if isinstance(vd.get("rhsa"), dict) else {}
    out["rhsa_id"] = rhsa.get("id") or ""
    out["rhsa_severity"] = rhsa.get("severity") or ""
    for entry in rhsa.get("cve", []) or []:
        if isinstance(entry, dict) and entry.get("id") == cve:
            out["cve_vendor_severity"] = entry.get("severity") or ""
            c3 = entry.get("cvss3") or {}
            out["cve_vendor_cvss3"] = c3.get("baseScore") if isinstance(c3, dict) else ""
            break
    return out


def _packages(vuln: dict) -> List[Dict[str, str]]:
    """Affected packages: software[] preferred, else parse the `result` table."""
    sw = vuln.get("software")
    pkgs: List[Dict[str, str]] = []
    if isinstance(sw, list) and sw:
        for s in sw:
            if not isinstance(s, dict):
                continue
            pkgs.append({
                "package_name": s.get("name") or "",
                "installed_version": s.get("version") or "",
                "fixed_version": s.get("fixVersion") or "",
                "package_path": s.get("packagePath") or "",
                "package_scan_type": s.get("scanType") or "",
            })
    if not pkgs:
        pkgs = _parse_result_table(vuln.get("result"))
    return pkgs or [{"package_name": "", "installed_version": "",
                     "fixed_version": "", "package_path": "",
                     "package_scan_type": ""}]


def _parse_result_table(result: Any) -> List[Dict[str, str]]:
    """Parse the `#table cols="N"` blob (Package / Installed_Version / Required_Version)."""
    if not isinstance(result, str) or "#table" not in result:
        return []
    lines = [ln for ln in result.splitlines() if ln.strip()]
    lines = [ln for ln in lines if not ln.startswith("#table")]
    if len(lines) < 2:
        return []
    header = lines[0].split()
    idx = {h.lower(): i for i, h in enumerate(header)}
    pkgs = []
    for row in lines[1:]:
        cols = row.split()
        if len(cols) < 2:
            continue

        def col(name: str) -> str:
            i = idx.get(name)
            return cols[i] if i is not None and i < len(cols) else ""
        pkgs.append({
            "package_name": col("package"),
            "installed_version": col("installed_version"),
            "fixed_version": col("required_version"),
            "package_path": col("install_path"),
            "package_scan_type": col("language"),
        })
    return pkgs


def _dedup_key(*parts: str) -> str:
    raw = "|".join(p or "" for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
#  Flatten one asset into detection rows                                        #
# --------------------------------------------------------------------------- #
def flatten_asset(scope: str, detail: dict, vulns: List[dict],
                  extracted_at: str) -> Iterator[dict]:
    is_image = scope == "images"

    repo = (detail.get("repo") or [{}])
    repo0 = repo[0] if isinstance(repo, list) and repo else {}
    digest = ""
    rd = detail.get("repoDigests") or []
    if isinstance(rd, list) and rd and isinstance(rd[0], dict):
        digest = rd[0].get("digest") or ""

    host_src = detail.get("host") or detail.get("lastFoundOnHost")
    k8s = _k8s_from_labels(detail.get("label"))
    cluster = detail.get("cluster") if isinstance(detail.get("cluster"), dict) else {}

    image_sha = detail.get("sha", "") if is_image else detail.get("imageSha", "")
    container_sha = "" if is_image else detail.get("sha", "")

    # synthetic asset identifier for ETM
    if is_image:
        ref = repo0.get("repository") or detail.get("imageId") or image_sha
        tag = repo0.get("tag") or "latest"
        synthetic_asset = f"{repo0.get('registry','')}/{ref}:{tag}".strip("/")
    else:
        synthetic_asset = (
            f"{cluster.get('name', _first(host_src, 'hostname'))}/"
            f"{k8s['k8s_namespace']}/{k8s['k8s_pod'] or detail.get('name','')}"
        )

    ctx = {
        "source_scope": scope,
        "image_sha": image_sha,
        "image_id": detail.get("imageId", ""),
        "container_sha": container_sha,
        "container_id": detail.get("containerId", "") if not is_image else "",
        "synthetic_asset_id": synthetic_asset,
        "registry": repo0.get("registry", ""),
        "repository": repo0.get("repository", ""),
        "image_tag": repo0.get("tag", ""),
        "image_digest": digest,
        "operating_system": detail.get("operatingSystem", ""),
        "architecture": detail.get("architecture", ""),
        "sensor_uuid": _first(host_src, "sensorUuid"),
        "hostname": _first(host_src, "hostname"),
        "host_ip": _first(host_src, "ipAddress"),
        "k8s_namespace": k8s["k8s_namespace"],
        "k8s_pod": k8s["k8s_pod"],
        "k8s_cluster": cluster.get("name", ""),
        "image_source": ",".join(detail.get("source", []) or []),
        "image_criticality": detail.get("criticality", ""),
        "container_state": detail.get("state", "") if not is_image else "",
        "extracted_at": extracted_at,
    }

    for v in vulns:
        if not isinstance(v, dict):
            continue
        cvss2 = v.get("cvssInfo") or {}
        cvss3 = v.get("cvss3Info") or {}
        ti = _threat_intel(v.get("threatIntel"))
        sev = v.get("severity")
        base = {
            "qid": v.get("qid", ""),
            "title": v.get("title", ""),
            "category": v.get("category", ""),
            "severity": sev,
            "severity_label": _SEV_LABEL.get(sev, ""),
            "customer_severity": v.get("customerSeverity", ""),
            "risk": v.get("risk", ""),
            "qds_score": v.get("qdsScore", ""),
            "cvss2_base": (cvss2 or {}).get("baseScore", ""),
            "cvss2_vector": (cvss2 or {}).get("accessVector", ""),
            "cvss3_base": (cvss3 or {}).get("baseScore", ""),
            "cvss3_temporal": (cvss3 or {}).get("temporalScore", ""),
            "type_detected": v.get("typeDetected", ""),
            "patch_available": v.get("patchAvailable", ""),
            "is_exempted": v.get("isExempted", ""),
            "layer_sha": v.get("layerSha", ""),
            "scan_type": ",".join(v.get("scanType", []) or []),
            "first_found": _epoch_to_iso(v.get("firstFound")),
            "last_found": _epoch_to_iso(v.get("lastFound")),
            "published": _epoch_to_iso(v.get("published")),
        }
        base.update(ti)

        cves = v.get("cveids") or [""]
        packages = _packages(v)
        for cve in cves:
            rhsa = _rhsa(v.get("vendorData"), cve)
            for pkg in packages:
                row = {**ctx, **base, "cve": cve, **rhsa, **pkg}
                row["dedup_key"] = _dedup_key(
                    digest or image_sha, str(row["qid"]), cve,
                    pkg["package_name"], pkg["installed_version"],
                )
                yield row


# --------------------------------------------------------------------------- #
#  CSV columns                                                                  #
# --------------------------------------------------------------------------- #
CSV_FULL = [
    "dedup_key", "source_scope", "synthetic_asset_id", "image_sha", "image_id",
    "container_sha", "container_id", "registry", "repository", "image_tag",
    "image_digest", "operating_system", "architecture", "sensor_uuid",
    "hostname", "host_ip", "k8s_namespace", "k8s_pod", "k8s_cluster",
    "image_source", "image_criticality", "container_state",
    "qid", "cve", "title", "category", "severity", "severity_label",
    "customer_severity", "risk", "qds_score", "cvss2_base", "cvss2_vector",
    "cvss3_base", "cvss3_temporal", "type_detected", "patch_available",
    "is_exempted", "layer_sha", "scan_type", "first_found", "last_found",
    "published",
    "ti_active_attacks", "ti_zero_day", "ti_public_exploit", "ti_easy_exploit",
    "ti_exploit_kit", "ti_malware", "ti_denial_of_service",
    "ti_high_lateral_movement", "ti_high_data_loss", "ti_no_patch",
    "ti_ransomware", "exploit_available", "exploitation_state",
    "rhsa_id", "rhsa_severity", "cve_vendor_severity", "cve_vendor_cvss3",
    "package_name", "installed_version", "fixed_version", "package_path",
    "package_scan_type", "extracted_at",
]

# ETM-oriented subset (Generic CSV) — adjust to your 27-column schema as needed.
CSV_ETM = [
    "dedup_key", "synthetic_asset_id", "image_digest", "hostname",
    "k8s_namespace", "k8s_pod", "qid", "cve", "title", "severity_label",
    "qds_score", "cvss3_base", "exploitation_state", "exploit_available",
    "patch_available", "package_name", "installed_version", "fixed_version",
    "first_found", "last_found",
]


# --------------------------------------------------------------------------- #
#  Orchestration                                                               #
# --------------------------------------------------------------------------- #
def process_asset(client: QualysCSClient, scope: str, summary: dict,
                  extracted_at: str) -> List[dict]:
    sha = summary.get("sha") or summary.get("imageSha")
    if not sha:
        return []
    try:
        detail = client.asset_detail(scope, sha) or summary
        vulns = client.asset_vulns(scope, sha)
    except requests.HTTPError as exc:
        LOG.warning("Asset %s skipped (%s)", sha[:12], exc)
        return []
    return list(flatten_asset(scope, detail, vulns, extracted_at))


def run(args: argparse.Namespace) -> int:
    gateway = os.environ.get("QUALYS_GATEWAY", args.gateway or "")
    user = os.environ.get("QUALYS_USERNAME", "")
    pwd = os.environ.get("QUALYS_PASSWORD", "")
    if not (gateway and user and pwd):
        LOG.error("QUALYS_GATEWAY / QUALYS_USERNAME / QUALYS_PASSWORD required")
        return 2

    client = QualysCSClient(gateway, user, pwd)
    extracted_at = datetime.now(timezone.utc).isoformat()
    scope = args.scope

    ndjson_fh = None
    csv_fh = None
    csv_writer = None
    cols = CSV_ETM if args.etm else CSV_FULL
    if args.format in ("ndjson", "both"):
        ndjson_fh = open(f"{args.out_prefix}.ndjson", "w", encoding="utf-8")
    if args.format in ("csv", "both"):
        csv_fh = open(f"{args.out_prefix}.csv", "w", newline="", encoding="utf-8")
        csv_writer = csv.DictWriter(csv_fh, fieldnames=cols, extrasaction="ignore")
        csv_writer.writeheader()

    seen: set[str] = set()
    n_assets = n_rows = n_dupes = 0
    write_lock = threading.Lock()

    def emit(rows: List[dict]) -> None:
        nonlocal n_rows, n_dupes
        with write_lock:
            for row in rows:
                key = row["dedup_key"]
                if key in seen:
                    n_dupes += 1
                    continue
                seen.add(key)
                n_rows += 1
                if ndjson_fh:
                    ndjson_fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                if csv_writer:
                    csv_writer.writerow(row)

    LOG.info("Enumerating %s (filter=%s)...", scope, args.filter or "—")
    asset_iter = client.paginate(scope, args.page_size, args.filter,
                                 args.max_images)

    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {}
        for summary in asset_iter:
            n_assets += 1
            fut = pool.submit(process_asset, client, scope, summary, extracted_at)
            futures[fut] = summary.get("sha", "?")
            if len(futures) >= args.concurrency * 4:
                _drain(futures, emit)
        _drain(futures, emit, wait_all=True)

    for fh in (ndjson_fh, csv_fh):
        if fh:
            fh.close()

    LOG.info("Done: %d assets, %d unique rows, %d duplicates skipped",
             n_assets, n_rows, n_dupes)
    LOG.info("Outputs: %s", args.out_prefix +
             (".{ndjson,csv}" if args.format == "both" else f".{args.format}"))
    return 0


def _drain(futures: dict, emit, wait_all: bool = False) -> None:
    done = [f for f in futures if f.done()] if not wait_all else list(futures)
    if wait_all:
        for f in as_completed(futures):
            emit(f.result())
        futures.clear()
        return
    for f in done:
        emit(f.result())
        futures.pop(f, None)


# --------------------------------------------------------------------------- #
#  CLI                                                                          #
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Complete Qualys Container Security vulnerability extraction.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--gateway", help="Gateway URL (else $QUALYS_GATEWAY)")
    p.add_argument("--scope", choices=["images", "containers"], default="images",
                   help="Asset type to extract")
    p.add_argument("--filter", help="Qualys QQL filter (e.g. image.updated:[now-7d ... now])")
    p.add_argument("--page-size", type=int, default=50, help="API page size")
    p.add_argument("--max-images", type=int, default=None,
                   help="Cap the number of assets (testing)")
    p.add_argument("--concurrency", type=int, default=5,
                   help="Parallel detail/vuln worker threads")
    p.add_argument("--format", choices=["ndjson", "csv", "both"], default="both")
    p.add_argument("--etm", action="store_true",
                   help="Reduced ETM-schema CSV (else full schema)")
    p.add_argument("--out-prefix", default="qcs_vulns",
                   help="Output file prefix")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main() -> None:
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    try:
        sys.exit(run(args))
    except KeyboardInterrupt:
        LOG.warning("Interrupted")
        sys.exit(130)


if __name__ == "__main__":
    main()
