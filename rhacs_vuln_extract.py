#!/usr/bin/env python3
"""
rhacs_vuln_extract.py  (EN)
===========================
Extract image vulnerabilities from RHACS / StackRox Central (the storage.Image
graph behind the /v1/ API) and emit the SAME normalized NDJSON/CSV schema as
qcs_vuln_extract.py — so the output drops straight into qualys_vuln_loader.py
and gets pushed to Qualys ETM. Pipeline:

    RHACS API ──[this script]──> qcs-schema NDJSON/CSV ──[qualys_vuln_loader.py]──> Qualys ETM

One row per granular detection: image x CVE x affected component(package).
RHACS is CVE-native (no QID), so `qid` is left empty — the loader uses the CVE
as the finding id, which is exactly what ETM expects from a non-Qualys source.

Source:
    GET /v1/export/images            (streamed NDJSON of {"image": storage.Image})
    fallback: /v1/images + /v1/images/{id}
    optional: /v1/export/deployments to attach cluster/namespace/deployment
              context (the synthetic hostname cluster/namespace/deployment).

Dependency: requests

Environment:
    ROX_ENDPOINT      e.g. central.stackrox.example.com:443   (no scheme)
    ROX_API_TOKEN     RHACS API token (role with Image read access)

Examples:
    # all images, attach deployment context, ETM-oriented CSV + NDJSON
    python rhacs_vuln_extract.py --with-deployments --insecure

    # only fixable CRITICAL/IMPORTANT vulns via RHACS query
    python rhacs_vuln_extract.py \\
        --query "Fixable:true+Severity:CRITICAL_VULNERABILITY_SEVERITY"
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Iterator, List, Optional

try:
    import requests
except ImportError:
    sys.exit("Missing 'requests' module: pip install requests")

LOG = logging.getLogger("rhacs_extract")
RETRY_STATUS = {429, 500, 502, 503, 504}

# RHACS severity enum -> (label, numeric 1..5 like the shared schema)
_SEV = {
    "LOW_VULNERABILITY_SEVERITY": ("LOW", 2),
    "MODERATE_VULNERABILITY_SEVERITY": ("MEDIUM", 3),
    "IMPORTANT_VULNERABILITY_SEVERITY": ("HIGH", 4),
    "CRITICAL_VULNERABILITY_SEVERITY": ("CRITICAL", 5),
}
_EXEMPT_STATES = {"DEFERRED", "FALSE_POSITIVE"}


# --------------------------------------------------------------------------- #
#  RHACS Central client                                                        #
# --------------------------------------------------------------------------- #
class RHACSClient:
    def __init__(self, endpoint: str, token: str, verify: bool = True,
                 timeout: int = 120, max_retries: int = 5):
        base = endpoint if endpoint.startswith("http") else f"https://{endpoint}"
        self.base = base.rstrip("/")
        self.timeout, self.max_retries = timeout, max_retries
        self._s = requests.Session()
        self._s.headers.update({"Authorization": f"Bearer {token}",
                                "Accept": "application/json"})
        self._s.verify = verify
        if not verify:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _request(self, method: str, path: str, *, stream: bool = False,
                 params: Optional[dict] = None) -> requests.Response:
        url = f"{self.base}{path}"
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = self._s.request(method, url, params=params, stream=stream,
                                       timeout=self.timeout)
            except requests.RequestException as exc:
                if attempt > self.max_retries:
                    raise
                wait = min(2 ** attempt, 30)
                LOG.warning("Network error (%s) — retry in %ss", exc, wait)
                time.sleep(wait)
                continue
            if resp.status_code in RETRY_STATUS and attempt <= self.max_retries:
                wait = int(resp.headers.get("Retry-After", min(2 ** attempt, 30)))
                LOG.warning("HTTP %s on %s — retry in %ss",
                            resp.status_code, path, wait)
                time.sleep(wait)
                continue
            resp.raise_for_status()
            return resp

    # -- streaming export of full storage.Image objects ---------------------- #
    def export_images(self, query: Optional[str]) -> Iterator[dict]:
        params = {"query": query} if query else None
        resp = self._request("GET", "/v1/export/images", stream=True, params=params)
        for line in resp.iter_lines(decode_unicode=True):
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            # grpc-gateway wraps stream items as {"result": {...}}
            if isinstance(obj, dict) and "result" in obj:
                obj = obj["result"]
            img = obj.get("image") if isinstance(obj, dict) else None
            if img:
                yield img

    # -- paginated fallback (list ids, then fetch detail) -------------------- #
    def list_image_ids(self, query: Optional[str], page_size: int) -> Iterator[str]:
        offset = 0
        while True:
            params = {"pagination.limit": page_size, "pagination.offset": offset}
            if query:
                params["query"] = query
            data = self._request("GET", "/v1/images", params=params).json()
            rows = data.get("images", []) if isinstance(data, dict) else []
            if not rows:
                break
            for r in rows:
                if r.get("id"):
                    yield r["id"]
            if len(rows) < page_size:
                break
            offset += page_size

    def get_image(self, image_id: str) -> dict:
        return self._request("GET", f"/v1/images/{image_id}").json()

    # -- deployment context map: image_id -> (cluster, namespace, deployment) - #
    def deployment_context(self) -> Dict[str, Dict[str, str]]:
        mapping: Dict[str, Dict[str, str]] = {}
        try:
            resp = self._request("GET", "/v1/export/deployments", stream=True)
        except requests.HTTPError as exc:
            LOG.warning("Deployment export unavailable (%s) — skipping context", exc)
            return mapping
        for line in resp.iter_lines(decode_unicode=True):
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if "result" in obj:
                obj = obj["result"]
            dep = obj.get("deployment") if isinstance(obj, dict) else None
            if not dep:
                continue
            ctx = {"k8s_cluster": dep.get("clusterName", ""),
                   "k8s_namespace": dep.get("namespace", ""),
                   "deployment": dep.get("name", "")}
            for c in dep.get("containers", []) or []:
                img = (c.get("image") or {})
                iid = img.get("id") or (img.get("name") or {}).get("fullName")
                if iid and iid not in mapping:
                    mapping[iid] = ctx
        LOG.info("Deployment context: %d image references mapped", len(mapping))
        return mapping


# --------------------------------------------------------------------------- #
#  Helpers                                                                      #
# --------------------------------------------------------------------------- #
def _digest(image: dict) -> str:
    md = image.get("metadata") or {}
    for key in ("v2", "v1"):
        d = (md.get(key) or {}).get("digest")
        if d:
            return d
    return ""


def _name_parts(image: dict) -> Dict[str, str]:
    n = image.get("name") or {}
    return {"registry": n.get("registry", ""), "repository": n.get("remote", ""),
            "image_tag": n.get("tag", ""), "full_name": n.get("fullName", "")}


def _iso(value: Any) -> str:
    """RHACS timestamps are already RFC3339 strings; pass through cleanly."""
    return str(value).strip() if value else ""


def _dedup_key(*parts: str) -> str:
    return hashlib.sha256("|".join(p or "" for p in parts).encode()).hexdigest()


# --------------------------------------------------------------------------- #
#  Flatten one image into shared-schema detection rows                         #
# --------------------------------------------------------------------------- #
def flatten_image(image: dict, dep_ctx: Dict[str, Dict[str, str]],
                  extracted_at: str) -> Iterator[dict]:
    name = _name_parts(image)
    digest = _digest(image)
    image_sha = image.get("id") or digest
    scan = image.get("scan") or {}
    operating_system = scan.get("operatingSystem", "")

    ctx_k8s = dep_ctx.get(image_sha) or dep_ctx.get(name["full_name"]) or {}
    cluster = ctx_k8s.get("k8s_cluster", "")
    namespace = ctx_k8s.get("k8s_namespace", "")
    deployment = ctx_k8s.get("deployment", "")
    if deployment:
        synthetic = f"{cluster}/{namespace}/{deployment}".strip("/")
    else:
        ref = name["repository"] or image_sha
        synthetic = f"{name['registry']}/{ref}:{name['image_tag'] or 'latest'}".strip("/")

    ctx = {
        "source_scope": "images",
        "image_sha": image_sha,
        "image_id": image_sha[:12] if image_sha else "",
        "container_sha": "",
        "container_id": "",
        "synthetic_asset_id": synthetic,
        "registry": name["registry"],
        "repository": name["repository"],
        "image_tag": name["image_tag"],
        "image_digest": digest,
        "operating_system": operating_system,
        "architecture": "",
        "sensor_uuid": "",
        "hostname": "",
        "host_ip": "",
        "k8s_namespace": namespace,
        "k8s_pod": deployment,       # RHACS asset granularity = deployment, not pod
        "k8s_cluster": cluster,
        "image_source": "RHACS",
        "image_criticality": "",
        "container_state": "",
        "extracted_at": extracted_at,
    }

    for comp in scan.get("components", []) or []:
        pkg_name = comp.get("name", "")
        pkg_ver = comp.get("version", "")
        comp_source = comp.get("source", "")
        comp_path = comp.get("location", "")
        comp_fixed = comp.get("fixedBy", "")
        for v in comp.get("vulns", []) or []:
            cve = v.get("cve", "")
            sev_label, sev_num = _SEV.get(v.get("severity", ""), ("", ""))
            cvss3 = v.get("cvssV3") or {}
            cvss2 = v.get("cvssV2") or {}
            epss = v.get("epss") or {}
            advisory = v.get("advisory") or {}
            fixed_by = v.get("fixedBy") or comp_fixed
            adv_name = advisory.get("name", "")
            row = {
                **ctx,
                "qid": "",                       # RHACS is CVE-native (no QID)
                "cve": cve,
                "title": v.get("summary", "") or cve,
                "category": comp_source,
                "severity": sev_num,
                "severity_label": sev_label,
                "customer_severity": "",
                "risk": "",
                "qds_score": "",
                "cvss2_base": cvss2.get("score", v.get("cvss", "")),
                "cvss2_vector": cvss2.get("vector", ""),
                "cvss3_base": cvss3.get("score", ""),
                "cvss3_temporal": "",
                "nvd_cvss": v.get("nvdCvss", ""),
                "type_detected": "",
                "patch_available": bool(fixed_by),
                "is_exempted": v.get("state", "OBSERVED") in _EXEMPT_STATES,
                "vuln_state": v.get("state", "OBSERVED"),
                "layer_sha": "",
                "scan_type": comp_source,
                "first_found": _iso(v.get("firstImageOccurrence")
                                    or v.get("firstSystemOccurrence")),
                "last_found": _iso(v.get("lastModified")),
                "published": _iso(v.get("publishedOn")),
                # threat-intel placeholders (RHACS has no native RTI; enrich later)
                "ti_active_attacks": False, "ti_zero_day": False,
                "ti_public_exploit": False, "ti_easy_exploit": False,
                "ti_exploit_kit": False, "ti_malware": False,
                "ti_denial_of_service": False, "ti_high_lateral_movement": False,
                "ti_high_data_loss": False, "ti_no_patch": False,
                "ti_ransomware": False,
                "exploit_available": False,
                "exploitation_state": "NONE",
                "epss_probability": epss.get("epssProbability", ""),
                "epss_percentile": epss.get("epssPercentile", ""),
                "rhsa_id": adv_name if adv_name.startswith("RHSA") else "",
                "rhsa_severity": "",
                "cve_vendor_severity": "",
                "cve_vendor_cvss3": "",
                "advisory_link": advisory.get("link", ""),
                "package_name": pkg_name,
                "installed_version": pkg_ver,
                "fixed_version": fixed_by,
                "package_path": comp_path,
                "package_scan_type": comp_source,
            }
            row["dedup_key"] = _dedup_key(
                digest or image_sha, cve, pkg_name, pkg_ver)
            yield row


# Shared schema (identical to qcs_vuln_extract) + RHACS extras (epss, advisory).
CSV_FULL = [
    "dedup_key", "source_scope", "synthetic_asset_id", "image_sha", "image_id",
    "container_sha", "container_id", "registry", "repository", "image_tag",
    "image_digest", "operating_system", "architecture", "sensor_uuid",
    "hostname", "host_ip", "k8s_namespace", "k8s_pod", "k8s_cluster",
    "image_source", "image_criticality", "container_state",
    "qid", "cve", "title", "category", "severity", "severity_label",
    "customer_severity", "risk", "qds_score", "cvss2_base", "cvss2_vector",
    "cvss3_base", "cvss3_temporal", "nvd_cvss", "type_detected",
    "patch_available", "is_exempted", "vuln_state", "layer_sha", "scan_type",
    "first_found", "last_found", "published",
    "ti_active_attacks", "ti_zero_day", "ti_public_exploit", "ti_easy_exploit",
    "ti_exploit_kit", "ti_malware", "ti_denial_of_service",
    "ti_high_lateral_movement", "ti_high_data_loss", "ti_no_patch",
    "ti_ransomware", "exploit_available", "exploitation_state",
    "epss_probability", "epss_percentile", "rhsa_id", "rhsa_severity",
    "cve_vendor_severity", "cve_vendor_cvss3", "advisory_link",
    "package_name", "installed_version", "fixed_version", "package_path",
    "package_scan_type", "extracted_at",
]
CSV_ETM = [
    "dedup_key", "synthetic_asset_id", "image_digest", "k8s_namespace", "k8s_pod",
    "k8s_cluster", "cve", "title", "severity_label", "cvss3_base",
    "epss_probability", "exploitation_state", "exploit_available",
    "patch_available", "package_name", "installed_version", "fixed_version",
    "first_found",
]


# --------------------------------------------------------------------------- #
#  Orchestration                                                               #
# --------------------------------------------------------------------------- #
def iter_images(client: RHACSClient, args: argparse.Namespace) -> Iterator[dict]:
    if args.fallback:
        ids = client.list_image_ids(args.query, args.page_size)
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            futures = {}
            for iid in ids:
                futures[pool.submit(client.get_image, iid)] = iid
                if len(futures) >= args.concurrency * 4:
                    for f in [x for x in futures if x.done()]:
                        try:
                            yield f.result()
                        except requests.HTTPError as exc:
                            LOG.warning("image skipped (%s)", exc)
                        futures.pop(f)
            for f in as_completed(futures):
                try:
                    yield f.result()
                except requests.HTTPError as exc:
                    LOG.warning("image skipped (%s)", exc)
    else:
        yield from client.export_images(args.query)


def run(args: argparse.Namespace) -> int:
    endpoint = os.environ.get("ROX_ENDPOINT", args.endpoint or "")
    token = os.environ.get("ROX_API_TOKEN", "")
    if not (endpoint and token):
        LOG.error("ROX_ENDPOINT and ROX_API_TOKEN are required")
        return 2

    client = RHACSClient(endpoint, token, verify=not args.insecure)
    extracted_at = datetime.now(timezone.utc).isoformat()
    dep_ctx = client.deployment_context() if args.with_deployments else {}

    cols = CSV_ETM if args.etm else CSV_FULL
    ndjson_fh = open(f"{args.out_prefix}.ndjson", "w", encoding="utf-8") \
        if args.format in ("ndjson", "both") else None
    csv_w = None
    csv_fh = None
    if args.format in ("csv", "both"):
        csv_fh = open(f"{args.out_prefix}.csv", "w", newline="", encoding="utf-8")
        csv_w = csv.DictWriter(csv_fh, fieldnames=cols, extrasaction="ignore")
        csv_w.writeheader()

    seen: set[str] = set()
    n_img = n_rows = n_dupes = 0
    for image in iter_images(client, args):
        n_img += 1
        for row in flatten_image(image, dep_ctx, extracted_at):
            key = row["dedup_key"]
            if key in seen:
                n_dupes += 1
                continue
            seen.add(key)
            n_rows += 1
            if ndjson_fh:
                ndjson_fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            if csv_w:
                csv_w.writerow(row)
        if args.max_images and n_img >= args.max_images:
            break

    for fh in (ndjson_fh, csv_fh):
        if fh:
            fh.close()
    LOG.info("Done: %d images, %d unique rows, %d duplicates skipped",
             n_img, n_rows, n_dupes)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Extract RHACS image vulnerabilities into the shared "
                    "(qcs) schema for the Qualys loader.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--endpoint", help="Central endpoint (else $ROX_ENDPOINT)")
    p.add_argument("--query", help="RHACS search query (e.g. Fixable:true)")
    p.add_argument("--with-deployments", action="store_true",
                   help="Attach cluster/namespace/deployment context")
    p.add_argument("--fallback", action="store_true",
                   help="Use /v1/images list+detail instead of /v1/export/images")
    p.add_argument("--insecure", action="store_true",
                   help="Disable TLS verification (self-signed Central)")
    p.add_argument("--page-size", type=int, default=100)
    p.add_argument("--concurrency", type=int, default=5)
    p.add_argument("--max-images", type=int, default=None)
    p.add_argument("--format", choices=["ndjson", "csv", "both"], default="both")
    p.add_argument("--etm", action="store_true", help="Reduced ETM-schema CSV")
    p.add_argument("--out-prefix", default="rhacs_vulns")
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
