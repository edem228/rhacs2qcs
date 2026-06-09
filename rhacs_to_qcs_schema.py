#!/usr/bin/env python3
"""
rhacs_to_qcs_schema.py
======================
Transforms the RHACS vulnerability report (Vulnerability Reporting CSV or
API export) into a schema aligned with Qualys Container Security (QCS,
csapi/v1.3), for ingestion through the ETM Generic CSV connector.

ARCHITECTURE NOTE: QCS does not provide an ingestion API for external
findings. The import target is therefore ETM (Generic CSV / S3), using a
column schema consistent with QCS exports to make reconciliation easier.

Implemented mapping (see mapping-rhacs-qcs.md):
  RHACS Cluster        -> cluster.name
  RHACS Namespace      -> cluster.k8s.pod.namespace
  RHACS Deployment     -> cluster.k8s.pod.controller[0].name
  RHACS Image          -> repo.registry / repo.repository / repo.tag (+ sha if available)
  RHACS Component      -> software.name / software.version
  RHACS CVE            -> cveids (1 RHACS row = 1 CVE; no synthesized QID)
  RHACS Fixable        -> patchAvailable (bool)
  RHACS Fixed In Ver.  -> software.fixVersion
  RHACS Severity       -> severity (QCS 1-5 scale)
  RHACS CVSS           -> cvss3.baseScore
  RHACS Discovered     -> firstFound (epoch ms)

Usage:
  # From an RHACS report CSV
  python rhacs_to_qcs_schema.py --input rhacs_report.csv --output qcs_aligned.csv

  # From the RHACS API (reuses the rhacs_to_etm.py extraction logic)
  python rhacs_to_qcs_schema.py --from-api --central https://central.redhat.com \
      --output qcs_aligned.csv

  # With S3 upload for the ETM connector
  python rhacs_to_qcs_schema.py --input rhacs_report.csv \
      --output qcs_aligned.csv --s3-bucket my-bucket --s3-prefix etm/rhacs/
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import sys
from dataclasses import dataclass, asdict, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("rhacs2qcs")

# ---------------------------------------------------------------------------
# 1. QCS-aligned output schema (csapi/v1.3)
# ---------------------------------------------------------------------------

@dataclass
class QcsAlignedFinding:
    """One output row = 1 finding at the (image, package, CVE) grain,
    using QCS field names for consistency with csapi exports."""

    # --- Cluster context (carried by the Container in QCS) ---
    cluster_name: str = ""                    # cluster.name
    cluster_k8s_pod_namespace: str = ""       # cluster.k8s.pod.namespace
    cluster_k8s_pod_controller_name: str = "" # cluster.k8s.pod.controller[0].name
    cluster_k8s_pod_controller_type: str = "" # controller[0].type (if known)

    # --- Image identity (QCS Image object) ---
    image_sha: str = ""                       # sha / imageId (digest, dedup key)
    repo_registry: str = ""                   # repo[].registry
    repo_repository: str = ""                 # repo[].repository
    repo_tag: str = ""                        # repo[].tag
    image_full_name: str = ""                 # rebuilt for traceability

    # --- Detection (QCS vulnerability object) ---
    cveids: str = ""                          # cveids[] -> 1 CVE per row here
    qid: str = ""                             # empty: cannot be synthesized without the Qualys KB
    severity: str = ""                        # QCS 1-5 scale
    severity_label_rhacs: str = ""            # original RHACS severity (traceability)
    cvss3_base_score: str = ""                # cvss3Info.baseScore
    patch_available: str = ""                 # patchAvailable (true/false)
    first_found: str = ""                     # epoch ms
    first_found_iso: str = ""                 # human-readable

    # --- Package (vulnerability.software[]) ---
    software_name: str = ""                   # software[].name
    software_version: str = ""                # software[].version
    software_fix_version: str = ""            # software[].fixVersion

    # --- Source traceability ---
    source: str = "RHACS"
    reference: str = ""                       # CVE link from the RHACS report

    # Finding key for ETM dedup: (sha, package, version, cve)
    finding_key: str = ""

    def compute_key(self) -> None:
        self.finding_key = "|".join(
            [self.image_sha or self.image_full_name,
             self.software_name, self.software_version, self.cveids]
        )


CSV_HEADERS = [f.name for f in fields(QcsAlignedFinding)]

# ---------------------------------------------------------------------------
# 2. Conversions
# ---------------------------------------------------------------------------

# RHACS -> QCS 1-5 scale (documented approximation: native QCS severity is
# derived from the QID, not the CVE; the original label is kept alongside)
SEVERITY_MAP = {
    "CRITICAL": "5", "CRITICAL_VULNERABILITY_SEVERITY": "5",
    "IMPORTANT": "4", "IMPORTANT_VULNERABILITY_SEVERITY": "4", "HIGH": "4",
    "MODERATE": "3", "MODERATE_VULNERABILITY_SEVERITY": "3", "MEDIUM": "3",
    "LOW": "2", "LOW_VULNERABILITY_SEVERITY": "2",
    "UNKNOWN": "1",
}

# registry/repository:tag -> (registry, repository, tag)
# Handles: quay.io/org/app:1.2, registry:5000/app:tag, app:tag, app@sha256:...
IMAGE_RE = re.compile(
    r"^(?:(?P<registry>[^/]+\.[^/]+|[^/]+:\d+)/)?"   # registry if it contains . or :port
    r"(?P<repository>[^@:]+(?:/[^@:]+)*)"
    r"(?::(?P<tag>[^@]+))?"
    r"(?:@(?P<digest>sha256:[0-9a-f]{64}))?$"
)


def parse_image_ref(full: str) -> dict:
    """Splits an image reference the way QCS repo[] does."""
    full = (full or "").strip()
    m = IMAGE_RE.match(full)
    if not m:
        return {"registry": "", "repository": full, "tag": "", "digest": ""}
    d = m.groupdict()
    return {
        "registry": d.get("registry") or "docker.io",
        "repository": d.get("repository") or "",
        "tag": d.get("tag") or "",
        "digest": d.get("digest") or "",
    }


def to_epoch_ms(value: str) -> tuple[str, str]:
    """RHACS date (ISO 8601 or 'Jan 02, 2006') -> (epoch_ms, iso). Lenient."""
    value = (value or "").strip()
    if not value:
        return "", ""
    fmts = ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%d", "%b %d, %Y", "%d %b %Y", "%b %d %Y", "%m/%d/%Y"]
    for fmt in fmts:
        try:
            dt = datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
            return str(int(dt.timestamp() * 1000)), dt.isoformat()
        except ValueError:
            continue
    log.warning("Unrecognized date: %r (kept as-is)", value)
    return "", value


def to_bool_str(value: str) -> str:
    v = (value or "").strip().lower()
    if v in ("true", "fixable", "yes", "1"):
        return "true"
    if v in ("false", "not fixable", "unfixable", "no", "0", ""):
        return "false"
    return "false"

# ---------------------------------------------------------------------------
# 3. Reading the RHACS report (CSV)
# ---------------------------------------------------------------------------

# Header tolerance: the RHACS report may vary across versions/locales
HEADER_ALIASES = {
    "cluster": "cluster",
    "namespace": "namespace",
    "deployment": "deployment",
    "image": "image",
    "component": "component",
    "cve": "cve",
    "fixable": "fixable",
    "cve fixed in version": "fixed_version",
    "component upgrade": "fixed_version",
    "severity": "severity",
    "cvss": "cvss",
    "discovered date": "discovered",
    "first discovered": "discovered",
    "reference": "reference",
    "link": "reference",
}


def normalize_headers(headers: list[str]) -> dict[int, str]:
    """Indexes the RHACS CSV columns onto our internal keys."""
    mapping: dict[int, str] = {}
    for i, h in enumerate(headers):
        key = HEADER_ALIASES.get(h.strip().lower())
        if key:
            mapping[i] = key
    missing = {"cluster", "image", "cve"} - set(mapping.values())
    if missing:
        raise SystemExit(f"RHACS columns not found in the CSV: {missing}. "
                         f"Headers read: {headers}")
    return mapping


def read_rhacs_csv(path: Path) -> Iterator[dict]:
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.reader(fh)
        headers = next(reader)
        colmap = normalize_headers(headers)
        for raw in reader:
            row = {colmap[i]: raw[i].strip() for i in colmap if i < len(raw)}
            if row.get("cve"):
                yield row

# ---------------------------------------------------------------------------
# 4. Reading from the RHACS API (optional, same grain as the report)
# ---------------------------------------------------------------------------

def read_rhacs_api(central: str, token: str, verify: bool = True) -> Iterator[dict]:
    """API extraction at the same grain as the report:
    deployments -> images -> components -> vulns. Reuses the classic
    pagination from rhacs_to_etm.py (simplified version)."""
    import requests  # local import: optional dependency

    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {token}"
    s.verify = verify

    def get(path: str, **params):
        r = s.get(f"{central.rstrip('/')}{path}", params=params, timeout=60)
        r.raise_for_status()
        return r.json()

    deployments = get("/v1/deployments").get("deployments", [])
    log.info("RHACS API: %d deployments", len(deployments))

    for dep in deployments:
        detail = get(f"/v1/deployments/{dep['id']}")
        for c in detail.get("containers", []):
            img_id = (c.get("image") or {}).get("id")
            if not img_id:
                continue
            img = get(f"/v1/images/{img_id}")
            full = ((img.get("name") or {}).get("fullName")) or ""
            for comp in (img.get("scan") or {}).get("components", []):
                for v in comp.get("vulns", []):
                    yield {
                        "cluster": detail.get("clusterName", ""),
                        "namespace": detail.get("namespace", ""),
                        "deployment": detail.get("name", ""),
                        "deployment_type": detail.get("type", ""),
                        "image": full,
                        "image_sha": img.get("id", ""),
                        "component": comp.get("name", ""),
                        "component_version": comp.get("version", ""),
                        "cve": v.get("cve", ""),
                        "fixable": "true" if v.get("fixedBy") else "false",
                        "fixed_version": v.get("fixedBy", ""),
                        "severity": v.get("severity", ""),
                        "cvss": str(v.get("cvss", "")),
                        "discovered": v.get("firstImageOccurrence", ""),
                        "reference": v.get("link", ""),
                    }

# ---------------------------------------------------------------------------
# 5. Transformation -> QCS schema
# ---------------------------------------------------------------------------

def transform(row: dict) -> QcsAlignedFinding:
    ref = parse_image_ref(row.get("image", ""))
    epoch_ms, iso = to_epoch_ms(row.get("discovered", ""))
    sev_raw = (row.get("severity") or "").upper()

    f = QcsAlignedFinding(
        cluster_name=row.get("cluster", ""),
        cluster_k8s_pod_namespace=row.get("namespace", ""),
        cluster_k8s_pod_controller_name=row.get("deployment", ""),
        cluster_k8s_pod_controller_type=row.get("deployment_type", ""),
        image_sha=row.get("image_sha", "") or ref["digest"],
        repo_registry=ref["registry"],
        repo_repository=ref["repository"],
        repo_tag=ref["tag"],
        image_full_name=row.get("image", ""),
        cveids=row.get("cve", ""),
        severity=SEVERITY_MAP.get(sev_raw, "1"),
        severity_label_rhacs=sev_raw,
        cvss3_base_score=row.get("cvss", ""),
        patch_available=to_bool_str(row.get("fixable", "")),
        first_found=epoch_ms,
        first_found_iso=iso,
        software_name=row.get("component", ""),
        software_version=row.get("component_version", ""),
        software_fix_version=row.get("fixed_version", ""),
        reference=row.get("reference", ""),
    )
    f.compute_key()
    return f

# ---------------------------------------------------------------------------
# 6. Writing + optional S3 upload
# ---------------------------------------------------------------------------

def write_csv(findings: Iterator[QcsAlignedFinding], out: Path) -> int:
    seen: set[str] = set()
    n = 0
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_HEADERS)
        w.writeheader()
        for f in findings:
            if f.finding_key in seen:        # dedup at the (sha, pkg, ver, cve) grain
                continue
            seen.add(f.finding_key)
            w.writerow(asdict(f))
            n += 1
    return n


def upload_s3(path: Path, bucket: str, prefix: str) -> str:
    import boto3  # optional dependency
    key = f"{prefix.rstrip('/')}/{path.name}"
    boto3.client("s3").upload_file(str(path), bucket, key)
    return f"s3://{bucket}/{key}"

# ---------------------------------------------------------------------------
# 7. CLI
# ---------------------------------------------------------------------------

def main() -> None:
    p = argparse.ArgumentParser(description="RHACS report -> QCS schema -> ETM CSV")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--input", type=Path, help="RHACS report CSV")
    src.add_argument("--from-api", action="store_true", help="Extract via the RHACS API")
    p.add_argument("--central", help="RHACS Central URL (API mode)")
    p.add_argument("--output", type=Path, required=True, help="Output CSV")
    p.add_argument("--s3-bucket", help="Target S3 bucket (ETM connector)")
    p.add_argument("--s3-prefix", default="etm/rhacs", help="S3 prefix")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification (API)")
    args = p.parse_args()

    if args.from_api:
        token = os.environ.get("ROX_API_TOKEN")
        if not (args.central and token):
            sys.exit("API mode: --central required and ROX_API_TOKEN set in the environment.")
        rows = read_rhacs_api(args.central, token, verify=not args.insecure)
    else:
        rows = read_rhacs_csv(args.input)

    count = write_csv((transform(r) for r in rows), args.output)
    log.info("Wrote %d deduplicated findings -> %s", count, args.output)

    if args.s3_bucket:
        uri = upload_s3(args.output, args.s3_bucket, args.s3_prefix)
        log.info("S3 upload: %s", uri)


if __name__ == "__main__":
    main()