#!/usr/bin/env python3
"""
Supprime dans Qualys (CSAM / ETM) les assets Prisma sans IP, identifiés par un tag statique.

Dry-run par défaut : liste les candidats dans un CSV. --apply pour supprimer réellement.

.env attendu :
    QUALYS_API_URL=https://qualysapi.qualys.eu
    QUALYS_USERNAME=...
    QUALYS_PASSWORD=...

Usage :
    python qualys_purge_no_ip_assets.py --tag "Prisma-NoIP"                 # dry-run
    python qualys_purge_no_ip_assets.py --tag "Prisma-NoIP" --apply --max 100
    python qualys_purge_no_ip_assets.py --tag "Prisma-NoIP" --apply --yes
"""

import argparse
import csv
import os
import sys
import time
import xml.etree.ElementTree as ET
from typing import Iterator

import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PAGE_SIZE = 1000      # max par page de recherche QPS
DELETE_BATCH = 200    # ids par appel de suppression
EXCLUDED_TRACKING = {"AGENT", "QAGENT"}   # jamais supprimés, même taggés


class Qualys:
    def __init__(self, url: str, user: str, password: str):
        self.base = url.rstrip("/") + "/qps/rest/2.0"
        self.s = requests.Session()
        self.s.auth = (user, password)
        self.s.verify = False
        self.s.headers.update({"X-Requested-With": "python", "Content-Type": "text/xml"})

    def post(self, path: str, body: str) -> ET.Element:
        r = self.s.post(self.base + path, data=body.encode(), timeout=120)
        r.raise_for_status()
        root = ET.fromstring(r.content)
        if root.findtext("responseCode") != "SUCCESS":
            raise RuntimeError(root.findtext("responseErrorDetails/errorMessage") or r.text[:300])
        return root

    def search(self, obj: str, tag: str) -> Iterator[dict]:
        """Itère sur tous les assets portant le tag (pagination par id croissant)."""
        last_id = 0
        while True:
            body = (f"<ServiceRequest><preferences><limitResults>{PAGE_SIZE}</limitResults></preferences>"
                    f"<filters><Criteria field='tagName' operator='EQUALS'>{tag}</Criteria>"
                    f"<Criteria field='id' operator='GREATER'>{last_id}</Criteria></filters></ServiceRequest>")
            root = self.post(f"/search/am/{obj}", body)
            items = root.findall("data/*")
            for el in items:
                yield parse(el)
                last_id = int(el.findtext("id"))
            if not items or root.findtext("hasMoreRecords") != "true":
                return

    def delete(self, obj: str, ids: list[int]) -> int:
        body = (f"<ServiceRequest><filters><Criteria field='id' operator='IN'>"
                f"{','.join(map(str, ids))}</Criteria></filters></ServiceRequest>")
        return int(self.post(f"/delete/am/{obj}", body).findtext("count") or 0)


def parse(el: ET.Element) -> dict:
    ips = {el.findtext("address") or ""} | {i.findtext("address") or "" for i in el.iter("HostAssetInterface")}
    return {
        "id": int(el.findtext("id")),
        "name": el.findtext("name") or "",
        "ips": "|".join(sorted(ips - {""})),
        "tracking": el.findtext("trackingMethod") or "",
        "sources": "|".join(s.findtext("name") or "" for s in el.iter("AssetSource")),
        "created": el.findtext("created") or "",
    }


def main() -> None:
    load_dotenv()
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--tag", required=True, help="Tag statique posé sur les assets à supprimer")
    p.add_argument("--asset-type", choices=["hostasset", "asset"], default="hostasset")
    p.add_argument("--require-source", default="Palo Alto", help="Sous-chaîne attendue dans la source (garde-fou)")
    p.add_argument("--no-ip-check", action="store_true", help="Ne pas re-vérifier l'absence d'IP")
    p.add_argument("--apply", action="store_true", help="Supprimer réellement (sinon dry-run)")
    p.add_argument("--max", type=int, default=0, help="Plafond de suppressions (0 = illimité)")
    p.add_argument("--yes", action="store_true", help="Pas de confirmation interactive")
    p.add_argument("-o", "--output", default="qualys_purge_candidates.csv")
    a = p.parse_args()

    try:
        q = Qualys(os.environ["QUALYS_API_URL"], os.environ["QUALYS_USERNAME"], os.environ["QUALYS_PASSWORD"])
    except KeyError as k:
        sys.exit(f"Variable manquante dans .env : {k}")

    # 1. Candidats : tag + sans IP + bonne source + pas un agent
    candidates = [
        x for x in q.search(a.asset_type, a.tag)
        if (a.no_ip_check or not x["ips"])
        and a.require_source.lower() in x["sources"].lower()
        and x["tracking"].upper() not in EXCLUDED_TRACKING
    ]
    if a.max:
        candidates = candidates[:a.max]

    with open(a.output, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(candidates[0]) if candidates else ["id"])
        w.writeheader()
        w.writerows(candidates)
    print(f"{len(candidates)} candidat(s) -> {a.output}")

    if not candidates or not a.apply:
        print("Dry-run : rien supprimé." if candidates else "Aucun candidat.")
        return
    if not a.yes and input(f"Supprimer {len(candidates)} asset(s) ? Tapez DELETE : ").strip() != "DELETE":
        sys.exit("Annulé.")

    # 2. Suppression par lots d'ids explicites
    ids, done = [x["id"] for x in candidates], 0
    for i in range(0, len(ids), DELETE_BATCH):
        try:
            done += q.delete(a.asset_type, ids[i:i + DELETE_BATCH])
            print(f"  {done}/{len(ids)} supprimés")
        except RuntimeError as e:
            print(f"  lot {i // DELETE_BATCH + 1} en erreur : {e}", file=sys.stderr)
        time.sleep(1)
    print(f"Terminé : {done} asset(s) supprimé(s).")


if __name__ == "__main__":
    main()