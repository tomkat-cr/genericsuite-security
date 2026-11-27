#!/usr/bin/env python3
"""Parse OPTIMJACK_Complete_IOC_Intelligence_*.xlsx into a JSON IOC pack.

Stdlib only (zipfile + ElementTree). Writes the same shape consumed by
scan_runtime_supply_chain.py --optimjack-json / the shipped
iocs/optimjack-2026-11-17.json.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
REL_NS = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"


def _col_row(ref: str) -> Tuple[int, int]:
    m = re.match(r"([A-Z]+)(\d+)", ref)
    if not m:
        raise ValueError(ref)
    col, row = m.group(1), int(m.group(2))
    n = 0
    for c in col:
        n = n * 26 + (ord(c) - 64)
    return n - 1, row - 1


def _load_sheets(xlsx: Path) -> Dict[str, List[List[str]]]:
    with zipfile.ZipFile(xlsx) as z:
        shared: List[str] = []
        if "xl/sharedStrings.xml" in z.namelist():
            root = ET.fromstring(z.read("xl/sharedStrings.xml"))
            for si in root.findall("m:si", NS):
                texts = [
                    t.text or ""
                    for t in si.iter(
                        "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t"
                    )
                ]
                shared.append("".join(texts))
        wb = ET.fromstring(z.read("xl/workbook.xml"))
        sheets = []
        for sh in wb.findall("m:sheets/m:sheet", NS):
            sheets.append((sh.attrib.get("name"), sh.attrib.get(REL_NS + "id")))
        rels = ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))
        rid_to_target = {rel.attrib["Id"]: rel.attrib["Target"] for rel in rels}
        out: Dict[str, List[List[str]]] = {}
        for name, rid in sheets:
            target = rid_to_target[rid]
            path = "xl/" + target.lstrip("/")
            root = ET.fromstring(z.read(path))
            rows: Dict[int, Dict[int, str]] = defaultdict(dict)
            max_c = 0
            for c in root.iter(
                "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}c"
            ):
                ref = c.attrib.get("r")
                if not ref:
                    continue
                ci, ri = _col_row(ref)
                max_c = max(max_c, ci)
                t = c.attrib.get("t")
                v = c.find("m:v", NS)
                is_el = c.find("m:is", NS)
                val = ""
                if t == "s" and v is not None and v.text is not None:
                    val = shared[int(v.text)]
                elif t == "inlineStr" and is_el is not None:
                    val = "".join(
                        x.text or ""
                        for x in is_el.iter(
                            "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t"
                        )
                    )
                elif v is not None and v.text is not None:
                    val = v.text
                rows[ri][ci] = val
            table: List[List[str]] = []
            if rows:
                for ri in range(max(rows) + 1):
                    table.append([rows[ri].get(ci, "") for ci in range(max_c + 1)])
            out[name] = table
        return out


def _table_from(sheet_rows: List[List[str]], header_names: Sequence[str]):
    hdr_i = None
    first = header_names[0].lower()
    for i, r in enumerate(sheet_rows):
        if any(c.strip().lower() == first for c in r):
            hdr_i = i
            break
    if hdr_i is None:
        return [], []
    headers = [c.strip() for c in sheet_rows[hdr_i]]
    data = []
    for r in sheet_rows[hdr_i + 1 :]:
        if not any(c.strip() for c in r):
            continue
        data.append(
            {
                headers[j]: (r[j] if j < len(r) else "")
                for j in range(len(headers))
                if headers[j]
            }
        )
    return headers, data


def extract_pack(xlsx: Path) -> dict:
    sheets = _load_sheets(xlsx)
    domains, ips, urls, sha256, wallets = set(), set(), set(), set(), set()
    poisoned_urls, poisoned_hosts = set(), set()
    exclusions_hashes = set()

    _, reg = _table_from(sheets.get("IOC Register", []), ["IOC ID", "Category"])
    for row in reg:
        typ = (row.get("Type") or "").strip().lower()
        val = (row.get("Indicator / value") or "").strip()
        cat = (row.get("Category") or "").strip().lower()
        if not val or "affected" in cat and "site" in cat:
            continue
        if typ == "domain":
            domains.add(val.lower().rstrip(".").lstrip("*."))
        elif typ in {"ip", "ipv4", "ipv6"}:
            ips.add(val)
        elif typ in {"url", "uri"}:
            urls.add(val)
        elif re.fullmatch(r"[a-fA-F0-9]{64}", val):
            sha256.add(val.lower())

    _, net = _table_from(sheets.get("Network IOCs", []), ["ID", "Type"])
    for row in net:
        typ = (row.get("Type") or "").strip().lower()
        val = (row.get("Hostname, IP or exact URL") or "").strip()
        if not val:
            continue
        if typ == "domain" or re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", val):
            domains.add(val.lower().rstrip(".").lstrip("*."))
        elif typ in {"ip", "ipv4", "ipv6"} or re.match(r"^\d+\.\d+\.\d+\.\d+$", val):
            ips.add(val)
        elif typ in {"url", "uri", "path", "exact url"} or val.startswith("http"):
            urls.add(val)

    _, hashes = _table_from(sheets.get("File Hashes", []), ["ID", "Hash type"])
    for row in hashes:
        h = (row.get("SHA-256 (verbatim)") or "").strip().lower()
        if re.fullmatch(r"[a-f0-9]{64}", h):
            sha256.add(h)

    _, wrows = _table_from(sheets.get("Crypto Wallets", []), ["ID", "Chain"])
    for row in wrows:
        a = (row.get("Address (verbatim)") or "").strip()
        if a:
            wallets.add(a)

    _, pois = _table_from(sheets.get("Poisoned Scripts", []), ["ID", "Provider"])
    for row in pois:
        u = (row.get("Exact legitimate vendor URL") or "").strip()
        h = (row.get("SHA-256 if reported") or "").strip().lower()
        if u:
            poisoned_urls.add(u)
            m = re.match(r"https?://([^/]+)", u, re.I)
            if m:
                poisoned_hosts.add(m.group(1).lower())
        if re.fullmatch(r"[a-f0-9]{64}", h):
            sha256.add(h)

    _, excl = _table_from(
        sheets.get("Exclusions", []), ["Reported string / entity", "Exclude as"]
    )
    for row in excl:
        s = (row.get("Reported string / entity") or "").strip()
        if re.fullmatch(r"[a-fA-F0-9]{64}", s):
            exclusions_hashes.add(s.lower())
            sha256.discard(s.lower())

    for u in list(urls):
        m = re.match(r"https?://([^/]+)", u, re.I)
        if m:
            domains.add(m.group(1).lower())

    return {
        "campaign": "OPTIMJACK",
        "source_workbook": xlsx.name,
        "attacker_domains": sorted(domains),
        "attacker_ips": sorted(ips),
        "attacker_urls": sorted(urls),
        "sha256": sorted(sha256),
        "wallets": sorted(wallets),
        "poisoned_cdn_hosts": sorted(poisoned_hosts),
        "poisoned_script_urls": sorted(poisoned_urls),
        "browser_markers_high_signal": [
            "window._k7",
            "window.__k7b",
            "window._cc",
            "window._qxc",
            "window._shot",
            "obChTK",
            "__DAILI_CFG",
            "__LDY_CFG",
            "__cais_ds_eval_ok_v1",
            "data-daili-gate",
            "02111110",
            "d7K9mP2x",
            "ds_sw_fired",
            "ds_vk",
            "BIGNIAO",
            "post_exploit.js",
            "rce_worker_26.x.js",
            "keychain-2.db",
            "chainFrame",
        ],
        "exclusions_hashes": sorted(exclusions_hashes),
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("xlsx", type=Path, help="Path to OPTIMJACK *.xlsx workbook")
    p.add_argument("-o", "--out", type=Path, required=True, help="Output JSON path")
    args = p.parse_args(argv)
    if not args.xlsx.is_file():
        print(f"not found: {args.xlsx}", file=sys.stderr)
        return 2
    pack = extract_pack(args.xlsx)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(pack, indent=2) + "\n", encoding="utf-8")
    print(
        f"wrote {args.out} domains={len(pack['attacker_domains'])} "
        f"ips={len(pack['attacker_ips'])} sha256={len(pack['sha256'])} "
        f"cdn_hosts={len(pack['poisoned_cdn_hosts'])}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
