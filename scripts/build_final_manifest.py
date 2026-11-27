#!/usr/bin/env python3
"""
Dual-Repo Unified Manifest & Catalog Builder for ZarNiTho/NUT + ZarNiTho/Qualcomm_Loaders.
Scans .elf, .mbn, .bin, .melf (plus extensionless ELF loaders, MTK .h targets, SPD .xml configs),
extracts real ELF/MBN HW_ID/PK_HASH/ELF-class metadata, deduplicates by SHA-256 while merging
model aliases, pairs VIP digest/sig bundles, and emits:
  - final_qc.json
  - spd_manifest.json
  - main.json
  - appcatlog.json
  - report.txt
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

NOW = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

SKIP_DIRS = {
    ".git",
    ".github",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "wiko",  # Root WIKO duplicates Spd/WIKO inside NUT
}

SKIP_PATH_SUBSTRINGS = (
    "not valid",
    "不太能用的",
    "/broken/",
    "/org/",
)

ARCHIVE_EXTS = {".tar", ".zip", ".rar", ".tgz", ".7z", ".gz", ".xz"}
QC_BINARY_EXTS = {".elf", ".mbn", ".bin", ".melf"}
MTK_EXTS = {".bin", ".img", ".h"}
SPD_EXTS = {".bin", ".xml"}
GENERATED_FILES = {
    "main.json",
    "final_qc.json",
    "spd_manifest.json",
    "appcatlog.json",
    "report.txt",
    "report.json",
}
CATALOG_CANDIDATES = ("device_catalogue.json", "device_catalog.json")

# Bidirectional SoC <-> 24-bit MSM_HWID / SOC_HW mapping (synced with QualcommConfig.kt)
SOC_TO_HWID8: dict[str, list[str]] = {
    "MSM8909": ["009600E1"],
    "MSM8909W": ["000510E1", "000520E1"],
    "MSM8916": ["007050E1"],
    "APQ8016": ["007060E1"],
    "MSM8917": ["000560E1"],
    "APQ8017": ["000550E1"],
    "MSM8920": ["000860E1"],
    "MSM8926": ["008050E1"],
    "MSM8929": ["0091B0E1"],
    "MSM8936": ["0090B0E1"],
    "MSM8937": ["0004F0E1"],
    "MSM8939": ["0090B0E1"],
    "MSM8940": ["0006B0E1"],
    "MSM8952": ["009720E1"],
    "MSM8953": ["000460E1"],
    "APQ8053": ["000660E1"],
    "MSM8974": ["007B00E1", "007B30E1", "007B40E1", "007B80E1", "007BC0E1", "006B10E1"],
    "MSM8976": ["009900E1"],
    "MSM8992": ["009690E1"],
    "MSM8994": ["009400E1"],
    "MSM8996": ["009470E1", "0005F0E1"],
    "MSM8998": ["0005E0E1", "30020000"],
    "SDM835": ["0005E0E1", "30020000"],
    "QM215": ["001060E1"],
    "SDM429": ["000BE0E1"],
    "SDM439": ["000BF0E1"],
    "SDM450": ["0009A0E1"],
    "SDM630": ["000AC0E1", "30070000"],
    "SDM632": ["000BA0E1", "000BB0E1"],
    "SDM636": ["000CC0E1"],
    "SDM660": ["0008C0E1", "30060000"],
    "SDM670": ["000910E1", "000930E1", "60040000"],
    "SDM710": ["000DB0E1", "60040000"],
    "SDM845": ["0008B0E1", "0008E0E1", "60000000"],
    "SDM850": ["000B70E1"],
    "SDM855": ["000A50E1", "000A60E1", "60030000"],
    "SM8150": ["000A50E1", "000A60E1", "60030000"],
    "SM6115": ["001360E1"],
    "SM4250": ["001360E1"],
    "SM4350": ["0016F0E1"],
    "SM6125": ["000E10E1", "0014D0E1"],
    "SM6150": ["000950E1", "000EC0E1", "60070000"],
    "SM6225": ["001700E1", "001A90E1"],
    "SM6250": ["0011E0E1"],
    "SM6375": ["001B80E1"],
    "SM7125": ["000A20E1", "0011E0E1"],
    "SM7150": ["000E60E1", "000E70E1", "600C0000"],
    "SM7225": ["000B60E1", "0013F0E1"],
    "SM7250": ["000D80E1", "001630E1"],
    "SM7325": ["0013B0E1", "0014D0E1", "001590E1"],
    "SM7450": ["001920E1"],
    "SM7475": ["001920E1"],
    "SM8250": ["000C30E1", "000CE0E1", "001560E1", "60080000"],
    "SM8350": ["001300E1", "001350E1", "600F0000"],
    "SM8450": ["001620E1"],
    "SM8475": ["001920E1"],
    "SM8550": ["001A00E1"],
    "SM8650": ["001F00E1"],
    "QCM2290": ["001860E1"],
    "QCM6125": ["001750E1"],
    "MDM9205": ["001070E1"],
    "MDM9207": ["000480E1"],
    "MDM9607": ["0004A0E1"],
    "SDX20": ["0007F0E1"],
    "SDX24": ["000960E1", "000970E1"],
    "SDX55": ["000CF0E1", "000E50E1"],
}

HWID8_TO_SOC: dict[str, str] = {}
for _soc, _ids in SOC_TO_HWID8.items():
    for _hid in _ids:
        HWID8_TO_SOC.setdefault(_hid.upper(), _soc)

BRAND_ALIASES: dict[str, list[str]] = {
    "xiaomi": ["xiaomi", "redmi", "poco", "blackshark", "mi"],
    "oppo": ["oppo", "realme", "oneplus", "oplus"],
    "realme": ["realme", "oppo", "oplus"],
    "oneplus": ["oneplus", "oppo", "oplus"],
    "motorola": ["motorola", "lenovo_motorola", "lenovo", "moto"],
    "lenovo": ["lenovo", "lenovo_motorola", "motorola"],
    "nokia": ["nokia", "nokia_foxconn", "hmd"],
    "asus": ["asus", "asus_wingtech", "zenfone", "rog"],
    "samsung": ["samsung"],
    "vivo": ["vivo", "iqoo"],
    "zte": ["zte", "nubia"],
    "huawei": ["huawei", "honor"],
    "tecno": ["tecno", "transsion"],
    "infinix": ["infinix", "transsion"],
    "itel": ["itel", "transsion"],
    "tcl": ["tcl", "alcatel"],
}

SPD_CHIP_PROFILES: dict[str, dict[str, Any]] = {
    "UMS9230": {"fdl1": "0x65000800", "fdl2": "0x9EFFFE00", "exec": "0x65015F08"},
    "UMS512": {"fdl1": "0x5000", "fdl2": "0x9EFFFE00", "exec": "0x5500"},
    "SC9863A": {"fdl1": "0x5000", "fdl2": "0x9EFFFE00", "exec": "0x5500"},
    "UMS312": {"fdl1": "0x5000", "fdl2": "0x9EFFFE00", "exec": "0x5500"},
    "SC9832E": {"fdl1": "0x5000", "fdl2": "0x9EFFFE00", "exec": "0"},
    "SC7731E": {"fdl1": "0x5000", "fdl2": "0x9EFFFE00", "exec": "0"},
    "UD710": {"fdl1": "0x5000", "fdl2": "0x9EFFFE00", "exec": "0x5500"},
    "UMS9620": {"fdl1": "0x65000800", "fdl2": "0x9EFFFE00", "exec": "0"},
}

SOC_FOLDER_ALIASES: dict[str, str] = {
    "460": "SM4250",
    "662": "SM6115",
    "480": "SM4350",
    "695": "SM6375",
    "6g1": "SM6450",
    "7sg2": "SM7435",
    "7+gen2": "SM7475",
    "7+gen3": "SM7675",
    "845": "SDM845",
    "855": "SM8150",
    "888": "SM8350",
    "8+": "SM8475",
    "8g1": "SM8450",
    "8g2": "SM8550",
    "8+gen2": "SM8550",
    "8g3": "SM8650",
    "8sgen4": "SM8735",
    "8e": "SM8750",
}

QC_FILENAME_RE = re.compile(r"^([0-9a-fA-F]{16})_([0-9a-fA-F]{16,96})(?:_|\.|$)")
SM_SOC_RE = re.compile(
    r"(SM\d{4}[A-Z]?|SDM\d{3,4}|MSM\d{4}|APQ\d{4}|MDM\d{4}|QCM\d{4}|SDX\d{2,3}|QM\d{3}|SC8\d{3}X?)",
    re.I,
)
MODEL_CODE_RE = re.compile(
    r"\b(SM-[A-Z]\d{3,4}[A-Z0-9]*|CPH\d{4}|RMX\d{4}|PD\d{4}[A-Z]?|XT\d{4}(?:-\d)?|M\d{4}[A-Z0-9]+|2\d{6,7}[A-Z]{0,2}|[ASGNFMTX]\d{3}[A-Z]{1,2})\b",
    re.I,
)
BIT_RE = re.compile(r"(?i)(?:_|\b|-)(?:bit[_-]?([0-9]+|[a-f])|u([0-9]+))\b")
MTK_CHIP_RE = re.compile(r"MT\d{4}[A-Z]?", re.I)
CERT_OU_HWID_RE = re.compile(rb"01\s+([0-9A-Fa-f]{16})\s+HW_ID")
CERT_OU_OEM_RE = re.compile(rb"03\s+([0-9A-Fa-f]{4,8})\s+OEM_ID")
CERT_OU_MODEL_RE = re.compile(rb"04\s+([0-9A-Fa-f]{4,8})\s+MODEL_ID")
CERT_OU_SERIAL_RE = re.compile(rb"(?:06|07)\s+([0-9A-Fa-f]{8,16})\s+SERIAL")


def norm(v: Any) -> str:
    s = re.sub(r"[^a-z0-9]+", " ", str(v or "").lower().replace("\\", "/"))
    return re.sub(r"\s+", " ", s).strip()


def compact(v: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(v or "").lower())


def unique_list(items: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for x in items:
        s = str(x).strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            blk = f.read(1024 * 1024)
            if not blk:
                break
            h.update(blk)
    return h.hexdigest()


def url_for(repo: str, branch: str, rel: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{quote(branch, safe='')}/{quote(rel, safe='/')}"


def is_plain_ascii(data: bytes) -> bool:
    sample = data[:128]
    if not sample:
        return True
    return all(b in (9, 10, 13) or 32 <= b <= 126 for b in sample)


def is_mtk_binary_header(head: bytes) -> bool:
    return (
        head.startswith(b"MMM")
        or b"MTK_BLOADER_INFO" in head[:512]
        or b"MTK_DOWNLOAD_AGENT" in head[:512]
        or b"MTK_ALLINONE_DA" in head[:512]
        or head.startswith(b"EMMC_BOOT")
        or head.startswith(b"UFS_BOOT")
        or head.startswith(b"BRLYT")
    )


def parse_elf_and_cert_meta(data: bytes) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    if len(data) < 64:
        return meta
    if data[:4] == b"\x7fELF":
        ei_class = data[4]
        meta["format"] = "ELF"
        meta["elf_class"] = 32 if ei_class == 1 else (64 if ei_class == 2 else 0)
        # Extract MBN v3/v5/v6 certificate hash-table segment if small header exists
        # and scan certificate OU strings anywhere in first 2MB
    elif not is_plain_ascii(data[:256]) and not is_mtk_binary_header(data):
        meta["format"] = "MBN"

    scan = data[: min(len(data), 3 * 1024 * 1024)]
    m_hw = CERT_OU_HWID_RE.search(scan)
    if m_hw:
        full = m_hw.group(1).decode("ascii").upper()
        meta["hwid_full"] = full
        meta["msm_hwid"] = "0x" + full[:8]
        meta["oem_id"] = full[8:12]
        meta["model_id"] = full[12:16]
        meta["metadata_source"] = "elf_cert"
    else:
        m_oem = CERT_OU_OEM_RE.search(scan)
        m_mod = CERT_OU_MODEL_RE.search(scan)
        if m_oem:
            meta["oem_id"] = m_oem.group(1).decode("ascii").upper().zfill(4)[-4:]
        if m_mod:
            meta["model_id"] = m_mod.group(1).decode("ascii").upper().zfill(4)[-4:]

    # Also detect embedded Qualcomm root cert SHA256 if X.509 DER exists
    idx = scan.find(b"HW_ID")
    if idx != -1 and "hwid_full" not in meta:
        snippet = scan[max(0, idx - 32) : idx + 32]
        m_alt = re.search(rb"([0-9A-Fa-f]{16})", snippet)
        if m_alt:
            full = m_alt.group(1).decode("ascii").upper()
            meta["hwid_full"] = full
            meta["msm_hwid"] = "0x" + full[:8]
            meta["oem_id"] = full[8:12]
            meta["model_id"] = full[12:16]
            meta["metadata_source"] = "elf_cert_near"

    return meta


def infer_soc_from_text(text: str) -> str:
    m = SM_SOC_RE.search(text)
    if m:
        return m.group(1).upper()
    low = text.lower()
    for alias, soc in SOC_FOLDER_ALIASES.items():
        if alias in low:
            return soc
    return ""


def extract_models_and_bit(rel: str, brand: str) -> tuple[list[str], str]:
    models: list[str] = []
    bit = ""
    fn = rel.rsplit("/", 1)[-1]
    stem = fn.rsplit(".", 1)[0] if "." in fn else fn

    for m in re.findall(r"[\[\(]([^\]\)]{2,36})[\]\)]", rel):
        cleaned = m.strip()
        if cleaned and not cleaned.lower().endswith("nm"):
            models.append(cleaned)

    for m in MODEL_CODE_RE.findall(rel):
        models.append(m.upper())

    bm = BIT_RE.search(fn)
    if bm:
        bval = (bm.group(1) or bm.group(2) or "").upper()
        if bval:
            bit = f"BIT{bval}"

    # Xiaomi / FirehoseLoaders clean human names
    low = rel.lower()
    if any(k in low for k in ("bl/", "xiaomi/", "mi/", "redmi", "poco/", "mix/", "pad/")):
        clean_stem = re.sub(r"\(\d+(?:st|nd|rd|th)\s+firehose\)", "", stem, flags=re.I).strip()
        if clean_stem and not QC_FILENAME_RE.match(clean_stem):
            models.append(clean_stem)

    # _fhprg_<model>.bin tail
    tail_m = re.search(r"_fhprg_(?:peek_)?([a-z0-9_]+)$", stem, re.I)
    if tail_m:
        tail = tail_m.group(1)
        if tail.lower() not in ("peek", "edlauth", "noauth", "2", "ddr"):
            models.append(tail)

    return unique_list(models), bit


def infer_qc_brand(rel: str, oem_id: str = "") -> str:
    parts = [p.lower() for p in rel.split("/")]
    joined = "/".join(parts)
    if "samsung" in joined or re.search(r"\bsm-[a-z]\d{3}", joined) or re.search(r"/(?:a|s|g|n|f|m)\d{3}[a-z]", joined):
        return "samsung"
    if any(k in joined for k in ("xiaomi", "redmi", "poco", "bl/", "blackshark", "mi/")):
        return "xiaomi"
    if "oppo" in joined or "cph" in joined or "firehose_files/" in joined:
        return "oppo"
    if "realme" in joined or "rmx" in joined:
        return "realme"
    if "oneplus" in joined or "_op" in joined:
        return "oneplus"
    if "vivo" in joined or "iqoo" in joined or "pd2" in joined:
        return "vivo"
    if "lenovo_motorola" in joined or "moto" in joined or "lenovo" in joined:
        return "lenovo_motorola"
    if "nokia" in joined:
        return "nokia_foxconn"
    if "asus" in joined:
        return "asus_wingtech"
    if "zte" in joined:
        return "zte"
    if "huawei" in joined:
        return "huawei"
    if "lg/" in joined:
        return "lg"
    if "tcl/" in joined:
        return "tcl"
    oem_map = {
        "0004": "zte",
        "0015": "huawei",
        "0017": "lenovo_motorola",
        "0020": "samsung",
        "0029": "asus_wingtech",
        "0031": "lg",
        "0035": "nokia_foxconn",
        "0042": "tcl",
        "0045": "nokia_foxconn",
        "0051": "oppo",
        "0072": "xiaomi",
        "0073": "vivo",
        "02E8": "lenovo_motorola",
    }
    if oem_id.upper() in oem_map:
        return oem_map[oem_id.upper()]
    return "generic"


def infer_qc_auth_mode(rel: str) -> str:
    low = rel.lower()
    if "edlauth" in low:
        return "edl_auth"
    if "noauth" in low or "no auth" in low or "no_need_authorized" in low or low.startswith("bl/"):
        return "no_auth"
    if "auth skip" in low or "auth bypass" in low:
        return "xiaomi_sig"
    if "firehose_files/" in low or re.match(r"^(?:460|480|695|6g1|7\+gen|8\+|845|855|888|8sgen4|8e|8g[123]|sm\d{4})", low):
        return "oppo_vip"
    return "standard"


def infer_storage_type(rel: str, soc: str) -> str:
    low = rel.lower()
    if "ufs" in low:
        return "UFS"
    if "emmc" in low:
        return "eMMC"
    if "nand" in low:
        return "NAND"
    s = soc.upper()
    if any(s.startswith(p) for p in ("SM8", "SM72", "SM73", "SM74", "SM76", "SM6225", "SM6250", "SM6375", "SDM845", "SDM85", "MSM8996", "MSM8998")):
        return "UFS"
    return "eMMC/UFS"


def find_vip_companions(dir_path: Path, repo_root: Path, repo_name: str, branch: str) -> tuple[str, str]:
    digest_url = ""
    sig_url = ""
    if not dir_path.is_dir():
        return "", ""
    for sibling in sorted(dir_path.iterdir()):
        if not sibling.is_file():
            continue
        sn = sibling.name.lower()
        rel_s = sibling.relative_to(repo_root).as_posix()
        if "digest" in sn and not digest_url:
            digest_url = url_for(repo_name, branch, rel_s)
        elif (sn in ("sig", "sign.bin") or sn.endswith("_sign.bin")) and not sig_url:
            sig_url = url_for(repo_name, branch, rel_s)
    return digest_url, sig_url


def qc_priority_score(rec: dict[str, Any]) -> int:
    rel = rec["path"].lower()
    score = 0
    if rec.get("auth_mode") == "no_auth":
        score += 40
    elif rec.get("auth_mode") == "oppo_vip":
        score += 35
    elif rec.get("auth_mode") == "xiaomi_sig":
        score += 30
    if rel.startswith(("bl/", "samsung-edl-loaders-master/", "firehoseloaders/", "firehose_files/", "qualcomm-firehoses-main/")):
        score += 30
    elif rel.startswith("loaders/"):
        score += 20
    elif rel.startswith(("loaders-main/", "programmers-master/", "collection_")):
        score += 5
    score += min(20, len(rec.get("models", [])) * 5)
    if rec.get("bit"):
        score += 10
    if rec.get("msm_hwid") and rec["msm_hwid"] != "0x00000000":
        score += 10
    return score


def scan_qcom_repo_dir(root: Path, repo_name: str, branch: str, include_xiaomi_sigs: bool = True) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    loaders: list[dict[str, Any]] = []
    sigs: list[dict[str, Any]] = []
    if not root.is_dir():
        return loaders, sigs

    for walk_root, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d.lower() not in SKIP_DIRS and not d.startswith("."))
        cur_dir = Path(walk_root)
        rel_dir_low = cur_dir.relative_to(root).as_posix().lower() if cur_dir != root else ""
        if any(s in f"/{rel_dir_low}/" for s in SKIP_PATH_SUBSTRINGS):
            dirs[:] = []
            continue

        # Capture Xiaomi SIG files separately
        if include_xiaomi_sigs and "xiaomi/sig" in rel_dir_low:
            for n in sorted(names):
                p = cur_dir / n
                if not p.is_file() or p.name.startswith("."):
                    continue
                rel = p.relative_to(root).as_posix()
                sigs.append({
                    "name": p.name,
                    "path": rel,
                    "repo": repo_name,
                    "url": url_for(repo_name, branch, rel),
                    "size": p.stat().st_size,
                    "sha256": sha256_file(p),
                })
            continue

        for n in sorted(names):
            if n.startswith(".") or n in GENERATED_FILES or n in CATALOG_CANDIDATES:
                continue
            p = cur_dir / n
            if not p.is_file():
                continue
            rel = p.relative_to(root).as_posix()
            low = rel.lower()
            if any(s in f"/{low}" for s in SKIP_PATH_SUBSTRINGS):
                continue

            ext = p.suffix.lower()
            if ext in ARCHIVE_EXTS:
                continue
            # Ignore NUT non-QCOM folders
            if repo_name == "ZarNiTho/NUT" and (
                low.startswith(("da/", "preloader/", "payloads/", "targets/", "spd/", "tempblu/"))
                or "preloader" in n.lower()
            ):
                continue

            # Skip standalone VIP digest/sig files from loader list (paired below)
            fn_low = n.lower()
            if "digest" in fn_low or fn_low in ("sig", "sign.bin") or fn_low.endswith("_sign.bin"):
                continue

            size = p.stat().st_size
            if size < 4096:
                continue

            with p.open("rb") as f:
                head = f.read(512)
            if is_mtk_binary_header(head) or is_plain_ascii(head):
                continue

            is_elf_or_mbn = head[:4] == b"\x7fELF" or ext in QC_BINARY_EXTS
            if not is_elf_or_mbn:
                continue

            with p.open("rb") as f:
                data = f.read(min(size, 4 * 1024 * 1024))

            qname = QC_FILENAME_RE.match(n)
            parsed = parse_elf_and_cert_meta(data)
            hwid_full = ""
            msm_hwid = parsed.get("msm_hwid", "")
            oem_id = parsed.get("oem_id", "")
            model_id = parsed.get("model_id", "")
            pk_hash = ""
            if qname:
                hwid_full = qname.group(1).upper()
                if not msm_hwid or msm_hwid == "0x00000000":
                    msm_hwid = "0x" + hwid_full[:8]
                oem_id = oem_id or hwid_full[8:12]
                model_id = model_id or hwid_full[12:16]
                pk_hash = qname.group(2).lower()
            elif parsed.get("hwid_full"):
                hwid_full = parsed["hwid_full"]

            brand = infer_qc_brand(rel, oem_id)
            models, bit = extract_models_and_bit(rel, brand)
            soc = infer_soc_from_text(rel)
            if not soc and msm_hwid:
                soc = HWID8_TO_SOC.get(msm_hwid.removeprefix("0x").upper(), "")
            if (not msm_hwid or msm_hwid == "0x00000000") and soc and soc.upper() in SOC_TO_HWID8:
                msm_hwid = "0x" + SOC_TO_HWID8[soc.upper()][0]

            auth_mode = infer_qc_auth_mode(rel)
            digest_url, sig_url = ("", "")
            if auth_mode == "oppo_vip" or "firehose_files/" in low:
                digest_url, sig_url = find_vip_companions(cur_dir, root, repo_name, branch)
                if digest_url or sig_url:
                    auth_mode = "oppo_vip"

            loaders.append({
                "name": n,
                "repo": repo_name,
                "path": rel,
                "url": url_for(repo_name, branch, rel),
                "size": size,
                "sha256": sha256_file(p),
                "format": parsed.get("format", "ELF" if ext in (".elf", ".melf") else "BIN"),
                "elf_class": parsed.get("elf_class", 0),
                "msm_hwid": msm_hwid or "0x00000000",
                "oem_id": oem_id,
                "model_id": model_id,
                "pk_hash": pk_hash,
                "soc": soc,
                "brand": brand,
                "models": models,
                "bit": bit,
                "storage": infer_storage_type(rel, soc),
                "auth_mode": auth_mode,
                "digest_url": digest_url,
                "sig_url": sig_url,
            })
    return loaders, sigs


def deduplicate_qc_loaders(raw_loaders: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_sha: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rec in raw_loaders:
        by_sha[rec["sha256"]].append(rec)

    deduped: list[dict[str, Any]] = []
    for sha, group in by_sha.items():
        group.sort(key=lambda r: (-qc_priority_score(r), r["repo"] != "ZarNiTho/NUT", len(r["path"])))
        primary = dict(group[0])
        merged_models: list[str] = []
        merged_hwids: list[str] = []
        for g in group:
            merged_models.extend(g.get("models", []))
            if g.get("msm_hwid") and g["msm_hwid"] != "0x00000000":
                merged_hwids.append(g["msm_hwid"])
            if not primary.get("soc") and g.get("soc"):
                primary["soc"] = g["soc"]
            if not primary.get("pk_hash") and g.get("pk_hash"):
                primary["pk_hash"] = g["pk_hash"]
            if not primary.get("bit") and g.get("bit"):
                primary["bit"] = g["bit"]
            if not primary.get("digest_url") and g.get("digest_url"):
                primary["digest_url"] = g["digest_url"]
            if not primary.get("sig_url") and g.get("sig_url"):
                primary["sig_url"] = g["sig_url"]
        primary["models"] = unique_list(merged_models)
        if (not primary.get("msm_hwid") or primary["msm_hwid"] == "0x00000000") and merged_hwids:
            primary["msm_hwid"] = merged_hwids[0]
        primary["id"] = f"qc_{sha[:12]}"
        deduped.append(primary)

    deduped.sort(key=lambda x: (x["brand"], x["soc"], x["name"].lower(), x["id"]))
    return deduped


def parse_spd_xml_addrs(xml_path: Path | None) -> tuple[str, str]:
    if not xml_path or not xml_path.is_file():
        return "", ""
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        fdl1_addr = ""
        fdl2_addr = ""
        for elem in root.iter():
            tag = elem.tag.lower()
            if tag == "file":
                fid = (elem.attrib.get("id") or "").strip().upper()
                if fid in ("FDL", "FDL1", "FDL2"):
                    base = ""
                    for block in elem.iter():
                        if block.tag.lower() == "base":
                            base = (block.text or "").strip()
                            break
                    if not base:
                        base = (elem.attrib.get("base") or "").strip()
                    if fid in ("FDL", "FDL1") and base and not fdl1_addr:
                        fdl1_addr = base
                    elif fid == "FDL2" and base and not fdl2_addr:
                        fdl2_addr = base
        return fdl1_addr, fdl2_addr
    except Exception:
        return "", ""


def infer_spd_soc_id(text: str) -> str:
    u = text.upper()
    if "UMS9230" in u or "T606" in u or "T612" in u or "T616" in u or "T7250" in u:
        return "UMS9230"
    if "UMS512" in u or "T610" in u or "T618" in u:
        return "UMS512"
    if "9863" in u:
        return "SC9863A"
    if "312" in u or "T310" in u:
        return "UMS312"
    if "9832" in u:
        return "SC9832E"
    if "7731" in u or "7721" in u:
        return "SC7731E"
    if "9820" in u:
        return "SC9820"
    if "9620" in u or "T760" in u or "T770" in u or "T820" in u:
        return "UMS9620"
    if "710" in u or "T700" in u or "T740" in u:
        return "UD710"
    return "UMS9230"


def build_spd_manifest(nut_root: Path, repo_name: str, branch: str) -> dict[str, Any]:
    spd_root = nut_root / "Spd"
    entries: list[dict[str, Any]] = []
    if not spd_root.is_dir():
        return {"version": 1, "updatedAt": NOW, "baseUrl": f"https://raw.githubusercontent.com/{repo_name}/{branch}/", "loaders": []}

    for walk_root, dirs, names in os.walk(spd_root):
        dirs[:] = sorted(dirs)
        cur = Path(walk_root)
        bins = [cur / n for n in sorted(names) if n.lower().endswith(".bin")]
        fdl1 = next((b for b in bins if "fdl1" in b.name.lower()), None)
        fdl2 = next((b for b in bins if "fdl2" in b.name.lower()), None)
        if not fdl1 or not fdl2:
            continue

        xml_file = next((cur / n for n in sorted(names) if n.lower().endswith(".xml")), None)
        rel_dir = cur.relative_to(spd_root).as_posix()
        parts = rel_dir.split("/")
        brand = "Generic" if parts[0].lower().startswith("auto") else parts[0].title()
        model_label = parts[-1]
        soc_id = infer_spd_soc_id(rel_dir + " " + (xml_file.name if xml_file else ""))
        prof = SPD_CHIP_PROFILES.get(soc_id, SPD_CHIP_PROFILES["UMS9230"])
        xml_f1, xml_f2 = parse_spd_xml_addrs(xml_file)

        entries.append({
            "id": compact(rel_dir)[:48] or f"spd_{len(entries)}",
            "brand": brand,
            "model": model_label,
            "socId": soc_id,
            "fdl1Path": fdl1.relative_to(nut_root).as_posix(),
            "fdl1Url": url_for(repo_name, branch, fdl1.relative_to(nut_root).as_posix()),
            "fdl1Sha256": sha256_file(fdl1),
            "fdl1Addr": xml_f1 or prof["fdl1"],
            "fdl2Path": fdl2.relative_to(nut_root).as_posix(),
            "fdl2Url": url_for(repo_name, branch, fdl2.relative_to(nut_root).as_posix()),
            "fdl2Sha256": sha256_file(fdl2),
            "fdl2Addr": xml_f2 or prof["fdl2"],
            "execAddr": prof["exec"],
        })

    return {
        "version": 2,
        "updatedAt": NOW,
        "baseUrl": f"https://raw.githubusercontent.com/{repo_name}/{branch}/",
        "loaders": entries,
    }


def scan_nut_non_qc(nut_root: Path, repo_name: str, branch: str) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    mtk: dict[str, list[dict[str, Any]]] = {"da": [], "loader_payloads": [], "preloader": [], "targets": []}
    tempblu: list[dict[str, Any]] = []

    for sub, cat_key in (("Da", "da"), ("payloads", "loader_payloads"), ("Preloader", "preloader"), ("targets", "targets")):
        folder = nut_root / sub
        if not folder.is_dir():
            continue
        for p in sorted(folder.rglob("*")):
            if not p.is_file() or p.name.startswith("."):
                continue
            rel = p.relative_to(nut_root).as_posix()
            ext = p.suffix.lower()
            if cat_key == "targets" and ext != ".h":
                continue
            if cat_key != "targets" and ext not in (".bin", ".img", ".patched"):
                continue
            chip = MTK_CHIP_RE.search(p.name)
            hw_m = re.match(r"^([0-9a-fA-F]{4})_", p.name)
            models, _ = extract_models_and_bit(rel, "mtk")
            mtk[cat_key].append({
                "name": p.name,
                "path": rel,
                "url": url_for(repo_name, branch, rel),
                "size": p.stat().st_size,
                "sha256": sha256_file(p),
                "chipset": chip.group(0).upper() if chip else "",
                "hw_code": hw_m.group(1).upper() if hw_m else "",
                "models": models,
                "category": cat_key.rstrip("s") if cat_key == "targets" else ("payload" if cat_key == "loader_payloads" else cat_key),
            })

    tb_dir = nut_root / "tempblu"
    if tb_dir.is_dir():
        for model_dir in sorted(tb_dir.iterdir()):
            if not model_dir.is_dir():
                continue
            files = {f.name.lower(): f for f in sorted(model_dir.iterdir()) if f.is_file()}
            abl = files.get("abl.elf") or files.get("abl.img")
            xbl = files.get("xbl.elf") or files.get("xbl.img")
            if abl or xbl:
                tempblu.append({
                    "model": model_dir.name,
                    "abl_path": abl.relative_to(nut_root).as_posix() if abl else "",
                    "abl_url": url_for(repo_name, branch, abl.relative_to(nut_root).as_posix()) if abl else "",
                    "abl_sha256": sha256_file(abl) if abl else "",
                    "xbl_path": xbl.relative_to(nut_root).as_posix() if xbl else "",
                    "xbl_url": url_for(repo_name, branch, xbl.relative_to(nut_root).as_posix()) if xbl else "",
                    "xbl_sha256": sha256_file(xbl) if xbl else "",
                })
    return mtk, tempblu


def evaluate_catalog(
    nut_root: Path,
    qc_loaders: list[dict[str, Any]],
    mtk: dict[str, list[dict[str, Any]]],
    spd_manifest: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    cat_path = next((nut_root / c for c in CATALOG_CANDIDATES if (nut_root / c).is_file()), None)
    if not cat_path:
        return [], {"catalog_models": 0, "matched": 0}

    raw = json.loads(cat_path.read_text(encoding="utf-8"))
    models: list[dict[str, Any]] = []
    if isinstance(raw, list):
        models = raw
    elif isinstance(raw, dict):
        for pkey, pdata in raw.get("platforms", {}).items():
            for b in pdata.get("brands", []):
                for m in b.get("models", []):
                    item = dict(m)
                    item.setdefault("brand", b.get("name", b.get("key", "")))
                    item.setdefault("engine", pkey)
                    models.append(item)

    qc_by_hwid: dict[str, list[dict[str, Any]]] = defaultdict(list)
    qc_by_brand: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for l in qc_loaders:
        if l["msm_hwid"] != "0x00000000":
            qc_by_hwid[l["msm_hwid"].upper()].append(l)
        qc_by_brand[l["brand"].lower()].append(l)

    spd_by_soc: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in spd_manifest["loaders"]:
        spd_by_soc[s["socId"].upper()].append(s)

    matched_list: list[dict[str, Any]] = []
    tier_counts: Counter[str] = Counter()

    for m in models:
        eng = str(m.get("engine", "")).lower()
        brand_raw = str(m.get("brand", ""))
        b_comp = compact(brand_raw)
        name_raw = str(m.get("name", m.get("model", "")))
        chip_code = str(m.get("chip_code", "")).upper()
        chip_label = str(m.get("chip", "")).upper()
        tokens = [compact(t) for t in re.split(r"[\s\(\)\[\]/,_-]+", f"{name_raw} {chip_code} {chip_label}") if len(compact(t)) >= 3]

        best_files: list[dict[str, Any]] = []
        score = 0

        if eng == "qcom" or (eng == "samsung" and ("SM-" in name_raw.upper() or "QCOM" in chip_code or "SM" in chip_code or "SDM" in chip_code)):
            target_hwids = set()
            if chip_code.startswith("0X"):
                target_hwids.add(chip_code[:10])
            inferred_soc = infer_soc_from_text(f"{chip_code} {chip_label}")
            for hid in SOC_TO_HWID8.get(inferred_soc, []):
                target_hwids.add("0X" + hid)

            aliases = BRAND_ALIASES.get(b_comp, [b_comp])
            candidates: list[tuple[int, dict[str, Any]]] = []
            pool = []
            for al in aliases:
                pool.extend(qc_by_brand.get(al, []))
            for hid in target_hwids:
                pool.extend(qc_by_hwid.get(hid, []))
            seen_ids: set[str] = set()
            for c in pool:
                if c["id"] in seen_ids:
                    continue
                seen_ids.add(c["id"])
                sc = 0
                c_blob = compact(c["path"] + " " + " ".join(c.get("models", [])))
                tok_hits = sum(1 for t in tokens if len(t) >= 4 and t in c_blob)
                if tok_hits:
                    sc += min(55, 30 + tok_hits * 12)
                if c["msm_hwid"].upper() in target_hwids:
                    sc += 40
                if c["brand"] in aliases:
                    sc += 15
                if sc >= 45:
                    candidates.append((sc, c))
            candidates.sort(key=lambda x: -x[0])
            if candidates:
                score = min(100, candidates[0][0])
                best_files = [{"id": c["id"], "path": c["path"], "repo": c["repo"], "url": c["url"], "auth_mode": c["auth_mode"], "score": sc} for sc, c in candidates[:8]]

        elif eng == "mtk":
            mt_m = MTK_CHIP_RE.search(f"{chip_code} {chip_label}")
            soc_base = mt_m.group(0).upper()[:6] if mt_m else ""
            pl_hits = []
            for pl in mtk["preloader"]:
                pl_blob = compact(pl["name"] + " " + " ".join(pl.get("models", [])))
                tok_hits = sum(1 for t in tokens if len(t) >= 4 and t in pl_blob)
                if tok_hits or (soc_base and soc_base in pl["name"].upper()):
                    pl_hits.append((75 if tok_hits else 55, pl))
            pl_hits.sort(key=lambda x: -x[0])
            if pl_hits:
                score = pl_hits[0][0]
                best_files = [{"path": x["path"], "url": x["url"], "role": "preloader", "score": sc} for sc, x in pl_hits[:5]]
            elif soc_base:
                # Payload + Generic DA always available for supported MT67xx/MT68xx
                pay = [p for p in mtk["loader_payloads"] if soc_base in p["name"].upper()]
                if pay:
                    score = 65
                    best_files = [{"path": pay[0]["path"], "url": pay[0]["url"], "role": "payload", "score": 65}]

        elif eng == "spd":
            soc_id = infer_spd_soc_id(f"{chip_code} {chip_label} {m.get('loader_hint', '')}")
            hits = spd_by_soc.get(soc_id, [])
            if hits:
                score = 80 if any(compact(brand_raw) in compact(h["brand"] + " " + h["model"]) for h in hits) else 65
                best_files = [{"id": h["id"], "fdl1": h["fdl1Path"], "fdl2": h["fdl2Path"], "socId": h["socId"], "score": score} for h in hits[:4]]

        if best_files:
            tier = "match" if score >= 75 else "need_test"
            tier_counts[tier] += 1
            matched_list.append({
                "id": m.get("id", ""),
                "brand": brand_raw,
                "model": name_raw,
                "engine": eng,
                "chip_code": chip_code,
                "tier": tier,
                "score": score,
                "candidates": best_files,
            })

    stats = {
        "catalog_models": len(models),
        "matched_models": len(matched_list),
        "match": tier_counts.get("match", 0),
        "need_test": tier_counts.get("need_test", 0),
        "unmatched": len(models) - len(matched_list),
    }
    return matched_list, stats


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nut-dir", default=".", help="Path to ZarNiTho/NUT checkout")
    ap.add_argument("--qcom-dir", default="", help="Path to ZarNiTho/Qualcomm_Loaders checkout")
    ap.add_argument("--nut-repo", default=os.environ.get("GITHUB_REPOSITORY", "ZarNiTho/NUT"))
    ap.add_argument("--qcom-repo", default="ZarNiTho/Qualcomm_Loaders")
    ap.add_argument("--branch", default=os.environ.get("GITHUB_REF_NAME", "main"))
    args = ap.parse_args()

    nut_root = Path(args.nut_dir).resolve()
    qcom_root = Path(args.qcom_dir).resolve() if args.qcom_dir else None

    nut_qc, _ = scan_qcom_repo_dir(nut_root, args.nut_repo, args.branch, include_xiaomi_sigs=False)
    qcom_qc, xiaomi_sigs = (
        scan_qcom_repo_dir(qcom_root, args.qcom_repo, "main", include_xiaomi_sigs=True)
        if qcom_root and qcom_root.is_dir()
        else ([], [])
    )

    deduped_qc = deduplicate_qc_loaders(nut_qc + qcom_qc)
    spd_manifest = build_spd_manifest(nut_root, args.nut_repo, args.branch)
    mtk_data, tempblu_data = scan_nut_non_qc(nut_root, args.nut_repo, args.branch)
    matched_models, match_stats = evaluate_catalog(nut_root, deduped_qc, mtk_data, spd_manifest)

    final_qc = {
        "schema_version": 1,
        "generated_at": NOW,
        "repos": [args.nut_repo] + ([args.qcom_repo] if qcom_qc else []),
        "stats": {
            "raw_nut_qc": len(nut_qc),
            "raw_qcom_repo": len(qcom_qc),
            "deduped_qc_loaders": len(deduped_qc),
            "xiaomi_sigs": len(xiaomi_sigs),
            "by_auth_mode": dict(Counter(l["auth_mode"] for l in deduped_qc)),
            "by_brand": dict(Counter(l["brand"] for l in deduped_qc).most_common(25)),
        },
        "xiaomi_sigs": xiaomi_sigs,
        "loaders": deduped_qc,
    }

    # App-compatible main.json (supports both model_map.json nested dict & v3 metadata)
    qc_by_brand_nested: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for l in deduped_qc:
        qc_by_brand_nested[l["brand"]].append({
            "id": l["id"],
            "name": l["name"],
            "path": l["path"],
            "url": l["url"],
            "repo": l["repo"],
            "brand": l["brand"],
            "model": ", ".join(l["models"][:3]) if l["models"] else l["name"],
            "chipset": l["soc"],
            "msm_hwid": l["msm_hwid"],
            "pk_hash": l["pk_hash"],
            "storage_type": l["storage"],
            "auth_mode": l["auth_mode"],
            "bit": l["bit"],
            "digest_url": l["digest_url"],
            "sig_url": l["sig_url"],
            "file_size": l["size"],
            "sha256": l["sha256"],
        })

    main_json = {
        "schema_version": 4,
        "version": 218,
        "updated_at": NOW,
        "primary_source": "github_raw",
        "base_url": f"https://raw.githubusercontent.com/{args.nut_repo}/{args.branch}/",
        "stats": {
            "deduped_qc_loaders": len(deduped_qc),
            "mtk_da": len(mtk_data["da"]),
            "mtk_payloads": len(mtk_data["loader_payloads"]),
            "mtk_preloaders": len(mtk_data["preloader"]),
            "mtk_targets": len(mtk_data["targets"]),
            "spd_fdl_bundles": len(spd_manifest["loaders"]),
            "xiaomi_tempblu": len(tempblu_data),
            **match_stats,
        },
        "mtk": mtk_data,
        "qualcomm": {"loaders": dict(sorted(qc_by_brand_nested.items()))},
        "spd": spd_manifest["loaders"],
        "tempblu": tempblu_data,
        "xiaomi_sigs": xiaomi_sigs,
    }

    appcatlog = {
        "schema_version": 2,
        "generated_at": NOW,
        "stats": match_stats,
        "models": matched_models,
    }

    report_lines = [
        "DUAL-REPO UNIFIED BUILD REPORT",
        "=" * 64,
        f"Generated UTC: {NOW}",
        f"Raw NUT QC binaries: {len(nut_qc)}",
        f"Raw Qualcomm_Loaders binaries: {len(qcom_qc)}",
        f"Deduplicated Final QC loaders: {len(deduped_qc)}",
        f"Auth breakdown: {final_qc['stats']['by_auth_mode']}",
        f"MTK -> DA={len(mtk_data['da'])}, Payloads={len(mtk_data['loader_payloads'])}, Preloaders={len(mtk_data['preloader'])}, Targets={len(mtk_data['targets'])}",
        f"SPD FDL bundles: {len(spd_manifest['loaders'])}",
        f"Xiaomi tempblu bundles: {len(tempblu_data)}, SIG files: {len(xiaomi_sigs)}",
        f"Catalog eval: total={match_stats.get('catalog_models', 0)}, matched={match_stats.get('matched_models', 0)} (match={match_stats.get('match', 0)}, need_test={match_stats.get('need_test', 0)})",
    ]

    (nut_root / "final_qc.json").write_text(json.dumps(final_qc, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    (nut_root / "spd_manifest.json").write_text(json.dumps(spd_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (nut_root / "main.json").write_text(json.dumps(main_json, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (nut_root / "appcatlog.json").write_text(json.dumps(appcatlog, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (nut_root / "report.txt").write_text("\n".join(report_lines) + "\n", encoding="utf-8")

    print("\n".join(report_lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
