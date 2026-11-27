#!/usr/bin/env python3
"""
Production-grade precleaner, binary ELF/MBN validator & metadata enricher for ZarNiTho/NUT.
Supports nut_main.yml CLI:
  --mode preclean --nut-dir . --qcom-dir <path> [--purge-qcom-temp] [--purge-nut-bad]
  --mode enrich   --nut-dir . --qcom-dir <path> [--prev-version <int>]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ELF_MAGIC = b"\x7fELF"
CODEWORD_MAGICS = (0x844BDCD1, 0x874BDCD1, 0xD1DC4B84)
CODEWORD_W1 = 0x73D71034
HEX16_NAME_RE = re.compile(r"^([0-9a-f]{8})([0-9a-f]{4})([0-9a-f]{4})_([0-9a-f]{8,64})", re.I)

QC_BINARY_EXTS = {".elf", ".mbn", ".melf", ".bin"}
NON_QC_DIR_NAMES = {
    ".git", ".github", "scripts", "mtk", "preloader", "preloaders", "da",
    "payloads", "loader_payloads", "targets", "spd", "fdl", "tempblu", "sigs",
    "xiaomi_sigs", "sig", "bl",
}
BAD_ARCHIVE_EXTS = {".7z", ".zip", ".rar", ".tar", ".gz", ".xz", ".bz2", ".apk", ".exe", ".pdf"}

OEM_ID_TO_BRAND = {
    0x0001: "nokia_foxconn",
    0x0004: "zte",
    0x0015: "huawei",
    0x0017: "lenovo_motorola",
    0x0020: "samsung",
    0x0029: "asus_wingtech",
    0x0031: "lg",
    0x0035: "nokia_foxconn",
    0x0042: "tcl",
    0x0045: "nokia_foxconn",
    0x0051: "oppo",
    0x0072: "xiaomi",
    0x0073: "vivo",
    0x00C8: "lenovo_motorola",
    0x0168: "lenovo_motorola",
    0x01B0: "lenovo_motorola",
    0x0208: "lenovo_motorola",
    0x0228: "lenovo_motorola",
    0x02E8: "lenovo_motorola",
    0x0328: "lenovo_motorola",
    0x0348: "lenovo_motorola",
    0x0368: "lenovo_motorola",
    0x03C8: "lenovo_motorola",
    0x1043: "asus_wingtech",
    0x1111: "asus_wingtech",
    0x143A: "asus_wingtech",
}

# Verified real-hardware MBN v6 SOC_HW16 -> Canonical SoC
SOC_HW16_TO_SOC = {
    0x2013: "MDM9205",
    0x2014: "QCS405",
    0x3002: "SDM835",
    0x3006: "SDM660",
    0x3007: "SDM630",
    0x6000: "SDM845",
    0x6001: "SDA845",
    0x6002: "SDX24",
    0x6003: "SM8150",
    0x6004: "SDM670",
    0x6005: "SDM670",
    0x6006: "SC8180X",
    0x6007: "SM6150",
    0x6008: "SM8250",
    0x6009: "SDM670",
    0x600B: "SDX55",
    0x600C: "SM7150",
    0x600D: "SM7250",
    0x600E: "SM7125",
    0x600F: "SM8350",
    0x6012: "SM7225",
    0x6013: "SM8350",
    0x6016: "SDX65",
    0x6017: "SM7350",
    0x6018: "SM7325",
    0x9001: "SM6125",
    0x9002: "SM6115",
    0x9003: "SM4250",
    0x9004: "SM4350",
    0x9006: "SM6375",
    0x9007: "SM6225",
}

# Authoritative 24-bit MSM_HWID (all keys UPPERCASE "0X...") -> Canonical SoC
HWID_TO_SOC = {
    "0X000460E1": "MSM8953",
    "0X000480E1": "MDM9207",
    "0X0004A0E1": "MDM9607",
    "0X0004F0E1": "MSM8937",
    "0X000510E1": "MSM8909",
    "0X000520E1": "MSM8909",
    "0X000550E1": "APQ8017",
    "0X000560E1": "MSM8917",
    "0X0005E0E1": "MSM8998",
    "0X0005F0E1": "MSM8996",
    "0X000660E1": "MSM8953",
    "0X0006B0E1": "MSM8940",
    "0X0006F0E1": "MSM8996",
    "0X000700E1": "SDM636",
    "0X000860E1": "MSM8920",
    "0X0008B0E1": "SDM845",
    "0X0008C0E1": "SDM660",
    "0X0008E0E1": "SDA845",
    "0X000910E1": "SDM670",
    "0X000940E1": "MSM8905",
    "0X000950E1": "SM6150",
    "0X0009A0E1": "SDM450",
    "0X000A20E1": "SM7125",
    "0X000A50E1": "SM8150",
    "0X000A60E1": "SM8150",
    "0X000AC0E1": "SDM630",
    "0X000B40E1": "SM6150",
    "0X000B60E1": "SM7225",
    "0X000BA0E1": "SDM632",
    "0X000BB0E1": "SDA632",
    "0X000BE0E1": "SDM429",
    "0X000BF0E1": "SDM439",
    "0X000C30E1": "SM8250",
    "0X000CC0E1": "SDM636",
    "0X000CE0E1": "SM8250",
    "0X000D80E1": "SM7250",
    "0X000DB0E1": "SDM710",
    "0X000E10E1": "SM6125",
    "0X000E60E1": "SM7150",
    "0X000E70E1": "SM7150",
    "0X000EC0E1": "SM6150",
    "0X001060E1": "QM215",
    "0X0010A0E1": "SM6125",
    "0X0011E0E1": "SM7250",
    "0X0012A0E1": "SM7125",
    "0X001300E1": "SM8350",
    "0X001350E1": "SM8350",
    "0X001360E1": "SM6115",
    "0X001370E1": "SM6115",
    "0X0013B0E1": "SM7325",
    "0X0013F0E1": "SM7225",
    "0X001420E1": "SM8350",
    "0X001450E1": "SM4250",
    "0X0014D0E1": "SM6115",
    "0X0014E0E1": "SM6115",
    "0X001560E1": "SM8250",
    "0X001590E1": "SM7350",
    "0X001620E1": "SM8450",
    "0X001630E1": "SM7250",
    "0X0016F0E1": "SM4350",
    "0X001700E1": "SM6225",
    "0X001750E1": "QCM6125",
    "0X001860E1": "QCM2290",
    "0X001920E1": "SM7450",
    "0X001A00E1": "SM8550",
    "0X001A90E1": "SM6225",
    "0X001B80E1": "SM6375",
    "0X001F00E1": "SM8650",
    "0X007050E1": "MSM8916",
    "0X007060E1": "APQ8016",
    "0X007210E1": "MSM8930",
    "0X008050E1": "MSM8926",
    "0X008110E1": "MSM8210",
    "0X008140E1": "MSM8212",
    "0X0090B0E1": "MSM8939",
    "0X009180E1": "MSM8928",
    "0X0091B0E1": "MSM8929",
    "0X009400E1": "MSM8994",
    "0X009470E1": "MSM8996",
    "0X009600E1": "MSM8909",
    "0X009690E1": "MSM8992",
    "0X009720E1": "MSM8952",
    "0X009900E1": "MSM8976",
    "0X009B00E1": "MSM8956",
}

EMMC_ONLY_SOCS = {
    "MSM8210", "MSM8212", "MSM8905", "MSM8909", "MSM8916", "APQ8016", "MSM8917",
    "APQ8017", "MSM8920", "MSM8926", "MSM8928", "MSM8929", "MSM8930", "MSM8936",
    "MSM8937", "MSM8939", "MSM8940", "MSM8952", "MSM8953", "MSM8956", "MSM8976",
    "SDM429", "SDM439", "SDM450", "SDM630", "SDM632", "SDA632", "SDM636", "QM215",
}


def is_valid_qc_bytes(data: bytes) -> Tuple[bool, str]:
    size = len(data)
    if size < 4096 or size > 4_194_304:
        return False, "bad_size"
    head_ascii = data[:160].lstrip()
    for bad_prefix in (b"<!DOCTYPE", b"<html", b"version https://git-lfs", b"404:", b"MMM", b"EMMC_BOOT", b"UFS_BOOT", b"BRLYT"):
        if head_ascii.startswith(bad_prefix):
            return False, "non_qc_header"
    if b"MTK_BLOADER" in head_ascii or b"MTK_DOWNLOAD_AGENT" in head_ascii:
        return False, "mtk_binary"
    # 1. Valid ELF32/ELF64 little-endian
    if data[:4] == ELF_MAGIC:
        if data[4] in (1, 2) and data[5] == 1:
            return True, f"elf{32 if data[4] == 1 else 64}"
        return False, "bad_elf_ident"
    # 2. Legacy Qualcomm Codeword MBN (MSM8909/8916/8936/8939/8974/8x10)
    w0, w1 = struct.unpack_from("<II", data, 0)
    if w0 in CODEWORD_MAGICS and w1 == CODEWORD_W1:
        return True, "mbn_codeword"
    # 3. Standard 40-byte MBN header (v1..v10)
    if size >= 40:
        img_sz = struct.unpack_from("<I", data, 16)[0]
        if 0 <= w0 <= 0x40 and 1 <= w1 <= 10 and 1024 <= img_sz <= size + 4096:
            return True, "mbn_hdr"
    return False, "corrupt_or_encrypted"


def _extract_asn1_certs_and_meta(blob: bytes) -> Tuple[str, int, int, int]:
    certs: List[bytes] = []
    pos = 0
    n = len(blob)
    while pos + 4 < n:
        if blob[pos] == 0x30 and blob[pos + 1] in (0x81, 0x82):
            if blob[pos + 1] == 0x81:
                clen = blob[pos + 2]
                hdr = 3
            else:
                clen = (blob[pos + 2] << 8) | blob[pos + 3]
                hdr = 4
            total = hdr + clen
            if 200 <= total <= n - pos and blob[pos + hdr] == 0x30:
                certs.append(blob[pos : pos + total])
                pos += total
                continue
        pos += 1

    pk_hash = ""
    hwid32 = 0
    oem_id = 0
    soc_hw16 = 0

    if certs:
        root_cert = certs[-1]
        if b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02" in root_cert:
            pk_hash = hashlib.sha384(root_cert).hexdigest()
        else:
            pk_hash = hashlib.sha256(root_cert).hexdigest()

        attest = certs[0]
        m_hw = re.search(rb"01\s+([0-9A-Fa-f]{16})\s+HW_ID", attest)
        if m_hw:
            v64 = int(m_hw.group(1).decode("ascii"), 16)
            hwid32 = (v64 >> 32) & 0xFFFFFFFF
            oem_id = (v64 >> 16) & 0xFFFF
        m_oem = re.search(rb"04\s+([0-9A-Fa-f]{4})\s+OEM_ID", attest)
        if m_oem and oem_id == 0:
            oem_id = int(m_oem.group(1).decode("ascii"), 16)
        m_sv = re.search(rb"07\s+([0-9A-Fa-f]{4,8})\s+SOC_VERS", attest)
        if m_sv:
            sv_val = int(m_sv.group(1).decode("ascii")[-4:], 16)
            if sv_val in SOC_HW16_TO_SOC:
                soc_hw16 = sv_val

    return pk_hash, hwid32, oem_id, soc_hw16


def parse_qc_metadata(file_path: Path) -> Optional[Dict[str, Any]]:
    try:
        data = file_path.read_bytes()
    except OSError:
        return None
    ok, fmt = is_valid_qc_bytes(data)
    if not ok:
        return None

    elf_class = 0
    hash_seg = b""
    if data[:4] == ELF_MAGIC:
        ei_class = data[4]
        elf_class = 32 if ei_class == 1 else 64
        if ei_class == 1 and len(data) >= 52:
            e_phoff, _, _, e_phentsize, e_phnum = struct.unpack_from("<IIHHH", data, 28)
            for i in range(min(e_phnum, 64)):
                off = e_phoff + i * e_phentsize
                if off + 32 > len(data):
                    break
                p_type, p_offset, _, _, p_filesz, _, p_flags, _ = struct.unpack_from("<IIIIIIII", data, off)
                if p_filesz >= 40 and p_offset + p_filesz <= len(data):
                    if (p_flags & 0x07000000) == 0x02000000 or (i == 1 and p_type == 0):
                        hash_seg = data[p_offset : p_offset + p_filesz]
                        break
        elif ei_class == 2 and len(data) >= 64:
            e_phoff = struct.unpack_from("<Q", data, 32)[0]
            e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
            for i in range(min(e_phnum, 64)):
                off = e_phoff + i * e_phentsize
                if off + 56 > len(data):
                    break
                p_type, p_flags, p_offset, _, _, p_filesz = struct.unpack_from("<IIQQQQ", data, off)
                if p_filesz >= 40 and p_offset + p_filesz <= len(data):
                    if (p_flags & 0x07000000) == 0x02000000 or (i == 1 and p_type == 0):
                        hash_seg = data[p_offset : p_offset + p_filesz]
                        break
    else:
        hash_seg = data[: min(len(data), 131072)]

    hwid32 = 0
    oem_id = 0
    soc_hw16 = 0
    pk_hash = ""

    if len(hash_seg) >= 48:
        ver = struct.unpack_from("<I", hash_seg, 4)[0]
        if ver == 6 and len(hash_seg) >= 64:
            common_sz, qti_sz = struct.unpack_from("<II", hash_seg, 8)
            code_sz, qti_sig_sz, qti_cert_sz = struct.unpack_from("<III", hash_seg, 20)
            sig_sz, cert_sz = struct.unpack_from("<II", hash_seg, 32)
            md_off = 48
            if md_off + 24 <= len(hash_seg) and common_sz >= 24:
                md_major = struct.unpack_from("<I", hash_seg, md_off)[0]
                if md_major in (0, 1):
                    _, _, _, msm_part, md_oem, _ = struct.unpack_from("<IIIIII", hash_seg, md_off)
                    if msm_part and (msm_part & 0xFF) == 0xE1:
                        hwid32 = msm_part & 0xFFFFFFFF
                    if 0 < md_oem < 0xFFFF:
                        oem_id = md_oem
                    if common_sz >= 76 and md_off + 76 <= len(hash_seg):
                        for j in range(12):
                            sv = struct.unpack_from("<I", hash_seg, md_off + 28 + j * 4)[0]
                            sv_hi = (sv >> 16) & 0xFFFF
                            sv_lo = sv & 0xFFFF
                            if sv_hi in SOC_HW16_TO_SOC:
                                soc_hw16 = sv_hi
                                break
                            if sv_lo in SOC_HW16_TO_SOC:
                                soc_hw16 = sv_lo
                                break
            cert_start = 48 + common_sz + qti_sz + code_sz + qti_sig_sz + qti_cert_sz + sig_sz
            if cert_sz > 200 and cert_start + cert_sz <= len(hash_seg):
                c_pk, c_hw, c_oem, c_sv = _extract_asn1_certs_and_meta(hash_seg[cert_start : cert_start + cert_sz])
                pk_hash = c_pk or pk_hash
                if not hwid32 and c_hw:
                    hwid32 = c_hw
                if not oem_id and c_oem:
                    oem_id = c_oem
                if not soc_hw16 and c_sv:
                    soc_hw16 = c_sv
        elif ver in (3, 5):
            c_pk, c_hw, c_oem, c_sv = _extract_asn1_certs_and_meta(hash_seg)
            pk_hash, hwid32, oem_id, soc_hw16 = c_pk, c_hw, c_oem, c_sv

    if not pk_hash and hash_seg:
        c_pk, c_hw, c_oem, c_sv = _extract_asn1_certs_and_meta(hash_seg)
        pk_hash = c_pk
        if not hwid32 and c_hw:
            hwid32 = c_hw
        if not oem_id and c_oem:
            oem_id = c_oem
        if not soc_hw16 and c_sv:
            soc_hw16 = c_sv

    msm_hwid = "0x00000000"
    if hwid32 and (hwid32 & 0xFF) == 0xE1:
        msm_hwid = f"0x{hwid32:08X}"
    elif soc_hw16:
        msm_hwid = f"0x{soc_hw16:04X}0000"

    return {
        "fmt": fmt,
        "elf_class": elf_class,
        "msm_hwid": msm_hwid,
        "soc_hw16": soc_hw16,
        "oem_id": oem_id,
        "pk_hash": pk_hash,
    }


def resolve_local_file(entry: Dict[str, Any], nut_root: Path, qcom_root: Optional[Path]) -> Optional[Path]:
    rel_path = str(entry.get("path") or "").lstrip("/")
    if not rel_path:
        return None
    repo = str(entry.get("repo") or "")
    url = str(entry.get("url") or entry.get("raw_url") or "")
    is_qcom_repo = ("Qualcomm_Loaders" in repo) or ("Qualcomm_Loaders" in url)
    if is_qcom_repo and qcom_root:
        cand = qcom_root / rel_path
        if cand.is_file():
            return cand
    cand = nut_root / rel_path
    if cand.is_file():
        return cand
    if qcom_root:
        cand2 = qcom_root / rel_path
        if cand2.is_file():
            return cand2
    return None


def resolve_authoritative_soc(hwid_hex: str, soc_hw16: int) -> str:
    hw_up = (hwid_hex or "").upper()
    if hw_up in HWID_TO_SOC:
        return HWID_TO_SOC[hw_up]
    if soc_hw16 in SOC_HW16_TO_SOC:
        return SOC_HW16_TO_SOC[soc_hw16]
    if hw_up.startswith("0X") and len(hw_up) == 10 and hw_up.endswith("0000"):
        try:
            hi16 = int(hw_up[2:6], 16)
            if hi16 in SOC_HW16_TO_SOC:
                return SOC_HW16_TO_SOC[hi16]
        except ValueError:
            pass
    return ""


def enrich_entry(entry: Dict[str, Any], meta: Dict[str, Any]) -> Dict[str, Any]:
    name = str(entry.get("name") or "")
    rel_path = str(entry.get("path") or "")
    low_path = rel_path.lower()

    fn_hwid = ""
    fn_oem = 0
    fn_pk = ""
    m = HEX16_NAME_RE.match(name)
    if m:
        if m.group(1) != "00000000":
            fn_hwid = f"0x{m.group(1).upper()}"
        fn_oem = int(m.group(2), 16)
        fn_pk = m.group(4).lower()

    bin_hwid = str(meta["msm_hwid"])
    if fn_hwid:
        final_hwid = fn_hwid
    elif bin_hwid != "0x00000000":
        final_hwid = bin_hwid
    else:
        cur_hw = str(entry.get("msm_hwid") or "0x00000000").upper()
        final_hwid = "0x" + cur_hw[2:] if cur_hw.startswith("0X") and len(cur_hw) == 10 else "0x00000000"
        if final_hwid == "0x001360E1" and "samsung" in low_path and "g991" in low_path:
            final_hwid = "0x600F0000"

    entry["msm_hwid"] = final_hwid

    cur_pk = str(entry.get("pk_hash") or "").strip().lower()
    if meta["pk_hash"] and len(meta["pk_hash"]) >= len(cur_pk):
        entry["pk_hash"] = meta["pk_hash"]
    elif not cur_pk and fn_pk:
        entry["pk_hash"] = fn_pk

    oem_id = int(meta["oem_id"] or 0) or fn_oem
    if oem_id:
        entry["oem_id"] = f"{oem_id:04x}"
        oem_brand = OEM_ID_TO_BRAND.get(oem_id)
        cur_brand = str(entry.get("brand") or "generic").lower()
        if oem_brand:
            if cur_brand in ("", "generic", "unknown") or (oem_id == 0x0072 and cur_brand == "lenovo_motorola"):
                entry["brand"] = oem_brand

    if meta["elf_class"]:
        entry["elf_class"] = meta["elf_class"]

    auth_soc = resolve_authoritative_soc(final_hwid, int(meta["soc_hw16"] or 0))
    cur_soc = str(entry.get("soc") or "").strip()
    if auth_soc:
        entry["soc"] = auth_soc
    elif cur_soc == "SM8750":
        if not ("sm8750" in low_path or "/8e/" in low_path):
            entry["soc"] = "SM8450" if "s908" in low_path else ""

    final_soc = str(entry.get("soc") or "").upper()
    if final_soc in EMMC_ONLY_SOCS and "ufs" not in low_path:
        entry["storage"] = "eMMC"

    return entry


def preclean_dir(root: Path, label: str, purge: bool) -> Dict[str, int]:
    counts = Counter()
    if not root or not root.is_dir():
        return dict(counts)
    for fp in root.rglob("*"):
        if not fp.is_file():
            continue
        rel_parts = [p.lower() for p in fp.relative_to(root).parts[:-1]]
        if any(p in NON_QC_DIR_NAMES for p in rel_parts):
            continue
        ext = fp.suffix.lower()
        if ext in BAD_ARCHIVE_EXTS:
            counts["bad_archive"] += 1
            if purge:
                fp.unlink(missing_ok=True)
            continue
        if ext not in QC_BINARY_EXTS:
            continue
        try:
            data = fp.read_bytes()
        except OSError:
            continue
        ok, reason = is_valid_qc_bytes(data)
        if not ok:
            counts[f"bad_{reason}"] += 1
            if purge:
                fp.unlink(missing_ok=True)
        else:
            counts["valid"] += 1
    print(f"[preclean:{label}] purge={purge} stats={dict(counts)}")
    return dict(counts)


def run_enrich(nut_root: Path, qcom_root: Optional[Path], prev_version: int) -> None:
    final_qc_path = nut_root / "final_qc.json"
    main_path = nut_root / "main.json"
    report_path = nut_root / "report.txt"

    if not final_qc_path.is_file():
        print("ERROR: final_qc.json not found", file=sys.stderr)
        sys.exit(1)

    fq = json.loads(final_qc_path.read_text(encoding="utf-8"))
    raw_loaders = fq.get("loaders", [])
    cleaned: List[Dict[str, Any]] = []
    drop_stats = Counter()

    for item in raw_loaders:
        rel_path = str(item.get("path") or "").lstrip("/")
        if rel_path.startswith("_qcom_loaders/") or rel_path.startswith("bl/"):
            drop_stats["dropped_bad_dir"] += 1
            continue
        local_f = resolve_local_file(item, nut_root, qcom_root)
        if not local_f:
            drop_stats["dropped_missing"] += 1
            continue
        meta = parse_qc_metadata(local_f)
        if not meta:
            drop_stats["dropped_corrupt_or_encrypted"] += 1
            continue
        cleaned.append(enrich_entry(dict(item), meta))
        drop_stats["kept"] += 1

    by_brand = Counter(str(x.get("brand") or "generic") for x in cleaned)
    by_auth = Counter(str(x.get("auth_mode") or "standard") for x in cleaned)
    pk_cnt = sum(1 for x in cleaned if len(str(x.get("pk_hash") or "")) >= 16)
    soc_cnt = sum(1 for x in cleaned if str(x.get("soc") or "").strip())

    fq["loaders"] = cleaned
    fq["stats"] = {
        **fq.get("stats", {}),
        "deduped_qc_loaders": len(cleaned),
        "by_brand": dict(sorted(by_brand.items(), key=lambda kv: (-kv[1], kv[0]))),
        "by_auth_mode": dict(sorted(by_auth.items(), key=lambda kv: (-kv[1], kv[0]))),
    }
    final_qc_path.write_text(json.dumps(fq, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # Sync cleaned QC loaders into main.json (grouped dict: main["qualcomm"]["loaders"][brand])
    if main_path.is_file():
        mj = json.loads(main_path.read_text(encoding="utf-8"))
        grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for entry in cleaned:
            grouped[str(entry.get("brand") or "generic")].append(entry)
        qc_sec = mj.setdefault("qualcomm", {})
        qc_sec["loaders"] = {b: grouped[b] for b in sorted(grouped.keys())}
        if "count" in qc_sec:
            qc_sec["count"] = len(cleaned)
        if isinstance(mj.get("stats"), dict):
            mj["stats"]["deduped_qc_loaders"] = len(cleaned)
            if "by_brand" in mj["stats"]:
                mj["stats"]["by_brand"] = fq["stats"]["by_brand"]
            if "by_auth_mode" in mj["stats"]:
                mj["stats"]["by_auth_mode"] = fq["stats"]["by_auth_mode"]
        if prev_version > 0:
            mj["version"] = max(prev_version + 1, int(mj.get("version") or 0))
        main_path.write_text(json.dumps(mj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    summary = (
        f"[enrich] final_qc: {len(raw_loaders)} -> {len(cleaned)} valid | "
        f"PK_HASH: {pk_cnt}/{len(cleaned)} ({100.0 * pk_cnt / max(1, len(cleaned)):.1f}%) | "
        f"SoC: {soc_cnt}/{len(cleaned)} ({100.0 * soc_cnt / max(1, len(cleaned)):.1f}%) | "
        f"{dict(drop_stats)}"
    )
    print(summary)
    if report_path.is_file():
        prev = report_path.read_text(encoding="utf-8").rstrip()
        report_path.write_text(prev + "\n\n--- Clean & Enrich ---\n" + summary + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("preclean", "enrich"), default="enrich")
    ap.add_argument("--nut-dir", default=".")
    ap.add_argument("--qcom-dir", default="")
    ap.add_argument("--purge-qcom-temp", action="store_true")
    ap.add_argument("--purge-nut-bad", action="store_true")
    ap.add_argument("--prev-version", type=int, default=0)
    args = ap.parse_args()

    nut_root = Path(args.nut_dir).resolve()
    qcom_root = Path(args.qcom_dir).resolve() if args.qcom_dir and Path(args.qcom_dir).is_dir() else None

    if args.mode == "preclean":
        if qcom_root:
            preclean_dir(qcom_root, "qcom_temp", purge=args.purge_qcom_temp)
        preclean_dir(nut_root, "nut_repo", purge=args.purge_nut_bad)
    else:
        run_enrich(nut_root, qcom_root, args.prev_version)
    return 0


if __name__ == "__main__":
    sys.exit(main())