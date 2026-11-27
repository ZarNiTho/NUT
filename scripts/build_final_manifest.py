#!/usr/bin/env python3
"""Pre-cleaner + MBN v3/v5/v6/v7 & X.509 Enricher for ZarNiTho/NUT manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
from collections import Counter
from pathlib import Path
from typing import Any

MIN_QC_SIZE = 4096
MAX_QC_SIZE = 4 * 1024 * 1024

NON_FIREHOSE_EXTS = {
    ".7z", ".zip", ".rar", ".tar", ".tgz", ".gz", ".xz", ".bz2",
    ".apk", ".exe", ".pdf", ".txt", ".md", ".json", ".xml", ".html",
}

SOC_HW16_TO_SOC: dict[int, str] = {
    0x3002: "SDM835",
    0x3006: "SDM660",
    0x3007: "SDM630",
    0x6000: "SDM845",
    0x6003: "SM8150",
    0x6004: "SDM710",
    0x6007: "SM6150",
    0x6008: "SM8250",
    0x600C: "SM7150",
    0x600E: "SM7125",
    0x600F: "SM8350",
    0x6010: "SM7325",
    0x6014: "SM7250",
    0x6017: "SM6115",
    0x6018: "SM4250",
    0x601A: "SM6225",
    0x601B: "SM6375",
}

HWID_FIXUPS: dict[str, str] = {
    "0x0014D0E1": "SM6115",
    "0x0014E0E1": "SM6115",
    "0x001360E1": "SM6115",
    "0x000BA0E1": "SDM632",
    "0x000CC0E1": "SDM636",
    "0x0005E0E1": "SDM835",
    "0x000460E1": "MSM8953",
}

OEM_ID_TO_BRAND: dict[str, str] = {
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

CERT_OU_HWID_RE = re.compile(rb"01\s+([0-9A-Fa-f]{16})\s+HW_ID")
CERT_OU_OEM_RE = re.compile(rb"03\s+([0-9A-Fa-f]{4,8})\s+OEM_ID")
CERT_OU_MODEL_RE = re.compile(rb"04\s+([0-9A-Fa-f]{4,8})\s+MODEL_ID")
CERT_OU_SOCVERS_RE = re.compile(rb"0B\s+([0-9A-Fa-f]{8,64})\s+SOC_VERS")
SHA384_OIDS = (
    b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c",  # sha384WithRSAEncryption
    b"\x2a\x86\x48\xce\x3d\x04\x03\x03",      # ecdsa-with-SHA384
)


def classify_qc_binary(path: Path) -> tuple[bool, str]:
    """Strictly validate Qualcomm Firehose ELF32/ELF64 or Legacy MBN."""
    if not path.is_file():
        return False, "missing"
    if path.suffix.lower() in NON_FIREHOSE_EXTS:
        return False, "non_firehose_ext"
    size = path.stat().st_size
    if size < MIN_QC_SIZE:
        return False, "too_small"
    if size > MAX_QC_SIZE:
        return False, "too_large"
    with path.open("rb") as f:
        head = f.read(512)
    if len(head) < 40:
        return False, "too_small"

    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return False, "7z_archive"
    if head.startswith(b"data ddc"):
        return False, "mrt_ddc"
    if head.startswith(b".rtc"):
        return False, "eft_rtc"
    if head.startswith(b"\x7fELE"):
        return False, "obfuscated_ele"
    if head.startswith((b"PK\x03\x04", b"Rar!")):
        return False, "zip_rar"
    if head.startswith((b"MMM", b"EMMC_BOOT", b"UFS_BOOT", b"BRLYT")) or b"MTK_BLOADER_INFO" in head:
        return False, "mtk_binary"

    # Valid Little-Endian ELF32 / ELF64
    if head[:4] == b"\x7fELF" and head[4] in (1, 2) and head[5] == 1:
        return True, "elf32" if head[4] == 1 else "elf64"

    # Valid Legacy Qualcomm MBN (codeword + magic, or 40B MBN v3 header)
    if head[:4] in (b"\xd1\xdc\x4b\x84", b"\xd1\xdc\x4b\x87", b"\x84\x4b\xdc\xd1") and head[4:8] == b"\x34\x10\xd7\x73":
        return True, "mbn_legacy"
    img_id, ver, _, _, img_sz, code_sz = struct.unpack_from("<6I", head, 0)
    if ver in (3, 5, 6, 7) and img_id <= 0x40 and 4096 <= img_sz <= MAX_QC_SIZE and code_sz <= img_sz:
        return True, f"mbn_v{ver}"

    return False, f"unknown_{head[:4].hex()}"


def extract_certs_der(blob: bytes) -> list[bytes]:
    certs: list[bytes] = []
    i, n = 0, len(blob)
    while i < n - 10:
        idx = blob.find(b"\x30\x82", i)
        if idx == -1 or idx + 8 > n:
            break
        total = 4 + struct.unpack(">H", blob[idx + 2 : idx + 4])[0]
        if 300 <= total <= 4096 and idx + total <= n and blob[idx + 4 : idx + 6] == b"\x30\x82":
            cert = blob[idx : idx + total]
            if b"\x55\x04" in cert:
                certs.append(cert)
                i = idx + total
                continue
        i = idx + 2
    return certs


def parse_qc_metadata(path: Path) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    raw = path.read_bytes()
    if len(raw) < 64:
        return meta

    hash_seg = b""
    mbn_ver = 0
    if raw[:4] == b"\x7fELF" and raw[4] in (1, 2):
        ei_class = raw[4]
        if ei_class == 1:
            phoff = struct.unpack_from("<I", raw, 28)[0]
            phentsize, phnum = struct.unpack_from("<HH", raw, 42)
            segs = [
                (p[0], p[1], p[4], p[6])
                for i in range(phnum)
                if phoff + (i + 1) * phentsize <= len(raw)
                for p in (struct.unpack_from("<IIIIIIII", raw, phoff + i * phentsize),)
            ]
        else:
            phoff = struct.unpack_from("<Q", raw, 32)[0]
            phentsize, phnum = struct.unpack_from("<HH", raw, 54)
            segs = [
                (p[0], p[2], p[5], p[1])
                for i in range(phnum)
                if phoff + (i + 1) * phentsize <= len(raw)
                for p in (struct.unpack_from("<IIQQQQQQ", raw, phoff + i * phentsize),)
            ]
        for _, p_off, p_fsz, p_flags in segs:
            if (p_flags & 0x07000000) == 0x02000000 and p_fsz >= 40 and p_off + p_fsz <= len(raw):
                hash_seg = raw[p_off : p_off + p_fsz]
                break

    if hash_seg:
        _, w1 = struct.unpack_from("<II", hash_seg, 0)
        if w1 == 6 and len(hash_seg) >= 80:
            mbn_ver = 6
            for hdr_sz in (48, 36, 40):
                if hdr_sz + 80 <= len(hash_seg):
                    vals = struct.unpack_from("<8I", hash_seg, hdr_sz)
                    if vals[0] in (0, 1, 2, 3) and vals[1] == 0 and vals[2] in (3, 7):
                        if vals[3] and vals[3] != 0xFFFFFFFF:
                            meta["msm_hwid"] = f"0x{vals[3]:08X}"
                        if vals[4] and vals[4] <= 0xFFFF:
                            meta["oem_id"] = f"{vals[4]:04X}"
                        soc_vers = [x for x in struct.unpack_from("<12I", hash_seg, hdr_sz + 32) if x not in (0, 0xFFFFFFFF)]
                        if soc_vers and "msm_hwid" not in meta:
                            sv16 = soc_vers[0] & 0xFFFF
                            if sv16:
                                meta["msm_hwid"] = f"0x{sv16:04X}0000"
                                if sv16 in SOC_HW16_TO_SOC:
                                    meta["chipset"] = SOC_HW16_TO_SOC[sv16]
                        break
        elif w1 == 7 and len(hash_seg) >= 96:
            mbn_ver = 7
            cm_sz, qm_sz, om_sz = struct.unpack_from("<III", hash_seg, 8)
            oem_off = 64 + cm_sz + qm_sz
            if om_sz >= 32 and oem_off + 80 <= len(hash_seg):
                vals = struct.unpack_from("<8I", hash_seg, oem_off)
                if vals[3] and vals[3] != 0xFFFFFFFF:
                    meta["msm_hwid"] = f"0x{vals[3]:08X}"
                if vals[4] and vals[4] <= 0xFFFF:
                    meta["oem_id"] = f"{vals[4]:04X}"
                soc_vers = [x for x in struct.unpack_from("<12I", hash_seg, oem_off + 32) if x not in (0, 0xFFFFFFFF)]
                if soc_vers and "msm_hwid" not in meta:
                    sv16 = soc_vers[0] & 0xFFFF
                    if sv16:
                        meta["msm_hwid"] = f"0x{sv16:04X}0000"
                        if sv16 in SOC_HW16_TO_SOC:
                            meta["chipset"] = SOC_HW16_TO_SOC[sv16]

    buf = hash_seg if hash_seg else raw[: min(len(raw), 512 * 1024)]
    m_hw = CERT_OU_HWID_RE.search(buf)
    if m_hw:
        full = m_hw.group(1).decode("ascii").upper()
        meta.setdefault("msm_hwid", "0x" + full[:8])
        meta.setdefault("oem_id", full[8:12])
    else:
        m_oem = CERT_OU_OEM_RE.search(buf)
        if m_oem:
            meta.setdefault("oem_id", m_oem.group(1).decode("ascii").upper().zfill(4)[-4:])
    m_sv = CERT_OU_SOCVERS_RE.search(buf)
    if m_sv and "msm_hwid" not in meta:
        sv_hex = m_sv.group(1).decode("ascii").upper()
        sv16 = int(sv_hex[-4:], 16)
        if sv16:
            meta["msm_hwid"] = f"0x{sv16:04X}0000"
            if sv16 in SOC_HW16_TO_SOC:
                meta.setdefault("chipset", SOC_HW16_TO_SOC[sv16])

    certs = extract_certs_der(buf)
    if certs:
        root_cert = certs[-1]
        use_384 = mbn_ver >= 6 and any(oid in root_cert for oid in SHA384_OIDS)
        meta["pk_hash"] = (hashlib.sha384(root_cert) if use_384 else hashlib.sha256(root_cert)).hexdigest()[:16]

    return meta


def preclean_dir(target_dir: Path, purge: bool, label: str) -> Counter[str]:
    stats: Counter[str] = Counter()
    if not target_dir.is_dir():
        return stats
    skip_top = {".git", ".github", "da", "preloader", "payloads", "targets", "spd", "tempblu", "scripts", "wiko"}
    for root, dirs, files in os.walk(target_dir):
        cur = Path(root)
        if cur == target_dir:
            dirs[:] = [d for d in dirs if d.lower() not in skip_top]
        rel_dir = cur.relative_to(target_dir).as_posix().lower() if cur != target_dir else ""
        if "xiaomi/sig" in rel_dir:
            continue
        for fn in files:
            p = cur / fn
            fn_low = fn.lower()
            if fn.startswith(".") or fn_low.endswith((".json", ".txt", ".md", ".py", ".yml", ".yaml", ".xml", ".h")):
                continue
            if "digest" in fn_low or fn_low in ("sig", "sign.bin") or fn_low.endswith("_sign.bin"):
                continue
            ok, reason = classify_qc_binary(p)
            if ok:
                stats[f"valid_{reason}"] += 1
            else:
                stats[f"rejected_{reason}"] += 1
                if purge:
                    p.unlink(missing_ok=True)
    print(f"[PRECLEAN:{label}] purge={purge} -> {dict(stats)}")
    return stats


def enrich_manifests(nut_dir: Path, qcom_dir: Path | None, prev_version: int) -> None:
    main_path = nut_dir / "main.json"
    final_path = nut_dir / "final_qc.json"
    report_path = nut_dir / "report.txt"
    if not main_path.is_file():
        raise FileNotFoundError(f"Missing {main_path}")

    main_data = json.loads(main_path.read_text(encoding="utf-8"))
    reject_counts: Counter[str] = Counter()
    enriched_hwid = 0
    enriched_pk = 0
    fixed_brand = 0

    def resolve_local(entry: dict[str, Any]) -> Path | None:
        rel = entry.get("path", "")
        if not rel or rel.startswith(("_qcom_loaders/", "bl/")):
            return None
        repo = entry.get("repo", "")
        if "Qualcomm_Loaders" in repo and qcom_dir:
            return qcom_dir / rel
        return nut_dir / rel

    new_by_brand: dict[str, list[dict[str, Any]]] = {}
    kept_ids: set[str] = set()
    kept_total = 0

    for brand_key, items in main_data.get("qualcomm", {}).get("loaders", {}).items():
        for entry in items:
            local = resolve_local(entry)
            if local is None:
                reject_counts["ghost_or_bl_path"] += 1
                continue
            ok, reason = classify_qc_binary(local)
            if not ok:
                reject_counts[reason] += 1
                continue

            meta = parse_qc_metadata(local)
            hw = str(entry.get("msm_hwid") or "").upper()
            if (not hw or hw == "0X00000000") and meta.get("msm_hwid"):
                entry["msm_hwid"] = meta["msm_hwid"]
                hw = meta["msm_hwid"].upper()
                enriched_hwid += 1
            if hw in HWID_FIXUPS:
                entry["chipset"] = HWID_FIXUPS[hw]
            elif not entry.get("chipset") and meta.get("chipset"):
                entry["chipset"] = meta["chipset"]

            if not entry.get("pk_hash") and meta.get("pk_hash"):
                entry["pk_hash"] = meta["pk_hash"]
                enriched_pk += 1

            oem_id = meta.get("oem_id", "")
            target_brand = brand_key
            if brand_key == "generic" and oem_id in OEM_ID_TO_BRAND:
                target_brand = OEM_ID_TO_BRAND[oem_id]
                entry["brand"] = target_brand
                fixed_brand += 1

            new_by_brand.setdefault(target_brand, []).append(entry)
            kept_ids.add(entry.get("id", ""))
            kept_total += 1

    main_data["version"] = max(prev_version + 1, int(main_data.get("version", 218)) + 1)
    main_data["qualcomm"]["loaders"] = dict(sorted(new_by_brand.items()))
    main_data.setdefault("stats", {})["deduped_qc_loaders"] = kept_total
    main_data["stats"]["qc_rejected_corrupt"] = sum(reject_counts.values())
    main_data["stats"]["qc_enriched_hwid"] = enriched_hwid
    main_data["stats"]["qc_enriched_pk_hash"] = enriched_pk
    main_path.write_text(json.dumps(main_data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if final_path.is_file():
        final_data = json.loads(final_path.read_text(encoding="utf-8"))
        flat_map = {e["id"]: e for items in new_by_brand.values() for e in items}
        cleaned_flat = []
        for rec in final_data.get("loaders", []):
            upd = flat_map.get(rec.get("id", ""))
            if not upd:
                continue
            rec["msm_hwid"] = upd["msm_hwid"]
            rec["pk_hash"] = upd["pk_hash"]
            rec["soc"] = upd.get("chipset", rec.get("soc", ""))
            rec["brand"] = upd.get("brand", rec.get("brand", ""))
            cleaned_flat.append(rec)
        final_data["loaders"] = cleaned_flat
        final_data.setdefault("stats", {})["deduped_qc_loaders"] = len(cleaned_flat)
        final_path.write_text(json.dumps(final_data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")

    summary = [
        "",
        "SANITIZE & MBN v6/v7 ENRICHMENT SUMMARY",
        "-" * 64,
        f"Manifest version: v{main_data['version']}",
        f"Valid Firehose ELF/MBN kept: {kept_total}",
        f"Corrupt/Encrypted/404 rejected: {sum(reject_counts.values())} -> {dict(reject_counts)}",
        f"Auto-enriched HWID: +{enriched_hwid}, PK_HASH: +{enriched_pk}, Brand from OEM_ID: +{fixed_brand}",
    ]
    if report_path.is_file():
        report_path.write_text(report_path.read_text(encoding="utf-8") + "\n".join(summary) + "\n", encoding="utf-8")
    print("\n".join(summary))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=("preclean", "enrich"), required=True)
    ap.add_argument("--nut-dir", default=".")
    ap.add_argument("--qcom-dir", default="")
    ap.add_argument("--purge-nut-bad", action="store_true", help="Delete corrupt/7z files in NUT repo (e.g. bl/)")
    ap.add_argument("--purge-qcom-temp", action="store_true", help="Delete corrupt files in temp qcom clone before scan")
    ap.add_argument("--prev-version", type=int, default=218)
    args = ap.parse_args()

    nut_dir = Path(args.nut_dir).resolve()
    qcom_dir = Path(args.qcom_dir).resolve() if args.qcom_dir else None

    if args.mode == "preclean":
        preclean_dir(nut_dir, purge=args.purge_nut_bad, label="NUT")
        if qcom_dir:
            preclean_dir(qcom_dir, purge=args.purge_qcom_temp, label="Qualcomm_Loaders")
    else:
        enrich_manifests(nut_dir, qcom_dir, args.prev_version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())