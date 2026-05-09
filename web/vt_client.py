# -*- coding: utf-8 -*-
"""Tra cứu VirusTotal API v3 theo SHA256 và/hoặc MD5 (không upload file)."""
from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request

VT_FILES_URL = "https://www.virustotal.com/api/v3/files/"


def _normalize_engine_results(raw: dict) -> list[dict]:
    """Chuẩn hóa last_analysis_results của VT → list hiển thị trên UI."""
    if not isinstance(raw, dict):
        return []
    out: list[dict] = []
    for engine_name in sorted(raw.keys(), key=lambda x: str(x).lower()):
        entry = raw.get(engine_name)
        if not isinstance(entry, dict):
            continue
        cat = str(entry.get("category") or "").lower() or "unknown"
        result = entry.get("result")
        if result is not None and not isinstance(result, str):
            result = str(result)
        out.append(
            {
                "engine": str(engine_name),
                "category": cat,
                "result": result,
            }
        )
    return out


def _https_context() -> ssl.SSLContext:
    """Dùng bundle CA từ certifi (tránh lỗi CERTIFICATE_VERIFY_FAILED trên nhiều bản Python/macOS)."""
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def _valid_hex_hash(value: str, length: int) -> bool:
    h = (value or "").strip().lower()
    return len(h) == length and all(c in "0123456789abcdef" for c in h)


def _vt_fetch_json(api_key: str, file_id: str, timeout: float) -> tuple[str, dict | None]:
    """
    GET /api/v3/files/{file_id}
    file_id: SHA256 (64), SHA1 (40) hoặc MD5 (32) — VirusTotal tự nhận diện.

    Trả về:
      ("ok", body_dict)
      ("not_found", None)
      ("error", error_result_dict) — trả thẳng cho client, không thử hash khác (429, 5xx, …)
    """
    hid = (file_id or "").strip().lower()
    url = VT_FILES_URL + hid
    req = urllib.request.Request(url, headers={"x-apikey": api_key})
    ctx = _https_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return "ok", body
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "not_found", None
        if e.code == 429:
            return "error", {
                "queried": True,
                "configured": True,
                "available": False,
                "error": "rate_limited",
                "message": "Vượt giới hạn API VirusTotal (429). Đợi vài phút hoặc kiểm tra hạn mức gói.",
            }
        try:
            detail = e.read().decode("utf-8", errors="replace")
        except Exception:
            detail = ""
        return "error", {
            "queried": True,
            "configured": True,
            "available": False,
            "error": f"http_{e.code}",
            "message": (detail or str(e))[:800],
        }
    except urllib.error.URLError as e:
        reason = getattr(e, "reason", None) or str(e)
        return "error", {
            "queried": True,
            "configured": True,
            "available": False,
            "error": "network",
            "message": str(reason),
        }
    except Exception as e:
        return "error", {
            "queried": True,
            "configured": True,
            "available": False,
            "error": "parse_or_unknown",
            "message": str(e)[:500],
        }


def _build_success_result(body: dict, *, lookup_via: str, lookup_hash: str) -> dict:
    data = body.get("data") or {}
    attr = data.get("attributes") or {}
    stats = attr.get("last_analysis_stats") or {}
    engines = attr.get("last_analysis_results") or {}

    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    undetected = int(stats.get("undetected") or 0)
    harmless = int(stats.get("harmless") or 0)
    total = malicious + suspicious + undetected + harmless
    if total <= 0 and isinstance(engines, dict) and engines:
        total = len(engines)

    tags = attr.get("tags")
    if not isinstance(tags, list):
        tags = []

    canonical_sha = attr.get("sha256") or data.get("id") or lookup_hash
    if isinstance(canonical_sha, str):
        canonical_sha = canonical_sha.strip().lower()
    else:
        canonical_sha = (lookup_hash or "").strip().lower()

    permalink = f"https://www.virustotal.com/gui/file/{canonical_sha}" if canonical_sha else None

    md5_attr = attr.get("md5")
    if isinstance(md5_attr, str):
        md5_attr = md5_attr.lower()

    return {
        "queried": True,
        "configured": True,
        "available": True,
        "lookup_via": lookup_via,
        "lookup_hash": lookup_hash,
        "sha256": canonical_sha,
        "md5": md5_attr,
        "stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": undetected,
            "harmless": harmless,
            "timeout": int(stats.get("timeout") or 0),
            "failure": int(stats.get("failure") or 0),
        },
        "engines_reported": total if total > 0 else None,
        "meaningful_name": attr.get("meaningful_name"),
        "type_description": attr.get("type_description"),
        "size": attr.get("size"),
        "tags": [str(t) for t in tags[:40]],
        "engine_results": _normalize_engine_results(engines),
        "permalink": permalink,
    }


def virustotal_file_report(
    api_key: str,
    sha256_hex: str = "",
    md5_hex: str = "",
    timeout: float = 28.0,
) -> dict:
    """
    Tra cứu báo cáo file: ưu tiên SHA256, nếu 404 thì thử MD5 (một request thêm — tiết kiệm quota).
    """
    key = (api_key or "").strip()
    if not key:
        return {
            "queried": False,
            "configured": False,
            "message": "Chưa cấu hình VIRUSTOTAL_API_KEY trong môi trường.",
        }

    sha = (sha256_hex or "").strip().lower()
    md = (md5_hex or "").strip().lower()

    attempts: list[tuple[str, str]] = []
    if _valid_hex_hash(sha, 64):
        attempts.append(("sha256", sha))
    if _valid_hex_hash(md, 32):
        attempts.append(("md5", md))

    if not attempts:
        return {
            "queried": False,
            "configured": True,
            "error": "invalid_hashes",
            "message": "Cần ít nhất một hash hợp lệ: SHA256 (64 ký tự hex) hoặc MD5 (32 ký tự hex).",
        }

    tried_404 = False
    for via, hid in attempts:
        status, payload = _vt_fetch_json(key, hid, timeout)
        if status == "ok" and payload is not None:
            return _build_success_result(payload, lookup_via=via, lookup_hash=hid)
        if status == "not_found":
            tried_404 = True
            continue
        if status == "error" and payload is not None:
            return payload

    if tried_404:
        msg = "Không tìm thấy file trên VirusTotal"
        if len(attempts) == 2:
            msg += " (đã thử SHA256 và MD5)."
        elif attempts[0][0] == "sha256":
            msg += " theo SHA256."
        else:
            msg += " theo MD5."
        return {
            "queried": True,
            "configured": True,
            "available": False,
            "not_found": True,
            "message": msg,
        }

    return {
        "queried": True,
        "configured": True,
        "available": False,
        "error": "unknown",
        "message": "Lỗi không xác định khi gọi VirusTotal.",
    }
