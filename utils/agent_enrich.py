
#!/usr/bin/env python3
"""
agent_two_enrich_core_local.py

Single-file, offline-only enrichment module for Agent Two that integrates with your
existing `core.config.settings` (Pydantic Settings) but gracefully falls back to env
variables or defaults when fields are missing.

Provided entrypoint:
    enrich_email_local(email: dict, agent_one: Optional[dict] = None, run_id: Optional[str] = None,
                       phishtank_path: Optional[str] = None,
                       geolite2_city: Optional[str] = None,
                       geolite2_asn: Optional[str] = None) -> dict
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Set, Tuple
import os, re, json, uuid, bz2, zipfile, hashlib

# ---- Settings bridge --------------------------------------------------------
def _get_path_from_settings_or_env(attr: str, env_key: str, default: str) -> str:
    try:
        from core.config import settings  # your Settings instance
        val = getattr(settings, attr, None)
        if val:
            return str(val)
    except Exception:
        pass
    return os.getenv(env_key, default)

DEFAULT_PHISHTANK = _get_path_from_settings_or_env("PHISHTANK_DB_PATH", "PHISHTANK_DB_PATH", "./phishtank/online-valid.json")
DEFAULT_GEO_CITY  = _get_path_from_settings_or_env("GEOLITE2_CITY_DB", "GEOLITE2_CITY_DB", "./geoip/GeoLite2-City.mmdb")
DEFAULT_GEO_ASN   = _get_path_from_settings_or_env("GEOLITE2_ASN_DB", "GEOLITE2_ASN_DB", "./geoip/GeoLite2-ASN.mmdb")

# ---- Heuristics & regexes ---------------------------------------------------
SUSPICIOUS_TLDS: Set[str] = {
    ".zip",".mov",".click",".xyz",".top",".mom",".gq",".tk",".ml",".cf",".work",".quest"
}
DANGEROUS_EXTS: Set[str] = {
    ".exe",".scr",".js",".vbs",".jar",".bat",".cmd",".ps1",
    ".docm",".xlsm",".pptm",".doc",".xls",".ppt",".rtf",
    ".zip",".rar",".7z",".iso",".dll"
}
LOGIN_PATH_HINT = re.compile(r"/(login|logon|signin|sign-in|verify|update|password|reset|auth|account)", re.I)
URL_RE = re.compile(r"(?P<url>(?:https?://|www\.)[^\s<>\"]+)", re.I)
EMAIL_RE = re.compile(r"<([^>]+)>")
PUNYCODE_PREFIX = "xn--"
PDF_URL_RE = re.compile(r"https?://[^\s<>\)\"']+", re.I)

# Optional deps
try:
    import magic  # python-magic
except Exception:
    magic = None
try:
    import oletools.olevba as olevba
except Exception:
    olevba = None
try:
    import pefile
except Exception:
    pefile = None
try:
    from PyPDF2 import PdfReader
except Exception:
    PdfReader = None
try:
    import geoip2.database
except Exception:
    geoip2 = None

# ---- Dataclass for the response shape --------------------------------------
@dataclass
class EnrichmentResult:
    run_id: str
    # Links
    url_count: int = 0
    url_domains: List[str] = None
    url_tlds: List[str] = None
    url_obfuscation_hits: int = 0
    url_looks_like_login: bool = False
    url_reputation: str = "unknown"  # "high"|"medium"|"low"|"unknown"
    # Attachments
    attachment_count: int = 0
    attachment_exts: List[str] = None
    attachment_dangerous: bool = False
    attachment_total_size: Optional[int] = None
    attachment_macro_detected: bool = False
    attachment_archive_contains_dangerous: bool = False
    attachment_pdf_links: bool = False
    # Headers/auth
    spf: str = "unknown"
    dkim: str = "unknown"
    dmarc: str = "unknown"
    reply_to_mismatch: bool = False
    # IP/Geo/ASN
    sender_ip: Optional[str] = None
    sender_asn: Optional[str] = None
    sender_geo: Optional[str] = None
    # Language
    lang_code: Optional[str] = None
    lang_confidence: Optional[float] = None
    # Derived flags
    suspicious_link: bool = False
    suspicious_attachment: bool = False
    needs_review: bool = False
    # Evidence
    details: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["url_domains"] = d.get("url_domains") or []
        d["url_tlds"] = d.get("url_tlds") or []
        d["attachment_exts"] = d.get("attachment_exts") or []
        d["details"] = d.get("details") or {}
        return d

# ---- Utilities --------------------------------------------------------------
def _normalize_url(u: str) -> str:
    u = u.strip()
    if u.startswith("www."):
        u = "http://" + u
    return u

def _domain_from_url(u: str) -> Optional[str]:
    try:
        from urllib.parse import urlparse
        host = urlparse(_normalize_url(u)).netloc.lower().split(":")[0]
        return host or None
    except Exception:
        return None

def _tld_from_domain(host: str) -> Optional[str]:
    if not host or "." not in host: return None
    return host[host.rfind("."):].lower()

def _email_addr(s: str) -> str:
    m = EMAIL_RE.search(s or "")
    if m: return m.group(1).strip().lower()
    return (s or "").strip().lower()

def _domain_from_email_addr(addr: str) -> Optional[str]:
    return addr.split("@",1)[1].lower() if (addr and "@" in addr) else None

def _header_value(headers: Dict[str, Any], key: str) -> Optional[str]:
    if not headers: return None
    for k, v in headers.items():
        if k.lower() == key.lower(): return v
    return None

def _extract_urls(email: Dict[str, Any]) -> List[str]:
    urls = set()
    for f in ("links_json",):
        for u in (email.get(f) or []):
            if isinstance(u, str) and u.strip(): urls.add(u.strip())
    for f in ("body_plain","body_html"):
        txt = email.get(f) or ""
        for m in URL_RE.finditer(txt): urls.add(m.group("url").strip())
    return list(urls)

# ---- Link enrichment --------------------------------------------------------
def _enrich_links(email: Dict[str, Any]) -> Dict[str, Any]:
    urls = _extract_urls(email)
    domains, tlds = [], []
    obf_hits, looks_like_login, puny_hits = 0, False, 0
    for u in urls:
        host = _domain_from_url(u)
        if not host: continue
        domains.append(host)
        tld = _tld_from_domain(host)
        if tld: tlds.append(tld)
        if "@" in u or u.count(".") >= 4 or "0x" in u.lower(): obf_hits += 1
        if host.startswith(PUNYCODE_PREFIX) or f".{PUNYCODE_PREFIX}" in host: puny_hits += 1
        try:
            from urllib.parse import urlparse
            if LOGIN_PATH_HINT.search(urlparse(_normalize_url(u)).path or ""): looks_like_login = True
        except Exception: pass

    url_count = len(set(urls))
    suspicious_tld_count = sum(1 for t in tlds if t in SUSPICIOUS_TLDS)
    if url_count == 0:
        reputation = "unknown"
    else:
        if suspicious_tld_count > 0 or puny_hits > 0 or (obf_hits >= 1 and looks_like_login): reputation = "high"
        elif obf_hits >= 1 or looks_like_login or url_count >= 3: reputation = "medium"
        else: reputation = "low"

    return {
        "url_count": url_count,
        "url_domains": sorted(set(domains)),
        "url_tlds": sorted(set(tlds)),
        "url_obfuscation_hits": int(obf_hits + puny_hits),
        "url_looks_like_login": bool(looks_like_login),
        "url_reputation": reputation,
        "suspicious_link": (reputation in {"high","medium"}),
        "details_links": {"urls": sorted(set(urls)), "punycode_hits": int(puny_hits)}
    }

# ---- Header/auth enrichment -------------------------------------------------
def _norm_auth(v: Optional[str]) -> str:
    if v is None: return "unknown"
    s = str(v).strip().lower()
    if "pass" in s: return "pass"
    if "fail" in s: return "fail"
    if "none" in s: return "none"
    if "softfail" in s: return "softfail"
    return s or "unknown"

def _enrich_headers(email: Dict[str, Any]) -> Dict[str, Any]:
    h = email.get("headers_json") or {}
    spf = _norm_auth(_header_value(h, "SPF"))
    dkim = _norm_auth(_header_value(h, "DKIM"))
    dmarc = _norm_auth(_header_value(h, "DMARC"))
    from_raw = _header_value(h, "From") or email.get("sender_address") or ""
    reply_to_raw = _header_value(h, "Reply-To") or ""
    from_addr = _email_addr(from_raw)
    reply_to_addr = _email_addr(reply_to_raw)
    from_dom = _domain_from_email_addr(from_addr)
    reply_dom = _domain_from_email_addr(reply_to_addr)
    reply_to_mismatch = bool(from_dom and reply_dom and (from_dom != reply_dom))
    return {
        "spf": spf, "dkim": dkim, "dmarc": dmarc, "reply_to_mismatch": reply_to_mismatch,
        "details_headers": {"from_addr": from_addr, "reply_to_addr": reply_to_addr, "from_domain": from_dom, "reply_to_domain": reply_dom}
    }

# ---- IP enrichment (local-only) --------------------------------------------
def _enrich_ip(email: Dict[str, Any]) -> Dict[str, Any]:
    ip = email.get("sender_ip"); private = False
    if ip:
        try:
            import ipaddress
            private = ipaddress.ip_address(ip).is_private
        except Exception:
            pass
    return {"sender_ip": ip, "sender_asn": None, "sender_geo": "private" if private else None, "details_ip": {"private": private}}

# ---- Language detection (best-effort) --------------------------------------
def _detect_language(email: Dict[str, Any]) -> Dict[str, Any]:
    text = (email.get("body_plain") or "") + "\n" + (email.get("subject") or "")
    text = text.strip()
    if not text:
        return {"lang_code": None, "lang_confidence": None, "details_lang": {"used": "none"}}
    try:
        from langdetect import detect, DetectorFactory
        DetectorFactory.seed = 42
        code = detect(text)
        return {"lang_code": code, "lang_confidence": None, "details_lang": {"used": "langdetect"}}
    except Exception:
        import re as _re
        alpha = _re.sub(r"[^A-Za-z]", "", text)
        ratio = (len(alpha) / max(1, len(text)))
        code = "en" if ratio > 0.7 else None
        conf = 0.55 if code == "en" else None
        return {"lang_code": code, "lang_confidence": conf, "details_lang": {"used": "heuristic", "alpha_ratio": ratio}}

# ---- Attachment analyzer (passive) -----------------------------------------
def _file_ext(name: str) -> str:
    import os
    return os.path.splitext(name or "")[1].lower()

def _sha256_file(path: str, cap_mb: int = 50) -> Optional[str]:
    try:
        h = hashlib.sha256()
        cap = cap_mb * 1024 * 1024
        with open(path, "rb") as f:
            read = 0
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk: break
                h.update(chunk)
                read += len(chunk)
                if read >= cap: break
        return h.hexdigest()
    except Exception:
        return None

def _zip_members(path: str) -> Tuple[List[str], bool]:
    names, bad = [], False
    try:
        with zipfile.ZipFile(path, "r") as z:
            for n in z.namelist():
                names.append(n)
                if _file_ext(n) in DANGEROUS_EXTS:
                    bad = True
    except Exception:
        pass
    return names, bad

def _pdf_link_count(path: str) -> int:
    if PdfReader is None: return 0
    try:
        reader = PdfReader(path)
        n = 0
        for page in reader.pages:
            try:
                txt = page.extract_text() or ""
                n += len(PDF_URL_RE.findall(txt))
            except Exception:
                pass
            try:
                annots = page.get("/Annots") or []
                for a in annots:
                    try:
                        uri = a.get_object().get("/A", {}).get("/URI")
                        if uri: n += 1
                    except Exception: pass
            except Exception: pass
        return n
    except Exception:
        return 0

def _has_macros(path: str) -> bool:
    if olevba is None: return False
    try:
        vb = olevba.VBA_Parser(path)
        return vb.detect_vba_macros()
    except Exception:
        return False

def _is_pe(path: str) -> bool:
    if pefile is None: return False
    try:
        _ = pefile.PE(path, fast_load=True)
        return True
    except Exception:
        return False

def _magic_mime(path: str) -> Optional[str]:
    if magic is None: return None
    try:
        ms = magic.Magic(mime=True)
        return ms.from_file(path)
    except Exception:
        return None

def _enrich_attachments(email: Dict[str, Any]) -> Dict[str, Any]:
    attachments = email.get("attachments") or []
    results: List[Dict[str, Any]] = []
    any_danger = any_macro = any_zip_bad = any_pdf_links = False
    total_size = 0
    exts = set()

    for a in attachments[:10]:
        fn = (a.get("filename") if isinstance(a, dict) else str(a)) or ""
        p = (a.get("content_path") if isinstance(a, dict) else None) or ""
        size = a.get("size")
        mime = a.get("mime")
        ext = _file_ext(fn)
        if ext: exts.add(ext)

        sha256 = None; zip_names = []; zip_bad = False; pdf_links = 0
        has_mac = False; is_pe = False; mime_det = None

        if p and os.path.exists(p):
            try:
                if size is None: size = os.path.getsize(p)
                total_size += size or 0
            except Exception: pass

            mime_det = _magic_mime(p) or mime
            sha256 = _sha256_file(p)
            if ext == ".zip": zip_names, zip_bad = _zip_members(p)
            if ext == ".pdf": pdf_links = _pdf_link_count(p)
            if ext in {".doc",".docm",".xls",".xlsm",".ppt",".pptm"}: has_mac = _has_macros(p)
            if ext in {".exe",".dll"}: is_pe = _is_pe(p)

        danger = (ext in DANGEROUS_EXTS) or zip_bad or is_pe or has_mac
        any_danger = any_danger or danger
        any_macro = any_macro or has_mac
        any_zip_bad = any_zip_bad or zip_bad
        any_pdf_links = any_pdf_links or (pdf_links > 0)

        results.append({
            "filename": fn, "path": p or None, "size": size, "ext": ext,
            "mime": mime or mime_det, "sha256": sha256,
            "zip_members": zip_names if zip_names else None,
            "zip_contains_dangerous": zip_bad,
            "pdf_link_count": pdf_links if pdf_links else 0,
            "macros_detected": has_mac, "is_pe": is_pe, "danger": danger
        })

    return {
        "attachment_count": email.get("attachment_count") or len(attachments),
        "attachment_exts": sorted(e for e in exts if e),
        "attachment_dangerous": any_danger,
        "attachment_total_size": total_size,
        "attachment_macro_detected": any_macro,
        "attachment_archive_contains_dangerous": any_zip_bad,
        "attachment_pdf_links": any_pdf_links,
        "details_attachments": {"files": results}
    }

# ---- Offline providers ------------------------------------------------------
class PhishTankJSON:
    """
    Lightweight reader for online-valid.json (or .json.bz2).
    Builds:
      - exact URL set
      - best-by-host dict (largest phish_id wins)
    """
    def __init__(self, path: str):
        self.path = path
        self._exact = set()
        self._by_host: Dict[str, Dict[str, Any]] = {}
        self._loaded = False

    def _iter_rows(self):
        if self.path.endswith(".bz2"):
            data = bz2.decompress(open(self.path, "rb").read()).decode("utf-8", errors="ignore")
            obj = json.loads(data)
        else:
            obj = json.load(open(self.path, "r", encoding="utf-8", errors="ignore"))
        rows = obj if isinstance(obj, list) else obj.get("data", [])
        for e in rows:
            yield e

    @staticmethod
    def _host_of(url: str) -> str:
        try:
            from urllib.parse import urlparse
            return urlparse(url.strip()).netloc.lower()
        except Exception:
            return ""

    def load(self):
        if self._loaded: return
        if not self.path or not os.path.exists(self.path):
            self._loaded = True
            return
        for row in self._iter_rows():
            url = row.get("url")
            if not url: continue
            self._exact.add(url.strip())
            host = self._host_of(url)
            pid = int(row.get("phish_id") or 0)
            prev = self._by_host.get(host)
            if prev is None or pid > prev.get("_pid", -1):
                r = dict(row); r["_pid"] = pid
                self._by_host[host] = r
        self._loaded = True

    def risk(self, url: str) -> Optional[str]:
        if not self._loaded: self.load()
        if not self._by_host and not self._exact:
            return None  # db not provided
        u = (url or "").strip()
        if not u: return "unknown"
        if u in self._exact:
            host = self._host_of(u); row = self._by_host.get(host)
            v = str((row or {}).get("verified")).lower() in {"true","yes","1"}
            on = str((row or {}).get("online")).lower() in {"true","yes","1"}
            return "high" if (v and on) else "medium"
        host = self._host_of(u); row = self._by_host.get(host)
        if not row: return "unknown"
        v = str(row.get("verified")).lower() in {"true","yes","1"}
        on = str(row.get("online")).lower() in {"true","yes","1"}
        return "high" if (v and on) else "medium"

class GeoLocal:
    def __init__(self, city_mmdb: str, asn_mmdb: str):
        self.city_path = city_mmdb
        self.asn_path  = asn_mmdb
        self.city_r = None
        self.asn_r  = None
        if geoip2:
            if self.city_path and os.path.exists(self.city_path):
                try: self.city_r = geoip2.database.Reader(self.city_path)
                except Exception: self.city_r = None
            if self.asn_path and os.path.exists(self.asn_path):
                try: self.asn_r = geoip2.database.Reader(self.asn_path)
                except Exception: self.asn_r = None

    def intel(self, ip: str) -> Optional[Dict[str, Optional[str]]]:
        if not ip: return None
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast:
                return {"asn": None, "country": "private"}
        except Exception: pass
        if not (self.city_r or self.asn_r): return None
        country = None; asn = None
        try:
            if self.city_r:
                resp = self.city_r.city(ip)
                if resp and resp.country and resp.country.iso_code:
                    country = resp.country.iso_code
        except Exception: pass
        try:
            if self.asn_r:
                resp = self.asn_r.asn(ip)
                if resp and getattr(resp, "autonomous_system_number", None):
                    asn = f"AS{resp.autonomous_system_number}"
        except Exception: pass
        return {"asn": asn, "country": country} if (country or asn) else None

# ---- Derive flags -----------------------------------------------------------
def _derive_flags(parts: Dict[str, Any], agent_one: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    spf, dkim, dmarc = parts.get("spf","unknown"), parts.get("dkim","unknown"), parts.get("dmarc","unknown")
    suspicious_link = parts.get("suspicious_link", False)
    attachment_dangerous = parts.get("attachment_dangerous", False)
    needs_review = (((spf == "fail" or dkim == "fail" or dmarc == "fail") and suspicious_link)
                    or attachment_dangerous
                    or bool((agent_one or {}).get("requires_review", False)))
    return {
        "suspicious_link": bool(suspicious_link),
        "suspicious_attachment": bool(attachment_dangerous),
        "needs_review": bool(needs_review)
    }

# ---- Public API -------------------------------------------------------------
def enrich_email_local(
    email: Dict[str, Any],
    agent_one: Optional[Dict[str, Any]] = None,
    run_id: Optional[str] = None,
    *,
    phishtank_path: Optional[str] = None,
    geolite2_city: Optional[str] = None,
    geolite2_asn: Optional[str] = None
) -> Dict[str, Any]:
    """
    Offline enrichment using local datasets and passive static file checks.

    Args:
        email: dict with keys like subject, body_plain/body_html, headers_json, links_json (list),
               has_attachments, attachments: [{filename, content_path, size?, mime?}], sender_ip, sender_address
        agent_one: optional context (e.g., {"requires_review": True})
        run_id: optional external correlation id
        phishtank_path/geolite2_*: optional path overrides (else pulled from settings/env/defaults)

    Returns: dict (see EnrichmentResult schema)
    """
    rid = run_id or uuid.uuid4().hex[:12]

    # 1) local heuristics
    parts_links = _enrich_links(email)
    parts_headers = _enrich_headers(email)
    parts_ip = _enrich_ip(email)
    parts_lang = _detect_language(email)
    parts_attach = _enrich_attachments(email)

    # 2) offline URL rep (PhishTank)
    pt_path = phishtank_path or DEFAULT_PHISHTANK
    pt = PhishTankJSON(pt_path) if (pt_path and os.path.exists(pt_path)) else None
    urls = _extract_urls(email)
    levels = []
    if pt:
        for u in urls[:10]:
            lvl = pt.risk(u)
            if lvl:
                levels.append(lvl)
                if lvl == "high":
                    break
        if levels:
            def rk(x): return {"high":3,"medium":2,"low":1,"unknown":0}.get(x or "unknown", 0)
            ext_best = max(levels, key=rk)
            cur = parts_links["url_reputation"]
            parts_links["url_reputation"] = ext_best if rk(ext_best) > rk(cur) else cur
            parts_links["suspicious_link"] = (parts_links["url_reputation"] in {"high","medium"})
            parts_links.setdefault("details_links", {}).update({"phishtank_local": True, "phishtank_levels": levels})

    # 3) offline GeoLite2
    city = geolite2_city or DEFAULT_GEO_CITY
    asn = geolite2_asn or DEFAULT_GEO_ASN
    geo = GeoLocal(city, asn)
    ip = (email.get("sender_ip") or "").strip()
    if ip:
        g = geo.intel(ip)
        if g:
            parts_ip["sender_asn"] = g.get("asn") or parts_ip.get("sender_asn")
            parts_ip["sender_geo"] = g.get("country") or parts_ip.get("sender_geo")
            parts_ip.setdefault("details_ip", {}).update({"geolite2_local": True, "geo": g})

    # 4) merge & flags
    merged: Dict[str, Any] = {}
    for d in (parts_links, parts_attach, parts_headers, parts_ip, parts_lang):
        merged.update(d)

    flags = _derive_flags(merged, agent_one)

    result = EnrichmentResult(
        run_id=rid,
        url_count=merged.get("url_count", 0),
        url_domains=merged.get("url_domains", []),
        url_tlds=merged.get("url_tlds", []),
        url_obfuscation_hits=merged.get("url_obfuscation_hits", 0),
        url_looks_like_login=merged.get("url_looks_like_login", False),
        url_reputation=merged.get("url_reputation", "unknown"),
        attachment_count=merged.get("attachment_count", 0),
        attachment_exts=merged.get("attachment_exts", []),
        attachment_dangerous=merged.get("attachment_dangerous", False),
        attachment_total_size=merged.get("attachment_total_size"),
        attachment_macro_detected=merged.get("attachment_macro_detected", False),
        attachment_archive_contains_dangerous=merged.get("attachment_archive_contains_dangerous", False),
        attachment_pdf_links=merged.get("attachment_pdf_links", False),
        spf=merged.get("spf", "unknown"),
        dkim=merged.get("dkim", "unknown"),
        dmarc=merged.get("dmarc", "unknown"),
        reply_to_mismatch=merged.get("reply_to_mismatch", False),
        sender_ip=merged.get("sender_ip"),
        sender_asn=merged.get("sender_asn"),
        sender_geo=merged.get("sender_geo"),
        lang_code=merged.get("lang_code"),
        lang_confidence=merged.get("lang_confidence"),
        suspicious_link=flags["suspicious_link"],
        suspicious_attachment=flags["suspicious_attachment"],
        needs_review=flags["needs_review"],
        details={k: v for k, v in merged.items() if k.startswith("details_")}
    )
    return result.to_dict()
