import re
from urllib.parse import quote

import requests

from modules import EDY_RECON_VERSION
from modules.osint import APIError
from modules.safety import request_with_retry, safe_error, sanitize_data


class DarkWebScanner:
    UA = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) EDYRECON/{EDY_RECON_VERSION}"

    def __init__(self, cfg):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.UA})
        self._scan_cache = {}

    def _get(self, url, **kw):
        kw.setdefault("timeout", 20)
        try:
            return request_with_retry(self.session.get, url, max_attempts=2, **kw)
        except requests.exceptions.RequestException as e:
            raise APIError(safe_error(e))

    def _cached(self, provider, query, params, callback):
        key = (provider, str(query).strip().casefold(), tuple(sorted((params or {}).items())))
        if key not in self._scan_cache:
            self._scan_cache[key] = callback()
        return self._scan_cache[key]

    def intelx_darknet(self, query, maxresults=15, terminate=40):
        if not self.cfg.has_key("intelx"):
            return {"error": "sem chave IntelligenceX"}
        try:
            r = self._get(
                "https://2.intelx.io/intelligent/search",
                params={"q": query, "maxresults": maxresults, "media": 0, "sort": 2,
                        "datefrom": -1, "dateto": -1, "terminateafter": terminate},
                headers={"x-key": self.cfg.key("intelx")},
            )
            if r.status_code != 200:
                return {"error": f"IntelX HTTP {r.status_code}"}
            sid = r.json().get("id")
            if not sid:
                return {"ok": []}
            import time
            for _ in range(8):
                time.sleep(2)
                rr = self._get(
                    f"https://2.intelx.io/intelligent/search/result?id={sid}&limit=10",
                    headers={"x-key": self.cfg.key("intelx"), "x-intelx-api-key": self.cfg.key("intelx")},
                )
                if rr.status_code == 200:
                    res = rr.json()
                    if res.get("status") == 1 or res.get("records"):
                        return {"ok": res.get("records", [])}
                elif rr.status_code == 429:
                    return {"error": "IntelX: limite de requisições"}
            return {"ok": []}
        except APIError as e:
            return {"error": f"IntelX darknet: {e}"}

    def dehashed(self, query, size=50):
        if not (self.cfg.key("dehashed_email") and self.cfg.key("dehashed_key")):
            return {"error": "sem credenciais DeHashed"}
        try:
            r = self._get(
                "https://api.dehashed.com/search",
                params={"query": query, "size": size},
                auth=(self.cfg.key("dehashed_email"), self.cfg.key("dehashed_key")),
            )
            if r.status_code == 200:
                d = sanitize_data(r.json())
                return {"ok": d.get("entries", []), "total": d.get("total", 0)}
            return {"error": f"DeHashed HTTP {r.status_code}"}
        except APIError as e:
            return {"error": f"DeHashed: {e}"}

    def hibp_pastes(self, email):
        if not self.cfg.has_key("hibp"):
            return {"error": "sem chave HIBP"}
        try:
            r = self._get(
                f"https://haveibeenpwned.com/api/v3/pasteaccount/{quote(email)}",
                headers={"hibp-api-key": self.cfg.key("hibp")},
            )
            if r.status_code == 200:
                return {"ok": r.json()}
            if r.status_code == 404:
                return {"ok": []}
            return {"error": f"HIBP pastes HTTP {r.status_code}"}
        except APIError as e:
            return {"error": f"HIBP pastes: {e}"}

    def ahmia(self, query, maxresults=15):
        try:
            r = self._get(f"https://ahmia.fi/search/?q={quote(query)}")
            if r.status_code != 200:
                return {"error": f"Ahmia HTTP {r.status_code}"}
            html = r.text
            items = re.findall(
                r'<li>\s*<a href="(http://[^"]+\.onion[^"]*)">([^<]+)</a>.*?</li>',
                html, re.S | re.I,
            )
            results = []
            for url, title in items[:maxresults]:
                snippet = ""
                m = re.search(r'<a href="' + re.escape(url) + r'".*?</a>\s*<p[^>]*>(.*?)</p>', html, re.S)
                if m:
                    snippet = re.sub(r"<[^>]+>", "", m.group(1)).strip()[:200]
                results.append({"onion": url, "title": title.strip(), "snippet": snippet})
            return {"ok": results, "source": "Ahmia (índice .onion)"}
        except APIError as e:
            return {"error": f"Ahmia: {e}"}
        except Exception:
            return {"error": "Ahmia indisponível"}

    def scan(self, queries, opts=None, skip_sources=None):
        opts = opts or {}
        skip_sources = {str(item).casefold() for item in (skip_sources or ())}
        results = []
        for q in queries:
            if "intelx" not in skip_sources:
                maxresults = opts.get("intelx_results", 15)
                r = self._cached("intelx", q, {"maxresults": maxresults}, lambda: self.intelx_darknet(q, maxresults=maxresults))
                if "error" in r:
                    results.append({"query": q, "source": "IntelX darknet", "error": r["error"]})
                else:
                    for rec in r.get("ok", []):
                        results.append({
                            "query": q, "source": "IntelX darknet", "tipo": rec.get("name", "?"),
                            "data": rec.get("date", "?"), "bucket": rec.get("bucket", "?"),
                            "id": rec.get("id", ""),
                        })
            domain_query = f"domain:{q.split('@')[-1]}"
            size = opts.get("dehashed_results", 50)
            d = None
            if "@" in q and "dehashed" not in skip_sources:
                d = self._cached("dehashed", domain_query, {"size": size}, lambda: self.dehashed(domain_query, size=size))
            if d and "error" in d:
                results.append({"query": q, "source": "DeHashed", "error": d["error"]})
            elif d:
                for e in d.get("ok", []):
                    results.append({
                        "query": q, "source": "DeHashed", "email": e.get("email", "?"),
                        "banco": e.get("database_name", "?"),
                    })
            a = self.ahmia(q, maxresults=opts.get("ahmia_results", 10))
            if "error" in a:
                results.append({"query": q, "source": "Ahmia", "error": a["error"]})
            else:
                for it in a.get("ok", []):
                    results.append({
                        "query": q, "source": "Ahmia (.onion)", "titulo": it["title"],
                        "onion": it["onion"], "trecho": it.get("snippet", ""),
                    })
        return results
