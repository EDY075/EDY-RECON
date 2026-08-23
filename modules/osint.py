import re
import socket
import time
from urllib.parse import quote

import requests

from modules import EDY_RECON_VERSION
from modules.safety import request_with_retry, safe_error, sanitize_data


class UserTarget:
    def __init__(self, name="", emails=None, usernames=None, domains=None):
        self.name = name or ""
        self.emails = [e.strip().lower() for e in (emails or []) if e and "@" in e]
        self.usernames = [u.strip() for u in (usernames or []) if u]
        self.domains = [d.strip().lower().lstrip(".") for d in (domains or []) if d]

    def add_email(self, email):
        email = email.strip().lower()
        if email and "@" in email and email not in self.emails:
            self.emails.append(email)

    def all_domains(self):
        ds = list(self.domains)
        for e in self.emails:
            d = e.split("@", 1)[1]
            if d not in ds:
                ds.append(d)
        return ds


class APIError(Exception):
    pass


class OSINTScanner:
    UA = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) EDYRECON/{EDY_RECON_VERSION}"

    def __init__(self, cfg):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.UA})

    def _get(self, url, **kw):
        kw.setdefault("timeout", 15)
        try:
            return request_with_retry(self.session.get, url, max_attempts=2, **kw)
        except requests.exceptions.RequestException as e:
            raise APIError(safe_error(e))

    # ---------- FONTES POR EMAIL ----------

    def emailrep(self, email):
        if not email:
            return None
        url = f"https://emailrep.io/{quote(email)}"
        headers = {}
        k = self.cfg.key("emailrep")
        if k:
            headers["Key"] = k
        try:
            r = self._get(url, headers=headers)
            if r.status_code == 200:
                d = r.json()
                return {
                    "reputation": d.get("reputation", "?"),
                    "suspicious": d.get("suspicious", False),
                    "references": d.get("references", 0),
                    "details": d.get("details", {}),
                    "source": "EmailRep.io",
                }
            if r.status_code in (401, 403):
                return {"error": "chave EmailRep inválida ou limite atingido"}
            if r.status_code == 429:
                return {"error": "limite de requisições EmailRep"}
            return {"error": f"EmailRep HTTP {r.status_code}"}
        except APIError as e:
            return {"error": f"EmailRep: {e}"}

    def hibp_breaches(self, email):
        if not self.cfg.has_key("hibp"):
            return {"error": "sem chave HIBP (Have I Been Pwned)"}
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}?truncateResponse=false"
        headers = {"hibp-api-key": self.cfg.key("hibp")}
        try:
            r = self._get(url, headers=headers)
            if r.status_code == 200:
                return {"ok": r.json()}
            if r.status_code == 404:
                return {"ok": []}
            if r.status_code in (401, 403):
                return {"error": "chave HIBP inválida"}
            return {"error": f"HIBP HTTP {r.status_code}"}
        except APIError as e:
            return {"error": f"HIBP: {e}"}

    def hibp_pastes(self, email):
        if not self.cfg.has_key("hibp"):
            return {"error": "sem chave HIBP"}
        url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{quote(email)}"
        headers = {"hibp-api-key": self.cfg.key("hibp")}
        try:
            r = self._get(url, headers=headers)
            if r.status_code == 200:
                return {"ok": r.json()}
            if r.status_code == 404:
                return {"ok": []}
            return {"error": f"HIBP pastes HTTP {r.status_code}"}
        except APIError as e:
            return {"error": f"HIBP pastes: {e}"}

    def intelx_search(self, query, maxresults=20, terminate=45):
        if not self.cfg.has_key("intelx"):
            return {"error": "sem chave IntelligenceX (intelx.io)"}
        try:
            r = self._get(
                "https://2.intelx.io/intelligent/search",
                params={"q": query, "maxresults": maxresults, "media": 0, "sort": 2,
                        "datefrom": -1, "dateto": -1, "terminateafter": terminate},
                headers={"x-key": self.cfg.key("intelx")},
            )
            if r.status_code != 200:
                return {"error": f"IntelX search HTTP {r.status_code}"}
            data = r.json()
            sid = data.get("id")
            if not sid:
                return {"ok": []}
            for _ in range(terminate // 5 + 1):
                time.sleep(2)
                rr = self._get(
                    f"https://2.intelx.io/intelligent/search/result?id={sid}&limit=10",
                    headers={"x-key": self.cfg.key("intelx"), "x-intelx-api-key": self.cfg.key("intelx")},
                )
                if rr.status_code == 200:
                    res = rr.json()
                    if res.get("status") == 1 or res.get("records") or res.get("status") == 0:
                        return {"ok": res.get("records", []), "total": res.get("total", len(res.get("records", [])))}
                elif rr.status_code == 429:
                    return {"error": "IntelX: limite de requisições"}
                elif rr.status_code in (401, 403):
                    return {"error": "IntelX: chave inválida"}
            return {"ok": []}
        except APIError as e:
            return {"error": f"IntelX: {e}"}

    def dehashed(self, query, size=50):
        if not (self.cfg.key("dehashed_email") and self.cfg.key("dehashed_key")):
            return {"error": "sem credenciais DeHashed (email+chave)"}
        try:
            r = self._get(
                "https://api.dehashed.com/search",
                params={"query": query, "size": size},
                auth=(self.cfg.key("dehashed_email"), self.cfg.key("dehashed_key")),
            )
            if r.status_code == 200:
                d = sanitize_data(r.json())
                return {"ok": d.get("entries", []), "total": d.get("total", 0)}
            if r.status_code == 401:
                return {"error": "DeHashed: credenciais inválidas"}
            return {"error": f"DeHashed HTTP {r.status_code}"}
        except APIError as e:
            return {"error": f"DeHashed: {e}"}

    def hunter_verify(self, email):
        if not self.cfg.has_key("hunter"):
            return None
        try:
            r = self._get(
                "https://api.hunter.io/v2/email-verifier",
                params={"email": email, "api_key": self.cfg.key("hunter")},
            )
            if r.status_code == 200:
                d = r.json().get("data", {})
                return {"status": d.get("status"), "score": d.get("score"),
                        "disposable": d.get("disposable"), "source": "Hunter.io"}
            return {"error": f"Hunter HTTP {r.status_code}"}
        except APIError as e:
            return {"error": f"Hunter: {e}"}

    # ---------- DOMÍNIO ----------

    def crtsh_subdomains(self, domain, limit=200):
        try:
            r = self._get(f"https://crt.sh/?q=%25.{quote(domain)}&output=json")
            if r.status_code != 200:
                return {"error": f"crt.sh HTTP {r.status_code}"}
            subs = set()
            for row in r.json():
                names = row.get("name_value", "")
                for n in names.splitlines():
                    n = n.strip().lower()
                    if n.endswith(domain):
                        subs.add(n)
            return {"ok": sorted(subs)[:limit]}
        except Exception:
            return {"error": "crt.sh indisponível"}

    def rdap(self, domain):
        try:
            r = self._get(f"https://rdap.org/domain/{quote(domain)}")
            if r.status_code == 404:
                return {"ok": None}
            if r.status_code != 200:
                return {"error": f"RDAP HTTP {r.status_code}"}
            d = r.json()
            events = {e.get("eventAction", "?"): e.get("eventDate", "?") for e in d.get("events", [])}
            return {
                "ok": {
                    "registrar": (d.get("entities") or [{}])[0].get("vcardArray", [[], []])[1] and
                    next((v for e in (d.get("entities") or []) for x in e.get("vcardArray", [[], []])[1] if x[0] == "fn" for v in x[3:]), "?"),
                    "criado": events.get("registration", "?"),
                    "atualizado": events.get("last changed", "?"),
                    "expira": events.get("expiration", "?"),
                    "status": d.get("status", []),
                }
            }
        except Exception:
            return {"error": "RDAP indisponível"}

    def dns_basic(self, domain):
        out = {"a": None, "mx": None, "ns": None}
        try:
            out["a"] = socket.gethostbyname(domain)
        except Exception:
            out["a"] = None
        try:
            import dns.resolver
            out["mx"] = [str(x.exchange) for x in dns.resolver.resolve(domain, "MX")]
            out["ns"] = [str(x) for x in dns.resolver.resolve(domain, "NS")]
        except Exception:
            try:
                r = self._get(f"https://dns.google/resolve?name={quote(domain)}&type=MX")
                if r.status_code == 200:
                    mx = []
                    for answer in r.json().get("Answer", []):
                        if answer.get("type") != 15:
                            continue
                        data = str(answer.get("data") or "").strip()
                        parts = data.split(maxsplit=1)
                        host = parts[1] if len(parts) == 2 and parts[0].isdigit() else data
                        if host:
                            mx.append(host)
                    out["mx"] = mx
            except Exception:
                out["mx"] = []
        if out["mx"] is None:
            out["mx"] = []
        if out["ns"] is None:
            out["ns"] = []
        return out

    def virustotal_domain(self, domain):
        if not self.cfg.has_key("virustotal"):
            return None
        try:
            r = self._get(
                f"https://www.virustotal.com/api/v3/domains/{quote(domain)}",
                headers={"x-apikey": self.cfg.key("virustotal")},
            )
            if r.status_code == 200:
                a = r.json().get("data", {}).get("attributes", {})
                return {"malicioso": a.get("last_analysis_stats", {}).get("malicious", 0),
                        "suspeito": a.get("last_analysis_stats", {}).get("suspicious", 0),
                        "reputacao": a.get("reputation"), "source": "VirusTotal"}
            return {"error": f"VirusTotal HTTP {r.status_code}"}
        except APIError as e:
            return {"error": f"VirusTotal: {e}"}

    def ipinfo(self, ip):
        """Geolocalização de IP (ipinfo.io) — funciona sem chave; token opcional."""
        if not ip:
            return None
        try:
            url = f"https://ipinfo.io/{quote(ip)}/json"
            params = {}
            k = self.cfg.key("ipinfo")
            if k:
                params["token"] = k
            r = self._get(url, params=params)
            if r.status_code == 200:
                d = r.json()
                return {
                    "ip": d.get("ip"),
                    "cidade": d.get("city", "?"),
                    "regiao": d.get("region", "?"),
                    "pais": d.get("country", "?"),
                    "org": d.get("org", "?"),
                    "asn": (d.get("org", "") or "").split()[0] if d.get("org") else "?",
                    "hostname": d.get("hostname", ""),
                    "source": "ipinfo.io",
                }
            return {"error": f"ipinfo HTTP {r.status_code}"}
        except APIError as e:
            return {"error": f"ipinfo: {e}"}

    def shodan_host(self, host):
        """Enumeração de portas/serviços do host (Shodan) — exige chave free."""
        if not self.cfg.has_key("shodan"):
            return None
        try:
            r = self._get(
                f"https://api.shodan.io/shodan/host/{quote(host)}",
                params={"key": self.cfg.key("shodan")},
            )
            if r.status_code == 200:
                d = r.json()
                portas = {}
                for svc in d.get("data", []):
                    p = svc.get("port")
                    portas.setdefault(p, {"produto": svc.get("product", "?"), "servico": svc.get("transport", "?")})
                return {
                    "ip": d.get("ip_str"),
                    "portas": sorted(portas.keys()),
                    "servicos": portas,
                    "os": d.get("os", "?"),
                    "hostnames": d.get("hostnames", []),
                    "vulns": d.get("vulns", []),
                    "source": "Shodan",
                }
            if r.status_code == 403:
                return {"error": "Shodan: chave inválida"}
            if r.status_code == 404:
                return {"error": "Shodan: host sem dados públicos"}
            return {"error": f"Shodan HTTP {r.status_code}"}
        except APIError as e:
            return {"error": f"Shodan: {e}"}

    def urlscan_search(self, domain):
        """Scans/avaliações públicas do domínio (urlscan.io) — exige chave free."""
        if not self.cfg.has_key("urlscan"):
            return None
        try:
            headers = {"API-Key": self.cfg.key("urlscan")}
            r = self._get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"domain:{domain}", "size": 5},
                headers=headers,
            )
            if r.status_code == 200:
                items = []
                for res in r.json().get("results", []):
                    task = res.get("task", {})
                    page = res.get("page", {})
                    vt = res.get("verdicts", {}).get("overall", {})
                    items.append({
                        "url": task.get("url", "?"),
                        "tempo": task.get("time", "?"),
                        "ip": page.get("ip", "?"),
                        "pais": page.get("country", "?"),
                        "malicioso": vt.get("malicious", False),
                        "score": vt.get("score", 0),
                    })
                return {"total": r.json().get("total", len(items)), "items": items, "source": "urlscan.io"}
            if r.status_code in (401, 403):
                return {"error": "urlscan: chave inválida"}
            return {"error": f"urlscan HTTP {r.status_code}"}
        except APIError as e:
            return {"error": f"urlscan: {e}"}

    def otx_domain(self, domain):
        """Indicadores/pulses de ameaça (AlienVault OTX) — exige chave free."""
        if not self.cfg.has_key("otx"):
            return None
        try:
            r = self._get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(domain)}/pulses",
                params={"limit": 10, "page": 1},
                headers={"X-OTX-API-KEY": self.cfg.key("otx")},
            )
            if r.status_code == 200:
                d = r.json()
                pulses = []
                for p in d.get("results", []):
                    pulses.append({
                        "nome": p.get("name", "?"),
                        "descricao": (p.get("description", "") or "")[:150],
                        "tags": [t.get("name") for t in p.get("tags", [])][:5],
                        "criado": p.get("created", "?"),
                    })
                return {"pulses": pulses, "total": d.get("count", len(pulses)), "source": "AlienVault OTX"}
            if r.status_code in (401, 403):
                return {"error": "OTX: chave inválida"}
            return {"error": f"OTX HTTP {r.status_code}"}
        except APIError as e:
            return {"error": f"OTX: {e}"}

    def wayback_urls(self, domain, limit=100):
        """URLs arquivadas do domínio (Wayback Machine CDX) — sem chave."""
        try:
            r = self._get(
                "https://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"{domain}/*",
                    "output": "json",
                    "fl": "original,timestamp,statuscode",
                    "collapse": "urlkey",
                    "limit": limit,
                },
                timeout=30,
            )
            if r.status_code != 200:
                return {"error": f"Wayback CDX HTTP {r.status_code}"}
            rows = r.json()
            if not rows or len(rows) < 2:
                return {"urls": [], "total": 0, "source": "Wayback Machine CDX"}
            urls = []
            for row in rows[1:]:
                if len(row) >= 3:
                    urls.append({"url": row[0], "timestamp": row[1], "status": row[2]})
            return {"urls": urls, "total": len(urls), "source": "Wayback Machine CDX"}
        except Exception as e:
            return {"error": f"Wayback: {e}"}

    def hackertarget_hostsearch(self, domain):
        """Subdomínios via HackerTarget hostsearch — sem chave (rate limit diário)."""
        try:
            r = self._get("https://api.hackertarget.com/hostsearch/", params={"q": domain})
            if r.status_code != 200:
                return {"error": f"HackerTarget HTTP {r.status_code}"}
            hosts = []
            for ln in r.text.strip().splitlines():
                if "," in ln:
                    host, ip = ln.split(",", 1)
                    hosts.append({"host": host.strip(), "ip": ip.strip()})
            return {"hosts": hosts, "total": len(hosts), "source": "HackerTarget"}
        except Exception as e:
            return {"error": f"HackerTarget: {e}"}

    # ---------- VARIANTES ----------

    def generate_variants(self, email):
        if "@" not in email:
            return []
        name, domain = email.split("@", 1)
        name = name.lower()
        base = name.replace(".", "").replace("-", "").replace("_", "")
        parts = [p for p in re.split(r"[._\-]+", name) if p]
        combos = [base]
        if len(parts) >= 2:
            first, last = parts[0], parts[-1]
            combos += [f"{first}.{last}", f"{first}_{last}", f"{first}-{last}",
                       first + last, f"{first[:1]}.{last}", f"{first[:1]}{last}",
                       f"{first}.{last[:1]}", first + last[:1], f"{last}.{first}",
                       last + first, f"{last}{first[:1]}", f"{first[:1]}.{last[:1]}",
                       f"{first}.{last}{base}"]
        if len(parts) >= 3:
            mid = "".join(p[0] for p in parts[1:-1])
            combos += [f"{parts[0]}.{mid}.{parts[-1]}", f"{parts[0]}{mid}{parts[-1]}"]
        variants = []
        for c in sorted(set(combos)):
            if c:
                variants.append(f"{c}@{domain}")
        alt_domains = ["gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "proton.me",
                       "icloud.com", "live.com", "aol.com", "uol.com.br", "bol.com.br",
                       "terra.com.br", "ig.com.br"]
        for d in alt_domains:
            if d != domain:
                variants.append(f"{name}@{d}")
        for c in sorted(set(combos)):
            if not c:
                continue
            for suf in ["1", "123", "2020", "2021", "2022", "2023", "2024", "2025", "2026", "_1", "00", "01", "1234"]:
                variants.append(f"{c}{suf}@{domain}")
        if domain in ("gmail.com", "googlemail.com"):
            for tag in ["jobs", "news", "bank", "social", "games", "work", "personal", "compras", "trabalho"]:
                variants.append(f"{name}+{tag}@{domain}")
        return sorted(set(variants))

    # ---------- ORQUESTRAÇÃO ----------

    def scan_email(self, email, opts=None):
        opts = opts or {}
        result = {"email": email, "fonte": {}, "erros": []}
        r = self.emailrep(email)
        if r:
            if "error" in r:
                result["erros"].append(r["error"])
            else:
                result["fonte"]["emailrep"] = r
        h = self.hibp_breaches(email)
        if "error" in h:
            result["erros"].append(h["error"])
        else:
            result["fonte"]["hibp"] = h["ok"]
        hp = self.hibp_pastes(email)
        if "error" in hp:
            pass
        else:
            result["fonte"]["hibp_pastes"] = hp["ok"]
        i = self.intelx_search(email, maxresults=opts.get("intelx_results", 20))
        if "error" in i:
            result["erros"].append(i["error"])
        else:
            result["fonte"]["intelx"] = i["ok"]
        d = self.dehashed(f"email:{email}", size=opts.get("dehashed_results", 50))
        if "error" in d:
            result["erros"].append(d["error"])
        else:
            result["fonte"]["dehashed"] = d["ok"]
        hv = self.hunter_verify(email)
        if hv and "error" not in hv:
            result["fonte"]["hunter"] = hv
        return result

    def scan_domain(self, domain, opts=None):
        opts = opts or {}
        out = {"domain": domain, "erros": []}
        out["dns"] = self.dns_basic(domain)
        out["rdap"] = self.rdap(domain)
        out["crtsh"] = self.crtsh_subdomains(domain, limit=opts.get("crtsh_limit", 200))
        vt = self.virustotal_domain(domain)
        if vt and "error" not in vt:
            out["virustotal"] = vt
        ip = out["dns"].get("a")
        if ip:
            geo = self.ipinfo(ip)
            if geo and "error" not in geo:
                out["ipinfo"] = geo
            elif geo:
                out["erros"].append(geo["error"])
        sh = self.shodan_host(ip or domain)
        if sh and "error" not in sh:
            out["shodan"] = sh
        elif sh:
            out["erros"].append(sh["error"])
        us = self.urlscan_search(domain)
        if us and "error" not in us:
            out["urlscan"] = us
        elif us:
            out["erros"].append(us["error"])
        otx = self.otx_domain(domain)
        if otx and "error" not in otx:
            out["otx"] = otx
        elif otx:
            out["erros"].append(otx["error"])
        wb = self.wayback_urls(domain, limit=opts.get("wayback_limit", 100))
        if "error" not in wb:
            out["wayback"] = wb
        else:
            out["erros"].append(wb["error"])
        ht = self.hackertarget_hostsearch(domain)
        if "error" not in ht:
            out["hackertarget"] = ht
        else:
            out["erros"].append(ht["error"])
        return out
