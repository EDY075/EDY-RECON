import hashlib
import os
import sys

from modules import EDY_RECON_VERSION
from modules import config as cfgmod
from modules.safety import request_with_retry, safe_error


class PasswordManager:
    def __init__(self):
        self.in_memory = set()
        self.streams = []
        self.meta = {
            "sources": [],
            "in_memory_count": 0,
            "memory_bytes": 0,
            "stream_count": 0,
            "stream_lines": 0,
        }
        self._builtin_loaded = False

    def load(self, extra_lists=None):
        self.in_memory = set()
        self.streams = []
        self.meta = {"sources": [], "in_memory_count": 0, "memory_bytes": 0, "stream_count": 0, "stream_lines": 0}
        builtin = os.path.join(cfgmod.DATA_DIR, "passwords_base.lst")
        self._load_file_full(builtin, "base embutida")
        self._builtin_loaded = True
        for path in (extra_lists or []):
            path = os.path.expanduser(path)
            if not os.path.isfile(path):
                self.meta["sources"].append(f"(não encontrada) {path}")
                continue
            size = os.path.getsize(path)
            # Listas acima de 512KB vão para STREAMING (não ocupam RAM),
            # mantendo apenas a base embutida pequena em memória.
            if size <= 512 * 1024:
                self._load_file_full(path, path)
            else:
                self._load_file_stream(path, path)
        return self

    def _load_file_full(self, path, label):
        count = 0
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    pw = line.strip()
                    if pw:
                        self.in_memory.add(pw)
                        count += 1
        except Exception as e:
            self.meta["sources"].append(f"(erro ao ler) {label}: {safe_error(e)}")
            return
        self.meta["sources"].append(f"{label} (completa em RAM)")
        self.meta["in_memory_count"] = len(self.in_memory)
        self.meta["memory_bytes"] = sum(len(p) for p in self.in_memory) * 2

    def _load_file_stream(self, path, label):
        count = 0
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for _ in f:
                    count += 1
        except Exception as e:
            self.meta["sources"].append(f"(erro ao ler) {label}: {safe_error(e)}")
            return
        self.streams.append(path)
        self.meta["stream_count"] += 1
        self.meta["stream_lines"] += count
        self.meta["sources"].append(f"{label} (streaming, {count:,} linhas)")

    def contains(self, pw):
        return pw in self.in_memory

    def iter_memory(self):
        for pw in sorted(self.in_memory):
            yield pw

    def iter_streams(self):
        for path in self.streams:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        pw = line.strip()
                        if pw:
                            yield pw
            except Exception:
                continue

    def iter_all(self, limit=None):
        n = 0
        for pw in self.iter_memory():
            yield pw
            n += 1
            if limit and n >= limit:
                return
        for pw in self.iter_streams():
            yield pw
            n += 1
            if limit and n >= limit:
                return

    def candidates_for_user(self, username):
        if not username:
            return []
        base = username.lower().strip()
        cands = [base, base.capitalize(), base.upper()]
        digits = ["123", "1234", "12345", "1", "12"]
        years = [str(y) for y in range(2026, 2016, -1)]
        for c in list(cands):
            for d in digits:
                cands.append(c + d)
            for y in years:
                cands.append(c + y)
            cands.append(c + "@")
            cands.append(c + "!")
            cands.append(c + "#")
        cands.append("senha")
        cands.append("senha123")
        cands.append("password")
        cands.append("password123")
        cands.append("admin")
        cands.append("admin123")
        return list(dict.fromkeys(c for c in cands if c))

    def stats(self):
        m = self.meta
        mb = m["memory_bytes"] / (1024 * 1024)
        return {
            "in_memory": m["in_memory_count"],
            "memory_mb": round(mb, 2),
            "streams": m["stream_count"],
            "stream_lines": m["stream_lines"],
            "sources": m["sources"],
        }

    def check_pwned_hibp(self, password):
        sha1 = hashlib.sha1(password.encode("utf-8", errors="ignore")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        try:
            import requests
            r = request_with_retry(
                requests.get,
                f"https://api.pwnedpasswords.com/range/{prefix}",
                max_attempts=2,
                headers={"user-agent": f"EDYRECON-{EDY_RECON_VERSION}"},
                timeout=15,
            )
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}", "hash": sha1}
            for line in r.text.splitlines():
                part, count = line.split(":", 1)
                if part.strip().upper() == suffix:
                    return {"found": True, "count": int(count.strip()), "hash": sha1}
            return {"found": False, "count": 0, "hash": sha1}
        except Exception as e:
            return {"error": safe_error(e, 120), "hash": sha1}
