import json
import os
from copy import deepcopy

from modules.safety import atomic_write_json, is_configured_secret

MODULE_DIR = os.path.dirname(os.path.realpath(__file__))
BASE_DIR = os.path.dirname(MODULE_DIR)
DATA_DIR = os.path.join(BASE_DIR, "data")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
SESSIONS_DIR = os.path.join(BASE_DIR, "sessions")

DEFAULT_CONFIG = {
    "theme": "NEO",
    "user_name": "Analista",
    "api_keys": {
        "hibp": "",
        "intelx": "",
        "dehashed_email": "",
        "dehashed_key": "",
        "hunter": "",
        "virustotal": "",
        "emailrep": "",
        "shodan": "",
        "urlscan": "",
        "otx": "",
        "ipinfo": "",
    },
    "ai": {
        "provider": "skynet",
        "base_url": "",
        "api_key": "",
        "model": "",
        "email": "",
        "password": "",
        "session_id": "",
        "provider_keys": {},
    },
    "wordlists": [],
    "bruteforce": {"threads": 8, "delay": 0.4, "timeout": 10, "max_passwords": 1000000},
    "scan": {
        "variants_to_check": 12,
        "intelx_results": 20,
        "dehashed_results": 50,
        "crtsh_limit": 200,
    },
    "last_emails": [],
}

CONFIG_PATH = os.path.join(DATA_DIR, "config.json")


def ensure_dirs():
    for d in (DATA_DIR, REPORTS_DIR, SESSIONS_DIR):
        os.makedirs(d, exist_ok=True)


class ConfigManager:
    def __init__(self):
        ensure_dirs()
        self.cfg = deepcopy(DEFAULT_CONFIG)
        self.last_error = None

    def load(self):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            for k, v in DEFAULT_CONFIG.items():
                if isinstance(v, dict):
                    self.cfg[k] = {**v, **(loaded.get(k, {}) or {})}
                else:
                    self.cfg[k] = loaded.get(k, v)
        except FileNotFoundError:
            self.last_error = None
        except (OSError, ValueError, TypeError) as e:
            self.last_error = f"configuração inválida: {type(e).__name__}"
        return self

    def save(self):
        try:
            atomic_write_json(CONFIG_PATH, self.cfg)
            self.last_error = None
            return True
        except (OSError, TypeError, ValueError) as e:
            self.last_error = f"não foi possível salvar: {type(e).__name__}"
            return False

    def theme(self):
        return self.cfg.get("theme", "NEO")

    def set_theme(self, name):
        self.cfg["theme"] = name
        self.save()

    def key(self, name):
        return (self.cfg.get("api_keys") or {}).get(name, "").strip()

    def has_key(self, name):
        return is_configured_secret(self.key(name))

    def ai(self):
        return self.cfg.get("ai", {})
