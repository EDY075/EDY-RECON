from __future__ import annotations

import copy
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import offline_guard


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class FakeConfig:
    def __init__(self, ai_key="SYNTHETIC_PLACEHOLDER", variants=2):
        self.cfg = {
            "api_keys": {},
            "scan": {"variants_to_check": variants},
            "bruteforce": {"threads": 2, "delay": 0, "timeout": 1},
            "ai": {
                "provider": "skynet",
                "base_url": "https://synthetic.invalid/v1",
                "api_key": ai_key,
                "model": "synthetic-model",
                "email": "user@example.com",
                "password": "synthetic-password",
                "session_id": "",
            },
        }

    def ai(self):
        return self.cfg["ai"]

    def save(self):
        return True

    def theme(self):
        return "NEO"

    def has_key(self, _name):
        return False

    def key(self, _name):
        return ""


class FakeResponse:
    def __init__(self, status_code=200, payload=None, headers=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = headers or {}
        self.text = "synthetic response"

    def json(self):
        return self._payload


class ContainmentTests(unittest.TestCase):
    def test_domains_and_dominios_are_compatible(self):
        from modules.bruteforce import BruteForce

        bf = BruteForce(FakeConfig(), None)
        bf.probe_ports = lambda *_args, **_kwargs: [22]
        sessions = [
            {"targets": [{"dominios": [{"domain": "example.com"}]}]},
            {"targets": [{"domains": ["example.com"]}]},
        ]
        with patch("modules.bruteforce.socket.gethostbyname", return_value="192.0.2.10"):
            derived = [bf.derive_targets(session) for session in sessions]
        self.assertEqual(derived[0], derived[1])
        self.assertEqual(derived[0][0]["domain"], "example.com")

    def test_dns_fallback_parses_data_and_never_none(self):
        from modules.osint import OSINTScanner

        scanner = OSINTScanner(FakeConfig())
        scanner._get = lambda *_args, **_kwargs: FakeResponse(
            payload={"Answer": [{"type": 15, "data": "10 mail.example.com."}]}
        )
        resolver = types.ModuleType("dns.resolver")
        resolver.resolve = lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("offline"))
        dns = types.ModuleType("dns")
        dns.resolver = resolver
        with patch.dict(sys.modules, {"dns": dns, "dns.resolver": resolver}), patch(
            "modules.osint.socket.gethostbyname", side_effect=OSError("offline")
        ):
            result = scanner.dns_basic("example.com")
        self.assertEqual(result["mx"], ["mail.example.com."])
        self.assertNotIn(None, result["mx"])

    def test_requirements_declares_dnspython(self):
        requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8").lower()
        self.assertIn("dnspython", requirements)

    def test_placeholder_is_not_a_configured_key(self):
        from modules.config import ConfigManager

        cfg = object.__new__(ConfigManager)
        for value in ("SYNTHETIC_PLACEHOLDER", "change_me", "your_api_key", "sua_chave_aqui"):
            cfg.cfg = {"api_keys": {"hunter": value}}
            self.assertFalse(cfg.has_key("hunter"), value)

    def test_provider_switch_does_not_inherit_previous_key(self):
        from modules.ai import AIClient

        cfg = FakeConfig(ai_key="SYNTHETIC_PLACEHOLDER")
        client = AIClient(cfg)
        client.set_provider("openrouter")
        self.assertNotEqual(cfg.ai()["api_key"], "SYNTHETIC_PLACEHOLDER")

    def test_provider_reselect_preserves_key_and_custom_does_not_inherit(self):
        from modules.ai import AIClient

        cfg = FakeConfig(ai_key="synthetic-current-key")
        cfg.ai()["provider"] = "openrouter"
        client = AIClient(cfg)
        client.set_provider("openrouter")
        self.assertEqual(cfg.ai()["api_key"], "synthetic-current-key")
        client.set_provider("custom")
        self.assertNotEqual(cfg.ai()["api_key"], "synthetic-current-key")

    def test_scan_uses_variants_limit_and_skips_duplicate_providers(self):
        import edyrecon

        class FakeOSINT:
            def __init__(self, _cfg):
                pass

            def scan_email(self, email, _opts):
                return {"fonte": {"intelx": [], "dehashed": [], "hibp_pastes": []}, "erros": []}

            def generate_variants(self, _email):
                return [f"variant{i}@example.com" for i in range(5)]

            def scan_domain(self, domain, _opts):
                return {"domain": domain, "dns": {}, "rdap": {}, "crtsh": {"ok": []}}

        class FakeDark:
            skip_sources = None

            def __init__(self, _cfg):
                pass

            def scan(self, _queries, _opts=None, skip_sources=None):
                type(self).skip_sources = set(skip_sources or ())
                return []

        edyrecon.CFG = FakeConfig(variants=2)
        edyrecon.DB = types.SimpleNamespace(records=[])
        with patch.object(edyrecon, "OSINTScanner", FakeOSINT), patch.object(
            edyrecon, "DarkWebScanner", FakeDark
        ), patch.object(edyrecon.ui, "status_bar"), patch.object(edyrecon.ui, "clear_line"):
            target = edyrecon.scan_target("Synthetic", ["user@example.com"], {"variants_to_check": 2})
        self.assertEqual(len(target["variantes"]), 2)
        self.assertTrue({"intelx", "hibp_pastes"}.issubset(FakeDark.skip_sources))
        self.assertNotIn("dehashed", FakeDark.skip_sources)  # consulta de domínio é distinta e fica cacheada

    def test_secret_prompt_and_mask_never_echo_value(self):
        from modules import ui

        secret = "synthetic-secret-value"
        output = io.StringIO()
        with patch("getpass.getpass", return_value=secret), redirect_stdout(output):
            value = ui.ask_secret("NEO", "Chave> ")
        self.assertEqual(value, secret)
        self.assertNotIn(secret, output.getvalue())
        self.assertNotEqual(ui.mask_secret(secret), secret)
        self.assertNotIn(secret, ui.mask_secret(secret))

    def test_provider_password_fields_are_discarded(self):
        import edyrecon
        from modules.darkweb import DarkWebScanner

        secret = "synthetic-provider-password"
        source = {"email": "user@example.com", "password": secret, "database_name": "fixture"}
        converted = edyrecon.dehashed_to_dark([copy.deepcopy(source)])
        self.assertNotIn(secret, json.dumps(converted, ensure_ascii=False))

        scanner = DarkWebScanner(FakeConfig())
        scanner.intelx_darknet = lambda *_args, **_kwargs: {"ok": []}
        scanner.dehashed = lambda *_args, **_kwargs: {"ok": [copy.deepcopy(source)]}
        scanner.ahmia = lambda *_args, **_kwargs: {"ok": []}
        result = scanner.scan(["user@example.com"])
        self.assertNotIn(secret, json.dumps(result, ensure_ascii=False))
        self.assertNotIn("senha_hash", json.dumps(result, ensure_ascii=False).lower())

    def test_recursive_sanitizer_and_safe_error(self):
        from modules.safety import safe_error, sanitize_data

        secret = "synthetic-provider-password"
        original = {"nested": [{"Password": secret, "ok": "keep"}]}
        cleaned = sanitize_data(original)
        self.assertEqual(original["nested"][0]["Password"], secret)
        self.assertNotIn(secret, json.dumps(cleaned, ensure_ascii=False))
        raw = "GET https://user:pass@example.com/path?api_key=secret#frag for user@example.com Bearer tokenvalue"
        error = safe_error(raw)
        for leaked in ("user:pass", "api_key", "secret", "user@example.com", "tokenvalue", "#frag"):
            self.assertNotIn(leaked, error)

    def test_config_session_and_reports_use_atomic_replace_and_sanitize(self):
        import edyrecon
        from modules import config as cfgmod
        from modules.config import ConfigManager
        from modules.report import generate_html, generate_txt

        secret = "synthetic-provider-password"
        session = {"targets": [{"emails": [{
            "email": "user@example.com",
            "Password": secret,
            "erros": [f"https://example.com/?api_key={secret}"],
        }]}]}
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            config_path = root / "config.json"
            with patch.object(cfgmod, "CONFIG_PATH", str(config_path)), patch(
                "modules.safety.os.replace", wraps=os.replace
            ) as replace:
                manager = ConfigManager()
                self.assertTrue(manager.save())
                self.assertTrue(replace.called)

            sessions = root / "sessions"
            with patch.object(cfgmod, "SESSIONS_DIR", str(sessions)), patch(
                "modules.safety.os.replace", wraps=os.replace
            ) as replace:
                saved = pathlib.Path(edyrecon.save_session(copy.deepcopy(session)))
                self.assertTrue(replace.called)
                self.assertNotIn(secret, saved.read_text(encoding="utf-8"))

            for writer, suffix in ((generate_html, ".html"), (generate_txt, ".txt")):
                destination = root / f"report{suffix}"
                with patch("modules.safety.os.replace", wraps=os.replace) as replace:
                    writer(copy.deepcopy(session), str(destination))
                    self.assertTrue(replace.called)
                self.assertNotIn(secret, destination.read_text(encoding="utf-8"))

    def test_atomic_failure_preserves_previous_file(self):
        from modules.safety import atomic_write_text

        with tempfile.TemporaryDirectory() as tmp:
            destination = pathlib.Path(tmp) / "state.txt"
            destination.write_text("previous", encoding="utf-8")
            with patch("modules.safety.os.replace", side_effect=OSError("synthetic failure")):
                with self.assertRaises(OSError):
                    atomic_write_text(destination, "replacement")
            self.assertEqual(destination.read_text(encoding="utf-8"), "previous")
            self.assertEqual(list(destination.parent.glob(".edyrecon-*.tmp")), [])

    def test_config_atomic_save_preserves_local_ai_credential(self):
        from modules import config as cfgmod
        from modules.config import ConfigManager

        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "config.json"
            with patch.object(cfgmod, "CONFIG_PATH", str(path)):
                manager = ConfigManager()
                manager.cfg["ai"]["password"] = "synthetic-local-password"
                self.assertTrue(manager.save())
                loaded = ConfigManager().load()
            self.assertEqual(loaded.cfg["ai"]["password"], "synthetic-local-password")

    def test_dehashed_domain_query_is_cached_within_scan(self):
        from modules.darkweb import DarkWebScanner

        scanner = DarkWebScanner(FakeConfig())
        calls = []
        scanner.dehashed = lambda query, size=50: calls.append((query, size)) or {"ok": []}
        scanner.ahmia = lambda *_args, **_kwargs: {"ok": []}
        scanner.scan(
            ["first@example.com", "second@example.com"],
            skip_sources={"intelx", "hibp_pastes"},
        )
        self.assertEqual(calls, [("domain:example.com", 50)])

    def test_timeout_error_does_not_leak_url_query(self):
        import requests
        from modules.osint import APIError, OSINTScanner

        scanner = OSINTScanner(FakeConfig())
        scanner.session.get = unittest.mock.Mock(
            side_effect=requests.Timeout("https://user@example.com/path?api_key=synthetic-secret")
        )
        with self.assertRaises(APIError) as raised:
            scanner._get("https://example.com/path", params={"api_key": "synthetic-secret"})
        rendered = str(raised.exception)
        self.assertNotIn("synthetic-secret", rendered)
        self.assertNotIn("user@example.com", rendered)

    def test_html_report_is_responsive_escaped_and_sanitized(self):
        from modules.report import generate_html

        fixture = {
            "operador": "Synthetic",
            "targets": [
                {
                    "name": "<script>alert(1)</script>",
                    "emails": [{"email": "user@example.com", "password": "synthetic-secret"}],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "report.html"
            generate_html(fixture, path)
            html = path.read_text(encoding="utf-8")
        self.assertIn('name="viewport"', html)
        self.assertIn("@media (max-width:720px)", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)
        self.assertNotIn("synthetic-secret", html)
        self.assertNotIn("<script>alert(1)</script>", html)

    def test_429_retry_is_bounded_and_honors_retry_after(self):
        from modules.osint import OSINTScanner

        scanner = OSINTScanner(FakeConfig())
        scanner.session.get = unittest.mock.Mock(
            side_effect=[
                FakeResponse(429, headers={"Retry-After": "1"}),
                FakeResponse(200, payload={"ok": True}),
            ]
        )
        with patch("modules.safety.time.sleep") as sleep:
            result = scanner._get("https://example.com/synthetic")
        self.assertEqual(result.status_code, 200)
        self.assertEqual(scanner.session.get.call_count, 2)
        sleep.assert_called_once()


class StaticContractTests(unittest.TestCase):
    def test_scripts_have_safe_permissions_and_guarded_sync(self):
        kali = (ROOT / "kali_install.sh").read_text(encoding="utf-8")
        sync = (ROOT / "sync_to_kali.sh").read_text(encoding="utf-8")
        combined = kali + sync
        self.assertNotIn("chmod -R 777", combined)
        self.assertNotIn('source "$CONF"', sync)
        self.assertIn("--dry-run", sync)
        self.assertIn(".edyrecon-managed", sync)
        self.assertIn("--backup-dir", sync)
        self.assertIn("--delete-delay", sync)
        self.assertIn("--backup-dir", kali)

    def test_kali_launcher_exists_and_is_portable(self):
        launcher = ROOT / "EDYRECON.sh"
        self.assertTrue(launcher.is_file())
        text = launcher.read_text(encoding="utf-8")
        self.assertIn(".venv/bin/python", text)
        self.assertNotIn("command -v python3", text)
        self.assertIn("Ambiente virtual .venv nao encontrado", text)
        self.assertNotIn("/home/kali", text)

    def test_version_is_imported_from_single_source(self):
        expected_import = "from modules import EDY_RECON_VERSION"
        for relative in (
            "edyrecon.py",
            "atualizar_wordlists.py",
            "modules/ai.py",
            "modules/breaches.py",
            "modules/bruteforce.py",
            "modules/ui.py",
            "modules/osint.py",
            "modules/darkweb.py",
            "modules/passwords.py",
            "modules/report.py",
        ):
            text = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn(expected_import, text, relative)

    def test_readme_uses_venv_and_has_no_environment_key_status(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(".venv", readme)
        self.assertIn("--apply", readme)
        self.assertNotIn("Status atual", readme)
        self.assertNotIn("--password kali", readme)

    def test_no_network_attempt_was_made(self):
        self.assertEqual(offline_guard.NETWORK_ATTEMPTS, [])

    def test_main_menu_and_themes_are_preserved(self):
        source = (ROOT / "edyrecon.py").read_text(encoding="utf-8")
        for option in [str(i) for i in range(1, 13)] + ["T", "0"]:
            self.assertIn(f'("{option}",', source)
        from modules import ui

        self.assertEqual(set(ui.THEMES), {"CYBER", "NEO", "DARK", "BLUE"})

    def test_no_color_and_ascii_modes_are_plain(self):
        env = dict(os.environ)
        env["NO_COLOR"] = "1"
        env["EDYRECON_ASCII"] = "1"
        python = ROOT / ".venv" / "Scripts" / "python.exe"
        result = subprocess.run(
            [str(python), "-B", "-c", "from modules import ui; ui.banner(); ui.menu(items=[('1','Opção sintética','primary')])"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=True,
        )
        self.assertNotIn("\x1b", result.stdout)
        self.assertTrue(result.stdout.isascii())

    def test_secret_values_are_not_interpolated_in_menus(self):
        source = (ROOT / "edyrecon.py").read_text(encoding="utf-8")
        self.assertNotIn("api_key: {ai.get('api_key')", source)
        self.assertNotIn('cur = CFG.key(nome) or "(vazia)"', source)
        self.assertNotIn('ui.ask(t, "Senha> ", default=ai.get("password"))', source)


if __name__ == "__main__":
    unittest.main()
