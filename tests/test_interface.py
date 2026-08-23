from __future__ import annotations

import os
import pathlib
import re
import subprocess
import unittest
from unittest.mock import Mock, patch

import offline_guard  # noqa: F401 — bloqueia rede antes dos imports do projeto


ROOT = pathlib.Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
ANSI = re.compile(r"\x1b\[[0-9;]*m")


class InterfaceTests(unittest.TestCase):
    def test_main_dispatches_every_menu_without_network_or_writes(self):
        import edyrecon

        fake_config = Mock()
        fake_config.cfg = {"wordlists": []}
        fake_config.theme.return_value = "NEO"
        fake_config.has_key.return_value = False
        fake_passwords = Mock()
        fake_database = Mock(loaded=True, error=None)
        selections = [str(i) for i in range(1, 13)] + ["T", "0"]
        callback_names = [
            "cmd_scan_completa", "cmd_verificar_email", "cmd_darkweb", "cmd_variantes",
            "cmd_breaches", "cmd_pwned", "cmd_bruteforce", "cmd_domain",
            "cmd_relatorios", "cmd_config", "cmd_sobre", "cmd_ia", "cmd_tema",
        ]
        callbacks = {name: Mock() for name in callback_names}
        config_factory = Mock()
        config_factory.return_value.load.return_value = fake_config
        password_factory = Mock()
        password_factory.return_value.load.return_value = fake_passwords
        database_factory = Mock()
        database_factory.return_value.load.return_value = fake_database

        patches = [patch.object(edyrecon, name, callback) for name, callback in callbacks.items()]
        with patch.object(edyrecon.cfgmod, "ConfigManager", config_factory), \
             patch.object(edyrecon, "PasswordManager", password_factory), \
             patch.object(edyrecon, "BreachDB", database_factory), \
             patch.object(edyrecon, "banner_info"), \
             patch.object(edyrecon.ui, "enable_console"), \
             patch.object(edyrecon.ui, "hr"), \
             patch.object(edyrecon.ui, "menu"), \
             patch.object(edyrecon.ui, "p"), \
             patch.object(edyrecon.ui, "ask", side_effect=selections):
            for active_patch in patches:
                active_patch.start()
            try:
                edyrecon.main()
            finally:
                for active_patch in reversed(patches):
                    active_patch.stop()

        for callback in callbacks.values():
            callback.assert_called_once()

    def test_all_themes_fit_a_24_column_ascii_terminal(self):
        env = dict(os.environ)
        env.update({"NO_COLOR": "1", "EDYRECON_ASCII": "1", "COLUMNS": "24", "LINES": "30"})
        code = (
            "from modules import ui; "
            "[(ui.banner(t), ui.menu(t, 'MENU', [('1','Opção sintética longa','primary')], footer='Rodapé sintético')) "
            "for t in ui.THEME_ORDER]"
        )
        result = subprocess.run(
            [str(PYTHON), "-B", "-c", code], cwd=ROOT, env=env,
            capture_output=True, text=True, encoding="utf-8", timeout=20, check=True,
        )
        self.assertTrue(result.stdout.isascii())
        self.assertNotIn("\x1b", result.stdout)
        self.assertLessEqual(max(len(line) for line in result.stdout.splitlines()), 24)

    def test_four_themes_render_without_broken_ansi(self):
        code = (
            "from modules import ui; ui.enable_console(); "
            "[ui.menu(t, t, [('1','Teste','primary'),('0','Sair','warn')]) for t in ui.THEME_ORDER]"
        )
        result = subprocess.run(
            [str(PYTHON), "-B", "-c", code], cwd=ROOT,
            capture_output=True, text=True, encoding="utf-8", timeout=20, check=True,
        )
        plain = ANSI.sub("", result.stdout)
        for theme in ("CYBER", "NEO", "DARK", "BLUE"):
            self.assertIn(theme, plain)
        self.assertEqual(result.stdout.count("\x1b["), len(ANSI.findall(result.stdout)))

    def test_cli_starts_and_exits_normally_offline(self):
        env = dict(os.environ)
        env.update({"NO_COLOR": "1", "EDYRECON_ASCII": "1"})
        result = subprocess.run(
            [str(PYTHON), "-B", "edyrecon.py"], cwd=ROOT, env=env,
            input="0\n", capture_output=True, text=True, encoding="utf-8", timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Encerrando EDY RECON", result.stdout)
        self.assertNotIn("Traceback", result.stdout)

    def test_password_check_uses_hidden_input(self):
        source = (ROOT / "edyrecon.py").read_text(encoding="utf-8")
        self.assertIn('ui.ask_secret(t, "Senha a verificar> ")', source)
        self.assertNotIn('ui.ask(t, "Senha a verificar> ")', source)


if __name__ == "__main__":
    unittest.main()
