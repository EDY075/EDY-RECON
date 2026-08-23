from __future__ import annotations

import os
import pathlib
import re
import tempfile
import unittest
from unittest.mock import patch

import offline_guard  # noqa: F401 — bloqueia rede antes dos imports do projeto


ROOT = pathlib.Path(__file__).resolve().parents[1]


def synthetic_session():
    return {
        "synthetic": True,
        "operador": "Analista Sintético çãõ",
        "modo": "SESSÃO SINTÉTICA",
        "data": "2026-08-23T18:30:00-03:00",
        "warnings": ["Mock indisponível: https://example.com/a?api_key=synthetic-error-secret"],
        "targets": [{
            "name": "<script>alert('target')</script>",
            "variantes": ["edy", "<img src=x onerror=alert(1)>"] ,
            "variantes_correlacionadas": ["edy@example.com"],
            "domains": [{
                "domain": "example.com<script>alert(2)</script>",
                "dns": {"a": ["192.0.2.10"]},
                "rdap": {"ok": {"criado": "2020-01-01"}},
                "crtsh": {"ok": ["www.example.com"]},
                "erros": ["GET https://example.com/?token=synthetic-domain-secret"],
            }],
            "emails": [{
                "email": "user@example.com",
                "password": "synthetic-password-secret",
                "api_key": "synthetic-api-secret",
                "token": "synthetic-token-secret",
                "reputacao": {
                    "reputation": "good",
                    "suspicious": "<svg onload=alert(3)>",
                    "references": "<b>7</b>",
                },
                "hunter": {"status": "valid", "score": "<img src=x onerror=alert(4)>"},
                "vazamentos": [{
                    "source": "Mock Breach",
                    "site": "Fixture & Teste",
                    "data": "2026-01-02",
                    "registros": 1,
                    "categoria": "Teste",
                    "status": "Sintético",
                }],
                "darkweb": [{"source": "Mock Dark", "data": "2026", "tipo": "fixture", "bucket": "documental"}],
                "erros": ["Bearer synthetic-bearer-secret em https://user:pass@example.com/?secret=synthetic-query-secret"],
            }],
        }],
    }


class ReportTests(unittest.TestCase):
    def test_txt_and_html_are_utf8_complete_and_secret_free(self):
        from modules.report import generate_html, generate_txt

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            txt_path = root / "synthetic.txt"
            html_path = root / "synthetic.html"
            generate_txt(synthetic_session(), txt_path)
            generate_html(synthetic_session(), html_path)
            txt = txt_path.read_text(encoding="utf-8", errors="strict")
            html = html_path.read_text(encoding="utf-8", errors="strict")

        for content in (txt, html):
            self.assertIn("2026-08-23T18:30:00-03:00", content)
            self.assertIn("Resumo das fontes" if content is html else "RESUMO DAS FONTES", content)
            self.assertIn("Sint", content)
            for secret in (
                "synthetic-password-secret", "synthetic-api-secret", "synthetic-token-secret",
                "synthetic-error-secret", "synthetic-domain-secret", "synthetic-bearer-secret",
                "synthetic-query-secret", "user:pass",
            ):
                self.assertNotIn(secret, content)
        self.assertIn("Analista Sintético çãõ", txt)
        self.assertIn("Analista Sintético çãõ", html)

    def test_html_escapes_every_hostile_field_and_has_no_external_dependency(self):
        from modules.report import generate_html

        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "synthetic.html"
            generate_html(synthetic_session(), path)
            html = path.read_text(encoding="utf-8")

        for active in ("<script", "<img", "<svg"):
            self.assertNotIn(active, html.casefold())
        self.assertIsNone(re.search(r"<[^>]+\bon(?:error|load)\s*=", html, re.I))
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("Content-Security-Policy", html)
        self.assertIn("default-src 'none'", html)
        self.assertIn("@media print", html)
        self.assertIsNone(re.search(r"(?:src|href)\s*=\s*['\"]https?://", html, re.I))

    def test_relative_and_temporary_paths_work(self):
        from modules.report import generate_html, generate_txt

        previous = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            os.chdir(tmp)
            try:
                self.assertEqual(pathlib.Path(generate_txt(synthetic_session(), "relative.txt")).name, "relative.txt")
                self.assertEqual(pathlib.Path(generate_html(synthetic_session(), "relative.html")).name, "relative.html")
                self.assertTrue(pathlib.Path("relative.txt").is_file())
                self.assertTrue(pathlib.Path("relative.html").is_file())
            finally:
                os.chdir(previous)

    def test_format_selection_preserves_names_and_directory(self):
        import edyrecon
        from modules import config as cfgmod

        with tempfile.TemporaryDirectory() as tmp, patch.object(cfgmod, "REPORTS_DIR", tmp):
            both = [pathlib.Path(p) for p in edyrecon._generate_selected_reports(synthetic_session(), "3")]
            self.assertEqual({p.suffix for p in both}, {".txt", ".html"})
            self.assertEqual(len({p.stem for p in both}), 1)
            self.assertTrue(all(p.parent == pathlib.Path(tmp) for p in both))
            self.assertEqual(edyrecon._generate_selected_reports(synthetic_session(), "0"), [])

    def test_windows_txt_and_html_openers_use_safe_argv_and_file_uri(self):
        import edyrecon

        with tempfile.TemporaryDirectory() as tmp:
            txt_path = pathlib.Path(tmp) / "report synthetic.txt"
            html_path = pathlib.Path(tmp) / "report synthetic.html"
            txt_path.write_text("fixture", encoding="utf-8")
            html_path.write_text("<html></html>", encoding="utf-8")
            with patch.object(edyrecon.os, "name", "nt"), patch.object(edyrecon.subprocess, "Popen") as popen:
                self.assertTrue(edyrecon._open_saved_report(txt_path))
                popen.assert_called_once_with(["notepad.exe", str(txt_path.resolve())], close_fds=True)
            with patch.object(edyrecon.webbrowser, "open", return_value=True) as browser:
                self.assertTrue(edyrecon._open_saved_report(html_path))
                called = browser.call_args.args[0]
                self.assertTrue(called.startswith("file:///"))
                self.assertNotIn(" ", called)


if __name__ == "__main__":
    unittest.main()
