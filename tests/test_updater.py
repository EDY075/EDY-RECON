from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

import offline_guard  # ativa o bloqueio global


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import atualizar_wordlists as updater


class FakeDownload:
    def __init__(self, payload, declared_length=None):
        self.payload = payload
        self.offset = 0
        self.headers = {"Content-Length": str(declared_length if declared_length is not None else len(payload))}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _size):
        if self.offset:
            return b""
        self.offset = len(self.payload)
        return self.payload


class UpdaterSafetyTests(unittest.TestCase):
    def test_download_replaces_atomically_after_validation(self):
        payload = b"synthetic-one\nsynthetic-two\n"
        with tempfile.TemporaryDirectory() as tmp:
            destination = pathlib.Path(tmp) / "fixture.txt"
            with patch.object(updater.urllib.request, "urlopen", return_value=FakeDownload(payload)):
                self.assertTrue(updater.download("https://example.com/fixture", str(destination), force=True))
            self.assertEqual(destination.read_bytes(), payload)
            self.assertFalse(pathlib.Path(str(destination) + ".part").exists())

    def test_incomplete_download_preserves_previous_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = pathlib.Path(tmp) / "fixture.txt"
            destination.write_bytes(b"previous-content")
            response = FakeDownload(b"short", declared_length=50)
            with patch.object(updater.urllib.request, "urlopen", return_value=response):
                self.assertFalse(updater.download("https://example.com/fixture", str(destination), force=True))
            self.assertEqual(destination.read_bytes(), b"previous-content")
            self.assertFalse(pathlib.Path(str(destination) + ".part").exists())

    def test_invalid_config_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = pathlib.Path(tmp) / "config.json"
            config.write_text("{invalid", encoding="utf-8")
            with patch.object(updater, "CONFIG_PATH", str(config)):
                self.assertFalse(updater.registrar_no_config())
            self.assertEqual(config.read_text(encoding="utf-8"), "{invalid")


if __name__ == "__main__":
    unittest.main()
