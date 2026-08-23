from __future__ import annotations

import pathlib
import sys
import unittest

import offline_guard  # noqa: F401 — ativa o bloqueio global antes dos testes


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class FakeConfig:
    cfg = {"bruteforce": {"threads": 2, "delay": 0, "timeout": 1}}


class GuardedPasswords:
    """Falha se o executor consumir além da janela inicial antes do sucesso."""

    def __iter__(self):
        yield "p1"
        yield "p2"
        raise AssertionError("executor consumiu combinações além da janela limitada")


class BruteForceSafetyTests(unittest.TestCase):
    def test_ssh_is_bounded_and_redacts_password(self):
        from modules.bruteforce import BruteForce

        bf = BruteForce(FakeConfig(), None)
        bf._try_ssh = lambda _host, _port, user, password, _timeout: (user, password)
        result = bf.ssh("192.0.2.10", 22, ["synthetic-user"], GuardedPasswords(), threads=2, delay=0)
        self.assertEqual(result[0][3], "synthetic-user")
        self.assertEqual(result[0][4], "***")

    def test_ftp_is_bounded_and_redacts_password(self):
        from modules.bruteforce import BruteForce

        bf = BruteForce(FakeConfig(), None)
        bf._try_ftp = lambda _host, _port, user, password, _timeout: (user, password)
        result = bf.ftp("192.0.2.20", 21, ["synthetic-user"], GuardedPasswords(), threads=2, delay=0)
        self.assertEqual(result[0][3], "synthetic-user")
        self.assertEqual(result[0][4], "***")


if __name__ == "__main__":
    unittest.main()
