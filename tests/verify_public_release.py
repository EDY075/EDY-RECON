#!/usr/bin/env python3
"""Auditoria local da allowlist pública do EDY RECON.

O modo padrão é estrito e foi projetado para um checkout público limpo. Use
``--local-with-private`` apenas na árvore de desenvolvimento: arquivos privados
são classificados por caminho e metadados, mas nunca abertos ou impressos.
"""

from __future__ import annotations

import argparse
import ast
import ipaddress
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAX_PUBLIC_BYTES = 10 * 1024 * 1024

PUBLIC_FILES = {
    ".env.example",
    ".gitattributes",
    ".github/workflows/offline-ci.yml",
    ".gitignore",
    "ACCEPTABLE_USE.md",
    "CHANGELOG.md",
    "DATA_SOURCES.md",
    "EDYRECON.bat",
    "EDYRECON.sh",
    "LICENSE",
    "PRIVACY.md",
    "README.md",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.md",
    "WORDLISTS_MANIFEST.csv",
    "atualizar_wordlists.py",
    "data/config.example.json",
    "edyrecon.py",
    "instalar_windows.bat",
    "kali_install.sh",
    "kali_pos_install.sh",
    "kali_target.conf.example",
    "logs/.gitkeep",
    "modules/__init__.py",
    "modules/ai.py",
    "modules/breaches.py",
    "modules/bruteforce.py",
    "modules/config.py",
    "modules/darkweb.py",
    "modules/osint.py",
    "modules/passwords.py",
    "modules/report.py",
    "modules/safety.py",
    "modules/ui.py",
    "reports/.gitkeep",
    "requirements.txt",
    "sessions/.gitkeep",
    "sync_to_kali.sh",
    "tests/__init__.py",
    "tests/offline_guard.py",
    "tests/test_bruteforce_safety.py",
    "tests/test_containment.py",
    "tests/test_interface.py",
    "tests/test_reports.py",
    "tests/test_updater.py",
    "tests/verify_public_release.py",
    "verificar_wordlists.py",
}

REQUIRED_GITIGNORE = {
    ".venv/", "venv/", "__pycache__/", "*.py[cod]", ".pytest_cache/",
    ".mypy_cache/", ".ruff_cache/", ".coverage", "htmlcov/",
    "data/config.json", "kali_target.conf", "tmp_kali_config.py",
    "reports/**", "!reports/.gitkeep", "sessions/**", "!sessions/.gitkeep",
    "logs/**", "!logs/.gitkeep", "data/wordlists/**",
    "data/passwords_base.lst", "data/breaches.json", ".env", ".env.*",
    "!.env.example", "archive/", "*.log", "*.tmp", "*.part", "*.bak",
    ".DS_Store", "Thumbs.db", ".vscode/", ".idea/",
}

PRIVATE_EXACT = {
    "data/config.json", "data/passwords_base.lst", "data/breaches.json",
    "kali_target.conf", "tmp_kali_config.py",
}
PRIVATE_PREFIXES = (
    ".venv/", "venv/", "archive/", "data/wordlists/", "__pycache__/",
)

SECRET_PATTERNS = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    "aws-key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "bearer-value": re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    "secret-assignment": re.compile(
        r"(?i)(?:api[_-]?key|token|secret|password|passwd|pwd|senha)"
        r"\s*[:=]\s*[\"'][^\"']{4,}[\"']"
    ),
}
PERSONAL_WINDOWS = re.compile(r"(?i)\b[A-Z]:\\Users\\[^\\\s\"']+")
PERSONAL_POSIX = re.compile(r"(?<![A-Za-z0-9_])/home/[a-z_][a-z0-9_-]*")
EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b")
IPV4 = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
URL_HOST = re.compile(r"(?i)https?://([^/\s\"'<>]+)")
TARGET_HOST_ASSIGNMENT = re.compile(r"(?i)\b(?:KALI_HOST|HOST|HOSTNAME)\s*[:=]")
SAFE_MARKERS = ("synthetic", "example", "placeholder", "redacted", "masked", "***", "fixture")
DOC_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("127.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)


def posix(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def is_private_path(relative: str) -> bool:
    if relative in PRIVATE_EXACT:
        return True
    if relative.startswith(PRIVATE_PREFIXES):
        return True
    parts = relative.split("/")
    if "__pycache__" in parts or relative.endswith((".pyc", ".pyo")):
        return True
    if parts[0] in {"reports", "sessions", "logs"} and not relative.endswith("/.gitkeep"):
        return True
    if relative == ".env" or (relative.startswith(".env.") and relative != ".env.example"):
        return True
    if relative.endswith((".log", ".tmp", ".part", ".bak")):
        return True
    return False


def iter_files():
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        relative = posix(path)
        if relative == ".git" or relative.startswith(".git/"):
            continue
        yield path, relative


def safe_fixture_line(relative: str, line: str) -> bool:
    folded = line.casefold()
    if any(marker in folded for marker in SAFE_MARKERS):
        return True
    if relative.startswith("tests/") and ("assertnotin" in folded or "assert not" in folded):
        return True
    return False


def scan_public_file(path: Path, relative: str, errors: list[str], masked: list[str]) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        errors.append(f"{relative}: conteúdo público não é UTF-8")
        return

    for number, line in enumerate(text.splitlines(), 1):
        for kind, pattern in SECRET_PATTERNS.items():
            if not pattern.search(line):
                continue
            masked.append(f"{relative}:{number}:{kind}:***MASKED***")
            if not safe_fixture_line(relative, line):
                errors.append(f"{relative}:{number}: possível {kind} mascarado")

        if PERSONAL_WINDOWS.search(line) or PERSONAL_POSIX.search(line):
            masked.append(f"{relative}:{number}:personal-path:***MASKED***")
            if not safe_fixture_line(relative, line):
                errors.append(f"{relative}:{number}: possível path pessoal mascarado")

        for match in EMAIL.finditer(line):
            domain = match.group(1).casefold()
            masked.append(f"{relative}:{number}:email:***MASKED***")
            if domain not in {"example.com", "example.org", "example.net"} and not safe_fixture_line(relative, line):
                errors.append(f"{relative}:{number}: e-mail não documental mascarado")

        for raw_ip in IPV4.findall(line):
            try:
                address = ipaddress.ip_address(raw_ip)
            except ValueError:
                errors.append(f"{relative}:{number}: IPv4 inválido mascarado")
                continue
            masked.append(f"{relative}:{number}:ipv4:***MASKED***")
            if not any(address in network for network in DOC_NETWORKS):
                errors.append(f"{relative}:{number}: IPv4 não documental mascarado")

        if URL_HOST.search(line) or TARGET_HOST_ASSIGNMENT.search(line):
            masked.append(f"{relative}:{number}:hostname:***MASKED***")


def validate_syntax(candidates: list[tuple[Path, str]], errors: list[str]) -> None:
    for path, relative in candidates:
        if path.suffix != ".py":
            continue
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        except (SyntaxError, UnicodeDecodeError) as exc:
            errors.append(f"{relative}: sintaxe/encoding inválido ({type(exc).__name__})")


def validate_json(errors: list[str]) -> None:
    for relative in sorted(PUBLIC_FILES):
        if not relative.endswith(".json"):
            continue
        try:
            json.loads((ROOT / relative).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            errors.append(f"{relative}: JSON inválido ({type(exc).__name__})")


def validate_readme_links(errors: list[str]) -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", readme):
        target = target.strip().split("#", 1)[0]
        if not target or re.match(r"^(?:https?://|mailto:)", target, re.I):
            continue
        if not (ROOT / target).exists():
            errors.append(f"README.md: link local ausente: {target}")


def validate_gitignore(errors: list[str]) -> None:
    lines = {
        line.strip()
        for line in (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    for missing in sorted(REQUIRED_GITIGNORE - lines):
        errors.append(f".gitignore: regra ausente: {missing}")


def validate_test_count(errors: list[str]) -> None:
    count = 0
    for relative in sorted(PUBLIC_FILES):
        if not relative.startswith("tests/test_") or not relative.endswith(".py"):
            continue
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"), filename=relative)
        count += sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_") for node in ast.walk(tree))
    if count != 40:
        errors.append(f"suíte offline: esperados 40 testes, encontrados {count}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Audita a allowlist pública do EDY RECON")
    parser.add_argument(
        "--local-with-private",
        action="store_true",
        help="tolera arquivos privados locais, classificando-os sem ler conteúdo",
    )
    args = parser.parse_args()

    errors: list[str] = []
    masked: list[str] = []
    candidates: list[tuple[Path, str]] = []
    private_count = 0
    private_bytes = 0
    unexpected: list[str] = []

    for path, relative in iter_files():
        if relative in PUBLIC_FILES:
            candidates.append((path, relative))
            if path.stat().st_size > MAX_PUBLIC_BYTES:
                errors.append(f"{relative}: arquivo público excede 10 MiB")
            continue
        if is_private_path(relative):
            private_count += 1
            private_bytes += path.stat().st_size
            if not args.local_with_private:
                errors.append(f"arquivo privado presente no checkout: {relative}")
            continue
        unexpected.append(relative)

    missing = sorted(PUBLIC_FILES - {relative for _, relative in candidates})
    errors.extend(f"allowlist: arquivo ausente: {relative}" for relative in missing)
    errors.extend(f"allowlist: arquivo inesperado: {relative}" for relative in unexpected)

    for path, relative in candidates:
        scan_public_file(path, relative, errors, masked)

    validate_syntax(candidates, errors)
    validate_json(errors)
    validate_readme_links(errors)
    validate_gitignore(errors)
    validate_test_count(errors)

    print(f"PUBLIC_COUNT={len(candidates)}")
    print(f"PUBLIC_BYTES={sum(path.stat().st_size for path, _ in candidates)}")
    print(f"PRIVATE_EXCLUDED_COUNT={private_count}")
    print(f"PRIVATE_EXCLUDED_BYTES={private_bytes}")
    print(f"MASKED_OCCURRENCES={len(masked)}")
    for _, relative in sorted(candidates, key=lambda item: item[1]):
        print(f"CANDIDATE={relative}")
    for occurrence in masked:
        print(f"MASKED={occurrence}")
    for error in errors:
        print(f"ERROR={error}", file=sys.stderr)

    if errors:
        print(f"RESULT=FAIL ({len(errors)} erro(s))", file=sys.stderr)
        return 1
    print("RESULT=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
