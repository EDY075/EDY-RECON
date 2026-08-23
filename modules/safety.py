"""Controles locais de segurança, sanitização e persistência atômica."""

from __future__ import annotations

import copy
import json
import os
import random
import re
import tempfile
import time
from urllib.parse import urlsplit, urlunsplit


SENSITIVE_FIELDS = {
    "password",
    "passwords",
    "passwd",
    "pwd",
    "passphrase",
    "passwordhash",
    "senha",
    "senhas",
    "senhahash",
    "apikey",
    "authorization",
    "accesstoken",
    "refreshtoken",
    "token",
    "secret",
    "clientsecret",
    "credential",
    "credentials",
}

PLACEHOLDERS = {
    "change_me",
    "changeme",
    "your_api_key",
    "your_key_here",
    "api_key_here",
    "sua_chave_aqui",
    "synthetic_placeholder",
    "test_key",
    "example",
}

SENSITIVE_MESSAGE_FIELDS = {"error", "errors", "erro", "erros", "warning", "warnings", "aviso", "avisos"}

_URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.I)
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[^\s,;]+")
_SECRET_PAIR_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|pwd|senha|authorization)\s*[:=]\s*[^\s,;&]+"
)


def _normalized_key(value):
    return re.sub(r"[^a-z0-9]", "", str(value).casefold())


def is_configured_secret(value):
    value = str(value or "").strip()
    return bool(value) and value.casefold() not in PLACEHOLDERS


def mask_secret(value):
    value = str(value or "")
    if not value:
        return "(vazio)"
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}{'*' * min(8, len(value) - 4)}{value[-2:]}"


def sanitize_data(value):
    """Remove campos de senha recursivamente sem alterar o objeto original."""
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            normalized = _normalized_key(key)
            if normalized in SENSITIVE_FIELDS:
                continue
            if normalized in SENSITIVE_MESSAGE_FIELDS:
                if isinstance(item, (list, tuple)):
                    cleaned[key] = [sanitize_text(message, limit=500) for message in item]
                else:
                    cleaned[key] = sanitize_text(item, limit=500)
            else:
                cleaned[key] = sanitize_data(item)
        return cleaned
    if isinstance(value, list):
        return [sanitize_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_data(item) for item in value)
    return copy.deepcopy(value)


def sanitize_url(url):
    try:
        parts = urlsplit(str(url))
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
        return urlunsplit((parts.scheme, host, parts.path, "", ""))
    except (TypeError, ValueError):
        return "[redacted-url]"


def sanitize_text(value, limit=None):
    text = str(value or "")
    text = _URL_RE.sub(lambda m: sanitize_url(m.group(0)), text)
    text = _EMAIL_RE.sub("[redacted-email]", text)
    text = _BEARER_RE.sub("Bearer [redacted]", text)
    text = _SECRET_PAIR_RE.sub("[redacted-secret]", text)
    if limit is not None:
        text = text[:limit]
    return text


def safe_error(error, limit=160):
    return sanitize_text(error, limit=limit) or "falha sem detalhe seguro"


def _ensure_directory(path):
    existed = os.path.isdir(path)
    os.makedirs(path, exist_ok=True)
    if not existed and os.name != "nt":
        os.chmod(path, 0o700)


def atomic_write_text(path, text, mode=0o600):
    path = os.path.abspath(os.fspath(path))
    directory = os.path.dirname(path) or "."
    _ensure_directory(directory)
    fd, temporary = tempfile.mkstemp(prefix=".edyrecon-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(str(text))
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(temporary, mode)
        os.replace(temporary, path)
        if os.name != "nt":
            os.chmod(path, mode)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return path


def atomic_write_json(path, value, mode=0o600):
    payload = json.dumps(value, ensure_ascii=False, indent=2)
    return atomic_write_text(path, payload + "\n", mode=mode)


def request_with_retry(request, url, *, max_attempts=2, retry_statuses=None, **kwargs):
    """Retry curto para leitura passiva; respeita Retry-After e limita tentativas."""
    retry_statuses = set(retry_statuses or (429, 500, 502, 503, 504))
    attempts = max(1, min(int(max_attempts), 3))
    response = None
    for attempt in range(attempts):
        response = request(url, **kwargs)
        if response.status_code not in retry_statuses or attempt + 1 >= attempts:
            return response
        retry_after = str((getattr(response, "headers", {}) or {}).get("Retry-After", "")).strip()
        try:
            delay = min(5.0, max(0.0, float(retry_after)))
        except ValueError:
            delay = min(4.0, (2**attempt) + random.uniform(0.0, 0.25))
        time.sleep(delay)
    return response
