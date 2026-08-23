"""Bloqueio global de rede para a suíte offline."""

from __future__ import annotations

import http.client
import socket
import urllib.request
from unittest.mock import patch

import requests


NETWORK_ATTEMPTS = []


def _blocked(*args, **kwargs):
    NETWORK_ATTEMPTS.append((args, kwargs))
    raise AssertionError("acesso de rede bloqueado pela suíte offline")


_PATCHERS = [
    patch.object(socket, "create_connection", _blocked),
    patch.object(socket.socket, "connect", _blocked),
    patch.object(socket.socket, "connect_ex", _blocked),
    patch.object(socket, "getaddrinfo", _blocked),
    patch.object(socket, "gethostbyname", _blocked),
    patch.object(requests.sessions.Session, "request", _blocked),
    patch.object(requests.api, "request", _blocked),
    patch.object(urllib.request, "urlopen", _blocked),
    patch.object(http.client.HTTPConnection, "connect", _blocked),
]

for _patcher in _PATCHERS:
    _patcher.start()
