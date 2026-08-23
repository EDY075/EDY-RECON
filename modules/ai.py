# -*- coding: utf-8 -*-
"""
modules/ai.py — Integração de IA para o EDYRECON
=================================================
Providers suportados:
  1. skynet   — API grátis do Skynet Chat (skynet.genisys.online / api.genom.genisys.online)
                Conta free: register/login automático via auth Lambda (SHA-256 da senha).
                Endpoint principal (JSON widget) com fallback SSE em node1.skyos.online.
  2. openrouter / hackclub / completions / ollama / custom
                Qualquer API compatível com OpenAI (Chat Completions).
                Hack Club AI (https://ai.hackclub.com) e OpenRouter têm tiers grátis.

Se o provider falhar, levanta AIError com mensagem amigável — o EDYRECON trata
erros de IA como não-bloqueantes (a ferramenta segue funcionando sem IA).
"""

import hashlib
import json
import time
import uuid

import requests

from modules import EDY_RECON_VERSION
from modules.safety import is_configured_secret, safe_error, sanitize_text

AI_DEFAULT_TIMEOUT = 60

# ---- Constantes do Skynet Chat ----
SKYNET_CHAT = "https://api.genom.genisys.online/api/v1/chat"
SKYNET_STATUS = "https://api.genom.genisys.online/api/v1/status"
SKYNET_NODE_CHAT = "https://node1.skyos.online/api/chat"
SKYNET_AUTH = "https://a3fkeoowx7zx4dosd4ygenlst40pzyow.lambda-url.us-east-1.on.aws/api/v1/auth"
SKYNET_WIDGET_SOURCE = "skynet-widget-v1.0.0"

PRESETS = {
    "skynet": {
        "label": "Skynet Chat (grátis, conta free)",
        "base_url": SKYNET_CHAT,
        "api_key": "",
        "model": "",
        "openai_compat": False,
    },
    "openrouter": {
        "label": "OpenRouter (models grátis: mistral, llama, deepseek...)",
        "base_url": "https://openrouter.ai/api/v1/chat/completions",
        "api_key": "",
        "model": "mistralai/mistral-7b-instruct:free",
        "openai_compat": True,
    },
    "hackclub": {
        "label": "Hack Club AI (chave grátis em https://ai.hackclub.com)",
        "base_url": "https://ai.hackclub.com/v1/chat/completions",
        "api_key": "",
        "model": "gpt-4o-mini",
        "openai_compat": True,
    },
    "completions": {
        "label": "API OpenAI-compatível genérica (ex.: OpenAI, Groq, Together)",
        "base_url": "https://api.openai.com/v1/chat/completions",
        "api_key": "",
        "model": "gpt-4o-mini",
        "openai_compat": True,
    },
    "ollama": {
        "label": "Ollama local (http://localhost:11434/v1/chat/completions)",
        "base_url": "http://localhost:11434/v1/chat/completions",
        "api_key": "ollama",
        "model": "llama3.2",
        "openai_compat": True,
    },
    "custom": {
        "label": "URL personalizada OpenAI-compatível",
        "base_url": "",
        "api_key": "",
        "model": "",
        "openai_compat": True,
    },
}


class AIError(Exception):
    pass


class AIClient:
    """Cliente de IA do EDYRECON. Recebe um ConfigManager (modules/config.py)."""

    def __init__(self, cfg):
        self.cfg = cfg
        ai = cfg.ai() or {}
        self.provider = (ai.get("provider") or "skynet").strip().lower()
        self.base_url = (ai.get("base_url") or "").strip()
        raw_api_key = (ai.get("api_key") or "").strip()
        self.api_key = raw_api_key if is_configured_secret(raw_api_key) else ""
        self.model = (ai.get("model") or "").strip()
        self.email = (ai.get("email") or "").strip()
        self.password = ai.get("password") or ""
        self.session_id = (ai.get("session_id") or "").strip()
        self._token = None
        self.http = requests.Session()
        self.http.headers.update({"User-Agent": f"EDYRECON/{EDY_RECON_VERSION} (AI integration)"})

    # ---------------------------------------------------------------- config

    def set_provider(self, name):
        name = (name or "").strip().lower()
        if name not in PRESETS:
            raise AIError(f"Provider desconhecido: {name}. Válidos: {', '.join(PRESETS)}")
        p = PRESETS[name]
        ai = self.cfg.ai()
        previous = (ai.get("provider") or "skynet").strip().lower()
        provider_keys = dict(ai.get("provider_keys") or {})
        current_key = (ai.get("api_key") or "").strip()
        switching = previous != name
        if switching and is_configured_secret(current_key):
            provider_keys[previous] = current_key
        ai["provider"] = name
        if name == "custom":
            if switching:
                ai["base_url"] = ""
                ai["model"] = ""
                ai["api_key"] = provider_keys.get(name, "")
        else:
            ai["base_url"] = p["base_url"]
            if switching:
                ai["api_key"] = provider_keys.get(name, "")
            if p["api_key"] and name in ("ollama",):
                ai["api_key"] = p["api_key"]
            if p["model"]:
                ai["model"] = p["model"]
        self.provider = name
        self.base_url = ai.get("base_url", "")
        self.api_key = ai.get("api_key", "")
        self.model = ai.get("model", "")
        ai["provider_keys"] = provider_keys
        self.cfg.cfg["ai"] = ai
        self.cfg.save()

    def save(self):
        self.cfg.cfg["ai"] = {
            "provider": self.provider,
            "base_url": self.base_url,
            "api_key": self.api_key,
            "model": self.model,
            "email": self.email,
            "password": self.password,
            "session_id": self.session_id,
            "provider_keys": dict((self.cfg.ai() or {}).get("provider_keys") or {}),
        }
        self.cfg.save()

    # ---------------------------------------------------------------- status

    def check(self):
        """Retorna dict de status do provider (sem levantar exceção)."""
        if self.provider == "skynet":
            return self._check_skynet()
        if self.provider == "ollama":
            try:
                r = self.http.get("http://localhost:11434/api/tags", timeout=5)
                ok = r.status_code == 200
                return {"ok": ok, "detail": "Ollama local respondendo" if ok else f"HTTP {r.status_code}"}
            except Exception as e:
                return {"ok": False, "detail": f"Ollama offline: {safe_error(e, 80)}"}
        if self.base_url:
            return {"ok": bool(self.api_key) or self.provider == "custom",
                    "detail": "base_url + api_key configurados" if (self.base_url and self.api_key)
                             else "configure base_url e api_key no menu de IA"}
        return {"ok": False, "detail": "provider sem configuração"}

    def _check_skynet(self):
        try:
            r = self.http.get(SKYNET_STATUS, timeout=10)
            if r.status_code == 200:
                d = r.json()
                ok = bool(d.get("node_healthy")) and bool(d.get("skyos_api"))
                return {"ok": ok, "detail": ("backend OK" if ok else "backend do Skynet indisponível")}
            return {"ok": False, "detail": f"status HTTP {r.status_code}"}
        except Exception as e:
            return {"ok": False, "detail": f"Skynet sem resposta: {safe_error(e, 80)}"}

    # ---------------------------------------------------------------- auth

    def _hash_password(self):
        return hashlib.sha256(self.password.encode("utf-8")).hexdigest()

    def _skynet_auth(self, action="login"):
        """login ou register no auth Lambda do Skynet. Retorna token."""
        if not self.email or not self.password:
            raise AIError("Configure email e senha do Skynet no menu de IA (conta free).")
        url = f"{SKYNET_AUTH}/{action}"
        try:
            r = self.http.post(
                url,
                json={
                    "email": self.email,
                    "password_hash": self._hash_password(),
                    "client_name": "edyrecon",
                },
                timeout=20,
            )
        except requests.exceptions.RequestException as e:
            raise AIError(f"Skynet auth indisponível: {safe_error(e, 120)}")
        if r.status_code not in (200, 201):
            raise AIError(f"Skynet auth ({action}) HTTP {r.status_code}")
        try:
            d = r.json()
        except Exception:
            raise AIError("Skynet auth retornou resposta inválida")
        token = d.get("token") or d.get("access_token") or d.get("data", {}).get("token")
        if not token:
            raise AIError("Skynet auth não retornou token")
        return token

    def _ensure_token(self):
        if not self._token:
            try:
                self._token = self._skynet_auth("login")
            except AIError:
                self._token = self._skynet_auth("register")
        return self._token

    # ---------------------------------------------------------------- chat

    def chat(self, message, system=None, max_tokens=1000):
        """Envia mensagem ao provider configurado e retorna texto de resposta."""
        if not message or not str(message).strip():
            raise AIError("Mensagem vazia.")
        if self.provider == "skynet":
            return self._chat_skynet(str(message), system)
        if PRESETS.get(self.provider, {}).get("openai_compat") or self.provider == "custom":
            return self._chat_openai(str(message), system, max_tokens)
        raise AIError(f"Provider '{self.provider}' não implementado.")

    def _chat_skynet(self, message, system=None):
        prompt = message
        if system:
            prompt = f"[{system}]\n\n{message}"
        token = self._ensure_token()
        # 1) endpoint widget JSON (api.genom.genisys.online)
        try:
            r = self.http.post(
                SKYNET_CHAT,
                json={"message": prompt, "sessionId": self.session_id or None},
                headers={
                    "Content-Type": "application/json",
                    "X-Widget-Source": SKYNET_WIDGET_SOURCE,
                    "Authorization": f"Bearer {token}",
                },
                timeout=AI_DEFAULT_TIMEOUT,
            )
            if r.status_code == 200:
                try:
                    d = r.json()
                    reply = d.get("reply") or d.get("message") or d.get("text") or d.get("answer")
                    if reply:
                        self.session_id = d.get("sessionId") or self.session_id
                        self.save()
                        return str(reply).strip()
                except Exception:
                    pass
            if r.status_code in (401, 403):
                self._token = None
                raise AIError("Skynet rejeitou credenciais (401/403). Verifique email/senha no menu de IA.")
            # 2) fallback: node1.skyos.online (SSE)
            return self._chat_skynet_node(message, system, token)
        except requests.exceptions.RequestException as e:
            raise AIError(f"Skynet indisponível: {safe_error(e, 120)}")

    def _chat_skynet_node(self, message, system=None, token=None):
        """Fallback SSE em node1.skyos.online/api/chat."""
        headers = {
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
            "Authorization": f"Bearer {token or ''}",
            "X-Session-ID": self.session_id or "",
        }
        try:
            r = self.http.post(
                SKYNET_NODE_CHAT,
                json={"message": message, "system": system or ""},
                headers=headers,
                timeout=AI_DEFAULT_TIMEOUT,
                stream=True,
            )
            if r.status_code != 200:
                raise AIError(f"Skynet node HTTP {r.status_code}")
            parts = []
            for line in r.iter_lines(decode_unicode=True):
                if not line:
                    continue
                line = line.strip()
                if line.startswith("data:"):
                    payload = line[5:].strip()
                    if payload and payload != "[DONE]":
                        try:
                            obj = json.loads(payload)
                            chunk = obj.get("reply") or obj.get("message") or obj.get("text") or obj.get("content") or obj.get("choices", [{}])[0].get("delta", {}).get("content", "")
                            if chunk:
                                parts.append(str(chunk))
                        except Exception:
                            parts.append(payload)
            r.close()
            if not parts:
                raise AIError("Skynet node não retornou conteúdo")
            return "".join(parts).strip()
        except AIError:
            raise
        except Exception as e:
            raise AIError(f"Skynet indisponível: {safe_error(e, 120)}")

    def _chat_openai(self, message, system=None, max_tokens=1000):
        if not self.base_url:
            raise AIError("Configure a URL do provider (base_url) no menu de IA.")
        if not self.api_key and self.provider != "custom":
            raise AIError(f"Configure a api_key do provider '{self.provider}' no menu de IA.")
        url = self.base_url
        if not url.rstrip("/").endswith("chat/completions"):
            url = url.rstrip("/") + "/chat/completions"
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": message})
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        if self.provider == "openrouter":
            headers["HTTP-Referer"] = "https://edyrecon.local"
            headers["X-Title"] = "EDYRECON"
        payload = {"messages": messages, "max_tokens": max_tokens}
        if self.model:
            payload["model"] = self.model
        try:
            r = self.http.post(url, json=payload, headers=headers, timeout=AI_DEFAULT_TIMEOUT)
        except requests.exceptions.RequestException as e:
            raise AIError(f"Falha ao falar com {self.provider}: {safe_error(e, 120)}")
        if r.status_code not in (200, 201):
            raise AIError(f"{self.provider} HTTP {r.status_code}")
        try:
            d = r.json()
            return d["choices"][0]["message"]["content"].strip()
        except Exception:
            raise AIError(f"{self.provider} retornou JSON inesperado")

    # ---------------------------------------------------------------- helpers de análise

    def analyze(self, text, question=None):
        """Analisa um texto (ex.: relatório OSINT) com a IA."""
        if not text or not str(text).strip():
            raise AIError("Nada para analisar.")
        system = (
            "Você é um analista sênior de OSINT e segurança da informação. "
            "Analise o conteúdo fornecido e responda em português (pt-BR), "
            "de forma objetiva, destacando: pontos de risco, dados sensíveis expostos, "
            "padrões suspeitos e recomendações práticas de mitigação. "
            "Não invente informações que não estejam no texto."
        )
        q = question or "Faça uma análise completa do material abaixo."
        material = sanitize_text(text, limit=12000)
        return self.chat(f"{q}\n\n--- MATERIAL ---\n{material}", system=system)
