#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EDY RECON - Verificador de Wordlists
=====================================
Mostra quantas senhas estao carregadas, quantas em STREAMING (disco, sem RAM)
e quantas em memoria. Rode apos atualizar as wordlists:

  python3 verificar_wordlists.py

Valores esperados (v2.0):
  - Dezenas de arquivos de wordlists registrados no config.json
  - Total de linhas: 25M+ (streaming) + base embutida pequena na RAM
"""
import os

from modules.config import ConfigManager
from modules.passwords import PasswordManager


def main():
    cfg = ConfigManager().load().cfg
    wl = cfg.get("wordlists", [])
    pwm = PasswordManager().load(wl)
    s = pwm.stats()
    total = s["in_memory"] + s["stream_lines"]
    print("=" * 64)
    print("  EDY RECON - VERIFICADOR DE WORDLISTS")
    print("=" * 64)
    print(f"  Wordlists registradas no config: {len(wl)}")
    print(f"  TOTAL de senhas disponiveis.....: {total:,}")
    print(f"  Em memoria (RAM)................: {s['in_memory']:,} senhas / {s['memory_mb']} MB")
    print(f"  Em STREAMING (disco, sem RAM)...: {s['streams']} arquivos / {s['stream_lines']:,} linhas")
    print("-" * 64)
    for src in s["sources"]:
        print("   -", src)
    print("=" * 64)
    if total > 1_000_000:
        print("  [OK] Mais de 1 milhao de senhas disponiveis.")
    else:
        print("  [!] Abaixo de 1 milhao - rode: python3 atualizar_wordlists.py")
    print("=" * 64)


if __name__ == "__main__":
    main()
