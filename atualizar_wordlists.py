#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EDY RECON - Atualizador de Wordlists (Windows e Kali Linux)
=============================================================
Baixa e mantém atualizadas as wordlists PUBLICAS de senhas comuns usadas
em testes autorizados (pentest/auditoria de segurança). Total: 25M+ senhas.

Categorias:
  1) Classicas          - RockYou (14M), XatoNet (5.1M e 1M)
  2) Comuns atuais      - NCSC top-100k, Pwdb top-100k, probable-v2, darkweb2017...
  3) Por pais/idioma    - Brasil (pt-br passphrases 2.4M, BRDumps, wordlist-br)
                          + ES / FR / DE / CN / AR / IT / RU / TR / PL / NL / UA
  4) Vazamentos publicos- SecLists Leaked-Databases (SOMENTE senhas, SEM dados
                          pessoais - sem nomes, e-mails ou CPFs)
  5) Credenciais padrao - default-passwords, CIRT, betterdefaultpasslist (SSH,
                          MySQL, Postgres, FTP, Windows, Tomcat, MSSQL, VNC...)

Uso:
  python3 atualizar_wordlists.py          # baixa o que falta e registra no config
  python3 atualizar_wordlists.py --force  # baixa TUDO de novo (atualizacao completa)
  python3 atualizar_wordlists.py --check  # so verifica/registra o que ja existe

Observacao de memoria: listas acima de 512KB sao usadas em STREAMING
(nao ocupam RAM). Veja modules/passwords.py -> PasswordManager.load().
"""
import os
import sys
import json
import urllib.request
import hashlib

from modules import EDY_RECON_VERSION
from modules.safety import atomic_write_json

BASE = os.path.dirname(os.path.abspath(__file__))
WL_DIR = os.path.join(BASE, "data", "wordlists")
CONFIG_PATH = os.path.join(BASE, "data", "config.json")

SL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords"
BRD = "https://raw.githubusercontent.com/BRDumps/wordlists/master"
UPDATER_VERSION = "2.1"

SOURCES = [
    # ------------------------------------------------------------- 1) CLASSICAS
    {"name": "rockyou.txt",
     "url": "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
     "cat": "1-Classicas", "desc": "RockYou 14M (vazamento classico de 2009)"},
    {"name": "xato-net-10-million-passwords.txt",
     "url": f"{SL}/Common-Credentials/xato-net-10-million-passwords.txt",
     "cat": "1-Classicas", "desc": "XatoNet 5.1M unicas (mais comuns primeiro)"},
    {"name": "xato-net-10-million-passwords-1000000.txt",
     "url": f"{SL}/Common-Credentials/xato-net-10-million-passwords-1000000.txt",
     "cat": "1-Classicas", "desc": "XatoNet top-1M (as mais usadas)"},
    # ---------------------------------------------------------- 2) COMUNS ATUAIS
    {"name": "10k-most-common.txt",
     "url": f"{SL}/Common-Credentials/10k-most-common.txt",
     "cat": "2-Comuns-atuais", "desc": "Top-10k comuns"},
    {"name": "100k-most-used-passwords-NCSC.txt",
     "url": f"{SL}/Common-Credentials/100k-most-used-passwords-NCSC.txt",
     "cat": "2-Comuns-atuais", "desc": "Top-100k NCSC (Reino Unido)"},
    {"name": "2025-199_most_used_passwords.txt",
     "url": f"{SL}/Common-Credentials/2025-199_most_used_passwords.txt",
     "cat": "2-Comuns-atuais", "desc": "Top-199 de 2025 (atual)"},
    {"name": "500-worst-passwords.txt",
     "url": f"{SL}/Common-Credentials/500-worst-passwords.txt",
     "cat": "2-Comuns-atuais", "desc": "500 piores senhas"},
    {"name": "Pwdb_top-1000.txt",
     "url": f"{SL}/Common-Credentials/Pwdb_top-1000.txt",
     "cat": "2-Comuns-atuais", "desc": "Pwdb top-1k (base 1 bilhao)"},
    {"name": "Pwdb_top-10000.txt",
     "url": f"{SL}/Common-Credentials/Pwdb_top-10000.txt",
     "cat": "2-Comuns-atuais", "desc": "Pwdb top-10k"},
    {"name": "Pwdb_top-100000.txt",
     "url": f"{SL}/Common-Credentials/Pwdb_top-100000.txt",
     "cat": "2-Comuns-atuais", "desc": "Pwdb top-100k"},
    {"name": "probable-v2_top-12000.txt",
     "url": f"{SL}/Common-Credentials/probable-v2_top-12000.txt",
     "cat": "2-Comuns-atuais", "desc": "Probable-v2 top-12k"},
    {"name": "probable-v2_top-1575.txt",
     "url": f"{SL}/Common-Credentials/probable-v2_top-1575.txt",
     "cat": "2-Comuns-atuais", "desc": "Probable-v2 top-1575"},
    {"name": "probable-v2_top-207.txt",
     "url": f"{SL}/Common-Credentials/probable-v2_top-207.txt",
     "cat": "2-Comuns-atuais", "desc": "Probable-v2 top-207"},
    {"name": "darkweb2017_top-10000.txt",
     "url": f"{SL}/Common-Credentials/darkweb2017_top-10000.txt",
     "cat": "2-Comuns-atuais", "desc": "Darkweb 2017 top-10k"},
    {"name": "xato-net-10-million-passwords-100000.txt",
     "url": f"{SL}/Common-Credentials/xato-net-10-million-passwords-100000.txt",
     "cat": "2-Comuns-atuais", "desc": "XatoNet top-100k"},
    # ---------------------------------------------------- 3) POR PAIS / IDIOMA
    {"name": "pt-br-passphrases.txt",
     "url": "https://github.com/victormagalhaess/pt-br-passphrase-wordlist/releases/download/v2024.1/passphrases.txt",
     "cat": "3-Por-pais", "desc": "BR passphrases 2.4M (frases em portugues)"},
    {"name": "dic-ptbr-utf8.txt",
     "url": f"{BRD}/dic-ptbr-utf8.txt",
     "cat": "3-Por-pais", "desc": "BRDumps dicionario pt-BR"},
    {"name": "dic-ptbr-utf8-2.txt",
     "url": f"{BRD}/dic-ptbr-utf8-2.txt",
     "cat": "3-Por-pais", "desc": "BRDumps dicionario pt-BR v2"},
    {"name": "first-name-pt-br.txt",
     "url": f"{BRD}/first-name-pt-br.txt",
     "cat": "3-Por-pais", "desc": "BRDumps nomes brasileiros"},
    {"name": "brazilian-soccer-teams.txt",
     "url": f"{BRD}/brazilian-soccer-teams.txt",
     "cat": "3-Por-pais", "desc": "BRDumps times de futebol BR"},
    {"name": "biblic-words-pt-br.txt",
     "url": f"{BRD}/biblic-words-pt-br.txt",
     "cat": "3-Por-pais", "desc": "BRDumps palavras biblicas"},
    {"name": "0xc0da-ptbr.txt",
     "url": f"{BRD}/0xc0da-ptbr.txt",
     "cat": "3-Por-pais", "desc": "BRDumps 0xc0da pt-BR"},
    {"name": "wordlist-br_MrP4p3r.txt",
     "url": "https://raw.githubusercontent.com/Mr-P4p3r/wordlist-br/main/MrP4p3r",
     "cat": "3-Por-pais", "desc": "wordlist-br 165k (nomes, cidades, times, numeros)"},
    {"name": "Portugese_Pwdb_common-password-list-top-150.txt",
     "url": f"{SL}/Common-Credentials/Language-Specific/Portugese_Pwdb_common-password-list-top-150.txt",
     "cat": "3-Por-pais", "desc": "Portugues top-150"},
    {"name": "Spanish_Pwdb_common-password-list-top-150.txt",
     "url": f"{SL}/Common-Credentials/Language-Specific/Spanish_Pwdb_common-password-list-top-150.txt",
     "cat": "3-Por-pais", "desc": "Espanhol top-150"},
    {"name": "French-common-password-list-top-20000.txt",
     "url": f"{SL}/Common-Credentials/Language-Specific/French-common-password-list-top-20000.txt",
     "cat": "3-Por-pais", "desc": "Frances top-20k"},
    {"name": "German_common-password-list-top-10000.txt",
     "url": f"{SL}/Common-Credentials/Language-Specific/German_common-password-list-top-10000.txt",
     "cat": "3-Por-pais", "desc": "Alemao top-10k"},
    {"name": "Chinese-common-password-list-top-100000.txt",
     "url": f"{SL}/Common-Credentials/Language-Specific/Chinese-common-password-list-top-100000.txt",
     "cat": "3-Por-pais", "desc": "Chines top-100k"},
    {"name": "Arabic_common-password-list-top-487.txt",
     "url": f"{SL}/Common-Credentials/Language-Specific/Arabic_common-password-list-top-487.txt",
     "cat": "3-Por-pais", "desc": "Arabe top-487"},
    {"name": "Italian_Pwdb_common-password-list-top-150.txt",
     "url": f"{SL}/Common-Credentials/Language-Specific/Italian_Pwdb_common-password-list-top-150.txt",
     "cat": "3-Por-pais", "desc": "Italiano top-150"},
    {"name": "Russian_Pwdb_common-password-list-top-150.txt",
     "url": f"{SL}/Common-Credentials/Language-Specific/Russian_Pwdb_common-password-list-top-150.txt",
     "cat": "3-Por-pais", "desc": "Russo top-150"},
    {"name": "Turkish_Pwdb_common-password-list-top-150.txt",
     "url": f"{SL}/Common-Credentials/Language-Specific/Turkish_Pwdb_common-password-list-top-150.txt",
     "cat": "3-Por-pais", "desc": "Turco top-150"},
    {"name": "Polish-common-password-list.txt",
     "url": f"{SL}/Common-Credentials/Language-Specific/Polish-common-password-list.txt",
     "cat": "3-Por-pais", "desc": "Polones"},
    {"name": "Dutch_common-pasword-list.txt",
     "url": f"{SL}/Common-Credentials/Language-Specific/Dutch_common-pasword-list.txt",
     "cat": "3-Por-pais", "desc": "Holandes (nome original do SecLists)"},
    {"name": "Ukranian_Pwdb_common-password-list-top-150.txt",
     "url": f"{SL}/Common-Credentials/Language-Specific/Ukranian_Pwdb_common-password-list-top-150.txt",
     "cat": "3-Por-pais", "desc": "Ucraniano top-150"},
    # -------------------------------------------- 4) VAZAMENTOS PUBLICOS (SEM PII)
    {"name": "phpbb.txt",
     "url": f"{SL}/Leaked-Databases/phpbb.txt",
     "cat": "4-Vazamentos", "desc": "phpBB (senhas sem PII)"},
    {"name": "myspace.txt",
     "url": f"{SL}/Leaked-Databases/myspace.txt",
     "cat": "4-Vazamentos", "desc": "MySpace (senhas sem PII)"},
    {"name": "tuscl.txt",
     "url": f"{SL}/Leaked-Databases/tuscl.txt",
     "cat": "4-Vazamentos", "desc": "TUSCL (senhas sem PII)"},
    {"name": "000webhost.txt",
     "url": f"{SL}/Leaked-Databases/000webhost.txt",
     "cat": "4-Vazamentos", "desc": "000webhost (senhas sem PII)"},
    {"name": "alleged-gmail-passwords.txt",
     "url": f"{SL}/Leaked-Databases/alleged-gmail-passwords.txt",
     "cat": "4-Vazamentos", "desc": "Gmail alegadas (senhas sem PII)"},
    {"name": "md5decryptor-uk.txt",
     "url": f"{SL}/Leaked-Databases/md5decryptor-uk.txt",
     "cat": "4-Vazamentos", "desc": "md5decryptor UK"},
    {"name": "Ashley-Madison.txt",
     "url": f"{SL}/Leaked-Databases/Ashley-Madison.txt",
     "cat": "4-Vazamentos", "desc": "Ashley Madison (senhas sem PII)"},
    {"name": "honeynet.txt",
     "url": f"{SL}/Leaked-Databases/honeynet.txt",
     "cat": "4-Vazamentos", "desc": "Honeynet"},
    {"name": "muslimMatch.txt",
     "url": f"{SL}/Leaked-Databases/muslimMatch.txt",
     "cat": "4-Vazamentos", "desc": "MuslimMatch"},
    {"name": "fortinet-2021_passwords.txt",
     "url": f"{SL}/Leaked-Databases/fortinet-2021_passwords.txt",
     "cat": "4-Vazamentos", "desc": "Fortinet 2021 (senhas sem PII)"},
    {"name": "rockyou-75.txt",
     "url": f"{SL}/Leaked-Databases/rockyou-75.txt",
     "cat": "4-Vazamentos", "desc": "RockYou filtrada (ate 75 chars)"},
    {"name": "twitter-banned.txt",
     "url": f"{SL}/Leaked-Databases/twitter-banned.txt",
     "cat": "4-Vazamentos", "desc": "Twitter banned"},
    # -------------------------------------------- 5) CREDENCIAIS PADRAO (CHAVES PADRAO)
    {"name": "default-passwords.csv",
     "url": f"{SL}/Default-Credentials/default-passwords.csv",
     "cat": "5-Chaves-padrao", "desc": "Credenciais padrao (CSV)"},
    {"name": "default-passwords.txt",
     "url": f"{SL}/Default-Credentials/default-passwords.txt",
     "cat": "5-Chaves-padrao", "desc": "Credenciais padrao (TXT)"},
    {"name": "cirt-net_collection.txt",
     "url": f"{SL}/Default-Credentials/cirt-net_collection.txt",
     "cat": "5-Chaves-padrao", "desc": "Colecao CIRT default creds"},
    {"name": "ssh-betterdefaultpasslist.txt",
     "url": f"{SL}/Default-Credentials/ssh-betterdefaultpasslist.txt",
     "cat": "5-Chaves-padrao", "desc": "SSH default creds"},
    {"name": "telnet-betterdefaultpasslist.txt",
     "url": f"{SL}/Default-Credentials/telnet-betterdefaultpasslist.txt",
     "cat": "5-Chaves-padrao", "desc": "Telnet default creds"},
    {"name": "mysql-betterdefaultpasslist.txt",
     "url": f"{SL}/Default-Credentials/mysql-betterdefaultpasslist.txt",
     "cat": "5-Chaves-padrao", "desc": "MySQL default creds"},
    {"name": "postgres-betterdefaultpasslist.txt",
     "url": f"{SL}/Default-Credentials/postgres-betterdefaultpasslist.txt",
     "cat": "5-Chaves-padrao", "desc": "PostgreSQL default creds"},
    {"name": "ftp-betterdefaultpasslist.txt",
     "url": f"{SL}/Default-Credentials/ftp-betterdefaultpasslist.txt",
     "cat": "5-Chaves-padrao", "desc": "FTP default creds"},
    {"name": "windows-betterdefaultpasslist.txt",
     "url": f"{SL}/Default-Credentials/windows-betterdefaultpasslist.txt",
     "cat": "5-Chaves-padrao", "desc": "Windows default creds"},
    {"name": "tomcat-betterdefaultpasslist.txt",
     "url": f"{SL}/Default-Credentials/tomcat-betterdefaultpasslist.txt",
     "cat": "5-Chaves-padrao", "desc": "Tomcat default creds"},
    {"name": "mssql-betterdefaultpasslist.txt",
     "url": f"{SL}/Default-Credentials/mssql-betterdefaultpasslist.txt",
     "cat": "5-Chaves-padrao", "desc": "MSSQL default creds"},
    {"name": "vnc-betterdefaultpasslist.txt",
     "url": f"{SL}/Default-Credentials/vnc-betterdefaultpasslist.txt",
     "cat": "5-Chaves-padrao", "desc": "VNC default creds"},
    {"name": "oracle-betterdefaultpasslist.txt",
     "url": f"{SL}/Default-Credentials/oracle-betterdefaultpasslist.txt",
     "cat": "5-Chaves-padrao", "desc": "Oracle DB default creds"},
    {"name": "db2-betterdefaultpasslist.txt",
     "url": f"{SL}/Default-Credentials/db2-betterdefaultpasslist.txt",
     "cat": "5-Chaves-padrao", "desc": "DB2 default creds"},
]


def download(url, dest, force=False):
    if not force and os.path.exists(dest) and os.path.getsize(dest) > 100:
        print(f"  [skip] {os.path.basename(dest)} ja existe "
              f"({os.path.getsize(dest) // 1024} KB)")
        return True
    print(f"  [*] baixando {os.path.basename(dest)} ...")
    partial = dest + ".part"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "EDYRECON-updater/2.0"})
        digest = hashlib.sha256()
        received = 0
        with urllib.request.urlopen(req, timeout=180) as r, open(partial, "wb") as f:
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
                digest.update(chunk)
                received += len(chunk)
            f.flush()
            os.fsync(f.fileno())
            expected_length = r.headers.get("Content-Length")
        size = os.path.getsize(partial)
        if expected_length and received != int(expected_length):
            raise ValueError("download incompleto: tamanho divergente")
        if size < 5:
            raise ValueError(f"download vazio ({size} bytes)")
        # rejeita paginas de erro HTML/JSON em vez de wordlists reais
        try:
            with open(partial, "r", encoding="utf-8", errors="replace") as f:
                head = f.read(256).lstrip().lower()
        except Exception:
            head = ""
        if head.startswith(("<html", "<!doctype html", "{\"error", "{\"message", "404:")):
            raise ValueError("resposta recebida não é uma wordlist")
        expected_hash = next((item.get("sha256") for item in SOURCES if item["name"] == os.path.basename(dest)), None)
        actual_hash = digest.hexdigest()
        if expected_hash and actual_hash.casefold() != expected_hash.casefold():
            raise ValueError("SHA-256 divergente do manifesto")
        os.replace(partial, dest)
        hash_status = "manifesto SHA-256 validado" if expected_hash else "SHA-256 calculado para auditoria"
        print(f"  [OK] {os.path.basename(dest)} ({size // 1024} KB, {hash_status})")
        return True
    except Exception as e:
        try:
            if os.path.exists(partial):
                os.remove(partial)
        except OSError:
            pass
        print(f"  [X] falha: {e}")
        return False


def registrar_no_config():
    """Registra TODAS as wordlists presentes no config.json (caminhos absolutos)."""
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except FileNotFoundError:
        cfg = {}
    except (OSError, ValueError) as e:
        print(f"  [X] config.json inválido; arquivo preservado ({type(e).__name__})")
        return False
    rels = []
    for src in SOURCES:
        full = os.path.join(WL_DIR, src["name"])
        if os.path.isfile(full):
            rels.append(os.path.abspath(full))
    cfg["wordlists"] = rels
    atomic_write_json(CONFIG_PATH, cfg)
    print(f"\n  [OK] config.json registrado com {len(rels)} wordlists "
          f"(caminhos absolutos: portatil para qualquer pasta)")
    return True


def main():
    force = "--force" in sys.argv
    check = "--check" in sys.argv
    print("=" * 64)
    print(f"  EDY RECON v{EDY_RECON_VERSION} - ATUALIZADOR DE WORDLISTS (v{UPDATER_VERSION})")
    print("  Wordlists publicas para testes autorizados")
    print("  Modo:", "FORCA (redownload)" if force else ("CHECK" if check else "normal (so o que falta)"))
    print("=" * 64)
    os.makedirs(WL_DIR, exist_ok=True)

    if check:
        registrar_no_config()
        ok = sum(1 for s in SOURCES if os.path.isfile(os.path.join(WL_DIR, s["name"])))
        print(f"\n[+] {ok}/{len(SOURCES)} wordlists presentes em {WL_DIR}")
        return

    cats = {}
    total_ok = 0
    for src in SOURCES:
        cat = src["cat"]
        cats.setdefault(cat, {"ok": 0, "total": 0})
        cats[cat]["total"] += 1
        print(f"\n[{src['cat']}] {src['desc']}")
        dest = os.path.join(WL_DIR, src["name"])
        if download(src["url"], dest, force):
            cats[cat]["ok"] += 1
            total_ok += 1

    print("\n" + "=" * 64)
    for cat, c in cats.items():
        print(f"  {cat}: {c['ok']}/{c['total']}")
    print(f"  TOTAL: {total_ok}/{len(SOURCES)} wordlists em {WL_DIR}")
    registrar_no_config()
    print("\n[+] Concluido! As wordlists grandes (>512KB) sao usadas em STREAMING")
    print("    (nao ocupam RAM). Rode verificar_wordlists.py para conferir.")
    print("    Para forcar re-download completo:  python3 atualizar_wordlists.py --force")


if __name__ == "__main__":
    main()
