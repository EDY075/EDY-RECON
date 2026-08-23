#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EDY RECON - OSINT + BRUTE FORCE - SURFACE
Ferramenta de reconhecimento OSINT e teste de senhas para uso profissional autorizado.
"""
import json
import os
import pathlib
import subprocess
import sys
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from datetime import datetime

from modules import EDY_RECON_VERSION
from modules import config as cfgmod
from modules import ui
from modules.breaches import BreachDB
from modules.bruteforce import BruteForce
from modules.darkweb import DarkWebScanner
from modules.osint import OSINTScanner, UserTarget
from modules.passwords import PasswordManager
from modules.report import generate_html, generate_txt
from modules.ai import AIClient, AIError, PRESETS
from modules.safety import (
    atomic_write_json,
    is_configured_secret,
    mask_secret,
    safe_error,
    sanitize_data,
    sanitize_text,
)


# --------------------------------------------------------------------------
# Estado global
# --------------------------------------------------------------------------
CFG = None
PWM = None
DB = None


def _open_saved_report(path, theme="NEO"):
    """Abre relatórios por extensão sem executar conteúdo via shell textual."""
    absolute = os.path.abspath(os.fspath(path))
    try:
        if absolute.lower().endswith((".html", ".htm")):
            return bool(webbrowser.open(pathlib.Path(absolute).as_uri()))
        if absolute.lower().endswith(".txt") and os.name == "nt":
            subprocess.Popen(["notepad.exe", absolute], close_fds=True)
            return True
    except (OSError, ValueError) as exc:
        ui.p(f"Não foi possível abrir o relatório: {safe_error(exc)}", theme, "warn")
        return False
    return False


def _generate_selected_reports(session, selection):
    formats = {"1": ("txt",), "2": ("html",), "3": ("txt", "html")}.get(selection)
    if not formats:
        return []
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = os.path.join(cfgmod.REPORTS_DIR, f"relatorio_EDYRECON_{stamp}")
    paths = []
    if "txt" in formats:
        paths.append(generate_txt(session, base + ".txt"))
    if "html" in formats:
        paths.append(generate_html(session, base + ".html"))
    return paths

API_KEY_FIELDS = [
    "hibp", "intelx", "dehashed_email", "dehashed_key", "hunter",
    "virustotal", "emailrep", "shodan", "urlscan", "otx", "ipinfo",
]


def n_api_keys():
    return len([k for k in API_KEY_FIELDS if CFG and CFG.has_key(k)])


def banner_info():
    ui.banner(CFG.theme())
    ui.p("", CFG.theme())
    ui.box("CARREGADO NA MEMÓRIA (RAM)", [
        ui.paint(f"Wordlist embutida      : {PWM.stats()['in_memory']:,} senhas "
                 f"({PWM.stats()['memory_mb']} MB em RAM)", CFG.theme(), "accent"),
        ui.paint(f"Wordlists em streaming : {PWM.stats()['streams']} arquivo(s), "
                 f"{PWM.stats()['stream_lines']:,} linhas", CFG.theme(), "accent"),
        ui.paint(f"Base de vazamentos     : {DB.count()} incidentes (2007–hoje)", CFG.theme(), "info"),
        ui.paint(f"APIs configuradas      : {n_api_keys()} de {len(API_KEY_FIELDS)}",
                 CFG.theme(), "warn"),
        ui.paint(f"IA                     : {_ai_status()}", CFG.theme(), "accent"),
    ], CFG.theme())
    ui.p("", CFG.theme())


def save_session(session):
    os.makedirs(cfgmod.SESSIONS_DIR, exist_ok=True)
    path = os.path.join(cfgmod.SESSIONS_DIR,
                        f"session_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json")
    return atomic_write_json(path, sanitize_data(session))


def hibp_to_vazamentos(breaches, email):
    out = []
    for b in breaches:
        st = "Ativa"
        if b.get("IsRetired"):
            st = "Encerrada"
        m = DB.match_name(b.get("Name", ""))
        if m and m.get("status") in ("Ativa", "Encerrada", "Adquirida"):
            st = m["status"]
        out.append({
            "site": b.get("Title") or b.get("Name", "?"),
            "data": str(b.get("BreachDate", "?")),
            "registros": f"{b.get('PwnCount', 0):,}".replace(",", "."),
            "categoria": ", ".join(b.get("DataClasses", []) or ["?"])[:80],
            "status": st,
        })
    return out


def intelx_to_dark(records):
    out = []
    for r in records:
        out.append({
            "source": "IntelX",
            "data": str(r.get("date", "?")),
            "tipo": r.get("name", "?"),
            "bucket": r.get("bucket", "?"),
        })
    return out


def dehashed_to_dark(entries):
    out = []
    for e in entries:
        out.append({
            "source": "DeHashed",
            "data": "?",
            "tipo": e.get("database_name", "?"),
            "bucket": "campo de senha descartado",
        })
    return out


def pastes_to_dark(pastes):
    out = []
    for p in pastes:
        out.append({
            "source": "HIBP Pastes",
            "data": str(p.get("Date", "?")),
            "tipo": p.get("Source", "?"),
            "bucket": p.get("Title", "?")[:60],
        })
    return out


def collect_emails():
    ui.p("Informe UM OU MAIS emails do alvo (um por linha). Linha vazia finaliza.", CFG.theme(), "info")
    emails = []
    while True:
        e = ui.ask(CFG.theme(), "  email> ", allow_empty=True)
        if e is None:
            break
        if not e:
            break
        if "@" in e:
            emails.append(e.lower())
        else:
            ui.p(f"  ! ignorado (sem @): {e}", CFG.theme(), "warn")
    emails = list(dict.fromkeys(emails))
    if not emails:
        return []
    CFG.cfg["last_emails"] = emails
    CFG.save()
    return emails


def scan_target(name, emails, opts):
    osint = OSINTScanner(CFG)
    dw = DarkWebScanner(CFG)
    target = {"name": name, "emails": [], "variantes": [], "dominios": []}
    variantes = []
    dominios = set()

    for i, email in enumerate(emails, 1):
        ui.status_bar(CFG.theme(), f"Varredura OSINT do email {email} ({i}/{len(emails)})")
        res = osint.scan_email(email, opts)
        entry = {"email": email}
        entry["reputacao"] = res["fonte"].get("emailrep")
        entry["hunter"] = res["fonte"].get("hunter")
        entry["vazamentos"] = hibp_to_vazamentos(res["fonte"].get("hibp", []), email)
        dark = []
        dark += intelx_to_dark(res["fonte"].get("intelx", []))
        dark += dehashed_to_dark(res["fonte"].get("dehashed", []))
        dark += pastes_to_dark(res["fonte"].get("hibp_pastes", []))
        dwres = dw.scan([email], opts, skip_sources={"intelx", "hibp_pastes"})
        for item in dwres:
            if "error" in item:
                err = f"{item['source']}: {item['error']}"
                if err not in res["erros"]:
                    res["erros"].append(err)
                continue
            dark.append({
                "source": item.get("source", "Dark"),
                "data": item.get("data", "?"),
                "tipo": item.get("tipo", item.get("titulo", item.get("banco", "?"))),
                "bucket": item.get("bucket", item.get("onion", item.get("trecho", "?"))),
            })
        entry["darkweb"] = dark
        entry["erros"] = res["erros"]
        target["emails"].append(entry)
        variantes += osint.generate_variants(email)
        for d in email.split("@", 1)[1:]:
            dominios.add(d)
    ui.clear_line()

    variantes = list(dict.fromkeys(variantes))
    variants_limit = opts.get("variants_to_check", CFG.cfg.get("scan", {}).get("variants_to_check", 12))
    try:
        variants_limit = max(0, int(variants_limit))
    except (TypeError, ValueError):
        variants_limit = 12
    variantes = variantes[:variants_limit]
    target["variantes"] = variantes

    # Correlação local: variantes cujo domínio teve vazamento documentado
    correlacionadas = []
    for v in variantes:
        vd = v.split("@", 1)[1]
        for b in DB.records:
            if vd in str(b.get("site", "")).lower() or vd in str(b.get("domain", "")).lower():
                correlacionadas.append(v)
                break
    target["variantes_correlacionadas"] = correlacionadas

    for d in sorted(dominios):
        ui.status_bar(CFG.theme(), f"OSINT de domínio {d}")
        dom = osint.scan_domain(d, opts)
        target["dominios"].append(dom)
    ui.clear_line()

    return target


def print_scan_summary(target):
    t = CFG.theme()
    ui.hr(t, role="border")
    ui.p(f"ALVO: {target.get('name') or target['emails'][0]['email']}", t, "primary", bold=True)
    for e in target["emails"]:
        ui.p(f"  📧 {e['email']}", t, "secondary", bold=True)
        rep = e.get("reputacao")
        if rep and "error" not in rep:
            ui.p(f"     Reputação: {rep.get('reputation')} | suspeito: {rep.get('suspicious')} | refs: {rep.get('references')}", t, "info")
        ui.p(f"     Vazamentos confirmados (HIBP): {len(e['vazamentos'])}", t, "accent" if e["vazamentos"] else "dim")
        for b in e["vazamentos"][:10]:
            ui.p(f"        • {b['site']} — {b['data']} — {b['registros']} registros [{b['status']}]", t, "secondary")
        ui.p(f"     Ocorrências dark web/pastes: {len(e['darkweb'])}", t, "warn" if e["darkweb"] else "dim")
        for d in e["darkweb"][:10]:
            ui.p(f"        • [{d['source']}] {d['tipo']} — {str(d['bucket'])[:50]}", t, "secondary")
        if e.get("erros"):
            ui.p(f"     Sem resposta (chaves/falhas): {len(e['erros'])} fonte(s) — detalhes no relatório", t, "warn")
    ui.p(f"  Variantes de nome geradas: {len(target['variantes'])} "
         f"({len(target.get('variantes_correlacionadas', []))} com domínio em vazamento documentado)", t, "info")
    for d in target.get("dominios", []):
        ip = (d.get("dns") or {}).get("a") or "?"
        criado = ((d.get("rdap") or {}).get("ok") or {}).get("criado", "?")
        subs = len((d.get("crtsh") or {}).get("ok", [])) if "ok" in (d.get("crtsh") or {}) else 0
        ui.p(f"  🌐 {d['domain']} | IP: {ip} | criado: {criado} | subdomínios: {subs}", t, "secondary")


def cmd_scan_completa():
    t = CFG.theme()
    ui.hr(t, role="border")
    ui.p("VARREDURA OSINT COMPLETA", t, "primary", bold=True)
    nome = ui.ask(t, "Nome/identificação do alvo (Enter = 'Alvo 1')> ", default="Alvo 1")
    emails = collect_emails()
    if not emails:
        ui.p("Nenhum email informado. Operação cancelada.", t, "warn")
        return

    opts = CFG.cfg.get("scan", {})
    alvos = []
    for grp in _group(emails, 5):
        alvos.append(scan_target(nome, grp, opts))

    session = {
        "operador": CFG.cfg.get("user_name", "Analista"),
        "modo": "OSINT COMPLETA",
        "data": datetime.now().isoformat(timespec="seconds"),
        "targets": alvos,
    }
    for alvo in alvos:
        print_scan_summary(alvo)

    ui.hr(t, role="border")
    if ui.confirm(t, "Gerar relatório da varredura?", default="s"):
        ui.menu(t, "FORMATO DO RELATÓRIO", [
            ("1", "TXT", "primary"),
            ("2", "HTML", "primary"),
            ("3", "TXT + HTML", "accent"),
            ("0", "Cancelar", "warn"),
        ])
        selection = ui.ask(t, "Formato [3]> ", default="3")
        paths = _generate_selected_reports(session, selection)
        if paths:
            for report_path in paths:
                ui.p(f"  {pathlib.Path(report_path).suffix[1:].upper():4}: {report_path}", t, "accent")
            if ui.confirm(t, "Abrir relatório(s) agora?", default="n"):
                for report_path in paths:
                    _open_saved_report(report_path, t)
        elif selection != "0":
            ui.p("Formato inválido; nenhum relatório foi gerado.", t, "warn")

    sp = save_session(session)
    ui.p(f"  Sessão salva: {sp}", t, "info")

    ui.p("", t)
    if ui.confirm(t, "Varredura concluída. Deseja executar um BRUTE FORCE com os dados da varredura?", default="n"):
        cmd_bruteforce(session=session)


def _group(items, n):
    for i in range(0, len(items), n):
        yield items[i:i + n]


def cmd_verificar_email():
    t = CFG.theme()
    ui.hr(t, role="border")
    ui.p("VERIFICAR EMAIL EM VAZAMENTOS", t, "primary", bold=True)
    emails = collect_emails()
    if not emails:
        return
    osint = OSINTScanner(CFG)
    for email in emails:
        ui.status_bar(CFG.theme(), f"Consultando {email} (HIBP + EmailRep + IntelX + DeHashed)...")
        res = osint.scan_email(email, CFG.cfg.get("scan", {}))
        ui.clear_line()
        ui.hr(t)
        ui.p(f"EMAIL: {email}", t, "primary", bold=True)
        rep = res["fonte"].get("emailrep")
        if rep and "error" not in rep:
            ui.p(f"  EmailRep  : {rep.get('reputation')} | suspeito: {rep.get('suspicious')} | refs: {rep.get('references')}", t, "info")
        vzs = res["fonte"].get("hibp", [])
        if vzs:
            ui.p(f"  VAZADO em {len(vzs)} serviço(s):", t, "accent", bold=True)
            for b in vzs:
                ui.p(f"    • {b.get('Title') or b.get('Name')} | vazamento: {b.get('BreachDate')} | "
                     f"registros: {b.get('PwnCount'):,}".replace(",", "."), t, "secondary")
        else:
            ui.p("  HIBP: nenhum vazamento conhecido para este email (resposta real).", t, "dim")
        if res["fonte"].get("hibp_pastes"):
            ui.p(f"  Pastes (HIBP): {len(res['fonte']['hibp_pastes'])}", t, "warn")
        dh = res["fonte"].get("dehashed", [])
        if dh:
            ui.p(f"  DeHashed: {len(dh)} entrada(s)", t, "warn")
        ix = res["fonte"].get("intelx", [])
        if ix:
            ui.p(f"  IntelX: {len(ix)} resultado(s)", t, "warn")
        for err in res["erros"]:
            ui.p(f"  ! {err}", t, "warn")
    ui.p("", t)


def cmd_darkweb():
    t = CFG.theme()
    ui.hr(t, role="border")
    ui.p("VARREDURA DARK WEB (IntelX darknet, DeHashed, HIBP pastes, Ahmia .onion)", t, "primary", bold=True)
    q = ui.ask(t, "Termo/email para buscar na dark web> ")
    if not q:
        return
    dw = DarkWebScanner(CFG)
    ui.status_bar(t, "Varrendo...")
    res = dw.scan([q], CFG.cfg.get("scan", {}))
    ui.clear_line()
    n_ok = sum(1 for r in res if "error" not in r)
    ui.p(f"Resultados reais: {n_ok} | fontes sem resposta: {len(res) - n_ok}", t, "info")
    for r in res:
        if "error" in r:
            ui.p(f"  ! [{r['source']}] {r['error']}", t, "warn")
            continue
        ui.p(f"  • [{r.get('source')}] {r.get('tipo', r.get('titulo', r.get('banco', '?')))} | "
             f"{r.get('data', '?')} | {str(r.get('bucket', r.get('onion', r.get('trecho', '?'))))[:70]}", t, "secondary")
    ui.p("", t)


def cmd_variantes():
    t = CFG.theme()
    ui.hr(t, role="border")
    ui.p("GERAR VARIANTES DE NOME/EMAIL", t, "primary", bold=True)
    emails = collect_emails()
    if not emails:
        return
    osint = OSINTScanner(CFG)
    todas = []
    for e in emails:
        v = osint.generate_variants(e)
        todas += v
        ui.p(f"\n{e} → {len(v)} variantes:", t, "info", bold=True)
        for i in range(0, len(v), 4):
            ui.p("   " + "   ".join(v[i:i + 4]), t, "secondary")
    todas = list(dict.fromkeys(todas))
    if ui.confirm(t, f"Exportar as {len(todas)} variantes para TXT?", default="n"):
        os.makedirs(cfgmod.REPORTS_DIR, exist_ok=True)
        path = os.path.join(cfgmod.REPORTS_DIR, f"variantes_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(todas))
        ui.p(f"  Salvo: {path}", t, "accent")
    ui.p("", t)


def cmd_breaches():
    t = CFG.theme()
    while True:
        ui.hr(t)
        ui.menu(t, "BASE DE VAZAMENTOS (2007–HOJE)", [
            ("1", "Resumo/estatísticas", "primary"),
            ("2", "Listar por período (anos)", "primary"),
            ("3", "Buscar por nome/site", "primary"),
            ("4", "Exportar lista completa em TXT", "primary"),
            ("5", "Exportar lista completa em HTML (busca integrada)", "primary"),
            ("0", "Voltar", "warn"),
        ])
        op = ui.ask(t, "Opção> ")
        if op == "1":
            st = DB.stats()
            ui.p(f"Total de incidentes: {DB.count()}", t, "accent", bold=True)
            ui.p(f"Registros somados (estimativa): {st['registros_estimados']:,}".replace(",", "."), t, "info")
            ui.p("Por ano:", t, "info")
            for ano in sorted(st["anos"]):
                ui.p(f"   {ano}: {st['anos'][ano]}", t, "secondary")
            ui.p("Por status:", t, "info")
            for s, c in st["statuses"].items():
                ui.p(f"   {s}: {c}", t, "secondary")
        elif op == "2":
            y1 = ui.ask(t, "Ano inicial (ex.: 2012)> ", default="2007")
            y2 = ui.ask(t, "Ano final (ex.: 2026)> ", default="2026")
            try:
                res = DB.by_year(int(y1), int(y2))
            except ValueError:
                ui.p("Ano inválido.", t, "warn")
                continue
            ui.p(f"{len(res)} incidente(s) entre {y1} e {y2}:", t, "info", bold=True)
            for r in res:
                ui.p(f"   • {r.get('site')} | {r.get('breach_date')} | {r.get('records')} | {r.get('status')}", t, "secondary")
        elif op == "3":
            termo = ui.ask(t, "Buscar (site, categoria, status...)> ")
            if not termo:
                continue
            res = DB.search(termo)
            ui.p(f"{len(res)} resultado(s) para '{termo}':", t, "info", bold=True)
            for r in res[:40]:
                ui.p(f"   • {r.get('site')} | {r.get('breach_date')} | {r.get('records')} | {r.get('status')}", t, "secondary")
        elif op == "4":
            p = DB.export_txt()
            ui.p(f"  TXT exportado: {p}", t, "accent")
        elif op == "5":
            p = DB.export_html()
            ui.p(f"  HTML exportado: {p}", t, "accent")
            if ui.confirm(t, "Abrir no navegador?", default="n"):
                import webbrowser
                webbrowser.open("file://" + os.path.abspath(p).replace("\\", "/"))
        elif op == "0" or op is None:
            break


def cmd_pwned():
    t = CFG.theme()
    ui.hr(t, role="border")
    ui.p("VERIFICAR SENHA EM VAZAMENTOS (HIBP Pwned Passwords — k-anonimato)", t, "primary", bold=True)
    ui.p("A senha NÃO é enviada; apenas os 5 primeiros dígitos do SHA-1.", t, "dim")
    pw = ui.ask_secret(t, "Senha a verificar> ")
    if not pw:
        return
    r = PWM.check_pwned_hibp(pw)
    if "error" in r:
        ui.p(f"  Erro: {r['error']}", t, "warn")
    elif r["found"]:
        ui.p(f"  ⚠ SENHA VAZADA — encontrada {r['count']:,}x".replace(",", "."), t, "warn", bold=True)
    else:
        ui.p("  ✅ Não encontrada na base pública (até o momento).", t, "accent", bold=True)
    if PWM.contains(pw):
        ui.p("  Obs.: também presente na wordlist embutida.", t, "dim")
    ui.p("", t)


def cmd_bruteforce(session=None):
    t = CFG.theme()
    ui.hr(t, role="border")
    ui.p("BRUTE FORCE (SSH / FTP / HTTP-FORM)", t, "primary", bold=True)
    alvo = ui.ask(t, "Host/domínio/IP> ", default="")
    if not alvo:
        if session:
            bf = BruteForce(CFG, PWM, CFG.theme())
            alvos = bf.derive_targets(session)
            if not alvos:
                ui.p("Nenhum serviço acessível detectado nos domínios da varredura.", t, "warn")
                return
            ui.p("Serviços acessíveis detectados na varredura:", t, "info")
            for a in alvos:
                ui.p(f"   • {a['domain']} ({a['host']}) portas: {a['ports']}", t, "secondary")
            alvo = alvos[0]["domain"]
        else:
            ui.p("Host não informado.", t, "warn")
            return

    bf = BruteForce(CFG, PWM, CFG.theme())
    ui.status_bar(t, "Verificando portas abertas...")
    ports = bf.probe_ports(alvo)
    ui.clear_line()
    ui.p(f"Portas abertas em {alvo}: {ports or 'nenhuma detectada'}", t, "info")
    if not ports:
        if not ui.confirm(t, "Nenhuma porta aberta detectada. Continuar mesmo assim?", default="n"):
            return

    # usuários
    usuarios = []
    if session:
        for al in session.get("targets", []):
            for e in al.get("emails", []):
                u = e.get("email", "").split("@", 1)[0]
                if u and u not in usuarios:
                    usuarios.append(u)
        nome = (session.get("targets") or [{}])[0].get("name", "")
        if nome and nome not in ("Alvo 1",):
            usuarios.insert(0, nome.lower().replace(" ", ""))
    if usuarios:
        ui.p(f"Usuários derivados da varredura: {', '.join(usuarios)}", t, "accent")
    extra = ui.ask(t, "Usuários extras (separados por vírgula) ou Enter para pular> ", default="")
    if extra:
        usuarios += [u.strip() for u in extra.split(",") if u.strip()]
    if not usuarios:
        ui.p("Informe ao menos um usuário.", t, "warn")
        return
    usuarios = list(dict.fromkeys(usuarios))

    # serviço
    serv = ui.ask(t, "Serviço [ssh/ftp/http]> ", default="ssh")
    if not serv:
        return
    serv = serv.lower()
    porta = None
    if serv in ("ssh", "ftp"):
        porta_s = ui.ask(t, f"Porta (padrão {'22' if serv == 'ssh' else '21'})> ",
                         default="22" if serv == "ssh" else "21")
        try:
            porta = int(porta_s)
        except ValueError:
            ui.p("Porta inválida, usando padrão.", t, "warn")
            porta = 22 if serv == "ssh" else 21

    # senhas
    ui.p("Fonte de senhas:", t, "info")
    ui.menu(t, "SENHAS", [
        ("1", "Wordlist embutida na memória (base.lst)", "primary"),
        ("2", "Variantes geradas dos usuários", "primary"),
        ("3", "Arquivo de wordlist (caminho)", "primary"),
        ("4", "Tudo: embutida + variantes + wordlists configuradas", "primary"),
    ])
    op = ui.ask(t, "Fonte> ", default="1")
    if op is None:
        return
    senhas = []
    if op == "1":
        senhas = list(PWM.iter_memory())
    elif op == "2":
        for u in usuarios:
            senhas += PWM.candidates_for_user(u)
    elif op == "3":
        path = ui.ask(t, "Caminho do arquivo> ")
        if path and os.path.isfile(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                senhas = [l.strip() for l in f if l.strip()]
        else:
            ui.p("Arquivo não encontrado.", t, "warn")
            return
    else:
        for u in usuarios:
            senhas += PWM.candidates_for_user(u)
        senhas += list(PWM.iter_all(limit=CFG.cfg.get("bruteforce", {}).get("max_passwords", 1000000)))
    senhas = list(dict.fromkeys(senhas))
    limite = CFG.cfg.get("bruteforce", {}).get("max_passwords", 1000000)
    if len(senhas) > limite:
        senhas = senhas[:limite]
    if not senhas:
        ui.p("Nenhuma senha disponível.", t, "warn")
        return
    ui.p(f"Alvo: {alvo} | usuários: {len(usuarios)} | senhas: {len(senhas):,} | "
         f"combinações: {len(usuarios) * len(senhas):,}".replace(",", "."), t, "info")

    if not ui.confirm(t, "Iniciar brute force?", default="s"):
        return

    def log_cb(msg, role="secondary"):
        ui.clear_line()
        ui.p(msg, t, role)

    try:
        if serv == "ssh":
            bf.ssh(alvo, porta, usuarios, senhas)
        elif serv == "ftp":
            bf.ftp(alvo, porta, usuarios, senhas)
        elif serv == "http":
            url = ui.ask(t, "URL do formulário (ex.: https://site/login)> ")
            if not url:
                return
            method = ui.ask(t, "Método [POST/GET]> ", default="POST").upper()
            ui.p("Campos do formulário (chave=valor por linha, use {user}/{pass}; vazio termina):", t, "info")
            fields = {}
            while True:
                f = ui.ask(t, "  campo> ", allow_empty=True)
                if not f:
                    break
                if "=" in f:
                    k, v = f.split("=", 1)
                    fields[k.strip()] = v.strip()
            okm = ui.ask(t, "Marcador de sucesso na resposta (ex.: logout)> ", default="")
            bf.http_form(url, method, fields, usuarios, senhas,
                         ok_marker=okm or None)
        else:
            ui.p("Serviço inválido.", t, "warn")
            return
    except KeyboardInterrupt:
        bf._stop = True
        ui.p("\nInterrompido pelo usuário.", t, "warn")

    ui.clear_line()
    ui.hr(t)
    ui.p(f"Tentativas: {bf.attempts:,}".replace(",", "."), t, "info")
    if bf.found:
        for f in bf.found:
            ui.p(f"  ✅ CREDENCIAL ENCONTRADA: {f}", t, "accent", bold=True)
    else:
        ui.p("  Nenhuma credencial encontrada com as listas usadas.", t, "warn")
    ui.p("", t)


def cmd_domain():
    t = CFG.theme()
    ui.hr(t, role="border")
    ui.p("OSINT DE DOMÍNIO (crt.sh / RDAP / DNS / VT / ipinfo / Shodan / urlscan / OTX / Wayback / HackerTarget)", t, "primary", bold=True)
    dom = ui.ask(t, "Domínio (ex.: exemplo.com.br)> ")
    if not dom:
        return
    osint = OSINTScanner(CFG)
    ui.status_bar(t, "Coletando dados do domínio...")
    res = osint.scan_domain(dom, CFG.cfg.get("scan", {}))
    ui.clear_line()
    dns = res.get("dns", {})
    ui.p(f"  DNS A : {dns.get('a') or 'sem registro'}", t, "secondary")
    ui.p(f"  DNS MX: {', '.join(dns.get('mx', [])) or '—'}", t, "secondary")
    rd = res.get("rdap", {})
    if "error" in rd:
        ui.p(f"  RDAP : {rd['error']}", t, "warn")
    elif rd.get("ok"):
        ui.p(f"  Criado : {rd['ok'].get('criado')}", t, "secondary")
        ui.p(f"  Expira : {rd['ok'].get('expira')}", t, "secondary")
        ui.p(f"  Registrar: {rd['ok'].get('registrar')}", t, "secondary")
    cr = res.get("crtsh", {})
    if "error" in cr:
        ui.p(f"  crt.sh: {cr['error']}", t, "warn")
    else:
        subs = cr.get("ok", [])
        ui.p(f"  Subdomínios encontrados (crt.sh): {len(subs)}", t, "accent", bold=True)
        for i in range(0, min(len(subs), 60), 3):
            ui.p("   " + "   ".join(subs[i:i + 3]), t, "secondary")
    vt = res.get("virustotal")
    if vt:
        if "error" in vt:
            ui.p(f"  VirusTotal: {vt['error']}", t, "warn")
        else:
            ui.p(f"  VirusTotal: malicioso={vt.get('malicioso')} suspeito={vt.get('suspeito')} reputação={vt.get('reputacao')}", t, "info")
    geo = res.get("ipinfo")
    if geo:
        if "error" in geo:
            ui.p(f"  ipinfo: {geo['error']}", t, "warn")
        else:
            ui.p(f"  GeoIP : {geo.get('cidade')}, {geo.get('regiao')} ({geo.get('pais')}) | {geo.get('org')}", t, "info")
    sh = res.get("shodan")
    if sh:
        if "error" in sh:
            ui.p(f"  Shodan: {sh['error']}", t, "warn")
        else:
            ui.p(f"  Shodan: portas={', '.join(map(str, sh.get('portas', [])))} | OS: {sh.get('os')} | vulns: {len(sh.get('vulns', []))}", t, "info")
    us = res.get("urlscan")
    if us:
        if "error" in us:
            ui.p(f"  urlscan: {us['error']}", t, "warn")
        else:
            ui.p(f"  urlscan: {us.get('total')} scan(s) públicos | maliciosos: {sum(1 for i in us.get('items', []) if i.get('malicioso'))}", t, "info")
    ox = res.get("otx")
    if ox:
        if "error" in ox:
            ui.p(f"  OTX: {ox['error']}", t, "warn")
        else:
            ui.p(f"  OTX: {ox.get('total')} pulse(s) de ameaça sobre o domínio", t, "info")
    wb = res.get("wayback")
    if wb:
        if "error" in wb:
            ui.p(f"  Wayback: {wb['error']}", t, "warn")
        else:
            ui.p(f"  Wayback Machine: {wb.get('total')} URL(s) arquivada(s) do domínio", t, "info")
            for u in wb.get("urls", [])[:15]:
                ui.p(f"    • {u.get('timestamp')} [{u.get('status')}] {u.get('url')[:90]}", t, "secondary")
    ht = res.get("hackertarget")
    if ht:
        if "error" in ht:
            ui.p(f"  HackerTarget: {ht['error']}", t, "warn")
        else:
            ui.p(f"  HackerTarget: {ht.get('total')} subdomínio(s) descoberto(s)", t, "info")
            for h in ht.get("hosts", [])[:15]:
                ui.p(f"    • {h.get('host')} → {h.get('ip')}", t, "secondary")
    for e in res.get("erros", []):
        ui.p(f"  ! {e}", t, "dim")
    ui.p("", t)


def cmd_relatorios():
    t = CFG.theme()
    ui.hr(t, role="border")
    ui.p("RELATÓRIOS SALVOS", t, "primary", bold=True)
    arquivos = []
    for d in (cfgmod.REPORTS_DIR, cfgmod.SESSIONS_DIR):
        if os.path.isdir(d):
            arquivos += [
                os.path.join(d, f) for f in sorted(os.listdir(d))
                if os.path.isfile(os.path.join(d, f))
                and pathlib.Path(f).suffix.casefold() in {".txt", ".html", ".htm", ".json"}
            ]
    if not arquivos:
        ui.p("Nenhum relatório/sessão salvo ainda.", t, "warn")
        return
    for i, a in enumerate(arquivos, 1):
        ui.p(f"  [{i}] {a} ({os.path.getsize(a):,} bytes)".replace(",", "."), t, "secondary")
    op = ui.ask(t, "Número para abrir (Enter = voltar)> ")
    if op and op.isdigit():
        idx = int(op) - 1
        if 0 <= idx < len(arquivos):
            path = arquivos[idx]
            if path.lower().endswith((".txt", ".html", ".htm")):
                if not _open_saved_report(path, t):
                    ui.p("O sistema não confirmou a abertura do relatório.", t, "warn")
            else:
                try:
                    with open(path, "r", encoding="utf-8", errors="strict") as f:
                        conteudo = f.read(4000)
                    print(sanitize_text(conteudo, limit=4000))
                except (OSError, UnicodeError) as exc:
                    ui.p(f"Não foi possível ler a sessão: {safe_error(exc)}", t, "warn")
    ui.p("", t)


def cmd_config():
    while True:
        t = CFG.theme()
        ui.hr(t)
        ui.menu(t, "CONFIGURAÇÕES", [
            ("1", f"Chaves de API ({_n_keys()} configuradas)", "primary"),
            ("2", f"Tema atual: {CFG.theme()}", "primary"),
            ("3", "Wordlists (caminhos adicionais)", "primary"),
            ("4", "Parâmetros do brute force", "primary"),
            ("5", f"Nome do operador: {CFG.cfg.get('user_name')}", "primary"),
            ("6", f"IA — provider: {CFG.ai().get('provider', 'skynet')}", "accent"),
            ("0", "Voltar", "warn"),
        ])
        op = ui.ask(t, "Opção> ")
        if op == "1":
            _menu_apis()
        elif op == "2":
            cmd_tema(show=True)
        elif op == "3":
            wl = CFG.cfg.get("wordlists", [])
            ui.p("Wordlists configuradas:", t, "info")
            for w in wl:
                ui.p(f"   • {w}", t, "secondary")
            if not wl:
                ui.p("   (nenhuma além da embutida)", t, "dim")
            novo = ui.ask(t, "Adicionar caminho (Enter = não)> ", default="")
            if novo:
                wl.append(os.path.expanduser(novo))
                CFG.cfg["wordlists"] = wl
                CFG.save()
                ui.p("Wordlist adicionada. Recarregue as senhas (menu inicial: carregar wordlists).", t, "accent")
            if wl and ui.confirm(t, "Limpar lista?", default="n"):
                CFG.cfg["wordlists"] = []
                CFG.save()
        elif op == "4":
            bf = CFG.cfg.get("bruteforce", {})
            for k in ("threads", "delay", "timeout", "max_passwords"):
                cur = bf.get(k)
                v = ui.ask(t, f"{k} (atual: {cur})> ", default=str(cur))
                try:
                    if k in ("delay", "timeout"):
                        bf[k] = float(v)
                    else:
                        bf[k] = int(v)
                except ValueError:
                    ui.p("Valor inválido.", t, "warn")
            CFG.save()
        elif op == "5":
            nome = ui.ask(t, "Nome do operador> ", default=CFG.cfg.get("user_name"))
            if nome:
                CFG.cfg["user_name"] = nome
                CFG.save()
        elif op == "6":
            _menu_ia()
        elif op == "0" or op is None:
            break


def _n_keys():
    return len([k for k in API_KEY_FIELDS if CFG.has_key(k)])


def _menu_apis():
    t = CFG.theme()
    apis = [
        ("hibp", "Have I Been Pwned (hibp-api-key) — vazamentos + pastes"),
        ("intelx", "IntelligenceX (intelx.io) — pesquisa + darknet"),
        ("dehashed_email", "DeHashed — email de login"),
        ("dehashed_key", "DeHashed — chave de API"),
        ("hunter", "Hunter.io — verificação de email"),
        ("virustotal", "VirusTotal — reputação de domínios"),
        ("emailrep", "EmailRep.io — reputação de email (opcional)"),
        ("shodan", "Shodan — portas/serviços do host"),
        ("urlscan", "urlscan.io — histórico de scans do domínio"),
        ("otx", "AlienVault OTX — pulses de ameaça"),
        ("ipinfo", "ipinfo.io — GeoIP/ASN (token opcional)"),
    ]
    while True:
        ui.menu(t, "CHAVES DE API", [(str(i), f"{nome} — {'✅ configurada' if CFG.has_key(nome) else '❌ vazia'} ({desc})", "primary")
                                     for i, (nome, desc) in enumerate(apis, 1)] + [("0", "Voltar", "warn")])
        op = ui.ask(t, "Opção> ")
        if op and op.isdigit():
            i = int(op) - 1
            if 0 <= i < len(apis):
                nome, desc = apis[i]
                cur = mask_secret(CFG.key(nome))
                val = ui.ask_secret(t, f"{nome} (atual: {cur}) — nova chave (Enter = manter, 'x' = apagar)> ", default=CFG.key(nome))
                if val == "x":
                    CFG.cfg["api_keys"][nome] = ""
                    CFG.save()
                    ui.p("Chave apagada.", t, "warn")
                elif val:
                    CFG.cfg["api_keys"][nome] = val
                    CFG.save()
                    ui.p("Chave salva.", t, "accent")
        elif op == "0" or op is None:
            break


def _ai_provider_label():
    ai = CFG.ai()
    p = ai.get("provider", "skynet")
    if p in PRESETS:
        return PRESETS[p]["label"]
    return f"{p} (custom)"


def _ai_status():
    ai = CFG.ai()
    p = ai.get("provider", "skynet")
    if p == "skynet" and ai.get("email"):
        return "Skynet (conta free pronta)"
    if p != "skynet" and (ai.get("base_url") or is_configured_secret(ai.get("api_key"))):
        return f"{p} configurado"
    return "não configurada"


def _ia_enviar(t, texto, pergunta):
    ai = AIClient(CFG)
    ui.status_bar(t, "IA pensando... (pode levar alguns segundos)")
    try:
        resp = ai.analyze(texto, pergunta)
    except AIError as e:
        ui.clear_line()
        ui.p(f"  ✗ IA indisponível: {e}", t, "warn")
        return
    ui.clear_line()
    ui.hr(t)
    ui.p("RESPOSTA DA IA:", t, "accent", bold=True)
    for i in range(0, len(resp), 180):
        ui.p(resp[i:i + 180], t, "secondary")
    ui.p("", t)


def _ultimo_relatorio():
    candidatos = []
    for d in (cfgmod.REPORTS_DIR, cfgmod.SESSIONS_DIR):
        if os.path.isdir(d):
            for f in os.listdir(d):
                p = os.path.join(d, f)
                if os.path.isfile(p):
                    candidatos.append(p)
    if not candidatos:
        return None
    return max(candidatos, key=os.path.getmtime)


def _ia_analisar_ultimo():
    t = CFG.theme()
    p = _ultimo_relatorio()
    if not p:
        ui.p("Nenhum relatório/sessão salvo ainda. Execute uma varredura antes (opção 1).", t, "warn")
        return
    ui.p(f"Arquivo: {p}", t, "info")
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            conteudo = sanitize_text(f.read(12000), limit=12000)
    except OSError as e:
        ui.p(f"  ! Não foi possível ler: {safe_error(e)}", t, "warn")
        return
    _ia_enviar(t, conteudo, "Analise o relatório de varredura abaixo e resuma riscos, dados expostos e recomendações.")


def _ia_analisar_dominio():
    t = CFG.theme()
    dom = ui.ask(t, "Domínio para análise> ")
    if not dom:
        return
    osint = OSINTScanner(CFG)
    ui.status_bar(t, "Coletando dados rápidos (DNS / crt.sh / Wayback / HackerTarget)...")
    try:
        dns = osint.dns_basic(dom)
        crtsh = osint.crtsh_subdomains(dom, limit=100)
        wb = osint.wayback_urls(dom, limit=50)
        ht = osint.hackertarget_hostsearch(dom)
    except Exception as e:
        ui.clear_line()
        ui.p(f"  ! Falha ao coletar dados: {safe_error(e)}", t, "warn")
        return
    ui.clear_line()
    resumo = {
        "dominio": dom,
        "dns_a": (dns or {}).get("a"),
        "dns_mx": (dns or {}).get("mx", []),
        "subdominios_crtsh": crtsh.get("ok", []) if isinstance(crtsh, dict) else [],
        "wayback_urls": wb.get("urls", []) if isinstance(wb, dict) else [],
        "hackertarget": ht.get("hosts", []) if isinstance(ht, dict) else [],
    }
    texto = json.dumps(resumo, ensure_ascii=False, indent=2)
    _ia_enviar(t, texto, "Analise o domínio abaixo como analista sênior de OSINT: superfície de ataque, subdomínios interessantes, endpoints expostos e recomendações.")


def _ia_chat_livre():
    t = CFG.theme()
    ui.p("Chat livre com a IA. Linha vazia volta ao menu.", t, "info")
    ai = AIClient(CFG)
    while True:
        msg = ui.ask(t, "  você> ", allow_empty=True)
        if not msg:
            break
        ui.status_bar(t, "IA pensando...")
        try:
            resp = ai.chat(msg)
        except AIError as e:
            ui.clear_line()
            ui.p(f"  ✗ IA indisponível: {e}", t, "warn")
            continue
        ui.clear_line()
        ui.p(f"  IA> {resp}", t, "accent")
    ui.p("", t)


def cmd_ia():
    t = CFG.theme()
    ui.hr(t, role="border")
    ui.p(f"ANÁLISE COM IA — provider: {_ai_provider_label()}", t, "primary", bold=True)
    st = AIClient(CFG).check()
    if not st.get("ok"):
        ui.p(f"  ! {st.get('detail')}", t, "warn")
        ui.p("  Você pode tentar mesmo assim (a IA pode estar instável) ou configurar em '4 — Config IA'.", t, "dim")
    while True:
        ui.menu(t, "ANÁLISE COM IA", [
            ("1", "Analisar o último relatório/sessão salvo", "primary"),
            ("2", "Análise rápida de um domínio (DNS + crt.sh + Wayback + HackerTarget)", "primary"),
            ("3", "Chat livre com a IA", "primary"),
            ("4", "Configuração da IA (provider, credenciais)", "primary"),
            ("0", "Voltar", "warn"),
        ])
        op = ui.ask(t, "Opção> ")
        if op == "1":
            _ia_analisar_ultimo()
        elif op == "2":
            _ia_analisar_dominio()
        elif op == "3":
            _ia_chat_livre()
        elif op == "4":
            _menu_ia()
        elif op == "0" or op is None:
            break


def _menu_ia_provider():
    t = CFG.theme()
    ui.menu(t, "PROVIDER DE IA", [
        (str(i), f"{k} — {PRESETS[k]['label']}", "primary")
        for i, k in enumerate(PRESETS, 1)
    ] + [("0", "Voltar", "warn")])
    op = ui.ask(t, "Opção> ")
    if op and op.isdigit():
        i = int(op) - 1
        keys = list(PRESETS)
        if 0 <= i < len(keys):
            try:
                AIClient(CFG).set_provider(keys[i])
                ui.p(f"Provider alterado para {keys[i]}.", t, "accent")
            except AIError as e:
                ui.p(f"  ! {e}", t, "warn")


def _menu_ia():
    t = CFG.theme()
    while True:
        ai = CFG.ai()
        prov = ai.get("provider", "skynet")
        ui.menu(t, "CONFIGURAÇÃO DA IA", [
            ("1", f"Provider: {prov}", "primary"),
            ("2", f"Email (Skynet): {'configurado' if ai.get('email') else '(vazio)'}", "primary"),
            ("3", f"Senha (Skynet): {'****' if ai.get('password') else '(vazio)'}", "primary"),
            ("4", f"base_url: {ai.get('base_url') or '(padrão do provider)'}", "primary"),
            ("5", f"api_key: {mask_secret(ai.get('api_key'))}", "primary"),
            ("6", f"model: {ai.get('model') or '(padrão do provider)'}", "primary"),
            ("7", "Testar status/conexão do provider", "primary"),
            ("0", "Voltar", "warn"),
        ])
        op = ui.ask(t, "Opção> ")
        if op == "1":
            _menu_ia_provider()
        elif op == "2":
            v = ui.ask_secret(t, "Email (entrada protegida; Enter = manter)> ", default=ai.get("email"))
            if v:
                ai["email"] = v.strip()
                CFG.save()
        elif op == "3":
            v = ui.ask_secret(t, "Senha (Enter = manter)> ", default=ai.get("password"))
            if v:
                ai["password"] = v
                CFG.save()
        elif op == "4":
            v = ui.ask(t, "base_url (Enter = padrão do provider)> ", default=ai.get("base_url"))
            ai["base_url"] = v.strip()
            CFG.save()
        elif op == "5":
            v = ui.ask_secret(t, "api_key (Enter = manter)> ", default=ai.get("api_key"))
            if v is not None:
                ai["api_key"] = v.strip()
                CFG.save()
        elif op == "6":
            v = ui.ask(t, "model (Enter = padrão)> ", default=ai.get("model"))
            ai["model"] = v.strip()
            CFG.save()
        elif op == "7":
            st = AIClient(CFG).check()
            if st.get("ok"):
                ui.p(f"  ✅ OK — {st.get('detail')}", t, "accent")
            else:
                ui.p(f"  ✗ {st.get('detail')}", t, "warn")
        elif op == "0" or op is None:
            break


def cmd_tema(show=False):
    t = CFG.theme()
    ui.p("Temas disponíveis:", t, "info")
    for i, nome in enumerate(ui.THEME_ORDER, 1):
        sel = " ◀" if nome == CFG.theme() else ""
        ui.p(f"  [{i}] {ui.THEMES[nome]['name']}{sel}", t, "accent" if nome == CFG.theme() else "secondary")
    op = ui.ask(t, f"Escolha o tema (1-{len(ui.THEME_ORDER)}, Enter = manter)> ", default="")
    if op and op.isdigit():
        i = int(op) - 1
        if 0 <= i < len(ui.THEME_ORDER):
            CFG.set_theme(ui.THEME_ORDER[i])
            t = CFG.theme()
            ui.p(f"Tema alterado para {ui.THEME_ORDER[i]}.", t, "accent")
    if show:
        ui.p("", t)


def cmd_sobre():
    t = CFG.theme()
    ui.hr(t)
    ui.box(f"EDY RECON v{EDY_RECON_VERSION} — OSINT + BRUTE FORCE - SURFACE", [
        ui.paint("Ferramenta de reconhecimento OSINT e teste de credenciais", t, "secondary"),
        ui.paint("para profissionais de segurança com autorização formal.", t, "secondary"),
        "",
        ui.paint("FONTES PÚBLICAS (sem chave): crt.sh, RDAP, DNS, Ahmia, Wayback Machine, HackerTarget", t, "info"),
        ui.paint("APIs (chaves configuráveis no menu 10 — CONFIGURAÇÕES):", t, "info"),
        ui.paint("  • Have I Been Pwned (vazamentos + pastes)", t, "secondary"),
        ui.paint("  • IntelligenceX (pesquisa + darknet)", t, "secondary"),
        ui.paint("  • DeHashed (buscas em vazamentos)", t, "secondary"),
        ui.paint("  • Hunter.io (verificação de email)", t, "secondary"),
        ui.paint("  • VirusTotal (reputação de domínios)", t, "secondary"),
        ui.paint("  • EmailRep.io (reputação de email)", t, "secondary"),
        ui.paint("  • Shodan (portas/serviços do host)", t, "secondary"),
        ui.paint("  • urlscan.io (histórico de scans do domínio)", t, "secondary"),
        ui.paint("  • AlienVault OTX (pulses de ameaça)", t, "secondary"),
        ui.paint("  • ipinfo.io (GeoIP/ASN do host)", t, "secondary"),
        "",
        ui.paint("IA (menu 12): Skynet Chat free + providers OpenAI-compatíveis (OpenRouter,", t, "accent"),
        ui.paint("Hack Club AI, Ollama local). Análise de relatórios e chat com a IA.", t, "accent"),
        "",
        ui.paint("RESPOSTAS: apenas dados REAIS retornados pelas fontes no momento da", t, "warn"),
        ui.paint("varredura são exibidos. Sem chave ou falha de rede é informado.", t, "warn"),
        "",
        ui.paint("PLATAFORMAS SUPORTADAS:", t, "accent", bold=True),
        ui.paint("  • Windows:  clique em instalar_windows.bat (instala tudo sozinho)", t, "secondary"),
        ui.paint("  • Kali    :  sudo bash kali_install.sh   -> rodar: edyrecon", t, "secondary"),
        ui.paint("  • Kali remoto:  bash sync_to_kali.sh (sincroniza o projeto todo via SSH)", t, "secondary"),
        "",
        ui.paint("Base de vazamentos (menu 5): metadados de divulgação pública 2007–hoje.", t, "dim"),
        ui.paint("Não contém credenciais. Senhas reais vêm das wordlists e da API HIBP.", t, "dim"),
    ], t)
    ui.p("", t)


def main():
    global CFG, PWM, DB
    ui.enable_console()
    CFG = cfgmod.ConfigManager().load()
    PWM = PasswordManager().load(CFG.cfg.get("wordlists", []))
    DB = BreachDB().load()

    if not DB.loaded:
        ui.p(f"AVISO: base de vazamentos não carregou: {DB.error}", "NEO", "warn")

    banner_info()

    while True:
        try:
            t = CFG.theme()
            ui.hr(t)
            ui.menu(t, "MENU PRINCIPAL", [
                ("1", "VARREDURA OSINT COMPLETA (email + vazamentos + dark web + relatório)", "primary"),
                ("2", "VERIFICAR EMAIL EM VAZAMENTOS", "primary"),
                ("3", "VARREDURA DARK WEB", "primary"),
                ("4", "GERAR VARIANTES DE NOME/EMAIL", "primary"),
                ("5", "BASE DE VAZAMENTOS 2007–HOJE (ver/exportar TXT|HTML)", "primary"),
                ("6", "VERIFICAR SENHA VAZADA (HIBP)", "primary"),
                ("7", "BRUTE FORCE (SSH/FTP/HTTP-FORM)", "primary"),
                ("8", "OSINT DE DOMÍNIO (crt.sh/RDAP/DNS/VT/ipinfo/Shodan/urlscan/OTX)", "primary"),
                ("9", "RELATÓRIOS SALVOS", "primary"),
                ("10", "CONFIGURAÇÕES (APIs/Tema/Wordlists)", "primary"),
                ("11", "SOBRE / AJUDA", "primary"),
                ("12", "ANÁLISE COM IA", "accent"),
                ("T", "TROCAR TEMA", "accent"),
                ("0", "SAIR", "warn"),
            ], footer="EDY RECON • OSINT + BRUTE FORCE - SURFACE")
            op = ui.ask(t, "Opção> ")
            if op is None:
                break
            op = op.upper()
            if op == "1":
                cmd_scan_completa()
            elif op == "2":
                cmd_verificar_email()
            elif op == "3":
                cmd_darkweb()
            elif op == "4":
                cmd_variantes()
            elif op == "5":
                cmd_breaches()
            elif op == "6":
                cmd_pwned()
            elif op == "7":
                cmd_bruteforce()
            elif op == "8":
                cmd_domain()
            elif op == "9":
                cmd_relatorios()
            elif op == "10":
                cmd_config()
            elif op == "11":
                cmd_sobre()
            elif op == "12":
                cmd_ia()
            elif op == "T":
                cmd_tema()
            elif op == "0":
                ui.p("Encerrando EDY RECON. Até a próxima!", t, "accent", bold=True)
                break
            else:
                ui.p("Opção inválida.", t, "warn")
        except KeyboardInterrupt:
            ui.p("\nInterrompido (Ctrl+C).", CFG.theme(), "warn")
        except Exception as exc:
            ui.clear_line()
            ui.p(f"A operação não pôde ser concluída: {safe_error(exc)}", CFG.theme(), "warn")
            ui.p("Você pode tentar novamente ou voltar com 0.", CFG.theme(), "dim")


if __name__ == "__main__":
    main()
