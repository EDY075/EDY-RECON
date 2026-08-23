import html as htmlmod
import os
from datetime import datetime

from modules import EDY_RECON_VERSION
from modules import config as cfgmod
from modules.safety import atomic_write_text, safe_error, sanitize_data


def _fmt_data(dt):
    return dt.strftime("%d/%m/%Y %H:%M:%S")


def _compact(records, limit=8):
    return records[:limit] if records else []


def _escape(value, default="?"):
    if value is None:
        value = default
    return htmlmod.escape(str(value), quote=True)


def _plain(value, default="?"):
    if value is None:
        value = default
    return " ".join(str(value).replace("\r", " ").replace("\n", " ").split())


def _domains(target):
    """Aceita o contrato atual e sessões legadas sem duplicar resultados."""
    current = target.get("dominios")
    return current if current is not None else target.get("domains", [])


def _session_messages(session):
    messages = []
    for key in ("avisos", "warnings", "erros", "errors"):
        value = session.get(key, [])
        if isinstance(value, (str, bytes)):
            value = [value]
        if isinstance(value, (list, tuple)):
            messages.extend(safe_error(item, limit=300) for item in value)
    return list(dict.fromkeys(message for message in messages if message))


def _source_summary(session):
    counts = {}

    def add(name, amount=1):
        name = _plain(name, "Fonte não identificada")
        counts[name] = counts.get(name, 0) + amount

    for target in session.get("targets", []):
        for email in target.get("emails", []):
            if email.get("reputacao"):
                add("EmailRep")
            if email.get("hunter"):
                add("Hunter.io")
            for breach in email.get("vazamentos", []):
                add(breach.get("source") or "Vazamentos")
            for record in email.get("darkweb", []):
                add(record.get("source") or "Dark web/pastes")
        for domain in _domains(target):
            for key, label in (("dns", "DNS"), ("rdap", "RDAP"), ("crtsh", "crt.sh")):
                if domain.get(key):
                    add(label)
    return sorted(counts.items(), key=lambda item: item[0].casefold())


def _ensure_parent(path):
    parent = os.path.dirname(os.path.abspath(os.fspath(path)))
    os.makedirs(parent, exist_ok=True)


def _is_synthetic(session):
    mode = str(session.get("modo", "")).casefold()
    return bool(session.get("synthetic") or session.get("sintetica") or "sint" in mode or "mock" in mode)


def generate_html(session, path=None):
    session = sanitize_data(session)
    if path is None:
        path = os.path.join(cfgmod.REPORTS_DIR,
                            f"relatorio_EDYRECON_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    _ensure_parent(path)
    now = datetime.now()
    session_time = _plain(session.get("data"), "não informado")
    source_summary = _source_summary(session)
    session_messages = _session_messages(session)

    cards = []
    total_emails = 0
    total_breaches = 0
    total_dw = 0
    for t in session.get("targets", []):
        for e in t.get("emails", []):
            total_emails += 1
            total_breaches += len(e.get("vazamentos", []))
            total_dw += len(e.get("darkweb", []))
    cards.append(("<div class='card'><div class='num red'>{}</div><div class='lbl'>Alvos</div></div>").format(len(session.get("targets", []))))
    cards.append(f"<div class='card'><div class='num'>{total_emails}</div><div class='lbl'>Emails</div></div>")
    cards.append(f"<div class='card'><div class='num blue'>{total_breaches}</div><div class='lbl'>Vazamentos</div></div>")
    cards.append(f"<div class='card'><div class='num warn'>{total_dw}</div><div class='lbl'>Hits dark web</div></div>")

    sections = []
    for t in session.get("targets", []):
        first_email = (t.get("emails") or [{}])[0]
        fallback_name = first_email.get("email", "Alvo") if isinstance(first_email, dict) else str(first_email)
        target_name = t.get("name") or fallback_name
        h = f"<h2>🎯 {_escape(target_name)}</h2>"
        blocks = []
        for e in t.get("emails", []):
            email = e.get("email", "?")
            rep = e.get("reputacao")
            rep_html = ""
            if rep:
                cor = "green" if rep.get("suspicious") in (False, None) and rep.get("reputation") in ("good", "high") else "red"
                rep_html = (f"<span class='badge' style='color:var(--{cor});'>{_escape(rep.get('reputation'))}</span> "
                            f"suspeito: {_escape(rep.get('suspicious'))} • referências: {_escape(rep.get('references', 0))}")
            hunter = e.get("hunter")
            hunter_html = ""
            if hunter:
                hunter_html = f"Hunter: <b>{_escape(hunter.get('status'))}</b> (score {_escape(hunter.get('score'))})"
            rows = ""
            for b in e.get("vazamentos", []):
                st = b.get("status", "?")
                rows += ("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td>"
                         "<td><span class='badge' style='color:var(--green);'>{}</span></td></tr>").format(
                    _escape(b.get("site")),
                    _escape(b.get("data")),
                    _escape(b.get("registros")),
                    _escape(b.get("categoria")),
                    _escape(st),
                )
            dw_rows = ""
            for d in e.get("darkweb", []):
                dw_rows += ("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>").format(
                    _escape(d.get("source")),
                    _escape(d.get("data", d.get("data_", "?"))),
                    _escape(d.get("tipo", d.get("titulo", d.get("banco", "?")))),
                    _escape(str(d.get("bucket", d.get("onion", d.get("trecho", "?"))))[:80]),
                )
            erros = "".join(f"<li>{_escape(safe_error(x, limit=300))}</li>" for x in e.get("erros", []))
            blocks.append(f"""
<div class='email'>
<h3>📧 {_escape(email)}</h3>
<div class='meta'>{rep_html} {hunter_html}</div>
<h4>Vazamentos encontrados ({len(e.get('vazamentos', []))})</h4>
<table><thead><tr><th>Serviço</th><th>Data</th><th>Registros</th><th>Categoria</th><th>Status</th></tr></thead>
<tbody>{rows or '<tr><td colspan=5>Nenhum vazamento confirmado para este email.</td></tr>'}</tbody></table>
<h4>Ocorrências dark web / pastes ({len(e.get('darkweb', []))})</h4>
<table><thead><tr><th>Fonte</th><th>Data</th><th>Tipo</th><th>Detalhe</th></tr></thead>
<tbody>{dw_rows or '<tr><td colspan=4>Sem ocorrências.</td></tr>'}</tbody></table>
{f"<div class='erros'><b>Fontes sem resposta:</b><ul>{erros}</ul></div>" if erros else ""}
</div>""")
        variants = t.get("variantes", [])
        var_html = "".join(f"<span class='chip'>{_escape(v)}</span>" for v in variants[:60])
        dom_html = ""
        dom_errors = []
        for d in _domains(t):
            rd = d.get("rdap", {})
            criado = (rd.get("ok") or {}).get("criado", "?")
            crtsh = d.get("crtsh", {})
            subs = len(crtsh.get("ok", [])) if "ok" in crtsh else 0
            dom_html += (f"<tr><td>{_escape(d.get('domain'))}</td><td>{_escape(criado)}</td>"
                         f"<td>{_escape(d.get('dns', {}).get('a'))}</td><td>{subs}</td></tr>")
            dom_errors.extend(safe_error(error, limit=300) for error in d.get("erros", []))
        dom_error_html = "".join(f"<li>{_escape(error)}</li>" for error in dom_errors)
        sections.append(f"""
<div class='target'>{h}
{''.join(blocks)}
<h4>Variantes de nome geradas ({len(variants)})</h4><div class='chips'>{var_html or '—'}</div>
{f"<h4>Domínios</h4><table><thead><tr><th>Domínio</th><th>Registro criado</th><th>IP (A)</th><th>Subdomínios (crt.sh)</th></tr></thead><tbody>{dom_html}</tbody></table>" if dom_html else ""}
{f"<div class='erros'><b>Avisos de domínio:</b><ul>{dom_error_html}</ul></div>" if dom_error_html else ""}
</div>""")

    source_rows = "".join(
        f"<tr><td>{_escape(name)}</td><td>{count}</td></tr>" for name, count in source_summary
    )
    message_items = "".join(f"<li>{_escape(message)}</li>" for message in session_messages)
    provenance = "Sessão exclusivamente sintética/mockada" if _is_synthetic(session) else "Sessão registrada pelo aplicativo"

    html = f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>EDY RECON - Relatório de Varredura</title>
<style>
:root {{ --red:#ff5367; --white:#f7f7fb; --green:#33f0a0; --blue:#69c3ff; --warn:#ffd24a; }}
* {{ box-sizing:border-box; margin:0; padding:0; }}
body {{ background:#0a0a12; color:var(--white); font-family:'Segoe UI',Roboto,Arial,sans-serif; padding:20px; }}
header {{ border-bottom:3px solid var(--red); padding-bottom:14px; margin-bottom:16px; }}
h1 {{ color:var(--red); letter-spacing:2px; }}
h1 span {{ color:var(--white); }}
.sub {{ color:var(--green); font-weight:bold; letter-spacing:1px; }}
.meta {{ color:var(--blue); font-size:12px; margin-top:6px; }}
.summary {{ background:#10101b; border:1px solid #2a2a3a; border-radius:10px; padding:14px; margin:14px 0; }}
.summary ul {{ margin:8px 0 0 20px; }}
.cards {{ display:flex; gap:10px; flex-wrap:wrap; margin:14px 0; }}
.card {{ background:#14141f; border:1px solid #2a2a3a; border-radius:10px; padding:12px 20px; }}
.card .num {{ font-size:24px; font-weight:bold; color:var(--green); }}
.card .num.red {{ color:var(--red); }} .card .num.blue {{ color:var(--blue); }} .card .num.warn {{ color:var(--warn); }}
.card .lbl {{ color:#8a8a9a; font-size:11px; text-transform:uppercase; letter-spacing:1px; }}
.target {{ margin-top:22px; }}
h2 {{ color:var(--red); border-left:4px solid var(--red); padding-left:10px; margin-bottom:12px; }}
.email {{ background:#0e0e18; border:1px solid #1e1e2c; border-radius:10px; padding:14px; margin:12px 0; }}
h3 {{ color:var(--white); }}
h4 {{ color:var(--green); margin:12px 0 6px; font-size:13px; text-transform:uppercase; letter-spacing:1px; }}
table {{ width:100%; border-collapse:collapse; font-size:13px; }}
table {{ display:block; overflow-x:auto; max-width:100%; }}
th {{ text-align:left; color:var(--blue); border-bottom:2px solid var(--blue); padding:8px; }}
td {{ padding:7px 8px; border-bottom:1px solid #1c1c28; }}
tr:nth-child(even) td {{ background:#0c0c14; }}
.badge {{ padding:2px 8px; border-radius:10px; font-size:11px; border:1px solid currentColor; }}
.chips {{ display:flex; flex-wrap:wrap; gap:6px; }}
.chip {{ background:#14141f; border:1px solid #2a2a3a; color:var(--green); border-radius:12px; padding:3px 10px; font-size:12px; font-family:monospace; }}
.erros {{ color:var(--warn); font-size:12px; margin-top:8px; }}
footer {{ margin-top:24px; border-top:1px solid #353547; padding-top:10px; color:#a9a9b7; font-size:11px; }}
@media (max-width:720px) {{
  body {{ padding:10px; }}
  h1 {{ font-size:22px; letter-spacing:1px; }}
  .cards {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); }}
  .card,.email {{ padding:10px; }}
  th,td {{ min-width:120px; }}
  .meta,.chip,td {{ overflow-wrap:anywhere; }}
}}
@media print {{
  :root {{ --red:#8c1020; --white:#111; --green:#075b38; --blue:#075987; --warn:#744f00; }}
  body {{ background:#fff; color:#111; padding:0; font-size:11pt; }}
  .card,.email,.summary {{ background:#fff; border-color:#777; break-inside:avoid; }}
  table {{ display:table; overflow:visible; }}
  thead {{ display:table-header-group; }}
  tr {{ break-inside:avoid; }}
  footer {{ color:#444; }}
}}
</style></head><body>
<header>
<h1>EDY <span>RECON</span> — RELATÓRIO DE VARREDURA</h1>
<div class="sub">OSINT + BRUTE FORCE - SURFACE</div>
<div class="meta">Sessão: {_escape(session_time)} • gerado em {_fmt_data(now)} • operador: {_escape(session.get('operador', 'Analista'))} • modo: {_escape(session.get('modo', 'OSINT'))}</div>
</header>
<div class="cards">{''.join(cards)}</div>
<section class="summary" aria-labelledby="fontes-title">
<h4 id="fontes-title">Resumo das fontes</h4>
<table><thead><tr><th>Fonte</th><th>Registros</th></tr></thead><tbody>{source_rows or '<tr><td colspan="2">Nenhuma fonte registrada.</td></tr>'}</tbody></table>
{f'<h4>Avisos e erros</h4><ul>{message_items}</ul>' if message_items else '<p class="meta">Sem avisos gerais registrados.</p>'}
</section>
{''.join(sections)}
<footer>EDY RECON v{EDY_RECON_VERSION} • {_escape(provenance)} • Uso profissional autorizado. O relatório é autocontido e não carrega dependências externas.</footer>
</body></html>"""
    return atomic_write_text(path, html)


def generate_txt(session, path=None):
    session = sanitize_data(session)
    if path is None:
        path = os.path.join(cfgmod.REPORTS_DIR,
                            f"relatorio_EDYRECON_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    _ensure_parent(path)
    generated_at = datetime.now()
    session_time = _plain(session.get("data"), "não informado")
    L = []
    L.append("=" * 78)
    L.append("EDY RECON - RELATÓRIO DE VARREDURA")
    L.append("OSINT + BRUTE FORCE - SURFACE")
    L.append(f"Data/hora da sessão: {session_time}")
    L.append(f"Gerado em: {_fmt_data(generated_at)}")
    L.append(f"Operador: {_plain(session.get('operador'), 'Analista')}")
    L.append(f"Modo: {_plain(session.get('modo'), 'OSINT')}")
    L.append(f"Proveniência: {'sessão exclusivamente sintética/mockada' if _is_synthetic(session) else 'sessão registrada pelo aplicativo'}")
    L.append("=" * 78)
    L.append("")
    L.append("## RESUMO DAS FONTES")
    sources = _source_summary(session)
    if sources:
        for source, count in sources:
            L.append(f"  - {source}: {count} registro(s)")
    else:
        L.append("  Nenhuma fonte registrada.")
    messages = _session_messages(session)
    L.append("")
    L.append("## AVISOS E ERROS GERAIS")
    if messages:
        L.extend(f"  - {message}" for message in messages)
    else:
        L.append("  Nenhum aviso geral registrado.")
    for t in session.get("targets", []):
        nome = t.get("name") or (t.get("emails", [{}])[0].get("email") if t.get("emails") else "Alvo")
        L.append("")
        L.append(f"## ALVO: {_plain(nome)}")
        for e in t.get("emails", []):
            L.append("")
            L.append(f"  EMAIL: {_plain(e.get('email'))}")
            rep = e.get("reputacao")
            if rep:
                L.append(f"    Reputação (EmailRep): {_plain(rep.get('reputation'))} | suspeito: {_plain(rep.get('suspicious'))} | refs: {_plain(rep.get('references'))}")
            hun = e.get("hunter")
            if hun:
                L.append(f"    Hunter: {_plain(hun.get('status'))} (score {_plain(hun.get('score'))})")
            L.append(f"    Vazamentos encontrados: {len(e.get('vazamentos', []))}")
            for b in e.get("vazamentos", []):
                L.append(f"      - {_plain(b.get('site'))} | data: {_plain(b.get('data'))} | registros: {_plain(b.get('registros'))} | status: {_plain(b.get('status'))}")
            L.append(f"    Ocorrências dark web/pastes: {len(e.get('darkweb', []))}")
            for d in e.get("darkweb", []):
                L.append(f"      - [{_plain(d.get('source'))}] {_plain(d.get('data', d.get('data_', '?')))} | {_plain(d.get('tipo', d.get('titulo', d.get('banco', '?'))))}")
            if e.get("erros"):
                L.append("    Fontes sem resposta (chave/falha): " + "; ".join(safe_error(error, limit=300) for error in e["erros"]))
        vars = t.get("variantes", [])
        L.append("")
        L.append(f"  Variantes de nome geradas: {len(vars)}")
        for i in range(0, len(vars), 8):
            L.append("    " + "  ".join(_plain(value) for value in vars[i:i + 8]))
        correlated = t.get("variantes_correlacionadas", [])
        L.append(f"  Variantes correlacionadas: {len(correlated)}")
        for d in _domains(t):
            rd = (d.get("rdap") or {}).get("ok") or {}
            L.append(f"  Domínio: {_plain(d.get('domain'))} | IP: {_plain(d.get('dns', {}).get('a'))} | criado: {_plain(rd.get('criado'))} | subdomínios crt.sh: {len((d.get('crtsh') or {}).get('ok', [])) if 'ok' in (d.get('crtsh') or {}) else 'n/a'}")
            for error in d.get("erros", []):
                L.append(f"    Aviso de domínio: {safe_error(error, limit=300)}")
    L.append("")
    L.append("=" * 78)
    L.append("FIM DO RELATÓRIO - dados da sessão preservados e sanitizados")
    return atomic_write_text(path, "\n".join(L))
