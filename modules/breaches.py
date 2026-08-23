import html as htmlmod
import json
import os
from datetime import datetime

from modules import EDY_RECON_VERSION
from modules import config as cfgmod
from modules.safety import atomic_write_text


class BreachDB:
    def __init__(self):
        self.records = []
        self.loaded = False
        self.error = None

    def load(self):
        path = os.path.join(cfgmod.DATA_DIR, "breaches.json")
        try:
            with open(path, "r", encoding="utf-8") as f:
                self.records = json.load(f)
            self.loaded = True
        except Exception as e:
            self.error = str(e)
            self.records = []
        return self

    def count(self):
        return len(self.records)

    def stats(self):
        anos = {}
        statuses = {}
        total = 0
        for r in self.records:
            bd = r.get("breach_date", "?")
            ano = str(bd)[:4]
            anos[ano] = anos.get(ano, 0) + 1
            st = r.get("status", "Desconhecida")
            statuses[st] = statuses.get(st, 0) + 1
            try:
                n = int("".join(ch for ch in str(r.get("records", "0")) if ch.isdigit()))
                total += n
            except Exception:
                pass
        return {"anos": anos, "statuses": statuses, "registros_estimados": total}

    def search(self, term):
        term = term.lower()
        out = []
        for r in self.records:
            hay = " ".join(str(v) for v in r.values()).lower()
            if term in hay:
                out.append(r)
        return out

    def by_year(self, y1, y2):
        out = []
        for r in self.records:
            bd = str(r.get("breach_date", "?"))
            ano = int(bd[:4]) if bd[:4].isdigit() else 0
            if y1 <= ano <= y2:
                out.append(r)
        return out

    def match_name(self, name):
        name = (name or "").lower().replace(" ", "")
        for r in self.records:
            site = str(r.get("site", "")).lower().replace(" ", "")
            if name and (name in site or site in name):
                return r
        return None

    def export_txt(self, path=None):
        if path is None:
            path = os.path.join(cfgmod.REPORTS_DIR, f"vazamentos_2007_hoje_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        lines = []
        lines.append("=" * 88)
        lines.append("EDY RECON - BASE DE VAZAMENTOS DE DADOS (2007 - HOJE)")
        lines.append(f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        lines.append(f"Total de incidentes documentados: {len(self.records)}")
        lines.append("Fonte: divulgações públicas (HIBP, imprensa, CERTs, pesquisadores)")
        lines.append("=" * 88)
        lines.append("")
        ano_atual = None
        for r in sorted(self.records, key=lambda x: str(x.get("breach_date", "9999"))):
            ano = str(r.get("breach_date", "?"))[:4]
            if ano != ano_atual:
                ano_atual = ano
                lines.append("")
                lines.append(f"---------- {ano_atual} ----------")
                lines.append("")
            lines.append(f"  SITE           : {r.get('site', '?')}")
            lines.append(f"  Vazamento      : {r.get('breach_date', '?')}")
            lines.append(f"  Criação do site: {r.get('site_created', '?')}")
            lines.append(f"  Registros      : {r.get('records', '?')}")
            lines.append(f"  Categoria      : {r.get('category', '?')}")
            lines.append(f"  Status         : {r.get('status', '?')}")
            lines.append(f"  Últ. atividade : {r.get('last_activity', '?')}")
            lines.append(f"  Dados expostos : {r.get('exposed', '?')}")
            if r.get("notes"):
                lines.append(f"  Observação     : {r.get('notes')}")
            lines.append("-" * 88)
        return atomic_write_text(path, "\n".join(lines))

    def export_html(self, path=None):
        if path is None:
            path = os.path.join(cfgmod.REPORTS_DIR, f"vazamentos_2007_hoje_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        badge = {
            "Ativa": ("#00eb82", "#001a0d"),
            "Encerrada": ("#ff2841", "#1a0205"),
            "Adquirida": ("#ffbe00", "#1a1200"),
            "Desconhecida": ("#888", "#111"),
            "N/A": ("#888", "#111"),
        }
        rows = []
        for r in sorted(self.records, key=lambda x: str(x.get("breach_date", "9999"))):
            st = r.get("status", "?")
            fg, bg = badge.get(st, ("#ccc", "#111"))
            rows.append(
                "<tr>"
                f"<td class='site'>{htmlmod.escape(r.get('site', '?'))}</td>"
                f"<td>{htmlmod.escape(str(r.get('site_created', '?')))}</td>"
                f"<td class='bdate'>{htmlmod.escape(str(r.get('breach_date', '?')))}</td>"
                f"<td>{htmlmod.escape(str(r.get('records', '?')))}</td>"
                f"<td>{htmlmod.escape(str(r.get('category', '?')))}</td>"
                f"<td><span class='badge' style='color:{fg};background:{bg};'>{htmlmod.escape(st)}</span></td>"
                f"<td>{htmlmod.escape(str(r.get('last_activity', '?')))}</td>"
                f"<td class='exposed'>{htmlmod.escape(str(r.get('exposed', '?')))}</td>"
                "</tr>"
            )
        stats = self.stats()
        cards = ""
        for ano in sorted(stats["anos"].keys()):
            cards += f"<div class='card'><div class='num'>{stats['anos'][ano]}</div><div class='lbl'>{ano}</div></div>"
        html = f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EDY RECON - Base de Vazamentos 2007-2026</title>
<style>
:root {{ --red:#ff2841; --white:#fff; --green:#00eb82; --blue:#37afff; }}
* {{ box-sizing:border-box; margin:0; padding:0; }}
body {{ background:#0a0a12; color:var(--white); font-family:'Segoe UI',Roboto,Arial,sans-serif; padding:20px; }}
header {{ border-bottom:3px solid var(--red); padding-bottom:14px; margin-bottom:18px; }}
h1 {{ color:var(--red); letter-spacing:2px; font-size:26px; }}
h1 span {{ color:var(--white); }}
.sub {{ color:var(--green); font-weight:bold; letter-spacing:1px; margin-top:4px; }}
.meta {{ color:var(--blue); font-size:12px; margin-top:6px; }}
.cards {{ display:flex; flex-wrap:wrap; gap:8px; margin:14px 0; }}
.card {{ background:#14141f; border:1px solid #2a2a3a; border-radius:8px; padding:8px 14px; text-align:center; min-width:70px; }}
.card .num {{ color:var(--green); font-size:20px; font-weight:bold; }}
.card .lbl {{ color:#8a8a9a; font-size:11px; }}
.filter {{ margin:14px 0; }}
input[type=text] {{ width:100%; padding:10px 14px; background:#14141f; border:1px solid #2a2a3a; color:var(--white); border-radius:8px; font-size:14px; outline:none; }}
input[type=text]:focus {{ border-color:var(--blue); }}
table {{ width:100%; border-collapse:collapse; margin-top:12px; font-size:13px; }}
th {{ background:linear-gradient(90deg,#1c0a0e,#14141f); color:var(--red); text-transform:uppercase; letter-spacing:1px; font-size:11px; padding:10px 8px; text-align:left; border-bottom:2px solid var(--red); position:sticky; top:0; }}
td {{ padding:9px 8px; border-bottom:1px solid #1c1c28; vertical-align:top; }}
tr:nth-child(even) td {{ background:#0e0e18; }}
tr:hover td {{ background:#16161f; }}
td.site {{ color:var(--white); font-weight:bold; }}
td.bdate {{ color:var(--blue); }}
td.exposed {{ color:#aab; font-size:12px; }}
.badge {{ padding:2px 10px; border-radius:10px; font-size:11px; font-weight:bold; border:1px solid currentColor; }}
footer {{ margin-top:22px; color:#555; font-size:11px; border-top:1px solid #1c1c28; padding-top:10px; }}
</style></head><body>
<header>
  <h1>EDY <span>RECON</span> — BASE DE VAZAMENTOS</h1>
  <div class="sub">OSINT + BRUTE FORCE - SURFACE</div>
  <div class="meta">Gerado em {datetime.now().strftime('%d/%m/%Y %H:%M:%S')} • {len(self.records)} incidentes documentados (2007–hoje) • dados de divulgação pública</div>
</header>
<div class="cards">{cards}</div>
<div class="filter"><input type="text" id="busca" placeholder="🔍 Filtrar por site, ano, categoria, status..." onkeyup="filtro()"></div>
<table id="tbl">
<thead><tr>
<th>Site</th><th>Criação</th><th>Data do vazamento</th><th>Registros</th><th>Categoria</th><th>Status</th><th>Última atividade</th><th>Dados expostos</th>
</tr></thead>
<tbody>
{''.join(rows)}
</tbody></table>
<footer>EDY RECON v{EDY_RECON_VERSION} • Ferramenta de OSINT para profissionais autorizados. Metadados de vazamentos: fontes públicas (Have I Been Pwned, imprensa, CERTs). Não contém credenciais reais.</footer>
<script>
function filtro() {{
  var q = document.getElementById('busca').value.toLowerCase();
  var trs = document.querySelectorAll('#tbl tbody tr');
  trs.forEach(function(tr) {{
    tr.style.display = tr.textContent.toLowerCase().indexOf(q) >= 0 ? '' : 'none';
  }});
}}
</script>
</body></html>"""
        return atomic_write_text(path, html)
