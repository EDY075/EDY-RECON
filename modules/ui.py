import os
import re
import sys
import shutil
import getpass
import unicodedata

from modules import EDY_RECON_VERSION
from modules.safety import mask_secret

try:
    import colorama
    colorama.just_fix_windows_console()
except Exception:
    pass

NO_COLOR = "NO_COLOR" in os.environ
ASCII_MODE = os.environ.get("EDYRECON_ASCII", "").strip().lower() in ("1", "true", "yes", "on")

RESET = "" if NO_COLOR else "\x1b[0m"
BOLD = "" if NO_COLOR else "\x1b[1m"
DIM = "" if NO_COLOR else "\x1b[2m"
REVERSE = "" if NO_COLOR else "\x1b[7m"

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _rgb(r, g, b):
    if NO_COLOR:
        return ""
    return f"\x1b[38;2;{r};{g};{b}m"


def _bg(r, g, b):
    if NO_COLOR:
        return ""
    return f"\x1b[48;2;{r};{g};{b}m"


def _display_text(value):
    text = str(value)
    if ASCII_MODE:
        for source, replacement in {
            "–": "-", "—": "-", "•": "*", "…": "...",
            "⚡": "*", "🎯": "[ALVO]", "📧": "[EMAIL]", "🌐": "[WEB]",
            "✅": "[OK]", "⚠": "[!]", "❌": "[X]", "✗": "[X]", "◀": "<",
        }.items():
            text = text.replace(source, replacement)
        text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    return text


def _vis(s):
    """Comprimento visível (sem códigos ANSI)."""
    return _ANSI_RE.sub("", str(s))


def _center(text, inner):
    """Centraliza texto em largura 'inner' com preenchimento de espaços."""
    text = _clip(text, inner)
    lp = max(0, (inner - len(text)) // 2)
    rp = max(0, inner - len(text) - lp)
    return " " * lp + text + " " * rp


def _clip(text, limit):
    """Evita overflow em terminais estreitos, inclusive com texto colorido."""
    text = _display_text(text)
    visible = _vis(text)
    if len(visible) <= max(0, limit):
        return text
    suffix = "..." if ASCII_MODE else "…"
    plain = _display_text(visible)
    return plain[: max(0, limit - len(suffix))] + suffix


THEMES = {
    "CYBER": {
        "name": "CYBER (Neon Ciano/Magenta/Verde)",
        "primary": _rgb(0, 255, 234),
        "secondary": _rgb(230, 240, 255),
        "accent": _rgb(0, 255, 130),
        "info": _rgb(80, 180, 255),
        "warn": _rgb(255, 200, 0),
        "dim": _rgb(120, 140, 160),
        "bg": _bg(3, 5, 12),
        "border": _rgb(255, 0, 170),
        "title": _rgb(255, 255, 255),
    },
    "NEO": {
        "name": "NEO (Vermelho/Branco/Verde/Azul)",
        "primary": _rgb(255, 40, 65),
        "secondary": _rgb(255, 255, 255),
        "accent": _rgb(0, 235, 130),
        "info": _rgb(55, 175, 255),
        "warn": _rgb(255, 190, 0),
        "dim": _rgb(140, 150, 165),
        "bg": _bg(10, 10, 18),
        "border": _rgb(255, 40, 65),
        "title": _rgb(255, 255, 255),
    },
    "DARK": {
        "name": "DARK (Verde/Preto clássico)",
        "primary": _rgb(0, 255, 120),
        "secondary": _rgb(200, 255, 220),
        "accent": _rgb(0, 255, 160),
        "info": _rgb(80, 220, 255),
        "warn": _rgb(255, 220, 60),
        "dim": _rgb(90, 140, 110),
        "bg": _bg(0, 0, 0),
        "border": _rgb(0, 255, 120),
        "title": _rgb(255, 255, 255),
    },
    "BLUE": {
        "name": "AZUL (Azul/Branco)",
        "primary": _rgb(0, 150, 255),
        "secondary": _rgb(235, 245, 255),
        "accent": _rgb(0, 230, 210),
        "info": _rgb(120, 200, 255),
        "warn": _rgb(255, 200, 60),
        "dim": _rgb(120, 145, 170),
        "bg": _bg(6, 12, 24),
        "border": _rgb(0, 150, 255),
        "title": _rgb(255, 255, 255),
    },
}

THEME_ORDER = ["CYBER", "NEO", "DARK", "BLUE"]

BANNER_LINES = ["EDY RECON"] if ASCII_MODE else [
    "███████╗██████╗ ██╗   ██╗",
    "██╔════╝██╔══██╗╚██╗ ██╔╝",
    "█████╗  ██║  ██║ ╚████╔╝ ",
    "██╔══╝  ██║  ██║  ╚██╔╝  ",
    "███████╗██████╔╝   ██║   ",
    "╚══════╝╚═════╝    ╚═╝   ",
    "██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗",
    "██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║",
    "██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║",
    "██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║",
    "██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║",
    "╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝",
]


def enable_console():
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def paint(text, theme="NEO", role="secondary", bold=False):
    t = THEMES.get(theme, THEMES["NEO"])
    prefix = BOLD if bold else ""
    return f"{prefix}{t.get(role, t['secondary'])}{_display_text(text)}{RESET}"


def p(text="", theme="NEO", role="secondary", end="\n", bold=False):
    print(paint(str(text), theme, role, bold), end=end)


def width():
    try:
        return shutil.get_terminal_size((80, 24)).columns
    except Exception:
        return 80


def hr(theme="NEO", ch="═", role="border"):
    t = THEMES.get(theme, THEMES["NEO"])
    w = max(20, width())
    if ASCII_MODE:
        ch = "-"
    print(f"{t[role]}{ch * w}{RESET}")


def box(title, lines, theme="NEO"):
    t = THEMES.get(theme, THEMES["NEO"])
    w = max(20, min(width() - 2, 118))
    inner = w - 2
    tlc, trc, blc, brc, vert, horiz, cross_l, cross_r = (
        ("+", "+", "+", "+", "|", "-", "+", "+") if ASCII_MODE
        else ("╔", "╗", "╚", "╝", "║", "═", "╠", "╣")
    )
    print(f"{t['border']}{tlc}{horiz * inner}{trc}{RESET}")
    if title:
        tl = f"[ {title} ]"
        print(f"{t['border']}{vert}{RESET}{BOLD}{t['primary']}{_center(_display_text(tl), inner)}{RESET}{t['border']}{vert}{RESET}")
        print(f"{t['border']}{cross_l}{horiz * inner}{cross_r}{RESET}")
    for line in lines:
        txt = _clip(line, inner - 2)
        pad = max(1, inner - len(_vis(txt)) - 2)
        print(f"{t['border']}{vert}{RESET} {txt}{' ' * pad}{t['border']}{vert}{RESET}")
    print(f"{t['border']}{blc}{horiz * inner}{brc}{RESET}")


def banner(theme="NEO"):
    t = THEMES.get(theme, THEMES["NEO"])
    w = max(20, min(width() - 2, 118))
    inner = w - 2
    cols = [t["primary"], t["accent"], t["info"], t["secondary"]]
    tlc, trc, blc, brc, vert, horiz, cross_l, cross_r = (
        ("+", "+", "+", "+", "|", "-", "+", "+") if ASCII_MODE
        else ("╔", "╗", "╚", "╝", "║", "═", "╠", "╣")
    )
    print(f"{t['border']}{BOLD}{tlc}{horiz * inner}{trc}{RESET}")
    texture = (("-" if ASCII_MODE else "░▒▓") * (inner + 1))[:inner]
    print(f"{t['border']}{vert}{RESET}{DIM}{texture}{RESET}{t['border']}{vert}{RESET}")
    for i, line in enumerate(BANNER_LINES):
        row = _center(line, inner)
        print(f"{t['border']}{vert}{RESET}{BOLD}{cols[i % len(cols)]}{row}{RESET}{t['border']}{vert}{RESET}")
    print(f"{t['border']}{cross_l}{horiz * inner}{cross_r}{RESET}")
    tag = _display_text(f"⚡ OSINT + BRUTE FORCE - SURFACE  •  v{EDY_RECON_VERSION} CYBER EDITION ⚡")
    print(f"{t['border']}{vert}{RESET}{BOLD}{t['accent']}{_center(tag, inner)}{RESET}{t['border']}{vert}{RESET}")
    print(f"{t['border']}{BOLD}{blc}{horiz * inner}{brc}{RESET}")
    print(RESET)


def ask(theme="NEO", prompt="> ", default=None, allow_empty=True):
    try:
        val = input(paint(prompt, theme, "accent", bold=True))
        if default is not None:
            if val.strip() == "":
                return default
            return val.strip()
        return val.strip() if val.strip() != "" or allow_empty else None
    except (KeyboardInterrupt, EOFError):
        print()
        return None


def ask_secret(theme="NEO", prompt="Chave> ", default=None, allow_empty=True):
    """Entrada sem eco; o valor anterior nunca aparece no prompt."""
    try:
        value = getpass.getpass(paint(prompt, theme, "accent", bold=True))
        if not value and default is not None:
            return default
        return value if value or allow_empty else None
    except (KeyboardInterrupt, EOFError):
        print()
        return None


def confirm(theme="NEO", question="Continuar?", default="s"):
    t = THEMES.get(theme, THEMES["NEO"])
    suf = "[s/N]" if default.lower() != "s" else "[S/n]"
    print(f"{BOLD}{t['warn']}?{RESET} {t['secondary']}{question}{RESET} {BOLD}{t['accent']}{suf}{RESET} ", end="", flush=True)
    try:
        r = input().strip().lower()
    except (KeyboardInterrupt, EOFError):
        print()
        return default.lower() == "s"
    if r == "":
        return default.lower() == "s"
    return r in ("s", "sim", "y", "yes")


def menu(theme="NEO", title="MENU PRINCIPAL", items=None, footer=None):
    t = THEMES.get(theme, THEMES["NEO"])
    w = max(20, min(width() - 2, 118))
    inner = w - 2
    tlc, trc, blc, brc, vert, horiz, cross_l, cross_r = (
        ("+", "+", "+", "+", "|", "-", "+", "+") if ASCII_MODE
        else ("╔", "╗", "╚", "╝", "║", "═", "╠", "╣")
    )
    print(f"{t['border']}{tlc}{horiz * inner}{trc}{RESET}")
    tl = f"[ {title} ]"
    print(f"{t['border']}{vert}{RESET}{BOLD}{t['primary']}{_center(_display_text(tl), inner)}{RESET}{t['border']}{vert}{RESET}")
    print(f"{t['border']}{cross_l}{horiz * inner}{cross_r}{RESET}")
    for num, label, role in items:
        if role == "sep":
            sep = "." if ASCII_MODE else "·"
            print(f"{t['border']}{vert}{RESET} {t['dim']}{sep * max(1, inner - 4)}{RESET} {t['border']}{vert}{RESET}")
            continue
        ns = str(num)
        lbl = _display_text(label)
        max_lbl = inner - 3 - len(ns)
        lbl = _clip(lbl, max_lbl)
        txt = f"{BOLD}{t[role]}{ns}{RESET} {t['secondary']}{lbl}{RESET}"
        pad = max(1, inner - len(ns) - len(lbl) - 2)
        print(f"{t['border']}{vert}{RESET} {txt}{' ' * pad}{t['border']}{vert}{RESET}")
    if footer:
        print(f"{t['border']}{cross_l}{horiz * inner}{cross_r}{RESET}")
        ftxt = _clip(footer, inner - 4)
        pad = max(1, inner - len(ftxt) - 2)
        print(f"{t['border']}{vert}{RESET} {BOLD}{t['accent']}{ftxt}{RESET}{' ' * pad}{t['border']}{vert}{RESET}")
    print(f"{t['border']}{blc}{horiz * inner}{brc}{RESET}")


_SPIN = ["|", "/", "-", "\\"] if ASCII_MODE else ["◐", "◓", "◑", "◒"]
_spin_i = 0


def status_bar(theme, text, total=None, done=0):
    global _spin_i
    t = THEMES.get(theme, THEMES["NEO"])
    if total:
        pct = min(100, int(done * 100 / total)) if total else 0
        bar_w = 22
        filled = int(pct * bar_w / 100)
        bar = ("#" * filled + "-" * (bar_w - filled)) if ASCII_MODE else ("█" * filled + "░" * (bar_w - filled))
        sys.stdout.write(
            f"\r{BOLD}{t['accent']}[{bar}]{RESET} {t['secondary']}{pct:3d}%{RESET} "
            f"{t['info']}{_display_text(text)}{RESET}   "
        )
    else:
        _spin_i += 1
        c = _SPIN[_spin_i % len(_SPIN)]
        sys.stdout.write(f"\r{BOLD}{t['accent']}{c}{RESET} {t['secondary']}{_display_text(text)}{RESET}   ")
    sys.stdout.flush()


def clear_line():
    sys.stdout.write("\r" + " " * max(1, width() - 1) + "\r")
    sys.stdout.flush()
