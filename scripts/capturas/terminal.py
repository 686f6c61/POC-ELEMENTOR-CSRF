#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Convierte una salida de terminal en HTML con aspecto de ventana macOS.

(port del lab CVE-2026-93485; este script NO ejecuta nada y NO escribe
ficheros: lee stdin, escupe el HTML por stdout y "HEIGHT=<px>" por stderr.
Quien orquesta (scripts/capturas/generar.sh) redirige y rasteriza con
Chrome headless.)

Uso:
    comando ... | python3 scripts/capturas/terminal.py \
        --title "make click" --cmd "make click" > /tmp/click.html
"""

import argparse
import html
import re
import sys

FONT_PX = 13.5
LINE_H = 21.5


def colorize_line(line: str) -> str:
    esc = html.escape(line, quote=False)
    if re.match(r"^\s*(✗|ERROR|\[!\])", line):
        cls = "bad"
    elif re.match(r"^\s*(✓|\[PWNED|\[CONFIRMADO|\[VECTORES|\[HARDENING)", line):
        cls = "good"
    elif re.match(r"^\s*(──|═══|==|\[espera\])", line) or "VEREDICTO" in line:
        cls = "sep"
    elif re.match(r"^\s*(make |bash |sh |curl |docker |python3|\$ |GET |POST )", line) or line.startswith("LAB_URL"):
        cls = "cmd"
    elif re.match(r"^\s*(·|->|\[clic\]|\[uso\]|\[limpia|\[1\]|\[2\]|\[3\]|\[4\]|\[A\]|\[B\]|antes:|después:)", line):
        cls = "dim"
    else:
        cls = ""
    if cls:
        return f'<span class="{cls}">{esc}</span>'
    return esc


def build_html(title: str, cmd: str | None, text: str) -> str:
    lines = text.rstrip("\n").splitlines()
    body = []
    if cmd:
        body.append(f'<div class="cmdline"><span class="dollar">$</span> {html.escape(cmd)}</div>')
    body += [colorize_line(l) for l in lines]
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>
    html,body{{margin:0;padding:0;background:#0d1117;}}
    .term{{width:1040px;background:#0d1117;border:1px solid #21262d;border-radius:10px;
      overflow:hidden;font-family:'JetBrains Mono','Cascadia Mono','SF Mono',Menlo,Consolas,monospace;}}
    .bar{{height:38px;background:#161b22;border-bottom:1px solid #21262d;display:flex;
      align-items:center;padding:0 14px;gap:8px}}
    .dot{{width:12px;height:12px;border-radius:50%;display:inline-block}}
    .r{{background:#ff5f57}} .y{{background:#febc2e}} .g{{background:#28c840}}
    .bartitle{{margin-left:10px;color:#8b949e;font-size:12.5px;user-select:none}}
    pre{{margin:0;padding:20px 22px 24px;font-size:{FONT_PX}px;line-height:{LINE_H}px;
      color:#c9d1d9;white-space:pre-wrap;word-break:break-all}}
    .cmdline{{color:#e6edf3;font-weight:700}}
    .dollar{{color:#3fb950}}
    .good{{color:#3fb950}} .bad{{color:#f85149;font-weight:600}}
    .sep{{color:#d29922}} .cmd{{color:#e6edf3;font-weight:600}}
    .dim{{color:#8b949e}}
    </style></head><body>
    <div style="padding:18px"><div class="term">
      <div class="bar"><span class="dot r"></span><span class="dot y"></span><span class="dot g"></span>
      <span class="bartitle">{html.escape(title)}</span></div>
      <pre>{chr(10).join(body)}</pre>
    </div></div>
    </body></html>"""


def estimate_rows(lines, cmd, chars_per_line=108):
    rows = 1 if cmd else 0
    for l in lines:
        rows += max(1, -(-len(l) // chars_per_line))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--title", required=True)
    ap.add_argument("--cmd", default=None, help="línea de comando a mostrar sobre la salida")
    args = ap.parse_args()

    if sys.stdin.isatty():
        ap.error("canaliza la entrada: cmd ... | terminal.py ...")

    text = sys.stdin.read()
    sys.stdout.write(build_html(args.title, args.cmd, text))
    rows = estimate_rows(text.rstrip("\n").splitlines(), args.cmd)
    print(f"HEIGHT={int(rows * LINE_H + 140)}", file=sys.stderr)


if __name__ == "__main__":
    main()
