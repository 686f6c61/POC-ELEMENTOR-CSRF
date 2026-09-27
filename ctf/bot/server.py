#!/usr/bin/env python3
"""Bot víctima del CTF — "El admin de pruebas pulsa el enlace que le enseñan".

Servicio web mínimo (stdlib, sin dependencias) que actúa como la víctima:

  * GET  /          -> formulario + instrucciones del reto.
  * POST /visitar   -> el admin de pruebas (admin del sitio del CTF, sesión
                       fresca en cada visita) hace GET a la URL que le pases
                       y devuelve estado + fragmento de la respuesta.

El bot JAMÁS entrega sus cookies ni su contraseña: solo el resultado de sus
clics. Es la abstracción del "one click": el jugador fabrica el enlace y
la víctima de laboratorio lo pulsa.

Seguridad (el bot es un fetcher de URLs):
  * Solo http/https.
  * Solo el host del CTF (validado contra HOSTS_PUBLICOS; internamente se
    traduce a WP_BASE para salir por la red de docker).
  * Sesión nueva en cada visita (no se acumulan privilegios entre jugadores).
"""
from __future__ import annotations

import html
import http.cookiejar
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WP_BASE = os.environ.get("WP_BASE", "http://ctf").rstrip("/")
HOSTS_PUBLICOS = {
    h.strip().lower()
    for h in os.environ.get("HOSTS_PUBLICOS", "localhost:8087").split(",")
    if h.strip()
}
VICTIMA_USER = os.environ.get("VICTIMA_USER", "editor-demo")
VICTIMA_PASS = os.environ.get("VICTIMA_PASS", "")
PUERTO = int(os.environ.get("PUERTO", "8080"))

PAGINA = """<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bot víctima — CTF La Subcadena Mágica</title>
<style>
 body{{font-family:ui-monospace,Menlo,Consolas,monospace;background:#0b1220;color:#e2e8f0;
      max-width:760px;margin:40px auto;padding:0 18px;line-height:1.55}}
 h1{{color:#38bdf8;font-size:1.3rem}} .warn{{color:#fbbf24}} .ok{{color:#4ade80}}
 form{{background:#111a2c;border:1px solid #1e293b;border-radius:10px;padding:16px}}
 input[type=text]{{width:100%;box-sizing:border-box;padding:10px;border-radius:6px;
      border:1px solid #334155;background:#0a0f1c;color:#e2e8f0;font-family:inherit}}
 button{{margin-top:10px;background:#2271b1;color:#fff;border:0;border-radius:6px;
      padding:10px 20px;font-family:inherit;font-weight:600;cursor:pointer}}
 pre{{background:#0a0f1c;border:1px solid #1e293b;border-radius:8px;padding:12px;
      overflow:auto;font-size:.85rem}}
 .resp{{margin-top:14px}} code{{color:#a5d6ff}}
</style></head><body>
<h1>&#128269; Bot víctima — "La Subcadena Mágica"</h1>
<p>El admin de pruebas (<code>editor-demo</code>) tiene sesión de administrador
en el sitio del reto. Pégale un enlace y, si confía, hará clic.</p>
<form method="post" action="/visitar">
  <input type="text" name="url" placeholder="http://localhost:8087/wp-json/..." required>
  <button type="submit">Hacer que el admin de pruebas pulse el enlace</button>
</form>
{cuerpo}
<p class="warn" style="font-size:.85rem">El bot solo habla con el host del CTF
(<code>{hosts}</code>), abre sesión nueva en cada visita y nunca revela sus
cookies. Sin JavaScript del lado del jugador: todo lo que el admin hace es un
simple GET de navegador.</p>
</body></html>"""


def _url_valida(url: str) -> tuple[str, str] | None:
    """Valida la URL (solo http/https + host del reto) y devuelve
    (path+query interno, url pública saneada) o None si se rechaza."""
    try:
        p = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    if p.scheme not in ("http", "https"):
        return None
    host = (p.hostname or "").lower()
    puerto = p.port
    netloc = f"{host}:{puerto}" if puerto else host
    if netloc not in HOSTS_PUBLICOS:
        return None
    destino = p.path or "/"
    if p.query:
        destino += "?" + p.query
    saneada = urllib.parse.urlunsplit(("http", netloc, p.path, p.query, ""))
    return destino, saneada


def _sesion_victima() -> tuple[urllib.request.OpenerDirector, http.cookiejar.CookieJar]:
    """Login fresco de la víctima (cookie jar limpio por visita)."""
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    opener.addheaders = [("User-Agent", "Mozilla/5.0 (demo-navegadora) CTFbot/1.0")]
    body = urllib.parse.urlencode(
        {
            "log": VICTIMA_USER,
            "pwd": VICTIMA_PASS,
            "wp-submit": "Log In",
            "redirect_to": WP_BASE + "/wp-admin/",
            "testcookie": "1",
        }
    ).encode()
    try:
        opener.open(WP_BASE + "/wp-login.php", data=body, timeout=10).read()
    except urllib.error.HTTPError:
        pass
    return opener, jar


def visitar(url: str) -> tuple[int, str]:
    destino = _url_valida(url)
    if destino is None:
        return 0, "URL rechazada: solo http/https y solo el host del reto."
    path, saneada = destino
    opener, jar = _sesion_victima()
    if not any("wordpress_logged_in" in c.name for c in jar):
        return 0, "La víctima no pudo iniciar sesión (¿está el sitio del reto arriba?)."
    time.sleep(0.3)
    try:
        with opener.open(WP_BASE + path, timeout=15) as r:
            cuerpo = r.read(4000).decode("utf-8", "replace")
            return r.status, cuerpo
    except urllib.error.HTTPError as e:
        cuerpo = e.read(4000).decode("utf-8", "replace")
        return e.code, cuerpo
    except (urllib.error.URLError, TimeoutError):
        return 0, "Error de red hacia el sitio del reto."


class Handler(BaseHTTPRequestHandler):
    def _pagina(self, cuerpo: str = "") -> None:
        hosts = ", ".join(sorted(HOSTS_PUBLICOS))
        html_ = PAGINA.format(cuerpo=cuerpo, hosts=html.escape(hosts))
        data = html_.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        self._pagina()

    def do_POST(self) -> None:
        if self.path != "/visitar":
            self._pagina()
            return
        n = int(self.headers.get("Content-Length") or 0)
        datos = urllib.parse.parse_qs(self.rfile.read(n).decode("utf-8", "replace"))
        url = (datos.get("url") or [""])[0].strip()
        estado, cuerpo = visitar(url)
        color = "ok" if estado == 201 else ""
        cuerpo_html = (
            f'<div class="resp"><p>El admin de pruebas visitó <code>{html.escape(url)}</code></p>'
            f'<p><b class="{color}">HTTP {estado}</b></p>'
            f"<pre>{html.escape(cuerpo[:1600])}</pre></div>"
        )
        self._pagina(cuerpo_html)

    def log_message(self, fmt, *args):  # silencio relativo
        print(f"[bot] {self.address_string()} {fmt % args}")


if __name__ == "__main__":
    print(f"[bot] a la escucha en :{PUERTO} · WP_BASE={WP_BASE} · hosts={HOSTS_PUBLICOS}")
    ThreadingHTTPServer(("0.0.0.0", PUERTO), Handler).serve_forever()
