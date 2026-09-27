#!/usr/bin/env python3
"""Detector de IOCs del CSRF de Elementor (bypass del nonce REST).

Lee un access log (formato combined de Apache o cualquier línea con una
petición entre comillas) POR STDIN y clasifica cada línea:

  CRIT  explotación del bypass (subcadena mágica + override de verbo/roles)
  MED   uso del bypass en lectura (subcadena en query de ruta ajena)
  INFO  telemetría legítima del propio módulo Editor Events
  -     línea limpia (silencio)

La regla de oro del bug: la subcadena `elementor/v1/events/` en la query de
una petición cuya ruta NO es la del proxy de telemetría.

Uso (stdin, a propósito: cualquier fuente sirve):
    cat research/investigacion/access-log-ejemplo.log | python3 scripts/detectar_iocs.py
    make detectar-iocs            # sobre el log de ejemplo del repo
    make detectar-iocs-vivo      # sobre docker logs de la víctima (en vivo)

Sale con código 1 si hay al menos un CRIT (útil en demos/CI).
"""
from __future__ import annotations

import re
import sys

MAGICA = "elementor/v1/events/"
PETICION = re.compile(r'"(\S+)\s+(\S+)\s+([^"]*)"')


def clasificar(linea: str) -> tuple[str, str]:
    """Devuelve (severidad, motivo)."""
    m = PETICION.search(linea)
    if not m:
        return ("-", "")
    verbo, objetivo = m.group(1), m.group(2)

    # separa path de query
    if "?" in objetivo:
        path, query = objetivo.split("?", 1)
    else:
        path, query = objetivo, ""

    ruta_propia = path.startswith("/wp-json/elementor/v1/events/") or (
        "rest_route=/elementor/v1/events/" in query
    )
    magica_en_query = MAGICA in query
    override = any(f"_method={v}" in query for v in ("POST", "PUT", "PATCH"))
    roles = "roles%5B%5D=administrator" in query or "roles[]=administrator" in query
    app_pass = "application-passwords" in path and override

    if ruta_propia:
        return ("INFO", "telemetría legítima del proxy Editor Events")

    if magica_en_query:
        if app_pass:
            return ("CRIT", "§1 puerta silenciosa: app-password por GET con override de verbo")
        if roles:
            return ("CRIT", "creación/promoción de administrator por GET con override de verbo")
        if override:
            return ("CRIT", "escritura REST por GET con override de verbo + subcadena mágica")
        return ("MED", "subcadena mágica en query de ruta ajena (posible lectura con bypass)")

    if verbo == "GET" and override and roles:
        return ("MED", "override de verbo + roles sin subcadena (probable intento fallido)")
    return ("-", "")


def main() -> int:
    colores = {"CRIT": "\033[1;31m", "MED": "\033[1;33m", "INFO": "\033[2;34m", "-": "\033[2m"}
    conteo = {"CRIT": 0, "MED": 0, "INFO": 0, "-": 0}

    for linea in sys.stdin:
        linea = linea.rstrip("\n")
        if not linea.strip():
            continue
        sev, motivo = clasificar(linea)
        conteo[sev] += 1
        if sev != "-":
            c = colores[sev]
            fin = "\033[0m"
            print(f"{c}[{sev}]{fin} {motivo}")
            print(f"  {linea.strip()[:200]}")

    total = sum(conteo.values())
    limpias = total - conteo["CRIT"] - conteo["MED"] - conteo["INFO"]
    print(
        f"\nresumen: {conteo['CRIT']} CRIT · {conteo['MED']} MED · "
        f"{conteo['INFO']} INFO · {limpias} limpias"
    )
    if conteo["CRIT"]:
        print(
            "\033[1;31m>>> EXPLOTACIÓN DETECTADA: revisar usuarios, roles y "
            "app-passwords (ver README §Defensa)\033[0m"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
