#!/bin/sh
# Verificador del CTF — comprueba cada flag contra la instancia VIVA del reto
# (fuente de verdad: la base de datos del contenedor, no un fichero local).
#
# Uso:
#   ./ctf/verificar.sh 1 "4.3.1"
#   ./ctf/verificar.sh 2 "CTF{un-clic-un-admin}"
#   ./ctf/verificar.sh 3 "CTF{correo-del-jefe}@ctf.local"
#   ./ctf/verificar.sh 4 "CTF{perfil-del-huevo}"
#   ./ctf/verificar.sh 5 "tu-nick:9xxx xxxx xxxx xxxx xxxx"   # la contraseña
#                                                            # que devolvió el bot
set -u
CTF=elementorcsrf-ctf-1

n="${1:-}"
valor="${2:-}"

if [ -z "$n" ] || [ -z "$valor" ]; then
    echo "uso: $0 <1-5> <valor>"
    exit 64
fi

verde()  { printf '\033[1;32m%s\033[0m\n' "$1"; }
rojo()   { printf '\033[1;31m%s\033[0m\n' "$1"; }

wpe() { docker exec "$CTF" wp "$@" --allow-root 2>/dev/null; }

case "$n" in
1)
    real="$(wpe plugin get elementor --field=version | tr -d '\r\n')"
    limpio="$(echo "$valor" | sed 's/^CTF{//;s/}$//')"
    if [ "$limpio" = "$real" ]; then
        verde "✔ FLAG 1 correcta: Elementor $real (fingerprint del readme)."
    else
        rojo "✘ no: la versión instalada no es '$limpio'. Pista: wp-content/plugins/<plugin>/readme.txt es público."
    fi
    ;;
2)
    if wpe post list --post_type=post --post_status=private --field=post_content 2>/dev/null | grep -qF "$valor"; then
        verde "✔ FLAG 2 correcta: leíste el post privado del admin."
    else
        rojo "✘ esa cadena no está en ningún post. Necesitas tu PROPIO admin y leer el post privado."
    fi
    ;;
3)
    real="$(wpe option get admin_email | tr -d '\r\n')"
    if [ "$valor" = "$real" ]; then
        verde "✔ FLAG 3 correcta: filtraste admin_email por REST sin tocar wp-admin."
    else
        rojo "✘ admin_email no es eso. Pista: GET /wp/v2/settings... con la subcadena ANIDADA en otro parámetro."
    fi
    ;;
4)
    real="$(wpe user meta get huevo description | tr -d '\r\n')"
    if echo "$real" | grep -qF "$valor"; then
        verde "✔ FLAG 4 correcta: enumeraste perfiles con context=edit."
    else
        rojo "✘ no está en el perfil de 'huevo'. Pista: /wp/v2/users/<id>?context=edit (el admin lo ve todo)."
    fi
    ;;
5)
    nick="${valor%%:*}"
    pass="${valor#*:}"
    if [ -z "$nick" ] || [ -z "$pass" ] || [ "$nick" = "$pass" ]; then
        echo "formato: tu-nick:contraseña-devuelta"; exit 64
    fi
    # Verificación conductual, la misma que haría el atacante: Basic auth
    # contra el REST del reto. 200 = la credencial permanente FUNCIONA.
    code="$(curl -s -o /dev/null -w '%{http_code}' -u "editor-demo:$pass" \
        "http://localhost:8087/wp-json/wp/v2/users/me?context=edit")"
    if [ "$code" = "200" ]; then
        verde "✔ FLAG 5 desbloqueada ($nick): la contraseña de aplicación del admin FUNCIONA (Basic -> 200)."
        verde "  Credencial permanente sin cookies ni nonce. Flag final: CTF{puerta-silenciosa}"
    else
        rojo "✘ esa contraseña no valida contra la cuenta del admin (HTTP $code). La respuesta del bot al crear el app-password la trae en claro."
    fi
    ;;
*)
    echo "flags 1-5"; exit 64
    ;;
esac
