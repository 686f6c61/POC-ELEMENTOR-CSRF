#!/bin/sh
# Genera la galería de capturas PNG del laboratorio (docs/img/).
# Requiere: Chrome (o Chromium) y el lab levantado (make lab && make control).
# Uso: sh scripts/capturas/generar.sh
set -e
cd "$(dirname "$0")/../.."

CHROME="$(command -v google-chrome || command -v chromium || true)"
[ -z "$CHROME" ] && CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
[ -x "$CHROME" ] || { echo "[!] Chrome no disponible"; exit 1; }

IMG=docs/img
TMP=/tmp/lab-capturas
mkdir -p "$IMG" "$TMP"

# Preflight: sin lab levantado las capturas serían de ejecuciones fallidas.
for url in http://localhost:8085/wp-login.php http://localhost:8086/wp-login.php; do
    if ! curl -s -o /dev/null -m 5 "$url"; then
        echo "[capturas] LAB CAÍDO ($url no responde): make lab && make control primero"
        exit 1
    fi
done

# <png> <titulo-ventana> <comando-mostrado> <comando real...>
term() {
    png="$1"; title="$2"; shown="$3"; shift 3
    "$@" > "$TMP/out.txt" 2>&1 || true
    python3 scripts/capturas/terminal.py --title "$title" --cmd "$shown" \
        < "$TMP/out.txt" > "$TMP/page.html" 2> "$TMP/h.txt"
    H="$(sed -n 's/^HEIGHT=//p' "$TMP/h.txt")"
    "$CHROME" --headless=new --disable-gpu --hide-scrollbars \
        --force-device-scale-factor=2 --window-size=1100,"${H:-900}" \
        --screenshot="$IMG/$png" "file://$TMP/page.html" >/dev/null 2>&1
    echo "[capturas] $IMG/$png"
}

# <png> <url> <WxH>
shot() {
    "$CHROME" --headless=new --disable-gpu --hide-scrollbars \
        --force-device-scale-factor=2 --window-size="$3" \
        --virtual-time-budget=8000 --screenshot="$IMG/$1" "$2" >/dev/null 2>&1
    echo "[capturas] $IMG/$1"
}

echo "== capturas de terminal =="
term terminal-fase3.png   "FASE 3 · el clic (401 -> 201 -> %2F)"   "make click" \
    sh exploit/03_click_victim.sh http://localhost:8085 victima-4.3.1
term terminal-aportaciones.png "FASE 6 · vectores propios"   "make aportaciones" \
    sh exploit/06_aportaciones.sh http://localhost:8085
term terminal-firewall.png "FASE 7 · hardening neutralizado" "make hardening-demo" \
    sh exploit/07_hardening_bypass.sh http://localhost:8085
term terminal-mitigacion.png "FASE 8 · paliativa verificada" "make mitigacion-demo" \
    sh exploit/08_mitigacion_demo.sh http://localhost:8085
term terminal-blast.png "FASE 9 · plugins por GET + WooCommerce" "make blast-radius" \
    sh exploit/09_blast_radius.sh http://localhost:8085
term terminal-demoflip.png "FASE 5 · root cause en vivo"     "make demo-flip" \
    sh exploit/05_demo_root_cause.sh

echo "== capturas de navegador =="
# el correo que recibe la víctima (regenerado con los datos actuales)
python3 exploit/02_craft_link.py --base-url http://localhost:8085 >/dev/null
shot navegador-phishing.png "file://$(pwd)/exploit/correo-phishing.html" 1280,920

# la puerta trasera existe y es pública: /author/csrfadmin/
# (csrfadmin se crea ejecutando la fase 3; el author page solo existe si hay ataque)
sh exploit/03_click_victim.sh http://localhost:8085 victima-4.3.1 >/dev/null 2>&1 || true
shot navegador-victima.png  "http://localhost:8085/author/csrfadmin/" 1280,920
shot navegador-control.png  "http://localhost:8086/author/csrfadmin/" 1280,920

# si el CTF está levantado, capturar el bot víctima
if curl -s -o /dev/null -m 3 http://localhost:8089/; then
    shot navegador-bot.png "http://localhost:8089/" 1280,920
fi

echo "== og =="
shot og.png "file://$(pwd)/scripts/capturas/src/og.html" 1200,630

echo "== gif de la demo (marcos de 3+3+4s; sin duración explícita parpadea) =="
if [ -f "$IMG/demo-1-sesion.png" ] && command -v ffmpeg >/dev/null 2>&1; then
    ffmpeg -y -loglevel error \
        -loop 1 -t 3 -framerate 10 -i "$IMG/demo-1-sesion.png" \
        -loop 1 -t 3 -framerate 10 -i "$IMG/demo-2-correo.png" \
        -loop 1 -t 4 -framerate 10 -i "$IMG/demo-3-resultado.png" \
        -filter_complex "[0]scale=760:-1[t0];[1]scale=760:-1[t1];[2]scale=760:-1[t2];[t0][t1][t2]concat=n=3:v=1:a=0,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse" \
        -loop 0 "$IMG/demo-navegador.gif" && echo "[capturas] $IMG/demo-navegador.gif"
else
    echo "[capturas] (sin ffmpeg o sin demo-*.png: se conserva el gif actual)"
fi

echo "[capturas] galería completa en $IMG/"
