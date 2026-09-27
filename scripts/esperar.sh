#!/bin/sh
# Espera a que el WordPress del lab responda HTTP 200 (instalación completa).
set -u
URL="${1:-http://localhost:8080}/wp-login.php"
printf "[espera] %s " "$URL"
i=0
while [ $i -lt 90 ]; do
    code="$(curl -s -o /dev/null -w '%{http_code}' "$URL" 2>/dev/null || echo 000)"
    if [ "$code" = "200" ]; then
        printf "lista (HTTP 200)\n"
        exit 0
    fi
    printf "."
    i=$((i+1))
    sleep 2
done
printf "\n[!] agotados los intentos (último HTTP %s). Revisa: docker compose logs victima\n" "$code"
exit 1
