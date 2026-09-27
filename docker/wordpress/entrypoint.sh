#!/bin/sh
# Laboratorio Elementor CSRF — aprovisionamiento en el primer arranque.
#
# El entrypoint oficial de la imagen WordPress solo copia el core y genera
# wp-config.php cuando $1 es apache2*/php-fpm; aquí se replica ese bootstrap
# para poder instalar ANTES de arrancar Apache (así el sitio nace ya
# instalado y con Elementor activo, sin ventana de "5-minute install").
set -e
cd /var/www/html

# 1) Copiar el core de WordPress al volumen (primer arranque).
if [ ! -e wp-includes/version.php ]; then
    echo "[lab] copiando WordPress desde /usr/src/wordpress..."
    cp -a /usr/src/wordpress/. .
fi

# 2) wp-config.php desde el entorno.
if [ ! -f wp-config.php ]; then
    echo "[lab] generando wp-config.php"
    # WP_ENVIRONMENT_TYPE=local: habilita Application Passwords sobre HTTP,
    # replicando la condición de los sitios de producción (HTTPS) donde sí
    # están disponibles. Necesario para la fase 6 (aportación propia:
    # "puerta silenciosa" via application passwords). Se define en víctima
    # y control por igual: la variable única del experimento sigue siendo
    # la versión de Elementor.
    # FS_METHOD=direct: instalación de plugins por REST/WP-CLI sin credenciales
    # FTP (fase 9: endpoint /wp/v2/plugins).
    wp core config --allow-root --skip-check \
        --dbname="${WORDPRESS_DB_NAME:-wordpress}" \
        --dbuser="${WORDPRESS_DB_USER:-wordpress}" \
        --dbpass="${WORDPRESS_DB_PASSWORD:-wordpress}" \
        --dbhost="${WORDPRESS_DB_HOST:-db:3306}" \
        --dbprefix='wp_' \
        --extra-php="define( 'WP_ENVIRONMENT_TYPE', 'local' ); define( 'FS_METHOD', 'direct' );"
fi

# 3) Esperar MySQL (la imagen no trae cliente mysql: se prueba con mysqli).
echo "[lab] esperando MySQL en ${WORDPRESS_DB_HOST:-db:3306} ..."
until php -r 'exit(@mysqli_connect(getenv("WORDPRESS_DB_HOST"), getenv("WORDPRESS_DB_USER"), getenv("WORDPRESS_DB_PASSWORD")) ? 0 : 1);' 2>/dev/null; do
    sleep 2
done
echo "[lab] MySQL accesible"

# 4) Instalación idempotente de WordPress + Elementor.
if ! wp core is-installed --allow-root 2>/dev/null; then
    echo "[lab] instalando WordPress en ${LAB_URL}"
    wp core install --allow-root \
        --url="${LAB_URL}" \
        --title="${LAB_TITLE:-Elementor CSRF Lab}" \
        --admin_user="${LAB_ADMIN_USER:-admin}" \
        --admin_password="${LAB_ADMIN_PASSWORD:-admin}" \
        --admin_email="${LAB_ADMIN_EMAIL:-admin@lab.test}" \
        --skip-email

    echo "[lab] instalando Elementor ${ELEMENTOR_VERSION}"
    rm -rf wp-content/plugins/elementor
    cp -r /usr/src/elementor-dist/elementor wp-content/plugins/elementor
    wp plugin activate elementor --allow-root

    # Permalinks "bonitos": hace que /wp-json/wp/v2/users responda directamente
    # (con permalinks planos habría que usar ?rest_route=/wp/v2/users).
    wp rewrite structure '/%postname%/' --hard --allow-root
    wp rewrite flush --hard --allow-root

    # Apache (www-data) necesita escribir en wp-content (uploads, caché).
    chown -R www-data:www-data wp-content

    # Estado del experimento 'editor_events': vacío en instalación limpia =>
    # se aplica el default de "sitio nuevo" (>= 3.32.0) => ACTIVO por defecto.
    # Esa es exactamente la condición de los ~2M de sitios reales afectados.
    EXPERIMENTO="$(wp option get elementor_experiment-editor_events --allow-root 2>/dev/null || true)"
    echo "[lab] experimento editor_events = '${EXPERIMENTO:-<vacio, default nuevo-sitio=activo>}'"

    echo "[lab] sitio listo: ${LAB_URL} (admin / ${LAB_ADMIN_PASSWORD:-admin})"
fi

# ---------------------------------------------------------------- MODO CTF
# Instancia de reto (profile "ctf" del compose): instala limpia + flags +
# hardening anti-CSRF ACTIVO desde el arranque (los jugadores deben
# descubrir que el bypass lo silencia). Ver ctf/README.md.
if [ "${CTF_MODE:-0}" = "1" ] && ! wp option get ctf_instalado --allow-root >/dev/null 2>&1; then
    echo "[ctf] preparando instancia del reto..."

    # La víctima del CTF: admin de pruebas del sitio. Su contraseña no se
    # publica; el bot (ctf/bot) la usa internamente para simular sus clics.
    wp user create editor-demo demo@ctf.local --role=administrator \
        --user_pass="${CTF_ADMIN_PASS:-demo-super-secreta-2026}" --allow-root >/dev/null

    # FLAG 3: fuga por /wp/v2/settings (subcadena anidada).
    wp option update admin_email 'CTF{correo-del-admin}@ctf.local' --allow-root >/dev/null

    # FLAG 2: post privado del admin (legible tras crear tu propio admin).
    wp post create --post_author=editor-demo --post_title='Notas privadas del admin' \
        --post_content='Solo la administración de pruebas debería leer esto. Recompensa: CTF{un-clic-un-admin}' \
        --post_status=private --post_type=post --allow-root >/dev/null

    # FLAG 4: perfil de una cuenta dormida (fuga por context=edit).
    wp user create huevo huevo@ctf.local --role=subscriber --user_pass=huevo-dormido-2026 --allow-root >/dev/null
    wp user meta update huevo description 'Apuntes del becario: CTF{perfil-del-huevo}' --allow-root >/dev/null

    # Hardening anti-CSRF activo desde el inicio: el patrón canónico de los
    # plugins de seguridad deniega cookies-sin-nonce en REST... salvo que el
    # bug lo silencie. Eso es lo que el jugador debe descubrir.
    mkdir -p wp-content/mu-plugins
    if [ -f /usr/src/lab-hardening-rest.php ]; then
        cp /usr/src/lab-hardening-rest.php wp-content/mu-plugins/
        chown www-data:www-data wp-content/mu-plugins/lab-hardening-rest.php
        echo "[ctf] hardening anti-CSRF activo (mu-plugin)"
    fi
    wp option update ctf_instalado 1 --allow-root >/dev/null
    echo "[ctf] reto listo: ${LAB_URL} · bot en ${CTF_BOT_URL:-:8089}"
fi

exec docker-entrypoint.sh "$@"
