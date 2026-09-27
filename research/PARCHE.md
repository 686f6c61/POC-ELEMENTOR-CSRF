# PARCHE.md — Forense del fix 4.3.1 → 4.3.2

Archivo único donde vive el bug:

```
elementor/core/common/modules/events-manager/rest-api/events-proxy-rest-api.php
```

En 4.3.0 y 4.3.1 el archivo es **byte a byte idéntico** (verificado con `diff`).

Material verificado localmente (SHA256 de los zips oficiales de wordpress.org):

| Versión | SHA256 |
|---|---|
| elementor.4.3.0.zip | `3617ade04fc0b236756159399c56e4cc91c463daaedb3318b7cf5c7207cefa90` |
| elementor.4.3.1.zip | `9e947ce507a6c76d22ec7c710da96b65ecc7da18703dc662a6940f5443491c8d` |
| elementor.4.3.2.zip | `8b3eee68425e5fd90007dc84b37ffea844c0db44b6d342968f33c76187a94371` |

## El código vulnerable (4.3.0 / 4.3.1)

Registro del filtro — se ejecuta en **cada petición REST**, antes del dispatch:

```php
public function register_hooks() {
    add_action( 'rest_api_init', fn() => $this->register_routes() );
    add_filter( 'rest_authentication_errors', [ $this, 'bypass_nonce_check_for_own_routes' ], 0 );  // <-- prioridad 0
    ...
}

public function bypass_nonce_check_for_own_routes( $result ) {
    if ( $this->is_own_route_request() ) {
        return true;   // <-- "ya no hace falta validar nada"
    }
    return $result;
}

private function is_own_route_request(): bool {
    $request_uri = Utils::get_super_global_value( $_SERVER, 'REQUEST_URI' ) ?? '';

    // Subcadena SIN anclar sobre el URI CRUDO: path + QUERY STRING.
    return false !== strpos( $request_uri, self::API_NAMESPACE . '/' . self::API_BASE . '/' );
}
```

### Por qué rompe todo el REST API

Cadena causal en el core de WordPress:

1. `determine_current_user` resuelve a la víctima desde sus cookies de sesión
   (esto ocurre antes y NO está en juego).
2. `WP_REST_Server::serve_request()` dispara el filtro
   **`rest_authentication_errors`**. El hook del core
   `rest_cookie_check_errors()` está enganchado con **prioridad 100**;
   el de Elementor con **prioridad 0** → corre primero.
3. Para el endpoint de telemetría de Elementor la intención era: "si la
   petición es hacia mi propio proxy, no exijas nonce" (el editor mide y ya).
   El problema es cuándo se evalúa: **antes del routing**, cuando WordPress
   todavía no sabe qué ruta se ha pedido. Solo queda inspeccionar el URI crudo
   — y el URI crudo incluye la query string, controlada por el atacante.
4. Con `elementor/v1/events/` en cualquier posición del URI, Elementor
   devuelve `true`. En la prioridad 100, `rest_cookie_check_errors()` ve
   `$result` no vacío y **retorna antes de validar el nonce `wp_rest`**.
   (En condiciones normales, sin nonce válido, el core hace
   `wp_set_current_user( 0 )`: ese downgrade a anónimo es la única defensa
   CSRF del REST API autenticado por cookies.)
5. Resultado: la petición navega autenticada como el admin **sin nonce**.
   Cualquier endpoint cuyo `permission_callback` solo mire
   `current_user_can()` queda expuesto a CSRF — rutas del core **y de
   cualquier plugin**.

La subcadena ni siquiera necesita ser un parámetro real ni estar anclada:

```
/wp-json/wp/v2/users?zzz=elementor/v1/events/          ✓ pasa
/wp-json/wp/v2/users?elementor/v1/events/              ✓ pasa
/wp-json/wp/v2/users?q=foo-elementor/v1/events/-bar    ✓ pasa (¡anidada!)
/otherplugin/v1/x/elementor/v1/events/                 ✓ pasaría (¡en el path!)
```

## El parche (4.3.2)

`diff -u 4.3.1 4.3.2` del archivo (recortado a lo relevante):

```diff
 private function is_own_route_request(): bool {
-    $request_uri = Utils::get_super_global_value( $_SERVER, 'REQUEST_URI' ) ?? '';
+    global $wp;

-    return false !== strpos( $request_uri, self::API_NAMESPACE . '/' . self::API_BASE . '/' );
+    $route = $wp->query_vars['rest_route'] ?? null;
+
+    if ( ! is_string( $route ) ) {
+        return false;
+    }
+
+    return 0 === strpos( $route, '/' . self::API_NAMESPACE . '/' . self::API_BASE . '/' );
 }
```

Tres movimientos, uno principal y dos refuerzos:

1. **Fuente de verdad**: en lugar del `REQUEST_URI` crudo (que arrastra la
   query string del atacante), lee `$wp->query_vars['rest_route']` — la ruta
   REST **ya resuelta por el router de WP**, sin parámetros. La cadena mágica
   ya no puede viajar en la URL.
2. **Anclaje**: `0 === strpos(...)` (empieza por) en vez de
   `false !== strpos(...)` (contiene). Una ruta ajena tipo
   `/otherplugin/v1/x/elementor/v1/events/` ya no coincide.
3. **Tipado**: guard `is_string()` por si `rest_route` llegara como array.

Hay un segundo cambio en el mismo archivo, de **privacidad** más que de
seguridad: se elimina `'authorization'` de `FORWARDED_REQUEST_HEADERS` (el
proxy dejaba de reenviar a Mixpanel la cabecera `Authorization` de la petición
original — una fuga de credenciales hacia un tercero) y en su lugar se
construye un `Authorization` propio del proxy con el token de Mixpanel.

## Condiciones de exposición (quién es vulnerable en la realidad)

El módulo pertenece a un *experimento* oculto de Elementor
(`core/common/modules/events-manager/module.php`):

```php
'default' => Experiments_Manager::STATE_INACTIVE,   // sitios que ACTUALIZARON
'new_site' => [
    'default_active' => true,                        // instalaciones NUEVAS
    'minimum_installation_version' => '3.32.0',
],
'hidden' => true,                                    // invisible en la UI
```

`install_compare()` con historial de instalaciones vacío (instalación limpia)
compara la versión **actual**: cualquier sitio instalado con Elementor ≥ 3.32.0
tiene el experimento **activo por defecto**. De ahí los ~2M de sitios de los
10M que usan 4.3.0/4.3.1 según wordpress.org.

Mitigación sin actualizar (paliativa, para completar el análisis):

```bash
wp option update elementor_experiment-editor_events inactive
# (prefijo de opción: Experiments_Manager::OPTION_PREFIX = 'elementor_experiment-')
```
