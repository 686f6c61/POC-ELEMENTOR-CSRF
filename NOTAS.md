# NOTAS.md — Proceso de construcción del laboratorio

Cuaderno de bitácora, estilo forense: qué se hizo, qué falló y qué se aprendió.

## 1. Investigación previa (antes de escribir una línea)

1. Leído el artículo de elhacker.net que motiva el lab y el advisory original
   de Patchstack. Datos duros: 4.3.0/4.3.1, parche 4.3.2, módulo Editor Events,
   filtro `rest_authentication_errors`, subcadena `elementor/v1/events/` en el
   URI crudo, resultado = admin por un clic. Sin CVE aún.
2. Descargados los tres zips oficiales de wordpress.org y verificado:
   - El archivo vulnerable es idéntico byte a byte en 4.3.0 y 4.3.1.
   - Diff 4.3.1→4.3.2 del archivo: 3 cambios (ruta resuelta vs URI crudo,
     strpos anclado, guard is_string) + 1 de privacidad (dejan de reenviar
     el header `Authorization` de la petición original a Mixpanel).
3. Trazado el registro del módulo: `core/common/app.php` → componente
   `events-manager` solo si el experimento `editor_events` está activo.
   El experimento es `hidden` y su default depende de si el sitio es
   "nuevo" (instalado con ≥ 3.32.0, activo) o "viejo" (actualizado, inactivo).
   Con historial de instalaciones vacío, `install_compare()` compara la
   versión actual ⇒ **instalación limpia = experimento activo**. Decisión de
   diseño: el lab instala Elementor desde cero para reproducir exactamente
   la condición de los ~2M de sitios reales.

## 2. Diseño del experimento

- Misma imagen WordPress para víctima y control (`wordpress:7.1-php8.3-apache`,
  WP 7.1.2, PHP 8.3.35): la **única variable** es la versión de Elementor.
  (En el lab de CVE-2026-93485 la variable era el core; aquí el core es
  inocente y conviene dejarlo clavado.)
- Puertos 8085 (víctima) / 8086 (control) / 8095 (landing): 8080 y 8081
  estaban ocupados en el anfitrión por otros proyectos (minerva-web).
- Permalinks `/%postname%/` para que el ataque use `/wp-json/...` tal cual
  el writeup (con permalinks planos habría que usar `?rest_route=`).

## 3. Incidencias y arreglos (lo interesante)

### 3.1 `gosu: not found`
La imagen oficial de WordPress ya no embarca `gosu`; su entrypoint oficial
corre como root y Apache se degrada solo (`APACHE_RUN_USER`). Arreglado:
WP-CLI con `--allow-root` y `chown -R www-data:www-data wp-content` tras
instalar.

### 3.2 `docker-entrypoint.sh true` no copiaba WordPress
El entrypoint oficial envuelve TODA su lógica (copiar core + generar
wp-config) en `if [[ "$1" == apache2* ]] || "$1" == php-fpm`. Llamarlo con
`true` se saltaba el bloque entero y WP-CLI se encontraba un `/var/www/html`
sin core ("This does not seem to be a WordPress installation"). Arreglado:
el entrypoint del lab replica el bootstrap él mismo (`cp -a
/usr/src/wordpress/. .` + `wp core config`) y termina con
`exec docker-entrypoint.sh apache2-foreground`.

### 3.3 El detalle más sutil de TODO el lab: `%2F` mata el payload
`urllib.parse.urlencode` escapa `/` como `%2F`. El código vulnerable hace
`strpos($_SERVER['REQUEST_URI'], 'elementor/v1/events/')` sobre el URI
**crudo**: si la subcadena viaja como `elementor%2Fv1%2Fevents%2F`, NO
coincide y el bypass no dispara. Curiosamente es un mini-freno accidental
que solo existe si el generador del atacante sobre-codifica; el PoC de
fase 3 construye la URL a mano y siempre dispara. Arreglado en
`02_craft_link.py` y `cli/poc.py` con `urlencode(..., safe='/',
quote_via=quote)` y documentado en el propio código.

### 3.4 `wp/v1/settings` → 404
La ruta de settings del core es `/wp/v2/settings`. (La confusión venía del
resumen del advisory.) Con la ruta correcta, la variante de subcadena
anidada funciona: 401 → 200 filtrando el email del admin.

### 3.5 WP-CLI dentro del contenedor
Sin `--allow-root` WP-CLI se niega a correr (el contenedor corre root).
Añadido a los cuatro puntos donde se usa (`04_verificar_admin.sh`,
`make reset`, entrypoint).

### 3.6 Escape del namespace en el índice /wp-json/
El JSON llega con barras escapadas (`"elementor\/v1"`); el grep inicial
(`'"elementor/v1"'`) no casaba. Arreglado con un patrón que tolera `\/`.

## 4. Resultado de las ejecuciones (detallado en research/RESULTADOS.md)

| Prueba | Víctima 4.3.1 | Control 4.3.2 |
|---|---|---|
| GET create-user sin subcadena | 401 | 401 |
| GET create-user con subcadena | **201, admin creado** | **401** |
| /wp/v2/settings con subcadena anidada | **200** (filtra email admin) | 401 |
| Login de csrfadmin + /wp-admin/users.php | 200 | (usuario nunca creado) |

## 5. Decisiones de seguridad del propio repo

- El CLI (`cli/poc.py`) y el generador de enlaces se **niegan a operar fuera
  de localhost/127.0.0.1/::1** y solo aceptan http/https.
- Las fases invasivas exigen `--acepta-responsabilidad` (fricción deliberada,
  heredada del lab CVE-2026-93485).
- `make reset` borra la puerta trasera; `make clean` destruye todo el lab.
- Nada de esto sirve "tal cual" contra un sitio real sin adaptarlo, y
  adaptarlo está explícitamente fuera del alcance y del aviso de uso
  responsable del README.

## 6. Segunda jornada (2026-09-26, tarde): búsqueda de vectores propios

Metodología: sonda de 9 hipótesis (`research/investigacion/sonda_vectores.sh`)
contra la víctima viva + control 4.3.2 para cada positivo. Resultado: **3
vectores confirmados** (HALLAZGOS §1-§3), 2 negativos útiles, 4 detalles
forenses.

### 6.1 La «puerta silenciosa» nació de un 501

Primera sonda del vector app-password: HTTP **501**
`application_passwords_disabled`. Causa: los Application Passwords exigen
HTTPS (o `WP_ENVIRONMENT_TYPE=local`). Decisión de diseño: definir la
constante en víctima Y control (mantiene la variable única) para replicar la
condición de producción. Con esa condición: **201 con la contraseña en
claro**, y la credencial funciona por Basic sin nonce para siempre.
Lección defensiva: borrar «usuarios malos» tras un incidente NO basta; hay
que revocar app-passwords.

### 6.2 La «cuenta dormida» nació de pensar en EVIDENCIA, no en acceso

El vector canónico deja un usuario NUEVO con fecha de alta reciente. Pregunta
de investigación: ¿puede el clic lograr persistencia sin dejar altas?
Respuesta: promover una cuenta existente (`_method=POST` sobre
`/wp/v2/users/{id}` con `roles[]`). Menos ruido forense que el canónico.

### 6.3 El hardening neutralizado nació de releer una línea del advisory

Patchstack menciona de pasada que el bypass «también salta plugins de
seguridad que usan el mismo filtro». Lo verificamos empíricamente con un
mu-plugin canónico: la cláusula de coexistencia
(`if (!empty($result)) return $result;`) que usan los plugins REALES es
exactamente lo que el filtro de Elementor (prioridad 0) desarma. Es la
aportación más defensiva del repo: demuestra que la mitigación habitual
«bloquear cookies-sin-nonce» NO protege contra este CVE.

### 6.4 Negativos útiles

- `/wp/v2/settings` no expone `users_can_register` ni `default_role`: la vía
  «un clic activa registro libre con rol admin» no existe por REST (el
  schema del core no publica esos campos).
- Ningún bypass del parche: los tres vectores propios devuelven 401 contra
  4.3.2.

### 6.5 Incidencias de la jornada

- **302 transitorio en la fase 4**: en la primera pasada de `make full-demo`
  tras el rebuild, `GET /wp-admin/users.php` como csrfadmin devolvió 302
  (redirección a login) una sola vez — la fase 4 corre a los pocos segundos
  de crear el usuario en la fase 3. Reejecutada a mano e integrada en pasadas
  siguientes: 200 sistemático. Se anota por honestidad forense; no afecta a
  la evidencia (el ground truth WP-CLI y la autovverificación REST de la
  misma fase dieron `administrator`).
- El hook de seguridad del entorno bloqueó escribir scripts por heredoc de
  bash y exigir `subprocess` sin shell en Python: `scripts/capturas/terminal.py`
  acabó como generador HTML puro por stdin/stdout y la rasterización con
  Chrome la hace `generar.sh` (bash). Resultado igual de bonito y más simple.
- Los `<pre>` bilingües de la landing se escribieron mal anidados la primera
  vez (atributos `data-*` multi-línea tras un `</pre>`): detectado revisando
  el HTML parseado + capturas de ambos idiomas; corregidos y validados.

### 6.6 Credenciales de la puerta trasera configurables (petición de usuario)

El CLI ya admitía `--username/--password/--email` desde el principio, pero la
cadena no era consistente: las fases de shell usaban valores fijos y una
contraseña con `&`/espacios habría roto la URL (se interpolaba sin codificar).
Cambio: `03_click_victim.sh` construye la query con `urlencode` de python3
(`safe='/'` para que la subcadena mágica siga viajando literal) y el Makefile
expone `USUARIO`/`CLAVE`/`EMAIL` (exportadas como `POC_USER/POC_PASS/POC_MAIL`
a los scripts). Verificado end-to-end con `USUARIO=sombra CLAVE='Mi P@ss&2026
!x'`: 201 → login real 200 → REST roles administrator → `make reset USUARIO=sombra`.

## 6-tercera. Tercera jornada (2026-09-26, noche): 7 mejoras + CTF

Petición: mejorar evidencia, robustez y alcance, y montar un CTF. Resumen
de lo hecho y de lo aprendido (detalle en HALLAZGOS §5-§8 y RESULTADOS):

### 6.7 El hallazgo grande: WooCommerce (§5)

La hipótesis venía de §3: si el bypass silencia a cualquier consumidor de
`rest_authentication_errors` con cláusula de coexistencia, y WooCommerce
bloquea cookies en wc/v3 por ese filtro... la pared caería. Verificado:
401 → 200 en system_status con WooCommerce 11.1.2 real. La predicción del
mu-plugin casero (§3) resultó ser un caso real del plugin más instalado del
ecosistema. Además, el endpoint de plugins del core también cae: dos
enlaces instalan y activan un plugin de wp.org.

### 6.8 Incidencias de la jornada

- **`docker compose exec` se colgó** a mitad de jornada (los contenedores
  sanos, HTTP ok). Workaround: `docker exec <contenedor>` directo en las
  pruebas manuales; los scripts del repo siguen usando compose exec (funcionó
  durante las fases; si reaparece, reiniciar Docker Desktop).
- **`wp-content/upgrade` propiedad de root**: WP-CLI (--allow-root) crea
  directorios como root y apache (www-data) no puede instalar plugins por
  REST (500 mkdir_failed). Fix: chown en el entrypoint y al final de la
  fase 9.
- **`curl -d "url=...&..."` sin codificar me jugó una mala pasada** al
  probar el bot del CTF: el `&` partía el campo y el bot recibía la URL
  truncada (parecía que el bypass no funcionaba). El sitio estaba bien.
  Lección de testing: `--data-urlencode` SIEMPRE.
- **Firma cambiada en WP 7.1**: `wp_authenticate_application_password()`
  ahora pide `(input_user, username, password)` y en CLI devolvía NULL; el
  verificador de la FLAG 5 usa la comprobación conductual (Basic → 200),
  que es además más fiel al ataque.
- **Puerto 8088 ocupado** en el anfitrión: bot movido a 8089.
- **ffmpeg sin drawtext** (homebrew): el GIF de la demo va sin rótulos.
- **`.PHONY` olvidado** en los targets nuevos del Makefile: el directorio
  `ctf/` eclipsaba el target `ctf` ("up to date").

### 6.9 El CTF «La Subcadena Mágica»

- Instancia aislada (profile `ctf`) en :8087 con **hardening anti-CSRF
  activo desde el arranque**: el primer intento naif devuelve
  `rest_cookie_disabled` y fuerza a descubrir el bypass (la pedagogía de §3
  convertida en puzle).
- **Bot víctima** (:8089, python stdlib): sesión fresca del admin de pruebas por
  visita, guard anti-SSRF (solo http/https + host del reto), respuesta
  recortada a 4 KB, nunca revela cookies.
- 5 flags: recon (readme) · crear TU admin (nick/clave a elección — usa la
  funcionalad configurable del CLI) y leer post privado · settings con
  subcadena anidada · enumeración context=edit · app-password validada
  conductualmente. Resueltas y verificadas 5/5 de punta a punta.

## 7. Pendiente / ideas

- [x] IOCs para blue teams (README §Mitigación, ampliados con §1/§2).
- [ ] Vídeo corto de la demo con navegador real abriendo `correo-phishing.html`
      con la sesión del admin iniciada (la simulación por curl ya cubre el
      comportamiento HTTP equivalente).
- [ ] Explorar blast radius contra plugins concretos con endpoints REST de
      escritura sin nonces propios (los 154 endpoints de la base son solo
      core + Elementor).
