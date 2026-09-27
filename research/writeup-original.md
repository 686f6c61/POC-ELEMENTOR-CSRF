# writeup-original.md — Fuentes públicas de la vulnerabilidad

Este laboratorio replica y verifica con ejecución real un hallazgo público
reportado por **Saggre** vía **Patchstack**. Nada de lo que hay aquí es un
descubrimiento propio: la aportación del repo es la réplica verificable en
contenedores, el control negativo de una sola variable y el análisis forense
del parche.

## Cronología pública

| Fecha | Evento |
|---|---|
| 2026-09-01 | Se publica Elementor 4.3.1 (el módulo Editor Events ya venía de 4.3.0) |
| 2026-09-22 | Saggre reporta el fallo a Patchstack |
| 2026-09-24 | Elementor publica el parche 4.3.2 |
| 2026-09-25 | Advisory público de Patchstack (CVSS 8.8) |
| 2026-09-26 | Este laboratorio |

## Fuentes

1. **elhacker.net** — «Vulnerabilidad en Elementor para WordPress permite
   tomar el control de sitios con un solo clic» (noticia que motivó el lab):
   <https://blog.elhacker.net/2026/09/vulnerabilidad-en-elementor-para.html>
2. **Patchstack** — «Cross-Site Request Forgery in Elementor Plugin Affecting
   2 Million Sites» (análisis técnico original):
   <https://patchstack.com/articles/cross-site-request-forgery-in-elementor-plugin-affecting-2-million-sites>
3. **BleepingComputer** — cobertura de la noticia:
   <https://www.bleepingcomputer.com/news/security/elementor-wordpress-flaw-lets-attackers-create-admin-accounts>
4. Zips oficiales de wordpress.org empleados para el análisis estático
   (hashes en [PARCHE.md](PARCHE.md)).

## Lo que dicen las fuentes (resumen fiel)

- Afecta **solo** a Elementor 4.3.0 y 4.3.1; corregido en 4.3.2. Sin CVE
  asignado aún en el momento del lab.
- El módulo **Editor Events** (proxy de telemetría hacia Mixpanel) registra
  un filtro sobre `rest_authentication_errors` con prioridad 0 que devuelve
  `true` si el **URI crudo** de la petición contiene la subcadena
  `elementor/v1/events/`. Al evaluarse antes del routing, la única fuente
  disponible es el URI sin procesar, que incluye la query string controlada
  por el atacante.
- Consecuencia: `rest_cookie_check_errors()` (core, prioridad 100) retorna
  antes de validar el nonce `wp_rest`, y la petición viaja autenticada por
  cookies **sin la única defensa CSRF del REST API**.
- Impacto demostrado por Patchstack: `GET /wp-json/wp/v2/users?_method=POST&...&<algo>=elementor/v1/events/`
  crea una cuenta **administrator**. Un solo clic; sin JavaScript, sin
  formulario, sin web atacante.
- Exposición: hasta ~2M de sitios (de los 10M que usan Elementor) porque el
  módulo es un experimento oculto **activo por defecto en instalaciones
  nuevas** (desde 3.32.0).

## Qué añade este repo sobre las fuentes

- Reproducción **end-to-end verificada** en contenedores (401 → 201 → admin
  persistente → login real), con evidencia en [RESULTADOS.md](RESULTADOS.md).
- **Control negativo de una sola variable**: misma imagen WP, mismo PHP,
  mismo experimento activo; solo cambia Elementor 4.3.1 → 4.3.2 y el mismo
  enlace muere en 401.
- Verificación de que la subcadena **anidada** en otro parámetro
  (`q=foo-elementor/v1/events/-bar`) también dispara el bypass en rutas de
  lectura (`/wp/v2/settings` 401→200).
- Confirmación estática de que 4.3.0 y 4.3.1 llevan el archivo vulnerable
  **byte a byte idéntico**.
- Forense del parche completo (los tres cambios, incluido el de privacidad
  del header `Authorization`) en [PARCHE.md](PARCHE.md).
- **Tres aportaciones propias** ([HALLAZGOS.md](HALLAZGOS.md)): §1 «puerta
  silenciosa» (application password en la cuenta del admin, persistencia sin
  usuarios nuevos), §2 «escalada de cuenta dormida» (subscriber →
  administrator sin altas) y §3 hardening anti-CSRF neutralizado (los
  plugins que bloquean cookies-sin-nonce en `rest_authentication_errors`
  quedan silenciados por la prioridad 0 del filtro de Elementor).
- Cuantificación de la superficie: 154 endpoints de escritura en 231 rutas
  REST de una instalación base.
