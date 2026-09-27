<?php
/**
 * Plugin Name: Lab REST Hardening (demo)
 * Description: Hardening de demostración del laboratorio: REST solo con
 *              Application Password (Authorization: Basic) o nonce válido.
 *              Es la contramedida canónica contra el CSRF sobre REST que
 *              publican varios plugins de seguridad. El bypass de Elementor
 *              (prioridad 0 sobre el mismo filtro) la neutraliza.
 *              Ver research/HALLAZGOS.md §3 y exploit/07_hardening_bypass.sh.
 * Version: 1.0
 * Author: 686f6c61 (lab)
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

add_filter(
	'rest_authentication_errors',
	function ( $result ) {
		// Patrón de coexistencia estándar: si otro filtro ya fijó un veredicto
		// (no vacío), no pisarlo. Elementor devuelve `true` con prioridad 0:
		// al llegar aquí el hardening ya está neutralizado. Ese es el punto
		// demostrativo de este mu-plugin.
		if ( ! empty( $result ) ) {
			return $result;
		}

		// Se permite REST con Application Passwords (Basic)...
		if ( isset( $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'] ) ) {
			return $result;
		}

		// ...o con un nonce REST válido (cabecera o query).
		if ( isset( $_SERVER['HTTP_X_WP_NONCE'] ) || isset( $_REQUEST['_wpnonce'] ) ) {
			return $result;
		}

		// Resto de casos — cookies sin nonce — denegado: exactamente la clase
		// de petición CSRF que este hardening existe para bloquear.
		return new WP_Error(
			'rest_cookie_disabled',
			'Autenticación por cookies deshabilitada en REST (hardening del lab).',
			array( 'status' => 401 )
		);
	}
);
