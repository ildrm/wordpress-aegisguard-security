<?php
namespace AegisGuard\Security;

use AegisGuard\Core\Logger;
use AegisGuard\Support\Request;
use AegisGuard\Support\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class RuntimeFirewall {
	public static function preflight() {
		if ( ! function_exists( 'get_option' ) || ! Settings::get( 'waf_enabled', true ) ) {
			return;
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return;
		}

		$ip = Request::ip();
		if ( self::is_temporarily_blocked( $ip ) ) {
			self::deny( 'Temporary firewall block', 'high', array( 'reason' => 'active_ip_block' ) );
		}

		$request = self::request_sample();
		$result  = self::analyze( $request );
		$mode    = Settings::get( 'waf_mode', 'balanced' );
		$cutoff  = 'strict' === $mode ? 5 : 7;
		$blocks  = in_array( $mode, array( 'balanced', 'strict' ), true ) && $result['score'] >= $cutoff;

		if ( $result['score'] > 0 && 'learning' !== $mode && get_option( 'aegisguard_db_version', false ) ) {
			Logger::log(
				'security.waf_match',
				'Firewall pattern match detected.',
				$result['score'] >= 7 ? 'high' : 'medium',
				array(
					'score'   => $result['score'],
					'rules'   => implode( ',', $result['rules'] ),
					'blocked' => $blocks ? 'yes' : 'no',
				)
			);
		}

		if ( $blocks ) {
			self::add_temporary_block( $ip, Settings::get( 'block_duration', 1800 ) );
			self::deny( 'Request blocked by AegisGuard Security.', 'high', array( 'rules' => $result['rules'] ) );
		}
	}

	private static function request_sample() {
		$method = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
		$uri    = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '/';
		$query  = isset( $_SERVER['QUERY_STRING'] ) ? (string) wp_unslash( $_SERVER['QUERY_STRING'] ) : '';
		$agent  = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) : '';
		$content_type = isset( $_SERVER['CONTENT_TYPE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['CONTENT_TYPE'] ) ) ) : '';
		$body = '';
		if ( in_array( $method, array( 'POST', 'PUT', 'PATCH' ), true ) && false === strpos( $content_type, 'multipart/form-data' ) ) {
			$raw_body = file_get_contents( 'php://input', false, null, 0, 32768 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Bounded read of the current request body for WAF inspection.
			$body = is_string( $raw_body ) ? $raw_body : '';
		}

		return substr( $method . "\n" . $uri . "\n" . $query . "\n" . $agent . "\n" . $body, 0, 49152 );
	}

	private static function analyze( $raw ) {
		$decoded = rawurldecode( html_entity_decode( strtolower( (string) $raw ), ENT_QUOTES, 'UTF-8' ) );
		$rules   = array();
		$score   = 0;
		$checks  = array(
			'sqli_union'      => array( '/\bunion\s+(?:all\s+)?select\b/i', 5 ),
			'sqli_timing'     => array( '/\b(?:sleep|benchmark)\s*\(/i', 4 ),
			'sqli_metadata'   => array( '/\binformation_schema\b/i', 4 ),
			'sqli_boolean'    => array( "/(?:'|%27)\s*(?:or|and)\s+['\"0-9]+\s*=\s*['\"0-9]+/i", 4 ),
			'xss_script'      => array( '/<\s*script\b|%3c\s*script\b/i', 5 ),
			'xss_js_protocol' => array( '/javascript\s*:/i', 4 ),
			'xss_event'       => array( '/\bon(?:error|load|click|mouseover)\s*=/i', 3 ),
			'traversal'       => array( '/(?:\.\.\/|\.\.\\\\|%2e%2e(?:%2f|\/))/i', 4 ),
			'php_wrapper'     => array( '/(?:php|data|expect):\/\//i', 5 ),
			'php_exec'        => array( '/\b(?:eval|assert|base64_decode|gzinflate)\s*\(/i', 4 ),
			'sensitive_file'  => array( '#/(?:\.env(?:\.|$)|\.git/|wp-config\.php\.(?:bak|old|save)|id_rsa|database\.sql)#i', 5 ),
			'shell_meta'      => array( '/(?:;|\|\||&&)\s*(?:curl|wget|bash|sh|nc|python|perl)\b/i', 5 ),
			'scanner_agent'    => array( '/\b(?:sqlmap|nikto|nuclei|acunetix|nessus|wpscan)\b/i', 4 ),
		);

		foreach ( $checks as $name => $check ) {
			if ( preg_match( $check[0], $decoded ) ) {
				$rules[] = $name;
				$score  += $check[1];
			}
		}

		return array( 'score' => $score, 'rules' => $rules );
	}

	private static function is_temporarily_blocked( $ip ) {
		return false !== get_transient( 'aegisguard_ipblock_' . hash( 'sha256', $ip ) );
	}

	private static function add_temporary_block( $ip, $duration ) {
		set_transient( 'aegisguard_ipblock_' . hash( 'sha256', $ip ), 1, max( 60, (int) $duration ) );
	}

	private static function deny( $message, $severity, $context ) {
		if ( get_option( 'aegisguard_db_version', false ) ) {
			Logger::log( 'security.waf_block', $message, $severity, $context );
		}
		status_header( 403 );
		nocache_headers();
		header( 'Content-Type: text/plain; charset=utf-8' );
		exit( esc_html( $message ) );
	}
}
