<?php
namespace AegisGuard\Security;

use AegisGuard\Core\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class OutboundMonitor {
	public static function register() {
		add_action( 'http_api_debug', array( __CLASS__, 'observe' ), 10, 5 );
	}

	public static function observe( $response, $context, $transport_class, $parsed_args, $url ) {
		unset( $response, $transport_class, $parsed_args );
		if ( 'response' !== $context || empty( $url ) ) {
			return;
		}
		$host = wp_parse_url( $url, PHP_URL_HOST );
		if ( ! is_string( $host ) || '' === $host ) {
			return;
		}
		$host = strtolower( $host );
		if ( self::is_sensitive_destination( $host ) ) {
			Logger::log( 'security.outbound_sensitive_destination', 'WordPress made an outbound HTTP request to a local, private, or link-local destination.', 'high', array( 'host' => $host ) );
		}
	}

	private static function is_sensitive_destination( $host ) {
		if ( in_array( $host, array( 'localhost', 'metadata.google.internal' ), true ) ) {
			return true;
		}
		if ( ! filter_var( $host, FILTER_VALIDATE_IP ) ) {
			return false;
		}
		return false === filter_var( $host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}
}
