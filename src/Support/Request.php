<?php
namespace AegisGuard\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Request {
	public static function ip() {
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		if ( ! filter_var( $remote, FILTER_VALIDATE_IP ) ) {
			$remote = '0.0.0.0';
		}

		if ( ! Settings::get( 'trust_proxy_headers', false ) ) {
			return $remote;
		}

		$trusted = self::trusted_proxies();
		if ( ! in_array( $remote, $trusted, true ) ) {
			return $remote;
		}

		$forwarded = isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ? wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Each comma-delimited candidate must pass FILTER_VALIDATE_IP before use.
		if ( ! $forwarded ) {
			return $remote;
		}

		/*
		 * Walk the proxy chain from the server backwards. This avoids trusting a
		 * spoofed left-most X-Forwarded-For value when the configured reverse proxy
		 * appends the actual peer address to an existing client-supplied header.
		 */
		$parts   = array_values( array_filter( array_map( 'trim', explode( ',', $forwarded ) ) ) );
		$parts[] = $remote;
		for ( $index = count( $parts ) - 1; $index >= 0; $index-- ) {
			$candidate = $parts[ $index ];
			if ( ! filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
				continue;
			}
			if ( in_array( $candidate, $trusted, true ) ) {
				continue;
			}
			return $candidate;
		}

		return $remote;
	}

	public static function anonymized_ip( $ip = '' ) {
		$ip = $ip ? $ip : self::ip();
		if ( ! Settings::get( 'privacy_ip_anonymization', false ) ) {
			return $ip;
		}
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$parts    = explode( '.', $ip );
			$parts[3] = '0';
			return implode( '.', $parts );
		}
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			$packed = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- inet_pton can emit warnings for malformed input after validation edge cases.
			if ( false !== $packed ) {
				$packed = substr( $packed, 0, 6 ) . str_repeat( "\0", 10 );
				return inet_ntop( $packed );
			}
		}
		return '';
	}

	private static function trusted_proxies() {
		$raw = Settings::get( 'trusted_proxy_ips', '' );
		$ips = preg_split( '/[\r\n,]+/', (string) $raw );
		$out = array();
		foreach ( $ips as $ip ) {
			$ip = trim( $ip );
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				$out[] = $ip;
			}
		}
		return $out;
	}
}
