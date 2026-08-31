<?php
namespace AegisGuard\Security;

use AegisGuard\Core\Logger;
use AegisGuard\Support\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Hardening {
	public static function register() {
		if ( Settings::get( 'disable_pingbacks', true ) ) {
			add_filter( 'xmlrpc_methods', array( __CLASS__, 'remove_pingback_methods' ) );
			add_filter( 'wp_headers', array( __CLASS__, 'remove_pingback_header' ) );
		}
		if ( Settings::get( 'disable_xmlrpc', false ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', array( __CLASS__, 'disable_xmlrpc_methods' ), PHP_INT_MAX );
		}
		if ( Settings::get( 'protect_user_enumeration', true ) ) {
			add_filter( 'rest_pre_dispatch', array( __CLASS__, 'restrict_rest_user_endpoints' ), 10, 3 );
			add_action( 'template_redirect', array( __CLASS__, 'block_author_enumeration' ), 1 );
		}
		if ( Settings::get( 'disable_file_editor', true ) ) {
			add_filter( 'map_meta_cap', array( __CLASS__, 'deny_file_editor_capabilities' ), 10, 4 );
		}
		if ( Settings::get( 'security_headers', true ) ) {
			add_action( 'send_headers', array( __CLASS__, 'send_security_headers' ) );
		}
		add_filter( 'the_generator', '__return_empty_string' );
		remove_action( 'wp_head', 'wp_generator' );
		add_action( 'init', array( __CLASS__, 'enforce_lockdown' ), 0 );
		add_filter( 'rest_pre_dispatch', array( __CLASS__, 'enforce_rest_lockdown' ), 1, 3 );
	}

	public static function disable_xmlrpc_methods( $methods ) {
		unset( $methods );
		return array();
	}

	public static function remove_pingback_methods( $methods ) {
		unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
		return $methods;
	}

	public static function remove_pingback_header( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	public static function restrict_rest_user_endpoints( $result, $server, $request ) {
		unset( $server );
		$route = $request instanceof \WP_REST_Request ? $request->get_route() : '';
		if ( ! preg_match( '#^/wp/v2/users(?:/|$)#', $route ) ) {
			return $result;
		}
		if ( is_user_logged_in() ) {
			return $result;
		}
		return new \WP_Error( 'rest_no_route', __( 'No route was found matching the URL and request method.', 'aegisguard-security' ), array( 'status' => 404 ) );
	}

	public static function block_author_enumeration() {
		if ( is_admin() || is_user_logged_in() || ! isset( $_GET['author'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only request inspection.
			return;
		}
		$author = sanitize_text_field( wp_unslash( $_GET['author'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only request inspection.
		if ( ctype_digit( $author ) ) {
			status_header( 404 );
			nocache_headers();
			exit;
		}
	}

	public static function deny_file_editor_capabilities( $caps, $cap, $user_id, $args ) {
		unset( $user_id, $args );
		if ( in_array( $cap, array( 'edit_plugins', 'edit_themes' ), true ) ) {
			return array( 'do_not_allow' );
		}
		return $caps;
	}

	public static function send_security_headers() {
		if ( headers_sent() ) {
			return;
		}
		header( 'X-Content-Type-Options: nosniff' );
		header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		header( 'X-Frame-Options: SAMEORIGIN' );
		if ( is_ssl() ) {
			header( 'Strict-Transport-Security: max-age=31536000' );
		}
	}


	public static function enforce_rest_lockdown( $result, $server, $request ) {
		unset( $server, $request );
		if ( ! get_option( 'aegisguard_lockdown', false ) ) {
			return $result;
		}
		if ( Settings::get( 'lockdown_allow_admins', true ) && current_user_can( 'manage_options' ) ) {
			return $result;
		}
		return new \WP_Error( 'aegisguard_lockdown', __( 'This site is temporarily in security lockdown mode.', 'aegisguard-security' ), array( 'status' => 503 ) );
	}

	public static function enforce_lockdown() {
		if ( ! get_option( 'aegisguard_lockdown', false ) ) {
			return;
		}
		if ( is_admin() && Settings::get( 'lockdown_allow_admins', true ) && current_user_can( 'manage_options' ) ) {
			return;
		}
		if ( wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}
		if ( is_admin() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			Logger::log( 'security.lockdown_block', 'Request blocked by emergency lockdown.', 'high' );
			wp_die( esc_html__( 'This site is temporarily in security lockdown mode.', 'aegisguard-security' ), esc_html__( 'Security Lockdown', 'aegisguard-security' ), array( 'response' => 503 ) );
		}
	}
}
