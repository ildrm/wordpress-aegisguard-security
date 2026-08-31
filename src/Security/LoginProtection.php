<?php
namespace AegisGuard\Security;

use AegisGuard\Core\Logger;
use AegisGuard\Support\Request;
use AegisGuard\Support\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class LoginProtection {
	public static function register() {
		add_action( 'login_form', array( __CLASS__, 'honeypot_field' ), 5 );
		add_filter( 'authenticate', array( __CLASS__, 'honeypot_check' ), 35, 3 );
		add_filter( 'authenticate', array( __CLASS__, 'rate_limit_authentication' ), 40, 3 );
		add_action( 'wp_login_failed', array( __CLASS__, 'record_failure' ), 10, 2 );
		add_action( 'wp_login', array( __CLASS__, 'record_success' ), 10, 2 );
		add_filter( 'wp_login_errors', array( __CLASS__, 'generic_login_errors' ), 10, 2 );
	}


	public static function honeypot_field() {
		?>
		<div style="position:absolute;left:-10000px;width:1px;height:1px;overflow:hidden" aria-hidden="true">
			<label for="aegisguard_company_url"><?php esc_html_e( 'Company URL', 'aegisguard-security' ); ?></label>
			<input type="text" name="aegisguard_company_url" id="aegisguard_company_url" value="" tabindex="-1" autocomplete="off">
		</div>
		<?php
	}

	public static function honeypot_check( $user, $username, $password ) {
		unset( $username, $password );
		$trap = isset( $_POST['aegisguard_company_url'] ) ? sanitize_text_field( wp_unslash( $_POST['aegisguard_company_url'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Login request has no authenticated nonce context.
		if ( '' !== $trap ) {
			Logger::log( 'security.login_honeypot', 'Automated login honeypot was triggered.', 'high' );
			return new \WP_Error( 'aegisguard_invalid_credentials', __( 'The login details are invalid.', 'aegisguard-security' ) );
		}
		return $user;
	}

	public static function rate_limit_authentication( $user, $username, $password ) {
		unset( $password );
		if ( ! Settings::get( 'login_rate_limit', true ) || empty( $username ) ) {
			return $user;
		}
		$key      = self::key( $username );
		$ip_key   = self::ip_key();
		$data     = get_transient( $key );
		$ip_data  = get_transient( $ip_key );
		$limit    = (int) Settings::get( 'login_attempts', 8 );
		$ip_limit = max( 20, $limit * 4 );
		$identity_limited = is_array( $data ) && ! empty( $data['count'] ) && (int) $data['count'] >= $limit;
		$ip_limited       = is_array( $ip_data ) && ! empty( $ip_data['count'] ) && (int) $ip_data['count'] >= $ip_limit;
		if ( $identity_limited || $ip_limited ) {
			Logger::log( 'security.login_rate_limited', 'Login attempt rate-limited.', 'high', array( 'username_hash' => hash( 'sha256', strtolower( $username ) ), 'scope' => $ip_limited ? 'ip' : 'identity_ip' ) );
			return new \WP_Error( 'aegisguard_rate_limited', __( 'Too many login attempts. Please try again later.', 'aegisguard-security' ) );
		}
		return $user;
	}

	public static function record_failure( $username, $error = null ) {
		if ( ! Settings::get( 'login_rate_limit', true ) ) {
			return;
		}
		$key      = self::key( $username );
		$ip_key   = self::ip_key();
		$data     = get_transient( $key );
		$ip_data  = get_transient( $ip_key );
		$count    = is_array( $data ) && isset( $data['count'] ) ? (int) $data['count'] : 0;
		$ip_count = is_array( $ip_data ) && isset( $ip_data['count'] ) ? (int) $ip_data['count'] : 0;
		$count++;
		$ip_count++;
		$window = (int) Settings::get( 'login_window', 900 );
		set_transient( $key, array( 'count' => $count ), $window );
		set_transient( $ip_key, array( 'count' => $ip_count ), $window );
		Logger::log(
			'security.login_failed',
			'Failed login attempt.',
			$count >= (int) Settings::get( 'login_attempts', 8 ) ? 'high' : 'medium',
			array(
				'username_hash' => hash( 'sha256', strtolower( (string) $username ) ),
				'failure_count' => $count,
			)
		);
	}

	public static function record_success( $user_login, $user ) {
		delete_transient( self::key( $user_login ) );
		delete_transient( self::ip_key() );
		Logger::log( 'auth.login_success', 'User logged in.', 'info', array( 'user_id' => $user->ID ) );
	}

	public static function generic_login_errors( $errors, $redirect_to ) {
		unset( $redirect_to );
		if ( ! Settings::get( 'protect_user_enumeration', true ) || ! ( $errors instanceof \WP_Error ) ) {
			return $errors;
		}
		$credential_codes = array( 'invalid_username', 'invalid_email', 'incorrect_password' );
		$replace = false;
		foreach ( $credential_codes as $code ) {
			if ( $errors->get_error_message( $code ) ) {
				$errors->remove( $code );
				$replace = true;
			}
		}
		if ( $replace ) {
			$errors->add( 'aegisguard_invalid_credentials', __( 'The login details are invalid.', 'aegisguard-security' ) );
		}
		return $errors;
	}


	private static function ip_key() {
		return 'aegisguard_login_ip_' . hash_hmac( 'sha256', Request::ip(), wp_salt( 'auth' ) );
	}

	private static function key( $username ) {
		$identity = strtolower( trim( (string) $username ) ) . '|' . Request::ip();
		return 'aegisguard_login_' . hash_hmac( 'sha256', $identity, wp_salt( 'auth' ) );
	}
}
