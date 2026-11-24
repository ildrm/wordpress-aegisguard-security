<?php
namespace AegisGuard\Security;

use AegisGuard\Core\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Mfa {
	const SECRET_META          = '_aegisguard_totp_secret';
	const RECOVERY_META        = '_aegisguard_recovery_codes';
	const PENDING_META         = '_aegisguard_totp_pending';
	const COUNTER_PREFIX       = 'aegisguard_mfa_counter_';
	const RECOVERY_LOCK_PREFIX = 'aegisguard_mfa_recovery_lock_';
	public static function register() {
		add_action( 'login_form', array( __CLASS__, 'login_field' ) );
		add_filter( 'authenticate', array( __CLASS__, 'verify_login' ), 50, 3 );
		add_action( 'delete_user', array( __CLASS__, 'cleanup_user' ) );
		add_action( 'wpmu_delete_user', array( __CLASS__, 'cleanup_user' ) );
	}

	public static function login_field() {
		?>
		<p>
			<label for="aegisguard_otp"><?php esc_html_e( 'Authentication or recovery code (if enabled)', 'aegisguard-security' ); ?><br>
				<input type="text" name="aegisguard_otp" id="aegisguard_otp" class="input" autocapitalize="characters" spellcheck="false" autocomplete="one-time-code" maxlength="12" value="">
			</label>
		</p>
		<?php
	}

	public static function verify_login( $user, $username, $password ) {
		unset( $username, $password );
		if ( ! ( $user instanceof \WP_User ) || ! self::is_interactive_login() ) {
			return $user;
		}
		$encrypted = get_user_meta( $user->ID, self::SECRET_META, true );
		if ( empty( $encrypted ) ) {
			return $user;
		}
		$code   = isset( $_POST['aegisguard_otp'] ) ? sanitize_text_field( wp_unslash( $_POST['aegisguard_otp'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Login authentication occurs before a session nonce exists.
		$code   = preg_replace( '/\s+/', '', $code );
		$secret = self::read_user_secret( $user->ID, self::SECRET_META );
		if ( ! $secret ) {
			if ( self::consume_recovery_code( $user->ID, $code ) ) {
				Logger::log( 'auth.mfa_recovery_used', 'MFA recovery code used after secret decryption failure.', 'high', array( 'user_id' => $user->ID ) );
				return $user;
			}
			Logger::log( 'security.mfa_secret_error', 'MFA secret could not be decrypted.', 'high', array( 'user_id' => $user->ID ) );
			return new \WP_Error( 'aegisguard_mfa_unavailable', __( 'Multi-factor authentication is unavailable for this account. Use a recovery code or contact an administrator.', 'aegisguard-security' ) );
		}
		if ( self::verify_and_consume_code( $user->ID, $secret, $code ) ) {
			Logger::log( 'auth.mfa_success', 'MFA challenge passed.', 'info', array( 'user_id' => $user->ID ) );
			return $user;
		}
		if ( self::consume_recovery_code( $user->ID, $code ) ) {
			Logger::log( 'auth.mfa_recovery_used', 'MFA recovery code used.', 'medium', array( 'user_id' => $user->ID ) );
			return $user;
		}
		Logger::log( 'security.mfa_failed', 'MFA challenge failed.', 'high', array( 'user_id' => $user->ID ) );
		return new \WP_Error( 'aegisguard_mfa_required', __( 'A valid authentication or recovery code is required.', 'aegisguard-security' ) );
	}


	public static function begin_setup( $user_id ) {
		if ( self::is_enabled( $user_id ) ) {
			return new \WP_Error( 'already_enabled', __( 'Disable the current authenticator before setting up another one.', 'aegisguard-security' ) );
		}
		$secret    = self::generate_secret();
		$encrypted = self::encrypt( $secret );
		if ( ! $encrypted ) {
			return new \WP_Error( 'encryption_failed', __( 'Could not securely prepare the MFA secret.', 'aegisguard-security' ) );
		}
		if ( ! update_user_meta( $user_id, self::PENDING_META, $encrypted ) ) {
			return new \WP_Error( 'setup_failed', __( 'Could not save the MFA setup key. Try again.', 'aegisguard-security' ) );
		}
		return $secret;
	}

	public static function pending_secret( $user_id ) {
		return self::read_user_secret( $user_id, self::PENDING_META );
	}

	public static function clear_pending( $user_id ) {
		delete_user_meta( $user_id, self::PENDING_META );
	}

	public static function generate_secret() {
		$bytes = random_bytes( 20 );
		return self::base32_encode( $bytes );
	}

	public static function verify_code( $secret, $code, $time = null ) {

		return false !== self::matching_counter( $secret, $code, $time );
	}

	private static function matching_counter( $secret, $code, $time = null ) {

		if ( ! preg_match( '/^\d{6}$/', (string) $code ) ) {
				return false;
		}
		$time    = null === $time ? time() : (int) $time;
		$counter = (int) floor( $time / 30 );
		for ( $offset = -1; $offset <= 1; $offset++ ) {
			if ( hash_equals( self::totp( $secret, $counter + $offset ), (string) $code ) ) {
				return $counter + $offset;
			}
		}
		return false;
	}

	private static function verify_and_consume_code( $user_id, $secret, $code, $time = null ) {

		$counter = self::matching_counter( $secret, $code, $time );
		if ( false === $counter ) {
			return false;
		}
		$encoded = get_user_meta( $user_id, self::SECRET_META, true );
		if ( is_multisite() && preg_match( '/^site:(\d+):/', $encoded, $match ) && get_current_blog_id() !== (int) $match[1] ) {
			switch_to_blog( (int) $match[1] );
			try {
				return self::consume_counter( $user_id, $counter );
			} finally {
				restore_current_blog();
			}
		}
		return self::consume_counter( $user_id, $counter );
	}
	public static function enable_for_user( $user_id, $secret ) {

		$encrypted = self::encrypt( $secret );
		if ( ! $encrypted ) {
			return new \WP_Error( 'encryption_failed', __( 'Could not securely encrypt the MFA secret.', 'aegisguard-security' ) );
		}
		$codes  = self::generate_recovery_codes();
		$hashes = array();
		foreach ( $codes as $code ) {
			$hashes[] = wp_hash_password( $code );
		}
		if ( ! add_user_meta( $user_id, self::SECRET_META, $encrypted, true ) ) {
			return new \WP_Error( 'enable_failed', __( 'MFA could not be enabled. Refresh the page and check the current status.', 'aegisguard-security' ) );
		}
		if ( ! update_user_meta( $user_id, self::RECOVERY_META, $hashes ) ) {
			delete_user_meta( $user_id, self::SECRET_META, $encrypted );
			return new \WP_Error( 'recovery_failed', __( 'Could not save recovery codes. Retry MFA setup.', 'aegisguard-security' ) );
		}
		delete_option( self::counter_option( $user_id ) );
		self::clear_pending( $user_id );
		Logger::log( 'security.mfa_enabled', 'MFA enabled for user.', 'medium', array( 'user_id' => $user_id ) );
		return $codes;
	}

	public static function disable_for_user( $user_id ) {
		self::cleanup_user( $user_id );
		delete_user_meta( $user_id, self::SECRET_META );
		delete_user_meta( $user_id, self::RECOVERY_META );
		self::clear_pending( $user_id );
		Logger::log( 'security.mfa_disabled', 'MFA disabled for user.', 'high', array( 'user_id' => $user_id ) );
	}

	public static function get_secret_for_user( $user_id ) {
		return self::read_user_secret( $user_id, self::SECRET_META );
	}

	public static function is_enabled( $user_id ) {

		return (bool) get_user_meta( $user_id, self::SECRET_META, true );
	}

	public static function cleanup_user( $user_id ) {
		$encoded = get_user_meta( $user_id, self::SECRET_META, true );
		if ( is_multisite() && is_string( $encoded ) && preg_match( '/^site:(\d+):/', $encoded, $match ) && get_current_blog_id() !== (int) $match[1] ) {
			delete_blog_option( (int) $match[1], self::counter_option( $user_id ) );
			delete_blog_option( (int) $match[1], self::recovery_lock_option( $user_id ) );
		}
		delete_option( self::counter_option( $user_id ) );
		delete_option( self::recovery_lock_option( $user_id ) );
	}
	public static function provisioning_uri( $user, $secret ) {
		$issuer = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$label  = $issuer . ':' . $user->user_login;
		return 'otpauth://totp/' . rawurlencode( $label ) . '?secret=' . rawurlencode( $secret ) . '&issuer=' . rawurlencode( $issuer ) . '&algorithm=SHA1&digits=6&period=30';
	}

	private static function is_interactive_login() {
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
			return false;
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return false;
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return false;
		}
		$script = isset( $_SERVER['SCRIPT_NAME'] ) ? basename( sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ) ) ) : '';
		return 'wp-login.php' === $script;
	}

	private static function consume_recovery_code( $user_id, $code ) {

		if ( ! preg_match( '/^[A-Z0-9]{10}$/i', (string) $code ) ) {
			return false;
		}
		$hashes = get_user_meta( $user_id, self::RECOVERY_META, true );
		if ( ! is_array( $hashes ) ) {
			return false;
		}
		foreach ( $hashes as $index => $hash ) {
			if ( wp_check_password( strtoupper( $code ), $hash ) ) {
				$remaining = $hashes;
				unset( $remaining[ $index ] );
				// Only the request that replaces this exact list can consume the code.
				return (bool) update_user_meta( $user_id, self::RECOVERY_META, array_values( $remaining ), $hashes );
			}
		}
		return false;
	}

	private static function consume_counter( $user_id, $counter ) {

		$option_name = self::counter_option( $user_id );
		global $wpdb;
		// The options table's unique name index must elect exactly one initial consumer.
		$inserted = $wpdb->query( $wpdb->prepare( 'INSERT IGNORE INTO %i (option_name, option_value, autoload) VALUES (%s, %s, %s)', $wpdb->options, $option_name, (string) (int) $counter, 'no' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic replay guard.
		if ( 1 === $inserted ) {
			wp_cache_delete( 'notoptions', 'options' );
			return true;
		}
		if ( false === $inserted ) {
			return false;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Conditional update is required for atomic single-use TOTP counter consumption.
		$updated = $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND CAST(option_value AS UNSIGNED) < %d",
				(string) (int) $counter,
				$option_name,
				(int) $counter
			)
		); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- The options table name is supplied by WordPress; all values are prepared.
			wp_cache_delete( $option_name, 'options' );
		return 1 === $updated;
	}

	private static function counter_option( $user_id ) {

			return self::COUNTER_PREFIX . absint( $user_id );
	}

	private static function recovery_lock_option( $user_id ) {

		return self::RECOVERY_LOCK_PREFIX . absint( $user_id );
	}
	private static function generate_recovery_codes() {
		$codes    = array();
		$alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
		for ( $i = 0; $i < 10; $i++ ) {
			$code = '';
			for ( $j = 0; $j < 10; $j++ ) {
				$code .= $alphabet[ random_int( 0, strlen( $alphabet ) - 1 ) ];
			}
			$codes[] = $code;
		}
		return $codes;
	}

	private static function totp( $secret, $counter ) {
		$key            = self::base32_decode( $secret );
		$binary_counter = pack( 'N*', 0 ) . pack( 'N*', $counter );
		$hash           = hash_hmac( 'sha1', $binary_counter, $key, true );
		$offset         = ord( substr( $hash, -1 ) ) & 0x0f;
		$binary         = unpack( 'N', substr( $hash, $offset, 4 ) );
		$value          = ( $binary[1] & 0x7fffffff ) % 1000000;
		return str_pad( (string) $value, 6, '0', STR_PAD_LEFT );
	}

	private static function base32_encode( $data ) {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$bits     = '';
		foreach ( str_split( $data ) as $char ) {
			$bits .= str_pad( decbin( ord( $char ) ), 8, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			$chunk = str_pad( $chunk, 5, '0', STR_PAD_RIGHT );
			$out  .= $alphabet[ bindec( $chunk ) ];
		}
		return $out;
	}

	private static function base32_decode( $data ) {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$data     = strtoupper( preg_replace( '/[^A-Z2-7]/i', '', $data ) );
		$bits     = '';
		foreach ( str_split( $data ) as $char ) {
			$pos = strpos( $alphabet, $char );
			if ( false === $pos ) {
				continue;
			}
			$bits .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 8 ) as $chunk ) {
			if ( strlen( $chunk ) < 8 ) {
				break;
			}
			$out .= chr( bindec( $chunk ) );
		}
		return $out;
	}

	private static function encryption_key() {
		$encoded = get_option( 'aegisguard_mfa_key', '' );
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Binary cryptographic key deserialization, not code obfuscation.
		$key = base64_decode( (string) $encoded, true );
		if ( false !== $key && 32 === strlen( $key ) ) {
			return $key;
		}

		/* Activation normally creates this key. Generate it lazily for repaired/upgraded installs. */
		try {
			$key = random_bytes( 32 );
		} catch ( \Exception $exception ) {
			return false;
		}
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Binary cryptographic key serialization, not code obfuscation.
		if ( add_option( 'aegisguard_mfa_key', base64_encode( $key ), '', false ) ) {
			return $key;
		}
		$encoded = get_option( 'aegisguard_mfa_key', '' );
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Binary cryptographic key deserialization, not code obfuscation.
		$key = base64_decode( (string) $encoded, true );
		return false !== $key && 32 === strlen( $key ) ? $key : false;
	}

	private static function encrypt( $plaintext ) {
		$encoded = self::encrypt_with_site_key( $plaintext );
		return $encoded && is_multisite() ? 'site:' . get_current_blog_id() . ':' . $encoded : $encoded;
	}

	private static function encrypt_with_site_key( $plaintext ) {
		$key = self::encryption_key();
		if ( ! $key ) {
			return false;
		}
		if ( function_exists( 'sodium_crypto_secretbox' ) ) {
			$nonce  = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$cipher = sodium_crypto_secretbox( $plaintext, $nonce, $key );
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Binary authenticated-ciphertext serialization, not code obfuscation.
			return 'sodium:' . base64_encode( $nonce . $cipher );
		}
		if ( function_exists( 'openssl_encrypt' ) ) {
			$iv     = random_bytes( 12 );
			$tag    = '';
			$cipher = openssl_encrypt( $plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );
			if ( false !== $cipher ) {
				// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Binary authenticated-ciphertext serialization, not code obfuscation.
				return 'openssl:' . base64_encode( $iv . $tag . $cipher );
			}
		}
		return false;
	}

	// User metadata is shared across sites, while each encryption key belongs to one site.
	private static function read_user_secret( $user_id, $meta_key ) {
		$encoded = get_user_meta( $user_id, $meta_key, true );
		if ( ! is_string( $encoded ) || '' === $encoded ) {
			return '';
		}
		if ( ! is_multisite() ) {
			return self::decrypt( $encoded );
		}
		$tagged  = preg_match( '/^site:(\d+):(.+)$/', $encoded, $parts );
		$sites   = $tagged ? array( (int) $parts[1] ) : array_unique( array_merge( array( get_current_blog_id() ), array_keys( get_blogs_of_user( $user_id, true ) ) ) );
		$payload = $tagged ? $parts[2] : $encoded;
		// Older records have no site ID. Try the current site's key first.
		foreach ( $sites as $site_id ) {
				$key = get_blog_option( $site_id, 'aegisguard_mfa_key', '' );
			if ( ! $key ) {
				continue;
			}
				// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Stored binary encryption key.
				$secret = self::decrypt( $payload, base64_decode( $key, true ) );
			if ( false !== $secret ) {
				if ( ! $tagged ) {
					update_user_meta( $user_id, $meta_key, 'site:' . $site_id . ':' . $payload, $encoded );
				}
				return $secret;
			}
		}
		return false;
	}

	private static function decrypt( $encoded, $key = null ) {
		$key = null === $key ? self::encryption_key() : $key;
		if ( ! is_string( $key ) || 32 !== strlen( $key ) ) {
			return false;
		}
		if ( 0 === strpos( $encoded, 'sodium:' ) && function_exists( 'sodium_crypto_secretbox_open' ) ) {
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Binary authenticated-ciphertext deserialization, not code obfuscation.
			$raw = base64_decode( substr( $encoded, 7 ), true );
			if ( false === $raw || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
				return false;
			}
			$nonce  = substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$cipher = substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			return sodium_crypto_secretbox_open( $cipher, $nonce, $key );
		}
		if ( 0 === strpos( $encoded, 'openssl:' ) && function_exists( 'openssl_decrypt' ) ) {
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Binary authenticated-ciphertext deserialization, not code obfuscation.
			$raw = base64_decode( substr( $encoded, 8 ), true );
			if ( false === $raw || strlen( $raw ) <= 28 ) {
				return false;
			}
			$iv     = substr( $raw, 0, 12 );
			$tag    = substr( $raw, 12, 16 );
			$cipher = substr( $raw, 28 );
			return openssl_decrypt( $cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );
		}
		return false;
	}
}
