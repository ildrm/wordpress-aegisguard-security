<?php
namespace AegisGuard\Security;

use AegisGuard\Core\Logger;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Quarantine {
	public static function store( $path ) {

		if ( is_link( $path ) ) {
			return new \WP_Error( 'quarantine_symlink', __( 'Symbolic links cannot be quarantined safely.', 'aegisguard-security' ) );
		}
		$real         = realpath( $path );
		$content_root = realpath( WP_CONTENT_DIR );
		if ( ! $real || ! $content_root || 0 !== strpos( wp_normalize_path( $real ), wp_normalize_path( $content_root ) . '/' ) || 0 === strpos( wp_normalize_path( $real ), wp_normalize_path( AEGISGUARD_DIR ) ) ) {
			return new \WP_Error( 'invalid_path', __( 'The file is outside the allowed quarantine scope.', 'aegisguard-security' ) );
		}
		$size = filesize( $real );
		if ( false === $size || $size > 20 * MB_IN_BYTES ) {
			return new \WP_Error( 'quarantine_size', __( 'The file is too large for safe encrypted quarantine.', 'aegisguard-security' ) );
		}
		$content = file_get_contents( $real ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Confirmed local file is encrypted before quarantine storage.
		if ( ! is_string( $content ) ) {
			return new \WP_Error( 'quarantine_read', __( 'Could not read the file for quarantine.', 'aegisguard-security' ) );
		}
		$relative_path = ltrim( substr( wp_normalize_path( $real ), strlen( wp_normalize_path( $content_root ) ) ), '/' );
		$bundle        = wp_json_encode(
			array(
				'original_path' => $relative_path,
				'original_name' => sanitize_file_name( basename( $real ) ),
				'sha256'        => hash( 'sha256', $content ),
				'captured_at'   => gmdate( 'c' ),
				// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Binary quarantine payload serialization before authenticated encryption.
				'content'       => base64_encode( $content ),
			),
			JSON_UNESCAPED_SLASHES
		);
		if ( ! is_string( $bundle ) ) {
			return new \WP_Error( 'quarantine_bundle', __( 'Could not prepare the quarantine bundle.', 'aegisguard-security' ) );
		}
		$encrypted = self::encrypt_quarantine_payload( $bundle );
		if ( is_wp_error( $encrypted ) ) {
			return $encrypted;
		}

		$dir = WP_CONTENT_DIR . '/aegisguard-quarantine';
		if ( ! wp_mkdir_p( $dir ) ) {
			return new \WP_Error( 'quarantine_dir', __( 'Could not create the quarantine directory.', 'aegisguard-security' ) );
		}
		self::protect_quarantine_dir( $dir );
		$destination = trailingslashit( $dir ) . gmdate( 'Ymd-His' ) . '-' . wp_generate_password( 12, false, false ) . '.agq';
		$record      = wp_json_encode(
			array(
				'format'  => 2,
				'payload' => $encrypted,
			),
			JSON_UNESCAPED_SLASHES
		);
		if ( ! is_string( $record ) || false === file_put_contents( $destination, $record, LOCK_EX ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents,PluginCheck.CodeAnalysis.WriteFile.PluginDirectoryWrite -- Atomic write to the dedicated wp-content quarantine directory, never the plugin directory.
			return new \WP_Error( 'quarantine_write', __( 'Could not write the encrypted quarantine record.', 'aegisguard-security' ) );
		}
		@chmod( $destination, 0600 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Best-effort filesystem hardening after encrypted storage.
		if ( ! unlink( $real ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Confirmed file quarantine requires removing original after successful encrypted copy.
			unlink( $destination ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Roll back duplicate quarantine record if original cannot be removed.
			return new \WP_Error( 'quarantine_remove', __( 'Encrypted copy was created but the original file could not be removed; quarantine was rolled back.', 'aegisguard-security' ) );
		}
		Logger::log(
			'security.file_quarantined',
			'A file was encrypted and moved to quarantine.',
			'high',
			array(
				'file'            => wp_normalize_path( $real ),
				'quarantine_name' => basename( $destination ),
				'sha256'          => hash( 'sha256', $content ),
			)
		);
		return true;
	}

	public static function all() {
		$dir = WP_CONTENT_DIR . '/aegisguard-quarantine';
		if ( ! is_dir( $dir ) ) {
			return array();
		}
		$files = glob( trailingslashit( $dir ) . '*.agq' );
		if ( ! is_array( $files ) ) {
			return array();
		}
		$items = array();
		foreach ( $files as $file ) {
			$bundle = self::read_quarantine_bundle( $file );
			if ( is_wp_error( $bundle ) ) {
				$items[] = array(
					'name'          => basename( $file ),
					'valid'         => false,
					'original_path' => '',
					'captured_at'   => '',
					'sha256'        => '',
				);
				continue;
			}
			$items[] = array(
				'name'          => basename( $file ),
				'valid'         => true,
				'original_path' => (string) $bundle['original_path'],
				'captured_at'   => (string) $bundle['captured_at'],
				'sha256'        => (string) $bundle['sha256'],
			);
		}
		usort(
			$items,
			static function ( $a, $b ) {
				return strcmp( $b['name'], $a['name'] );
			}
		);
		return $items;
	}

	public static function restore( $name ) {
		$path = self::quarantine_record_path( $name );
		if ( is_wp_error( $path ) ) {
			return $path;
		}
		$bundle = self::read_quarantine_bundle( $path );
		if ( is_wp_error( $bundle ) ) {
			return $bundle;
		}
		$relative = wp_normalize_path( (string) $bundle['original_path'] );
		if ( '' === $relative || 0 === strpos( $relative, '/' ) || false !== strpos( $relative, '../' ) || '..' === $relative ) {
			return new \WP_Error( 'quarantine_restore_path', __( 'The encrypted quarantine record contains an invalid original path.', 'aegisguard-security' ) );
		}
		$target       = wp_normalize_path( trailingslashit( WP_CONTENT_DIR ) . $relative );
		$content_root = wp_normalize_path( trailingslashit( WP_CONTENT_DIR ) );
		if ( 0 !== strpos( $target, $content_root ) || 0 === strpos( $target, wp_normalize_path( AEGISGUARD_DIR ) ) ) {
			return new \WP_Error( 'quarantine_restore_scope', __( 'The original path is outside the permitted restore scope.', 'aegisguard-security' ) );
		}
		if ( file_exists( $target ) ) {
			return new \WP_Error( 'quarantine_restore_exists', __( 'Restore refused because a file already exists at the original path.', 'aegisguard-security' ) );
		}
		$parent       = dirname( $target );
		$parent_real  = realpath( $parent );
		$content_real = realpath( WP_CONTENT_DIR );
		if ( ! $parent_real || ! $content_real || 0 !== strpos( wp_normalize_path( $parent_real ), wp_normalize_path( trailingslashit( $content_real ) ) ) || self::path_has_symlink( $parent, $content_real ) || ! is_writable( $parent_real ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Direct atomic local restore requires validating the real destination directory.
			return new \WP_Error( 'quarantine_restore_parent', __( 'The original parent directory does not exist or is not writable.', 'aegisguard-security' ) );
		}
		if ( is_link( $target ) ) {
			return new \WP_Error( 'quarantine_restore_symlink', __( 'Restore refused because the original path is now a symbolic link.', 'aegisguard-security' ) );
		}
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Binary quarantine payload deserialization after authenticated decryption.
		$content = base64_decode( (string) $bundle['content'], true );
		if ( false === $content || ! hash_equals( (string) $bundle['sha256'], hash( 'sha256', $content ) ) ) {
			return new \WP_Error( 'quarantine_restore_integrity', __( 'The quarantine payload failed its integrity check.', 'aegisguard-security' ) );
		}
		$handle = @fopen( $target, 'xb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen,WordPress.PHP.NoSilencedErrors.Discouraged -- Exclusive creation prevents overwriting a raced restore target.
		if ( ! $handle ) {
			return new \WP_Error( 'quarantine_restore_write', __( 'The quarantined file could not be restored.', 'aegisguard-security' ) );
		}
		$written = fwrite( $handle, $content ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite,PluginCheck.CodeAnalysis.WriteFile.PluginDirectoryWrite -- Authorized restore to an authenticated wp-content path, never the plugin directory.
		$flushed = fflush( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fflush -- Ensure the restore is durable before deleting its encrypted record.
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- See above.
		if ( strlen( $content ) !== $written || ! $flushed ) {
			unlink( $target ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Roll back a partial restore.
			return new \WP_Error( 'quarantine_restore_write', __( 'The quarantined file could not be restored completely.', 'aegisguard-security' ) );
		}
		if ( ! unlink( $path ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Remove the encrypted record only after successful restoration.
			unlink( $target ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Roll back to avoid leaving both copies if record removal fails.
			return new \WP_Error( 'quarantine_restore_cleanup', __( 'The restored file was rolled back because the quarantine record could not be removed.', 'aegisguard-security' ) );
		}
		Logger::log(
			'security.file_restored',
			'A quarantined file was restored by an authorized administrator.',
			'high',
			array(
				'file'   => $relative,
				'sha256' => $bundle['sha256'],
			)
		);
		return true;
	}

	public static function delete( $name ) {
		$path = self::quarantine_record_path( $name );
		if ( is_wp_error( $path ) ) {
			return $path;
		}
		$bundle = self::read_quarantine_bundle( $path );
		if ( is_wp_error( $bundle ) ) {
			return $bundle;
		}
		if ( ! unlink( $path ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Explicit administrator-authorized destruction of a quarantine record.
			return new \WP_Error( 'quarantine_delete', __( 'The quarantine record could not be deleted.', 'aegisguard-security' ) );
		}
		Logger::log(
			'security.quarantine_deleted',
			'A quarantine record was permanently deleted by an authorized administrator.',
			'high',
			array(
				'original_path' => $bundle['original_path'],
				'sha256'        => $bundle['sha256'],
			)
		);
		return true;
	}

	private static function encrypt_quarantine_payload( $content ) {
		$key_material = get_option( 'aegisguard_quarantine_key', '' );
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Binary cryptographic key deserialization, not code obfuscation.
		$key = base64_decode( (string) $key_material, true );
		if ( false === $key || 32 !== strlen( $key ) ) {
			return new \WP_Error( 'quarantine_key', __( 'The quarantine encryption key is unavailable.', 'aegisguard-security' ) );
		}
		if ( function_exists( 'sodium_crypto_secretbox' ) ) {
			$nonce  = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$cipher = sodium_crypto_secretbox( $content, $nonce, $key );
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Binary authenticated-ciphertext serialization, not code obfuscation.
			return 'sodium:' . base64_encode( $nonce . $cipher );
		}
		if ( function_exists( 'openssl_encrypt' ) ) {
			$iv     = random_bytes( 12 );
			$tag    = '';
			$cipher = openssl_encrypt( $content, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );
			if ( false !== $cipher ) {
				// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Binary authenticated-ciphertext serialization, not code obfuscation.
				return 'openssl:' . base64_encode( $iv . $tag . $cipher );
			}
		}
		return new \WP_Error( 'quarantine_crypto', __( 'No supported authenticated-encryption provider is available.', 'aegisguard-security' ) );
	}

	private static function decrypt_quarantine_payload( $encoded ) {
		$key_material = get_option( 'aegisguard_quarantine_key', '' );
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Binary cryptographic key deserialization, not code obfuscation.
		$key = base64_decode( (string) $key_material, true );
		if ( false === $key || 32 !== strlen( $key ) ) {
			return new \WP_Error( 'quarantine_key', __( 'The quarantine encryption key is unavailable.', 'aegisguard-security' ) );
		}
		if ( 0 === strpos( (string) $encoded, 'sodium:' ) && function_exists( 'sodium_crypto_secretbox_open' ) ) {
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Binary authenticated-ciphertext deserialization, not code obfuscation.
			$raw = base64_decode( substr( $encoded, 7 ), true );
			if ( false === $raw || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
				return new \WP_Error( 'quarantine_payload', __( 'The quarantine payload is malformed.', 'aegisguard-security' ) );
			}
			$nonce  = substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$cipher = substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$plain  = sodium_crypto_secretbox_open( $cipher, $nonce, $key );
			return false === $plain ? new \WP_Error( 'quarantine_auth', __( 'The quarantine payload could not be authenticated.', 'aegisguard-security' ) ) : $plain;
		}
		if ( 0 === strpos( (string) $encoded, 'openssl:' ) && function_exists( 'openssl_decrypt' ) ) {
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Binary authenticated-ciphertext deserialization, not code obfuscation.
			$raw = base64_decode( substr( $encoded, 8 ), true );
			if ( false === $raw || strlen( $raw ) <= 28 ) {
				return new \WP_Error( 'quarantine_payload', __( 'The quarantine payload is malformed.', 'aegisguard-security' ) );
			}
			$iv     = substr( $raw, 0, 12 );
			$tag    = substr( $raw, 12, 16 );
			$cipher = substr( $raw, 28 );
			$plain  = openssl_decrypt( $cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );
			return false === $plain ? new \WP_Error( 'quarantine_auth', __( 'The quarantine payload could not be authenticated.', 'aegisguard-security' ) ) : $plain;
		}
		return new \WP_Error( 'quarantine_crypto', __( 'The quarantine record uses an unavailable encryption provider.', 'aegisguard-security' ) );
	}

	private static function read_quarantine_bundle( $path ) {
		$record_json = file_get_contents( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local encrypted quarantine record.
		$record      = is_string( $record_json ) ? json_decode( $record_json, true ) : null;
		if ( ! is_array( $record ) || 2 !== (int) ( isset( $record['format'] ) ? $record['format'] : 0 ) || empty( $record['payload'] ) ) {
			return new \WP_Error( 'quarantine_format', __( 'The quarantine record format is invalid or unsupported.', 'aegisguard-security' ) );
		}
		$plain = self::decrypt_quarantine_payload( $record['payload'] );
		if ( is_wp_error( $plain ) ) {
			return $plain;
		}
		$bundle = json_decode( $plain, true );
		if ( ! is_array( $bundle ) || empty( $bundle['original_path'] ) || empty( $bundle['sha256'] ) || ! isset( $bundle['content'] ) ) {
			return new \WP_Error( 'quarantine_bundle', __( 'The decrypted quarantine bundle is incomplete.', 'aegisguard-security' ) );
		}
		return $bundle;
	}

	private static function quarantine_record_path( $name ) {

		$name = sanitize_file_name( (string) $name );
		if ( ! preg_match( '/^[A-Za-z0-9-]+\.agq$/', $name ) ) {
			return new \WP_Error( 'quarantine_name', __( 'The quarantine record name is invalid.', 'aegisguard-security' ) );
		}
		$dir  = realpath( WP_CONTENT_DIR . '/aegisguard-quarantine' );
		$path = $dir ? realpath( trailingslashit( $dir ) . $name ) : false;
		if ( ! $dir || ! $path || 0 !== strpos( wp_normalize_path( $path ), wp_normalize_path( trailingslashit( $dir ) ) ) ) {
			return new \WP_Error( 'quarantine_record', __( 'The quarantine record could not be located safely.', 'aegisguard-security' ) );
		}
		return $path;
	}

	private static function path_has_symlink( $path, $root ) {

		$root = rtrim( wp_normalize_path( $root ), '/' );
		$path = wp_normalize_path( $path );
		if ( $path === $root ) {
			return false;
		}
		$relative = ltrim( substr( $path, strlen( $root ) ), '/' );
		$current  = $root;
		foreach ( array_filter( explode( '/', $relative ), 'strlen' ) as $segment ) {
			$current .= '/' . $segment;
			if ( is_link( $current ) ) {
				return true;
			}
		}
		return false;
	}
	private static function protect_quarantine_dir( $dir ) {
		$index     = trailingslashit( $dir ) . 'index.php';
		$htaccess  = trailingslashit( $dir ) . '.htaccess';
		$webconfig = trailingslashit( $dir ) . 'web.config';
		if ( ! file_exists( $index ) ) {
			file_put_contents( $index, "<?php\nhttp_response_code(404);\nexit;\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Security bootstrap file.
		}
		if ( ! file_exists( $htaccess ) ) {
			file_put_contents( $htaccess, "Require all denied\nDeny from all\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Defense-in-depth for Apache.
		}
		if ( ! file_exists( $webconfig ) ) {
			file_put_contents( $webconfig, '<?xml version="1.0"?><configuration><system.webServer><security><authorization><remove users="*" roles="" verbs=""/><add accessType="Deny" users="*"/></authorization></security></system.webServer></configuration>' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Defense-in-depth for IIS.
		}
	}
}
