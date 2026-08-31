<?php
namespace AegisGuard\Security;

use AegisGuard\Core\Logger;
use AegisGuard\Support\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Scanner {
	private static $allowed_extensions = array( 'php', 'js', 'html', 'htm', 'css', 'svg', 'htaccess', 'ini' );

	public static function register() {
		if ( defined( 'WP_CLI' ) && WP_CLI && class_exists( 'WP_CLI' ) ) {
			\WP_CLI::add_command( 'aegisguard', 'AegisGuard\\Security\\ScannerCliCommand' );
		}
	}

	public static function run_full_scan() {
		$started  = microtime( true );
		$findings = array();
		$stats    = array( 'files_scanned' => 0, 'database_rows_scanned' => 0, 'core_files_checked' => 0 );

		$file_result = self::scan_files();
		$findings    = array_merge( $findings, $file_result['findings'] );
		$stats['files_scanned'] = $file_result['scanned'];

		$core_result = self::verify_core_integrity();
		$findings    = array_merge( $findings, $core_result['findings'] );
		$stats['core_files_checked'] = $core_result['checked'];

		if ( Settings::get( 'database_scan', true ) ) {
			$db_result = self::scan_database();
			$findings  = array_merge( $findings, $db_result['findings'] );
			$stats['database_rows_scanned'] = $db_result['scanned'];
		}

		$findings = array_merge(
			$findings,
			self::scan_configuration(),
			self::scan_update_posture(),
			self::scan_sensitive_files(),
			self::scan_privileged_users(),
			self::scan_scheduled_tasks()
		);
		$audit_check = Logger::verify_chain( 2000 );
		if ( empty( $audit_check['valid'] ) ) {
			$findings[] = self::finding( 'critical', 'audit_chain_invalid', 'event:' . (int) $audit_check['broken_event_id'], 'The local audit-event hash chain could not be verified. Investigate possible log tampering or key loss.' );
		}
		usort( $findings, array( __CLASS__, 'sort_findings' ) );

		$result = array(
			'started_at' => gmdate( 'c' ),
			'duration'   => round( microtime( true ) - $started, 3 ),
			'stats'      => $stats,
			'findings'   => array_slice( $findings, 0, 1000 ),
			'summary'    => self::summarize( $findings ),
		);
		update_option( 'aegisguard_last_scan', current_time( 'mysql', true ), false );
		update_option( 'aegisguard_last_scan_results', $result, false );
		Logger::log( 'security.scan_completed', 'Security scan completed.', $result['summary']['critical'] > 0 ? 'critical' : ( $result['summary']['high'] > 0 ? 'high' : 'info' ), $result['summary'] );
		return $result;
	}

	public static function scan_files() {
		$max_files = (int) Settings::get( 'malware_scan_max_files', 10000 );
		$max_bytes = (int) Settings::get( 'file_scan_max_bytes', 2097152 );
		$findings  = array();
		$scanned   = 0;
		$baseline_initialized = (bool) get_option( 'aegisguard_integrity_initialized', false );
		$scan_started         = current_time( 'mysql', true );
		$limit_reached        = false;
		$root      = wp_normalize_path( ABSPATH );
		$exclude   = array(
			wp_normalize_path( WP_CONTENT_DIR . '/cache/' ),
			wp_normalize_path( WP_CONTENT_DIR . '/upgrade/' ),
			wp_normalize_path( WP_CONTENT_DIR . '/aegisguard-quarantine/' ),
		);

		try {
			$directory = new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS );
			$iterator  = new \RecursiveIteratorIterator( $directory, \RecursiveIteratorIterator::LEAVES_ONLY, \RecursiveIteratorIterator::CATCH_GET_CHILD );
			foreach ( $iterator as $file ) {
				if ( $scanned >= $max_files ) {
					$limit_reached = true;
					break;
				}
				if ( ! $file->isFile() || ! $file->isReadable() ) {
					continue;
				}
				$path = wp_normalize_path( $file->getPathname() );
				if ( self::excluded( $path, $exclude ) ) {
					continue;
				}
				$ext = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) );
				$basename = strtolower( basename( $path ) );
				if ( '.htaccess' === $basename ) {
					$ext = 'htaccess';
				}
				if ( ! in_array( $ext, self::$allowed_extensions, true ) ) {
					continue;
				}
				$scanned++;
				$size = (int) $file->getSize();
				if ( $size <= 0 || $size > $max_bytes ) {
					continue;
				}
				$content = file_get_contents( $path, false, null, 0, $max_bytes ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local read-only scanner; WP_Filesystem adds no security value here.
				if ( ! is_string( $content ) ) {
					continue;
				}
				if ( wp_normalize_path( __FILE__ ) !== $path ) {
					$findings = array_merge( $findings, self::inspect_content( $path, $content, $ext ) );
				}
				$integrity_finding = self::check_integrity_baseline( $path, $file, $ext, $baseline_initialized );
				if ( $integrity_finding ) {
					$findings[] = $integrity_finding;
				}
			}
		} catch ( \UnexpectedValueException $exception ) {
			$limit_reached = true;
			$findings[] = self::finding( 'medium', 'scan_error', $root, 'Part of the filesystem could not be read.', array( 'error' => $exception->getMessage() ) );
		}
		if ( $baseline_initialized && ! $limit_reached ) {
			$findings = array_merge( $findings, self::missing_baseline_files( $scan_started ) );
		}
		if ( $limit_reached ) {
			$findings[] = self::finding( 'info', 'scan_resource_limit', '', 'The filesystem scan stopped at its configured resource ceiling; missing-file checks were skipped to avoid false positives.' );
		}
		if ( $scanned > 0 && ! $baseline_initialized && ! $limit_reached ) {
			update_option( 'aegisguard_integrity_initialized', 1, false );
		}
		return array( 'scanned' => $scanned, 'findings' => $findings );
	}

	public static function verify_core_integrity() {
		$findings = array();
		$checked  = 0;
		global $wp_version;
		$locale = get_locale();
		if ( ! function_exists( 'get_core_checksums' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		if ( ! function_exists( 'get_core_checksums' ) ) {
			return array( 'checked' => 0, 'findings' => array( self::finding( 'low', 'core_integrity_unavailable', '', 'WordPress core checksum service is unavailable.' ) ) );
		}
		$checksums = get_core_checksums( $wp_version, $locale );
		if ( ! is_array( $checksums ) ) {
			return array( 'checked' => 0, 'findings' => array( self::finding( 'low', 'core_integrity_unavailable', '', 'Could not retrieve official WordPress core checksums.' ) ) );
		}
		foreach ( $checksums as $relative => $expected ) {
			$path = ABSPATH . $relative;
			$checked++;
			if ( ! file_exists( $path ) ) {
				$findings[] = self::finding( 'high', 'core_file_missing', $relative, 'A WordPress core file is missing.' );
				continue;
			}
			$actual = md5_file( $path ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_md5_file -- WordPress checksum API supplies MD5 values; used for integrity, not cryptography.
			if ( ! hash_equals( (string) $expected, (string) $actual ) ) {
				$findings[] = self::finding( 'critical', 'core_file_modified', $relative, 'A WordPress core file does not match the official checksum.' );
			}
		}
		return array( 'checked' => $checked, 'findings' => $findings );
	}

	public static function scan_database() {
		global $wpdb;
		$findings = array();
		$scanned  = 0;
		$patterns = array( '<script', 'javascript:', 'base64_decode(', 'gzinflate(', 'document.location', 'window.location=' );

		foreach ( $patterns as $pattern ) {
			$like = '%' . $wpdb->esc_like( $pattern ) . '%';
			$posts = $wpdb->get_results( $wpdb->prepare( "SELECT ID, post_type FROM {$wpdb->posts} WHERE post_content LIKE %s LIMIT 50", $like ) );
			$scanned += count( $posts );
			foreach ( $posts as $post ) {
				$findings[] = self::finding( 'medium', 'database_suspicious_content', 'post:' . (int) $post->ID, 'Suspicious executable or redirect pattern found in post content.', array( 'pattern' => $pattern, 'post_type' => $post->post_type ) );
			}
			$options = $wpdb->get_results( $wpdb->prepare( "SELECT option_name FROM {$wpdb->options} WHERE option_value LIKE %s LIMIT 50", $like ) );
			$scanned += count( $options );
			foreach ( $options as $option ) {
				$findings[] = self::finding( 'high', 'database_suspicious_option', 'option:' . $option->option_name, 'Suspicious executable or redirect pattern found in an option.', array( 'pattern' => $pattern ) );
			}
		}
		return array( 'scanned' => $scanned, 'findings' => $findings );
	}

	public static function scan_configuration() {
		$findings = array();
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG && defined( 'WP_DEBUG_LOG' ) && WP_DEBUG_LOG ) {
			$debug_log = is_string( WP_DEBUG_LOG ) ? WP_DEBUG_LOG : WP_CONTENT_DIR . '/debug.log';
			if ( file_exists( $debug_log ) ) {
				$findings[] = self::finding( 'medium', 'debug_log_enabled', wp_normalize_path( $debug_log ), 'WordPress debug logging is enabled and may expose sensitive information.' );
			}
		}
		if ( ! is_ssl() ) {
			$findings[] = self::finding( 'high', 'https_missing', home_url( '/' ), 'The site is not using HTTPS for its canonical home URL.' );
		}
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) || ! DISALLOW_FILE_EDIT ) {
			$findings[] = self::finding( 'low', 'file_edit_constant_missing', 'wp-config.php', 'DISALLOW_FILE_EDIT is not enabled in wp-config.php. AegisGuard denies editor capabilities at runtime, but the constant is stronger.' );
		}
		foreach ( array( WP_CONTENT_DIR . '/.user.ini', ABSPATH . '.user.ini' ) as $ini ) {
			if ( is_readable( $ini ) ) {
				$content = file_get_contents( $ini ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local security inspection.
				if ( is_string( $content ) && preg_match( '/auto_(?:prepend|append)_file\s*=/i', $content ) ) {
					$findings[] = self::finding( 'critical', 'php_persistence_directive', wp_normalize_path( $ini ), 'PHP auto_prepend_file or auto_append_file directive detected. Verify that it is intentional.' );
				}
			}
		}
		return $findings;
	}

	public static function scan_update_posture() {
		$findings = array();
		$plugins = get_site_transient( 'update_plugins' );
		if ( is_object( $plugins ) && ! empty( $plugins->response ) ) {
			foreach ( $plugins->response as $plugin => $data ) {
				$findings[] = self::finding( 'medium', 'plugin_update_available', $plugin, 'A plugin update is available.', array( 'new_version' => isset( $data->new_version ) ? $data->new_version : '' ) );
			}
		}
		$themes = get_site_transient( 'update_themes' );
		if ( is_object( $themes ) && ! empty( $themes->response ) ) {
			foreach ( $themes->response as $theme => $data ) {
				$findings[] = self::finding( 'low', 'theme_update_available', $theme, 'A theme update is available.', array( 'new_version' => isset( $data['new_version'] ) ? $data['new_version'] : '' ) );
			}
		}
		return $findings;
	}

	public static function scan_sensitive_files() {
		$findings = array();
		$candidates = array(
			ABSPATH . '.env',
			ABSPATH . '.git/config',
			ABSPATH . 'wp-config.php.bak',
			ABSPATH . 'wp-config.php.old',
			ABSPATH . 'wp-config.php.save',
			ABSPATH . 'database.sql',
			ABSPATH . 'backup.sql',
			WP_CONTENT_DIR . '/debug.log',
		);
		foreach ( $candidates as $path ) {
			if ( ! is_file( $path ) ) {
				continue;
			}
			$relative = 0 === strpos( wp_normalize_path( $path ), wp_normalize_path( ABSPATH ) )
				? ltrim( substr( wp_normalize_path( $path ), strlen( wp_normalize_path( ABSPATH ) ) ), '/' )
				: wp_normalize_path( $path );
			$severity = false !== strpos( strtolower( basename( $path ) ), 'wp-config' ) || '.env' === basename( $path ) ? 'high' : 'medium';
			$findings[] = self::finding( $severity, 'sensitive_file_present', $relative, 'A sensitive or backup file is present under the WordPress web root. Verify that it cannot be served publicly and remove it when no longer required.' );
		}
		return $findings;
	}

	public static function scan_privileged_users() {
		$findings = array();
		$admins   = get_users(
			array(
				'role'   => 'administrator',
				'fields' => array( 'ID', 'user_login', 'user_registered' ),
			)
		);
		foreach ( $admins as $admin ) {
			if ( ! Mfa::is_enabled( $admin->ID ) ) {
				$findings[] = self::finding( 'medium', 'administrator_without_mfa', 'user:' . (int) $admin->ID, 'An administrator account does not have AegisGuard TOTP MFA enabled.', array( 'registered' => $admin->user_registered ) );
			}
		}
		return $findings;
	}

	public static function scan_scheduled_tasks() {
		$findings = array();
		$cron     = _get_cron_array();
		if ( ! is_array( $cron ) ) {
			return $findings;
		}
		$high_frequency = 0;
		foreach ( $cron as $timestamp => $hooks ) {
			unset( $timestamp );
			foreach ( (array) $hooks as $hook => $events ) {
				foreach ( (array) $events as $event ) {
					$interval = isset( $event['interval'] ) ? absint( $event['interval'] ) : 0;
					if ( $interval > 0 && $interval < MINUTE_IN_SECONDS ) {
						$high_frequency++;
						if ( $high_frequency <= 25 ) {
							$findings[] = self::finding( 'low', 'high_frequency_cron', 'cron:' . sanitize_key( $hook ), 'A recurring WordPress cron event runs more frequently than once per minute. Verify that this is intentional.', array( 'interval' => $interval ) );
						}
					}
				}
			}
		}
		return $findings;
	}


	public static function reset_integrity_baseline() {
		global $wpdb;
		$table = $wpdb->prefix . 'aegisguard_integrity';
		$wpdb->query( "TRUNCATE TABLE {$table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Internal table name only.
		delete_option( 'aegisguard_integrity_initialized' );
		Logger::log( 'security.integrity_baseline_reset', 'File-integrity baseline reset by an authorized administrator.', 'high' );
	}


	public static function quarantine( $path ) {
		$real = realpath( $path );
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
		$bundle = wp_json_encode(
			array(
				'original_path' => $relative_path,
				'original_name' => sanitize_file_name( basename( $real ) ),
				'sha256'        => hash( 'sha256', $content ),
				'captured_at'   => gmdate( 'c' ),
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
		$record = wp_json_encode(
			array(
				'format'  => 2,
				'payload' => $encrypted,
			),
			JSON_UNESCAPED_SLASHES
		);
		if ( ! is_string( $record ) || false === file_put_contents( $destination, $record, LOCK_EX ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Atomic write of encrypted quarantine record.
			return new \WP_Error( 'quarantine_write', __( 'Could not write the encrypted quarantine record.', 'aegisguard-security' ) );
		}
		@chmod( $destination, 0600 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Best-effort filesystem hardening after encrypted storage.
		if ( ! unlink( $real ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Confirmed file quarantine requires removing original after successful encrypted copy.
			unlink( $destination ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Roll back duplicate quarantine record if original cannot be removed.
			return new \WP_Error( 'quarantine_remove', __( 'Encrypted copy was created but the original file could not be removed; quarantine was rolled back.', 'aegisguard-security' ) );
		}
		Logger::log( 'security.file_quarantined', 'A file was encrypted and moved to quarantine.', 'high', array( 'file' => wp_normalize_path( $real ), 'quarantine_name' => basename( $destination ), 'sha256' => hash( 'sha256', $content ) ) );
		return true;
	}

	public static function list_quarantine() {
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
				$items[] = array( 'name' => basename( $file ), 'valid' => false, 'original_path' => '', 'captured_at' => '', 'sha256' => '' );
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
		usort( $items, static function ( $a, $b ) { return strcmp( $b['name'], $a['name'] ); } );
		return $items;
	}

	public static function restore_quarantine( $name ) {
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
		$target = wp_normalize_path( trailingslashit( WP_CONTENT_DIR ) . $relative );
		$content_root = wp_normalize_path( trailingslashit( WP_CONTENT_DIR ) );
		if ( 0 !== strpos( $target, $content_root ) || 0 === strpos( $target, wp_normalize_path( AEGISGUARD_DIR ) ) ) {
			return new \WP_Error( 'quarantine_restore_scope', __( 'The original path is outside the permitted restore scope.', 'aegisguard-security' ) );
		}
		if ( file_exists( $target ) ) {
			return new \WP_Error( 'quarantine_restore_exists', __( 'Restore refused because a file already exists at the original path.', 'aegisguard-security' ) );
		}
		$parent = dirname( $target );
		if ( ! is_dir( $parent ) || ! is_writable( $parent ) ) {
			return new \WP_Error( 'quarantine_restore_parent', __( 'The original parent directory does not exist or is not writable.', 'aegisguard-security' ) );
		}
		$content = base64_decode( (string) $bundle['content'], true );
		if ( false === $content || ! hash_equals( (string) $bundle['sha256'], hash( 'sha256', $content ) ) ) {
			return new \WP_Error( 'quarantine_restore_integrity', __( 'The quarantine payload failed its integrity check.', 'aegisguard-security' ) );
		}
		if ( false === file_put_contents( $target, $content, LOCK_EX ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Explicit administrator-authorized restoration of an authenticated local quarantine bundle.
			return new \WP_Error( 'quarantine_restore_write', __( 'The quarantined file could not be restored.', 'aegisguard-security' ) );
		}
		if ( ! unlink( $path ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Remove the encrypted record only after successful restoration.
			unlink( $target ); // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Roll back to avoid leaving both copies if record removal fails.
			return new \WP_Error( 'quarantine_restore_cleanup', __( 'The restored file was rolled back because the quarantine record could not be removed.', 'aegisguard-security' ) );
		}
		Logger::log( 'security.file_restored', 'A quarantined file was restored by an authorized administrator.', 'high', array( 'file' => $relative, 'sha256' => $bundle['sha256'] ) );
		return true;
	}

	public static function delete_quarantine( $name ) {
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
		Logger::log( 'security.quarantine_deleted', 'A quarantine record was permanently deleted by an authorized administrator.', 'high', array( 'original_path' => $bundle['original_path'], 'sha256' => $bundle['sha256'] ) );
		return true;
	}

	private static function encrypt_quarantine_payload( $content ) {
		$key_material = get_option( 'aegisguard_quarantine_key', '' );
		$key = base64_decode( (string) $key_material, true );
		if ( false === $key || 32 !== strlen( $key ) ) {
			return new \WP_Error( 'quarantine_key', __( 'The quarantine encryption key is unavailable.', 'aegisguard-security' ) );
		}
		if ( function_exists( 'sodium_crypto_secretbox' ) ) {
			$nonce  = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$cipher = sodium_crypto_secretbox( $content, $nonce, $key );
			return 'sodium:' . base64_encode( $nonce . $cipher );
		}
		if ( function_exists( 'openssl_encrypt' ) ) {
			$iv  = random_bytes( 12 );
			$tag = '';
			$cipher = openssl_encrypt( $content, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag );
			if ( false !== $cipher ) {
				return 'openssl:' . base64_encode( $iv . $tag . $cipher );
			}
		}
		return new \WP_Error( 'quarantine_crypto', __( 'No supported authenticated-encryption provider is available.', 'aegisguard-security' ) );
	}

	private static function decrypt_quarantine_payload( $encoded ) {
		$key_material = get_option( 'aegisguard_quarantine_key', '' );
		$key = base64_decode( (string) $key_material, true );
		if ( false === $key || 32 !== strlen( $key ) ) {
			return new \WP_Error( 'quarantine_key', __( 'The quarantine encryption key is unavailable.', 'aegisguard-security' ) );
		}
		if ( 0 === strpos( (string) $encoded, 'sodium:' ) && function_exists( 'sodium_crypto_secretbox_open' ) ) {
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

	private static function protect_quarantine_dir( $dir ) {
		$index = trailingslashit( $dir ) . 'index.php';
		$htaccess = trailingslashit( $dir ) . '.htaccess';
		$webconfig = trailingslashit( $dir ) . 'web.config';
		if ( ! file_exists( $index ) ) {
			file_put_contents( $index, "<?php\nhttp_response_code(404);\nexit;\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Security bootstrap file.
		}
		if ( ! file_exists( $htaccess ) ) {
			file_put_contents( $htaccess, "Require all denied\nDeny from all\n" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Defense-in-depth for Apache.
		}
		if ( ! file_exists( $webconfig ) ) {
			file_put_contents( $webconfig, "<?xml version=\"1.0\"?><configuration><system.webServer><security><authorization><remove users=\"*\" roles=\"\" verbs=\"\"/><add accessType=\"Deny\" users=\"*\"/></authorization></security></system.webServer></configuration>" ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Defense-in-depth for IIS.
		}
	}

	private static function inspect_content( $path, $content, $ext ) {
		$findings = array();
		$relative = 0 === strpos( wp_normalize_path( $path ), wp_normalize_path( ABSPATH ) ) ? ltrim( substr( wp_normalize_path( $path ), strlen( wp_normalize_path( ABSPATH ) ) ), '/' ) : wp_normalize_path( $path );
		$signals  = 0;
		if ( preg_match( '/\beval\s*\(\s*(?:base64_decode|gzinflate|str_rot13)\s*\(/i', $content ) ) {
			$signals += 5;
			$findings[] = self::finding( 'critical', 'malware_obfuscated_eval', $relative, 'Obfuscated dynamic code execution pattern detected.' );
		}
		if ( preg_match( '/\b(?:shell_exec|passthru|proc_open|popen)\s*\(/i', $content ) ) {
			$signals += 2;
			$findings[] = self::finding( 'medium', 'dangerous_execution_function', $relative, 'Dangerous process execution function detected. Verify whether the use is legitimate.' );
		}
		if ( preg_match( '/(?:FilesMan|WSO\s*Shell|r57shell|c99shell|b374k)/i', $content ) ) {
			$signals += 8;
			$findings[] = self::finding( 'critical', 'known_webshell_marker', $relative, 'Known web-shell marker detected.' );
		}
		if ( 'php' === $ext && false !== strpos( wp_normalize_path( $path ), wp_normalize_path( WP_CONTENT_DIR . '/uploads/' ) ) ) {
			$signals += 6;
			$findings[] = self::finding( 'critical', 'php_in_uploads', $relative, 'PHP executable file found in the uploads directory.' );
		}
		if ( preg_match( '/\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*["\'][A-Za-z0-9+\/]{500,}={0,2}["\']/s', $content ) ) {
			$findings[] = self::finding( 'high', 'high_entropy_payload', $relative, 'Large encoded payload detected; review for obfuscation.' );
		}
		if ( $signals >= 8 ) {
			Logger::log( 'security.malware_candidate', 'High-confidence malware candidate detected during scan.', 'critical', array( 'file' => $relative, 'signal_score' => $signals ) );
		}
		return $findings;
	}



	private static function check_integrity_baseline( $path, $file, $ext, $baseline_initialized ) {
		global $wpdb;
		$table      = $wpdb->prefix . 'aegisguard_integrity';
		$normalized = wp_normalize_path( $path );
		$relative   = 0 === strpos( $normalized, wp_normalize_path( ABSPATH ) ) ? ltrim( substr( $normalized, strlen( wp_normalize_path( ABSPATH ) ) ), '/' ) : $normalized;
		$path_hash  = hash( 'sha256', $relative );
		$file_hash  = hash_file( 'sha256', $path );
		$existing   = $wpdb->get_row( $wpdb->prepare( "SELECT id, file_hash FROM {$table} WHERE path_hash = %s LIMIT 1", $path_hash ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Internal table name.

		if ( $existing ) {
			if ( ! hash_equals( (string) $existing->file_hash, (string) $file_hash ) ) {
				$wpdb->update(
					$table,
					array( 'file_size' => (int) $file->getSize(), 'file_mtime' => (int) $file->getMTime(), 'last_seen' => current_time( 'mysql', true ) ),
					array( 'id' => (int) $existing->id ),
					array( '%d', '%d', '%s' ),
					array( '%d' )
				);
				return self::finding( 'medium', 'file_modified_since_baseline', $relative, 'File contents changed since the accepted integrity baseline.' );
			}
			$wpdb->update( $table, array( 'last_seen' => current_time( 'mysql', true ) ), array( 'id' => (int) $existing->id ), array( '%s' ), array( '%d' ) );
			return null;
		}

		if ( $baseline_initialized ) {
			$severity = ( 'php' === $ext && false !== strpos( $normalized, wp_normalize_path( WP_CONTENT_DIR . '/uploads/' ) ) ) ? 'critical' : 'low';
			return self::finding( $severity, 'file_new_since_baseline', $relative, 'A new scannable file appeared after the accepted integrity baseline was established.' );
		}

		$wpdb->insert(
			$table,
			array(
				'file_path'  => $relative,
				'path_hash'  => $path_hash,
				'file_hash'  => $file_hash,
				'file_size'  => (int) $file->getSize(),
				'file_mtime' => (int) $file->getMTime(),
				'file_type'  => substr( sanitize_key( $ext ), 0, 30 ),
				'last_seen'  => current_time( 'mysql', true ),
			),
			array( '%s','%s','%s','%d','%d','%s','%s' )
		);
		return null;
	}

	private static function missing_baseline_files( $scan_started ) {
		global $wpdb;
		$table = $wpdb->prefix . 'aegisguard_integrity';
		$rows  = $wpdb->get_results( $wpdb->prepare( "SELECT file_path FROM {$table} WHERE last_seen < %s ORDER BY id ASC LIMIT 500", $scan_started ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Internal table name.
		$findings = array();
		foreach ( (array) $rows as $row ) {
			$relative = isset( $row->file_path ) ? (string) $row->file_path : '';
			if ( '' !== $relative && ! file_exists( ABSPATH . ltrim( $relative, '/' ) ) ) {
				$findings[] = self::finding( 'medium', 'file_missing_since_baseline', $relative, 'A file from the accepted integrity baseline is now missing.' );
			}
		}
		return $findings;
	}

	private static function excluded( $path, $prefixes ) {
		foreach ( $prefixes as $prefix ) {
			if ( 0 === strpos( $path, $prefix ) ) {
				return true;
			}
		}
		return false;
	}

	private static function finding( $severity, $type, $location, $message, $evidence = array() ) {
		return array(
			'severity' => $severity,
			'type'     => $type,
			'location' => $location,
			'message'  => $message,
			'evidence' => $evidence,
		);
	}

	private static function summarize( $findings ) {
		$summary = array( 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0, 'total' => count( $findings ) );
		foreach ( $findings as $finding ) {
			$severity = isset( $finding['severity'] ) ? $finding['severity'] : 'info';
			if ( isset( $summary[ $severity ] ) ) {
				$summary[ $severity ]++;
			}
		}
		return $summary;
	}

	public static function sort_findings( $a, $b ) {
		$rank = array( 'critical' => 5, 'high' => 4, 'medium' => 3, 'low' => 2, 'info' => 1 );
		return $rank[ $b['severity'] ] <=> $rank[ $a['severity'] ];
	}
}
