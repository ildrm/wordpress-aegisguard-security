<?php
namespace AegisGuard\Security;

use AegisGuard\Core\Logger;
use AegisGuard\Support\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Scanner {
	private static $allowed_extensions = array( 'php', 'js', 'html', 'htm', 'css', 'svg', 'htaccess', 'ini' );
	private static $core_checksums;
	private static $core_checksums_loaded = false;

	public static function register() {
		if ( defined( 'WP_CLI' ) && WP_CLI && class_exists( 'WP_CLI' ) ) {
			\WP_CLI::add_command( 'aegisguard', 'AegisGuard\\Security\\ScannerCliCommand' );
		}
	}

	public static function run_full_scan() {
		if ( ! self::lock() ) {
			return new \WP_Error( 'aegisguard_scan_locked', __( 'The scanner is busy or the database lock is unavailable. Try again shortly.', 'aegisguard-security' ) );
		}
		try {
			return self::run_scan_batch();
		} finally {
			self::unlock();
		}
	}

	private static function run_scan_batch() {
		$started  = microtime( true );
		$findings = array();
		$result   = get_option( 'aegisguard_last_scan_results', array() );
		if ( empty( $result['pending'] ) ) {
			$result                                = array(
				'started_at' => gmdate( 'c' ),
				'duration'   => 0,
				'stats'      => array(
					'files_scanned'         => 0,
					'files_skipped'         => 0,
					'file_errors'           => 0,
					'database_rows_scanned' => 0,
					'core_files_checked'    => 0,
				),
				'findings'   => array(),
				'summary'    => self::summarize( array() ),
				'pending'    => array(
					'files'    => array(),
					'baseline' => get_option( 'aegisguard_integrity_initialized', false ) ? 0 : null,
					'database' => Settings::get( 'database_scan' ) ? array() : null,
				),
			);
			$core_result                           = self::verify_core_integrity();
			$result['stats']['core_files_checked'] = $core_result['checked'];
			$findings                              = array_merge(
				$core_result['findings'],
				self::scan_configuration(),
				self::scan_update_posture(),
				self::scan_sensitive_files(),
				self::scan_privileged_users(),
				self::scan_scheduled_tasks()
			);
			$audit_check                           = Logger::verify_chain( 2000 );
			if ( ! empty( $audit_check['error'] ) ) {
				return new \WP_Error( 'aegisguard_audit_unavailable', __( 'The audit log is temporarily unavailable. Retry the scan.', 'aegisguard-security' ) );
			}
			if ( empty( $audit_check['valid'] ) ) {
				$findings[] = self::finding( 'critical', 'audit_chain_invalid', 'event:' . (int) $audit_check['broken_event_id'], 'The local audit-event hash chain could not be verified. Investigate possible log tampering or key loss.' );
			}
		}
		$pending = $result['pending'];
		if ( isset( $pending['files'] ) ) {
			$batch                             = self::scan_files( $pending['files'] );
			$pending['files']                  = $batch['cursor'];
			$result['stats']['files_scanned'] += $batch['scanned'];
			$result['stats']['files_skipped'] += $batch['skipped'];
			$result['stats']['file_errors']   += $batch['errors'];
			$findings                          = array_merge( $findings, $batch['findings'] );
		}
		if ( ! isset( $pending['files'] ) && isset( $pending['baseline'] ) ) {
			$batch = self::missing_baseline_files( $pending['baseline'] );
			if ( is_wp_error( $batch ) ) {
				return $batch;
			}
			$pending['baseline'] = $batch['cursor'];
			$findings            = array_merge( $findings, $batch['findings'] );
		}
		if ( isset( $pending['database'] ) && Settings::get( 'database_scan' ) ) {
			$batch = self::scan_database( $pending['database'] );
			if ( is_wp_error( $batch ) ) {
				return $batch;
			}
			$pending['database']                       = $batch['cursor'];
			$result['stats']['database_rows_scanned'] += $batch['scanned'];
			$findings                                  = array_merge( $findings, $batch['findings'] );
		} else {
			$pending['database'] = null;
		}
		foreach ( self::summarize( $findings ) as $severity => $count ) {
			$result['summary'][ $severity ] += $count;
		}
		$findings = array_merge( $result['findings'], $findings );
		usort( $findings, array( __CLASS__, 'sort_findings' ) );
		$result['findings']  = array_slice( $findings, 0, 1000 );
		$result['duration'] += round( microtime( true ) - $started, 3 );
		$result['pending']   = array_filter(
			$pending,
			static function ( $cursor ) {
				return null !== $cursor;
			}
		);
		if ( ! update_option( 'aegisguard_last_scan_results', $result, false ) && get_option( 'aegisguard_last_scan_results' ) !== $result ) {
			return new \WP_Error( 'aegisguard_scan_save_failed', __( 'The scanner could not save its progress. Try again after checking database permissions.', 'aegisguard-security' ) );
		}
		if ( empty( $result['pending'] ) ) {
			if ( $result['stats']['files_scanned'] > 0 && 0 === $result['stats']['file_errors'] ) {
				update_option( 'aegisguard_integrity_initialized', 1, false );
			}
			update_option( 'aegisguard_last_scan', current_time( 'mysql', true ), false );
			Logger::log( 'security.scan_completed', 'Security scan completed.', $result['summary']['critical'] > 0 ? 'critical' : ( $result['summary']['high'] > 0 ? 'high' : 'info' ), $result['summary'] );
		}
		return $result;
	}

	public static function scan_files( $cursor = array() ) {
		$max_files            = max( 1, (int) Settings::get( 'malware_scan_max_files', 10000 ) );
		$max_bytes            = (int) Settings::get( 'file_scan_max_bytes', 2097152 );
		$findings             = array();
		$scanned              = 0;
		$skipped              = 0;
		$errors               = 0;
		$baseline_initialized = (bool) get_option( 'aegisguard_integrity_initialized', false );
		$next                 = null;
		$root                 = untrailingslashit( wp_normalize_path( ABSPATH ) );
		$exclude              = array(
			wp_normalize_path( WP_CONTENT_DIR . '/cache/' ),
			wp_normalize_path( WP_CONTENT_DIR . '/upgrade/' ),
			wp_normalize_path( WP_CONTENT_DIR . '/aegisguard-quarantine/' ),
		);
		if ( defined( 'AEGISGUARD_DIR' ) ) {
			$exclude[] = wp_normalize_path( trailingslashit( AEGISGUARD_DIR ) . 'vendor/' );
		}

		$processed = 0;
		foreach ( self::file_entries( $root, $exclude, $cursor ) as $entry ) {
			list( $path, $position, $ext ) = $entry;
			if ( $processed >= $max_files ) {
				$next = $last_position;
				break;
			}
			++$processed;
			$last_position = $position;
			if ( null === $ext || ! is_readable( $path ) ) {
				++$errors;
				$findings[] = self::finding( 'medium', 'scan_error', implode( '/', $position ), 'This filesystem entry could not be read.' );
				continue;
			}
			$file = new \SplFileInfo( $path );
			try {
				$size = $file->getSize();
				if ( $size > $max_bytes ) {
					++$skipped;
					continue;
				}
				$content = @file_get_contents( $path, false, null, 0, $max_bytes + 1 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local read, which may fail if a file disappears during a scan.
				if ( ! is_string( $content ) ) {
					++$errors;
					continue;
				}
				if ( strlen( $content ) > $max_bytes ) {
					++$skipped;
					continue;
				}
				++$scanned;
				if ( wp_normalize_path( __FILE__ ) !== $path ) {
					$findings = array_merge( $findings, self::inspect_content( $path, $content, $ext ) );
				}
				$integrity_finding = self::check_integrity_baseline( $path, $file, $ext, $baseline_initialized, hash( 'sha256', $content ) );
				if ( is_wp_error( $integrity_finding ) ) {
					++$errors;
					continue;
				}
				if ( $integrity_finding ) {
					$findings[] = $integrity_finding;
				}
			} catch ( \RuntimeException $exception ) {
				++$errors;
			}
		}
		return array(
			'scanned'  => $scanned,
			'skipped'  => $skipped,
			'errors'   => $errors,
			'findings' => $findings,
			'cursor'   => $next,
		);
	}

	private static function file_entries( $root, $exclude, $cursor, $ancestors = array() ) {
		$dir   = $ancestors ? $root . '/' . implode( '/', $ancestors ) : $root;
		$names = @scandir( $dir, SCANDIR_SORT_NONE ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Report unreadable directories in the scan result.
		if ( false === $names ) {
			yield array( $dir, $ancestors, null );
			return;
		}
		sort( $names, SORT_STRING );
		foreach ( $names as $name ) {
			if ( '.' === $name || '..' === $name ) {
				continue;
			}
			$comparison = $cursor ? strcmp( $name, $cursor[0] ) : 1;
			if ( $comparison < 0 || ( 0 === $comparison && 1 === count( $cursor ) ) ) {
				continue;
			}
			$path = $dir . '/' . $name;
			if ( is_link( $path ) || self::excluded( $path . '/', $exclude ) ) {
				continue;
			}
			$position = array_merge( $ancestors, array( $name ) );
			if ( is_dir( $path ) ) {
				yield from self::file_entries( $root, $exclude, 0 === $comparison ? array_slice( $cursor, 1 ) : array(), $position );
				continue;
			}
			$ext = '.htaccess' === strtolower( $name ) ? 'htaccess' : strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
			if ( $comparison > 0 && is_file( $path ) && in_array( $ext, self::$allowed_extensions, true ) ) {
				yield array( $path, $position, $ext );
			}
		}
	}

	public static function verify_core_integrity() {
		$findings  = array();
		$checked   = 0;
		$checksums = self::core_checksums();
		if ( ! is_array( $checksums ) ) {
			return array(
				'checked'  => 0,
				'findings' => array( self::finding( 'low', 'core_integrity_unavailable', '', 'Could not retrieve official WordPress core checksums.' ) ),
			);
		}
		foreach ( $checksums as $relative => $expected ) {
			$path = ABSPATH . $relative;
			++$checked;
			if ( ! file_exists( $path ) ) {
				$findings[] = self::finding( 'high', 'core_file_missing', $relative, 'A WordPress core file is missing.' );
				continue;
			}
			$actual = md5_file( $path ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_md5_file -- WordPress checksum API supplies MD5 values; used for integrity, not cryptography.
			if ( ! hash_equals( (string) $expected, (string) $actual ) ) {
				$findings[] = self::finding( 'critical', 'core_file_modified', $relative, 'A WordPress core file does not match the official checksum.' );
			}
		}
		return array(
			'checked'  => $checked,
			'findings' => $findings,
		);
	}

	public static function scan_database( $cursor = array() ) {
		global $wpdb;
		$patterns = array( '<script', 'javascript:', 'base64_decode(', 'gzinflate(', 'document.location', 'window.location=' );
		$likes    = array_map(
			static function ( $pattern ) use ( $wpdb ) {
				return '%' . $wpdb->esc_like( $pattern ) . '%';
			},
			$patterns
		);
		$limit    = 200;
		$findings = array();
		$scanned  = 0;
		$next     = array();

		if ( ! $cursor ) {
			$cursor = array(
				'posts'   => 0,
				'options' => 0,
			);
		}
		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Bounded keyset inspection of current WordPress rows.
		if ( isset( $cursor['posts'] ) ) {
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					'SELECT ID AS scan_id, post_type AS label,
					 CASE WHEN post_content LIKE %s THEN 0 WHEN post_content LIKE %s THEN 1 WHEN post_content LIKE %s THEN 2
					 WHEN post_content LIKE %s THEN 3 WHEN post_content LIKE %s THEN 4 WHEN post_content LIKE %s THEN 5 END AS match_id
					 FROM %i WHERE ID > %d ORDER BY ID LIMIT %d',
					$likes[0],
					$likes[1],
					$likes[2],
					$likes[3],
					$likes[4],
					$likes[5],
					$wpdb->posts,
					$cursor['posts'],
					$limit + 1
				)
			);
			if ( $wpdb->last_error ) {
				return self::database_error();
			}
			if ( count( $rows ) > $limit ) {
				array_pop( $rows );
				$next['posts'] = (int) end( $rows )->scan_id;
			}
			$scanned += count( $rows );
			foreach ( $rows as $row ) {
				if ( null !== $row->match_id ) {
					$findings[] = self::finding(
						'medium',
						'database_suspicious_content',
						'post:' . $row->scan_id,
						'Suspicious executable or redirect pattern found in post content.',
						array(
							'pattern'   => $patterns[ $row->match_id ],
							'post_type' => $row->label,
						)
					);
				}
			}
		}
		if ( isset( $cursor['options'] ) ) {
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					'SELECT option_id AS scan_id, option_name AS label,
					 CASE WHEN option_value LIKE %s THEN 0 WHEN option_value LIKE %s THEN 1 WHEN option_value LIKE %s THEN 2
					 WHEN option_value LIKE %s THEN 3 WHEN option_value LIKE %s THEN 4 WHEN option_value LIKE %s THEN 5 END AS match_id
					 FROM %i WHERE option_id > %d AND option_name <> %s ORDER BY option_id LIMIT %d',
					$likes[0],
					$likes[1],
					$likes[2],
					$likes[3],
					$likes[4],
					$likes[5],
					$wpdb->options,
					$cursor['options'],
					'aegisguard_last_scan_results',
					$limit + 1
				)
			);
			if ( $wpdb->last_error ) {
				return self::database_error();
			}
			if ( count( $rows ) > $limit ) {
				array_pop( $rows );
				$next['options'] = (int) end( $rows )->scan_id;
			}
			$scanned += count( $rows );
			foreach ( $rows as $row ) {
				if ( null !== $row->match_id ) {
					$findings[] = self::finding( 'high', 'database_suspicious_option', 'option:' . $row->label, 'Suspicious executable or redirect pattern found in an option.', array( 'pattern' => $patterns[ $row->match_id ] ) );
				}
			}
		}
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return array(
			'scanned'  => $scanned,
			'findings' => $findings,
			'cursor'   => $next ? $next : null,
		);
	}

	private static function database_error() {
		return new \WP_Error( 'aegisguard_scan_database_failed', __( 'A database scan query failed. The scanner kept its last saved position.', 'aegisguard-security' ) );
	}

	private static function lock_name() {
		global $wpdb;
		return 'aegisguard_scan_' . substr( hash( 'sha256', DB_NAME . '|' . $wpdb->prefix ), 0, 32 );
	}

	private static function lock() {
		global $wpdb;
		return '1' === (string) $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, 0)', self::lock_name() ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Serialize scan state across requests.
	}

	private static function unlock() {
		global $wpdb;
		$wpdb->get_var( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', self::lock_name() ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Release the scan advisory lock.
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
		$plugins  = get_site_transient( 'update_plugins' );
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
		$findings   = array();
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
			$relative   = 0 === strpos( wp_normalize_path( $path ), wp_normalize_path( ABSPATH ) )
				? ltrim( substr( wp_normalize_path( $path ), strlen( wp_normalize_path( ABSPATH ) ) ), '/' )
				: wp_normalize_path( $path );
			$severity   = false !== strpos( strtolower( basename( $path ) ), 'wp-config' ) || '.env' === basename( $path ) ? 'high' : 'medium';
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
						++$high_frequency;
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
		if ( ! self::lock() ) {
			return false;
		}
		try {
			$result = get_option( 'aegisguard_last_scan_results', array() );
			if ( ! empty( $result['pending'] ) && ! delete_option( 'aegisguard_last_scan_results' ) ) {
				return false;
			}
			if ( false === $wpdb->query( $wpdb->prepare( 'TRUNCATE TABLE %i', $wpdb->prefix . 'aegisguard_integrity' ) ) ) { // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Explicit administrator-authorized reset of an internal table.
				return false;
			}
			delete_option( 'aegisguard_integrity_initialized' );
			Logger::log( 'security.integrity_baseline_reset', 'File-integrity baseline reset by an authorized administrator.', 'high' );
			return true;
		} finally {
			self::unlock();
		}
	}


	public static function quarantine( $path ) {
		return Quarantine::store( $path );
	}

	public static function list_quarantine() {
		return Quarantine::all();
	}

	public static function restore_quarantine( $name ) {
		return Quarantine::restore( $name );
	}

	public static function delete_quarantine( $name ) {
		return Quarantine::delete( $name );
	}

	private static function inspect_content( $path, $content, $ext ) {
		$findings = array();
		$relative = 0 === strpos( wp_normalize_path( $path ), wp_normalize_path( ABSPATH ) ) ? ltrim( substr( wp_normalize_path( $path ), strlen( wp_normalize_path( ABSPATH ) ) ), '/' ) : wp_normalize_path( $path );
		$signals  = 0;
		if ( preg_match( '/\beval\s*\(\s*(?:base64_decode|gzinflate|str_rot13)\s*\(/i', $content ) ) {
			$signals   += 5;
			$findings[] = self::finding( 'critical', 'malware_obfuscated_eval', $relative, 'Obfuscated dynamic code execution pattern detected.' );
		}
		if ( preg_match( '/\b(?:shell_exec|passthru|proc_open|popen)\s*\(/i', $content ) && ! self::official_core_file_is_clean( $path ) ) {
			$signals   += 2;
			$findings[] = self::finding( 'medium', 'dangerous_execution_function', $relative, 'Dangerous process execution function detected. Verify whether the use is legitimate.' );
		}
		if ( preg_match( '/(?:FilesMan|WSO\s*Shell|r57shell|c99shell|b374k)/i', $content ) ) {
			$signals   += 8;
			$findings[] = self::finding( 'critical', 'known_webshell_marker', $relative, 'Known web-shell marker detected.' );
		}
		if ( 'php' === $ext && false !== strpos( wp_normalize_path( $path ), wp_normalize_path( WP_CONTENT_DIR . '/uploads/' ) ) ) {
			$signals   += 6;
			$findings[] = self::finding( 'critical', 'php_in_uploads', $relative, 'PHP executable file found in the uploads directory.' );
		}
		if ( preg_match( '/\$[a-zA-Z_][a-zA-Z0-9_]*\s*=\s*["\'][A-Za-z0-9+\/]{500,}={0,2}["\']/s', $content ) ) {
			$findings[] = self::finding( 'high', 'high_entropy_payload', $relative, 'Large encoded payload detected; review for obfuscation.' );
		}
		if ( $signals >= 8 ) {
			Logger::log(
				'security.malware_candidate',
				'High-confidence malware candidate detected during scan.',
				'critical',
				array(
					'file'         => $relative,
					'signal_score' => $signals,
				)
			);
		}
		return $findings;
	}

	private static function core_checksums() {
		if ( self::$core_checksums_loaded ) {
			return self::$core_checksums;
		}
		self::$core_checksums_loaded = true;
		if ( ! function_exists( 'get_core_checksums' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		if ( ! function_exists( 'get_core_checksums' ) ) {
			self::$core_checksums = false;
			return false;
		}
		global $wp_version;
		$checksums            = get_core_checksums( $wp_version, get_locale() );
		self::$core_checksums = is_array( $checksums ) ? $checksums : false;
		return self::$core_checksums;
	}

	private static function official_core_file_is_clean( $path ) {
		$root       = wp_normalize_path( trailingslashit( ABSPATH ) );
		$normalized = wp_normalize_path( $path );
		if ( 0 !== strpos( $normalized, $root ) ) {
			return false;
		}
		$relative  = ltrim( substr( $normalized, strlen( $root ) ), '/' );
		$checksums = self::core_checksums();
		if ( ! is_array( $checksums ) || ! isset( $checksums[ $relative ] ) ) {
			return false;
		}
		$actual = md5_file( $normalized ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_md5_file -- WordPress checksum API supplies MD5 values; used only for integrity comparison.
		return is_string( $actual ) && hash_equals( (string) $checksums[ $relative ], $actual );
	}



	private static function check_integrity_baseline( $path, $file, $ext, $baseline_initialized, $file_hash ) {
		global $wpdb;
		$table      = $wpdb->prefix . 'aegisguard_integrity';
		$normalized = wp_normalize_path( $path );
		$relative   = 0 === strpos( $normalized, wp_normalize_path( ABSPATH ) ) ? ltrim( substr( $normalized, strlen( wp_normalize_path( ABSPATH ) ) ), '/' ) : $normalized;
		$path_hash  = hash( 'sha256', $relative );
		$existing   = $wpdb->get_row( $wpdb->prepare( "SELECT id, file_hash FROM {$table} WHERE path_hash = %s LIMIT 1", $path_hash ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Integrity scan requires the current internal baseline row.

		if ( $wpdb->last_error ) {
			return self::database_error();
		}
		if ( $existing ) {
			if ( ! hash_equals( (string) $existing->file_hash, (string) $file_hash ) ) {
				$updated = $wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Updates the plugin's current integrity baseline metadata.
					$table,
					array(
						'file_size'  => (int) $file->getSize(),
						'file_mtime' => (int) $file->getMTime(),
						'last_seen'  => current_time( 'mysql', true ),
					),
					array( 'id' => (int) $existing->id ),
					array( '%d', '%d', '%s' ),
					array( '%d' )
				);
				if ( false === $updated ) {
					return self::database_error();
				}
				return self::finding( 'medium', 'file_modified_since_baseline', $relative, 'File contents changed since the accepted integrity baseline.' );
			}
			$updated = $wpdb->update( $table, array( 'last_seen' => current_time( 'mysql', true ) ), array( 'id' => (int) $existing->id ), array( '%s' ), array( '%d' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Updates the plugin's current integrity baseline timestamp.
			return false === $updated ? self::database_error() : null;
		}

		if ( $baseline_initialized ) {
			$severity = ( 'php' === $ext && false !== strpos( $normalized, wp_normalize_path( WP_CONTENT_DIR . '/uploads/' ) ) ) ? 'critical' : 'low';
			return self::finding( $severity, 'file_new_since_baseline', $relative, 'A new scannable file appeared after the accepted integrity baseline was established.' );
		}

		$inserted = $wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Inserts an internal integrity baseline row.
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
			array( '%s', '%s', '%s', '%d', '%d', '%s', '%s' )
		);
		return false === $inserted ? self::database_error() : null;
	}

	private static function missing_baseline_files( $cursor ) {
		global $wpdb;
		$table = $wpdb->prefix . 'aegisguard_integrity';
		$rows  = $wpdb->get_results( $wpdb->prepare( 'SELECT id, file_path FROM %i WHERE id > %d ORDER BY id LIMIT 501', $table, $cursor ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Bounded keyset query against the accepted baseline.
		if ( $wpdb->last_error ) {
			return self::database_error();
		}
		$next = null;
		if ( count( $rows ) > 500 ) {
			array_pop( $rows );
			$next = (int) end( $rows )->id;
		}
		$findings = array();
		foreach ( $rows as $row ) {
			if ( '' !== $row->file_path && ! file_exists( ABSPATH . ltrim( $row->file_path, '/' ) ) ) {
				$findings[] = self::finding( 'medium', 'file_missing_since_baseline', $row->file_path, 'A file from the accepted integrity baseline is now missing.' );
			}
		}
		return array(
			'findings' => $findings,
			'cursor'   => $next,
		);
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
		$summary = array(
			'critical' => 0,
			'high'     => 0,
			'medium'   => 0,
			'low'      => 0,
			'info'     => 0,
			'total'    => count( $findings ),
		);
		foreach ( $findings as $finding ) {
			$severity = isset( $finding['severity'] ) ? $finding['severity'] : 'info';
			if ( isset( $summary[ $severity ] ) ) {
				++$summary[ $severity ];
			}
		}
		return $summary;
	}

	public static function sort_findings( $a, $b ) {
		$rank = array(
			'critical' => 5,
			'high'     => 4,
			'medium'   => 3,
			'low'      => 2,
			'info'     => 1,
		);
		return $rank[ $b['severity'] ] <=> $rank[ $a['severity'] ];
	}
}
