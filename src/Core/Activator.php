<?php
namespace AegisGuard\Core;

use AegisGuard\Support\Capabilities;
use AegisGuard\Support\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Activator {
	const DB_VERSION = '1.0.2';

	public static function activate( $network_wide = false ) {
		if ( is_multisite() && $network_wide ) {
			$site_ids = get_sites( array( 'fields' => 'ids' ) );
			foreach ( $site_ids as $site_id ) {
				switch_to_blog( (int) $site_id );
				$installed = self::install_site();
				restore_current_blog();
				if ( ! $installed ) {
					self::activation_failed();
				}
			}
			return;
		}
		if ( ! self::install_site() ) {
			self::activation_failed();
		}
	}

	private static function activation_failed() {
		wp_die( esc_html__( 'AegisGuard could not verify its database tables and indexes. Check the database permissions and try activation again.', 'aegisguard-security' ) );
	}

	public static function deactivate( $network_wide = false ) {
		if ( is_multisite() && $network_wide ) {
			$site_ids = get_sites( array( 'fields' => 'ids' ) );
			foreach ( $site_ids as $site_id ) {
				switch_to_blog( (int) $site_id );
				wp_clear_scheduled_hook( 'aegisguard_daily_maintenance' );
				restore_current_blog();
			}
			return;
		}
		wp_clear_scheduled_hook( 'aegisguard_daily_maintenance' );
	}

	public static function install_site() {
		global $wpdb;
		$previous = $wpdb->suppress_errors();
		try {
			$schema_ready = self::create_tables();
		} finally {
			$wpdb->suppress_errors( $previous );
		}
		if ( ! $schema_ready ) {
			set_transient( 'aegisguard_upgrade_retry', 1, MINUTE_IN_SECONDS );
			return false;
		}
		self::ensure_keys();
		Capabilities::grant_to_administrators();
		if ( false === get_option( Settings::OPTION, false ) ) {
			add_option( Settings::OPTION, Settings::defaults(), '', false );
		}
		if ( false === get_option( 'aegisguard_install_id', false ) ) {
			add_option( 'aegisguard_install_id', wp_generate_uuid4(), '', false );
		}
		update_option( 'aegisguard_db_version', self::DB_VERSION, false );
		delete_transient( 'aegisguard_upgrade_retry' );
		if ( ! wp_next_scheduled( 'aegisguard_daily_maintenance' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'aegisguard_daily_maintenance' );
		}
		return true;
	}

	private static function ensure_keys() {

		foreach ( array( 'aegisguard_quarantine_key', 'aegisguard_audit_key', 'aegisguard_mfa_key' ) as $option_name ) {
			if ( false === get_option( $option_name, false ) ) {
				// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Binary cryptographic key serialization, not code obfuscation.
				add_option( $option_name, base64_encode( random_bytes( 32 ) ), '', false );
			}
		}
	}
	private static function create_tables() {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $wpdb->get_charset_collate();

		$events = $wpdb->prefix . 'aegisguard_events';
		$sql    = "CREATE TABLE {$events} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			created_at datetime NOT NULL,
			event_type varchar(100) NOT NULL,
			severity varchar(20) NOT NULL DEFAULT 'info',
			actor_user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			ip_address varchar(64) NOT NULL DEFAULT '',
			request_method varchar(10) NOT NULL DEFAULT '',
			request_path text NULL,
			message text NOT NULL,
			context longtext NULL,
			chain_hash char(64) NOT NULL DEFAULT '',
			PRIMARY KEY  (id),
			KEY created_at (created_at),
			KEY event_type (event_type),
			KEY severity (severity),
			KEY actor_user_id (actor_user_id)
		) {$charset};";
		dbDelta( $sql );

		$incidents = $wpdb->prefix . 'aegisguard_incidents';
		$sql       = "CREATE TABLE {$incidents} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			created_at datetime NOT NULL,
			updated_at datetime NOT NULL,
			status varchar(20) NOT NULL DEFAULT 'open',
			severity varchar(20) NOT NULL DEFAULT 'high',
			title varchar(255) NOT NULL,
			description longtext NULL,
			fingerprint char(64) NOT NULL DEFAULT '',
			context longtext NULL,
			PRIMARY KEY  (id),
			KEY status (status),
			KEY severity (severity),
			KEY fingerprint (fingerprint)
		) {$charset};";
		dbDelta( $sql );

		$integrity = $wpdb->prefix . 'aegisguard_integrity';
		$sql       = "CREATE TABLE {$integrity} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			file_path text NOT NULL,
			path_hash char(64) NOT NULL,
			file_hash char(64) NOT NULL,
			file_size bigint(20) unsigned NOT NULL DEFAULT 0,
			file_mtime bigint(20) unsigned NOT NULL DEFAULT 0,
			file_type varchar(30) NOT NULL DEFAULT 'other',
			last_seen datetime NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY path_hash (path_hash),
			KEY file_type (file_type)
		) {$charset};";
		dbDelta( $sql );

		$limits = $wpdb->prefix . 'aegisguard_login_limits';
		$sql    = "CREATE TABLE {$limits} (
			bucket varchar(95) NOT NULL,
			failures int unsigned NOT NULL,
			expires_at bigint(20) unsigned NOT NULL,
			PRIMARY KEY  (bucket),
			KEY expires_at (expires_at)
		) {$charset};";
		dbDelta( $sql );

		return self::verify_table(
			$events,
			array( 'id', 'created_at', 'event_type', 'severity', 'actor_user_id', 'ip_address', 'request_method', 'request_path', 'message', 'context', 'chain_hash' ),
			array(
				'PRIMARY'       => 'id',
				'created_at'    => 'created_at',
				'event_type'    => 'event_type',
				'severity'      => 'severity',
				'actor_user_id' => 'actor_user_id',
			)
		)
			&& self::verify_table(
				$incidents,
				array( 'id', 'created_at', 'updated_at', 'status', 'severity', 'title', 'description', 'fingerprint', 'context' ),
				array(
					'PRIMARY'     => 'id',
					'status'      => 'status',
					'severity'    => 'severity',
					'fingerprint' => 'fingerprint',
				)
			)
			&& self::verify_table(
				$integrity,
				array( 'id', 'file_path', 'path_hash', 'file_hash', 'file_size', 'file_mtime', 'file_type', 'last_seen' ),
				array(
					'PRIMARY'   => 'id',
					'path_hash' => 'path_hash',
					'file_type' => 'file_type',
				)
			)
			&& self::verify_table(
				$limits,
				array( 'bucket', 'failures', 'expires_at' ),
				array(
					'PRIMARY'    => 'bucket',
					'expires_at' => 'expires_at',
				)
			);
	}

	private static function verify_table( $table, $required_columns, $required_indexes ) {
		global $wpdb;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Verify the actual schema after dbDelta, regardless of its reported operations.
		$columns = $wpdb->get_col( $wpdb->prepare( 'SHOW COLUMNS FROM %i', $table ) );
		$indexes = $wpdb->get_results( $wpdb->prepare( 'SHOW INDEX FROM %i', $table ), ARRAY_A );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		if ( array_diff( $required_columns, $columns ) ) {
			return false;
		}
		$by_name = array();
		foreach ( $indexes as $index ) {
			$by_name[ $index['Key_name'] ][] = $index;
		}
		foreach ( $required_indexes as $key => $column ) {
			$rows   = $by_name[ $key ] ?? array();
			$index  = $rows[0] ?? array();
			$unique = in_array( $key, array( 'PRIMARY', 'path_hash' ), true );
			if ( ! $index || $column !== $index['Column_name'] || 1 !== (int) $index['Seq_in_index'] || null !== $index['Sub_part'] ) {
				return false;
			}
			if ( $unique && ( 1 !== count( $rows ) || 0 !== (int) $index['Non_unique'] ) ) {
				return false;
			}
		}
		return true;
	}
}
