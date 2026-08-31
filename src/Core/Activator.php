<?php
namespace AegisGuard\Core;

use AegisGuard\Support\Capabilities;
use AegisGuard\Support\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Activator {
	const DB_VERSION = '1.0.0';

	public static function activate( $network_wide = false ) {
		if ( is_multisite() && $network_wide ) {
			$site_ids = get_sites( array( 'fields' => 'ids' ) );
			foreach ( $site_ids as $site_id ) {
				switch_to_blog( (int) $site_id );
				self::install_site();
				restore_current_blog();
			}
			return;
		}
		self::install_site();
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
		self::create_tables();
		Capabilities::grant_to_administrators();

		if ( false === get_option( Settings::OPTION, false ) ) {
			add_option( Settings::OPTION, Settings::defaults(), '', false );
		}
		if ( false === get_option( 'aegisguard_install_id', false ) ) {
			add_option( 'aegisguard_install_id', wp_generate_uuid4(), '', false );
		}
		if ( false === get_option( 'aegisguard_quarantine_key', false ) ) {
			add_option( 'aegisguard_quarantine_key', base64_encode( random_bytes( 32 ) ), '', false );
		}
		if ( false === get_option( 'aegisguard_audit_key', false ) ) {
			add_option( 'aegisguard_audit_key', base64_encode( random_bytes( 32 ) ), '', false );
		}
		if ( false === get_option( 'aegisguard_mfa_key', false ) ) {
			add_option( 'aegisguard_mfa_key', base64_encode( random_bytes( 32 ) ), '', false );
		}
		update_option( 'aegisguard_db_version', self::DB_VERSION, false );

		if ( ! wp_next_scheduled( 'aegisguard_daily_maintenance' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'aegisguard_daily_maintenance' );
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
	}
}
