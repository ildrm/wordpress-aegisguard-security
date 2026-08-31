<?php
namespace AegisGuard\Core;

use AegisGuard\Admin\Admin;
use AegisGuard\Security\ActivityMonitor;
use AegisGuard\Security\Hardening;
use AegisGuard\Security\LoginProtection;
use AegisGuard\Security\Mfa;
use AegisGuard\Security\OutboundMonitor;
use AegisGuard\Security\Scanner;
use AegisGuard\Security\UploadProtection;
use AegisGuard\Support\Privacy;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Plugin {
	private static $instance;
	private $booted = false;

	public static function instance() {
		if ( ! self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function boot() {
		if ( $this->booted ) {
			return;
		}
		$this->booted = true;

		add_action( 'plugins_loaded', array( $this, 'load_textdomain' ) );
		add_action( 'init', array( $this, 'maybe_upgrade' ), 1 );
		add_action( 'aegisguard_daily_maintenance', array( $this, 'maintenance' ) );
		if ( is_multisite() ) {
			add_action( 'wp_initialize_site', array( $this, 'initialize_network_site' ), 100, 2 );
		}

		Hardening::register();
		LoginProtection::register();
		Mfa::register();
		OutboundMonitor::register();
		UploadProtection::register();
		ActivityMonitor::register();
		Scanner::register();
		Privacy::register();

		if ( is_admin() ) {
			Admin::register();
		}
	}

	public function load_textdomain() {
		load_plugin_textdomain( 'aegisguard-security', false, dirname( AEGISGUARD_BASENAME ) . '/languages' );
	}

	public function maybe_upgrade() {
		$version = get_option( 'aegisguard_db_version', '0' );
		if ( version_compare( $version, Activator::DB_VERSION, '<' ) ) {
			Activator::install_site();
		}
	}


	public function initialize_network_site( $new_site, $args ) {
		unset( $args );
		$network_plugins = (array) get_site_option( 'active_sitewide_plugins', array() );
		if ( ! isset( $network_plugins[ AEGISGUARD_BASENAME ] ) || ! ( $new_site instanceof \WP_Site ) ) {
			return;
		}
		switch_to_blog( (int) $new_site->blog_id );
		Activator::install_site();
		restore_current_blog();
	}

	public function maintenance() {
		global $wpdb;
		$days   = max( 1, (int) \AegisGuard\Support\Settings::get( 'event_retention_days', 30 ) );
		$table  = $wpdb->prefix . 'aegisguard_events';
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );
		$batch = max( 100, min( 5000, (int) \AegisGuard\Support\Settings::get( 'log_retention_cleanup_batch', 1000 ) ) );
		$last_deleted = $wpdb->get_row( $wpdb->prepare( "SELECT id, chain_hash FROM {$table} WHERE created_at < %s ORDER BY id ASC LIMIT %d", $cutoff, $batch ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Internal table name.
		if ( $last_deleted ) {
			$candidates = $wpdb->get_results( $wpdb->prepare( "SELECT id, chain_hash FROM {$table} WHERE created_at < %s ORDER BY id ASC LIMIT %d", $cutoff, $batch ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Internal table name.
			if ( $candidates ) {
				$tail = end( $candidates );
				$ids  = array_map( 'absint', wp_list_pluck( $candidates, 'id' ) );
				$ids  = array_values( array_filter( $ids ) );
				if ( $ids ) {
					$placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
					$sql = $wpdb->prepare( "DELETE FROM {$table} WHERE id IN ({$placeholders})", $ids ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Placeholders are generated internally; values are integer IDs.
					$deleted = $wpdb->query( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Query is prepared immediately above.
					if ( $deleted && ! empty( $tail['chain_hash'] ) ) {
						update_option( 'aegisguard_audit_anchor', (string) $tail['chain_hash'], false );
					}
				}
			}
		}
	}
}
