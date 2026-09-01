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
		$days   = max( 1, (int) \AegisGuard\Support\Settings::get( 'event_retention_days', 30 ) );
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );
		$batch  = (int) \AegisGuard\Support\Settings::get( 'log_retention_cleanup_batch', 1000 );
		Logger::prune( $cutoff, $batch );
	}
}
