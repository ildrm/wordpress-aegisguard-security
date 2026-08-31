<?php
namespace AegisGuard\Security;

use AegisGuard\Core\Logger;
use AegisGuard\Support\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ActivityMonitor {
	public static function register() {
		if ( ! Settings::get( 'audit_logging', true ) ) {
			return;
		}
		add_action( 'user_register', array( __CLASS__, 'user_created' ) );
		add_action( 'deleted_user', array( __CLASS__, 'user_deleted' ) );
		add_action( 'set_user_role', array( __CLASS__, 'user_role_changed' ), 10, 3 );
		add_action( 'activated_plugin', array( __CLASS__, 'plugin_activated' ), 10, 2 );
		add_action( 'deactivated_plugin', array( __CLASS__, 'plugin_deactivated' ), 10, 2 );
		add_action( 'switch_theme', array( __CLASS__, 'theme_switched' ), 10, 3 );
		add_action( 'upgrader_process_complete', array( __CLASS__, 'upgrade_completed' ), 10, 2 );
		add_action( 'updated_option', array( __CLASS__, 'option_updated' ), 10, 3 );
		add_action( 'add_option', array( __CLASS__, 'option_added' ), 10, 2 );
		add_action( 'wp_logout', array( __CLASS__, 'logout' ) );
		add_action( 'application_password_did_authenticate', array( __CLASS__, 'application_password_authenticated' ), 10, 2 );

		if ( Settings::get( 'woocommerce_monitoring', true ) ) {
			add_action( 'woocommerce_order_refunded', array( __CLASS__, 'woocommerce_refund' ), 10, 2 );
		}
	}

	public static function user_created( $user_id ) {
		$user = get_userdata( $user_id );
		$roles = $user ? implode( ',', $user->roles ) : '';
		Logger::log( 'user.created', 'User account created.', in_array( 'administrator', $user ? $user->roles : array(), true ) ? 'high' : 'info', array( 'target_user_id' => $user_id, 'roles' => $roles ) );
	}

	public static function user_deleted( $user_id ) {
		Logger::log( 'user.deleted', 'User account deleted.', 'medium', array( 'target_user_id' => $user_id ) );
	}

	public static function user_role_changed( $user_id, $role, $old_roles ) {
		$severity = 'administrator' === $role ? 'high' : 'medium';
		Logger::log( 'user.role_changed', 'User role changed.', $severity, array( 'target_user_id' => $user_id, 'new_role' => $role, 'old_roles' => implode( ',', (array) $old_roles ) ) );
	}

	public static function plugin_activated( $plugin, $network_wide ) {
		Logger::log( 'plugin.activated', 'Plugin activated.', 'medium', array( 'plugin' => $plugin, 'network_wide' => $network_wide ? 'yes' : 'no' ) );
	}

	public static function plugin_deactivated( $plugin, $network_wide ) {
		$severity = AEGISGUARD_BASENAME === $plugin ? 'critical' : 'medium';
		Logger::log( 'plugin.deactivated', 'Plugin deactivated.', $severity, array( 'plugin' => $plugin, 'network_wide' => $network_wide ? 'yes' : 'no' ) );
	}

	public static function theme_switched( $new_name, $new_theme, $old_theme ) {
		Logger::log( 'theme.switched', 'Active theme changed.', 'medium', array( 'new_theme' => $new_name, 'old_theme' => $old_theme ? $old_theme->get( 'Name' ) : '' ) );
	}

	public static function upgrade_completed( $upgrader, $options ) {
		unset( $upgrader );
		$type = isset( $options['type'] ) ? sanitize_key( $options['type'] ) : 'unknown';
		$action = isset( $options['action'] ) ? sanitize_key( $options['action'] ) : 'unknown';
		Logger::log( 'software.updated', 'WordPress software update operation completed.', 'medium', array( 'type' => $type, 'action' => $action ) );
	}

	public static function option_updated( $option, $old_value, $value ) {
		unset( $old_value, $value );
		if ( self::skip_option( $option ) ) {
			return;
		}
		Logger::log( 'option.updated', 'WordPress option updated.', 'low', array( 'option' => $option ) );
	}

	public static function option_added( $option, $value ) {
		unset( $value );
		if ( self::skip_option( $option ) ) {
			return;
		}
		Logger::log( 'option.added', 'WordPress option added.', 'low', array( 'option' => $option ) );
	}

	public static function logout() {
		Logger::log( 'auth.logout', 'User logged out.', 'info' );
	}

	public static function application_password_authenticated( $user, $item ) {
		Logger::log( 'auth.application_password', 'Application password authenticated.', 'medium', array( 'user_id' => $user->ID, 'application_uuid' => isset( $item['uuid'] ) ? $item['uuid'] : '' ) );
	}

	public static function woocommerce_refund( $order_id, $refund_id ) {
		Logger::log( 'woocommerce.refund', 'WooCommerce refund created.', 'high', array( 'order_id' => $order_id, 'refund_id' => $refund_id ) );
	}

	private static function skip_option( $option ) {
		$option = (string) $option;
		return 0 === strpos( $option, '_transient_' ) || 0 === strpos( $option, '_site_transient_' ) || 0 === strpos( $option, 'aegisguard_' ) || in_array( $option, array( 'cron', 'rewrite_rules' ), true );
	}
}
