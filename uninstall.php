<?php
/**
 * AegisGuard Security uninstall routine.
 *
 * @package AegisGuardSecurity
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

/**
 * Remove AegisGuard capabilities and optionally stored data for one site.
 */
function aegisguard_uninstall_site( $delete_account_data ) {
	$role = get_role( 'administrator' );
	if ( $role ) {
		foreach ( array( 'aegisguard_view_security', 'aegisguard_manage_security', 'aegisguard_run_scans', 'aegisguard_manage_incidents' ) as $cap ) {
			$role->remove_cap( $cap );
		}
	}

	wp_clear_scheduled_hook( 'aegisguard_daily_maintenance' );

	global $wpdb;
	if ( $delete_account_data ) {
		delete_option( 'aegisguard_mfa_key' );
		$counter_pattern = $wpdb->esc_like( 'aegisguard_mfa_counter_' ) . '%';
		$lock_pattern    = $wpdb->esc_like( 'aegisguard_mfa_recovery_lock_' ) . '%';
		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Opt-in uninstall cleanup of per-user replay and mutex options.
			$wpdb->prepare(
				"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
				$counter_pattern,
				$lock_pattern
			)
		); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- WordPress supplies the options table name; both patterns use placeholders.
	}

	$settings = get_option( 'aegisguard_settings', array() );
	if ( empty( $settings['delete_data_on_uninstall'] ) ) {
		return;
	}

	$tables = array(
		$wpdb->prefix . 'aegisguard_events',
		$wpdb->prefix . 'aegisguard_incidents',
		$wpdb->prefix . 'aegisguard_integrity',
		$wpdb->prefix . 'aegisguard_login_limits',
	);

	foreach ( $tables as $table ) {
		$wpdb->query( 'DROP TABLE IF EXISTS `' . esc_sql( $table ) . '`' ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange -- Opt-in uninstall cleanup of internal tables derived only from $wpdb->prefix.
	}

	foreach (
		array(
			'aegisguard_settings',
			'aegisguard_db_version',
			'aegisguard_last_scan',
			'aegisguard_last_scan_results',
			'aegisguard_install_id',
			'aegisguard_lockdown',
			'aegisguard_integrity_initialized',
			'aegisguard_quarantine_key',
			'aegisguard_audit_key',
			'aegisguard_audit_anchor',
		) as $option
	) {
		delete_option( $option );
	}
	delete_transient( 'aegisguard_upgrade_retry' );
}

$aegisguard_delete_account_data = false;
if ( is_multisite() ) {
	$aegisguard_site_ids = get_sites(
		array(
			'fields' => 'ids',
			'number' => 0,
		)
	);
	// Credentials are shared user metadata. Retain their keys if any installed site retains its data.
	$aegisguard_delete_account_data = true;
	$aegisguard_any_opt_in          = false;
	foreach ( $aegisguard_site_ids as $aegisguard_site_id ) {
		$aegisguard_settings   = get_blog_option( $aegisguard_site_id, 'aegisguard_settings', false );
		$aegisguard_any_opt_in = $aegisguard_any_opt_in || ! empty( $aegisguard_settings['delete_data_on_uninstall'] );
		if ( false !== $aegisguard_settings && empty( $aegisguard_settings['delete_data_on_uninstall'] ) ) {
			$aegisguard_delete_account_data = false;
			break;
		}
	}
	$aegisguard_delete_account_data = $aegisguard_delete_account_data && $aegisguard_any_opt_in;
	foreach ( $aegisguard_site_ids as $aegisguard_site_id ) {
		switch_to_blog( (int) $aegisguard_site_id );
		aegisguard_uninstall_site( $aegisguard_delete_account_data );
		restore_current_blog();
	}
} else {
	$aegisguard_settings            = get_option( 'aegisguard_settings', array() );
	$aegisguard_delete_account_data = ! empty( $aegisguard_settings['delete_data_on_uninstall'] );
	aegisguard_uninstall_site( $aegisguard_delete_account_data );
}

if ( $aegisguard_delete_account_data ) {
	foreach ( array( '_aegisguard_totp_secret', '_aegisguard_totp_pending', '_aegisguard_recovery_codes' ) as $aegisguard_meta_key ) {
		delete_metadata( 'user', 0, $aegisguard_meta_key, '', true );
	}
}
