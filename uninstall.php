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
function aegisguard_uninstall_site() {
	$role = get_role( 'administrator' );
	if ( $role ) {
		foreach ( array( 'aegisguard_view_security', 'aegisguard_manage_security', 'aegisguard_run_scans', 'aegisguard_manage_incidents' ) as $cap ) {
			$role->remove_cap( $cap );
		}
	}

	wp_clear_scheduled_hook( 'aegisguard_daily_maintenance' );

	$settings = get_option( 'aegisguard_settings', array() );
	if ( empty( $settings['delete_data_on_uninstall'] ) ) {
		return;
	}

	global $wpdb;
	$tables = array(
		$wpdb->prefix . 'aegisguard_events',
		$wpdb->prefix . 'aegisguard_incidents',
		$wpdb->prefix . 'aegisguard_integrity',
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
			'aegisguard_mfa_key',
		) as $option
	) {
		delete_option( $option );
	}

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

if ( is_multisite() ) {
	$aegisguard_site_ids = get_sites( array( 'fields' => 'ids' ) );
	foreach ( $aegisguard_site_ids as $aegisguard_site_id ) {
		switch_to_blog( (int) $aegisguard_site_id );
		aegisguard_uninstall_site();
		restore_current_blog();
	}
} else {
	aegisguard_uninstall_site();
}
