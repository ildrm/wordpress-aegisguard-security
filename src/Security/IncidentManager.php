<?php
namespace AegisGuard\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class IncidentManager {
	public static function observe( $event_id, $type, $message, $severity, $context = array() ) {
		if ( ! in_array( $severity, array( 'high', 'critical' ), true ) ) {
			return;
		}
		if ( 'high' === $severity && 0 !== strpos( (string) $type, 'security.' ) ) {
			return;
		}

		global $wpdb;
		$table       = $wpdb->prefix . 'aegisguard_incidents';
		$fingerprint = hash( 'sha256', preg_replace( '/[^a-z0-9._-]/', '', strtolower( (string) $type ) ) . '|' . sanitize_text_field( $message ) );
		$existing    = $wpdb->get_row( $wpdb->prepare( "SELECT id, context FROM {$table} WHERE fingerprint = %s AND status = 'open' ORDER BY id DESC LIMIT 1", $fingerprint ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Internal table name.
		$now         = current_time( 'mysql', true );

		if ( $existing ) {
			$old_context = json_decode( (string) $existing->context, true );
			$old_context = is_array( $old_context ) ? $old_context : array();
			$count       = isset( $old_context['event_count'] ) ? (int) $old_context['event_count'] + 1 : 2;
			$wpdb->update(
				$table,
				array(
					'updated_at' => $now,
					'severity'   => $severity,
					'context'    => wp_json_encode( array( 'event_count' => $count, 'latest_event_id' => (int) $event_id ) ),
				),
				array( 'id' => (int) $existing->id ),
				array( '%s', '%s', '%s' ),
				array( '%d' )
			);
			return;
		}

		$wpdb->insert(
			$table,
			array(
				'created_at'  => $now,
				'updated_at'  => $now,
				'status'      => 'open',
				'severity'    => $severity,
				'title'       => sanitize_text_field( self::title_for_type( $type ) ),
				'description' => sanitize_text_field( $message ),
				'fingerprint' => $fingerprint,
				'context'     => wp_json_encode( array( 'event_count' => 1, 'latest_event_id' => (int) $event_id ) ),
			),
			array( '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s' )
		);
	}

	private static function title_for_type( $type ) {
		$labels = array(
			'security.waf_block'          => __( 'Firewall blocked a hostile request', 'aegisguard-security' ),
			'security.malware_candidate'  => __( 'Malware candidate detected', 'aegisguard-security' ),
			'security.upload_polyglot'     => __( 'Executable upload payload detected', 'aegisguard-security' ),
			'security.login_rate_limited' => __( 'Login attack rate-limited', 'aegisguard-security' ),
			'security.mfa_failed'          => __( 'MFA challenge failures detected', 'aegisguard-security' ),
		);
		return isset( $labels[ $type ] ) ? $labels[ $type ] : ucwords( str_replace( array( '.', '_' ), ' ', (string) $type ) );
	}
}
