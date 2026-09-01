<?php
namespace AegisGuard\Support;

use AegisGuard\Security\Mfa;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Privacy {
	const PAGE_SIZE = 50;

	public static function register() {
		add_filter( 'wp_privacy_personal_data_exporters', array( __CLASS__, 'register_exporter' ) );
		add_filter( 'wp_privacy_personal_data_erasers', array( __CLASS__, 'register_eraser' ) );
		add_action( 'admin_init', array( __CLASS__, 'privacy_policy_content' ) );
	}

	public static function register_exporter( $exporters ) {
		$exporters['aegisguard-security'] = array(
			'exporter_friendly_name' => __( 'AegisGuard Security', 'aegisguard-security' ),
			'callback'               => array( __CLASS__, 'export_personal_data' ),
		);
		return $exporters;
	}

	public static function register_eraser( $erasers ) {
		$erasers['aegisguard-security'] = array(
			'eraser_friendly_name' => __( 'AegisGuard Security', 'aegisguard-security' ),
			'callback'             => array( __CLASS__, 'erase_personal_data' ),
		);
		return $erasers;
	}

	public static function export_personal_data( $email_address, $page = 1 ) {
		$user = get_user_by( 'email', $email_address );
		if ( ! $user ) {
			return array(
				'data' => array(),
				'done' => true,
			);
		}

		global $wpdb;
		$table  = $wpdb->prefix . 'aegisguard_events';
		$page   = max( 1, absint( $page ) );
		$offset = ( $page - 1 ) * self::PAGE_SIZE;
		$rows   = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Privacy export requires a current paginated read from the internal audit table.
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Internal table name; all values use placeholders.
				"SELECT id, created_at, event_type, severity, ip_address, request_method, request_path, message FROM {$table} WHERE actor_user_id = %d ORDER BY id ASC LIMIT %d OFFSET %d",
				$user->ID,
				self::PAGE_SIZE,
				$offset
			)
		);

		$data = array();
		if ( 1 === $page ) {
			$data[] = array(
				'group_id'          => 'aegisguard-security-profile',
				'group_label'       => __( 'AegisGuard Security profile', 'aegisguard-security' ),
				'group_description' => __( 'Security-state information associated with the WordPress account. Authentication secrets and recovery-code hashes are never exported.', 'aegisguard-security' ),
				'item_id'           => 'aegisguard-profile-' . (int) $user->ID,
				'data'              => array(
					array(
						'name'  => __( 'MFA enabled', 'aegisguard-security' ),
						'value' => Mfa::is_enabled( $user->ID ) ? __( 'Yes', 'aegisguard-security' ) : __( 'No', 'aegisguard-security' ),
					),
				),
			);
		}

		foreach ( (array) $rows as $row ) {
			$data[] = array(
				'group_id'          => 'aegisguard-security-events',
				'group_label'       => __( 'AegisGuard Security events', 'aegisguard-security' ),
				'group_description' => __( 'Security audit events recorded while this account was the authenticated actor.', 'aegisguard-security' ),
				'item_id'           => 'aegisguard-event-' . (int) $row->id,
				'data'              => array(
					array(
						'name'  => __( 'Time (UTC)', 'aegisguard-security' ),
						'value' => $row->created_at,
					),
					array(
						'name'  => __( 'Event type', 'aegisguard-security' ),
						'value' => $row->event_type,
					),
					array(
						'name'  => __( 'Severity', 'aegisguard-security' ),
						'value' => $row->severity,
					),
					array(
						'name'  => __( 'IP address', 'aegisguard-security' ),
						'value' => $row->ip_address,
					),
					array(
						'name'  => __( 'Request method', 'aegisguard-security' ),
						'value' => $row->request_method,
					),
					array(
						'name'  => __( 'Request path', 'aegisguard-security' ),
						'value' => $row->request_path,
					),
					array(
						'name'  => __( 'Message', 'aegisguard-security' ),
						'value' => $row->message,
					),
				),
			);
		}

		return array(
			'data' => $data,
			'done' => count( $rows ) < self::PAGE_SIZE,
		);
	}

	public static function erase_personal_data( $email_address, $page = 1 ) {
		unset( $page );
		$user = get_user_by( 'email', $email_address );
		if ( ! $user ) {
			return array(
				'items_removed'  => false,
				'items_retained' => false,
				'messages'       => array(),
				'done'           => true,
			);
		}

		global $wpdb;
		$table    = $wpdb->prefix . 'aegisguard_events';
		$count    = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE actor_user_id = %d", $user->ID ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Privacy policy text needs a current count from the internal audit table.
		$mfa      = Mfa::is_enabled( $user->ID );
		$messages = array();

		if ( $count > 0 ) {
			$messages[] = __( 'AegisGuard security audit events were retained to preserve the site security audit trail. They expire according to the configured event-retention policy.', 'aegisguard-security' );
		}
		if ( $mfa ) {
			$messages[] = __( 'MFA credentials were retained because the WordPress account still exists and removing them through a privacy erasure request would weaken account authentication. Disable MFA explicitly or delete the account when appropriate.', 'aegisguard-security' );
		}

		return array(
			'items_removed'  => false,
			'items_retained' => $count > 0 || $mfa,
			'messages'       => $messages,
			'done'           => true,
		);
	}

	public static function privacy_policy_content() {
		if ( ! function_exists( 'wp_add_privacy_policy_content' ) ) {
			return;
		}
		$text  = '<p>' . esc_html__( 'AegisGuard Security records security events that may include the authenticated WordPress user ID, IP address (or an anonymized form when enabled), request method and path, event severity, and security-related context. Passwords, authentication tokens, cookies, nonces, and recognized secret fields are redacted from event context.', 'aegisguard-security' ) . '</p>';
		$text .= '<p>' . esc_html__( 'Security events are retained for the number of days configured by the site administrator. The plugin does not transmit this local security telemetry to an AegisGuard cloud service in this standalone release.', 'aegisguard-security' ) . '</p>';
		wp_add_privacy_policy_content( __( 'AegisGuard Security', 'aegisguard-security' ), $text );
	}
}
