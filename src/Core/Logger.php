<?php
namespace AegisGuard\Core;

use AegisGuard\Support\Request;
use AegisGuard\Support\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Logger {

	public static function log( $type, $message, $severity = 'info', $context = array() ) {

		if ( ! Settings::get( 'audit_logging', true ) && 0 !== strpos( $type, 'security.' ) ) {
			return false;
		}

		global $wpdb;
		$table        = $wpdb->prefix . 'aegisguard_events';
		$path         = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- redact_url discards query data and sanitizes the retained path before storage.
		$path         = self::redact_url( $path );
		$method       = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_key( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';
		$method       = strtoupper( substr( $method, 0, 10 ) );
		$severity     = in_array( $severity, array( 'info', 'low', 'medium', 'high', 'critical' ), true ) ? $severity : 'info';
		$created_at   = current_time( 'mysql', true );
		$event_type   = self::normalize_event_type( $type );
		$actor_id     = get_current_user_id();
		$ip_address   = Request::anonymized_ip();
		$clean_text   = sanitize_text_field( $message );
		$clean_ctx    = self::redact_context( $context );
		$context_json = wp_json_encode( $clean_ctx );

		if ( ! self::acquire_chain_lock() ) {
			return false;
		}
		try {
			$previous   = self::last_hash();
			$payload    = self::chain_payload( $created_at, $event_type, $severity, $actor_id, $ip_address, $method, $path, $clean_text, $context_json, $previous );
			$chain_hash = hash_hmac( 'sha256', $payload, self::audit_key() );

			$result = $wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Append-only write to the plugin's audit table.
				$table,
				array(
					'created_at'     => $created_at,
					'event_type'     => $event_type,
					'severity'       => $severity,
					'actor_user_id'  => $actor_id,
					'ip_address'     => $ip_address,
					'request_method' => $method,
					'request_path'   => $path,
					'message'        => $clean_text,
					'context'        => $context_json,
					'chain_hash'     => $chain_hash,
				),
				array( '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s' )
			);
		} finally {
			self::release_chain_lock();
		}

		if ( false !== $result ) {
			\AegisGuard\Security\IncidentManager::observe( (int) $wpdb->insert_id, $type, $message, $severity );
			self::maybe_alert( $type, $message, $severity );
		}
		return false !== $result;
	}

	public static function prune( $cutoff, $batch = 1000 ) {
		if ( ! self::acquire_chain_lock() ) {
			return false;
		}
		try {
			global $wpdb;
			$table      = $wpdb->prefix . 'aegisguard_events';
			$batch      = max( 100, min( 5000, absint( $batch ) ) );
			$candidates = $wpdb->get_results( $wpdb->prepare( "SELECT id, chain_hash FROM {$table} WHERE created_at < %s ORDER BY id ASC LIMIT %d", sanitize_text_field( $cutoff ), $batch ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Serialized retention query against the internal audit table; values use placeholders.
			if ( ! $candidates ) {
				return 0;
			}
			$tail = end( $candidates );
			$ids  = array_values( array_filter( array_map( 'absint', wp_list_pluck( $candidates, 'id' ) ) ) );
			if ( ! $ids ) {
				return 0;
			}
			$placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
			$sql          = $wpdb->prepare( "DELETE FROM {$table} WHERE id IN ({$placeholders})", $ids ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- Table name and placeholder list are generated internally; values are integer IDs.
			$deleted      = $wpdb->query( $sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Query is prepared immediately above and serialized under the audit lock.
			if ( count( $ids ) !== (int) $deleted || empty( $tail['chain_hash'] ) ) {
				return false;
			}
			update_option( 'aegisguard_audit_anchor', (string) $tail['chain_hash'], false );
			return (int) $deleted;
		} finally {
			self::release_chain_lock();
		}
	}

	public static function verify_chain( $limit = 2000 ) {

		if ( ! self::acquire_chain_lock() ) {
			return array(
				'valid'           => false,
				'checked'         => 0,
				'broken_event_id' => 0,
				'error'           => 'lock_unavailable',
			);
		}
		try {
			global $wpdb;
			$table = $wpdb->prefix . 'aegisguard_events';
			$limit = max( 2, min( 10000, absint( $limit ) ) );
			$rows  = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM (SELECT id, created_at, event_type, severity, actor_user_id, ip_address, request_method, request_path, message, context, chain_hash FROM {$table} ORDER BY id DESC LIMIT %d) AS recent ORDER BY id ASC", $limit ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Serialized verification query against the internal audit table.
			if ( ! $rows ) {
				return array(
					'valid'           => true,
					'checked'         => 0,
					'broken_event_id' => 0,
				);
			}

			$first_id = (int) $rows[0]->id;
			$previous = '';
			if ( $first_id > 1 ) {
				$previous_hash = $wpdb->get_var( $wpdb->prepare( "SELECT chain_hash FROM {$table} WHERE id < %d ORDER BY id DESC LIMIT 1", $first_id ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Serialized chain predecessor query against the internal audit table.
				$previous      = is_string( $previous_hash ) && '' !== $previous_hash ? $previous_hash : (string) get_option( 'aegisguard_audit_anchor', '' );
			}

			$checked = 0;
			foreach ( $rows as $row ) {
				$payload  = self::chain_payload( $row->created_at, $row->event_type, $row->severity, (int) $row->actor_user_id, $row->ip_address, $row->request_method, $row->request_path, $row->message, $row->context, $previous );
				$expected = hash_hmac( 'sha256', $payload, self::audit_key() );
				++$checked;
				if ( ! is_string( $row->chain_hash ) || ! hash_equals( $expected, $row->chain_hash ) ) {
					return array(
						'valid'           => false,
						'checked'         => $checked,
						'broken_event_id' => (int) $row->id,
					);
				}
				$previous = $row->chain_hash;
			}
			return array(
				'valid'           => true,
				'checked'         => $checked,
				'broken_event_id' => 0,
			);
		} finally {
			self::release_chain_lock();
		}
	}

	private static function last_hash() {

		global $wpdb;
		$table = $wpdb->prefix . 'aegisguard_events';
		$hash  = $wpdb->get_var( "SELECT chain_hash FROM {$table} ORDER BY id DESC LIMIT 1" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Serialized query against the internal append-only audit table.
		return is_string( $hash ) && '' !== $hash ? $hash : (string) get_option( 'aegisguard_audit_anchor', '' );
	}

	private static function acquire_chain_lock() {

		global $wpdb;
		$result = $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, %d)', self::chain_lock_name(), 3 ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Database advisory lock coordinates audit-chain writers across PHP workers.
		return '1' === (string) $result;
	}

	private static function release_chain_lock() {

		global $wpdb;
		$wpdb->get_var( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', self::chain_lock_name() ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Releases the audit-chain database advisory lock.
	}

	private static function chain_lock_name() {

		global $wpdb;
		return 'aegisguard_audit_' . substr( hash( 'sha256', $wpdb->prefix . '|' . get_current_blog_id() ), 0, 32 );
	}

	private static function normalize_event_type( $type ) {
		return substr( preg_replace( '/[^a-z0-9._-]/', '', strtolower( (string) $type ) ), 0, 100 );
	}

	private static function audit_key() {
		$encoded = get_option( 'aegisguard_audit_key', '' );
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Binary cryptographic key deserialization, not code obfuscation.
		$key = base64_decode( (string) $encoded, true );
		if ( false !== $key && 32 === strlen( $key ) ) {
			return $key;
		}
		/* A deterministic fallback is used only until activation/upgrade creates the dedicated key. */
		return hash( 'sha256', wp_salt( 'auth' ) . '|aegisguard-audit', true );
	}

	private static function chain_payload( $created_at, $event_type, $severity, $actor_id, $ip_address, $method, $path, $message, $context_json, $previous ) {
		return implode(
			"\n",
			array(
				(string) $created_at,
				(string) $event_type,
				(string) $severity,
				(string) (int) $actor_id,
				(string) $ip_address,
				(string) $method,
				(string) $path,
				(string) $message,
				(string) $context_json,
				(string) $previous,
			)
		);
	}

	private static function redact_url( $url ) {
		$url = (string) $url;
		if ( '' === $url ) {
			return '';
		}
		$parts = wp_parse_url( $url );
		if ( empty( $parts['path'] ) ) {
			return '/';
		}
		return substr( sanitize_text_field( $parts['path'] ), 0, 1000 );
	}

	private static function redact_context( $context ) {
		if ( ! is_array( $context ) ) {
			return array();
		}
		$sensitive = array( 'password', 'pass', 'pwd', 'token', 'secret', 'api_key', 'authorization', 'cookie', 'nonce' );
		$out       = array();
		foreach ( $context as $key => $value ) {
			$key_string   = sanitize_key( (string) $key );
			$is_sensitive = false;
			foreach ( $sensitive as $needle ) {
				if ( false !== strpos( $key_string, $needle ) ) {
					$is_sensitive = true;
					break;
				}
			}
			if ( $is_sensitive ) {
				$out[ $key_string ] = '[redacted]';
			} elseif ( is_scalar( $value ) || null === $value ) {
				$out[ $key_string ] = substr( sanitize_text_field( (string) $value ), 0, 1000 );
			} elseif ( is_array( $value ) ) {
				$out[ $key_string ] = self::redact_context( $value );
			}
		}
		return $out;
	}

	private static function maybe_alert( $type, $message, $severity ) {
		if ( ! Settings::get( 'email_alerts', true ) ) {
			return;
		}
		$ranks     = array(
			'info'     => 0,
			'low'      => 1,
			'medium'   => 2,
			'high'     => 3,
			'critical' => 4,
		);
		$threshold = Settings::get( 'alert_threshold', 'high' );
		$threshold = isset( $ranks[ $threshold ] ) ? $threshold : 'high';
		if ( $ranks[ $severity ] < $ranks[ $threshold ] ) {
			return;
		}
		$key = 'aegisguard_alert_' . md5( $type . '|' . $message );
		if ( get_transient( $key ) ) {
			return;
		}
		set_transient( $key, 1, 15 * MINUTE_IN_SECONDS );
		$email = Settings::get( 'alert_email', get_option( 'admin_email' ) );
		if ( ! is_email( $email ) ) {
			return;
		}
		$subject = sprintf( '[%s] AegisGuard: %s', wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ), strtoupper( $severity ) );
		$body    = $message . "\n\nEvent: " . $type . "\nSite: " . home_url( '/' ) . "\nTime: " . current_time( 'mysql' );
		wp_mail( $email, $subject, $body );
	}
}
