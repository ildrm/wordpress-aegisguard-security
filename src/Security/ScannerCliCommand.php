<?php
namespace AegisGuard\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class ScannerCliCommand {
	/**
	 * Run a full local security scan.
	 *
	 * ## EXAMPLES
	 *
	 *     wp aegisguard scan
	 *
	 * @subcommand scan
	 */
	public function scan() {
		$result = Scanner::run_full_scan();
		if ( is_wp_error( $result ) ) {
			\WP_CLI::error( $result->get_error_message() );
			return;
		}
		if ( ! empty( $result['stats']['files_skipped'] ) || ! empty( $result['stats']['file_errors'] ) ) {
			\WP_CLI::warning( sprintf( 'Unscanned entries: %d over the byte limit, %d read or storage errors.', $result['stats']['files_skipped'], $result['stats']['file_errors'] ) );
		}
		if ( ! empty( $result['pending'] ) ) {
			\WP_CLI::log( sprintf( 'Scan progress saved with %d finding(s). Run the same command to continue.', $result['summary']['total'] ) );
			return;
		}
		\WP_CLI::success( sprintf( 'Scan complete: %d finding(s), %d critical, %d high.', $result['summary']['total'], $result['summary']['critical'], $result['summary']['high'] ) );
	}

	/**
	 * Enable emergency lockdown mode.
	 *
	 * @subcommand lockdown-enable
	 */
	public function lockdown_enable() {
		update_option( 'aegisguard_lockdown', 1, false );
		\WP_CLI::success( 'Emergency lockdown enabled.' );
	}

	/**
	 * Disable emergency lockdown mode.
	 *
	 * @subcommand lockdown-disable
	 */
	public function lockdown_disable() {
		delete_option( 'aegisguard_lockdown' );
		\WP_CLI::success( 'Emergency lockdown disabled.' );
	}

	/** Disable the local application firewall. */
	public function firewall_disable() {
		$settings                = \AegisGuard\Support\Settings::all();
		$settings['waf_enabled'] = false;
		update_option( \AegisGuard\Support\Settings::OPTION, $settings, false );
		\WP_CLI::success( 'Application firewall disabled.' );
	}

	/** Enable the local application firewall. */
	public function firewall_enable() {
		$settings                = \AegisGuard\Support\Settings::all();
		$settings['waf_enabled'] = true;
		update_option( \AegisGuard\Support\Settings::OPTION, $settings, false );
		\WP_CLI::success( 'Application firewall enabled.' );
	}

	/**
	 * Remove a temporary WAF block for an IP address.
	 *
	 * ## OPTIONS
	 * <ip>
	 * : IPv4 or IPv6 address.
	 */
	public function unblock( $args ) {
		$ip = isset( $args[0] ) ? $args[0] : '';
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			\WP_CLI::error( 'Provide a valid IPv4 or IPv6 address.' );
		}
		delete_transient( 'aegisguard_ipblock_' . hash( 'sha256', $ip ) );
		\WP_CLI::success( 'Temporary WAF block removed.' );
	}

	/**
	 * Disable MFA for a locked-out WordPress user.
	 *
	 * ## OPTIONS
	 * <user>
	 * : User ID, login, or email.
	 */
	public function mfa_disable( $args ) {
		$identity = isset( $args[0] ) ? (string) $args[0] : '';
		$user     = ctype_digit( $identity ) ? get_user_by( 'id', (int) $identity ) : get_user_by( 'login', $identity );
		if ( ! $user && is_email( $identity ) ) {
			$user = get_user_by( 'email', $identity );
		}
		if ( ! $user ) {
			\WP_CLI::error( 'User not found.' );
		}
		Mfa::disable_for_user( $user->ID );
		\WP_CLI::success( 'MFA disabled for user ' . $user->user_login . '.' );
	}
}
