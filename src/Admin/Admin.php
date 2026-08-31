<?php
namespace AegisGuard\Admin;

use AegisGuard\Core\Logger;
use AegisGuard\Security\Mfa;
use AegisGuard\Security\Scanner;
use AegisGuard\Support\Capabilities;
use AegisGuard\Support\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Admin {
	public static function register() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_action( 'admin_post_aegisguard_save_settings', array( __CLASS__, 'save_settings' ) );
		add_action( 'admin_post_aegisguard_run_scan', array( __CLASS__, 'run_scan' ) );
		add_action( 'admin_post_aegisguard_reset_baseline', array( __CLASS__, 'reset_baseline' ) );
		add_action( 'admin_post_aegisguard_toggle_lockdown', array( __CLASS__, 'toggle_lockdown' ) );
		add_action( 'admin_post_aegisguard_quarantine', array( __CLASS__, 'quarantine' ) );
		add_action( 'admin_post_aegisguard_restore_quarantine', array( __CLASS__, 'restore_quarantine' ) );
		add_action( 'admin_post_aegisguard_delete_quarantine', array( __CLASS__, 'delete_quarantine' ) );
		add_action( 'admin_post_aegisguard_resolve_incident', array( __CLASS__, 'resolve_incident' ) );
		add_action( 'admin_post_aegisguard_revoke_other_sessions', array( __CLASS__, 'revoke_other_sessions' ) );
		add_action( 'admin_notices', array( __CLASS__, 'admin_notices' ) );
	}

	public static function menu() {
		add_menu_page(
			__( 'AegisGuard Security', 'aegisguard-security' ),
			__( 'AegisGuard', 'aegisguard-security' ),
			Capabilities::VIEW,
			'aegisguard-security',
			array( __CLASS__, 'dashboard' ),
			'dashicons-shield-alt',
			58
		);
		add_submenu_page( 'aegisguard-security', __( 'Security Dashboard', 'aegisguard-security' ), __( 'Dashboard', 'aegisguard-security' ), Capabilities::VIEW, 'aegisguard-security', array( __CLASS__, 'dashboard' ) );
		add_submenu_page( 'aegisguard-security', __( 'Security Scanner', 'aegisguard-security' ), __( 'Scanner', 'aegisguard-security' ), Capabilities::SCAN, 'aegisguard-scanner', array( __CLASS__, 'scanner' ) );
		add_submenu_page( 'aegisguard-security', __( 'Quarantine', 'aegisguard-security' ), __( 'Quarantine', 'aegisguard-security' ), Capabilities::INCIDENT, 'aegisguard-quarantine', array( __CLASS__, 'quarantine_page' ) );
		add_submenu_page( 'aegisguard-security', __( 'Identity Security', 'aegisguard-security' ), __( 'Identity', 'aegisguard-security' ), Capabilities::VIEW, 'aegisguard-identity', array( __CLASS__, 'identity' ) );
		add_submenu_page( 'aegisguard-security', __( 'Security Incidents', 'aegisguard-security' ), __( 'Incidents', 'aegisguard-security' ), Capabilities::VIEW, 'aegisguard-incidents', array( __CLASS__, 'incidents' ) );
		add_submenu_page( 'aegisguard-security', __( 'Security Events', 'aegisguard-security' ), __( 'Events', 'aegisguard-security' ), Capabilities::VIEW, 'aegisguard-events', array( __CLASS__, 'events' ) );
		add_submenu_page( 'aegisguard-security', __( 'Attack Surface', 'aegisguard-security' ), __( 'Attack Surface', 'aegisguard-security' ), Capabilities::VIEW, 'aegisguard-surface', array( __CLASS__, 'attack_surface' ) );
		add_submenu_page( 'aegisguard-security', __( 'Security Settings', 'aegisguard-security' ), __( 'Settings', 'aegisguard-security' ), Capabilities::MANAGE, 'aegisguard-settings', array( __CLASS__, 'settings_page' ) );
	}

	public static function assets( $hook ) {
		if ( false === strpos( (string) $hook, 'aegisguard' ) ) {
			return;
		}
		wp_enqueue_style( 'aegisguard-admin', AEGISGUARD_URL . 'assets/css/admin.css', array(), AEGISGUARD_VERSION );
		wp_enqueue_script( 'aegisguard-admin', AEGISGUARD_URL . 'assets/js/admin.js', array(), AEGISGUARD_VERSION, true );
	}

	public static function dashboard() {
		self::require_cap( Capabilities::VIEW );
		$settings = Settings::all();
		$scan     = get_option( 'aegisguard_last_scan_results', array() );
		$score    = self::security_score( $settings, $scan );
		$summary  = isset( $scan['summary'] ) && is_array( $scan['summary'] ) ? $scan['summary'] : array( 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'total' => 0 );
		$lockdown = (bool) get_option( 'aegisguard_lockdown', false );
		?>
		<div class="wrap aegisguard-wrap">
			<?php self::header( __( 'Security Command Center', 'aegisguard-security' ), __( 'A concise view of site risk, active protections, and the actions that matter most.', 'aegisguard-security' ) ); ?>
			<div class="ag-grid ag-grid-4">
				<?php self::metric( __( 'Security score', 'aegisguard-security' ), $score . '/100', $score >= 85 ? 'good' : ( $score >= 65 ? 'warn' : 'danger' ) ); ?>
				<?php self::metric( __( 'Critical findings', 'aegisguard-security' ), (int) $summary['critical'], (int) $summary['critical'] > 0 ? 'danger' : 'good' ); ?>
				<?php self::metric( __( 'High findings', 'aegisguard-security' ), (int) $summary['high'], (int) $summary['high'] > 0 ? 'warn' : 'good' ); ?>
				<?php self::metric( __( 'Emergency lockdown', 'aegisguard-security' ), $lockdown ? __( 'Enabled', 'aegisguard-security' ) : __( 'Off', 'aegisguard-security' ), $lockdown ? 'danger' : 'good' ); ?>
			</div>

			<div class="ag-grid ag-grid-2 ag-section-gap">
				<section class="ag-card">
					<h2><?php esc_html_e( 'Protection status', 'aegisguard-security' ); ?></h2>
					<ul class="ag-status-list">
						<?php self::status_row( __( 'Application firewall', 'aegisguard-security' ), ! empty( $settings['waf_enabled'] ), ucfirst( $settings['waf_mode'] ) ); ?>
						<?php self::status_row( __( 'Login rate limiting', 'aegisguard-security' ), ! empty( $settings['login_rate_limit'] ) ); ?>
						<?php self::status_row( __( 'Upload protection', 'aegisguard-security' ), ! empty( $settings['upload_protection'] ) ); ?>
						<?php self::status_row( __( 'Security headers', 'aegisguard-security' ), ! empty( $settings['security_headers'] ) ); ?>
						<?php self::status_row( __( 'Audit logging', 'aegisguard-security' ), ! empty( $settings['audit_logging'] ) ); ?>
						<?php self::status_row( __( 'Database scanning', 'aegisguard-security' ), ! empty( $settings['database_scan'] ) ); ?>
					</ul>
				</section>

				<section class="ag-card">
					<h2><?php esc_html_e( 'Priority actions', 'aegisguard-security' ); ?></h2>
					<?php if ( empty( $scan ) ) : ?>
						<p><?php esc_html_e( 'No complete security scan has been run yet. Establish a baseline before making aggressive changes.', 'aegisguard-security' ); ?></p>
						<a class="button button-primary" href="<?php echo esc_url( admin_url( 'admin.php?page=aegisguard-scanner' ) ); ?>"><?php esc_html_e( 'Run first scan', 'aegisguard-security' ); ?></a>
					<?php elseif ( (int) $summary['critical'] > 0 ) : ?>
						<p class="ag-danger-text"><?php echo esc_html( sprintf( _n( '%d critical issue requires review.', '%d critical issues require review.', (int) $summary['critical'], 'aegisguard-security' ), (int) $summary['critical'] ) ); ?></p>
						<a class="button button-primary" href="<?php echo esc_url( admin_url( 'admin.php?page=aegisguard-scanner' ) ); ?>"><?php esc_html_e( 'Review findings', 'aegisguard-security' ); ?></a>
					<?php else : ?>
						<p><?php esc_html_e( 'No critical findings are present in the last scan. Review high and medium findings and keep WordPress, plugins, and themes current.', 'aegisguard-security' ); ?></p>
						<a class="button" href="<?php echo esc_url( admin_url( 'admin.php?page=aegisguard-events' ) ); ?>"><?php esc_html_e( 'Review security events', 'aegisguard-security' ); ?></a>
					<?php endif; ?>
				</section>
			</div>

			<section class="ag-card ag-section-gap">
				<div class="ag-card-head"><div><h2><?php esc_html_e( 'Incident response', 'aegisguard-security' ); ?></h2><p><?php esc_html_e( 'Emergency lockdown restricts wp-admin and REST access to help contain an active compromise. WP-CLI remains available for recovery.', 'aegisguard-security' ); ?></p></div></div>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<input type="hidden" name="action" value="aegisguard_toggle_lockdown">
					<?php wp_nonce_field( 'aegisguard_toggle_lockdown' ); ?>
					<input type="hidden" name="enable" value="<?php echo esc_attr( $lockdown ? '0' : '1' ); ?>">
					<button type="submit" class="button <?php echo esc_attr( $lockdown ? '' : 'button-secondary' ); ?>"><?php echo esc_html( $lockdown ? __( 'Disable lockdown', 'aegisguard-security' ) : __( 'Enable emergency lockdown', 'aegisguard-security' ) ); ?></button>
				</form>
			</section>
		</div>
		<?php
	}

	public static function scanner() {
		self::require_cap( Capabilities::SCAN );
		$result = get_option( 'aegisguard_last_scan_results', array() );
		?>
		<div class="wrap aegisguard-wrap">
			<?php self::header( __( 'Security Scanner', 'aegisguard-security' ), __( 'Checks files, official WordPress core checksums, database content, persistence indicators, configuration, and update posture.', 'aegisguard-security' ) ); ?>
			<section class="ag-card">
				<div class="ag-actions">
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
						<input type="hidden" name="action" value="aegisguard_run_scan">
						<?php wp_nonce_field( 'aegisguard_run_scan' ); ?>
						<button class="button button-primary button-hero" type="submit"><?php esc_html_e( 'Run full security scan', 'aegisguard-security' ); ?></button>
					</form>
					<?php if ( get_option( 'aegisguard_integrity_initialized', false ) && current_user_can( Capabilities::INCIDENT ) ) : ?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" data-ag-confirm="<?php echo esc_attr__( 'Rebuild the accepted integrity baseline? Do this only after you have verified current file changes are legitimate.', 'aegisguard-security' ); ?>">
						<input type="hidden" name="action" value="aegisguard_reset_baseline">
						<?php wp_nonce_field( 'aegisguard_reset_baseline' ); ?>
						<button class="button" type="submit"><?php esc_html_e( 'Rebuild integrity baseline', 'aegisguard-security' ); ?></button>
					</form>
					<?php endif; ?>
				</div>
				<p class="description"><?php esc_html_e( 'Large sites should begin with conservative scan limits in Settings. The scanner never executes discovered code.', 'aegisguard-security' ); ?></p>
			</section>
			<?php if ( ! empty( $result ) ) : self::render_scan_result( $result ); endif; ?>
		</div>
		<?php
	}


	public static function quarantine_page() {
		self::require_cap( Capabilities::INCIDENT );
		$items = Scanner::list_quarantine();
		?>
		<div class="wrap aegisguard-wrap">
			<?php self::header( __( 'Encrypted Quarantine', 'aegisguard-security' ), __( 'Review files that were explicitly quarantined. Records are encrypted at rest and can only be restored to their authenticated original path.', 'aegisguard-security' ) ); ?>
			<section class="ag-card">
				<div class="ag-card-head">
					<div>
						<h2><?php esc_html_e( 'Quarantined files', 'aegisguard-security' ); ?></h2>
						<p><?php esc_html_e( 'Restore only when you have verified that the file is legitimate. Permanent deletion cannot be undone.', 'aegisguard-security' ); ?></p>
					</div>
				</div>
				<div class="ag-table-wrap">
					<table class="widefat striped ag-table">
						<thead><tr><th><?php esc_html_e( 'Captured', 'aegisguard-security' ); ?></th><th><?php esc_html_e( 'Original path', 'aegisguard-security' ); ?></th><th><?php esc_html_e( 'SHA-256', 'aegisguard-security' ); ?></th><th><?php esc_html_e( 'Status', 'aegisguard-security' ); ?></th><th><?php esc_html_e( 'Actions', 'aegisguard-security' ); ?></th></tr></thead>
						<tbody>
						<?php if ( $items ) : foreach ( $items as $item ) : ?>
							<tr>
								<td><?php echo esc_html( ! empty( $item['captured_at'] ) ? $item['captured_at'] : '—' ); ?></td>
								<td><code class="ag-path"><?php echo esc_html( ! empty( $item['original_path'] ) ? $item['original_path'] : $item['name'] ); ?></code></td>
								<td><code class="ag-path"><?php echo esc_html( ! empty( $item['sha256'] ) ? $item['sha256'] : '—' ); ?></code></td>
								<td><span class="ag-badge <?php echo esc_attr( ! empty( $item['valid'] ) ? 'ag-badge-good' : 'ag-badge-warn' ); ?>"><?php echo esc_html( ! empty( $item['valid'] ) ? __( 'Verified', 'aegisguard-security' ) : __( 'Unreadable', 'aegisguard-security' ) ); ?></span></td>
								<td>
									<div class="ag-actions">
									<?php if ( ! empty( $item['valid'] ) ) : ?>
										<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" data-ag-confirm="<?php echo esc_attr__( 'Restore this file to its original location? Restoration is refused if a file already exists there.', 'aegisguard-security' ); ?>">
											<input type="hidden" name="action" value="aegisguard_restore_quarantine">
											<input type="hidden" name="record" value="<?php echo esc_attr( $item['name'] ); ?>">
											<?php wp_nonce_field( 'aegisguard_restore_quarantine_' . $item['name'] ); ?>
											<button class="button button-small" type="submit"><?php esc_html_e( 'Restore', 'aegisguard-security' ); ?></button>
										</form>
									<?php endif; ?>
										<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" data-ag-confirm="<?php echo esc_attr__( 'Permanently delete this quarantine record? This cannot be undone.', 'aegisguard-security' ); ?>">
											<input type="hidden" name="action" value="aegisguard_delete_quarantine">
											<input type="hidden" name="record" value="<?php echo esc_attr( $item['name'] ); ?>">
											<?php wp_nonce_field( 'aegisguard_delete_quarantine_' . $item['name'] ); ?>
											<button class="button button-small button-link-delete" type="submit"><?php esc_html_e( 'Delete permanently', 'aegisguard-security' ); ?></button>
										</form>
									</div>
								</td>
							</tr>
						<?php endforeach; else : ?>
							<tr><td colspan="5"><?php esc_html_e( 'No files are currently quarantined.', 'aegisguard-security' ); ?></td></tr>
						<?php endif; ?>
						</tbody>
					</table>
				</div>
			</section>
		</div>
		<?php
	}

	public static function identity() {
		self::require_cap( Capabilities::VIEW );
		$user_id = get_current_user_id();
		$user    = wp_get_current_user();
		$recovery_codes = array();
		$message = '';
		$error   = '';

		if ( isset( $_POST['aegisguard_mfa_action'] ) ) {
			check_admin_referer( 'aegisguard_identity' );
			$action = sanitize_key( wp_unslash( $_POST['aegisguard_mfa_action'] ) );
			if ( 'begin' === $action ) {
				$result = Mfa::begin_setup( $user_id );
				if ( is_wp_error( $result ) ) {
					$error = $result->get_error_message();
				} else {
					$message = __( 'Setup key generated. Add it to your authenticator app, then enter a current six-digit code to confirm.', 'aegisguard-security' );
				}
			} elseif ( 'enable' === $action ) {
				$secret = Mfa::pending_secret( $user_id );
				$code   = isset( $_POST['totp_code'] ) ? sanitize_text_field( wp_unslash( $_POST['totp_code'] ) ) : '';
				if ( ! $secret || ! Mfa::verify_code( $secret, $code ) ) {
					$error = __( 'The authentication code was not valid. Check the device time and try again.', 'aegisguard-security' );
				} else {
					$enabled = Mfa::enable_for_user( $user_id, $secret );
					if ( is_wp_error( $enabled ) ) {
						$error = $enabled->get_error_message();
					} else {
						$recovery_codes = $enabled;
						$message = __( 'MFA is enabled. Save the recovery codes now; they are shown only in this response.', 'aegisguard-security' );
					}
				}
			} elseif ( 'disable' === $action ) {
				$password = isset( $_POST['current_password'] ) ? (string) wp_unslash( $_POST['current_password'] ) : '';
				if ( ! wp_check_password( $password, $user->user_pass, $user_id ) ) {
					$error = __( 'The current password was not valid.', 'aegisguard-security' );
				} else {
					Mfa::disable_for_user( $user_id );
					$message = __( 'MFA has been disabled for your account.', 'aegisguard-security' );
				}
			}
		}

		$enabled = Mfa::is_enabled( $user_id );
		$pending = Mfa::pending_secret( $user_id );
		?>
		<div class="wrap aegisguard-wrap">
			<?php self::header( __( 'Identity Security', 'aegisguard-security' ), __( 'Protect privileged WordPress access with time-based one-time passwords and one-use recovery codes.', 'aegisguard-security' ) ); ?>
			<?php if ( $message ) : ?><div class="notice notice-success inline"><p><?php echo esc_html( $message ); ?></p></div><?php endif; ?>
			<?php if ( $error ) : ?><div class="notice notice-error inline"><p><?php echo esc_html( $error ); ?></p></div><?php endif; ?>
			<div class="ag-grid ag-grid-2">
				<section class="ag-card">
					<h2><?php esc_html_e( 'Your MFA status', 'aegisguard-security' ); ?></h2>
					<p><span class="ag-badge <?php echo esc_attr( $enabled ? 'ag-badge-good' : 'ag-badge-warn' ); ?>"><?php echo esc_html( $enabled ? __( 'Enabled', 'aegisguard-security' ) : __( 'Not enabled', 'aegisguard-security' ) ); ?></span></p>
					<?php if ( ! $enabled && ! $pending ) : ?>
						<form method="post">
							<?php wp_nonce_field( 'aegisguard_identity' ); ?>
							<input type="hidden" name="aegisguard_mfa_action" value="begin">
							<button class="button button-primary" type="submit"><?php esc_html_e( 'Generate setup key', 'aegisguard-security' ); ?></button>
						</form>
					<?php elseif ( ! $enabled && $pending ) : ?>
						<p><?php esc_html_e( 'Authenticator secret:', 'aegisguard-security' ); ?></p>
						<code class="ag-secret"><?php echo esc_html( $pending ); ?></code>
						<p class="description"><?php esc_html_e( 'Add this secret manually in any RFC 6238-compatible authenticator. Do not share it.', 'aegisguard-security' ); ?></p>
						<form method="post" class="ag-stack">
							<?php wp_nonce_field( 'aegisguard_identity' ); ?>
							<input type="hidden" name="aegisguard_mfa_action" value="enable">
							<label for="totp_code"><strong><?php esc_html_e( 'Current six-digit code', 'aegisguard-security' ); ?></strong></label>
							<input type="text" class="regular-text" inputmode="numeric" maxlength="6" autocomplete="one-time-code" id="totp_code" name="totp_code" required>
							<button class="button button-primary" type="submit"><?php esc_html_e( 'Confirm and enable MFA', 'aegisguard-security' ); ?></button>
						</form>
					<?php else : ?>
						<form method="post" class="ag-stack">
							<?php wp_nonce_field( 'aegisguard_identity' ); ?>
							<input type="hidden" name="aegisguard_mfa_action" value="disable">
							<label for="current_password"><strong><?php esc_html_e( 'Current password', 'aegisguard-security' ); ?></strong></label>
							<input type="password" class="regular-text" autocomplete="current-password" id="current_password" name="current_password" required>
							<button class="button" type="submit"><?php esc_html_e( 'Disable MFA', 'aegisguard-security' ); ?></button>
						</form>
					<?php endif; ?>
				</section>
				<section class="ag-card">
					<h2><?php esc_html_e( 'Session overview', 'aegisguard-security' ); ?></h2>
					<?php
					$manager = \WP_Session_Tokens::get_instance( $user_id );
					$sessions = $manager->get_all();
					?>
					<p class="ag-big-number"><?php echo esc_html( (string) count( $sessions ) ); ?></p>
					<p><?php esc_html_e( 'Active WordPress session(s) for your account.', 'aegisguard-security' ); ?></p>
					<?php if ( count( $sessions ) > 1 ) : ?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" data-ag-confirm="<?php echo esc_attr__( 'Terminate every other WordPress session for your account?', 'aegisguard-security' ); ?>"><input type="hidden" name="action" value="aegisguard_revoke_other_sessions"><?php wp_nonce_field( 'aegisguard_revoke_other_sessions' ); ?><button type="submit" class="button"><?php esc_html_e( 'Terminate other sessions', 'aegisguard-security' ); ?></button></form>
					<?php endif; ?>
				</section>
			</div>
			<?php if ( $recovery_codes ) : ?>
				<section class="ag-card ag-section-gap ag-recovery">
					<h2><?php esc_html_e( 'Recovery codes — save now', 'aegisguard-security' ); ?></h2>
					<p><?php esc_html_e( 'Each code works once. Store them offline in a password manager or another secure location.', 'aegisguard-security' ); ?></p>
					<div class="ag-code-grid"><?php foreach ( $recovery_codes as $code ) : ?><code><?php echo esc_html( $code ); ?></code><?php endforeach; ?></div>
				</section>
			<?php endif; ?>
		</div>
		<?php
	}


	public static function incidents() {
		self::require_cap( Capabilities::VIEW );
		global $wpdb;
		$table = $wpdb->prefix . 'aegisguard_incidents';
		$incidents = $wpdb->get_results( "SELECT * FROM {$table} ORDER BY FIELD(status,'open','resolved'), FIELD(severity,'critical','high','medium','low'), updated_at DESC LIMIT 200" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Internal table name and fixed ordering.
		?>
		<div class="wrap aegisguard-wrap">
			<?php self::header( __( 'Security Incidents', 'aegisguard-security' ), __( 'Correlated high-severity events are grouped into incidents so repeated attacks do not become alert noise.', 'aegisguard-security' ) ); ?>
			<section class="ag-card">
				<div class="ag-table-wrap"><table class="widefat striped ag-table"><thead><tr><th><?php esc_html_e( 'Status', 'aegisguard-security' ); ?></th><th><?php esc_html_e( 'Severity', 'aegisguard-security' ); ?></th><th><?php esc_html_e( 'Incident', 'aegisguard-security' ); ?></th><th><?php esc_html_e( 'Last update', 'aegisguard-security' ); ?></th><th><?php esc_html_e( 'Events', 'aegisguard-security' ); ?></th><th><?php esc_html_e( 'Action', 'aegisguard-security' ); ?></th></tr></thead><tbody>
				<?php if ( $incidents ) : foreach ( $incidents as $incident ) : $ctx = json_decode( (string) $incident->context, true ); ?>
				<tr><td><?php echo esc_html( ucfirst( $incident->status ) ); ?></td><td><span class="ag-badge ag-sev-<?php echo esc_attr( $incident->severity ); ?>"><?php echo esc_html( ucfirst( $incident->severity ) ); ?></span></td><td><strong><?php echo esc_html( $incident->title ); ?></strong><br><span class="ag-muted"><?php echo esc_html( $incident->description ); ?></span></td><td><?php echo esc_html( $incident->updated_at ); ?> UTC</td><td><?php echo esc_html( isset( $ctx['event_count'] ) ? (string) (int) $ctx['event_count'] : '1' ); ?></td><td>
				<?php if ( 'open' === $incident->status && current_user_can( Capabilities::INCIDENT ) ) : ?>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>"><input type="hidden" name="action" value="aegisguard_resolve_incident"><input type="hidden" name="incident_id" value="<?php echo esc_attr( $incident->id ); ?>"><?php wp_nonce_field( 'aegisguard_resolve_incident_' . $incident->id ); ?><button class="button button-small" type="submit"><?php esc_html_e( 'Mark resolved', 'aegisguard-security' ); ?></button></form>
				<?php else : ?><span class="ag-muted">—</span><?php endif; ?>
				</td></tr>
				<?php endforeach; else : ?><tr><td colspan="6"><?php esc_html_e( 'No incidents have been created.', 'aegisguard-security' ); ?></td></tr><?php endif; ?>
				</tbody></table></div>
			</section>
		</div>
		<?php
	}

	public static function events() {
		self::require_cap( Capabilities::VIEW );
		global $wpdb;
		$table = $wpdb->prefix . 'aegisguard_events';
		$page_num = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only pagination.
		$severity = isset( $_GET['severity'] ) ? sanitize_key( wp_unslash( $_GET['severity'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only filter.
		$allowed = array( 'info', 'low', 'medium', 'high', 'critical' );
		$limit = 50;
		$offset = ( $page_num - 1 ) * $limit;
		if ( in_array( $severity, $allowed, true ) ) {
			$events = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE severity = %s ORDER BY id DESC LIMIT %d OFFSET %d", $severity, $limit, $offset ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Internal table name.
			$total = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE severity = %s", $severity ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Internal table name.
		} else {
			$events = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} ORDER BY id DESC LIMIT %d OFFSET %d", $limit, $offset ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Internal table name.
			$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Internal table name.
		}
		?>
		<div class="wrap aegisguard-wrap">
			<?php self::header( __( 'Security Events', 'aegisguard-security' ), __( 'Tamper-evident, privacy-aware audit records for authentication, security controls, software changes, and suspicious activity.', 'aegisguard-security' ) ); ?>
			<form method="get" class="ag-filter-bar">
				<input type="hidden" name="page" value="aegisguard-events">
				<label for="severity"><?php esc_html_e( 'Severity', 'aegisguard-security' ); ?></label>
				<select id="severity" name="severity">
					<option value=""><?php esc_html_e( 'All', 'aegisguard-security' ); ?></option>
					<?php foreach ( $allowed as $item ) : ?><option value="<?php echo esc_attr( $item ); ?>" <?php selected( $severity, $item ); ?>><?php echo esc_html( ucfirst( $item ) ); ?></option><?php endforeach; ?>
				</select>
				<button class="button" type="submit"><?php esc_html_e( 'Filter', 'aegisguard-security' ); ?></button>
			</form>
			<div class="ag-table-wrap">
			<table class="widefat striped ag-table">
				<thead><tr><th><?php esc_html_e( 'Time (UTC)', 'aegisguard-security' ); ?></th><th><?php esc_html_e( 'Severity', 'aegisguard-security' ); ?></th><th><?php esc_html_e( 'Event', 'aegisguard-security' ); ?></th><th><?php esc_html_e( 'Message', 'aegisguard-security' ); ?></th><th><?php esc_html_e( 'IP', 'aegisguard-security' ); ?></th></tr></thead>
				<tbody>
				<?php if ( $events ) : foreach ( $events as $event ) : ?>
					<tr><td><?php echo esc_html( $event->created_at ); ?></td><td><span class="ag-badge ag-sev-<?php echo esc_attr( $event->severity ); ?>"><?php echo esc_html( ucfirst( $event->severity ) ); ?></span></td><td><code><?php echo esc_html( $event->event_type ); ?></code></td><td><?php echo esc_html( $event->message ); ?></td><td><?php echo esc_html( $event->ip_address ); ?></td></tr>
				<?php endforeach; else : ?><tr><td colspan="5"><?php esc_html_e( 'No events found.', 'aegisguard-security' ); ?></td></tr><?php endif; ?>
				</tbody>
			</table>
			</div>
			<?php
			$total_pages = max( 1, (int) ceil( $total / $limit ) );
			echo wp_kses_post( paginate_links( array( 'base' => add_query_arg( 'paged', '%#%' ), 'format' => '', 'current' => $page_num, 'total' => $total_pages, 'type' => 'list' ) ) );
			?>
		</div>
		<?php
	}

	public static function attack_surface() {
		self::require_cap( Capabilities::VIEW );
		$routes = rest_get_server()->get_routes();
		$cron   = _get_cron_array();
		$public_routes = array();
		foreach ( $routes as $route => $handlers ) {
			$methods = array();
			foreach ( $handlers as $handler ) {
				if ( isset( $handler['methods'] ) ) {
					$methods = array_merge( $methods, array_keys( array_filter( (array) $handler['methods'] ) ) );
				}
			}
			$public_routes[] = array( 'route' => $route, 'methods' => implode( ', ', array_unique( $methods ) ) );
		}
		?>
		<div class="wrap aegisguard-wrap">
			<?php self::header( __( 'Attack Surface', 'aegisguard-security' ), __( 'Inventory the interfaces attackers can reach and the scheduled code paths that can establish persistence.', 'aegisguard-security' ) ); ?>
			<div class="ag-grid ag-grid-3">
				<?php self::metric( __( 'REST routes', 'aegisguard-security' ), count( $public_routes ), 'neutral' ); ?>
				<?php self::metric( __( 'Cron timestamps', 'aegisguard-security' ), is_array( $cron ) ? count( $cron ) : 0, 'neutral' ); ?>
				<?php self::metric( __( 'XML-RPC', 'aegisguard-security' ), Settings::get( 'disable_xmlrpc', false ) ? __( 'Disabled', 'aegisguard-security' ) : __( 'Available', 'aegisguard-security' ), Settings::get( 'disable_xmlrpc', false ) ? 'good' : 'warn' ); ?>
			</div>
			<section class="ag-card ag-section-gap">
				<h2><?php esc_html_e( 'REST API route inventory', 'aegisguard-security' ); ?></h2>
				<div class="ag-table-wrap"><table class="widefat striped ag-table"><thead><tr><th><?php esc_html_e( 'Route', 'aegisguard-security' ); ?></th><th><?php esc_html_e( 'Methods', 'aegisguard-security' ); ?></th></tr></thead><tbody>
				<?php foreach ( array_slice( $public_routes, 0, 300 ) as $route ) : ?><tr><td><code><?php echo esc_html( $route['route'] ); ?></code></td><td><?php echo esc_html( $route['methods'] ); ?></td></tr><?php endforeach; ?>
				</tbody></table></div>
				<?php if ( count( $public_routes ) > 300 ) : ?><p class="description"><?php esc_html_e( 'Only the first 300 routes are shown to keep the admin page responsive.', 'aegisguard-security' ); ?></p><?php endif; ?>
			</section>
		</div>
		<?php
	}

	public static function settings_page() {
		self::require_cap( Capabilities::MANAGE );
		$s = Settings::all();
		?>
		<div class="wrap aegisguard-wrap">
			<?php self::header( __( 'Security Settings', 'aegisguard-security' ), __( 'Use safe defaults first. Strict controls can affect page builders, APIs, checkout flows, and integrations.', 'aegisguard-security' ) ); ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="ag-settings-form">
				<input type="hidden" name="action" value="aegisguard_save_settings">
				<?php wp_nonce_field( 'aegisguard_save_settings' ); ?>
				<section class="ag-card">
					<h2><?php esc_html_e( 'Firewall and authentication', 'aegisguard-security' ); ?></h2>
					<?php self::checkbox( 'waf_enabled', __( 'Enable application firewall', 'aegisguard-security' ), $s['waf_enabled'], __( 'Inspects request paths and query strings for high-confidence exploit patterns.', 'aegisguard-security' ) ); ?>
					<?php self::select( 'waf_mode', __( 'Firewall mode', 'aegisguard-security' ), $s['waf_mode'], array( 'learning' => __( 'Learning', 'aegisguard-security' ), 'monitoring' => __( 'Monitoring', 'aegisguard-security' ), 'balanced' => __( 'Balanced', 'aegisguard-security' ), 'strict' => __( 'Strict', 'aegisguard-security' ) ) ); ?>
					<?php self::checkbox( 'login_rate_limit', __( 'Enable login rate limiting', 'aegisguard-security' ), $s['login_rate_limit'] ); ?>
					<?php self::number( 'login_attempts', __( 'Attempts per identity/IP window', 'aegisguard-security' ), $s['login_attempts'], 3, 100 ); ?>
					<?php self::number( 'login_window', __( 'Login window (seconds)', 'aegisguard-security' ), $s['login_window'], 60, DAY_IN_SECONDS ); ?>
					<?php self::number( 'block_duration', __( 'Temporary firewall block (seconds)', 'aegisguard-security' ), $s['block_duration'], 60, WEEK_IN_SECONDS ); ?>
				</section>
				<section class="ag-card ag-section-gap">
					<h2><?php esc_html_e( 'WordPress hardening', 'aegisguard-security' ); ?></h2>
					<?php self::checkbox( 'disable_xmlrpc', __( 'Disable XML-RPC', 'aegisguard-security' ), $s['disable_xmlrpc'], __( 'Enable only if no mobile app, Jetpack-style integration, or XML-RPC client depends on it.', 'aegisguard-security' ) ); ?>
					<?php self::checkbox( 'disable_pingbacks', __( 'Disable XML-RPC pingbacks', 'aegisguard-security' ), $s['disable_pingbacks'] ); ?>
					<?php self::checkbox( 'protect_user_enumeration', __( 'Reduce public user enumeration', 'aegisguard-security' ), $s['protect_user_enumeration'] ); ?>
					<?php self::checkbox( 'disable_file_editor', __( 'Disable plugin/theme editor capabilities', 'aegisguard-security' ), $s['disable_file_editor'] ); ?>
					<?php self::checkbox( 'security_headers', __( 'Send baseline security headers', 'aegisguard-security' ), $s['security_headers'] ); ?>
					<?php self::checkbox( 'upload_protection', __( 'Inspect uploads for executable/polyglot content', 'aegisguard-security' ), $s['upload_protection'] ); ?>
				</section>
				<section class="ag-card ag-section-gap">
					<h2><?php esc_html_e( 'Scanning, logging, and privacy', 'aegisguard-security' ); ?></h2>
					<?php self::checkbox( 'database_scan', __( 'Scan database content', 'aegisguard-security' ), $s['database_scan'] ); ?>
					<?php self::checkbox( 'audit_logging', __( 'Enable security audit log', 'aegisguard-security' ), $s['audit_logging'] ); ?>
					<?php self::number( 'event_retention_days', __( 'Event retention (days)', 'aegisguard-security' ), $s['event_retention_days'], 1, 365 ); ?>
					<?php self::number( 'malware_scan_max_files', __( 'Maximum files per scan', 'aegisguard-security' ), $s['malware_scan_max_files'], 100, 100000 ); ?>
					<?php self::number( 'file_scan_max_bytes', __( 'Maximum bytes read from each file', 'aegisguard-security' ), $s['file_scan_max_bytes'], 65536, 10485760 ); ?>
					<?php self::checkbox( 'privacy_ip_anonymization', __( 'Anonymize logged IP addresses', 'aegisguard-security' ), $s['privacy_ip_anonymization'] ); ?>
				</section>
				<section class="ag-card ag-section-gap">
					<h2><?php esc_html_e( 'Alerts and proxy trust', 'aegisguard-security' ); ?></h2>
					<?php self::checkbox( 'email_alerts', __( 'Email high-priority alerts', 'aegisguard-security' ), $s['email_alerts'] ); ?>
					<?php self::text( 'alert_email', __( 'Alert email', 'aegisguard-security' ), $s['alert_email'], 'email' ); ?>
					<?php self::select( 'alert_threshold', __( 'Minimum alert severity', 'aegisguard-security' ), $s['alert_threshold'], array( 'low' => __( 'Low', 'aegisguard-security' ), 'medium' => __( 'Medium', 'aegisguard-security' ), 'high' => __( 'High', 'aegisguard-security' ), 'critical' => __( 'Critical', 'aegisguard-security' ) ) ); ?>
					<?php self::checkbox( 'trust_proxy_headers', __( 'Trust X-Forwarded-For from explicitly listed proxies', 'aegisguard-security' ), $s['trust_proxy_headers'], __( 'Never enable this without listing the actual reverse-proxy addresses below.', 'aegisguard-security' ) ); ?>
					<div class="ag-field"><label for="trusted_proxy_ips"><strong><?php esc_html_e( 'Trusted proxy IPs', 'aegisguard-security' ); ?></strong></label><textarea class="large-text code" rows="4" id="trusted_proxy_ips" name="trusted_proxy_ips"><?php echo esc_textarea( $s['trusted_proxy_ips'] ); ?></textarea><p class="description"><?php esc_html_e( 'One IP per line. CIDR ranges are intentionally not accepted in this version to avoid ambiguous trust.', 'aegisguard-security' ); ?></p></div>
				</section>
				<section class="ag-card ag-section-gap">
					<h2><?php esc_html_e( 'Data lifecycle', 'aegisguard-security' ); ?></h2>
					<?php self::checkbox( 'woocommerce_monitoring', __( 'Log WooCommerce-sensitive actions when WooCommerce is active', 'aegisguard-security' ), $s['woocommerce_monitoring'] ); ?>
					<?php self::checkbox( 'delete_data_on_uninstall', __( 'Delete AegisGuard tables and settings when the plugin is uninstalled', 'aegisguard-security' ), $s['delete_data_on_uninstall'], __( 'Leave this off if audit history must survive plugin removal.', 'aegisguard-security' ) ); ?>
				</section>
				<p class="submit"><button class="button button-primary" type="submit"><?php esc_html_e( 'Save security settings', 'aegisguard-security' ); ?></button></p>
			</form>
		</div>
		<?php
	}

	public static function save_settings() {
		self::require_cap( Capabilities::MANAGE );
		check_admin_referer( 'aegisguard_save_settings' );
		$keys = array( 'waf_enabled','waf_mode','login_rate_limit','login_attempts','login_window','block_duration','disable_xmlrpc','disable_pingbacks','protect_user_enumeration','disable_file_editor','security_headers','upload_protection','database_scan','audit_logging','event_retention_days','malware_scan_max_files','file_scan_max_bytes','privacy_ip_anonymization','email_alerts','alert_email','alert_threshold','trust_proxy_headers','trusted_proxy_ips','woocommerce_monitoring','delete_data_on_uninstall' );
		$checkboxes = array( 'waf_enabled','login_rate_limit','disable_xmlrpc','disable_pingbacks','protect_user_enumeration','disable_file_editor','security_headers','upload_protection','database_scan','audit_logging','privacy_ip_anonymization','email_alerts','trust_proxy_headers','woocommerce_monitoring','delete_data_on_uninstall' );
		$input = Settings::all();
		foreach ( $checkboxes as $key ) {
			$input[ $key ] = isset( $_POST[ $key ] ) ? 1 : 0;
		}
		foreach ( $keys as $key ) {
			if ( in_array( $key, $checkboxes, true ) ) {
				continue;
			}
			if ( isset( $_POST[ $key ] ) ) {
				$input[ $key ] = is_array( $_POST[ $key ] ) ? array_map( 'sanitize_text_field', wp_unslash( $_POST[ $key ] ) ) : wp_unslash( $_POST[ $key ] );
			}
		}
		update_option( Settings::OPTION, Settings::sanitize( $input ), false );
		Logger::log( 'security.settings_changed', 'AegisGuard security settings changed.', 'medium' );
		wp_safe_redirect( add_query_arg( 'ag_notice', 'settings_saved', admin_url( 'admin.php?page=aegisguard-settings' ) ) );
		exit;
	}

	public static function run_scan() {
		self::require_cap( Capabilities::SCAN );
		check_admin_referer( 'aegisguard_run_scan' );
		Scanner::run_full_scan();
		wp_safe_redirect( add_query_arg( 'ag_notice', 'scan_complete', admin_url( 'admin.php?page=aegisguard-scanner' ) ) );
		exit;
	}


	public static function reset_baseline() {
		self::require_cap( Capabilities::INCIDENT );
		check_admin_referer( 'aegisguard_reset_baseline' );
		Scanner::reset_integrity_baseline();
		wp_safe_redirect( add_query_arg( 'ag_notice', 'baseline_reset', admin_url( 'admin.php?page=aegisguard-scanner' ) ) );
		exit;
	}

	public static function toggle_lockdown() {
		self::require_cap( Capabilities::INCIDENT );
		check_admin_referer( 'aegisguard_toggle_lockdown' );
		$enable = isset( $_POST['enable'] ) && '1' === sanitize_text_field( wp_unslash( $_POST['enable'] ) );
		if ( $enable ) {
			update_option( 'aegisguard_lockdown', 1, false );
			Logger::log( 'security.lockdown_enabled', 'Emergency lockdown enabled.', 'critical' );
		} else {
			delete_option( 'aegisguard_lockdown' );
			Logger::log( 'security.lockdown_disabled', 'Emergency lockdown disabled.', 'high' );
		}
		wp_safe_redirect( admin_url( 'admin.php?page=aegisguard-security' ) );
		exit;
	}

	public static function quarantine() {
		self::require_cap( Capabilities::INCIDENT );
		check_admin_referer( 'aegisguard_quarantine' );
		$path = isset( $_POST['path'] ) ? wp_normalize_path( sanitize_text_field( wp_unslash( $_POST['path'] ) ) ) : '';
		$result = Scanner::quarantine( $path );
		$notice = is_wp_error( $result ) ? 'quarantine_failed' : 'quarantine_success';
		wp_safe_redirect( add_query_arg( 'ag_notice', $notice, admin_url( 'admin.php?page=aegisguard-scanner' ) ) );
		exit;
	}


	public static function restore_quarantine() {
		self::require_cap( Capabilities::INCIDENT );
		$record = isset( $_POST['record'] ) ? sanitize_file_name( wp_unslash( $_POST['record'] ) ) : '';
		check_admin_referer( 'aegisguard_restore_quarantine_' . $record );
		$result = Scanner::restore_quarantine( $record );
		$notice = is_wp_error( $result ) ? 'quarantine_restore_failed' : 'quarantine_restore_success';
		wp_safe_redirect( add_query_arg( 'ag_notice', $notice, admin_url( 'admin.php?page=aegisguard-quarantine' ) ) );
		exit;
	}

	public static function delete_quarantine() {
		self::require_cap( Capabilities::INCIDENT );
		$record = isset( $_POST['record'] ) ? sanitize_file_name( wp_unslash( $_POST['record'] ) ) : '';
		check_admin_referer( 'aegisguard_delete_quarantine_' . $record );
		$result = Scanner::delete_quarantine( $record );
		$notice = is_wp_error( $result ) ? 'quarantine_delete_failed' : 'quarantine_delete_success';
		wp_safe_redirect( add_query_arg( 'ag_notice', $notice, admin_url( 'admin.php?page=aegisguard-quarantine' ) ) );
		exit;
	}


	public static function resolve_incident() {
		self::require_cap( Capabilities::INCIDENT );
		$incident_id = isset( $_POST['incident_id'] ) ? absint( $_POST['incident_id'] ) : 0;
		check_admin_referer( 'aegisguard_resolve_incident_' . $incident_id );
		if ( $incident_id ) {
			global $wpdb;
			$table = $wpdb->prefix . 'aegisguard_incidents';
			$wpdb->update( $table, array( 'status' => 'resolved', 'updated_at' => current_time( 'mysql', true ) ), array( 'id' => $incident_id ), array( '%s', '%s' ), array( '%d' ) );
			Logger::log( 'incident.resolved', 'Security incident marked as resolved.', 'medium', array( 'incident_id' => $incident_id ) );
		}
		wp_safe_redirect( admin_url( 'admin.php?page=aegisguard-incidents' ) );
		exit;
	}


	public static function revoke_other_sessions() {
		self::require_cap( Capabilities::VIEW );
		check_admin_referer( 'aegisguard_revoke_other_sessions' );
		$user_id = get_current_user_id();
		$manager = \WP_Session_Tokens::get_instance( $user_id );
		$manager->destroy_others( wp_get_session_token() );
		Logger::log( 'security.sessions_revoked', 'User terminated all other WordPress sessions.', 'medium', array( 'user_id' => $user_id ) );
		wp_safe_redirect( admin_url( 'admin.php?page=aegisguard-identity' ) );
		exit;
	}

	public static function admin_notices() {
		if ( empty( $_GET['ag_notice'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display-only notice.
			return;
		}
		$key = sanitize_key( wp_unslash( $_GET['ag_notice'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Display-only notice.
		$messages = array(
			'settings_saved'     => array( 'success', __( 'Security settings saved.', 'aegisguard-security' ) ),
			'scan_complete'      => array( 'success', __( 'Security scan completed.', 'aegisguard-security' ) ),
			'baseline_reset'     => array( 'success', __( 'Integrity baseline cleared. The next full scan will establish a new accepted baseline.', 'aegisguard-security' ) ),
			'quarantine_success' => array( 'success', __( 'The file was moved into protected quarantine.', 'aegisguard-security' ) ),
			'quarantine_failed'  => array( 'error', __( 'The file could not be quarantined. Verify the path and filesystem permissions.', 'aegisguard-security' ) ),
			'quarantine_restore_success' => array( 'success', __( 'The quarantined file was restored to its original path.', 'aegisguard-security' ) ),
			'quarantine_restore_failed'  => array( 'error', __( 'The quarantined file could not be restored. The original location may already contain a file or may not be writable.', 'aegisguard-security' ) ),
			'quarantine_delete_success'  => array( 'success', __( 'The quarantine record was permanently deleted.', 'aegisguard-security' ) ),
			'quarantine_delete_failed'   => array( 'error', __( 'The quarantine record could not be permanently deleted.', 'aegisguard-security' ) ),
		);
		if ( ! isset( $messages[ $key ] ) ) {
			return;
		}
		echo '<div class="notice notice-' . esc_attr( $messages[ $key ][0] ) . ' is-dismissible"><p>' . esc_html( $messages[ $key ][1] ) . '</p></div>';
	}

	private static function render_scan_result( $result ) {
		$summary = isset( $result['summary'] ) ? $result['summary'] : array();
		$stats   = isset( $result['stats'] ) ? $result['stats'] : array();
		$findings = isset( $result['findings'] ) && is_array( $result['findings'] ) ? $result['findings'] : array();
		?>
		<div class="ag-grid ag-grid-4 ag-section-gap">
			<?php self::metric( __( 'Critical', 'aegisguard-security' ), isset( $summary['critical'] ) ? (int) $summary['critical'] : 0, ! empty( $summary['critical'] ) ? 'danger' : 'good' ); ?>
			<?php self::metric( __( 'High', 'aegisguard-security' ), isset( $summary['high'] ) ? (int) $summary['high'] : 0, ! empty( $summary['high'] ) ? 'warn' : 'good' ); ?>
			<?php self::metric( __( 'Files scanned', 'aegisguard-security' ), isset( $stats['files_scanned'] ) ? (int) $stats['files_scanned'] : 0, 'neutral' ); ?>
			<?php self::metric( __( 'Core files checked', 'aegisguard-security' ), isset( $stats['core_files_checked'] ) ? (int) $stats['core_files_checked'] : 0, 'neutral' ); ?>
		</div>
		<section class="ag-card ag-section-gap">
			<h2><?php esc_html_e( 'Findings', 'aegisguard-security' ); ?></h2>
			<div class="ag-table-wrap"><table class="widefat striped ag-table"><thead><tr><th><?php esc_html_e( 'Severity', 'aegisguard-security' ); ?></th><th><?php esc_html_e( 'Type', 'aegisguard-security' ); ?></th><th><?php esc_html_e( 'Location', 'aegisguard-security' ); ?></th><th><?php esc_html_e( 'Finding', 'aegisguard-security' ); ?></th><th><?php esc_html_e( 'Action', 'aegisguard-security' ); ?></th></tr></thead><tbody>
			<?php if ( $findings ) : foreach ( $findings as $finding ) : ?>
				<tr>
					<td><span class="ag-badge ag-sev-<?php echo esc_attr( $finding['severity'] ); ?>"><?php echo esc_html( ucfirst( $finding['severity'] ) ); ?></span></td>
					<td><code><?php echo esc_html( $finding['type'] ); ?></code></td>
					<td><code class="ag-path"><?php echo esc_html( $finding['location'] ); ?></code></td>
					<td><?php echo esc_html( $finding['message'] ); ?></td>
					<td>
					<?php if ( current_user_can( Capabilities::INCIDENT ) && self::quarantinable_finding( $finding ) ) : ?>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" data-ag-confirm="<?php echo esc_attr__( 'Quarantine this file? The site may depend on it. Use only for confirmed malicious files.', 'aegisguard-security' ); ?>">
							<input type="hidden" name="action" value="aegisguard_quarantine"><input type="hidden" name="path" value="<?php echo esc_attr( ABSPATH . ltrim( $finding['location'], '/' ) ); ?>"><?php wp_nonce_field( 'aegisguard_quarantine' ); ?><button class="button button-small" type="submit"><?php esc_html_e( 'Quarantine', 'aegisguard-security' ); ?></button>
						</form>
					<?php else : ?><span class="ag-muted">—</span><?php endif; ?>
					</td>
				</tr>
			<?php endforeach; else : ?><tr><td colspan="5"><?php esc_html_e( 'No findings were recorded.', 'aegisguard-security' ); ?></td></tr><?php endif; ?>
			</tbody></table></div>
		</section>
		<?php
	}

	private static function quarantinable_finding( $finding ) {
		if ( empty( $finding['location'] ) || empty( $finding['type'] ) ) {
			return false;
		}
		return in_array( $finding['type'], array( 'malware_obfuscated_eval', 'known_webshell_marker', 'php_in_uploads', 'high_entropy_payload' ), true ) && 0 === strpos( wp_normalize_path( ABSPATH . ltrim( $finding['location'], '/' ) ), wp_normalize_path( WP_CONTENT_DIR ) . '/' );
	}

	private static function security_score( $settings, $scan ) {
		$score = 100;
		foreach ( array( 'waf_enabled' => 12, 'login_rate_limit' => 8, 'upload_protection' => 8, 'security_headers' => 6, 'audit_logging' => 8, 'database_scan' => 5, 'disable_pingbacks' => 3, 'protect_user_enumeration' => 4, 'disable_file_editor' => 4 ) as $key => $penalty ) {
			if ( empty( $settings[ $key ] ) ) {
				$score -= $penalty;
			}
		}
		if ( isset( $scan['summary'] ) ) {
			$score -= min( 35, (int) $scan['summary']['critical'] * 15 + (int) $scan['summary']['high'] * 6 + (int) $scan['summary']['medium'] * 2 );
		} else {
			$score -= 10;
		}
		return max( 0, min( 100, $score ) );
	}

	private static function header( $title, $subtitle ) {
		echo '<div class="ag-page-head"><div><h1>' . esc_html( $title ) . '</h1><p>' . esc_html( $subtitle ) . '</p></div><div class="ag-version">v' . esc_html( AEGISGUARD_VERSION ) . '</div></div>';
	}

	private static function metric( $label, $value, $state ) {
		echo '<section class="ag-metric ag-state-' . esc_attr( $state ) . '"><span>' . esc_html( $label ) . '</span><strong>' . esc_html( (string) $value ) . '</strong></section>';
	}

	private static function status_row( $label, $enabled, $detail = '' ) {
		echo '<li><span><strong>' . esc_html( $label ) . '</strong>' . ( $detail ? '<small>' . esc_html( $detail ) . '</small>' : '' ) . '</span><span class="ag-badge ' . ( $enabled ? 'ag-badge-good' : 'ag-badge-warn' ) . '">' . esc_html( $enabled ? __( 'On', 'aegisguard-security' ) : __( 'Off', 'aegisguard-security' ) ) . '</span></li>';
	}

	private static function checkbox( $name, $label, $checked, $description = '' ) {
		echo '<div class="ag-field ag-check"><label><input type="checkbox" name="' . esc_attr( $name ) . '" value="1" ' . checked( (bool) $checked, true, false ) . '> <span><strong>' . esc_html( $label ) . '</strong>' . ( $description ? '<small>' . esc_html( $description ) . '</small>' : '' ) . '</span></label></div>';
	}

	private static function select( $name, $label, $value, $options ) {
		echo '<div class="ag-field"><label for="' . esc_attr( $name ) . '"><strong>' . esc_html( $label ) . '</strong></label><select id="' . esc_attr( $name ) . '" name="' . esc_attr( $name ) . '">';
		foreach ( $options as $key => $text ) {
			echo '<option value="' . esc_attr( $key ) . '" ' . selected( $value, $key, false ) . '>' . esc_html( $text ) . '</option>';
		}
		echo '</select></div>';
	}

	private static function number( $name, $label, $value, $min, $max ) {
		echo '<div class="ag-field"><label for="' . esc_attr( $name ) . '"><strong>' . esc_html( $label ) . '</strong></label><input class="small-text" type="number" id="' . esc_attr( $name ) . '" name="' . esc_attr( $name ) . '" value="' . esc_attr( $value ) . '" min="' . esc_attr( $min ) . '" max="' . esc_attr( $max ) . '"></div>';
	}

	private static function text( $name, $label, $value, $type = 'text' ) {
		echo '<div class="ag-field"><label for="' . esc_attr( $name ) . '"><strong>' . esc_html( $label ) . '</strong></label><input class="regular-text" type="' . esc_attr( $type ) . '" id="' . esc_attr( $name ) . '" name="' . esc_attr( $name ) . '" value="' . esc_attr( $value ) . '"></div>';
	}

	private static function require_cap( $cap ) {
		if ( ! current_user_can( $cap ) ) {
			wp_die( esc_html__( 'You do not have permission to access this security function.', 'aegisguard-security' ), '', array( 'response' => 403 ) );
		}
	}
}
