<?php
/**
 * WordPress integration and security-regression smoke tests.
 *
 * Run with:
 * wp eval-file wp-content/plugins/aegisguard-security/tests/integration-smoke.php
 */

use AegisGuard\Core\Logger;
use AegisGuard\Security\Hardening;
use AegisGuard\Security\LoginProtection;
use AegisGuard\Security\Mfa;
use AegisGuard\Security\Scanner;
use AegisGuard\Security\UploadProtection;
use AegisGuard\Support\Capabilities;
use AegisGuard\Support\Request;
use AegisGuard\Support\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit( 1 );
}

function aegisguard_test_assert( $condition, $message ) {
	if ( ! $condition ) {
		throw new RuntimeException( $message );
	}
}

function aegisguard_test_same( $expected, $actual, $message ) {
	if ( $expected !== $actual ) {
		throw new RuntimeException( $message . ' Expected ' . var_export( $expected, true ) . ', received ' . var_export( $actual, true ) . '.' );
	}
}

global $wpdb;

$required_tables = array(
	$wpdb->prefix . 'aegisguard_events',
	$wpdb->prefix . 'aegisguard_incidents',
	$wpdb->prefix . 'aegisguard_integrity',
);
foreach ( $required_tables as $table ) {
	$found = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) );
	aegisguard_test_same( $table, $found, 'Activation must create ' . $table );
}

$role = get_role( 'administrator' );
foreach ( Capabilities::all() as $capability ) {
	aegisguard_test_assert( $role && $role->has_cap( $capability ), 'Administrators must receive ' . $capability );
}

$sanitized = Settings::sanitize(
	array(
		'login_attempts'         => 999,
		'login_window'           => 1,
		'block_duration'         => 999999999,
		'event_retention_days'   => 0,
		'malware_scan_max_files' => 1,
		'file_scan_max_bytes'    => 1,
		'waf_mode'               => 'invalid',
	)
);
aegisguard_test_same( 100, $sanitized['login_attempts'], 'Login attempts must be bounded.' );
aegisguard_test_same( 60, $sanitized['login_window'], 'Login window must be bounded.' );
aegisguard_test_same( WEEK_IN_SECONDS, $sanitized['block_duration'], 'Block duration must be bounded.' );
aegisguard_test_same( 'balanced', $sanitized['waf_mode'], 'Unknown WAF modes must fail closed to balanced.' );

$original_settings = get_option( Settings::OPTION, array() );
$original_server   = $_SERVER;
$settings          = Settings::all();
$settings['trust_proxy_headers'] = true;
$settings['trusted_proxy_ips']   = "10.0.0.2\n10.0.0.3";
update_option( Settings::OPTION, $settings, false );
$_SERVER['REMOTE_ADDR']         = '10.0.0.3';
$_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.77, 203.0.113.8, 10.0.0.2';
aegisguard_test_same( '203.0.113.8', Request::ip(), 'Proxy parsing must return the nearest untrusted address.' );
$_SERVER['REMOTE_ADDR'] = '203.0.113.44';
aegisguard_test_same( '203.0.113.44', Request::ip(), 'Forwarding headers from an untrusted peer must be ignored.' );
$_SERVER = $original_server;
update_option( Settings::OPTION, $original_settings, false );

$user_login = 'aegisguard_audit_' . wp_generate_password( 8, false, false );
$user_id    = wp_create_user( $user_login, wp_generate_password( 32, true, true ), $user_login . '@example.test' );
aegisguard_test_assert( ! is_wp_error( $user_id ), 'A temporary MFA test user must be created.' );

try {
	$secret = Mfa::begin_setup( $user_id );
	aegisguard_test_assert( is_string( $secret ) && 32 === strlen( $secret ), 'MFA setup must generate a 160-bit Base32 secret.' );
	aegisguard_test_same( $secret, Mfa::pending_secret( $user_id ), 'Pending MFA secrets must decrypt correctly.' );

	$reflection = new ReflectionClass( Mfa::class );
	$totp       = $reflection->getMethod( 'totp' );
	$totp->setAccessible( true );
	$counter    = (int) floor( time() / 30 );
	$code       = $totp->invoke( null, $secret, $counter );
	aegisguard_test_assert( Mfa::verify_code( $secret, $code ), 'A current RFC 6238 code must verify.' );

	$recovery_codes = Mfa::enable_for_user( $user_id, $secret );
	aegisguard_test_assert( is_array( $recovery_codes ) && 10 === count( $recovery_codes ), 'Enabling MFA must issue ten recovery codes.' );

	$consume_totp = $reflection->getMethod( 'verify_and_consume_code' );
	$consume_totp->setAccessible( true );
	aegisguard_test_assert( $consume_totp->invoke( null, $user_id, $secret, $code ), 'The first use of a TOTP counter must succeed.' );
	aegisguard_test_assert( ! $consume_totp->invoke( null, $user_id, $secret, $code ), 'A TOTP counter must not be accepted twice.' );

	$consume_recovery = $reflection->getMethod( 'consume_recovery_code' );
	$consume_recovery->setAccessible( true );
	aegisguard_test_assert( $consume_recovery->invoke( null, $user_id, $recovery_codes[0] ), 'A recovery code must work once.' );
	aegisguard_test_assert( ! $consume_recovery->invoke( null, $user_id, $recovery_codes[0] ), 'A consumed recovery code must not work again.' );
} finally {
	Mfa::disable_for_user( $user_id );
	wp_delete_user( $user_id );
}

$upload_path = wp_tempnam( 'aegisguard-large-upload.txt' );
aegisguard_test_assert( is_string( $upload_path ) && '' !== $upload_path, 'A temporary upload fixture must be created.' );
file_put_contents( $upload_path, str_repeat( 'A', 6 * MB_IN_BYTES ) . "<?php system('id');" );
$upload_result = UploadProtection::inspect_upload(
	array(
		'name'     => 'large-note.txt',
		'tmp_name' => $upload_path,
		'error'    => 0,
	)
);
unlink( $upload_path );
aegisguard_test_assert( ! empty( $upload_result['error'] ), 'Executable content appended to a large upload must be blocked.' );

$uploads = wp_upload_dir();
aegisguard_test_assert( empty( $uploads['error'] ), 'The uploads directory must be writable for quarantine tests.' );
$fixture_dir = trailingslashit( $uploads['basedir'] ) . 'aegisguard-audit';
wp_mkdir_p( $fixture_dir );
$fixture_path = trailingslashit( $fixture_dir ) . 'quarantine-fixture.txt';
$fixture_body = 'AegisGuard quarantine integration fixture';
file_put_contents( $fixture_path, $fixture_body );
aegisguard_test_assert( true === Scanner::quarantine( $fixture_path ), 'An in-scope regular file must be quarantined.' );
$quarantine_items = Scanner::list_quarantine();
$record_name      = '';
foreach ( $quarantine_items as $item ) {
	if ( ! empty( $item['valid'] ) && false !== strpos( $item['original_path'], 'quarantine-fixture.txt' ) ) {
		$record_name = $item['name'];
		break;
	}
}
aegisguard_test_assert( '' !== $record_name, 'The encrypted quarantine record must be discoverable.' );
aegisguard_test_assert( true === Scanner::restore_quarantine( $record_name ), 'A valid record must restore to its authenticated original path.' );
aegisguard_test_same( $fixture_body, file_get_contents( $fixture_path ), 'Restored content must preserve its digest.' );
unlink( $fixture_path );

if ( function_exists( 'symlink' ) ) {
	$symlink_target = trailingslashit( $fixture_dir ) . 'symlink-target.txt';
	$symlink_path   = trailingslashit( $fixture_dir ) . 'symlink-fixture.txt';
	file_put_contents( $symlink_target, 'target' );
	if ( @symlink( $symlink_target, $symlink_path ) ) {
		$symlink_result = Scanner::quarantine( $symlink_path );
		aegisguard_test_assert( is_wp_error( $symlink_result ) && 'quarantine_symlink' === $symlink_result->get_error_code(), 'Quarantine must reject symbolic-link inputs.' );
		unlink( $symlink_path );
	}
	unlink( $symlink_target );
}

Logger::log( 'test.integration_one', 'Integration chain event one.' );
Logger::log( 'test.integration_two', 'Integration chain event two.' );
$chain = Logger::verify_chain();
aegisguard_test_assert( ! empty( $chain['valid'] ) && $chain['checked'] >= 2, 'The audit-event chain must verify after sequential writes.' );
$pruned = Logger::prune( gmdate( 'Y-m-d H:i:s', time() + HOUR_IN_SECONDS ), 100 );
aegisguard_test_assert( is_int( $pruned ) && $pruned > 0, 'Retention pruning must remove a complete serialized batch.' );
aegisguard_test_assert( '' !== get_option( 'aegisguard_audit_anchor', '' ), 'Retention pruning must preserve the deleted chain tail as an anchor.' );
Logger::log( 'test.integration_after_prune', 'Integration chain event after retention pruning.' );
$chain = Logger::verify_chain();
aegisguard_test_assert( ! empty( $chain['valid'] ) && $chain['checked'] >= 1, 'The audit-event chain must continue from its retention anchor.' );

$settings = Settings::all();
$settings['login_rate_limit'] = true;
update_option( Settings::OPTION, $settings, false );
$_SERVER['REMOTE_ADDR'] = '192.0.2.55';
LoginProtection::record_failure( 'first@example.test' );
$ip_key_method = new ReflectionMethod( LoginProtection::class, 'ip_key' );
$ip_key_method->setAccessible( true );
$ip_key        = $ip_key_method->invoke( null );
$before        = get_transient( $ip_key );
LoginProtection::record_success( 'audit_admin', get_user_by( 'login', 'audit_admin' ) );
$after = get_transient( $ip_key );
aegisguard_test_assert( is_array( $before ) && is_array( $after ) && $before['count'] === $after['count'], 'A successful login must not clear the IP-wide abuse counter.' );
delete_transient( $ip_key );
$_SERVER = $original_server;
update_option( Settings::OPTION, $original_settings, false );

wp_set_current_user( 0 );
$request = new WP_REST_Request( 'GET', '/wp/v2/users' );
$blocked = Hardening::restrict_rest_user_endpoints( null, rest_get_server(), $request );
aegisguard_test_assert( is_wp_error( $blocked ) && 404 === $blocked->get_error_data()['status'], 'Public REST user enumeration must be hidden.' );

fwrite( STDOUT, "AegisGuard WordPress integration smoke checks passed.\n" );
