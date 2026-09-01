<?php
/**
 * Pure-algorithm smoke checks that do not require WordPress bootstrap.
 */

define( 'ABSPATH', __DIR__ . '/' );

require_once dirname( __DIR__ ) . '/src/Security/Mfa.php';
require_once dirname( __DIR__ ) . '/src/Security/RuntimeFirewall.php';

function ag_assert_same( $expected, $actual, $message ) {
	if ( $expected !== $actual ) {
		fwrite( STDERR, "FAIL: {$message}\nExpected: " . var_export( $expected, true ) . "\nActual: " . var_export( $actual, true ) . "\n" );
		exit( 1 );
	}
}

function ag_assert_true( $actual, $message ) {
	if ( ! $actual ) {
		fwrite( STDERR, "FAIL: {$message}\n" );
		exit( 1 );
	}
}

$mfa_reflection = new ReflectionClass( 'AegisGuard\\Security\\Mfa' );
$totp           = $mfa_reflection->getMethod( 'totp' );
$totp->setAccessible( true );
$secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
ag_assert_same( '287082', $totp->invoke( null, $secret, 1 ), 'RFC 6238 SHA-1 six-digit TOTP vector at counter 1.' );

$firewall_reflection = new ReflectionClass( 'AegisGuard\\Security\\RuntimeFirewall' );
$analyze             = $firewall_reflection->getMethod( 'analyze' );
$analyze->setAccessible( true );
$normal = $analyze->invoke( null, "GET\n/about?ref=summer\nref=summer\nMozilla/5.0" );
ag_assert_same( 0, $normal['score'], 'Normal request must not receive a firewall score.' );

$sqli = $analyze->invoke( null, "GET\n/?id=1%20UNION%20SELECT%20password%20FROM%20users\nid=1%20UNION%20SELECT%20password%20FROM%20users\ncurl" );
ag_assert_true( $sqli['score'] >= 5, 'UNION SELECT payload must trigger SQL injection scoring.' );
ag_assert_true( in_array( 'sqli_union', $sqli['rules'], true ), 'UNION SELECT payload must identify the sqli_union rule.' );

$traversal = $analyze->invoke( null, "GET\n/?file=../../wp-config.php\nfile=../../wp-config.php\nMozilla/5.0" );
ag_assert_true( $traversal['score'] >= 4, 'Traversal payload must trigger traversal scoring.' );
$nested_traversal = $analyze->invoke( null, "GET\n/?file=%25252e%25252e%25252fwp-config.php\nfile=%25252e%25252e%25252fwp-config.php\nMozilla/5.0" );
ag_assert_true( $nested_traversal['score'] >= 4, 'Repeatedly encoded traversal payload must trigger traversal scoring.' );
fwrite( STDOUT, "Pure smoke checks passed.\n" );
