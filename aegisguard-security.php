<?php
/**
 * Plugin Name:       AegisGuard Security
 * Plugin URI:        https://ildrm.com/
 * Description:       WordPress security suite with WAF, malware scanning, hardening, MFA, audit logs, and incident response.
 * Version:           1.0.1
 * Requires at least: 6.5
 * Requires PHP:      7.4
 * Author:            Shahin Ilderemi
 * Author URI:        https://ildrm.com/
 * License:           GPL v2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       aegisguard-security
 *
 * @package AegisGuardSecurity
 * @copyright 2026 Shahin Ilderemi
 * @license GPL-2.0-or-later
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'AEGISGUARD_VERSION', '1.0.1' );
define( 'AEGISGUARD_FILE', __FILE__ );
define( 'AEGISGUARD_DIR', plugin_dir_path( __FILE__ ) );
define( 'AEGISGUARD_URL', plugin_dir_url( __FILE__ ) );
define( 'AEGISGUARD_BASENAME', plugin_basename( __FILE__ ) );

spl_autoload_register(
	static function ( $class_name ) {

		$prefix = 'AegisGuard\\';
		if ( 0 !== strpos( $class_name, $prefix ) ) {
			return;
		}

		$relative = substr( $class_name, strlen( $prefix ) );
		$path     = AEGISGUARD_DIR . 'src/' . str_replace( '\\', '/', $relative ) . '.php';

		if ( is_readable( $path ) ) {
			require_once $path;
		}
	}
);

register_activation_hook( __FILE__, array( 'AegisGuard\\Core\\Activator', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'AegisGuard\\Core\\Activator', 'deactivate' ) );

// Run the in-process request firewall as early as this plugin can execute.
AegisGuard\Security\RuntimeFirewall::preflight();

AegisGuard\Core\Plugin::instance()->boot();
