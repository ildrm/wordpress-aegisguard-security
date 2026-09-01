<?php
namespace AegisGuard\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Settings {
	const OPTION = 'aegisguard_settings';

	public static function defaults() {
		return array(
			'waf_enabled'                 => true,
			'waf_mode'                    => 'balanced',
			'login_rate_limit'            => true,
			'login_attempts'              => 8,
			'login_window'                => 900,
			'block_duration'              => 1800,
			'disable_xmlrpc'              => false,
			'disable_pingbacks'           => true,
			'protect_user_enumeration'    => true,
			'disable_file_editor'         => true,
			'security_headers'            => true,
			'upload_protection'           => true,
			'audit_logging'               => true,
			'event_retention_days'        => 30,
			'email_alerts'                => true,
			'alert_email'                 => get_option( 'admin_email' ),
			'alert_threshold'             => 'high',
			'privacy_ip_anonymization'    => false,
			'trust_proxy_headers'         => false,
			'trusted_proxy_ips'           => '',
			'malware_scan_max_files'      => 10000,
			'file_scan_max_bytes'         => 2097152,
			'database_scan'               => true,
			'woocommerce_monitoring'      => true,
			'delete_data_on_uninstall'    => false,
			'lockdown_allow_admins'       => true,
			'log_retention_cleanup_batch' => 1000,
		);
	}

	public static function all() {
		$saved = get_option( self::OPTION, array() );
		return wp_parse_args( is_array( $saved ) ? $saved : array(), self::defaults() );
	}

	public static function get( $key, $default_value = null ) {

		$settings = self::all();
		return array_key_exists( $key, $settings ) ? $settings[ $key ] : $default_value;
	}

	public static function sanitize( $input ) {
		$input    = is_array( $input ) ? $input : array();
		$defaults = self::defaults();
		$output   = $defaults;

		$bool_keys = array(
			'waf_enabled',
			'login_rate_limit',
			'disable_xmlrpc',
			'disable_pingbacks',
			'protect_user_enumeration',
			'disable_file_editor',
			'security_headers',
			'upload_protection',
			'audit_logging',
			'email_alerts',
			'privacy_ip_anonymization',
			'trust_proxy_headers',
			'database_scan',
			'woocommerce_monitoring',
			'delete_data_on_uninstall',
			'lockdown_allow_admins',
		);
		foreach ( $bool_keys as $key ) {
			$output[ $key ] = ! empty( $input[ $key ] );
		}

		$output['waf_mode']        = in_array( isset( $input['waf_mode'] ) ? $input['waf_mode'] : '', array( 'learning', 'monitoring', 'balanced', 'strict' ), true )
			? $input['waf_mode'] : 'balanced';
		$output['alert_threshold'] = in_array( isset( $input['alert_threshold'] ) ? $input['alert_threshold'] : '', array( 'low', 'medium', 'high', 'critical' ), true )
			? $input['alert_threshold'] : 'high';

		$output['login_attempts']              = max( 3, min( 100, absint( isset( $input['login_attempts'] ) ? $input['login_attempts'] : 8 ) ) );
		$output['login_window']                = max( 60, min( DAY_IN_SECONDS, absint( isset( $input['login_window'] ) ? $input['login_window'] : 900 ) ) );
		$output['block_duration']              = max( 60, min( WEEK_IN_SECONDS, absint( isset( $input['block_duration'] ) ? $input['block_duration'] : 1800 ) ) );
		$output['event_retention_days']        = max( 1, min( 365, absint( isset( $input['event_retention_days'] ) ? $input['event_retention_days'] : 30 ) ) );
		$output['malware_scan_max_files']      = max( 100, min( 100000, absint( isset( $input['malware_scan_max_files'] ) ? $input['malware_scan_max_files'] : 10000 ) ) );
		$output['file_scan_max_bytes']         = max( 65536, min( 10485760, absint( isset( $input['file_scan_max_bytes'] ) ? $input['file_scan_max_bytes'] : 2097152 ) ) );
		$output['log_retention_cleanup_batch'] = max( 100, min( 5000, absint( isset( $input['log_retention_cleanup_batch'] ) ? $input['log_retention_cleanup_batch'] : 1000 ) ) );
		$output['alert_email']                 = sanitize_email( isset( $input['alert_email'] ) ? $input['alert_email'] : get_option( 'admin_email' ) );
		$output['trusted_proxy_ips']           = sanitize_textarea_field( isset( $input['trusted_proxy_ips'] ) ? $input['trusted_proxy_ips'] : '' );

		return $output;
	}
}
