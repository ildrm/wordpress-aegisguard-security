<?php
namespace AegisGuard\Support;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Capabilities {
	const VIEW     = 'aegisguard_view_security';
	const MANAGE   = 'aegisguard_manage_security';
	const SCAN     = 'aegisguard_run_scans';
	const INCIDENT = 'aegisguard_manage_incidents';

	public static function all() {
		return array( self::VIEW, self::MANAGE, self::SCAN, self::INCIDENT );
	}

	public static function grant_to_administrators() {
		$role = get_role( 'administrator' );
		if ( ! $role ) {
			return;
		}
		foreach ( self::all() as $cap ) {
			$role->add_cap( $cap );
		}
	}

	public static function remove_from_administrators() {
		$role = get_role( 'administrator' );
		if ( ! $role ) {
			return;
		}
		foreach ( self::all() as $cap ) {
			$role->remove_cap( $cap );
		}
	}
}
