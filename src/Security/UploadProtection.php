<?php
namespace AegisGuard\Security;

use AegisGuard\Core\Logger;
use AegisGuard\Support\Settings;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class UploadProtection {
	public static function register() {
		if ( ! Settings::get( 'upload_protection', true ) ) {
			return;
		}
		add_filter( 'wp_handle_upload_prefilter', array( __CLASS__, 'inspect_upload' ) );
		add_filter( 'wp_handle_sideload_prefilter', array( __CLASS__, 'inspect_upload' ) );
	}

	public static function inspect_upload( $file ) {
		if ( empty( $file['name'] ) || empty( $file['tmp_name'] ) ) {
			return $file;
		}
		$name       = sanitize_file_name( $file['name'] );
		$ext        = strtolower( pathinfo( $name, PATHINFO_EXTENSION ) );
		$lower_name = strtolower( $name );
		$dangerous  = array( 'php', 'phtml', 'phar', 'cgi', 'pl', 'py', 'sh', 'bash', 'exe', 'com', 'bat', 'cmd', 'htaccess', 'user.ini' );

		$sensitive_names = array( '.htaccess', 'htaccess', '.user.ini', 'user.ini', 'php.ini' );
		if ( in_array( $ext, $dangerous, true ) || in_array( $lower_name, $sensitive_names, true ) || preg_match( '/\.(?:php\d*|phtml|phar)\.[a-z0-9]+$/i', $name ) ) {
			$file['error'] = __( 'AegisGuard blocked a potentially executable upload.', 'aegisguard-security' );
			Logger::log( 'security.upload_blocked', 'Dangerous upload extension blocked.', 'high', array( 'extension' => $ext ) );
			return $file;
		}

		if ( class_exists( 'finfo' ) ) {
			$finfo          = new \finfo( FILEINFO_MIME_TYPE );
			$actual_mime    = $finfo->file( $file['tmp_name'] );
			$expected_mimes = array(
				'jpg'  => array( 'image/jpeg' ),
				'jpeg' => array( 'image/jpeg' ),
				'png'  => array( 'image/png' ),
				'gif'  => array( 'image/gif' ),
				'webp' => array( 'image/webp' ),
				'pdf'  => array( 'application/pdf' ),
			);
			if ( isset( $expected_mimes[ $ext ] ) && is_string( $actual_mime ) && ! in_array( strtolower( $actual_mime ), $expected_mimes[ $ext ], true ) ) {
				$file['error'] = __( 'AegisGuard detected a mismatch between the file extension and its actual content type.', 'aegisguard-security' );
				Logger::log(
					'security.upload_mime_mismatch',
					'Upload extension and detected MIME type did not match.',
					'high',
					array(
						'extension'     => $ext,
						'detected_mime' => $actual_mime,
					)
				);
				return $file;
			}
		}

		$sample = self::sample_file_edges( $file['tmp_name'] );
		if ( is_string( $sample ) && preg_match( '/<\?(?:php|=)|\b(?:eval|shell_exec|passthru|system)\s*\(/i', $sample ) && ! in_array( $ext, array( 'php', 'phtml' ), true ) ) {
			$file['error'] = __( 'AegisGuard detected executable code inside the uploaded file.', 'aegisguard-security' );
			Logger::log( 'security.upload_polyglot', 'Executable code detected in a non-PHP upload.', 'critical', array( 'extension' => $ext ) );
		}
		return $file;
	}

	private static function sample_file_edges( $path ) {

			$handle = @fopen( $path, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen,WordPress.PHP.NoSilencedErrors.Discouraged -- Bounded read of a PHP-managed temporary upload before WP_Filesystem is available.
		if ( ! $handle ) {
			return false;
		}
		$head = fread( $handle, 16384 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Bounded security inspection.
		$tail = '';
		$size = @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Temporary upload may disappear concurrently.
		if ( false !== $size && $size > 16384 && 0 === fseek( $handle, -16384, SEEK_END ) ) {
// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fseek -- Bounded tail inspection catches appended polyglot payloads.
			$tail = fread( $handle, 16384 ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fread -- Bounded security inspection.
		}
		fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- See above.
			return ( is_string( $head ) ? $head : '' ) . ( is_string( $tail ) ? $tail : '' );
	}
}
