<?php
if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly
}

class NodossWPFtNoDossCsrf {

	/**
	 * Initialize the class and set up hooks
	 */
	public function __construct() {
		// Set up comment form modifications
		$this->setup_comment_form_modifications();

		// Attach verification engines natively using the approved action array pointers
		add_action( 'comment_form', array( $this, 'nodoss_add_comment_form_csrf' ) );
		add_filter( 'preprocess_comment', array( $this, 'nodoss_verify_comment_csrf' ) );
	}

	/**
	 * Set up comment form modifications
	 */
	private function setup_comment_form_modifications() {
		// Custom filter to remove website field safely
		add_filter(
			'comment_form_default_fields',
			function( array $fields ): array {
				// Only remove the URL text field if the CSRF feature itself is actively turned on
				if ( '1' === get_option( 'nodoss_security_enable_comment_csrf', '0' ) && isset( $fields['url'] ) ) {
					unset( $fields['url'] );
				}
				return $fields;
			}
		);
	}

	/**
	 * Generate and add CSRF tokens to the comment form
	 */
	public function nodoss_add_comment_form_csrf() {
		// FIX: Instantly exit execution loop if the admin dashboard toggle switch is set to off
		if ( get_option( 'nodoss_security_enable_comment_csrf', '0' ) !== '1' ) {
			return;
		}

		$wp_nonce     = wp_create_nonce( 'lodestar_wpcom_comment_form_csrf' );
		$random_bytes = bin2hex( random_bytes( 16 ) );
		$build_id     = 'comment-form-csrf-' . $random_bytes;

		$key       = defined( 'SECURE_AUTH_KEY' ) ? SECURE_AUTH_KEY : '';
		$data      = $build_id . $wp_nonce;
		$signature = hash_hmac( 'sha256', $data, $key );

		echo '<input type="hidden" name="nodoss_build_id" value="' . esc_attr( $build_id ) . '">';
		echo '<input type="hidden" name="nodoss_wp_nonce" value="' . esc_attr( $wp_nonce ) . '">';
		echo '<input type="hidden" name="nodoss_csrf_token" value="' . esc_attr( $signature ) . '">';
	}

	/**
	 * Validates the CSRF tokens for comment submission.
	 *
	 * @param array $commentdata The native incoming comment database layout row data.
	 * @return array The original validation array on success, halts execution via wp_die on breach.
	 */
	public function nodoss_verify_comment_csrf( array $commentdata ) {
		// FIX: Instantly bypass validation restrictions if the feature switch option is set to off
		if ( get_option( 'nodoss_security_enable_comment_csrf', '0' ) !== '1' ) {
			return $commentdata;
		}

		// Skip check for background system requests (like XML-RPC or REST API)
		if ( defined( 'XMLRPC_REQUEST' ) || defined( 'REST_REQUEST' ) ) {
			return $commentdata;
		}

		// Skip verification for administrators to prevent blocking development testing
		if ( current_user_can( 'manage_options' ) ) {
			return $commentdata;
		}

		// Skip check for non-standard comment types (trackbacks/pingbacks)
		if ( isset( $commentdata['comment_type'] ) && 'comment' !== $commentdata['comment_type'] ) {
			return $commentdata;
		}

		// Verify tokens natively against the actual $_POST array while enforcing verification filters
		if ( ! isset( $_POST['nodoss_wp_nonce'] ) || ! isset( $_POST['nodoss_csrf_token'] ) || ! isset( $_POST['nodoss_build_id'] ) ) {
			wp_die(
				esc_html__( 'Security signature context targets missing. Submission blocked.', 'nodoss' ),
				esc_html__( 'CSRF Security Violation', 'nodoss' ),
				array( 'response' => 403 )
			);
		}

		// Inputs unslashed natively using wp_unslash() prior to running sanitization wrappers
		$submitted_nonce  = sanitize_key( wp_unslash( $_POST['nodoss_wp_nonce'] ) );
		$submitted_token  = sanitize_text_field( wp_unslash( $_POST['nodoss_csrf_token'] ) );
		$submitted_build  = sanitize_text_field( wp_unslash( $_POST['nodoss_build_id'] ) );

		// Nonce name string updated to 'lodestar_wpcom_comment_form_csrf' to match generation properties
		if ( ! wp_verify_nonce( $submitted_nonce, 'lodestar_wpcom_comment_form_csrf' ) ) {
			wp_die(
				esc_html__( 'Security token verification signature expired.', 'nodoss' ),
				esc_html__( 'CSRF Token Invalid', 'nodoss' ),
				array( 'response' => 403 )
			);
		}

		// Re-verify the HMAC security checksum parameters on the server to prevent input forgery
		$key               = defined( 'SECURE_AUTH_KEY' ) ? SECURE_AUTH_KEY : '';
		$recalculated_data = $submitted_build . $submitted_nonce;
		$expected_token    = hash_hmac( 'sha256', $recalculated_data, $key );

		// Enforce a strict time-constant comparison check strategy to prevent timing analysis scanning vectors
		if ( ! hash_equals( $expected_token, $submitted_token ) ) {
			wp_die(
				esc_html__( 'Cryptographic form validation integrity failure detected.', 'nodoss' ),
				esc_html__( 'Security Check Failed', 'nodoss' ),
				array( 'response' => 403 )
			);
		}

		return $commentdata;
	}
}

// Initialize the class
new NodossWPFtNoDossCsrf();