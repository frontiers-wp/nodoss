<?php
namespace Frontiers\NosdossAntiClickJackHandler;
/**
 * @NoDoss 
 * @Anti Clickjack
 * Prevent your site from being clickjacked by adding OWASP's legacy browser frame breaking script & X-Frame-Options.
 */
defined('ABSPATH') or die("you do not have access to this page!");


class nodoss_anti_click_jack {

	public function nodos_incl_anticlickjack_script() {

		$nodossAntiClickjack = apply_filters( 'nodoss_anti_clickjack', true);

		if ( is_customize_preview() || wp_is_json_request() ) {
			$nodossAntiClickjack = false;
		}

		// phpcs:disable WordPress.Security.NonceVerification.Recommended --

		// Visual Composer
		if( ! empty( $_REQUEST['vc_editable'] ) ){
			if ( sanitize_text_field( wp_unslash( $_REQUEST['vc_editable'] ) ) === 'true' ) {
				$nodossAntiClickjack = false;
			}
		}
		
		// Divi Page Editor
		if( ! empty( $_REQUEST['et_fb'] ) ){
			if ( sanitize_text_field( wp_unslash( $_REQUEST['et_fb'] ) ) === '1' ) {
				$nodossAntiClickjack = false;
			}
		}
		
		// Cornerstone Editor
		if ( did_action( 'cs_before_preview_frame' ) ) {
			$nodossAntiClickjack = false;
		}

		// Elementor
		if( class_exists( '\Elementor\Plugin' ) ){
			if(\Elementor\Plugin::$instance->preview->is_preview_mode() || \Elementor\Plugin::$instance->editor->is_edit_mode() ||
				( ! empty( $_REQUEST['render_mode'] ) && sanitize_text_field( wp_unslash( $_REQUEST['render_mode'] ) ) === 'template-preview' )
			){
				$nodossAntiClickjack = false;
			}
		}

		// Thrive Editor
		if( ! empty( $_REQUEST['tve'] ) ){
			if ( sanitize_text_field( wp_unslash( $_REQUEST['tve'] ) ) === 'true' ) {
				$nodossAntiClickjack = false;
			}
		}

		// Avada Editor
		if( ! empty( $_REQUEST['builder'] ) ){
			if ( sanitize_text_field( wp_unslash( $_REQUEST['builder'] ) ) === 'true' ) {
				$nodossAntiClickjack = false;
			}
		}

		// Bricks Builder
		if ( ! empty( $_REQUEST['bricks'] ) ) {
			if ( sanitize_text_field( wp_unslash( $_REQUEST['bricks'] ) ) === 'run' ) {
				$nodossAntiClickjack = false;
			}
		}

		// Breakdance Builder
		if ( ! empty( $_REQUEST['breakdance'] ) || ! empty( $_REQUEST['breakdance_iframe'] ) ) {
			$nodossAntiClickjack = false;
		}

		// Oxygen Builder
		if ( ! empty( $_REQUEST['ct_builder'] ) || ! empty( $_REQUEST['oxygen_iframe'] ) ) {
			$nodossAntiClickjack= false;
		}

		// Spectra / Starter Templates
		if ( ! empty( $_REQUEST['spectra'] ) || ! empty( $_REQUEST['starter-templates-iframe'] ) ) {
			$nodossAntiClickjack = false;
		}

		// Gutenberg Full Site Editor (FSE)
		if ( ! empty( $_REQUEST['postType'] ) && ! empty( $_REQUEST['canvas'] ) ) {
			$nodossAntiClickjack = false;
		}

		// Block Editor iframe preview
		if ( ! empty( $_REQUEST['editor_frame'] ) || ! empty( $_REQUEST['block-editor'] ) ) {
			$nodossAntiClickjack= false;
		}

		if( ! empty( $_REQUEST['action'] ) ){
			$sanitized_action = sanitize_text_field( wp_unslash( $_REQUEST['action'] ) );
			if ( $sanitized_action === 'do-plugin-upgrade' || $sanitized_action === 'do-theme-upgrade' || $sanitized_action === 'update-selected' || $sanitized_action === 'update-selected-themes' ) {
				$$nodossAntiClickjack = false;
			}
		}

		// phpcs:enable WordPress.Security.NonceVerification.Recommended
        // FIXED: Sanitize the input within the conditional check block
		$raw_referer = ! empty( $_SERVER['HTTP_REFERER'] ) ? sanitize_url( wp_unslash( $_SERVER['HTTP_REFERER'] ) ) : '';

		if ( ! empty( $raw_referer ) ) {
			$referrer_parts = wp_parse_url( $raw_referer );
			$site_parts     = wp_parse_url( get_site_url() );

			if ( is_array( $referrer_parts ) && is_array( $site_parts ) &&
			     ! empty( $referrer_parts['host'] ) && ! empty( $site_parts['host'] ) ) {
				if ( sanitize_text_field( $referrer_parts['host'] ) !== $site_parts['host'] ) {
					$nodossAntiClickjack = true;
				}
			}
		}


		if ( $$nodossAntiClickjack ) {
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- JS block optimization requires a raw echo string. Inner string context contains no dynamic user data, preventing XSS risks.
			echo '<script type="text/javascript">
			 var style = document.createElement("style");
			 style.type = "text/css";
			 style.id = "antiClickjack";
			 if ("cssText" in style){
			   style.cssText = "body{display:none !important;}";
			 }else{
			   style.innerHTML = "body{display:none !important;}";
			 }
			 document.getElementsByTagName("head")[0].appendChild(style);

			 try {
			   if (top.document.domain === document.domain) {
			     var antiClickjack = document.getElementById("antiClickjack");
			     antiClickjack.parentNode.removeChild(antiClickjack);
			   } else {
			     top.location = self.location;
			   }
			 } catch (e) {
			   top.location = self.location;
			 }
			</script>';
		}
	}
}