<?php if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly
/**
 * Blocks requests from bad user agents and darknet spam comments
 */
class NoDossAgentSecurity {
    /**
     * Patterns for detecting malicious user agents
     *
     * @var array
     */
    private static $badUserAgentPatterns = [
        '/(\<|\>|\'|\$x0|\%0A|\%0D|\%27|\%3C|\%3E|\%00|\+select|\+union|\&lt)/i',
        '/(binlar|casper|checkprivacy|cmsworldmap|comodo|curious|diavol|doco)/i',
        '/(dotbot|feedfinder|flicky|ia_archiver|kmccrew|libwww|nutch)/i',
        '/(planetwork|purebot|pycurl|skygrid|sucker|turnit|vikspid|zmeu|zune)/i',
    ];

    /**
     * Patterns for detecting darknet spam
     *
     * @var array
     */
    private static $darknetSpamPatterns = [
        'dark net', 'dark web', 'dark market', 'darkmarket', 'darknet',
        'drug store', 'nexus market', 'nexus link', 'nexus url',
        'nexus dark', 'nexusdark', 'nexus onion'
    ];

    /**
     * Checks if a user agent is malicious
     *
     * @param string $userAgent The user agent string to check
     * @return bool True if the user agent is malicious, false otherwise
     */
    public static function isBadUserAgent(string $userAgent): bool {
        foreach (self::$badUserAgentPatterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Blocks darknet spam in POST requests
     *
     * @param array $request The request array (typically $_REQUEST or parsed request)
     */
    public static function blockDarknetSpam(array $request) {
        if (isset($request['method']) &&
            strtoupper($request['method']) === 'POST' &&
            isset($request['body']['comment'])) {

            $comment = $request['body']['comment'];

            foreach (self::$darknetSpamPatterns as $pattern) {
                if (stripos($comment, $pattern) !== false) {
                    http_response_code(403);
                    header('Content-Type: text/plain; charset=utf-8');
                    echo '403 Forbidden: Spam detected.';
                    exit;
                }
            }
        }
    }

    /**
     * Initializes the security checks by hooking into WordPress
     */
    public static function init() {
        // Check User Agent on initial load with proper sanitization
        if ( isset( $_SERVER['HTTP_USER_AGENT'] ) ) {
            $user_agent = sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) );
            
            if ( self::isBadUserAgent( $user_agent ) ) {
                http_response_code(403);
                exit('403 Forbidden: Malicious User Agent.');
            }
        }

        // Handle comment spam filtering using WordPress specific hooks
        add_filter('preprocess_comment', function($commentdata) {
            foreach (self::$darknetSpamPatterns as $pattern) {
                if (stripos($commentdata['comment_content'], $pattern) !== false) {
                    wp_die('Comment blocked due to spam keywords.', 'Submission Rejected', array('response' => 403));
                }
            }
            return $commentdata;
        });
    }
}

// Run the security class
NoDossAgentSecurity::init();
