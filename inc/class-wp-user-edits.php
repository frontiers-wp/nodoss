<?php if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly
/**
 * Hides the admin bar for authorized users (simulated via a global flag).
 */
function nodoss_wp_show_admin_bar() {
    if (current_user_can('show_admin_bar')) {
        // Simulate WordPress's `__return_false` by setting a global flag.
        $GLOBALS['show_admin_bar'] = false;
        // Return to false
        add_filter( 'show_admin_bar', '__return_false' );
    }
}

/**
 * Simulates WordPress's `admin_init` hook by calling the functions directly.
 * In a real PHP app, you might call these during session initialization or middleware.
 */
function nodoss_admin_init() {
    nodoss_wp_show_admin_bar();
}

/**
 * File rules configuration
 * @var array
 */
$NodossfilesRules = [
    [
        'pattern' => 'install.php',
        'order'   => 'Allow,Deny',
        'deny'    => 'all',
        'satisfy' => 'all'
    ],
    [
        'pattern' => 'php_error.log',
        'order'   => 'deny,allow',
        'deny'    => 'all'
    ],
    [
        'pattern' => 'fantversion.php',
        'order'   => 'deny,allow',
        'deny'    => 'all'
    ],
    [
        'pattern' => 'fantastico_fileslist.txt',
        'order'   => 'allow,deny',
        'deny'    => 'all'
    ],
    [
        'pattern' => 'README.md',
        'order'   => 'deny,allow',
        'deny'    => 'all'
    ],
    [
        'pattern' => '.gitignore',
        'order'   => 'deny,allow',
        'deny'    => 'all'
    ],
    [
        'pattern' => '*.txt',
        'deny'    => 'all'
    ],
    [
        'pattern' => 'license.txt',
        'order'   => 'deny,allow',
        'deny'    => 'all'
    ],
    [
        'pattern' => 'readme.html',
        'order'   => 'deny,allow',
        'deny'    => 'all'
    ],
    [
        'pattern' => 'php.ini',
        'order'   => 'Allow,Deny',
        'deny'    => 'all'
    ],
    [
        'pattern' => 'phprc',
        'order'   => 'Allow,Deny',
        'deny'    => 'all'
    ],
    [
        'pattern' => 'user.ini',
        'order'   => 'Allow,Deny',
        'deny'    => 'all'
    ],
    [
        'pattern' => '.htaccess',
        'order'   => 'deny,allow',
        'deny'    => 'all'
    ],
    [
        'pattern' => '~ "^\\.ht"',
        'order'   => 'allow,deny',
        'deny'    => 'all'
    ],
    [
        'pattern' => 'admin-ajax.php',
        'order'   => 'allow,deny',
        'allow'   => 'all',
        'satisfy' => 'any'
    ],
    [
        'pattern' => 'xmlrpc.php',
        'order'   => 'deny,allow',
        'deny'    => 'all'
    ],
    [
        'pattern' => 'wp-config.php',
        'order'   => 'allow,deny',
        'deny'    => 'all'
    ],
    [
        'pattern' => '*.gz',
        'order'   => 'allow,deny',
        'deny'    => 'all',
        'satisfy' => 'all'
    ],
    [
        'pattern' => '~ "^.*\\.([Hh][Tt][AaPp])"',
        'order'   => 'deny,allow',
        'deny'    => 'all',
        'satisfy' => 'all'
    ],
    [
        'pattern' => '~ "^.*\\.([Hh][Tt][Aa])"',
        'order'   => 'allow,deny',
        'deny'    => 'all',
        'satisfy' => 'all'
    ]
];
