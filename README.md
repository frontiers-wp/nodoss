=== NoDoss ===
Plugin URI: https://wordpress.org/plugins/nodoss
Donate link: https://paypal.me/EBekedam
Contributors: frontiers
Author URI: https://github.com/frontiers-wp/nodoss
Tags: security, performance, brute force,
Description: Lightweight Security plugin againts attacks, incl mordern securty headers.
Requires at least: 5.0
Tested up to: 6.9
Requires PHP: 8.1
Stable tag: 1.1.0
License: GPLv2
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Stop bots, pingbacks, protection againts brute force hacking, script jacking, Iframe XSS attacks, CSRF Proctection, Insecure requests,

== Description ==

Stop bots, pingbacks, protection againts brute force hacking, script jacking, Iframe XSS attacks, CSRF Proctection, Insecure requests, invalid unwanted user edits, 
Stops emulator and injection attacks 

Pre-set Security Headers: 

=cross origin policy=
=cross origin resource sharing=
=referrer-policy=
=x content-type-options =
=x permitted cross domain policies = 
=Strict-TransportSsecurity=
=Content-Security-Policy: upgrade-insecure=

== Installation ==

1. Upload 'nodoss.zip' to the '/wp-content/plugins/' directory
2. Extract the Plugin to a `nodoss` Folder
3. Activate the plugin through the 'Plugins' menu in WordPress
4. General Settings – Heartbeat <15> <240> Interval seconds 


1. Go to `Plugins` in the Admin menu
2. Click on the button `Add new`
3. Search for nodoss` and click 'Install Now' or click on the `upload` link to upload `nodoss.zip`
4. Click on `Activate plugin`
5. General Settings – Heartbeat <15> <240> Interval seconds 

== Frequently Asked Questions ==

= Why use NoDoss as a security plugin? =
Because it developed over a longer period of time, with fully hosted sites as well, there are performance and security layers that complement without breaking any of the basic functions of WordPress.

= Will the NoDoss plugin slow down my site? = 
It's developed to be lightweight because it covers all with very low impact on performance. 

= Will the plugin protect against XXS attacks? = 
Yes, XSS protection is part of this plugin.

== Screenshots ==
1. heartbeat-interval.png
2. safe-results.png
3. nodoss-banner-772-250.png
4. nodoss-ico.png
5. nodoss-icon.svg

== Changelog ==

= 1.0.0: November 01, 2025 =
* Birthday of nodoss -Beta-
= 1.0.1 
* Verfication of correctly sanitize ( wp_unslash. 
= 1.0.2
Better Headers for security
Improved class PHP
= 1.0.3
Hide WordPress version tag.
Add icon image.
nodoss-banner-772-250
= 1.0.4
Debug log.
Plugin check.
richt click disabled.
= 1.0.5
new use wp_enqueue commands
Data Sanitized, Escaped, and Validated
Nonces and User Permissions Needed for Security
PHP Syntax
= 1.0.6: December 01, 2025 =
* Birthday of nodoss
= 1.0.7: Puplic release 
Updated readme.
Plugin icon and header 
=1.0.8 Pulic release
Updated readme
= 1.0.9: April 04, 2026 =
Update readme.txt
Update plugin icon
update remove wp version
= 1.1.0: April 04, 2026 =
Stable tag

== Upgrade Notice ==
Your WordPress will be more secure.
