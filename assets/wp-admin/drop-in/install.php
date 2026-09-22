<?php
// Exit if accessed directly
if (!defined('ABSPATH')) {
    exit;
}

// Set security headers
header('X-Permitted-Cross-Domain-Policies: master-only');
header('X-Content-Type-Options: nosniff');
header('Content-Security-Policy: upgrade-insecure-requests');

// Set HTTP status headers
header('HTTP/1.1 503 Service Temporarily Unavailable');
header('Status: 503 Service Temporarily Unavailable');
header('Retry-After: 3600'); // 60 minutes

// Output HTML content
?>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xml:lang="en" xmlns="http://www.w3.org/1999/xhtml" lang="en">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
        <title>Error Establishing Database Connection</title>
    </head>
    <body>
        <img src="images/wordpress-logo.png" alt="WordPress Logo" />
        <h1>Error Establishing Database Connection</h1>
        <p>We are currently experiencing database issues. Please check back shortly. Thank you.</p>
    </body>
</html>