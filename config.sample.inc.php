<?php

/*
 * Author: Tan Chee Eng
 *
 * File DB_PATH needs to be writable by the PHP interperter.
 */

// The user allowed to access the admin page
// Set to empty string to disable
define('ADMIN_USER', 'admin');
// The group allowed to access the admin page
// Set to empty string to disable
define('ADMIN_GROUP', 'admin');
// The realm to use for HTTP basic authentication
define('REALM', 'realm');
// The path to the admin page, without the trailing slash
define('ADMIN_URL', 'https://example.com/admin');
// The filesystem path to the SQLite database
define('DB_PATH', 'db/users.sqlite');
// The filesystem path to a log file
define('LOG_PATH', 'db/auth.log');
// Will be run just after the "Create New Invite" header
function new_invite_preamble() {
}
