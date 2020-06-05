<?php

/*
 * Author: Tan Chee Eng
 *
 * Directory "db" needs to be writable by the PHP interperter.
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
// Will be run just after the "Create New Invite" header
function new_invite_preamble() {
}
