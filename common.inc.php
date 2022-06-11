<?php require 'config.inc.php';

// For compatibility with earlier versions of config.inc.php
if (!defined('DB_PATH')) {
    define('DB_PATH', 'db/users.sqlite');
}

// Defines used by to track logins on the admin page
define('AUTH_NONE',  0);
define('AUTH_USER',  1);
define('AUTH_ADMIN', 2);

global $user_data;
global $user_role;
global $db;
global $default_title;
global $message;
global $ui_error_return;

$user_data = null;
$user_role = AUTH_NONE;
$db = null;
$default_title = "User Administration";
$message = null;
$ui_error_return = null;

/*
 * Functions
 */

function redirect_login() {
    header("Location: " . ADMIN_URL . "/?page=login");
    http_response_code(302);
    exit;
}

function redirect($url) {
    header("Location: $url");
    http_response_code(303);
}

// Returns user data if password is correct, false otherwise
function check_user($user, $pass) {
    global $db;
    if (is_null($db)) return false;
    try {
        if ($user == '') return false;
        $u = SQLite3::escapeString($user);
        $u_data = $db->querySingle(
            "SELECT * FROM users WHERE name = '$u'",
            true /* entireRow */);
        if (($u_data === false) || empty($u_data)) {
            return false;
        }
        if (password_verify($pass, $u_data['hash'])) {
            return $u_data;
        } else {
            return false;
        }
    } catch (Exception $e) {
        // Ignore
    }
    return false;
}

/*
 * Checks auth status.
 *
 * If $no_admin_fail is true and the user is not an admin, will cause a
 * redirect to the login page.
 *
 * If no user is logged in, will also cause a redirect to the login page.
 *
 * On successful check, the globals $user_data and $user_role will be set.
 */
function require_auth($no_admin_fail = false) {
    global $db, $user_data, $user_role;

    if (is_null($db)) {
        echo "Database reference invalid";
        exit;
    }

    if (isset($_SESSION['user_role'])) {
        if (!isset($_SESSION['user_data'])) {
            // This should not happen (tm), but if it does, assume not
            // logged in
            $user_role = AUTH_NONE;
            $user_data = null;
        } else {
            $user_role = $_SESSION['user_role'];
            $user_data = $_SESSION['user_data'];
        }
    }

    if ($user_role == AUTH_NONE) {
        redirect_login();
    }

    if ($no_admin_fail && ($user_role != AUTH_ADMIN)) {
        redirect_login();
    }
}

function require_admin() {
    require_auth(true /* no_admin_fail */);
}

// Everything from doctype to head. On return head tag is still open.
function page_head($title = null) {
    global $default_title;
    if (is_null($title)) $title = $default_title;

    $res = function($file) {
        echo ADMIN_URL."/res/$file";
    };
    $jq = function($file) {
        echo ADMIN_URL."/res/jquery-ui-1.13.1.custom/$file";
    };
?><!DOCTYPE html>
<html><head><title><?php echo htmlesc($title); ?></title>
<link rel="stylesheet" href="<?php $jq('jquery-ui.min.css'); ?>" />
<link rel="stylesheet" href="<?php $res('style.css'); ?>" />
<script src="<?php $jq('external/jquery/jquery.js'); ?>"></script>
<script src="<?php $jq('jquery-ui.min.js'); ?>"></script>
<?php }

// Page footer. When called, body tag must still be open.
function page_tail() {
    echo '</body></html>';
}

function htmlesc($str) {
    return htmlentities($str, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5);
}

function jsesc($js) {
    return htmlesc(addslashes($js));
}

function check_auth_uri($uri, $user, $pass) {
    global $db;
    $auth_ok = false;
    $u_data = check_user($user, $pass);

    if (preg_match('/([a-z]+)\\/([^\\/]+)$/', $uri, $matches) == 1) {
        switch ($matches[1]) {
            case 'any':
                $auth_ok = ($u_data !== false);
                break;
            case 'user':
                if ($user == $matches[2]) {
                    $auth_ok = ($u_data !== false);
                }
                break;
            case 'group':
                $auth_ok = false;
                if ($u_data !== false) {
                    $u = SQLite3::escapeString($user);
                    $groups = explode(':', $matches[2]);
                    try {
                        // Check group memberships
                        foreach ($groups as $g) {
                            if ($g == '') continue;
                            $g = SQLite3::escapeString($g);
                            $res = $db->querySingle(
                                "SELECT user FROM groups WHERE ".
                                    "user = '$u' AND grp = '$g'");
                            if (!is_null($res) && $res !== false) {
                                // User belongs to this group
                                $auth_ok = true;
                                break;
                            }
                        }
                    } catch (Exception $e) {
                        // Ignore, default to fail auth
                    }
                }
                break;
            default:
                $auth_ok = false;
                break;
        }
    }

    return $auth_ok;
}

function db_rw_init() {
    global $db;

    $db = new SQLite3(DB_PATH,
        SQLITE3_OPEN_CREATE | SQLITE3_OPEN_READWRITE);
    $db->busyTimeout(10000);

    // Make sure tables are set up
    $db->query('CREATE TABLE IF NOT EXISTS "users" (
        "name" VARCHAR(32) PRIMARY KEY NOT NULL,
        "hash" TEXT NOT NULL,
        "comment" TEXT NOT NULL
    )');
    $db->query('CREATE TABLE IF NOT EXISTS "invites" (
        "token" VARCHAR(22) NOT NULL PRIMARY KEY,
        "expiry" DATETIME NOT NULL,
        "groups" TEXT NOT NULL,
        "comment" TEXT NOT NULL
    )');
    $db->query('CREATE TABLE IF NOT EXISTS "groups" (
        "user" VARCHAR(32) NOT NULL
            REFERENCES users(name)
                ON DELETE CASCADE
                ON UPDATE CASCADE,
        "grp" VARCHAR(32) NOT NULL,
        PRIMARY KEY (user, grp)
    )');

    // Housekeeping
    $db->query("DELETE FROM invites WHERE expiry < datetime('now');");
}

function db_ro_init() {
    global $db;

    $db = new SQLite3(DB_PATH,
        SQLITE3_OPEN_READONLY);
}

// Does not return, will exit after displaying
function show_error($msg, $set_400 = false) {
    global $db;
    if (!is_null($db)) $db->close();

    if ($set_400) http_response_code(400);

    echo $msg;
    exit;
}

function set_default_ui_title($title) {
    global $default_title;
    $default_title = $title;
}

function set_ui_error_return($uri) {
    global $ui_error_return;
    $ui_error_return = $uri;
}

// Does not return, will exit after displaying
function show_error_ui($msg, $title = null) {
    global $db, $default_title, $ui_error_return;
    if (!is_null($db)) $db->close();

    if (is_null($title)) $title = $default_title;
    $title = "Error: $title";

    page_head($title);
    ?>

    <script type="text/javascript">
        $(document).ready(function() {
            $('#tabs').tabs();
            $('.button').button();
        });
    </script></head><body>

    <div id="tabs" class="center-wrap">
        <ul><li><a href="#error"><?php echo $title; ?></a></li></ul>
        <div id="error">
            <p><?php echo $msg; ?></p>
            <?php if (!is_null($ui_error_return)) { ?>
                <a class="button" href="<?php echo $ui_error_return; ?>">
                    Back
                </a>
            <?php } ?>
        </div>
    </div><?php

    page_tail();
    exit;
}

// Does not return, will exit after displaying
function show_msg_ui($msg, $title = null) {
    global $db, $default_title;
    if (!is_null($db)) $db->close();

    if (is_null($title)) $title = $default_title;

    page_head($title);
    ?>

    <script type="text/javascript">
            $(document).ready(function() {
                $('#tabs').tabs();
                $('.button').button();
            });
        </script></head><body>

        <div id="tabs" class="center-wrap">
            <ul><li><a href="#msg"><?php echo $title; ?></a></li></ul>
            <div id="msg"><?php echo $msg; ?></div>
        </div><?php
    page_tail();
    exit;
}
