<?php require 'config.inc.php';

define('AUTH_NONE',  0);
define('AUTH_USER',  1);
define('AUTH_ADMIN', 2);

global $user_data, $user_role, $db, $default_title, $message;

$user_data = null;
$user_role = AUTH_NONE;
$db = null;
$default_title = "User Administration";
$message = null;

/*
 * Functions
 */

function send_401() {
    header("WWW-Authenticate: Basic realm=\"".REALM."\"");
    http_response_code(401);
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

 // Checks auth status.
 //
  // If $no_admin_fail is true, will send 401 if not admin
 //
 // If the password is bad or the user doesn't exist, exit and
 // request for authentication credentials.
 //
 // On successful authentication, the globals $user and $user_role
 // will be updated.
function require_auth($no_admin_fail = false) {
    global $db, $user_data, $user_role;

    if (is_null($db)) {
        echo "Database reference invalid";
        exit;
    }

    if ($user_role == AUTH_NONE) {
        // Make sure to reset
        $user_data = null;

        if (    isset($_SERVER['PHP_AUTH_USER']) && 
                isset($_SERVER['PHP_AUTH_PW']))
        {
            $user = $_SERVER['PHP_AUTH_USER'];
            $pass = $_SERVER['PHP_AUTH_PW'];
            $u = check_user($user, $pass);
            if ($u === false) {
                // Password bad, immediate fail
                send_401();
                exit;
            } else {
                // Password checks out, update $user_data
                $user_data = $u;

                // Check if user is an Admin
                if ($u['name'] == ADMIN_USER) {
                    $user_role = AUTH_ADMIN;
                } else {
                    // Check if user belongs to admin group
                    // Normal user by default
                    $user_role = AUTH_USER;

                    $u = SQLite3::escapeString($u['name']);
                    $g = SQLite3::escapeString(ADMIN_GROUP);
                    try {
                        $res = $db->querySingle(
                            "SELECT user FROM groups WHERE ".
                                "user = '$u' AND grp = '$g'");
                        if (!is_null($res) && $res !== false) {
                            // User is in ADMIN_GROUP
                            $user_role = AUTH_ADMIN;
                        }
                    } catch (Exception $e) {
                        // Ignore, default to "not admin".
                    }
                }
            }
        } else {
            // No credentials, ask for it
            send_401();
        }
    }

    if ($no_admin_fail && ($user_role != AUTH_ADMIN)) {
        send_401();
        exit;
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
        echo ADMIN_URL."/res/jquery-ui-1.13.0.custom/$file";
    };
?><!DOCTYPE html>
<html><head><title><?php echo htmlesc($title); ?></title>
<link rel="stylesheet" href="<?php $jq('jquery-ui.min.css'); ?>" />
<link rel="stylesheet" href="<?php $res('style.css'); ?>" />
<script src="<?php $res('jquery-3.6.0.min.js'); ?>"></script>
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

    $db = new SQLite3('db/users.sqlite',
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

    $db = new SQLite3('db/users.sqlite',
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

// Does not return, will exit after displaying
function show_error_ui($msg, $title = null) {
    global $db, $default_title;
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
            <div id="error"><?php echo $msg; ?></div>
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