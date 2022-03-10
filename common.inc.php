<?php require 'config.inc.php';

/*
 * Functions
 */

// Everything from doctype to head. On return head tag is still open.
function page_head($title) {
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

// Returns true if password is correct, false otherwise
function check_user($user, $pass) {
    global $db;
    try {
        if ($user == '') return false;
        $u = SQLite3::escapeString($user);
        $hash = $db->querySingle(
            "SELECT hash FROM users WHERE name = '$u'");
        if (    !(is_null($hash) || $hash === false)
                && password_verify($pass, $hash))
        {
            return true;
        }
    } catch (Exception $e) {
        // Ignore
    }
    return false;
}

function htmlesc($str) {
    return htmlentities($str, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5);
}

function jsesc($js) {
    return htmlesc(addslashes($js));
}

function check_auth($uri, $user, $pass) {
    global $db;
    $auth_ok = false;

    if (preg_match('/([a-z]+)\\/([^\\/]+)$/', $uri, $matches) == 1) {
        switch ($matches[1]) {
            case 'any':
                $auth_ok = check_user($user, $pass);
                break;
            case 'user':
                if ($user == $matches[2]) {
                    $auth_ok = check_user($user, $pass);
                }
                break;
            case 'group':
                $auth_ok = false;
                $u = SQLite3::escapeString($user);
                $groups = explode(':', $matches[2]);
                try {
                    if (check_user($user, $pass)) {
                        // User exists, now check group memberships
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
                    }
                } catch (Exception $e) {
                    // Ignore
                }
                break;
            default:
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
