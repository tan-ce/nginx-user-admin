<?php require 'common.inc.php';

// Extra init for admin pages
db_rw_init();
session_start();
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = token_gen();
}

function token_gen() {
    return substr(strtr(base64_encode(random_bytes(16)), '+/', '-_'), 0, 22);
}

// "Get Field" - get a POST field and escape for SQL
function gf($name, $optional = false) {
    if (!isset($_POST[$name])) {
        show_error("Invalid argument(s)", true /* set_400 */);
    }
    if (!$optional && (strlen($_POST[$name]) == 0)) {
        show_error("'$name' cannot be empty", true /* set_400 */);
    }
    return SQLite3::escapeString($_POST[$name]);
}

// "Get Field" - get a POST field and escape for SQL
function gf_ui($name, $optional = false) {
    if (!isset($_POST[$name])) {
        show_error_ui("Invalid argument(s)");
    }
    if (!$optional && (strlen($_POST[$name]) == 0)) {
        show_error_ui("'$name' cannot be empty");
    }
    return SQLite3::escapeString($_POST[$name]);
}

// Does not return
function passwd_page($msg = null) {
    global $message, $user_data;
    if (!isset($_GET['passwd'])) {
        if (isset($_POST['user'])) {
            $_GET['passwd'] = $_POST['user'];
        } else {
            $_GET['passwd'] = $user_data['name'];
        }
    }
    $message = $msg;
    require 'passwd_page.inc.php';
    exit;
}

function new_user_page($msg = null) {
    global $message;
    $message = $msg;
    require 'new_user_page.inc.php';
    exit;
}

// Returns true if OK, string if have problem
function check_password($pass) {
    if (strlen($pass) < 8) {
        return "Password too short!";
    } else if (substr(strtolower($pass), 0, 8) == 'password') {
        return "Please choose a better password...";
    } else {
        return true;
    }
}

function csrf_check() {
    if (!isset($_POST['csrf_token'])) {
        show_error("Missing CSRF Token", true /* set_400 */);
    }
    if ($_POST['csrf_token'] != $_SESSION['csrf_token']) {
        show_error("Invalid CSRF Token", true /* set_400 */);
    }
}

/*
 * Handle requests. Most of these are AJAX requests (but not all).
 */
function handle_post() {
    global $db;

    if (!isset($_POST['action'])) {
        show_error_ui("Lost?");
    }

    csrf_check();

    switch ($_POST['action']) {
    case 'passwd':
        /*
            * This action is NOT an AJAX action - our messages new to be a full UI message.
            */

        global $db, $user_role, $user_data;

        require_auth();
        set_default_ui_title("Change password");

        $pass = gf_ui('pass1', true /* optional */);
        $pass2 = gf_ui('pass2', true /* optional */);
        $pwdcheck = check_password($pass);

        if (!isset($_POST['user'])) show_error_ui("Invalid argument(s)");
        $user = $_POST['user'];

        // Only admins can change password w/o verifying existing password
        if ($user_role != AUTH_ADMIN) {
            if ($user != $user_data['name']) {
                show_error_ui("Invalid argument(s)");
            }

            $oldpass = gf_ui('oldpass', true);
            if (check_user($user, $oldpass) === false) {
                passwd_page("Current password is incorrect");
            }
        }
        $user = SQLite3::escapeString($user);

        if ($pass != $pass2) {
            passwd_page("New passwords do not match");
        } else if ($pwdcheck !== true) {
            passwd_page($pwdcheck);
        } else {
            $hash = password_hash($pass, PASSWORD_DEFAULT);
            $query = "UPDATE users SET hash = '$hash' WHERE name = '$user'";
            if ($db->query($query) === false) {
                show_error_ui("Error updating password: ".htmlesc($db->lastErrorMsg()));
            }
            if ($user_role == AUTH_ADMIN) {
                redirect(ADMIN_URL);
            } else {
                passwd_page("Password changed successfully!");
            }
        }
        exit;

    case 'deluser':
        require_admin();
        $user = gf('user');
        $db->query("DELETE FROM groups WHERE user = '$user'");
        $db->query("DELETE FROM users WHERE name = '$user'");
        break;

    case 'addgroup':
        require_admin();
        $user = gf('user');
        $grp = gf('grp');
        if ($grp == '') {
            show_error("Group cannot be blank");
        }
        if (preg_match('/^[a-zA-Z0-9_-]+$/', $grp) === 1) {
            $db->query("INSERT INTO groups(user, grp) VALUES ".
                "('$user', '$grp')");
        } else {
            show_error("Group must only contain letters, numbers, '_', or '-'");
        }
        break;

    case 'delmember':
        require_admin();
        $user = gf('user');
        $grp = gf('grp');
        $db->query("DELETE FROM groups WHERE ".
            "user = '$user' AND grp = '$grp'");
        break;

    case 'delgroup':
        require_admin();
        $grp = gf('grp');
        $db->query("DELETE FROM groups WHERE grp = '$grp'");
        break;

    case 'edit_comment':
        require_admin();
        $user = gf('user');
        // Comment may be blank
        if (isset($_POST['comment'])) {
            $comment = $_POST['comment'];
        } else {
            $comment = '';
        }
        $db->query("UPDATE users SET comment = '$comment' WHERE name = '$user'");
        break;

    case 'delinvite':
        require_admin();
        $token = gf('token');
        $db->query("DELETE FROM invites WHERE token = '$token'");
        break;

    case 'newinvite':
        require_admin();
        $groups = gf('groups', true);
        $comment = gf('comment', true);
        $token = token_gen();
        $db->query("INSERT INTO invites ".
            "(token, expiry, groups, comment) VALUES ".
                "('$token', datetime('now', '30 days'), ".
                    "'$groups', '$comment')");
        
        header('Location: '.ADMIN_URL, true, 303);
        break;

    case 'createuser':
        /*
         * This action is NOT an AJAX action - our messages new to be a full UI message.
         */
        set_default_ui_title("Create New User");

        if (!isset($_GET['token'])) {
            show_error_ui("Missing token");
        }
        $invite = get_invite($_GET['token']);
        if ($invite === false) {
            show_error_ui("Could not find your invite");
        }

        $user = strtolower(gf_ui('user', true /* optional */));
        $pass = strtolower(gf_ui('pass1', true /* optional */));
        $pass2 = strtolower(gf_ui('pass2', true /* optional */));
        $pwdcheck = check_password($pass);

        if (strlen($user) == 0) {
            new_user_page("Please provide a username");
        } else if (preg_match('/[a-zA-Z0-9_-]+/', $user) !== 1) {
            new_user_page("Usernames must only contain letters, numbers, '_', or '-'");
        } else if ($pass != $pass2) {
            new_user_page("Passwords do not match");
        } else if ($pwdcheck !== true) {
            new_user_page($pwdcheck);
        } else {
            $res = $db->querySingle("SELECT name FROM users WHERE name = '$user'");
            if (!is_null($res) && ($res !== false)) {
                new_user_page("Error: Username already taken");
            }
            $hash = password_hash($pass, PASSWORD_DEFAULT);
            $comment = SQLite3::escapeString($invite['comment']);
            $db->query("BEGIN TRANSACTION");
            $query = "INSERT INTO users(name, hash, comment) VALUES ".
                "('$user', '$hash', '$comment')";
            if ($db->query($query) === false) {
                $errmsg = "Error creating user: ".htmlesc($db->lastErrorMsg());
                $db->query("ROLLBACK");
                show_error_ui($errmsg);
            }

            foreach (explode(':', $invite['groups']) as $g) {
                if ($g == '') continue;
                $g = SQLite3::escapeString($g);
                $query = "INSERT INTO groups(user, grp) VALUES ".
                    "('$user', '$g')";
                if ($db->query($query) === false) {
                    $errmsg = "Error setting group permissions: ".htmlesc($db->lastErrorMsg());
                    $db->query("ROLLBACK");
                    show_error_ui($errmsg);
                }
            }

            $t = SQLite3::escapeString($invite['token']);
            $db->query("DELETE FROM invites WHERE token = '$t'");
            $db->query("COMMIT");
            show_msg_ui("User '$user' created successfully!");
        }

        break;

    default:
        show_error("Invalid action");
        exit;
    }
}

// Returns false if the token is invalid
function get_invite($token) {
    global $db;
    $token = SQLite3::escapeString($token);
    $res = $db->query("SELECT * FROM invites WHERE token = '$token'");
    if ($res !== false) {
        $invite = $res->fetchArray(SQLITE3_ASSOC);
        if ($invite !== false) {
            return $invite;
        }
    }
    return false;
}

if (isset($_POST['action'])) {
    handle_post();
    exit;
}

if (isset($_GET['page'])) {
    $page = $_GET['page'];
} else {
    if (isset($_GET['token'])) $page = 'new_user';
    else if (isset($_GET['passwd'])) $page = 'passwd';
    else $page = 'admin';
}

switch ($page) {
    case 'admin':
        require 'admin_page.inc.php';
        break;
    case 'new_user':
        new_user_page();
        break;
    case 'passwd':
        passwd_page();
        break;
    case 'logout':
        if (isset($_SESSION['logout_done'])) {
            unset($_SESSION['logout_done']);
            redirect(ADMIN_URL);
        } else {
            $_SESSION['logout_done'] = true;
            send_401();
        }
        exit;
    default:
        show_error_ui("Lost?");
        exit;
}