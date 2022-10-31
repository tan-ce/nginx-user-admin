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

// "Get Field and Escape" - get a POST field and escape for SQL
function gfe($name, $optional = false) {
    if (!isset($_POST[$name])) {
        show_error("Invalid argument(s)", true /* set_400 */);
    }
    if (!$optional && (strlen($_POST[$name]) == 0)) {
        show_error("'$name' cannot be empty", true /* set_400 */);
    }
    return SQLite3::escapeString($_POST[$name]);
}

// "Get Field and Escape" - get a POST field and escape for SQL
function gfe_ui($name, $optional = false) {
    if (!isset($_POST[$name])) {
        show_error_ui("Invalid argument(s)");
    }
    if (!$optional && (strlen($_POST[$name]) == 0)) {
        show_error_ui("'$name' cannot be empty");
    }
    return SQLite3::escapeString($_POST[$name]);
}

// "Get Field" - get a POST field and DON'T escape for SQL
function gf($name, $optional = false) {
    if (!isset($_POST[$name])) {
        show_error("Invalid argument(s)", true /* set_400 */);
    }
    if (!$optional && (strlen($_POST[$name]) == 0)) {
        show_error("'$name' cannot be empty", true /* set_400 */);
    }
    return $_POST[$name];
}

// "Get Field" - get a POST field and DON'T escape for SQL
function gf_ui($name, $optional = false) {
    if (!isset($_POST[$name])) {
        show_error_ui("Invalid argument(s)");
    }
    if (!$optional && (strlen($_POST[$name]) == 0)) {
        show_error_ui("'$name' cannot be empty");
    }
    return $_POST[$name];
}

// Does not return
function login_page($msg = null) {
    global $message;
    $message = $msg;
    require 'login_page.inc.php';
    exit;
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

// Does not return
// Precondition: global $invite is set
function invite_new_page($msg = null) {
    global $message;
    $message = $msg;
    require 'invite_new_page.inc.php';
    exit;
}

// Does not return
// Precondition: global $invite is set
function invite_reset_page($msg = null) {
    global $message;
    $message = $msg;
    require 'invite_reset_page.inc.php';
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

function handle_post_login() {
    global $db, $user_data, $user_role;
    /*
     * This action is NOT an AJAX action - our messages new to be a full UI message.
     */
    set_default_ui_title("Login");
    set_ui_error_return(ADMIN_URL."/?page=login");

    if (!isset($_POST['username']) || !isset($_POST['password'])) {
        show_error_ui("Invalid arguments(s)");
    }

    $user = $_POST['username'];
    $pass = $_POST['password'];
    $u = check_user($user, $pass);
    if ($u === false) {
        // Password bad, immediate fail
        login_page("Invalid username or password");
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

    // Update session
    $_SESSION['user_data'] = $user_data;
    $_SESSION['user_role'] = $user_role;

    log_msg("Logged in");

    // Redirect to home
    redirect(ADMIN_URL);
}

function handle_post_passwd() {
    global $db, $user_role, $user_data;
    /*
     * This action is NOT an AJAX action - our messages new to be a full UI message.
     */
    set_default_ui_title("Change password");

    require_auth();

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
            log_msg("Changed password for '$user'");
            redirect(ADMIN_URL);
        } else {
            log_msg("Changed password");
            passwd_page("Password changed successfully!");
        }
    }
}

function handle_post_invite_new() {
    global $db, $invite;
    /*
     * This action is NOT an AJAX action - our messages need to be a full UI message.
     */
    set_default_ui_title("Create New User");

    if (!isset($_POST['token'])) {
        show_error_ui("Missing token");
    }
    $invite = get_invite($_POST['token']);
    if ($invite === false) {
        show_error_ui("Could not find your invite");
    }
    switch ($invite['type']) {
        case INVITE_RESET:
            $email = null;
            $page_fn = 'invite_reset_page';
            break;
        case INVITE_NEW:
            $email = null;
            $page_fn = 'invite_new_page';
            break;
        case INVITE_NEW_EMAIL:
            $email = $invite['email'];
            $page_fn = 'invite_reset_page';
            break;
        default:
            show_error_ui("Wrong invite type");
    }

    if (is_null($invite['name'])) {
        $user = strtolower(gf_ui('user', true /* optional */));
        if (strlen($user) == 0) {
            $page_fn("Please provide a username");
        } else if (preg_match('/^[a-zA-Z0-9_-]+$/', $user) !== 1) {
            $page_fn("Usernames must only contain letters, numbers, '_', or '-'");
        }
    } else {
        $user = $invite['name'];
    }

    $pass = gf_ui('pass1', true /* optional */);
    $pass2 = gf_ui('pass2', true /* optional */);
    $pwdcheck = check_password($pass);

    if ($pass != $pass2) {
        $page_fn("Passwords do not match");
    } else if ($pwdcheck !== true) {
        $page_fn($pwdcheck);
    } else {
        // Hash password
        $hash = password_hash($pass, PASSWORD_DEFAULT);

        if ($invite['type'] == INVITE_RESET) {
            // Update password hash
            $stmt = $db->prepare('UPDATE users SET hash = :hash
                WHERE name = :name;');
            $stmt->bindValue(":name", $invite['name']);
            $stmt->bindValue(":hash", $hash);

            if ($stmt->execute() === false) {
                show_error_ui("Error changing password: ".
                    htmlesc($db->lastErrorMsg()));
            }

            $t = SQLite3::escapeString($invite['token']);
            $db->query("DELETE FROM invites WHERE token = '$t';");

            show_msg_ui("Password changed successfully!");
        } else {
            $db->exec("BEGIN TRANSACTION;");

            // Check if username already taken
            $e = SQLite3::escapeString($user);
            $res = $db->querySingle("SELECT name FROM users WHERE name = '$e'");
            if (!is_null($res) && ($res !== false)) {
                $db->exec("ROLLBACK;");
                $page_fn("Error: Username already taken");
            }
            if (is_null($invite['name'])) {
                $res = $db->querySingle("SELECT name FROM invites WHERE name = '$e'");
                if (!is_null($res) && ($res !== false)) {
                    $db->exec("ROLLBACK;");
                    $page_fn("Error: Username already taken");
                }
            }

            /*
            * Add user to database
            */
            $stmt = $db->prepare('INSERT INTO users(name, email, hash, comment)
                VALUES(:name, :email, :hash, :comment);');
            if ($stmt === false) {
                $db->exec("ROLLBACK;");
                show_error_ui("Internal database error (prepare)");
            }
            $stmt->bindValue(":name", $user, SQLITE3_TEXT);
            $stmt->bindValue(":email", $email, SQLITE3_TEXT);
            $stmt->bindValue(":hash", $hash, SQLITE3_TEXT);
            $stmt->bindValue(":comment", $invite['comment'], SQLITE3_TEXT);

            if ($stmt->execute() === false) {
                $errmsg = "Error creating user: ".htmlesc($db->lastErrorMsg());
                $db->exec("ROLLBACK;");
                show_error_ui($errmsg);
            }

            foreach (explode(':', $invite['groups']) as $g) {
                if ($g == '') continue;
                $stmt = $db->prepare('INSERT INTO groups(user, grp)
                    VALUES(:user, :grp);');
                if ($stmt === false) {
                    $db->exec("ROLLBACK;");
                    show_error_ui("Internal database error (prepare)");
                }
                $stmt->bindValue(":user", $user, SQLITE3_TEXT);
                $stmt->bindValue(":grp", $g, SQLITE3_TEXT);
                if ($stmt->execute() === false) {
                    $errmsg = "Error setting group permissions: ".htmlesc($db->lastErrorMsg());
                    $db->exec("ROLLBACK;");
                    show_error_ui($errmsg);
                }
            }

            $t = SQLite3::escapeString($invite['token']);
            $db->query("DELETE FROM invites WHERE token = '$t';");
            $db->query("COMMIT;");
            log_msg("Created user '${user}' with comment ".
                "'${invite['comment']}'");
            show_msg_ui("User '$user' created successfully!");
        }
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

    // CSRF mitigation
    if (!isset($_POST['csrf_token'])) {
        show_error("Missing CSRF Token", true /* set_400 */);
    }
        if ($_POST['csrf_token'] != $_SESSION['csrf_token']) {
        show_error("Invalid CSRF Token", true /* set_400 */);
    }
    $_SESSION['csrf_token'] = token_gen();

    switch ($_POST['action']) {
    case 'login':
        handle_post_login();
        exit;

    case 'passwd':
        handle_post_passwd();
        exit;

    case 'invite_new':
        handle_post_invite_new();
        exit;

    case 'deluser':
        require_admin();
        $user = gfe('user');
        $db->query("DELETE FROM groups WHERE user = '$user'");
        $db->query("DELETE FROM users WHERE name = '$user'");
        log_msg("User '$user' deleted");
        break;

    case 'addgroup':
        require_admin();
        $user = gfe('user');
        $grp = gfe('grp');
        if ($grp == '') {
            show_error("Group cannot be blank");
        }
        if (preg_match('/^[a-zA-Z0-9_-]+$/', $grp) === 1) {
            $db->query("INSERT INTO groups(user, grp) VALUES ".
                "('$user', '$grp')");
        } else {
            show_error("Group must only contain letters, numbers, '_', or '-'");
        }
        log_msg("Added '$user' to group '$grp'");
        break;

    case 'delmember':
        require_admin();
        $user = gfe('user');
        $grp = gfe('grp');
        $db->query("DELETE FROM groups WHERE ".
            "user = '$user' AND grp = '$grp'");
        log_msg("Removed '$user' from group '$grp'");
        break;

    case 'delgroup':
        require_admin();
        $grp = gfe('grp');
        $db->query("DELETE FROM groups WHERE grp = '$grp'");
        log_msg("Removed group '$grp'");
        break;

    case 'edit_comment':
        require_admin();
        $user = gfe('user');
        // Comment may be blank
        if (isset($_POST['comment'])) {
            $comment = $_POST['comment'];
        } else {
            $comment = '';
        }
        $db->query("UPDATE users SET comment = '$comment' WHERE name = '$user'");
        log_msg("Changed user '$user' comment to '$comment'");
        break;

    case 'delinvite':
        require_admin();
        $token = gfe('token');
        $db->query("DELETE FROM invites WHERE token = '$token'");
        log_msg("Deleted invitation");
        break;

    case 'add_invite_new':
        require_admin();

        set_ui_error_return(ADMIN_URL."/#invites");

        $groups = gf('groups', true);
        $comment = gf('comment', true);
        $name = trim(gf('name', true));
        $token = token_gen();

        if (strlen($name) == 0) {
            $name = null;
        } else {
            $name = strtolower($name);
            if (preg_match('/^[a-zA-Z0-9_-]+$/', $name) !== 1) {
                redirect_error_ui("Usernames must only contain letters, numbers, '_', or '-'");
            }
            $e = SQLite3::escapeString($name);
            $res = $db->querySingle("SELECT name FROM users WHERE name = '$e'");
            if (!is_null($res) && ($res !== false)) {
                redirect_error_ui("Username '$name' is already taken");
            }
        }

        $stmt = $db->prepare(
            'INSERT INTO invites
                ("token", "type", "name", "expiry", "groups", "comment")
            VALUES
                (:token, :type, :name, datetime("now", "30 days"),
                    :groups, :comment);');
        $stmt->bindValue(":token", $token, SQLITE3_TEXT);
        $stmt->bindValue(":type", INVITE_NEW, SQLITE3_INTEGER);
        $stmt->bindValue(":name", $name, SQLITE3_TEXT);
        $stmt->bindValue(":groups", $groups, SQLITE3_TEXT);
        $stmt->bindValue(":comment", $comment, SQLITE3_TEXT);

        if ($stmt->execute() === false) {
            redirect_error_ui("Error creating invitation!");
        }

        header('Location: '.ADMIN_URL, true, 303);
        if (is_null($name)) {
            log_msg("Created invitation with comment '$comment'");
        } else {
            log_msg("Created invitation for '$name' with comment '$comment'");
        }
        break;

    case 'gen_reset_invite':
        require_admin();

        set_ui_error_return(ADMIN_URL);

        $name = gf('name', true);
        $e = SQLite3::escapeString($name);
        $u = $db->querySingle("SELECT * FROM users WHERE name = '$e'",
            true /* entireRow */);
        if (($u === false) || empty($u)) {
            redirect_error_ui("User not found");
        }

        // Make sure we purge any existing reset links
        $stmt = $db->prepare('DELETE FROM invites WHERE name = :name;');
        $stmt->bindValue(":name", $u['name']);
        $stmt->execute();

        $stmt = $db->prepare(
            'INSERT INTO invites
                ("token", "type", "name", "expiry", "groups", "comment")
            VALUES
                (:token, :type, :name, datetime("now", "30 days"), "", "");');
        // groups and comment aren't used
        $stmt->bindValue(":token", token_gen(), SQLITE3_TEXT);
        $stmt->bindValue(":type", INVITE_RESET, SQLITE3_INTEGER);
        $stmt->bindValue(":name", $u['name'], SQLITE3_TEXT);

        if ($stmt->execute() === false) {
            redirect_error_ui("Error creating invitation!");
        }

        log_msg("Created password reset link for '$name'");

        redirect(ADMIN_URL."/#invites");

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

// Determine the name of the page
if (isset($_GET['page'])) {
    $page = $_GET['page'];
} else {
    if (isset($_GET['token'])) {
        global $invite;
        $invite = get_invite($_GET['token']);
        if ($invite === false) {
            show_error_ui("Could not find your invite");
        }
        switch ($invite['type']) {
            case INVITE_NEW:
                $page = "invite_new";
                break;
            case INVITE_NEW_EMAIL:
                $page = "invite_new_email";
                break;
            case INVITE_CHANGE_EMAIL:
                $page = "invite_change_email";
                break;
            case INVITE_RESET:
                $page = "invite_reset";
                break;
            default:
                show_error_ui("Internal error: Invalid invitation type");
                exit;
        }
    } else if (isset($_GET['passwd'])) $page = 'passwd';
    else $page = 'admin';
}

switch ($page) {
    case 'login':
        login_page();
        break;
    case 'invite_new':
        invite_new_page();
        break;
    case 'invite_reset':
        invite_reset_page();
        break;
    case 'admin':
        require 'admin_page.inc.php';
        break;
    case 'passwd':
        passwd_page();
        break;
    case 'logout':
        unset($_SESSION['user_role']);
        unset($_SESSION['user_data']);
        redirect_login();
        exit;
    case 'error':
        if (isset($_SESSION['error_ui'])) {
            $eui = $_SESSION['error_ui'];
            unset($_SESSION['error_ui']);
            set_ui_error_return($eui['return']);
            show_error_ui($eui['msg'], $eui['title']);
        } else {
            show_error_ui("Lost?");
        }
    default:
        show_error_ui("Lost?");
        exit;
}
