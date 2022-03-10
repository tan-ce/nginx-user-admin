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

function auth_admin() {
    global $db;
    if (    isset($_SERVER['PHP_AUTH_USER']) && 
            isset($_SERVER['PHP_AUTH_PW']))
    {
        $user = $_SERVER['PHP_AUTH_USER'];
        $pass = $_SERVER['PHP_AUTH_PW'];
        if (($user == ADMIN_USER) && check_user($user, $pass)) {
            return;
        } else {
            $u = SQLite3::escapeString($user);
            $g = SQLite3::escapeString(ADMIN_GROUP);
            try {
                $res = $db->querySingle(
                    "SELECT user FROM groups WHERE ".
                        "user = '$u' AND grp = '$g'");
                if (!is_null($res) && $res !== false) {
                    // User is in this group
                    if (check_user($user, $pass)) return;
                }
            } catch (Exception $e) {
                // Ignore
            }
        } 
    }
    header("WWW-Authenticate: Basic realm=\"".REALM."\"");
    http_response_code(401);
    exit;
}

// "Get Field" - get a POST field and escape for SQL
function gf($name, $optional = false) {
    if (!isset($_POST[$name])) {
        http_response_code(400);
        echo "Invalid argument(s)";
        exit;
    }
    if (!$optional && (strlen($_POST[$name]) == 0)) {
        http_response_code(400);
        echo "Invalid argument(s)";
        exit;
    }
    return SQLite3::escapeString($_POST[$name]);
}

function csrf_check() {
    if (!isset($_POST['csrf_token'])) {
        http_response_code(400);
        echo "Missing CSRF Token";
        exit;
    }
    if ($_POST['csrf_token'] != $_SESSION['csrf_token']) {
        http_response_code(400);
        echo "Invalid CSRF Token";
        exit;
    }
}

function admin() {
    global $db;

    // Handle ajax requests
    if (isset($_POST['action'])) {
        csrf_check();
        switch ($_POST['action']) {
        case 'deluser':
            auth_admin();
            $user = gf('user');
            $db->query("DELETE FROM groups WHERE user = '$user'");
            $db->query("DELETE FROM users WHERE name = '$user'");
            break;

        case 'addgroup':
            auth_admin();
            $user = gf('user');
            $grp = gf('grp');
            if ($grp == '') {
                echo "Group cannot be blank";
                exit;
            }
            if (preg_match('/^[a-zA-Z0-9_-]+$/', $grp) === 1) {
                $db->query("INSERT INTO groups(user, grp) VALUES ".
                    "('$user', '$grp')");
            } else {
                echo "Group must only contain letters, numbers, '_', or '-'";
                exit;
            }
            break;

        case 'delmember':
            auth_admin();
            $user = gf('user');
            $grp = gf('grp');
            $db->query("DELETE FROM groups WHERE ".
                "user = '$user' AND grp = '$grp'");
            break;

        case 'delgroup':
            auth_admin();
            $grp = gf('grp');
            $db->query("DELETE FROM groups WHERE grp = '$grp'");
            break;

        case 'edit_comment':
            auth_admin();
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
            auth_admin();
            $token = gf('token');
            $db->query("DELETE FROM invites WHERE token = '$token'");
            break;

        case 'newinvite':
            auth_admin();
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
            $invite = get_invite(gf('token'));
            $user = strtolower(gf('user'));
            $pass = gf('pass1');
            $pass2 = gf('pass2');
            if ($invite === false) {
                echo "Could not find your invite";
            } else if ($preg_match('/[a-zA-Z0-9_-]+/', $user) !== 1) {
                echo "Usernames must only contain letters, numbers, '_', or '-'";
            } else if ($pass != $pass2) {
                echo "Passwords do not match";
            } else if (strlen($pass) < 8) {
                echo "Password too short!";
            } else if (substr(strtolower($pass), 0, 8) == 'password') {
                echo "Please choose a better password...";
            } else {
                $res = $db->querySingle("SELECT name FROM users WHERE name = '$u'");
                if (!is_null($res) && ($res !== false)) {
                    echo "Error: Username already taken";
                    return;
                }
                $hash = password_hash($pass, PASSWORD_DEFAULT);
                $comment = SQLite3::escapeString($invite['comment']);
                $db->query("BEGIN TRANSACTION");
                $query = "INSERT INTO users(name, hash, comment) VALUES ".
                    "('$user', '$hash', '$comment')";
                if ($db->query($query) === false) {
                    echo "Error creating user: ";
                    echo htmlesc($db->lastErrorMsg());
                    $db->query("ROLLBACK");
                    return;
                }

                foreach (explode(':', $invite['groups']) as $g) {
                    if ($g == '') continue;
                    $g = SQLite3::escapeString($g);
                    $query = "INSERT INTO groups(user, grp) VALUES ".
                        "('$user', '$g')";
                    if ($db->query($query) === false) {
                        echo "Error setting group permissions: ";
                        echo htmlesc($db->lastErrorMsg());
                        $db->query("ROLLBACK");
                        return;
                    }
                }

                $t = SQLite3::escapeString($invite['token']);
                $db->query("DELETE FROM invites WHERE token = '$t'");
                $db->query("COMMIT");
                echo "User '$user' created successfully!";
            }

            break;

        default:
            echo "Invalid action";
            exit;
        }

        return;
    }
    
    // Show the page then
    auth_admin();
    require 'admin_page.inc.php';
    admin_page();
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

function new_user_page($token) {
    global $db;
    $invite = get_invite($token);
    if ($invite === false) {
        echo "The invite token is not valid";
        return;
    }

    ?><html><head><title>New user registration</title>
    <link rel="stylesheet" href="<?php echo ADMIN_URL; ?>/style.css" />
    </head><body><div class="center-wrap">
    </div></body></html><?php
}

if (isset($_GET['token'])) new_user_page($_GET['token']);
else admin();
