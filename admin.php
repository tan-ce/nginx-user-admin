<?php require 'common.inc.php';

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

// Init
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

// "Get Field"
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

function jsesc($js) {
    return htmlentities(addslashes($js));
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
                http_response_code(400);
                echo "Group cannot be blank";
                exit;
            }
            $db->query("INSERT INTO groups(user, grp) VALUES ".
                "('$user', '$grp')");
            break;

        case 'delmember':
            auth_admin();
            $user = gf('user');
            $grp = gf('grp');
            $db->query("DELETE FROM groups WHERE ".
                "user = '$user' AND grp = '$grp'");
            break;

        case 'edit_comment':
            auth_admin();
            $user = gf('user');
            $comment = gf('comment');
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
                    echo htmlentities($db->lastErrorMsg());
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
                        echo htmlentities($db->lastErrorMsg());
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
    ?><html><head><title>Admin</title>
    <link rel="stylesheet" href="<?php echo ADMIN_URL; ?>/style.css" />
    <script
        src="https://code.jquery.com/jquery-3.3.1.min.js"
        integrity="sha256-FgpCb/KJQlLNfOu91ta32o/NMZxltwRo8QtmkMRdAu8="
        crossorigin="anonymous"></script>
    <script type="text/javascript">
        var csrf_token = "<?php echo $_SESSION['csrf_token']; ?>";

        function deluser(user) {
            if (confirm("Really delete " + user + "?")) {
                $.post('<?php echo ADMIN_URL; ?>', {
                    'action': 'deluser',
                    'user': user,
                    'csrf_token': csrf_token
                }, function(ret) {
                    if (ret != '') alert(ret);
                    else window.location.reload();
                });
            }

            return false;
        }
        function addgroup(user) {
            grp = prompt("Add " + user + " to which group?", "");
            if (grp == null || grp == '') return false;

            $.post('<?php echo ADMIN_URL; ?>', {
                'action': 'addgroup',
                'user': user,
                'grp': grp,
                'csrf_token': csrf_token
            }, function(ret) {
                if (ret != '') alert(ret);
                else window.location.reload();
            });

            return false;
        }
        function delmember(user, grp) {
            if (!confirm("Really remove " + user + " from " + grp + "?")) {
                return false;
            }
            $.post('<?php echo ADMIN_URL; ?>', {
                'action': 'delmember',
                'user': user,
                'grp': grp,
                'csrf_token': csrf_token
            }, function(ret) {
                if (ret != '') alert(ret);
                else window.location.reload();
            });

            return false;
        }
        function delinvite(token) {
            if (confirm("Really delete this invite?")) {
                $.post('<?php echo ADMIN_URL; ?>', {
                    'action': 'delinvite',
                    'token': token,
                    'csrf_token': csrf_token
                }, function(ret) {
                    if (ret != '') alert(ret);
                    else window.location.reload();
                });
            }

            return false;
        }
        function edit_comment(user) {
            var ret = prompt("Please enter the new comment:", "");
            if (ret === null) {
                return false;
            }
            $.post('<?php echo ADMIN_URL; ?>', {
                'action': 'edit_comment',
                'user': user,
                'comment': ret,
                'csrf_token': csrf_token
            }, function(ret) {
                if (ret != '') alert(ret);
                else window.location.reload();
            });
            return false;
        }
    </script>
    <body><div class="center-wrap">

    <!-- User Table -->
    <h1>By User</h1>
    <p>Admin Group: <?php echo ADMIN_GROUP; ?><br></p>
    <table><?php
            $query = $db->query("SELECT DISTINCT grp FROM groups ORDER BY grp ASC");
            $grps = array();
            while ($g = $query->fetchArray(SQLITE3_ASSOC)) {
                $grps[] = $g['grp'];
            }
            /* Header row start */
?>      <tr><th>User</th><th>Comment</th><th></th><th></th><?php
            foreach ($grps as $g) {
                echo '<th>'.htmlentities($g).'</th>';
            }?></tr>
        <?php  /* Header row end */
        
        $users = $db->query("SELECT * FROM users ORDER BY name COLLATE NOCASE ASC");
        while ($r = $users->fetchArray(SQLITE3_ASSOC)) { 
            $name = htmlentities($r['name']);
            $jsname = jsesc($r['name']); ?>
            <tr><td><?php echo $name; ?></td>
            <td><div class="edit-box" onclick="javascript: return edit_comment('<?php
                echo $jsname; ?>');"></div><?php echo htmlentities($r['comment']); ?></td>
            <td><a href="#" onclick="javascript: return deluser('<?php
                echo $jsname; ?>')">Delete</a></td>
            <td><a href="#" onclick="javascript: return addgroup('<?php
                echo $jsname; ?>')">Add Group</a></td>
            <?php $e_u = SQLite3::escapeString($r['name']);
            foreach ($grps as $grp) {
                $e_g = SQLite3::escapeString($grp);
                $res = $db->querySingle("SELECT user FROM groups WHERE ".
                    "user = '$e_u' AND grp = '$e_g'");
                if (is_null($res) || ($res === false)) {
                    echo '<td></td>';
                } else {
                    ?><td><a href="#" onclick="javascript: return delmember('<?php
                    echo $jsname; ?>', '<?php 
                    echo jsesc($grp); ?>')"><?php
                    echo htmlentities($grp); ?></a></td><?php
                }
            } ?></tr>
        <?php } ?>
    </table><br>

    <!-- Group Table -->
    <h1>By Group</h1>
    <table>
        <?php $groupings = $db->query(
            "SELECT * FROM groups ORDER BY grp ASC, user ASC");
        $cur = "";
        while ($r = $groupings->fetchArray(SQLITE3_ASSOC)) {
            if ($cur != $r['grp']) {
                $cur = $r['grp'];
                echo '<tr><th colspan="2">'.
                    '<strong>'.$cur."</strong></th></tr>\n";
            } ?>
            <tr><td><?php echo htmlentities($r['user']); ?></td>
            <!-- <td><?php echo htmlentities($r['grp']); ?></td> -->
            <td><a href="#" onclick="javascript: return delmember('<?php
                echo jsesc($r['user']); ?>', '<?php 
                echo jsesc($r['grp']); ?>')">Remove</a></td></tr>
        <?php } ?>
    </table><br>

    <!-- Invites Table -->
    <h1>Invites</h1>
    <table>
        <tr>
            <th>Link</th>
            <th>Expiry</th>
            <th>Groups</th>
            <th>Comment</th>
            <th></th>
        </tr>
        <?php $invites = $db->query("SELECT * FROM invites ".
            "ORDER BY expiry DESC");
        while ($i = $invites->fetchArray(SQLITE3_ASSOC)) { 
            $link = ADMIN_URL."?token=".$i['token']; ?>
        <tr>
            <td><a href="<?php echo $link; ?>"><?php echo $link; ?></a></td>
            <td><?php echo $i['expiry']; ?></td>
            <td><?php echo htmlentities($i['groups']); ?></td>
            <td><?php echo htmlentities($i['comment']); ?></td>
            <td>
                <a href="#" onclick="javascript: return delinvite('<?php
                echo jsesc($i['token']); ?>')">Remove</a>
            </td>
        </tr>
        <?php } ?>
    </table><br>

    <h1>Create New Invite</h1>
    <?php new_invite_preamble(); ?>
    <form action="<?php echo ADMIN_URL; ?>" method="post">
        <input type="hidden" name="action" value="newinvite">

        Groups (seperate with colons):<br>
        <input type="text" name="groups"><br>
        Comments:<br>
        <input type="text" name="comment"><br>
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
        <input type="submit" value="Create Invite">
    </form>
    
    </div></body></html>
<?php }

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

function new_user($token) {
    global $db;
    $invite = get_invite($token);
    if ($invite === false) {
        echo "The invite token is not valid";
        return;
    }

    ?><html><head><title>New user registration</title>
    <link rel="stylesheet" href="<?php echo ADMIN_URL; ?>/style.css" />
    </head><body><div class="center-wrap">
    <h1>Create New User</h1>
    <form action="<?php echo ADMIN_URL; ?>" method="post">
        <input type="hidden" name="action" value="createuser">
        <input type="hidden" name="token" value="<?php 
            echo htmlentities($invite['token']); ?>">
        Username:<br>
        <input type="text" maxlength="32" name="user"><br>
        Password (at least 8 characters, enter twice):<br>
        <input type="password" name="pass1"><br>
        <input type="password" name="pass2"><br>
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
        <input type="submit" value="Create User">
    </form>
    </div></body></html><?php
}

if (isset($_GET['token'])) new_user($_GET['token']);
else admin();
