<?php require 'config.inc.php';

/*
 * Functions
 */

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
