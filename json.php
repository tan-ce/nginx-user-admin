<?php require 'common.inc.php';

$db = new SQLite3('db/users.sqlite',
    SQLITE3_OPEN_READONLY);

function debug_dump($var) {
    ob_start();
    var_dump($var);
    file_put_contents('db/debug.txt', ob_get_clean());
}

$creds = json_decode(file_get_contents('php://input'), true);
$auth_ok = false;

if (isset($creds['username']) && isset($creds['password'])) {
    $user = strtolower($creds['username']);
    $pass = $creds['password'];
    $uri = $_SERVER['DOCUMENT_URI'];

    $auth_ok = check_auth($uri, $user, $pass);
}

if ($auth_ok) {
    echo "true";
} else {
    echo "false";
}
