<?php require 'common.inc.php';

$db = new SQLite3('db/users.sqlite',
    SQLITE3_OPEN_READONLY);

function debug_dump($var) {
    ob_start();
    var_dump($var);
    file_put_contents('db/debug.txt', ob_get_clean());
}

$auth_ok = false;
if (isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW'])) {
    $user = strtolower($_SERVER['PHP_AUTH_USER']);
    $pass = $_SERVER['PHP_AUTH_PW'];
    $uri = $_SERVER['DOCUMENT_URI'];

    $auth_ok = check_auth($uri, $user, $pass);
}

if ($auth_ok) {
    http_response_code(200);
    echo "OK";
} else {
    header("WWW-Authenticate: Basic realm=\"".REALM."\"");
    http_response_code(401);
    echo "FAIL";
}
