<?php require 'common.inc.php';

db_ro_init();

$creds = json_decode(file_get_contents('php://input'), true);
$auth_ok = false;

if (isset($creds['username']) && isset($creds['password'])) {
    $user = strtolower($creds['username']);
    $pass = $creds['password'];
    $uri = $_SERVER['DOCUMENT_URI'];

    $auth_ok = check_auth_uri($uri, $user, $pass);
}

if ($auth_ok) {
    echo "true";
} else {
    echo "false";
}
