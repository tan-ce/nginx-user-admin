<?php require 'common.inc.php';

/*
 * This file implements nginx's subrequest auth protocol.
 */

db_ro_init();

$auth_ok = false;
if (isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW'])) {
    $user = strtolower($_SERVER['PHP_AUTH_USER']);
    $pass = $_SERVER['PHP_AUTH_PW'];
    $uri = $_SERVER['DOCUMENT_URI'];

    $auth_ok = check_auth_uri($uri, $user, $pass);
}

if ($auth_ok) {
    http_response_code(200);
    echo "OK";
} else {
    header("WWW-Authenticate: Basic realm=\"".REALM."\"");
    http_response_code(401);
    echo "FAIL";
}
