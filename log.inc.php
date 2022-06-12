<?php

require_once 'config.inc.php';

function log_msg($msg) {
    global $user_data, $user_role;

    switch ($user_role) {
        case AUTH_NONE:
            $user = "GUEST";
            break;
        case AUTH_USER:
            $user = "USER(${user_data['name']})";
            break;
        case AUTH_ADMIN:
            $user = "ADMIN(${user_data['name']})";
            break;
        default:
            // Should Never Happen (tm)
            $user = "UNDEF";
            break;
    }
    if (!defined('LOG_PATH')) return;
    $msg = date('Y-m-d g:ia P') . " [$user]: " . $msg . "\n";
    file_put_contents(LOG_PATH, $msg, FILE_APPEND);
}

function log_die($msg) {
    log_msg($msg);
    http_response_code(500);
    echo "Internal error!";
    exit;
}