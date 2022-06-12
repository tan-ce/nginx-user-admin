<?php

define('DB_VER', 2);

require_once 'config.inc.php';

global $db;
$db = null;

function db_get_rw() {
    $db_rw = new SQLite3(DB_PATH,
        SQLITE3_OPEN_CREATE | SQLITE3_OPEN_READWRITE);
    $db_rw->busyTimeout(10000);
    return $db_rw;
}

function db_get_ro() {
    return new SQLite3(DB_PATH, SQLITE3_OPEN_READONLY);
}

/*
 * Check if the database needs to be upgraded. If yes, perform the upgrade.
 *
 * $db_ro   - Set to true if the database was opened read only.
 */
function db_upgrade_check($db_ro = true) {
    global $db;

    $res = $db->querySingle("SELECT COUNT(name) FROM sqlite_master ".
        "WHERE type='table' AND (name='options' OR name='users');");

    if (($res === false) || ($res == 0)) {
        // Start from scratch
        if ($db_ro) {
            $db->close();
            $db = db_get_rw();
        }

        $db->exec("BEGIN EXCLUSIVE;");
        require 'db_install.inc.php';
        $db->exec("COMMIT;");

        log_msg("Initialized new database");

        if ($db_ro) {
            $db->close();
            $db = db_get_ro();
        }

        return;

    } else if ($res == 1) {
        // Version 0
        $version = 0;
    } else {
        $version = $db->querySingle("SELECT value FROM options ".
            "WHERE name='version';");
        if ($version === false) {
            log_die("Database seems corrupted (can't read version)");
        }
        $version = intval($version);
    }

    if ($version > DB_VER) {
        log_die("Database is newer than application expects!");
    }

    if ($version < DB_VER) {
        if ($db_ro) {
            $db->close();
            $db = db_get_rw();
        }

        $upgrade_ok = true;
        $db->exec("BEGIN EXCLUSIVE;");

        require 'db_upgrade.inc.php';

        if (!$upgrade_ok) {
            $db->exec("ROLLBACK;");
            log_die("Upgrade of database (".$version." to ".
                strval(DB_VER).") failed");
        }

        $db->exec("COMMIT;");
        log_msg("Upgraded database from version " . strval($version) .
            " to " . strval(DB_VER));
        if ($db_ro) {
            $db->close();
            $db = db_get_ro();
        }
    }
}

function db_rw_init() {
    global $db;

    $db = db_get_rw();
    db_upgrade_check(false /* db_ro */);

    // Housekeeping
    $db->exec("DELETE FROM invites WHERE expiry < datetime('now');");
}

function db_ro_init() {
    global $db;

    $db = db_get_ro();
    db_upgrade_check(true /* db_ro */);
}