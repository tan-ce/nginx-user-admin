<?php

if ($version < 1) {
    $upgrade_ok = $upgrade_ok && $db->exec(
        'CREATE TABLE "options" (
            "name" VARCHAR(16) PRIMARY KEY NOT NULL,
            "value" TEXT NOT NULL
    );');
    $upgrade_ok = $upgrade_ok && $db->exec(
        'INSERT INTO options("name", "value")
            VALUES("version", "'.strval(DB_VER).'");');
}

if ($version < 2) {
    // Cleanup botched upgrades
    @$db->exec('DROP TABLE "new_invites";');
    @$db->exec('DROP TABLE "new_users";');
    @$db->exec('DROP TABLE "email_spool";');

    // Upgrade users table
    $upgrade_ok = $upgrade_ok && $db->exec(
        'CREATE TABLE "new_users" (
            "name" VARCHAR(32) PRIMARY KEY NOT NULL,
            "email" VARCHAR(320) DEFAULT NULL,
            "hash" TEXT NOT NULL,
            "comment" TEXT NOT NULL DEFAULT ""
    );');
    $res = $db->query('SELECT * FROM "users";');
    if ($res === false) {
        $upgrade_ok = false;
    } else {
        while ($row = $res->fetchArray(SQLITE3_ASSOC)) {
            $stmt = $db->prepare(
                'INSERT INTO "new_users"
                    ("name", "hash", "comment")
                VALUES (:name, :hash, :comment);');
            if ($stmt == false) {
                $upgrade_ok = false;
                break;
            }
            foreach ($row as $k=>$v) {
                // Some older versions had NULL values
                if (is_null($v)) {
                    $row[$k] = '';
                }
            }
            $upgrade_ok = $upgrade_ok &&
                $stmt->bindValue(":name", $row['name']);
            $upgrade_ok = $upgrade_ok &&
                $stmt->bindValue(":hash", $row['hash']);
            $upgrade_ok = $upgrade_ok &&
                $stmt->bindValue(":comment", $row['comment']);
            if ($stmt->execute() === false) {
                $upgrade_ok = false;
            }
            if (!$upgrade_ok) break;
        }
    }
    $upgrade_ok = $upgrade_ok &&
        $db->exec('DROP TABLE "users";');
    $upgrade_ok = $upgrade_ok &&
        $db->exec('ALTER TABLE "new_users" RENAME TO "users";');

    // Add email_spool
    $upgrade_ok = $upgrade_ok && $db->exec(
        'CREATE TABLE "email_spool" (
            "id" INTEGER PRIMARY KEY AUTOINCREMENT,
            "ts" DATETIME NOT NULL,
            "email" VARCHAR(340) NOT NULL REFERENCES users("email")
                ON DELETE CASCADE
                ON UPDATE CASCADE,
            "msg" TEXT NOT NULL
    );');

    // Upgrade invites table
    $upgrade_ok = $upgrade_ok && $db->exec(
        'CREATE TABLE "new_invites" (
            "token" VARCHAR(22) NOT NULL PRIMARY KEY,
            "type" INTEGER NOT NULL DEFAULT 0,
            "expiry" DATETIME NOT NULL,
            "name" VARCHAR(32) DEFAULT NULL,
            "email" VARCHAR(320) DEFAULT NULL,
            "groups" TEXT NOT NULL,
            "comment" TEXT NOT NULL
    );');
    $upgrade_ok = $upgrade_ok && $db->exec(
        'INSERT INTO "new_invites" ("token", "expiry", "groups", "comment")
        SELECT "token", "expiry", "groups", "comment" FROM "invites";'
    );
    $upgrade_ok = $upgrade_ok && $db->exec('DROP TABLE "invites";');
    $upgrade_ok = $upgrade_ok &&
        $db->exec('ALTER TABLE "new_invites" RENAME TO "invites";');

    // Done, now update database version
    $upgrade_ok = $upgrade_ok &&
        $db->exec('UPDATE options SET value="'.strval(DB_VER).'"
            WHERE name="version";');
}