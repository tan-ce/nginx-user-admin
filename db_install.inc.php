<?php
$db->exec('CREATE TABLE "users" (
    "name" VARCHAR(32) PRIMARY KEY NOT NULL,
    "email" VARCHAR(320) DEFAULT NULL,
    "hash" TEXT NOT NULL,
    "comment" TEXT NOT NULL DEFAULT ""
);');
$db->exec('CREATE TABLE "invites" (
    "token" VARCHAR(22) NOT NULL PRIMARY KEY,
    "type" INTEGER NOT NULL DEFAULT 0,
    "expiry" DATETIME NOT NULL,
    "name" VARCHAR(32) DEFAULT NULL,
    "email" VARCHAR(320) DEFAULT NULL,
    "groups" TEXT NOT NULL,
    "comment" TEXT NOT NULL
);');
$db->exec('CREATE TABLE "groups" (
    "user" VARCHAR(32) NOT NULL
        REFERENCES users(name)
            ON DELETE CASCADE
            ON UPDATE CASCADE,
    "grp" VARCHAR(32) NOT NULL,
    PRIMARY KEY (user, grp)
);');
$db->exec('CREATE TABLE "email_spool" (
    "id" INT PRIMARY KEY AUTOINCREMENT,
    "ts" DATETIME NOT NULL,
    "email" VARCHAR(340) NOT NULL REFERENCES users("email")
        ON DELETE CASCADE
        ON UPDATE CASCADE,
    "msg" TEXT NOT NULL
);');
$db->exec('CREATE TABLE "options" (
    "name" VARCHAR(16) PRIMARY KEY NOT NULL,
    "value" TEXT NOT NULL
);');
$db->exec('INSERT INTO options("name", "value")
    VALUES("version", "'.strval(DB_VER).'");');