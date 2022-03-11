<?php global $db;
/*
 * Precondition: $_GET['token'] is set.
 */

$token = $_GET['token'];

page_head('New User Registration'); ?>
<script type="text/javascript">
    $(document).ready(function() {
        $('#tabs').tabs();
        $('.button').button();
    });
</script></head><body>

<div id="tabs" class="center-wrap">
    <ul><li><a href="#new_user">Create New User</a></li></ul>
    <div id="new_user">
    <?php if (!is_null($message)) {
        $msg = htmlesc($message);
        echo "<p class=\"message\">$msg</p>\n";
    } 

    $invite = get_invite($token);
    if ($invite === false) {
        echo "<p class=\"message\">The invite token is not valid</p>\n";
    } else { ?>
        <form action="<?php echo ADMIN_URL; ?>?token=<?php echo htmlesc($token); ?>" method="post">
            <input type="hidden" name="action" value="createuser">

            <p>Username:<br>
            <input type="text" maxlength="32" name="user"></p>

            <p>Password (at least 8 characters, enter twice):<br>
            <input type="password" name="pass1"><br>
            <input type="password" name="pass2"></p>

            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <input type="submit" value="Create User" class="button">
        </form>
<?php    } ?>

    </div>
</div>
<?php page_tail();