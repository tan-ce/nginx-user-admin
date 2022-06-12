<?php global $db, $invite;

if (!isset($invite)) {
    echo "Invitation missing!";
    exit;
}

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
        } ?>

        <form action="<?php echo ADMIN_URL; ?>" method="post">
            <input type="hidden" name="action" value="invite_new">
            <input type="hidden" name="token" value="<?php echo $invite['token']; ?>">

            <p>Username:<br>
            <?php if (is_null($invite['name'])) { ?>
            <input type="text" maxlength="32" name="user"></p>
            <?php } else {
                echo htmlesc($invite['name'])."</p>\n";
            } ?>

            <p>Password (at least 8 characters, enter twice):<br>
            <input type="password" name="pass1"><br>
            <input type="password" name="pass2"></p>

            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <input type="submit" value="Create User" class="button">
        </form>

    </div>
</div>
<?php page_tail();