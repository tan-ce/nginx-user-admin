<?php global $db, $invite;

if (!isset($invite)) {
    echo "Invitation missing!";
    exit;
}

page_head('Password Reset'); ?>
<script type="text/javascript">
    $(document).ready(function() {
        $('#tabs').tabs();
        $('.button').button();
    });
</script></head><body>

<div id="tabs" class="center-wrap">
    <ul><li><a href="#reset_pwd">Reset Password</a></li></ul>
    <div id="reset_pwd">
        <?php if (!is_null($message)) {
            $msg = htmlesc($message);
            echo "<p class=\"message\">$msg</p>\n";
        } ?>

        <form action="<?php echo ADMIN_URL; ?>" method="post">
            <input type="hidden" name="action" value="invite_new">
            <input type="hidden" name="token" value="<?php echo $invite['token']; ?>">

            <p>Username:<br><?php echo htmlesc($invite['name']); ?></p>

            <p>Password (at least 8 characters, enter twice):<br>
            <input type="password" name="pass1"><br>
            <input type="password" name="pass2"></p>

            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <input type="submit" value="Reset Password" class="button">
        </form>

    </div>
</div>
<?php page_tail();