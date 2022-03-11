<?php global $user_role, $user_data, $message;
/*
 * Precondition: $_GET['passwd'] is set.
 */

require_auth();
$user = $_GET['passwd'];
$title = "Change ${user}'s password";

page_head($title); ?>
<script type="text/javascript">
    $(document).ready(function() {
        $('#tabs').tabs();
        $('.button').button();
    });
</script></head><body>

<div id="tabs" class="center-wrap">
    <ul><li><a href="#passwd"><?php echo htmlesc($title); ?></a></li></ul>
    <div id="passwd">
        <?php if ($user_role == AUTH_ADMIN) {
            echo "<a class=\"button\" href=\"".ADMIN_URL."#users\">Back</a>\n";
        }
        
        if (!is_null($message)) {
            $msg = htmlesc($message);
            echo "<p class=\"message\">$msg</p>\n";
        } ?>
        <form action="<?php echo ADMIN_URL; ?>?passwd=<?php echo htmlesc($user); ?>" method="post">
            <input type="hidden" name="action" value="passwd">
            <input type="hidden" name="user" value="<?php echo htmlesc($user); ?>">

            <?php if ($user_role != AUTH_ADMIN) { ?>
            <p>Current Password:<br>
            <input type="password" name="oldpass"></p>
            <?php } ?>

            <p>Password (at least 8 characters, enter twice):<br>
            <input type="password" name="pass1"><br>
            <input type="password" name="pass2"></p>

            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <input type="submit" value="Change Password" class="button">
        </form>
    </div>
</div>
<?php page_tail();