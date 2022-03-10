<?php function new_user_page($token) {
    global $db;

    page_head('New User Registration');
    echo '<div class="center-wrap">'."\n";

    $invite = get_invite($token);
    if ($invite === false) {
        echo "The invite token is not valid";
    } else { ?>
        <h1>Create New User</h1>
        <form action="<?php echo ADMIN_URL; ?>" method="post">
            <input type="hidden" name="action" value="createuser">
            <input type="hidden" name="token" value="<?php 
                echo htmlesc($invite['token']); ?>">
            Username:<br>
            <input type="text" maxlength="32" name="user"><br>
            Password (at least 8 characters, enter twice):<br>
            <input type="password" name="pass1"><br>
            <input type="password" name="pass2"><br>
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <input type="submit" value="Create User">
        </form>
<?php    }

    echo "</div>\n";
    page_tail();
}
