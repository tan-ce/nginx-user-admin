<?php global $message;

page_head('Login'); ?>
<script type="text/javascript">
    $(document).ready(function() {
        $('#tabs').tabs();
        $('.button').button();
    });
</script></head><body>

<div id="tabs" class="center-wrap">
<div id="tabs" class="center-wrap">
    <ul><li><a href="#passwd">Login</a></li></ul>
    <div id="passwd">
        <?php if (!is_null($message)) {
            $msg = htmlesc($message);
            echo "<p class=\"message\">$msg</p>\n";
        } ?>
        <form action="<?php echo ADMIN_URL; ?>" method="post">
            <input type="hidden" name="action" value="login" />

            <p>User:<br>
            <input type="text" name="username" /></p>

            <p>Password:<br>
            <input type="password" name="password" /></p>
            
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <input type="submit" value="Login" class="button">
        </form>
    </div>
</div>
</div>
<?php page_tail();