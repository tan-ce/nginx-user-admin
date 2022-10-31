<?php global $db, $user_role, $user_data;

require_auth();
if ($user_role != AUTH_ADMIN) {
    /*
     * Non-admin user only allowed to change password
     */
    $_GET['passwd'] = $user_data['name'];
    require 'passwd_page.inc.php';
    exit;
}

page_head("Admin"); ?>
<script type="text/javascript">
    var csrf_token = "<?php echo $_SESSION['csrf_token']; ?>";

    function deluser(user) {
        if (confirm("Really delete " + user + "?")) {
            $.post('<?php echo ADMIN_URL; ?>', {
                'action': 'deluser',
                'user': user,
                'csrf_token': csrf_token
            }, function(ret) {
                if (ret != '') alert(ret);
                else window.location.reload();
            });
        }

        return false;
    }

    function setpasswd(user) {
        window.location.href = "?passwd=" + user;
        return false;
    }

    function resetpasswd(user) {
        var form = $('#resetpasswd');
        form.find("[name=name]").val(user);
        form.submit();
        return false;
    }

    function addgroup(user) {
        grp = prompt("Add " + user + " to which group?", "");
        if (grp == null || grp == '') return false;

        $.post('<?php echo ADMIN_URL; ?>', {
            'action': 'addgroup',
            'user': user,
            'grp': grp,
            'csrf_token': csrf_token
        }, function(ret) {
            if (ret != '') alert(ret);
            else window.location.reload();
        });

        return false;
    }

    function delmember(user, grp) {
        if (!confirm("Really remove " + user + " from " + grp + "?")) {
            return false;
        }
        $.post('<?php echo ADMIN_URL; ?>', {
            'action': 'delmember',
            'user': user,
            'grp': grp,
            'csrf_token': csrf_token
        }, function(ret) {
            if (ret != '') alert(ret);
            else window.location.reload();
        });

        return false;
    }

    function delgroup(grp) {
        if (!confirm("Really remove group " + grp + "?")) {
            return false;
        }
        $.post('<?php echo ADMIN_URL; ?>', {
            'action': 'delgroup',
            'grp': grp,
            'csrf_token': csrf_token
        }, function(ret) {
            if (ret != '') alert(ret);
            else window.location.reload();
        });

        return false;
    }

    function delinvite(token) {
        if (confirm("Really delete this invite?")) {
            $.post('<?php echo ADMIN_URL; ?>', {
                'action': 'delinvite',
                'token': token,
                'csrf_token': csrf_token
            }, function(ret) {
                if (ret != '') alert(ret);
                else window.location.reload();
            });
        }

        return false;
    }

    function edit_comment(user) {
        var ret = prompt("Please enter the new comment:", "");
        if (ret === null) {
            return false;
        }
        $.post('<?php echo ADMIN_URL; ?>', {
            'action': 'edit_comment',
            'user': user,
            'comment': ret,
            'csrf_token': csrf_token
        }, function(ret) {
            if (ret != '') alert(ret);
            else window.location.reload();
        });
        return false;
    }

    function init_stage2() {
        $('#users_table tr').hover(function() {
            $(this).addClass('hover');
        }, function() {
            $(this).removeClass('hover');
        });
        $('.want-buttons a').button();
        $('.button').button();
    }

    function select_user(user) {
        $("input[name=user_for_action]").prop('checked', false);
        $("input[name=user_for_action][value=" + $.escapeSelector(user) + "]").prop('checked', true);
    }

    function do_action(fn) {
        var elem = $('input[name=user_for_action]:checked');
        if (elem.length != 1) {
            alert("No user selected");
            return false;
        } else {
            return fn(elem.val());
        }
    }

    $(function() {
        var $tabs = $("#tabs");
        $tabs.tabs({
            create: function(event, ui) {
                // Adjust hashes to not affect URL when clicked
                var widget = $tabs.data("uiTabs");
                widget.panels.each(function(i) {
                    this.id = "uitab_" + this.id;
                    widget.anchors[i].hash = "#" + this.id;
                    $(widget.tabs[i]).attr("aria-controls", this.id);
                });

                // Continue with rest of the init
                init_stage2();
            },
            activate: function(event, ui) {
                window.location.hash = ui.newPanel.attr("id").replace("uitab_", "");
            }
        });
    });
</script>
<body>
<div id="current_user">
    Logged in as:
    <?php global $user_data;
    echo htmlesc($user_data['name']); ?>
    <a href="?page=logout">[Logout]</a>
</div><br clear="all">
<div id="tabs" class="center-wrap">
<ul>
    <li><a href="#users">Users</a></li>
    <li><a href="#groups">Groups</a></li>
    <li><a href="#invites">Invites</a></li>
</ul>

<!-- User Table -->
<div id="users">
    <form id="resetpasswd" style="display: hidden" method="post" action="<?php echo ADMIN_URL; ?>">
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
        <input type="hidden" name="action" value="gen_reset_invite">
        <input type="hidden" name="name">
    </form>
    <p>Admin Group: <?php echo ADMIN_GROUP; ?><br></p>
    <p>Click a group name to remove that user from that group.<br></p><?php
    function action_bar() { ?><div class="want-buttons">
        <a href="#" onclick="javascript: return do_action(deluser);">Delete User</a>
        <a href="#" onclick="javascript: return do_action(setpasswd);">Set Password</a>
        <a href="#" onclick="javascript: return do_action(resetpasswd);">Reset Password</a>
    </div><?php }
    action_bar(); ?>
    <br>
    <table id="users_table" class="want-buttons"><?php
            $query = $db->query("SELECT DISTINCT grp FROM groups ORDER BY grp ASC");
            $grps = array();
            while ($g = $query->fetchArray(SQLITE3_ASSOC)) {
                $grps[] = $g['grp'];
            }
            /* Header row start */
    ?>      <tr>
                <th></th>
                <th>User</th>
                <th>Comment</th>
                <th></th>
<?php           foreach ($grps as $g) {
                echo '<th>'.htmlesc($g).'</th>'; }?>
            </tr>
        <?php  /* Header row end */

        $users = $db->query("SELECT * FROM users ORDER BY name COLLATE NOCASE ASC");
        while ($r = $users->fetchArray(SQLITE3_ASSOC)) {
            $name = htmlesc($r['name']);
            $jsname = jsesc($r['name']);
            $urlname = urlencode($r['name']);
            $onclickselect = "onclick=\"javascript: select_user('$jsname');\""; ?>
            <tr <?php echo $onclickselect; ?>><td>
                <input type="radio" name="user_for_action" value="<?php echo $name; ?>">
            </td>
            <td><?php echo $name; ?></td>
            <td><div class="edit-box" onclick="javascript: return edit_comment('<?php
                echo $jsname; ?>');"></div><?php echo htmlesc($r['comment']); ?></td>
            <td><a href="#" onclick="javascript: return addgroup('<?php
                echo $jsname; ?>')">Add Group</a></td>
            <?php $e_u = SQLite3::escapeString($r['name']);
            foreach ($grps as $grp) {
                $e_g = SQLite3::escapeString($grp);
                $res = $db->querySingle("SELECT user FROM groups WHERE ".
                    "user = '$e_u' AND grp = '$e_g'");
                if (is_null($res) || ($res === false)) {
                    echo '<td></td>';
                } else {
                    ?><td><a href="#" onclick="javascript: return delmember('<?php
                    echo $jsname; ?>', '<?php
                    echo jsesc($grp); ?>')"><?php
                    echo htmlesc($grp); ?></a></td><?php
                }
            } ?></tr>
        <?php } ?>
    </table>
    <br><?php action_bar(); ?>
</div>

<!-- Group Table -->
<div id="groups">
    <p>To remove a user from a group, go to the User tab.</p>
    <table class="want-buttons">
    <tr><th>Group</th><th></th></tr>
    <?php $result = $db->query("SELECT DISTINCT grp FROM groups ORDER BY grp");
    while ($g = $result->fetchArray(SQLITE3_ASSOC)) {
        $grp_ui = htmlesc($g['grp']);
        $grp_js = jsesc($g['grp']);
        echo "<tr><td>$grp_ui</td><td><a href=\"#\" onclick=\"javascript: ".
            "return delgroup('$grp_js');\">Remove</a></td></tr>\n";
    } ?>
    </table>
</div>

<!-- Invites Table -->
<div id="invites">
    <h1>Invites</h1>
    <table>
        <tr>
            <th>Type</th>
            <th>Link</th>
            <th>Expiry</th>
            <th>Username</th>
            <th>Groups</th>
            <th>Comment</th>
            <th></th>
        </tr>
        <?php $invites = $db->query("SELECT * FROM invites ".
            "ORDER BY expiry DESC");
        while ($i = $invites->fetchArray(SQLITE3_ASSOC)) {
            $link = ADMIN_URL."/?token=".$i['token']; ?>
        <tr>
            <td><?php
                switch ($i['type']) {
                    case INVITE_NEW:
                    case INVITE_NEW_EMAIL:
                        echo "New";
                        break;
                    case INVITE_CHANGE_EMAIL:
                        echo "Email Change";
                        break;
                    case INVITE_RESET:
                        echo "Pass Reset";
                        break;
                }
            ?></td>
            <td><a href="<?php echo $link; ?>"><?php echo $link; ?></a></td>
            <td><?php echo $i['expiry']; ?></td>
            <td><?php echo htmlesc($i['name']); ?></td>
            <td><?php echo htmlesc($i['groups']); ?></td>
            <td><?php echo htmlesc($i['comment']); ?></td>
            <td>
                <a class="button" href="#" onclick="javascript: return delinvite('<?php
                echo jsesc($i['token']); ?>')">Remove</a>
            </td>
        </tr>
        <?php } ?>
    </table><br>

    <h1>Create New Invite</h1>
    <?php new_invite_preamble(); ?>
    <form action="<?php echo ADMIN_URL; ?>#invites" method="post">
        <input type="hidden" name="action" value="add_invite_new">

        <p>Username (leave blank to allow user to choose):<br>
        <input type="text" name="name"></p>

        <p>Groups (seperate with colons):<br>
        <input type="text" name="groups"></p>

        <p>Comments:<br>
        <input type="text" name="comment"></p>

        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
        <input type="submit" value="Create Invite" class="button">
    </form>
</div>

</div>
<?php page_tail();
