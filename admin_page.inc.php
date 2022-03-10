<?php function admin_page() {
    global $db;
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
<div id="tabs" class="center-wrap">
<ul>
    <li><a href="#users">Users</a></li>
    <li><a href="#groups">Groups</a></li>
    <li><a href="#invites">Invites</a></li>
</ul>

<!-- User Table -->
<div id="users">
    <p>Admin Group: <?php echo ADMIN_GROUP; ?><br></p>
    <p>Click a group name to remove that user from that group.<br></p>
    <table id="users_table"><?php
            $query = $db->query("SELECT DISTINCT grp FROM groups ORDER BY grp ASC");
            $grps = array();
            while ($g = $query->fetchArray(SQLITE3_ASSOC)) {
                $grps[] = $g['grp'];
            }
            /* Header row start */
    ?>      <tr><th>User</th><th>Comment</th><th></th><th></th><?php
            foreach ($grps as $g) {
                echo '<th>'.htmlesc($g).'</th>';
            }?></tr>
        <?php  /* Header row end */
        
        $users = $db->query("SELECT * FROM users ORDER BY name COLLATE NOCASE ASC");
        while ($r = $users->fetchArray(SQLITE3_ASSOC)) { 
            $name = htmlesc($r['name']);
            $jsname = jsesc($r['name']); ?>
            <tr><td><?php echo $name; ?></td>
            <td><div class="edit-box" onclick="javascript: return edit_comment('<?php
                echo $jsname; ?>');"></div><?php echo htmlesc($r['comment']); ?></td>
            <td><a href="#" onclick="javascript: return deluser('<?php
                echo $jsname; ?>')">Delete</a></td>
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
</div>

<!-- Group Table -->
<div id="groups">
    <p>To remove a user from a group, go to the User tab.</p>
    <table>
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
            <th>Link</th>
            <th>Expiry</th>
            <th>Groups</th>
            <th>Comment</th>
            <th></th>
        </tr>
        <?php $invites = $db->query("SELECT * FROM invites ".
            "ORDER BY expiry DESC");
        while ($i = $invites->fetchArray(SQLITE3_ASSOC)) { 
            $link = ADMIN_URL."?token=".$i['token']; ?>
        <tr>
            <td><a href="<?php echo $link; ?>"><?php echo $link; ?></a></td>
            <td><?php echo $i['expiry']; ?></td>
            <td><?php echo htmlesc($i['groups']); ?></td>
            <td><?php echo htmlesc($i['comment']); ?></td>
            <td>
                <a href="#" onclick="javascript: return delinvite('<?php
                echo jsesc($i['token']); ?>')">Remove</a>
            </td>
        </tr>
        <?php } ?>
    </table><br>

    <h1>Create New Invite</h1>
    <?php new_invite_preamble(); ?>
    <form action="<?php echo ADMIN_URL; ?>#invites" method="post">
        <input type="hidden" name="action" value="newinvite">

        Groups (seperate with colons):<br>
        <input type="text" name="groups"><br>
        Comments:<br>
        <input type="text" name="comment"><br>
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
        <input type="submit" value="Create Invite">
    </form>
</div>

</div>
<?php 
    page_tail();
} // function admin_page()
