<?php
# Copyright (C) 2010 Vitaliy Filippov <vitalif at mail.ru>
# http://yourcmc.ru/wiki/BasicAuth_(MediaWiki)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# http://www.gnu.org/copyleft/gpl.html

if (!defined('MEDIAWIKI'))
    die();

$wgExtensionCredits['hook'][] = array(
    'name'          => 'HttpAuth',
    'author'        => 'VitaliyFilippov',
    'svn-date'      => '$LastChangedDate: 2008-06-17 00:54:29 +0400 (Втр, 17 Июн 2008) $',
    'svn-revision'  => '$LastChangedRevision: 36357 $',
    'url'           => 'http://yourcmc.ru/wiki/CharInsertList_(MediaWiki)',
    'description'   => 'Allows using HTTP Basic authorization in your Wiki',
    /* TODO: add digest authentication support */
);
$wgHooks['UserLoadFromSession'][] = 'efHttpAuthUserLoadFromSession';

function efHttpAuthUserLoadFromSession($user_obj, &$result)
{
    global $wgSitename, $wgScriptPath, $wgCookiePrefix, $efBasicAuthUnauthHtml, $wgUser;
    $httpauth = $_GET['httpauth'] || $_POST['httpauth'] || $_COOKIE[$wgCookiePrefix.'httpauth'];
    if ($httpauth &&
        ($n = $_SERVER['PHP_AUTH_USER']) &&
        ($p = $_SERVER['PHP_AUTH_PW']))
    {
        $user = User::newFromName($n);
        if ($user->getId() && $user->checkPassword($p))
        {
            $user_obj->mId = $user->getId();
            $user_obj->loadFromId();
            $result = true;
            wfDebug("Authenticated ".$user_obj->getId()." = User:".$user_obj->getName()." via HTTP\n");
            return false;
        }
    }
    if ($httpauth && !$_COOKIE[$wgCookiePrefix.'UserID'])
    {
        header('HTTP/1.1 401 Unauthorized');
        header('WWW-Authenticate: Basic realm="'.$wgSitename.'"');
        if (!$_COOKIE[$wgCookiePrefix.'httpauth'])
            setcookie($wgCookiePrefix.'httpauth', 1, -1, $wgScriptPath);
        if ($efBasicAuthUnauthHtml !== NULL)
            print $efBasicAuthUnauthHtml;
        else
        {
?><html>
<head><title>401 Unauthorized</title></head>
<body>
<h1>Authentication Required</h1>
<p>This server could not verify that you are authorized to access the document requested. Either you supplied the wrong credentials (e.g., bad password), or your browser doesn't understand how to supply the credentials required.</p>
<hr>
<address>MediaWiki <?=$wgVersion?> at <?=$wgServer.$wgScriptPath?></address>
</body>
</html><?php
            exit;
        }
    }
    return true;
}
