<?php
/**
 * Copyright (C) 2010-2013 Vitaliy Filippov <vitalif at mail.ru>
 * http://wiki.4intra.net/HttpAuth
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * http://www.gnu.org/copyleft/gpl.html
 */

/**
 * This extension allows to use HTTP Basic authentication in your Wiki.
 * Just add &httpauth=1 parameter to any URL and it will request HTTP auth.
 *
 * WARNING: HTTP Basic authentication is unsecure because transmits user
 * passwords in cleartext. Use it ONLY either in trusted networks or
 * over SSL (https://).
 */

if (!defined('MEDIAWIKI'))
{
    die('Not an entry point');
}

$wgExtensionCredits['hook'][] = array(
    'name'          => 'HttpAuth',
    'author'        => 'VitaliyFilippov',
    'version'       => '2013-09-26',
    'url'           => 'http://wiki.4intra.net/HttpAuth',
    'description'   => 'Allows using HTTP Basic authentication in your Wiki',
    /* TODO: add digest authentication support */
);
$wgHooks['UserLoadFromSession'][] = 'efHttpAuthUserLoadFromSession';

function efHttpAuthUserLoadFromSession($user_obj, &$result)
{
    global $wgSitename, $wgScriptPath, $wgCookiePrefix, $efBasicAuthUnauthHtml, $wgUser;
    $httpauth = !empty($_GET['httpauth']) || !empty($_POST['httpauth']);
    if ($httpauth)
    {
        $n = isset($_SERVER['PHP_AUTH_USER']) ? $_SERVER['PHP_AUTH_USER'] : NULL;
        $p = isset($_SERVER['PHP_AUTH_PW']) ? $_SERVER['PHP_AUTH_PW'] : NULL;
        if ($n && $p)
        {
            $throttleCount = LoginForm::incLoginThrottle($n);
            if ($throttleCount === true)
            {
                wfDebug("HTTP Basic login throttled for $n\n");
            }
            else
            {
                $user = User::newFromName($n);
                if ($user->getId() && $user->checkPassword($p))
                {
                    $user_obj->mId = $user->getId();
                    $user_obj->loadFromId();
                    $result = true;
                    if ($throttleCount)
                    {
                        LoginForm::clearLoginThrottle($n);
                    }
                    wfDebug("Authenticated ".$user_obj->getId()." = User:".$user_obj->getName()." via HTTP\n");
                    return false;
                }
            }
        }
        header('HTTP/1.1 401 Unauthorized');
        header('WWW-Authenticate: Basic realm="'.$wgSitename.'"');
        if ($efBasicAuthUnauthHtml !== NULL)
        {
            print $efBasicAuthUnauthHtml;
        }
        else
        {
?><html>
<head><title>401 Unauthorized</title></head>
<body>
<h1>Authentication Required</h1>
<p>This server could not verify that you are authorized to access the document requested.
Either you supplied the wrong credentials (e.g., bad password), or your browser
doesn't understand how to supply the credentials required.</p>
<hr>
<address>MediaWiki <?=$wgVersion?> at <?=$wgServer.$wgScriptPath?></address>
</body>
</html><?php
                exit;
        }
    }
    return true;
}
