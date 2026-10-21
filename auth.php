<?php
/**
 * Plaintext authentication backend for PLD Linux
 *
 * @license    GPL 2 (http://www.gnu.org/licenses/gpl.html)
 * @author     Elan Ruusamäe <glen@pld-linux.org>
 */

// PLD separates local configuration from the packaged defaults in DOKU_CONF.
define('AUTH_PLDDIR', rtrim(defined('DOKU_LOCAL') ? DOKU_LOCAL : DOKU_CONF, '/').'/pld');

// copied from CVSROOT/passwd
define('AUTH_USERFILE', AUTH_PLDDIR.'/passwd');
// cvs up CVSROOT/users
define('AUTH_INFOFILE', AUTH_PLDDIR.'/users');
// manually modified
define('AUTH_GROUPFILE', AUTH_PLDDIR.'/groups');

class auth_plugin_authpld extends auth_plugin_authplain {
    /**
     * Constructor
     *
     * Carry out sanity checks to ensure the object is
     * able to operate. Set capabilities.
     */
    public function __construct() {
        // authplain's constructor enables writes to its own users.auth.php file.

        if (!@is_readable(AUTH_USERFILE)){
            $this->success = false;
        }else{
            $this->cando['getUsers']     = true;
            $this->cando['getUserCount'] = true;
            $this->cando['getGroups']    = true;
        }
    }

    /**
     * Load all user data
     *
     * loads the user file into a datastructure
     *
     */
    protected function loadUserData(){
        $this->users = array();

        if(!@file_exists(AUTH_USERFILE)) return;

        $lines = file(AUTH_USERFILE);
        foreach($lines as $line){
            $line = preg_replace('/#.*$/','',$line); //ignore comments
            $line = trim($line);
            if(empty($line)) continue;

            $row = explode(":",$line,6);
            if (count($row) < 3 || $row[0] === '') continue;
            // CVS records may omit the metadata, name and account status.
            $row = array_pad($row, 6, '');

            // skip builders
            if (preg_match('/^builder/', $row[0])) {
                continue;
            }

            // skip if sixth column is set and is not 'Enable'
            if ($row[5] !== '' && $row[5] !== 'Enable') {
                continue;
            }

            // translate group 'cvs' to 'user'
            $groups = str_replace("cvs", "user", $row[2]);
            $groups = array_unique(array_filter(explode(".", $groups)));

            $this->users[$row[0]]['pass'] = $row[1];
            $this->users[$row[0]]['name'] = urldecode($row[4]);
            $this->users[$row[0]]['mail'] = $row[0].'@pld-linux.org';
            $this->users[$row[0]]['grps'] = $groups;
        }

        $this->_loadGroupFile();
        $this->_loadInfoFile();
    }

    /**
     * load additional groups for users
     */
    private function _loadGroupFile() {
      if(!@file_exists(AUTH_GROUPFILE)) return;

      $lines = file(AUTH_GROUPFILE);
      foreach($lines as $line){
        $line = preg_replace('/#.*$/','',$line); //ignore comments
        $line = trim($line);
        if (empty($line)) continue;

        $row = explode(":", $line, 2);
        if (count($row) < 2) continue;
        $user = array_shift($row);
        $groups = explode(",",$row[0]);

        if (!isset($this->users[$user])) {
            continue;
        }

        $groups = array_merge($this->users[$user]['grps'], $groups);

        // remove users with @readonly group from 'users'
        if (in_array('readonly', $groups, true)) {
            $groups = array_filter($groups, function($v) { return $v != 'user'; });
        }

        $this->users[$user]['grps'] = $groups;
      }
    }

   /**
    * load users file, name and optional jid
    */
   private function _loadInfoFile() {
      if(!@file_exists(AUTH_INFOFILE)) return;

      $lines = file(AUTH_INFOFILE);
      foreach($lines as $line){
        $line = preg_replace('/#.*$/','',$line); //ignore comments
        $line = trim($line);
        if (empty($line)) continue;

        $row = explode(":", $line, 4);
        if (count($row) < 3) continue;
        list($user, $mail, $name, $jid) = array_pad($row, 4, '');

        if (!isset($this->users[$user])) {
            continue;
        }
        if (!empty($name)) {
            $this->users[$user]['name'] = $name;
        }
        if (!empty($jid)) {
            $this->users[$user]['jid'] = $jid;
        }
      }
    }

    function useSessionCache($user){
        // our backend is fast (all files are local). do not cache
        return false;
    }
}
//Setup VIM: ex: et ts=2 :
