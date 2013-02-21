<?php
/*
 *  This file is part of the Roundcube plugin: roundcube-defense.
 *
 *  @author Steve Allison <roundcube-defense@nooblet.org>
 *
 *  roundcube-defense is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  roundcube-defense is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with roundcube-defense.  If not, see <http://www.gnu.org/licenses/>.
 */
 
class defense extends rcube_plugin {
    
    // Roundcube parent class
    private $rc;
    
    // Config variables
    private $whitelist, $blacklist, $fail_max,
        $fail_reset, $ban_period, $repeat_multiplier,
        $repeat_reset, $db_table, $db_expire, $log_pwd;
    
    // Remote client IP address
    private $ipaddr;
    
    // Logfile
    private $logfile = 'defense.log';
    private $debugEnabled;
    
  /**
    * Output text to log file: $this->logfile
    *
    * @param string text for log
    */
    private function debug($string) {
        write_log($this->logfile, $this->ipaddr . " # " . $string);
    }
  /**
    * Check if IP is matched against all IPs in array,
    * including CIDR matches
    *
    * @param string ip address
    * @param array ip/cidr addresses to match against
    * @return bool
    */
    private function isIPinArray($ip, $array) {
        foreach ($array as $value) {
            // If no slash '/' then its not a CIDR address and we can just string match
            if ((strpos($value, '/') === false) && (strcmp($ip, $value) == 0)) { return true; }
            if (($this->isIPv6($ip)) && (!$this->isIPv6($value))) { return false; }
            if (($this->isIPv4($value)) && (!$this->isIPv4($ip))) { return false; }
            if (($this->isIPv4($ip) && ($this->isIPv4inCIDR($ip, $value)))) { return true; }
            if (($this->isIPv6($ip) && ($this->isIPv6inCIDR($ip, $value)))) { return true; }
        }
        return false;
    }
  /**
    * Check if IPv4 is within stated CIDR address
    *
    * @param string ip address
    * @param string cidr address
    * @return bool
    */
    private function isIPv4inCIDR($ip, $cidr) {
        list($subnet, $mask) = explode('/', $cidr);
        return ((ip2long($ip) & ~((1 << (32 - $mask)) - 1) ) == ip2long($subnet));
    }
  /**
    * Convert IPv6 mask to bytearray
    *
    * @param string subnet mask
    * @return string byte array
    */
    private function IPv6MaskToByteArray($subnetMask) {
        $addr = str_repeat("f", $subnetMask / 4);
        switch ($subnetMask % 4) {
            case 0:
                break;
            case 1:
                $addr .= "8";
                break;
            case 2:
                $addr .= "c";
                break;
            case 3:
                $addr .= "e";
                break;
        }
        $addr = str_pad($addr, 32, '0');
        $addr = pack("H*" , $addr);
        return $addr;
    }
  /**
    * Check if IPv6 is within stated CIDR address
    *
    * @param string subnet mask
    * @return string byte array
    */
    private function isIPv6inCIDR($ip, $cidr) {
        list($subnet, $mask) = explode('/', $cidr);
        $binMask = $this->IPv6MaskToByteArray($mask);
        return ($ip & $binMask) == $subnet;
    }
  /**
    * Check string if it is IPv6
    *
    * @param string ip address
    * @return bool
    */
    private function isIPv6($ip) {
        return (((!preg_match('/^[\.\/:0-9a-f]+$/', strtolower($ip))) || (substr_count($ip, ':') < 2)) ? true : false);
    }
  /**
    * Check string if it is IPv6
    *
    * @param string ip address
    * @return bool
    */
    private function isIPv4($ip) {
        return ((preg_match('/^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?$/', $ip)) ? true : false);
    }
  /**
    * Write to log stating database error
    *
    */
    private function dbError() {
        // I can't seem to try/catch database entries so I have no details regarding error
        $string = "Error communicating with database.";
        $this->debug($string);
        write_log('error', 'plugin::defense: ' . $string);
    }
  /**
    * Constructor, initialization
    *
    */
    public function init() {
    
        // create parent class
        $this->rc = rcube::get_instance();
        
        // load configuration
        $this->load_config();
        
        // set config variables, set defaults
        $this->db_table = $this->rc->config->get('defense_db_table', 'defense');
        
        $this->fail_max = $this->rc->config->get('defense_fail_max', 5);
        $this->fail_reset = $this->rc->config->get('defense_fail_reset', 600);
        $this->ban_period = $this->rc->config->get('defense_ban_period', 120);
        $this->ban_httpstatus = $this->rc->config->get('defense_ban_httpstatus', false);
        $this->repeat_multiplier = $this->rc->config->get('defense_repeat_multiplier', 4);
        $this->repeat_reset = $this->rc->config->get('defense_repeat_reset', 86400);

        $this->db_expire = $this->rc->config->get('defense_db_expire', 40);
        $this->log_pwd = $this->rc->config->get('defense_log_pwd', false);
        
        $this->debug_enabled = $this->rc->config->get('defense_debug_enabled', false);
        
        // set client ip
        $this->ipaddr = rcmail_remote_ip();
        
        // Roundcube event hooks
        $this->add_hook('template_object_loginform', array($this, 'hookLoginForm'));
        $this->add_hook('authenticate', array($this, 'hookAuthenticate'));
        $this->add_hook('login_failed', array($this, 'hookLoginFailed'));
        
        $this->debug("init() complete");
    }
    
  /**
    * Hooked function: login_form($content)
    * Process whitelist and blacklist
    *
    * @param string Login form HTML
    * @return string Login form HTML
    */
    public function hookLoginForm($content) {
    
        // set config variables, set defaults
        $this->whitelist = $this->rc->config->get('defense_whitelist', array('127.0.0.1'));
        $this->blacklist = $this->rc->config->get('defense_blacklist', array());
    
        // If IP is listed in whitelist, return unmodified $content
        if ($this->isIPinArray($this->ipaddr, $this->whitelist)) {
            $this->debug("whitelisted");
            return $content;
        }
        
        // If IP is listed in blacklist, deny access
        if ($this->isIPinArray($this->ipaddr, $this->blacklist)) {
            $this->debug("blacklisted");
            header('HTTP/1.1 403 Forbidden');
            die();
        }
        $this->debug("send login form");
    }
    
  /**
    * Hooked function: authenticate($host, $user, $cookiecheck, $valid)
    * Login attempt intercepted if IP is banned.
    *
    * @param var (untouched)
    * @return var (untouched)
    */
    public function hookAuthenticate($args) {
        return $args;
    }
    
  /**
    * Hooked function: login_failed($host, $user, $code)
    * Log event to database
    *
    * @param array args [ code, host, user, abort ]
    * @param int code
    * 
    */
    public function hookLoginFailed($args) {
    
        // Log failed login attempt
        $data = array('user' => $args['user']);
        $query = sprintf("INSERT INTO %s (epoch, type, ipaddr, data) VALUES (%d, %d, '%s', '%s')", $this->db_table, time(), 0, $this->ipaddr, serialize($data));
        $result = $this->rc->db->query($query);
        if (!$result) { $this->dbError($query); return; }
        $this->debug($query . " [" . $result->rowCount() . "]");
        // Get number of failed attempts in <fail_reset> seconds
        $rTime = (time() - $this->fail_reset); // How far to look back for failed logins
        $query = sprintf("SELECT count(*) AS n FROM %s WHERE ipaddr = '%s' AND epoch >= %d", $this->db_table, $this->ipaddr, $rTime);
        $result = $this->rc->db->query($query);
        if (!$result) { $this->dbError($query); return; }
        $this->debug($query . " [" . $result->rowCount() . "]");
        $row = $result->fetch();
        if (!$row) { $this->debug("Warning, SQL result empty: $query"); return; } // No rows? Strange, abort.
        $this->debug("Found " . $row['n'] . " failed attempts");
        // Check if we have too many failures
        if ($row['n'] >= $this->fail_max) {
            $this->debug("IP banned.");
            // This IP is now banned
            $repeat = 0;
            
            // Check if its been banned before
            $query = sprintf("SELECT epoch, data FROM %s WHERE ipaddr = '%s' AND type = %d ORDER BY id DESC LIMIT 1", $this->db_table, $this->ipaddr, 1);
            $result = $this->rc->db->query($query);
            if (!$result) { $this->dbError($query); return; }
            $this->debug($query . " [" . $result->rowCount() . "]");
            if ($result->rowCount() > 0) {
                // IP has been banned before, check if its a recent repeat offender
                $row = $result->fetch();
                $data = unserialize($row['data']);
                $this->debug("IP previous ban data: " . $row['data']);
                // Classed as a repeate offender if IP is banned again after the previous ban duration
                // multiplied by <repeat_multiplier>
                if (time() <= (($data['duration'] * $this->repeat_multiplier) + $row['epoch'])) {
                        // Repeat offender, increase repeat
                        $repeat = $data['repeat'] +1;
                        $this->debug("Repeat offender. Repeat set to " . $repeat);
                }
            }
            $duration = ($this->ban_period * ($repeat > 0 ? pow($this->repeat_multiplier,$repeat) : 1));
            $data = array(
                'duration' => $duration, // Ban duration based on history
                'repeat' => $repeat
              );
            $query = sprintf("INSERT INTO %s (epoch, type, ipaddr, data) VALUES (%d, %d, '%s', '%s')", $this->db_table, time(), 1, $this->ipaddr, serialize($data));
            $result = $this->rc->db->query($query, time(), 1, $this->ipaddr, serialize($data));
            if (!$result) { $this->dbError($query); return; }
            $this->debug($query . " [" . $result->rowCount() . "]");
            $this->debug("Ban set to: " . $duration . "s");
            return;
        }


        
    }
    
    
  /**
    * Return true if logs indicate given IP is banned
    *
    * @param string ip
    * @return bool
    * 
    */
    public function isBanned($ip) {
        $query = "SELECT count(id) FROM " . $this->db_table . " WHERE ip = ? AND ";
    }
}
 
 
 
?>
