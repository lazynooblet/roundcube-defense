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
            if ((strpos($value, '/') === false) && ($ip == $value)) { return true; }
            if (isIPinCIDR($ip, $value)) { return true; }
        }
        return false;
    }
  /**
    * Check if IP is within stated CIDR address
    *
    * @param string ip address
    * @param string cidr address
    * @return bool
    */
    private function isIPinCIDR($ip, $cidr) {
        list($subnet, $mask) = explode('/', $cidr);
        return ((ip2long($ip) & ~((1 << (32 - $mask)) - 1) ) == ip2long($subnet));
    }
    
  /**
    * Contructor, initialization
    *
    */
    public function init() {
    
        // create parent class
        $this->rc = rcube::get_instance();
        
        // load configuration
        $this->load_config();
        
        // set config variables, set defaults
        $this->whitelist = $this->rc->config->get('defense_whitelist', array('127.0.0.1'));
        $this->blacklist = $this->rc->config->get('defense_blacklist', array());
        $this->fail_max = $this->rc->config->get('defense_fail_max', 5);
        $this->fail_reset = $this->rc->config->get('defense_fail_reset', 600);
        $this->ban_period = $this->rc->config->get('defense_ban_period', 120);
        $this->repeat_multiplier = $this->rc->config->get('defense_repeat_multiplier', 4);
        $this->repeat_reset = $this->rc->config->get('defense_repeat_reset', 86400);
        $this->db_table = $this->rc->config->get('defense_db_table', 'defense');
        $this->db_expire = $this->rc->config->get('defense_db_expire', 40);
        $this->log_pwd = $this->rc->config->get('defense_log_pwd', false);
        
        // set client ip
        $this->ipaddr = rcmail_remote_ip();
        
        // Roundcube event hooks
        $this->add_hook('template_object_loginform', array($this, 'hookLoginForm'));
        $this->add_hook('authenticate', array($this, 'authenticate'));
        $this->add_hook('login_failed', array($this, 'login_failed'));
    }
    
  /**
    * Process whitelist and blacklist
    *
    * @param string Login form HTML
    * @return string Login form HTML
    */
    public function hookLoginForm($content) {
        // If IP is listed in whitelist, return unmodified $content
        if (isIPinArray($this->ipaddr, $this->whitelist)) {
            return $content;
        }
        
        // If IP is listed in blacklist, deny access
        if (isIPinArray($this->ipaddr, $this->blacklist)) {
            header('HTTP/1.1 403 Forbidden');
            die();
        }
    }
}
 
 
 
?>
