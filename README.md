Roundcube Defense
===================
Protects the Roundcube login page from bruteforce login attempts.

Original concept from the roundcube "security" plugin by Lazlo Westerhof.
Wanting to fix the shortfalls of that plugin led me to a rewrite.

FEATURES
-------------------
- Bruteforce protection
    - Ban based on X failed-logins per Y seconds (default: 5 fails / 60m)
    - Ban for X seconds. (default: 120)
    - Increasing ban duration by power of 4 for repeated offenders (2m, 8m, 32m, 8h32m, etc)
- Whitelist
- Blacklist
- Failed logins log
    - Only accessible by administrator

INSTALLATION
--------------------
1. Change to plugins/ directory
2. Clone git repository with: git clone https://github.com/stalks/roundcube-defense.git
3. Add 'defense' table to SQL structure by using schema in plugins/roundcube-defense/SQL/
4. Edit config file 'config.inc.php.dist' and save as 'config.inc.php'
4. Add 'roundcube-defense' to plugins array at config/main.inc.php

ISSUES
--------------------
Create an issue ticket at https://github.com/stalks/roundcube-defense/issues

===================
Created by Steve Allison - https://www.nooblet.org/