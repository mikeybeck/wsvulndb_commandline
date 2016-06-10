<span class="badge-paypal"><a href="https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&amp;hosted_button_id=GHSYAZJGSSRZ8" title="Donate to this project using Paypal"><img src="https://img.shields.io/badge/paypal-donate-yellow.svg" alt="PayPal donate button" /></a></span>

# wsvulndb_commandline
A very rough copy of https://github.com/anantshri/wpvulndb_commandline, modified for Wordshell

Uses [Wordshell](http://wordshell.net/) and [WPVulnDB](http://wpvulndb.com/).  Requires Python 2.7 and [the Requests module](https://github.com/kennethreitz/requests)

# Usage

Useful for anyone using Wordshell who wants a quick check of vulnerable plugins and themes being used on the site.



# CommandLine Options
```
usage: wsvulndb.py [-h] --site SITE [--vulnonly] [--coreonly] [--themesonly] [--pluginsonly] [--debug]


This program is used to run a quick wordpress scan via the wpscan API.

optional arguments:
  -h, --help     show this help message and exit
  --path PATH    Provide URL
  --vulnonly     Only list vulnerable items
  --coreonly     Only check the core version
  --themesonly   Only check the themes
  --pluginsonly  Only check the plugins
  --nosync       Don't sync; use cached plugins/themes only
  --debug        Provides extra information

If none of --coreonly, --themesonly or --pluginsonly is specified, everything will be checked.

Credit (C) Anant Shrivastava http://anantshri.info - original script for wpcli
and Mikey Beck - wordshell compatibility modifications
```

##Examples:
```
python wsvulndb.py --site wpsite

Syncing & checking core
[+]  Wordpress : 442 : No Reported Security Issues
Syncing & checking themes
[+]  Theme : Storefront : No Reported Security Issues
[+]  Theme : Twentyfifteen : No Reported Security Issues
[+]  Theme : Twentyfourteen : No Reported Security Issues
[+]  Theme : Twentysixteen : No Reported Security Issues
Syncing & checking plugins
[+]  Plugin : Akismet : No Reported Security Issues
[+]  Plugin : Clean-up-notifications : No Reported Security Issues
[+]  Plugin : Debug-bar : No Reported Security Issues
[+]  Plugin : Hello : No Reported Security Issues
[+]  Plugin : Nginx-helper : No Reported Security Issues
[-]  Plugin : Simple-ads-manager : 2.9.4.116 : is Vulnerable to Simple Ads Manager <= 2.9.4.116 - SQL Injection Fixed in  Version 2.9.5.118
[+]  Plugin : Woocommerce : No Reported Security Issues
[+]  Plugin : Wordpress-seo-premium : No Reported Security Issues
[+]  Plugin : Wpseo-woocommerce : No Reported Security Issues




python wsvulndb.py --site wpsite --themesonly --debug

Syncing & checking themes
wpsite    storefront                          1.6.1                   Storefront

wpsite    twentyfifteen (i)                   1.4                     Twenty Fifteen

wpsite    twentyfourteen (i)                  1.6                     Twenty Fourteen

wpsite    twentysixteen (i)                   1.1                     Twenty Sixteen

wpsite    storefront                          1.6.1                   Storefront

['\x1b[1mwpsite', '\x1b(B\x1b[m', 'storefront', '\x1b[1m1.6.1', '\x1b(B\x1b[m', 'Storefront']
storefront
1.6.1
storefront 1.6.1
https://wpvulndb.com/api/v1/themes/storefront
(404)
[+]  Theme : Storefront : No Reported Security Issues
wpsite    twentyfifteen                    1.4                     Twenty Fifteen

['\x1b[1mwpsite', '\x1b(B\x1b[m', 'twentyfifteen', '\x1b[1m1.4', '\x1b(B\x1b[m', 'Twenty', 'Fifteen']
twentyfifteen
1.4
twentyfifteen 1.4
https://wpvulndb.com/api/v1/themes/twentyfifteen
[+]  Theme : Twentyfifteen : No Reported Security Issues
wpsite    twentyfourteen                   1.6                     Twenty Fourteen

['\x1b[1mwpsite', '\x1b(B\x1b[m', 'twentyfourteen', '\x1b[1m1.6', '\x1b(B\x1b[m', 'Twenty', 'Fourteen']
twentyfourteen
1.6
twentyfourteen 1.6
https://wpvulndb.com/api/v1/themes/twentyfourteen
(404)
[+]  Theme : Twentyfourteen : No Reported Security Issues
wpsite    twentysixteen                    1.1                     Twenty Sixteen

['\x1b[1mwpsite', '\x1b(B\x1b[m', 'twentysixteen', '\x1b[1m1.1', '\x1b(B\x1b[m', 'Twenty', 'Sixteen']
twentysixteen
1.1
twentysixteen 1.1
https://wpvulndb.com/api/v1/themes/twentysixteen
(404)
[+]  Theme : Twentysixteen : No Reported Security Issues

```


## Basic working
Wordshell collects the names and version numbers of the core, themes and plugins.  This script parses that information, checks it via the WPVulnDB API and reports back.


### Notes
The progress tracker introduced in the most recent update isn't really accurate but is more there to show that *something* is happening.  However, it has a habit of staying on 1% for a looong time, particularly on sites with many plugins.  Sorry about that.




## External Services used and credits:
1. [Wordshell is used to get information from wordpress](http://wordshell.net/)
2. [WPVulnDB API used to get the vulnerability data.](https://wpvulndb.com/)
3. [Anant Shrivastava's wpvulndb_commandline script which this is heavily based on](https://github.com/anantshri/wpvulndb_commandline)