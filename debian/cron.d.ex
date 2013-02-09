#
# Regular cron jobs for the kwick-sdig package
#
0 4	* * *	root	[ -x /usr/bin/kwick-sdig_maintenance ] && /usr/bin/kwick-sdig_maintenance
