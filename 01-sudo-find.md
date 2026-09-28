###Finding: World-Writable Cron Job (Privilege Escalation)

**Discovery:**
LinEnum flagged /etc/cron_privesc_test.sh as world-writable (-rwxrwxrwx),
owned by root, executed every minute via /etc/crontab as root.

**Exploitation:**
Appended a payload to the script:
  cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash
Cron executed the modified script as root within 60 seconds, creating
a SUID-root copy of bash.

**Result:**
Executed /tmp/rootbash -p → euid=0(root)

**Root cause:**
Improper file permissions (777) on a script executed by a privileged
cron job. Any local user can inject arbitrary commands that execute
with root privileges.

**Remediation:**
chmod 700 on the script; restrict write access to root only.
