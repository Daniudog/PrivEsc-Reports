### Finding: Passwordless Sudo on `find` (Privilege Escalation via GTFOBins)

**Discovery:**
`sudo -l` revealed the following entry for user lowpriv:

    (ALL) NOPASSWD: /usr/bin/find

LinEnum flagged this explicitly under "Possible sudo pwnage."

**Exploitation:**
`find` supports the `-exec` flag, allowing arbitrary commands to run
against matched files. Since `find` was invocable via sudo with no
password, any command passed to `-exec` inherits root's privileges.

Command used:
    sudo find . -exec /bin/sh \; -quit

**Result:**
Spawned an interactive root shell.
    id → uid=0(root) gid=0(root)

**Root cause:**
Overly permissive sudoers rule granting passwordless execution of a
general-purpose binary with built-in command-execution functionality.
Not a vulnerability in `find` itself — a misconfiguration in scope of
sudo access granted to the user.

**Remediation:**
Remove `find` from the user's sudoers entry, or restrict it with
specific flags/paths if sudo access to `find` is operationally
required (e.g. via a wrapper script, not a bare binary).

**Reference:**
https://gtfobins.github.io/gtfobins/find/#sudo
