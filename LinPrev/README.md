# linpriv

A question-driven Linux privilege escalation enumeration script that reads like a guided walkthrough instead
of a wall of raw command output.

For every check, the script prints the **question** a pentester is trying
to answer and the **answer** only — the command behind it runs silently.

```
Q: Are there SUID binaries I can abuse?
[!] Non-standard SUID binaries (check each against GTFOBins):
    /usr/local/bin/weird_tool
```

## Color coding

- 🔴 **Red `[!]`** — potential vulnerability, investigate first (writable
  `/etc/passwd`, passwordless sudo, non-standard SUID binaries, writable
  cron/systemd files, PATH hijacks, extra UID 0 accounts, etc.)
- 🟡 **Yellow `[?]`** — worth a manual look, not confirmed dangerous
  (SGID binaries, world-writable files, old kernel, backup files, `.git`
  dirs, etc.)
- Plain text — informational only

## Structure

**1. Your Current Position**
Who am I, what UID/groups do I have, what do I already have access to via
sudo/capabilities?

**2. Understand the Machine**
OS, kernel, architecture, installed applications, running services, network
interfaces, listening ports, VM vs container, and existing users.

**3. Privilege Boundaries**
SUID/SGID, Linux capabilities, sudo rights, writable files/directories,
cron, services, PATH hijacking, credentials, sensitive information, and a
pointer to check kernel/software CVEs manually.

## Usage

```bash
chmod +x linpriv.sh
./linpriv.sh                 # print to screen (colored)
./linpriv.sh | tee out.txt   # save output too (colors preserved in most terminals)
```

Read-only. No system modification, no exploitation — enumeration only.

Every red/yellow finding should still be manually confirmed — in particular,
cross-reference any SUID/sudo findings against
[GTFOBins](https://gtfobins.github.io) before acting on them.

## Roadmap

- [ ] Optional `--no-color` flag for piping to files/CI
- [ ] Optional JSON output mode
- [ ] Skip slow `find /` scans via a config/flag on large filesystems
