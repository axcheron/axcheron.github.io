---
title: "Installation"
permalink: /writeups/mbe/installation/
excerpt: "How to install the MBE Lab (Warzone)."
---

---
[Modern Binary Exploitation (MBE)](https://github.com/RPISEC/MBE) is a free course developed and used by [RPISEC](http://rpis.ec) to teach Modern Binary Exploitation at [Rensselaer Polytechnic Institute](http://rpi.edu). It covers basic x86 reverse engineering, vulnerability analysis, and classical forms of Linux-based userland binary exploitation. It also focus on protections found on modern systems and the techniques used to defeat them. This course come with a large number of labs that I'll explain in this write-up.

This procedure is based on the [official documentation](https://github.com/RPISEC/MBE) of the MBE repository. I suggest you to read it if you need more details.

You can download the [slides](https://github.com/RPISEC/MBE/releases/download/v1.1_release/MBE_lectures.tar.gz) or clone the repository with the following command: 

`git clone https://github.com/RPISEC/MBE`

## Lab Breakdown

The challenges are based on the lectures present in the Github [repository](https://github.com/RPISEC/MBE). If you don't have the necessary knowledge to solve the labs, I advise you read them before starting.

Write-up | Topic | Corresponding Lectures
-------- | ----- | ----------------------
[01](/writeups/mbe/lab1c/) | Reverse Engineering | 01-03
[02](/writeups/mbe/lab2c/) | Memory Corruption | 04
[03](/writeups/mbe/lab3c/) | Shellcoding | 05
[04](/writeups/mbe/lab4c/) | Format Strings | 06
[05](/writeups/mbe/lab5c/) | DEP and ROP | 07
[06](/writeups/mbe/lab6c/) | ASLR | 09
[07](/writeups/mbe/lab7c/) | Heap | 10
[08](/writeups/mbe/lab8c/) | Misc and Stack Cookies | 11
[09](/writeups/mbe/lab9c/) | C++ | 12
[10](/writeups/mbe/lab10c/) | Linux Kernel | 13
[P1](/writeups/mbe/project1/) | Project 1 | 01-06
[P2](/writeups/mbe/project2/) | Project 2 | 01-12

## Virtual Machine Setup

The Warzone is a custom wargame that was built from the ground up for this course. It provided a complete and consistent learning platform for us to release the labs and projects to the students. The wargame was built ontop of a vanilla Ubuntu 14.04 32-bit server install, and is modeled after existing local privilege escalation themed wargames.
{: .text-justify}

You can download the VMDK (disk image) of the Warzone that is already setup [here](https://github.com/RPISEC/MBE/releases/download/v1.1_release/MBE_VM.vmdk.gz). To install the VM, extract the VMDK and create a new custom virtual machine in VMWare.

![image-center](/images/mbe/mbe_custom_vm.png){: .align-center}{:width="600px"}

Then, select **Ubuntu** as operating system.

![image-center](/images/mbe/mbe_os.png){: .align-center}{:width="600px"}

Finally, select the extracted **VMDK** as disk image.

![image-center](/images/mbe/mbe_disk.png){: .align-center}{:width="600px"}

As resources, you can stick to the following specifications:
* 1 CPU/Core
* 512MB RAM
* NAT Networking

## How to use the Warzone

Once the Virtual Machine is created, you can get the IP address by login as **gameadmin** (`gameadmin:gameadmin`) and type the command `ip addr`.

![image-center](/images/mbe/mbe_ip.png){: .align-center}{:width="600px"}

Then, you can SSH into the first challenge by using the credentials `lab1C:lab01start`. This pattern is the same for the following challenges (eg. `lab2C:lab02start`)

The Warzone is structured like any local privilege escalation wargame. You must exploit a challenge to escalate your privileges and gain access to another user (level). Once you exploit a level and escalate to the next user (confirm with `whoami`) and read their password from their home dir `/home/$USER/.pass`

**Note:** The easiest level is **labXC**, then **labXB** and, finally **labXA**.

The levels (challenges) are located in `/levels`. If you need to write scripts/exploits, `/tmp` is writable.

## Licensing
This course was explicitly designed for academic & educational use only. Please keep this in mind when sharing and distributing our course material. The specific licenses involved can be found below.

The lectures are covered by the Creative Commons Attribution-NonCommercial 4.0 International license [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/legalcode).

The code in is covered by the BSD 2-Clause license. You can view this license in [LICENSE](https://github.com/RPISEC/MBE/blob/master/LICENSE).