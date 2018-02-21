---
title: "MBE - Getting Started"
permalink: /writeups/mbe/installation/
excerpt: "How to install the MBE Lab (Warzone)."
---

---
[Modern Binary Exploitation (MBE)](https://github.com/RPISEC/MBE) is a free course developed and used by [RPISEC](http://rpis.ec) to teach Modern Binary Exploitation at [Rensselaer Polytechnic Institute](http://rpi.edu). It covers basic x86 reverse engineering, vulnerability analysis, and classical forms of Linux-based userland binary exploitation. It also focus on protections found on modern systems and the techniques used to defeat them. This course come with a large number of labs that I'll explain in this write-up.

This procedure is based on the [official documentation](https://github.com/RPISEC/MBE) of the MBE repository. I suggest you to read it if you need more details.

## Lab Breakdown

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

## How to use the Warzone

TBD

## Licensing
This course was explicitly designed for academic & educational use only. Please keep this in mind when sharing and distributing our course material. The specific licenses involved can be found below.

**Lecture Slides**

The lectures are covered by the Creative Commons Attribution-NonCommercial 4.0 International license [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/legalcode).
<p align="center">
<a href="https://creativecommons.org/licenses/by-nc/4.0/"><img src="/resources/images/cc-by-nc.png" alt="CC BY-NC 4.0"/></a>
</p>

**Code**

The code in is covered by the BSD 2-Clause license. You can view this license in [LICENSE](https://github.com/RPISEC/MBE/blob/master/LICENSE).