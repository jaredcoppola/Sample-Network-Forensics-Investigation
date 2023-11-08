# Sample-Network-Forensics-Investigation
Company Name and Pcap files were created for the sole purpose of practicing network forensics and should not be taken as legitimate data.

(I wish I still had the Pcap files to upload, unfortunatly I lost the files when I wiped my computer earlier this year.)

<h1>Sample Network Forensics Investigation</h1>

## Description
Project consists of analysis of sample pcap files that walks the user through the thought process and analysis of a ficticious company, FABCO. The project is written in the format of a real network forensic report.


## Tools and Programs Used

- Wireshark
- NetworkMiner
- VirusTotal
- hexed.it

## Environments Used

- Kali Linux VM (VMWare Workstation Pro)

## Network Forensic Report:


## 1. Executive Summary

It is difficult to identify one root cause of the network intrusion, and there is information lacking in the evidence gathered to definitively say what the malware did exactly and who was behind the attack. However, with the information that was gathered, the best lead to the intrusion of FABCO lies in the user-agent Medunja Solodunnia. The attack against FABCO is thought to have been a component of a Google Docs malware attack that also targets Windows, Android, and MacOS. The system might have been infected via one of three major approaches. The first one involves a link or document that was delivered to a worker, who then clicked on it and caused the malware to download. The second possibility is that it may have been discovered by chance while conducting a web search. Finally, an employee may have clicked a link to the malicious document. The link then generates several redirections dependent on different variables, and somewhere along all those redirects, a file that could contain malware is installed.

Within the many redirects that were recorded, there were many images that were uncovered within the PCAPs using NetworkMiner. However, it is difficult to determine which one could have contained the download of the malware. Using NetworkMiner, several pictures were found in the PCAPs of the numerous redirects that were recorded. It is challenging to pinpoint which one may have enabled the virus download.

Based on the information provided, we can determine that the malware will create self-deleting executables and DLL files to accomplish the goal of evading detection and infecting the system with as many different executables it can communicate with, as well as perform ARP spoofing to avoid detection. The virus begins by scanning the network for additional computers after being placed on the Reception PC, which was the site of infection. It was able to locate the accounting PC during that scan. The virus then made multiple connection attempts to the Accounting PC before being successful. Once it was linked to the Accounting PC, it began scanning for documents that may contain compromised sensitive information. Most of the data gathered in this case concerned workers, including salary and registration.

The presence of a botnet in this attack is the most likely scenario, however, it is unclear exactly what function it serves. It may be a host for the virus that is downloaded to the system over the chain of hops, or it might even be a host for every hop or redirect that occurs when the link is clicked. Although the actual impact of the botnet on this specific assault is now unknown, references to the User Agent Medunja Solodunnia are widely available. Because these documents may have contained sensitive information including pay, social security numbers, credit card details, etc., many of them may have been hacked. Customer information was not taken, as far as the inquiry can determine, but it is still premature to rule anything out. The information obtained throughout the investigation leads to the conclusion that there is cause for worry and that acting and further investigation is recommended.

  
## 2. Objectives

The objective of the investigation is to analyze the network for indications of compromise and run a thorough investigation of the network to find key IP addresses and files indicated by the nature of the compromise. Information provided by FABCO; Inc. indicated that the initial point of compromise on the network occurred before the PCAPs were recorded. The forensics report will include the following:

- Provide a list/map of relevant devices that are identifiable in the provided packet captures along with any information about their operating system, location, and function.
- Identify, if possible, a likely starting point and initial point of compromise in the network, along with as much detail as possible.
- Specify relevant devices (internal or external) that connected to or communicated with the victim device(s).
- Find any data/files that were copied off company devices and provide the contents of those files.
- Evidence that company devices have been infected with malware, and providing forensic details on the malware including type, name, and behavior.
- Determine if the Firewall and Proxy settings were properly configured.
- Determine if any attack/compromise/activity is/was STILL occurring as of the most recent packet captures.
- Provide the forensic investigator’s recommendations on what measures could be taken to better configure or secure our computer systems and network to prevent such events from occurring in the future.


## 3. Computer Evidence Analyzed

### 3.1. Network Capture File Details

The extracted PCAP file captures have the following file properties and details. The evidence for these details was extracted by Wireshark ver4.0.3.

**PCAP1.pcap**
- SHA1 Hash: 37574d1ab8ec2bbb87fc03d58d1773995ef651cd
- SHA256 Hash: 716fc7b0f147a9b747e0e48c321d326506b6ae6818104865c76629499dc7d116
- MD5 Hash: 55e0880b9e8588fc90b7def701aa7199
- Capture Length: 541 MB
- Packet Size Limit: 262,144 bytes
- First Packet: 2021-03-26 10:42:30 HRS
- Last Packet: 2021-03-26 12:12:40 HRS
- Elapsed Time: 01:30:10 (1 hour, 30 minutes, 10 seconds)
- Total Packets: 795,851
- Average Packets/sec: 147.1
- Average Packet Size: 665 bytes
- Average Bytes/sec: 97 k

**PCAP2.pcap**
- SHA1 Hash: 5c409bfc8f235b0a70ff33688beacc3c15181c0c
- SHA256 Hash: 4e739c18e177bda8763c29e317b32dfd43ff33c90f5eb47edec56374b91a9941
- MD5 Hash: ca49e538301e8c5b350ec441bd8c72c9
- Capture Length: 240 MB
- Packet Size Limit: 262,144 bytes
- First Packet: 2021-03-26 12:13:26 HRS
- Last Packet: 2021-03-26 12:47:19 HRS
- Elapsed Time: 00:33:52 (33 minutes, 52 seconds)
- Total Packets: 316,425
- Average Packets/sec: 155.7
- Average Packet Size: 746 bytes
- Average Bytes/sec: 116 k

**PCAP3.pcap**
- SHA1 Hash: d018bc842b5fd21c3d7fdfb2e804700c250a1e3b
- SHA256 Hash: b3ea9b966023b50264dabac665bb10816935a0624365595a521a420d821304c3
- MD5 Hash: 5326e9ff939b9c781c4f4b2f4a129e20
- Capture Length: 56 MB
- Packet Size Limit: 262,144 bytes
- First Packet: 2021-03-26 12:54:34 HRS
- Last Packet: 2021-03-26 14:57:43 HRS
- Elapsed Time: 02:03:09 (2 hours, 3 minutes, 9 seconds)
- Total Packets: 139,074
- Average Packets/sec: 18.8
- Average Packet Size: 389 bytes
- Average Bytes/sec: 7,322 k

**PCAP4.pcap**
- SHA1 Hash: eb60196f401f77f0312cfeedc4b4272e510e75a9
- SHA256 Hash: 49ac74bd9ededfeb1d54d1cabb49e3bfa43a0d14b3586d45232dba596273bd6d
- MD5 Hash: de3b81f6ad1ae3ff63a60ca10eb50c2d
- Capture Length: 173 MB
- Packet Size Limit: 262,144 bytes
- First Packet: 2021-03-26 15:04:16 HRS
- Last Packet: 2021-03-26 15:27:21 HRS
- Elapsed Time: 00:23:04 (23 minutes, 4 seconds)
- Total Packets: 235,808
- Average Packets/sec: 170.3
- Average Packet Size: 718 bytes
- Average Bytes/sec: 122 k

**PCAP5.pcap**
- SHA1 Hash: 84f3f6ba54c8d6b346b904ac29004ee635c018d4
- SHA256 Hash: 9fa7504be7123f3ed777c12af1a1d96f99560fdbf7f06ea383607da1e2b69350
- MD5 Hash: e6fc518a4a74baef2641dfc5151ed05b
- Capture Length: 255 MB
- Packet Size Limit: 262,144 bytes
- First Packet: 2021-03-26 15:28:22 HRS
- Last Packet: 2021-03-26 16:21:24 HRS
- Elapsed Time: 00:53:01 (53 minutes, 1 second)
- Total Packets: 345,566
- Average Packets/sec: 108.6
- Average Packet Size: 724 bytes
- Average Bytes/sec: 78 k

**PCAP6.pcap**
- SHA1 Hash: 41fcc0e609a774ee0dde6d906a8ed6c7c1cebb4c
- SHA256 Hash: 4dbfef7639e58500078cfb5fc426189b468c6d069268e390c9c2bef4394a41e3
- MD5 Hash: 20d54d24ff996ee98d311025d72bca36
- Capture Length: 297 MB
- Packet Size Limit: 262,144 bytes
- First Packet: 2021-03-26 16:22:16 HRS
- Last Packet: 2021-03-26 17:49:14 HRS
- Elapsed Time: 01:26:58 (1 hour, 26 minutes, 58 seconds)
- Total Packets: 496,251
- Average Packets/sec: 95.1
- Average Packet Size: 584 bytes
- Average Bytes/sec: 55 k

**PCAP7.pcap**
- SHA1 Hash: e472afaa396305cf0290d04a614fd804d3ac3670
- SHA256 Hash: f3304963a3d72f66bb27ba65e14a65617d3273b035de4e30e3a9b6012b54be9e
- MD5 Hash: 77023f2535c37e41d6611e2d04800cca
- Capture Length: 222 MB
- Packet Size Limit: 262,144 bytes
- First Packet: 2021-03-26 17:50:15 HRS
- Last Packet: 2021-03-26 19:28:19 HRS
- Elapsed Time: 01:38:04 (1 hour, 38 minutes, 4 seconds)
- Total Packets: 408,853
- Average Packets/sec: 69.5
- Average Packet Size: 528 bytes
- Average Bytes/sec: 36 k

**PCAP8.pcap**
- SHA1 Hash: 2c875b8f7c83ce90d20dca841cd5d28ff1cc6b5a
- SHA256 Hash: de4859b68940aee00260c096d96585dec37f83ae4294bc4ea140753694ea86ce
- MD5 Hash: 5c05b3a538e5867a942a2abf278a4bc6
- Capture Length: 59 MB
- Packet Size Limit: 262,144 bytes
- First Packet: 2021-03-26 19:28:51 HRS
- Last Packet: 2021-03-26 19:59:27 HRS
- Elapsed Time: 00:30:36 (30 minutes, 36 seconds)
- Total Packets: 100,929
- Average Packets/sec: 55.0
- Average Packet Size: 577 bytes
- Average Bytes/sec: 31 k

**PCAP9.pcap**
- SHA1 Hash: 19482e9429338511b7ada52b8a756869f9fb4c06
- SHA256 Hash: 92f66b0a3e4b2ea2f2aaeef74d6f7a182a85f85ddf1f84235e7683ea711b1197
- MD5 Hash: d6808cf9e70fdf5f6511d4bb067e5ddd
- Capture Length: 1,635 MB (1.59 GB)
- Packet Size Limit: 262,144 bytes
- First Packet: 2021-03-26 19:59:56 HRS
- Last Packet: 2021-03-26 22:31:23 HRS
- Elapsed Time: 02:31:26 (2 hours, 31 minutes, 26 seconds)
- Total Packets: 2,005,703
- Average Packets/sec: 220.7
- Average Packet Size: 800 bytes
- Average Bytes/sec: 176 k

**PCAP10.pcap**
- SHA1 Hash: ab6d14d82be1bb1d9db3d7f1070de1e39f4b1fee
- SHA256 Hash: f2d5ee623fbdfe9d091e526ec970dcbe6dee429844d7332da4ae46c58a7d13a1
- MD5 Hash: 2ce125a115463f15a521551b1c851983
- Capture Length: 1,027 MB (1.01 GB)
- Packet Size Limit: 262,144 bytes
- First Packet: 2021-03-26 22:35:18 HRS
- Last Packet: 2021-03-26 23:41:42 HRS
- Elapsed Time: 01:06:24 (1 hour, 6 minutes, 24 seconds)
- Total Packets: 1,193,863
- Average Packets/sec: 299.6
- Average Packet Size: 845 bytes
- Average Bytes/sec: 253 k

### 3.2. Network Components Identified

The details regarding relevant network components and devices are included below. The evidence for these details was extracted by Network Miner ver2.8.

**10.0.0.1**
- MAC: 000C29C79AF0
- NIC Vendor: VMware, Inc.
- MAC Age: 2003-01-21
- Hostname: N/A
- OS: Satori DHCP: NETGEAR WNR3500L
- Domain Name: fabcompany.com
- Device Family: NETGEAR
- Device Category: Wireless Access Point

**10.0.0.10**
- MAC: 000C2945CDB9
- NIC Vendor: VMware, Inc.
- MAC Age: 2003-01-21
- Hostname: ACCOUNTING-PC, Accounting-PC
- OS: Windows 7 Professional 6.1
- Domain Name: ACCOUNTING-PC, WORKGROUP
- Device Family: Axis Communications
- Device Category: Windows
- SMB File Share: \\ACCOUNTING-PC\IPC$

**10.0.0.12**
- MAC: 000C2936182F
- NIC Vendor: VMware, Inc.
- MAC Age: 2003-01-21
- Hostname: WIN-SCS47QKPGR3
- OS: Windows Version 1: 6.3
- Domain Name: FABCO
- Device Family: N/A
- Device Category: Windows
- SMB File Share: \\10.0.0.12\IPC$, \\10.0.0.12\shared
- Queried DNS Names: woad, isatap

**10.0.0.14**
- MAC: 000C29F70A01
- NIC Vendor: VMware, Inc.
- MAC Age: 2003-01-21
- Hostname: RECEPTION-PC, Reception-PC, Reception-PC.fabco.com
- OS: Windows Version 1: 6.1
- Domain Name: N/A
- Device Family: Axis Communications
- Device Category: Windows
- SMB File Share: N/A
- Queried DNS Names: fabco.com, ns1.worldnic.com, ns2.worldnic.com, NS1.WORLDNIC.com, ACCOUNTING-PC.fabco.com, teredo.ipv6.microsoft.com, Reception-PC.fabco.com, update.googleapis.com, Reception-PC, dns.msdtncsi.com, isatap.fabcompany.com

**5.149.248.134**
- MAC: 38700CC17374 (Same as hundreds of other IP addresses)
- NIC Vendor: ARRIS Group, Inc.
- MAC Age: 2016-02-17
- Hostname: 5.149.248.134
- OS: Linux – Redhat 7.5 (50%), Linux 3.10 (50%)
- Domain Name: N/A
- Device Family: N/A
- Device Category: Linux
- Web Server Banner: TCP 80 (Port 80 HTTP)
- Queried DNS Names: N/A

**195.201.43.23**
- MAC: 38700CC17374 (Same as hundreds of other IP addresses)
- NIC Vendor: ARRIS Group, Inc.
- MAC Age: 2016-02-17
- Hostname: 195.201.43.23
- OS: Linux – Redhat 7.5 (50%), Linux 3.10 (50%)
- Domain Name: N/A
- Device Family: N/A
- Device Category: Linux
- Web Server Banner: TCP 80: nginx (Port 80 HTTP)
- Queried DNS Names: N/A

### 3.3. Network Data/Files Identified

The details listed below are relevant files found within the PCAPs extracted from Wireshark v4.0.3 and analyzed using VirusTotal. All the EXE files grabbed from the PCAPs came up malicious. More info on these files will be listed in the Evidence Chain of Custody Tracking Form.

- **0a2104ee1ba0786c.exe**
  - MD5: 3df7aec6a5fb9af3dbe525f05aa54322
  - SHA1: d34a46fb0ec4c6c7ae51a419bfa09c2fb4c99002
  - SHA256: 0a2104ee1ba0786c6785453a79dd01b10922a77f89317c82d536ee80e8e87d0d

- **UltraAdwareKiller.exe**
  - MD5: 28ed8a345163962af1812a757e883275
  - SHA1: 6d8c3d60b7c80e94c4fb7907145d09ea497f3588
  - SHA256: e20e01221b19b7c6ed98cce0180d97ecb11eff7c974fb1c1b043a62f2c1b911c

- **1d28f3787a46bac489b5f3f50abe33ffa8a4976a1c84a468f61767316148aba0.exe**
  - MD5: e6315892982a033dfc9dffc6425e49ca
  - SHA1: b60f6d468870b58cd4841d239631f31373b93fc5
  - SHA256: 23f4ed957f3b010263e61513167d2b29df39cb15943d3867bfb3c0862fe667d9

- **BindStub.exe**
  - MD5: 0abb5fdb965367f3e4994b384e540486
  - SHA1: 7db72bfc6500cfd74b42cc5a181dfb80d68eb05a
  - SHA256: 1dc871ab69b22abf6bde46ddc4165112ecdf1f384a3516f217623becdc2b7f20

- **Amber.exe**
  - MD5: 57ca53190f243e3c45f1b310fe595ec3
  - SHA1: 1b62ba50be76117d4ab946adbf7fa3100cab7ee3
  - SHA256: f3c3df5c065eb9a06a0eade576df068cfdcb0d3e73a81642c0df8a9fe11a17e2

- **uCal147.exe**
  - MD5: a5beda5741f5f61e7675af805b9ce964
  - SHA1: 9858560c503eb487658b5b1631de13cf97614440
  - SHA256: 2fa4ac71c61b474bde542de4a6b7411c05eb55bb75e41fb3267e3bb084c01559

- **NEOwzcu.exe**
  - MD5: bfc455ed05e7be263db4255ccdf72fd2
  - SHA1: d552d4ead8276eb6ac53cee5ce50eecea8ec2f86
  - SHA256: 3bca07d2a5f2b70e319b716b81af3ce295eed19ada4a6b857ffee88a0741bf09

- **4c71be68d8b92c604bd8e172f617633a38d19ee867e8c05974876c5066ff4fbb.exe**
  - MD5: 34b64e6debb54863373a71452d4e9297
  - SHA1: 62ecfbe136d8b819247b6a5f7dc220499d3eb6bd
  - SHA256: b908cf5214c03a8939fcdbc4ce470cc7755ec00a070b5565eff7f639293d27eb

- **apicial.exe**
  - MD5: 90fc8f900562bfbefd77b05fe5bf863e
  - SHA1: 04bcac56c676eb1b73349acccb1b2f972eb79b5a
  - SHA256: badff02e8af272c8e3fe8664fcaa29137c8cc27da501dc8d9b9664e25167793f

- **Accounting_HR_Employees.docx**
  - MD5: 76763832d8bb023b57b06780d62d2876
  - SHA1: 6ae54e0bdcd547a4db14171fe404b06beeba09ca
  - SHA256: 0b114c1b8787e7f71067b4373e8083fe75050dc8be4b82b6a358c889df852a02

- **Accounting_Employee_Registry.docx**
  - MD5: c879fd924d29906e5aede6afd782efb5
  - SHA1: 543d10baea26e56b40f2df80368098a89b2f9b42
  - SHA256: 257781bf95c60a87f5495a3dae05fb3ba9926b5ced4c8799ff1150cd7717dfa8

- **Employee_Payroll.zip**
  - MD5: ac108475019f4387badb16892cc601ce
  - SHA1: 5a7864a9fb03c79754092bc1a9c8a61e55b68dde
  - SHA256: 603d59becd2972035e4427cb766e458ae64818059e3327fe48715d656e4c182f

- **Accounting_HR_Payroll.docx**
  - MD5: 55ca003ec42dde17bfff7cf8f08702a6
  - SHA1: 6dadfbda9f94b3ab71afd1c1a9aac99ef848c35e
  - SHA256: c5394f20810fd759eed23ef427bc898cdf9b2c02466f5d3c2ad1dc298f253410

- **Accounting_Employee_Payroll.xlsx**
  - MD5: aea0ed92e5d09dd893cd08c4a6c9a54f
  - SHA1: 0d50e7f8a5275bdf39f77bcf7d64de0683a9894e
  - SHA256: f34b405aff9249e38d8e6dd76a0751c4a873372694b9e782c52e85792e279caa
 
## 4. Relevant Findings

The compromised network of FABCO is suspected to be the result of an HTTP attack that occurred over port 80 (HTTP). It is impossible to find the definitive point of infiltration as the network administrator started monitoring the network with Wireshark after the machine in question was noticeably slower in performance. However, this does not mean we cannot find the root cause and methodology of the malware in question.

The network uses a web server called nginx that can also be used as a reverse proxy, load balancer, mail proxy, and HTTP cache. This was found by analyzing POST requests from the HTTP protocol over port 80. It should also be noted that almost all HTTP packets within the PCAPs use the protocol with the GET request, this TCP stream contains the only packets with POST requests. The evidence for this can be seen in the TCP stream in Figure 1 below under “Server”.

Figure 1: TCP stream of an HTTP POST request:  <br/>
![Figure 1: TCP stream of an HTTP POST request](https://imgur.com/KIsyuEk.png)

The IP address from the host in Figure 1 also leads to possible infectious websites. This IP address when ran through VirusTotal resulted in 9/87 vendors analyzing the IP address as malicious. What’s more interesting is the relations tab in VirusTotal. By cross examining the SHA256 hash values of the previously analyzed files and the IP in question resulted in the same Windows executables being found in relation with the IP address 5.149.248.134, such as uCall47.exe, amber.exe, and UltraAdwareKiller.exe and many more that were not found in the PCAPs. By examining this IP in Network Miner v2.8, it was also discovered that this IP address along with hundreds of other IP addresses resulted in having the same MAC address which is an indicator of ARP spoofing. ARP spoofing is a technique by which an attacker sends Address Resolution Protocol (ARP) messages onto a local area network. Generally, the aim is to associate the attacker's MAC address with the IP address of another host, such as the default gateway, causing any traffic meant for that IP address to be sent to the attacker instead. The exact same request, system, and indication of ARP spoofing can also be found from the IP address 195.201.43.23 and many other IP addresses. This can be seen in Figure 2 below.

Figure 2: ARP spoofing indication from 5.149.248.134 in Network Miner v2.8:  <br/>
![Figure 2: ARP spoofing indication from 5.149.248.134 in Network Miner v2.8](https://imgur.com/GAVRUmG.png)

The user-agent listed in the TCP stream from Figure 1, Medunja Solodunnja 6.0.0, is a cause for suspicious activity. Looking into the user-agent revealed an article by Artem Semenchenko on Fortinet that analyzed the functionality of Google Docs malware involving this user-agent. The article can be found at this [link](https://www.fortinet.com/blog/threat-research/cookie-maker-inside-the-google-docs-malicious-network). By analyzing the reading and behavior analysis provided in the article, the POST request over HTTP seen in Figure 8 looks very similar to the POST request in Figure 1 in this report. The malware in question opened a backdoor over HTTP port 80 before the PCAPs began and hid as a trojan virus until the malware got access to the Firewall and started creating DLL and EXE files over the SMB (Server Message Block) protocol over port 445 (Microsoft Directory Services). This can be seen in Figure 3 below.

Figure 3: SMB protocol over port 445 in PCAP5.pcap creating EXE files on Accounting-PC:  <br/>
![Figure 3: SMB protocol over port 445 in PCAP5.pcap creating EXE files on Accounting-PC](https://imgur.com/papaujO.png)

## 5. Supporting Details

### 5.1. Activity Timeline

1. Sometime before the PCAPS, the Accounting-PC Window’s desktop was infected with malware, creating a backdoor over port 80 (HTTP).

2. The network administrator notices the device is running slower than usual and starts monitoring the network activity using Wireshark at 2021-03-26 14:42:30 UTC.

3. The malware communicates from its host URL, which is unknown because of the ARP spoof over port 80, to start communications over HTTPS traffic.

4. When the malware is run, it utilizes the Dynamic Link Library (DLL) and self-deleting Windows executables to run the malware in the background, utilizing CMD to create more backdoors and system analyzing malware.

5. The malware will then steal personal data, credentials, and employee payrolls/information by grabbing the files on 10.0.0.10/24 utilizing web browsers and the nginx server over port 80 (HTTP) and port 445 (SMB).

6. The network administrator runs VirusTotal scans on the created files over SMB before ending the PCAPs.

## 5.2.	Noteworthy Behavior

Based on the information provided, we can determine that the malware will create self-deleting executables and DLL files to accomplish the goal of the evading detection and infecting the system with as many different executables it can communicate with, as well as perform ARP spoofing to avoid detection. This can be seen in a created VirusTotal graph in Figure 4 seen below.

Figure 4: VirusTotal graph showing the connections of executables, DLL files, and linked IP address:  <br/>
![Figure 4: VirusTotal graph showing the connections of executables, DLL files, and linked IP address](https://imgur.com/w9V9Ol6.png)

Because of nature of the malware, it is difficult to pinpoint exactly where the malware first started, however, we can determine that the main objective of the malware was to obtain private information such as employee payroll, employee information data, and data of the network.

## 6. Additional Subsections

### 6.1. Methodology

- **Wireshark**
  - *Version:* 4.0.3
  - *Use:* Used for packet capture and analysis

- **hexed.it**
  - *Version:* N/A
  - *Use:* Determining and analyzing hash values of the relevant files

- **NetworkMiner**
  - *Version:* 2.8
  - *Use:* Broad inspection for network, images, files, and anomaly inspection
 
- **VirusTotal**
  - *Version:* N/A
  - *Use:* Determining and analyzing hash values of the relevant files

### 6.2. User Applications

One of the most relevant applications and tools being used in this case is the nginx server being utilized on the network. Uninstalling this server from the network could have possibly saved the network from the injected malware. This wouldn't have stopped the backdoor being created as it is evident it was created as a backdoor over port 80 (HTTP), but it could have prevented other devices from becoming infected, as well as the executables and other files from being created and stolen. If the server is a necessity for the functionality of the network, I would recommend closing ports 80 and 445 in the firewall, as they are considered "unsafe" ports.

### 6.3. Recommendations

The best form of prevention is education for employees regarding cyber threats and how to protect your business from cyber-attacks or phishing attempts. Given that the origin of this breach was most likely a malicious link that was clicked, it is advised to have employees undergo cybersecurity training to prevent such incidents from happening again. It is also recommended to implement a web filter to help prevent employee access to potentially malicious websites. Web filters are a form of software that scans, monitors, approves, and rejects internet traffic based on certain markers that may be related to known security breaches.

Additionally, it is advised to hire a dedicated IT professional, if possible, to ensure the network's security and protect it from outside threats. An accountant doubling as an IT person may lack the experience and time needed to secure the network effectively. If hiring a full-time IT staff member is not feasible, consider contracting a professional who can help ensure network security.

Furthermore, since a botnet was potentially in use, adding a load balancer to the system can help deter and manage Distributed Denial of Service (DDoS) attacks. A load balancer, such as Azure Load Balancer, is used to distribute incoming and outgoing traffic across multiple instances, preventing specific network devices, like routers, from being overwhelmed and potentially causing hardware and software damage. While not a requirement, it can mitigate issues resulting from a large influx of incoming traffic and could potentially prevent ARP spoofing.

Lastly, it is recommended to implement a 3-tier architecture instead of a simple web proxy server communicating directly with the database (tier 2) on the internal network. Ideally, the network structure should be as follows: (Web DMZ) --> (App DMZ) --> (Database DMZ). Refer to Figure 5 below for a detailed illustration.

Figure 5: 3-Tier Architecture example:  <br/>
![Figure 5: 3-Tier Architecture example](https://imgur.com/N4GeHcf.png)

## 7. Conclusion

Identifying the root cause of the network intrusion is challenging, and there is still some information lacking in the evidence gathered to definitively determine the extent and origin of the malware attack on FABCO. However, the most significant lead to the intrusion of FABCO appears to be the user-agent "Medunja Solodunnia." This attack against FABCO is believed to be a component of a Google Docs malware attack that also targets Windows, Android, and MacOS. The system may have been infected through one of three major approaches.

The first approach involves a link or document that was delivered to an employee who unknowingly clicked on it, resulting in the malware download. The second possibility is that the malware was encountered while conducting a web search. The third scenario involves an employee clicking on a link to a malicious document, which triggers multiple redirections based on various variables, eventually leading to the installation of a file containing malware.

Several images were discovered within the PCAPs using NetworkMiner during the numerous redirects, making it challenging to pinpoint which one may have contained the malware download. The malware, once in the system, creates self-deleting executables and DLL files to evade detection and infect the system with various executables. It also employs ARP spoofing to avoid detection.

The virus initially scans the network for additional computers after infecting the Reception PC, where the infection occurred. It successfully locates the Accounting PC during this scan and makes multiple connection attempts. Once linked to the Accounting PC, the malware begins scanning for documents that may contain sensitive information, primarily related to employees, including salary and registration data.

While the presence of a botnet in this attack is the most likely scenario, its exact function remains unclear. It may serve as a host for the virus downloaded to the system through the chain of hops, or it could be a host for every hop or redirect that occurs when the link is clicked. Although the precise impact of the botnet on this specific attack is currently unknown, references to the User Agent "Medunja Solodunnia" are widespread.

As many documents potentially contained sensitive information, such as employee salaries, social security numbers, and credit card details, there is a high likelihood that many of them have been compromised. While customer information was not taken, as far as the investigation can determine, it is still premature to rule out any possibilities. The information obtained during the investigation suggests that there is cause for concern, and immediate action and further investigation are recommended.
