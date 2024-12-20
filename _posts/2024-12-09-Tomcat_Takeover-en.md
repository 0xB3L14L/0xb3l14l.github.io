---
title: "CyberDefenders - Tomcat Takeover - Easy"
date: 09-12-2024 00:00:00 +0800
categories: [CTF, Cyberdefenders, Network Forensics]
tags: [CTF, Blue Team, Wireshark]
author: 0xB3L14L
description: Analyze the network traffic to an Apache Tomcat web server for detected malicious activities.
lang: en
permalink: /posts/Cyberdefenders-Tomcat_Takeover
image:
  path: /Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-Takeover.png
---

The first step is to identify the IP address responsible for making requests to the web server; this IP performed a scan of active ports. Then, with the following filter:
```bash
tcp.flags.syn == 1 && tcp.flags.ack == 0
```
To show all packets that are initiating a `SYN` connection without an `ACK` response, something typical in a SYN scan.

With this filter, an IP is identified.
![source](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-source-ip.png)

Where the IP `14.0.0.120` performed the port scan.

Next, it is important to know the location of the IP address. This can be obtained with a tool that performs **IP Address Lookup** such as [WhatIsMyIpAddress](https://whatismyipaddress.com/ip-lookup).

![city](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-city.png)

The city is `Guangzhou`.

Next, it is requested to identify which port is used to access the web server. To do this, the HTTP traffic from the found IP address must be filtered.

```bash
ip.src == 14.0.0.120 && http
```
It shows that the port is `8080`.
![webserver](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-dstport.png)

It seems that the attacker also performed a directory and file enumeration of the web server, and the tool used must be identified.

One way to identify the tool is through the **User-Agent** since most tools tend to include their name in this field.

![gobuster](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-gobuster.png)

With this enumeration, the attacker managed to identify the directory that allows user login. To know the name, it can be filtered with HTTP status codes. In this case, it would be 302 to see if the directory was found.

```bash
ip.src == 10.0.0.112 &&  http.response.code == 302
```
![panel](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-302.png)

Among them, there is one with the name **Manager**.

![manager](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-manager.png)

After finding the admin panel, the attacker performed a brute force attack and managed to log in. If filtered with the authorization attempts.

```bash
ip.src == 14.0.0.120 &&  http.authorization
```

![auth1](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-auth1.png)

Reviewing the last packet of **/manager/html**, the correct credentials appear.

![auth2](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-auth2.png)

Once the attacker was inside the admin panel, they uploaded a reverse shell, the objective is to identify the name of the payload. Since it was a file upload, it can be filtered with the **POST** method.

```bash
ip.src == 14.0.0.120 &&  http.request.method == "POST"
```

![war1](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-upload1.png)

And upon looking at the HTTP flow, the file name is found.

![war2](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-upload2-war.png)

The last thing to do is to identify the command that the attacker used to gain persistence. It can be inferred what command was used, since the operating system is Linux. Therefore, persistence can be achieved in various ways, one of which is through a reverse shell that runs automatically.

You can filter by strings or content within the packets, so you can filter where the string **bash** is present.

```bash
ip.src == 14.0.0.120 && frame contains "bash"
```

![revshell1](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-revshell1.png)

Looking at the TCP flow, the command used will appear.

![revshell2](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-revshell2.png)

It is noted that the attacker created a cronjob as a persistence technique.