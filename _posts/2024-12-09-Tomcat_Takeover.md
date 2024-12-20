---
title: "CyberDefenders - Tomcat Takeover - Easy"
date: 09-12-2024 00:00:00 +0800
categories: [CTF, Cyberdefenders, Network Forensics]
tags: [Easy]
author: 0xB3L14L
description: Analizar el tráfico de red a un servidor web de Apache Tomcat por actividades maliciosas detectadas.
lang: es
permalink: /posts/Cyberdefenders-Tomcat_Takeover
image:
  path: /Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-Takeover.png
---

Lo primero que se pide es identifcar la dirección IP que es la responsable de realizar las solicitudes al servidor web, esta IP realizó un escaneo de puertos activos. Entonces, con el siguiente filtro: 
```bash
tcp.flags.syn == 1 && tcp.flags.ack == 0
```
Para mostar todos los paquetes que están iniciando conexión `SYN` sin una respuesta `ACK`, algo que es típico en el escaneo SYN.

Con este filtro, se identifica una IP.
![source](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-source-ip.png)

Donde la IP `14.0.0.120` realizó el escaneo de puertos.

Lo siguiente, es en conocer la localidad de la dirección IP. Esto se lo puedo conseguir con una herramienta que realice **IP Address Lookup** como por ejemplo [WhatIsMyIpAddress](https://whatismyipaddress.com/ip-lookup)

![city](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-city.png)

La ciudad es `Guangzhou`

Después solicita identifcar con cúal puerto se accede al servidor web. Para ello se debe filtrar el tráfico de tipo HTTP de la dirección IP que se encontró

```bash
ip.src == 14.0.0.120 && http
```
Muestra que el puerto es el `8080`
![webserver](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-dstport.png)

Al parecer el atacante también hizo una enumeración de directorios y archivos del webserver, y se debe identificar la herramienta utilizada.

Una forma identificar la herramienta es por medio del  **User-Agent** ya que la mayoría de las herramientas suelen incluir su nombre en este campo.

![gobuster](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-gobuster.png)

Con esta enumeración el atacante logró identificar el directorio que permite el login a los usuarios. Para saber el nombre, se puede filtrar con los códigos de estado HTTP. En esta caso sería el 302 para ver si el directorio fue encontrado.

```bash
ip.src == 10.0.0.112 &&  http.response.code == 302
```
![panel](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-302.png)

De todos, hay uno con el nombre **Manager**.

![manager](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-manager.png)

Tras haber encontrado el panel de admin, el atacante hizo un ataque de fuerza bruta y logró ingresar. Si se filtra con los intentos de autorización.

```bash
ip.src == 14.0.0.120 &&  http.authorization
```

![auth1](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-auth1.png)

Revisando el último paquete de **/manager/html**, aparecen las credenciales correctas.

![auth2](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-auth2.png)

Una vez que el atacante estaba dentro del panel de admin, subió una reverse shell, el objetivo es identificar el nombre del payload. Ya que fue una subida de archivo, se puede filtrar con el método **POST**.

```bash
ip.src == 14.0.0.120 &&  http.request.method == "POST"
```

![war1](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-upload1.png)

Y al mirar el flujo HTTP, se encuentra el nombre del archivo

![war2](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-upload2-war.png)

Lo último a realizar, es en identificar el comando que el atacante utilizó para tener persistencia. Se puede intuir el comando que se utilizó, ya que el sistema operativo es un Linux. Entónces, se puede conseguir persistencia de distintas maneras una de ellas es por medio de una reverse shell que se ejecute automáticamente.

Se puede filtrar por strings o contenido dentro de los paquetes, asi que se puede filtrar donde la string **bash** esté presente.

```bash
ip.src == 14.0.0.120 && frame contains "bash"
```

![revshell1](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-revshell1.png)

Mirando el flujo TCP aparecerá el comando utilizado.

![revshell2](/Media/Images/Blue-Team/CyberDefenders/Tomcat-Takeover/Tomcat-revshell2.png)

Se aprecia que el atacante creó un cronjob como técnica de persistencia.



