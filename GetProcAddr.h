#ifndef _GETPROCADDR_H
#define _GETPROCADDR_H

DWORD MyGetProcAddress(
	HMODULE hModule,    // handle to DLL module
	LPCSTR lpProcName   // function name
);

#endif