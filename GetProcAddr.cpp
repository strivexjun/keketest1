
#include "stdafx.h"
#include "GetProcAddr.h"


/**
 * 看雪抄过来的，获取导出表函数地址
 */
DWORD MyGetProcAddress(
	HMODULE hModule,    // handle to DLL module
	LPCSTR lpProcName   // function name
)
{
	int i = 0;
	char *pRet = NULL;
	PIMAGE_DOS_HEADER pImageDosHeader = NULL;
	PIMAGE_NT_HEADERS pImageNtHeader = NULL;
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;

	pImageDosHeader = (PIMAGE_DOS_HEADER)hModule;
	pImageNtHeader = (PIMAGE_NT_HEADERS)((DWORD)hModule + pImageDosHeader->e_lfanew);
	pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hModule + pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD dwExportRVA = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD dwExportSize = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	DWORD *pAddressOfFunction = (DWORD*)(pImageExportDirectory->AddressOfFunctions + (DWORD)hModule);
	DWORD *pAddressOfNames = (DWORD*)(pImageExportDirectory->AddressOfNames + (DWORD)hModule);
	DWORD dwNumberOfNames = (DWORD)(pImageExportDirectory->NumberOfNames);
	DWORD dwBase = (DWORD)(pImageExportDirectory->Base);

	WORD *pAddressOfNameOrdinals = (WORD*)(pImageExportDirectory->AddressOfNameOrdinals + (DWORD)hModule);

	//这个是查一下是按照什么方式（函数名称or函数序号）来查函数地址的
	DWORD dwName = (DWORD)lpProcName;
	if ((dwName & 0xFFFF0000) == 0)
	{
		goto xuhao;
	}

	for (i = 0; i < (int)dwNumberOfNames; i++)
	{
		char *strFunction = (char *)(pAddressOfNames[i] + (DWORD)hModule);
		if (strcmp(strFunction, (char *)lpProcName) == 0)
		{
			pRet = (char *)(pAddressOfFunction[pAddressOfNameOrdinals[i]] + (DWORD)hModule);
			goto _exit11;
		}
	}
	//这个是通过以序号的方式来查函数地址的
xuhao:
	if (dwName < dwBase || dwName > dwBase + pImageExportDirectory->NumberOfFunctions - 1)
	{
		return 0;
	}
	pRet = (char *)(pAddressOfFunction[dwName - dwBase] + (DWORD)hModule);
_exit11:
	//判断得到的地址有没有越界
	if ((DWORD)pRet<dwExportRVA + (DWORD)hModule || (DWORD)pRet > dwExportRVA + (DWORD)hModule + dwExportSize)
	{
		return (DWORD)pRet;
	}
	char pTempDll[100] = { 0 };
	char pTempFuction[100] = { 0 };
	lstrcpy(pTempDll, pRet);
	char *p = strchr(pTempDll, '.');
	if (!p)
	{
		return (DWORD)pRet;
	}
	*p = 0;
	lstrcpy(pTempFuction, p + 1);
	lstrcat(pTempDll, ".dll");
	HMODULE h = LoadLibrary(pTempDll);
	if (h == NULL)
	{
		return (DWORD)pRet;
	}
	return MyGetProcAddress(h, pTempFuction);
}
