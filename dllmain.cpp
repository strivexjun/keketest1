// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"

#define	LOGFILENAME		"kss-X.log"
#define KSSLIBRARY		"softlic32.dll"		
#define DEBUGCONSOLE	1

FARPROC g_decodeAPI = NULL;

/**
 * 通过读取导出表名称字符串来判断 是否是可可X DLL加载
 */
BOOL isKssXLibrary(PVOID imageBase, SIZE_T &imageSize)
{
	PIMAGE_DOS_HEADER pDosHead = (PIMAGE_DOS_HEADER)imageBase;
	if (pDosHead->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	PIMAGE_NT_HEADERS pNtHead = (PIMAGE_NT_HEADERS)(pDosHead->e_lfanew + (ULONG_PTR)pDosHead);
	if (pNtHead->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	PIMAGE_DATA_DIRECTORY pExportData = \
		&pNtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	if (pExportData->VirtualAddress == NULL || pExportData->Size == NULL) {
		return FALSE;
	}

	PIMAGE_EXPORT_DIRECTORY pExports = \
		(PIMAGE_EXPORT_DIRECTORY)(pExportData->VirtualAddress + (ULONG_PTR)pDosHead);

	if (pExports->Name == NULL) {
		return FALSE;
	}

	CHAR *nameString = (CHAR*)(pExports->Name + (ULONG_PTR)pDosHead);
	Log::Info("[%s] Library nameString: %s", __FUNCTION__, nameString);

	if (_stricmp(nameString, KSSLIBRARY) != 0) {
		return FALSE;
	}

	imageSize = pNtHead->OptionalHeader.SizeOfImage;

	Log::Info("[%s] TRUE", __FUNCTION__);

	return TRUE;
}


/**
 * Hook 函数GetStartupInfo ，等待可可X DLL解码
 */
typedef VOID(WINAPI* fn_GetStartupInfoA)(LPSTARTUPINFOA lpStartupInfo);
fn_GetStartupInfoA pfn_GetStartupInfoA = NULL;
VOID WINAPI HookedGetStartupInfoA(LPSTARTUPINFOA lpStartupInfo)
{
	LPVOID returnAddr = _ReturnAddress();
	SIZE_T imageSize = 0;

	Log::Info("[%s] -> ReturnAddress = %08x", __FUNCTION__, returnAddr);

	MEMORY_BASIC_INFORMATION	mbi32 = { 0 };
	if (VirtualQuery(returnAddr, &mbi32, sizeof(mbi32))) {
		Log::Info("[%s] Library -> ImageBase = %08x ", __FUNCTION__,mbi32.AllocationBase);

		if (isKssXLibrary(mbi32.AllocationBase, imageSize)) {

			MH_DisableHook(g_decodeAPI);
			Log::Info("[%s] start hook ks_library exports function!", __FUNCTION__);

			//
			//开始hook函数
			//

			startHookKssX(mbi32.AllocationBase, imageSize);

		}
	}

	pfn_GetStartupInfoA(lpStartupInfo);
}

/**
 * 
 */
void InstallHook()
{
	char exePath[MAX_PATH];
	GetModuleFileName(GetModuleHandle(NULL), exePath, MAX_PATH);
	Log::Info("Exe = %s", exePath);

	g_decodeAPI = GetProcAddress(GetModuleHandle("kernel32.dll"), "GetStartupInfoA");

	if (MH_CreateHook(g_decodeAPI, HookedGetStartupInfoA, (PVOID*)&pfn_GetStartupInfoA) != MH_OK) {
		Log::Info("[instHook] create hook decode api fail!");
		return;
	}

	if (MH_EnableHook(g_decodeAPI) != MH_OK) {
		Log::Info("[instHook] enable hook decode api fail!");
		return;
	}
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	{

#if DEBUGCONSOLE

		AllocConsole();
		freopen("CONOUT$", "w", stdout);

#endif
		DeleteFile(LOGFILENAME);

		Log::Initialise(LOGFILENAME);

		if (MH_Initialize() != MH_OK) 
		{
			Log::Info("MinHook initialize failed!!!");
			return FALSE;
		}

		InstallHook();

		break;
	}
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

