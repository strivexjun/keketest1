// ks_hook-X.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"


typedef
CHAR* (WINAPI *fnhooked_ks_cmd)(CHAR * cmdName, CHAR * cmdData);

typedef
CHAR* (WINAPI *fnhooked_GetPcCode)(CHAR * disk, CHAR * cpu, CHAR * adapter, CHAR * board);

typedef
CHAR* (WINAPI *fnhooked_ks_setSoft)(PSOFT_PARAMENTERS softParamPtr);

typedef
CHAR* (WINAPI *fnhooked_ks_setUser)(PUSER_PARAMENTERS userParamPtr);

typedef
VOID (WINAPI *fnhooked_FormatData)(CHAR** ioData);

fnhooked_ks_cmd pfnhooked_ks_cmd = NULL;
fnhooked_GetPcCode pfnhooked_GetPcCode = NULL;
fnhooked_ks_setSoft pfnhooked_ks_setSoft = NULL;
fnhooked_ks_setUser pfnhooked_ks_setUser = NULL;
fnhooked_FormatData pfnhooked_FormatData = NULL;


//
//开关模式，DLL注入后，用来获取数据还是用来破解？  1 = 调试数据  0 = 破解程序
//
#define		DEBUG_KSS_DATA		1

//
//开关模式，如果是C++的程序，C++版本需要hook类成员函数，麻烦的一逼，需要调试的数据的话 下面开启 1。 如果你是破解程序的话无视它
//
#define		DEBUG_CPLUSPLUS_KSS_DATA	1

//
// OD搜字符串 "DLL内部错误，返回的数据异常" ，然后到到函数头部地址就是了,这里就相当于Hook FD_函数取明码数据
// 这里Hook C++版本的可可验证，因为有ASLR 随机基址，所以需要基址+偏移方式取到这个函数
//
//PVOID		g_FormatData = (PVOID)((ULONG_PTR)GetModuleHandle(NULL) + 0x9980);
PVOID		g_FormatData = NULL;


//
// 这里是IPC通讯的调用和返回数据
//
// 0FA4C13B    8B45 08         mov eax, dword ptr ss : [ebp + 0x8]
// 0FA4C13E    8945 88         mov dword ptr ss : [ebp - 0x78], eax
// 0FA4C141    68 00200000     push 0x2000
// 0FA4C146    6A 00           push 0x0
// 0FA4C148    6A 00           push 0x0
// 0FA4C14A    68 1F000F00     push 0xF001F
// 0FA4C14F    8B4D 88         mov ecx, dword ptr ss : [ebp - 0x78]
// 0FA4C152    51              push ecx
//
// Hook 位置特征 50 8B 45 8C 50 E8 ?? ?? ?? ?? 83 C4 0C 8D 4D D8
//
FARPROC pfnhoooked_ipcMessage = NULL;

////////////////////////////////////////////////////////////////////////////////////
// 这是公告的返回
////////////////////////////////////////////////////////////////////////////////////
std::string g_announcementData = 
"<xml>"
"<state>100</state><message>取软件信息成功</message><upset>0</upset><softver>2</softver>"
"<softdownurl>http://www.baidu.com</softdownurl><yzpl>15</yzpl><softgg>Cracked by:xjun</softgg>"
"<pccode2>~DESKTOP-NS8NRTF.0C9D92C2E494</pccode2><dllver>[V1.3.16.239]</dllver>"
"</xml>";


////////////////////////////////////////////////////////////////////////////////////
// 登录验证返回数据  randomstr需要自己处理下返回对应的
////////////////////////////////////////////////////////////////////////////////////
std::string g_checkData =
"<xml><state>100</state><message>验证通过</message><index>0</index><IsPubUser>0</IsPubUser><ShengYuMiaoShu>2006139</ShengYuMiaoShu><endtime>2066-06-06 16:16:16</endtime><shostname>http://www.crack666.com:6666</shostname><shosttime>1555218409</shosttime><unbind_changetime>0</unbind_changetime><YanZhengPinLv>15</YanZhengPinLv><InfoA>返回信息为A</InfoA><InfoB>返回信息为B</InfoB><username>ttkkM858Ga</username><linknum>1</linknum><cday>30.00</cday><points>0</points><bdinfo></bdinfo><tag>??????</tag><keyextattr></keyextattr><BeiZhu></BeiZhu><cztimes>1</cztimes><managerid>1</managerid><randomstr>%s</randomstr><pccode>1595106748~DESKTOP-NS8NRTF.0C9D92C2E494</pccode><SiYouShuJu></SiYouShuJu><keystr>ttkkM858GafG25i5Q32VFqM82651ZTQ8</keystr></xml>";


////////////////////////////////////////////////////////////////////////////////////
// 处理成功返回数据
////////////////////////////////////////////////////////////////////////////////////
std::string g_exitData = "<xml><state>100</state><message>ok</message></xml>";


/**
 * 格式化字符串
 */
std::string FormatString(const char* format, ...)
{
	std::string result;
	va_list va;
	va_start(va, format);

	int len = _vscprintf(format, va);

	result.assign(len, '\0');

	vsprintf((char*)result.c_str(), format, va);

	va_end(va);

	return result;
}

/**
 * 取文本中间
 */
std::string GetTextSubString(std::string lpText, CONST CHAR* forward, CONST CHAR *behind)
{
	int pos, pos2;
	int start, len;
	std::string result;

	pos = lpText.find(forward);
	if (pos ==std::string::npos)
	{
		return result;
	}

	pos2 = lpText.find(behind, pos);
	if (pos2 == std::string::npos)
	{
		return result;
	}

	start = pos + strlen(forward);
	len = pos2 - start;

	result = lpText.substr(start, len);

	return result;
}

/**
 * Hook ipc_srvMessage Handler函数
 */
VOID WINAPI hooked_ipcMessage(CHAR* recvData, CHAR* replyData)
{
	Log::Info("> IPC_MESSAGE 通信过程\n> recvData:%s\n> replyData:%s",
		recvData, replyData);
}

__declspec(naked) VOID hooked_ipcJump()
{
	__asm {
		pushfd;
		pushad;

		push dword ptr ss : [esp + 0x28];
		push dword ptr ss : [esp + 0x28];
		call hooked_ipcMessage;

		popad;
		popfd;

		jmp pfnhoooked_ipcMessage;
	}
}


/**
 * 开始hook 可可动态链接库导出函数
 */
VOID * WINAPI startHookKssX(PVOID imageBase, SIZE_T imageSize)
{
	std::string imageWrapped;
	int npos;

	FARPROC ks_cmd, GetPcCode, ks_setSoft, ks_setUser,ks_ipcMessage;

	ks_cmd = (FARPROC)MyGetProcAddress(reinterpret_cast<HMODULE>(imageBase), "ks_cmd");
	GetPcCode = (FARPROC)MyGetProcAddress(reinterpret_cast<HMODULE>(imageBase), "GetPcCode");
	ks_setSoft = (FARPROC)MyGetProcAddress(reinterpret_cast<HMODULE>(imageBase), "ks_setSoft");
	ks_setUser = (FARPROC)MyGetProcAddress(reinterpret_cast<HMODULE>(imageBase), "ks_setUser");

	imageWrapped.assign((const char*)imageBase, imageSize);
	npos = imageWrapped.find("\x50\x8B\x45\x8C\x50\xE8");
	if (npos == std::string::npos)
	{
		Log::Error("> find ipc_srvMessage Handler failed.");
		ks_ipcMessage = NULL;
	}
	else
	{
		ks_ipcMessage = (FARPROC)((ULONG_PTR)imageBase + npos + 5);
	}


	Log::Info("[%s] ks_cmd:%p  GetPcCode:%p  ks_setSoft:%p  ks_setUser:%p ks_ipcMessage:%p\n",
		__FUNCTION__, ks_cmd, GetPcCode, ks_setSoft, ks_setUser, ks_ipcMessage);

	MH_CreateHook(ks_cmd, hooked_ks_cmd, (PVOID*)&pfnhooked_ks_cmd);
	MH_EnableHook(ks_cmd);

	MH_CreateHook(GetPcCode, hooked_GetPcCode, (PVOID*)&pfnhooked_GetPcCode);
	MH_EnableHook(GetPcCode);

	MH_CreateHook(ks_setSoft, hooked_ks_setSoft, (PVOID*)&pfnhooked_ks_setSoft);
	MH_EnableHook(ks_setSoft);

	MH_CreateHook(ks_setUser, hooked_ks_setUser, (PVOID*)&pfnhooked_ks_setUser);
	MH_EnableHook(ks_setUser);

	MH_CreateHook(ks_ipcMessage, hooked_ipcJump, (PVOID*)&pfnhoooked_ipcMessage);
	MH_EnableHook(ks_ipcMessage);

	

	return NULL;
}

/**
 * Hook _FD取明码数据 C++版本需要hook类成员函数，麻烦的一逼
 */
class CSoftLicTool
{

public:
	std::string  hooked_FD_(std::string &ioData);

};

typedef std::string(CSoftLicTool::* fnReal_FD_)(std::string &ioData);

static fnReal_FD_ pfnReal_FD_;

std::string CSoftLicTool::hooked_FD_(std::string &ioData)
{
	std::string result;
	std::string preDecrypt;
	std::string postDecrypt;

	preDecrypt = ioData;

	result = (this->*pfnReal_FD_)(ioData);

	postDecrypt = ioData;

	Log::Info("[%s]\n> _FD(\"%s\")\n> result: %s \n", __FUNCTION__, preDecrypt.c_str(), postDecrypt.c_str());

	return result;
}

//std::string(CSoftLicTool:: *CSoftLicTool::Real_FD_)(std::string &ioData) = (std::string(CSoftLicTool::*)(std::string&))&CSoftLicTool::padding_FD_;

/**
 * Hook _FD取明码数据
 */
VOID WINAPI hooked_FormatData(CHAR** ioData)
{
	std::string preDecrypt;
	std::string postDecrypt;

	preDecrypt = *ioData;

	pfnhooked_FormatData(ioData);

	postDecrypt = *ioData;

	Log::Info("[%s]\n> _FD(\"%s\")\n> result: %s \n", __FUNCTION__, preDecrypt.c_str(), postDecrypt.c_str());

}

/**
 * Hook ks_cmd函数
 */
CHAR * WINAPI hooked_ks_cmd(CHAR * cmdName, CHAR * cmdData)
{
	CHAR *result = NULL;

#if DEBUG_KSS_DATA


	result = pfnhooked_ks_cmd(cmdName, cmdData);
	

#else

	static std::string checkResult;

	//
	//这里返回公告
	//
	if (_stricmp(cmdName, "get") == 0)
	{
		result = (CHAR*)g_announcementData.c_str();
 	}

	//
	//验证操作
	//
	if (_stricmp(cmdName, "check") == 0)
	{

		std::string random;
		std::string subString;
		std::string advapiFormat = \
			"<xml><state>100</state><message>验证通过</message><randomstr>%s</randomstr><advapi>%s</advapi></xml>";

		random = GetTextSubString(cmdData, "<randomstr>", "</randomstr>");

		//
		//advapi
		//
		subString = GetTextSubString(cmdData, "<advapi>", "</advapi>");
		if (!subString.empty())
		{
			//
			//处理advapi
			//
			if (_strnicmp(subString.c_str(),"v_point",strlen("v_point")) == 0)
			{
				checkResult = FormatString(advapiFormat.c_str(), random.c_str(), "99999");//返回点数
				result = (CHAR*)checkResult.c_str();
			}
			else if (_strnicmp(subString.c_str(), "v_geta", strlen("v_geta")) == 0)
			{
				checkResult = FormatString(advapiFormat.c_str(), random.c_str(), "这里我们自定义返回 v_geta 接口的数据");//返回点数
				result = (CHAR*)checkResult.c_str();
			}
			else if (_strnicmp(subString.c_str(), "v_getb", strlen("v_getb")) == 0)
			{
				checkResult = FormatString(advapiFormat.c_str(), random.c_str(), "这里我们自定义返回 v_getb 接口的数据");//返回点数
				result = (CHAR*)checkResult.c_str();
			}
			else if (_strnicmp(subString.c_str(), "v_52pj", strlen("v_52pj")) == 0)
			{
				checkResult = FormatString(advapiFormat.c_str(), random.c_str(), "DOCT/A9m98rZSTBFYifVrHm8qljpl1f2lRg7S+/NNLZ3E4BwtNdi/X/qxU9WMn/OOKiW66vQ80U6GKs4jumH51itDQGbid6EuqTRBvr4zPJmtf4/rNOOAT5QPT8UWxjt0Kc0gLZ/NfZe9dJUMGz8BiMANFhTeMFbwF8Bazm/HG4=");

				result = (CHAR*)checkResult.c_str();

				//
				//开始Patch VMProtect RSA的模数
				//

				Log::Info("> 开始Patch VMProtect RSA N");

				g_pHeapAlloc = GetProcAddress(GetModuleHandle("kernel32"), "HeapAlloc");

				MH_CreateHook(g_pHeapAlloc, Jump, (PVOID*)&pfnHeapAlloc);

				MH_EnableHook(g_pHeapAlloc);

			}
			else 
			{
				//
				//这里其他的advapi自己处理吧
				//
				MessageBox(NULL, subString.c_str(), "advapi except!!!", MB_ICONINFORMATION);
			}
		}
		else
		{
			//
			//默认全部验证成功
			//
			checkResult = FormatString(g_checkData.c_str(), random.c_str());

			result = (CHAR*)checkResult.c_str();
		}

 	}

	//
	//ipc启动
	//
	if (_stricmp(cmdName,"ipc_start") == 0)
	{
		result = (CHAR*)g_exitData.c_str();
	}

	//
	//退出操作
	//
	if (_stricmp(cmdName, "exit") == 0)
	{
		result = (CHAR*)g_exitData.c_str();
 	}

	//
	//其他命令默认不处理，走原有逻辑
	//
	if (result == NULL)
	{
		result = pfnhooked_ks_cmd(cmdName, cmdData);
	}

#endif

	Log::Info("[%s]\n> ks_cmd(\"%s\",\"%s\")\n> result: %s \n", __FUNCTION__, cmdName, cmdData, result);

	return result;
}


/**
 * Hook GetPcCode函数
 */
CHAR * WINAPI hooked_GetPcCode(CHAR * disk, CHAR * cpu, CHAR * adapter, CHAR * board)
{
	CHAR *result = NULL;

	result = pfnhooked_GetPcCode(disk, cpu, adapter, board);

	Log::Info("[%s]\n> GetPcCode: disk:%s cpu:%s adapter:%s board:%s \n", __FUNCTION__, disk, cpu, adapter, board);

	return result;
}

/**
 * Hook ks_setSoft函数
 */
CHAR * WINAPI hooked_ks_setSoft(PSOFT_PARAMENTERS softParamPtr)
{
	CHAR *result = NULL;

#if DEBUG_KSS_DATA

#if DEBUG_CPLUSPLUS_KSS_DATA

 	std::string(CSoftLicTool::* pfn_FD_)(std::string &ioData) = &CSoftLicTool::hooked_FD_;

	MH_CreateHook(g_FormatData, *(PBYTE*)&pfn_FD_, (PVOID*)&pfnReal_FD_);
	MH_EnableHook(g_FormatData);

#else

	MH_CreateHook(g_FormatData, hooked_FormatData, (PVOID*)&pfnhooked_FormatData);
	MH_EnableHook(g_FormatData);

#endif

#endif


	//softParamPtr->m_licKey = (CHAR*)"UCcNlo4LWxoRH7tKD0U+r4Vm4bSRrHQ2fhQI1LI6Z/cHZZIvcGfytdJ9PSK93rcyLya8+KQfaQXGAxIVgPRRXe1mJ+TQxG9w/Rp+W8EBkE6wlcBFnATiHZQMnN2v4cESZv3RNxbueLOiG7FsjuPSa9C51eqRjV4b0CEPEbk6t7axB1IDnXvTqTjhYDg/a3eINJAFZD+VLaM6ZVnEPPJofpsXt/iDEq0Tpg89Xjz+RlDYJ3vYj3shPUsPjpF9gD2ydy6Yc3QBIHkhWDmfRpuCY75nqr0GkwX/hj7iJVUcL6QXwFxpXsQuSrmQCmBkIgKQUULyr3u8svKwWrwHJaOubA==|";
	//softParamPtr->m_softNumber = 1168602;

	Log::Info("[%s]:\n"
		"> 授权码:%s \n> INI文件路径:%s \n> 软件编号:%d \n> 是否启用备服:%d "
		"\n> 自定义机器码:%s \n> 取机器码项目:%d \n> 软件版本:%d \n> 加密数据头:%s \n> 通讯组件:%d "
		"\n> 是否启用HTTPS:%d \n> 回调函数:%p \n",
		__FUNCTION__,
		softParamPtr->m_licKey, softParamPtr->m_iniFile, softParamPtr->m_softNumber, softParamPtr->m_useAlternateSrv,
		softParamPtr->m_customMachineCode, softParamPtr->m_machineCodeItem, softParamPtr->m_softVer, softParamPtr->m_encrytDataHead, softParamPtr->m_comComponent,
		softParamPtr->m_useHttps, softParamPtr->m_callback);

	result = pfnhooked_ks_setSoft(softParamPtr);

	return result;
}

/**
 * Hook ks_setUser函数
 */
CHAR * WINAPI hooked_ks_setUser(PUSER_PARAMENTERS userParamPtr)
{
	CHAR *result = NULL;

	Log::Info("[%s]:\n"
		"> 用户名:%s \n> 密码:%s \n> 注册卡号:%s \n> 客户端ID:%d \n> 绑定信息:%s \n",
		__FUNCTION__,
		userParamPtr->m_account, userParamPtr->m_password, userParamPtr->m_registerCardNo, userParamPtr->m_clientID, userParamPtr->m_bindInfo);

	result = pfnhooked_ks_setUser(userParamPtr);

	return result;
}

