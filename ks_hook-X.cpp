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
#define		DEBUG_KSS_DATA		0


//
//开关模式，如果是C++的程序，C++版本需要hook类成员函数，麻烦的一逼，需要调试的数据的话 下面开启 1。 如果你是破解程序的话无视它
//
#define		DEBUG_CPLUSPLUS_KSS_DATA	1

//
// OD搜字符串 "DLL内部错误，返回的数据异常" ，然后到到函数头部地址就是了,这里就相当于Hook FD_函数取明码数据
// 这里Hook C++版本的可可验证，因为有ASLR 随机基址，所以需要基址+偏移方式取到这个函数
//
PVOID		g_FormatData = (PVOID)((ULONG_PTR)GetModuleHandle(NULL) + 0x11EE0);

////////////////////////////////////////////////////////////////////////////////////
// 这是公告的返回
////////////////////////////////////////////////////////////////////////////////////
std::string g_announcementData = 
"<xml>"
"<state>100</state><message>取软件信息成功</message><upset>0</upset><softver>2</softver>"
"<softdownurl>http://www.baidu.com</softdownurl><yzpl>15</yzpl><softgg>xjun测试</softgg>"
"<pccode2>~DESKTOP-NS8NRTF.0C9D92C2E494</pccode2><dllver>[V1.3.16.239]</dllver>"
"</xml>";


////////////////////////////////////////////////////////////////////////////////////
// 登录验证返回数据  randomstr需要自己处理下返回对应的
////////////////////////////////////////////////////////////////////////////////////
std::string g_checkData =
"<xml>"
"<state>100</state><message>验证通过</message><index>0</index><IsPubUser>0</IsPubUser>"
"<ShengYuMiaoShu>8888888</ShengYuMiaoShu><endtime>2088-08-08 22:22:22</endtime>"
"<shostname>http://v9.hphu.com:8080</shostname><shosttime>1554389205</shosttime>"
"<unbind_changetime>0</unbind_changetime><YanZhengPinLv>15</YanZhengPinLv>"
"<InfoA>返回信息A	</InfoA><InfoB>返回信息为B</InfoB><username>keketest1</username>"
"<linknum>5</linknum><cday>8888.00</cday><points>8888</points><bdinfo></bdinfo>"
"<tag>04-04</tag><keyextattr></keyextattr><BeiZhu></BeiZhu><cztimes>1</cztimes>"
"<managerid>2</managerid><randomstr>%s</randomstr><pccode>1595106748~DESKTOP-NS8NRTF.0C9D92C2E494</pccode><SiYouShuJu></SiYouShuJu>"
"</xml>";


////////////////////////////////////////////////////////////////////////////////////
// 程序退出返回数据
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
 * 开始hook 可可动态链接库导出函数
 */
VOID * WINAPI startHookKssX(PVOID imageBase)
{
	FARPROC ks_cmd, GetPcCode, ks_setSoft, ks_setUser;

	ks_cmd = (FARPROC)MyGetProcAddress(reinterpret_cast<HMODULE>(imageBase), "ks_cmd");
	GetPcCode = (FARPROC)MyGetProcAddress(reinterpret_cast<HMODULE>(imageBase), "GetPcCode");
	ks_setSoft = (FARPROC)MyGetProcAddress(reinterpret_cast<HMODULE>(imageBase), "ks_setSoft");
	ks_setUser = (FARPROC)MyGetProcAddress(reinterpret_cast<HMODULE>(imageBase), "ks_setUser");

	Log::Info("[%s] ks_cmd:%p  GetPcCode:%p  ks_setSoft:%p  ks_setUser:%p \n",
		__FUNCTION__, ks_cmd, GetPcCode, ks_setSoft, ks_setUser);

	MH_CreateHook(ks_cmd, hooked_ks_cmd, (PVOID*)&pfnhooked_ks_cmd);
	MH_EnableHook(ks_cmd);

	MH_CreateHook(GetPcCode, hooked_GetPcCode, (PVOID*)&pfnhooked_GetPcCode);
	MH_EnableHook(GetPcCode);

	MH_CreateHook(ks_setSoft, hooked_ks_setSoft, (PVOID*)&pfnhooked_ks_setSoft);
	MH_EnableHook(ks_setSoft);

	MH_CreateHook(ks_setUser, hooked_ks_setUser, (PVOID*)&pfnhooked_ks_setUser);
	MH_EnableHook(ks_setUser);

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
		static std::string checkResult;

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
