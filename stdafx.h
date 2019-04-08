// stdafx.h: 标准系统包含文件的包含文件，
// 或是经常使用但不常更改的
// 项目特定的包含文件
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // 从 Windows 头文件中排除极少使用的内容
// Windows 头文件
#include <windows.h>
#include <intrin.h>
#include <tchar.h>


// 在此处引用程序需要的其他标头

#include "Log.h"
#include "tinyxml2.h"
#include "MinHook/MinHook.h"
#include "GetProcAddr.h"

using namespace tinyxml2;

//函数申明


#pragma pack(push,1)

typedef struct _SOFT_PARAMENTERS
{
	CHAR *m_licKey;//授权码
	CHAR *m_iniFile;//保存验证日志的ini文件路径
	INT m_softNumber;//软件编号
	INT m_useAlternateSrv;//是否启用备服，不启用为0，启用为1
	CHAR *m_customMachineCode;//自定义机器码
	INT m_machineCodeItem; //不自定义机器码，由库内部取，这里设置取哪些，C表示CPU，D表示磁盘特征码，M表示网卡号，留空默认是D。可设置CMD, CM, CD, MD, C, M, D这七种组合
	INT m_softVer; // 软件版本号，需要软件更新或强制更新时用
	CHAR *m_encrytDataHead;//软件数据头
	INT m_comComponent;//取网络数据用到的组件，可设置1和2 默认为1  1是用winhttpAPI取网络数据，2是用WinHttpRequest COM对象取网络数据
	INT m_useHttps;//是否启用https,默认值是http，设置为1时启用https
	FARPROC *m_callback;//在调用ks_cmd("set","第二个参数的文本")和ks_cmd("check","第二个参数的文本")时会被回调执行 
}SOFT_PARAMENTERS, *PSOFT_PARAMENTERS;

typedef struct _USER_PARAMENTERS
{
	CHAR *m_account;//用户名
	CHAR *m_password;//密码
	CHAR *m_registerCardNo;//注册卡号
	INT m_clientID;//客户端ID
	CHAR *m_bindInfo;//绑定信息
}USER_PARAMENTERS, *PUSER_PARAMENTERS;

#pragma pack(pop)

extern
VOID* WINAPI  startHookKssX(PVOID imageBase);

extern
CHAR* WINAPI  hooked_ks_cmd(CHAR *cmdName, CHAR *cmdData);

extern
CHAR* WINAPI  hooked_GetPcCode(CHAR *disk, CHAR *cpu, CHAR *adapter, CHAR *board);

extern
CHAR* WINAPI  hooked_ks_setSoft(PSOFT_PARAMENTERS softParamPtr);

extern
CHAR* WINAPI  hooked_ks_setUser(PUSER_PARAMENTERS userParamPtr);
