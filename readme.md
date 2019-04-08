# ks_hook-X

可可网络X系统通杀补丁

理论支持所有语言，支持所有加壳程序，支持X系列内存加载的DLL，已测试官方最新版本 1.3.16.239

## 项目介绍

thread_inject -> 远程线程DLL注入程序，把ks_hook-X.dll注入到目标程序

ks_hook-X -> 核心DLL程序，注入到目标程序后，自动判断解码 自动HOOK可可网络验证的DLL库通信

## NOTE

在 ks_hook-X.cpp 注意2个宏


**DEBUG_KSS_DATA**
> 开关模式，DLL注入后，用来获取数据还是用来破解？  1 = 调试数据  0 = 破解程序

**DEBUG_CPLUSPLUS_KSS_DATA**
> 开关模式，如果是C++的程序，C++版本需要hook类成员函数，麻烦的一逼，需要调试的数据的话 下面开启 1。 如果你是破解程序的话无视它

**g_FormatData = (PVOID)((ULONG_PTR)GetModuleHandle(NULL) + 0x11EE0)**
> OD搜字符串 "DLL内部错误，返回的数据异常" ，然后到到函数头部地址就是了,这里就相当于Hook FD_函数取明码数据
这里Hook C++版本的可可验证，因为有ASLR 随机基址，所以需要基址+偏移方式取到这个函数
