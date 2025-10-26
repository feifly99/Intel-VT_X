#include <stdio.h>
#include <Windows.h>

#pragma warning(disable:6387)

extern VOID __fastcall transPidAndIoRegion(ULONG64 pid, PVOID ioRegion);
extern VOID __fastcall addAddressToMonitor(PVOID address);
extern VOID __fastcall removeAddressFromMonitor(PVOID address);
extern VOID __fastcall startMonitoring();
extern VOID __fastcall stopMonitoring();

ULONG64 g_targetPid = 0;

PVOID g_ioRegion = NULL;

VOID definePidAndIoRegion()
{
	printf("输入十进制进程ID: \n");
	g_targetPid = 0;
	scanf_s("%llu", &g_targetPid);
	g_ioRegion = malloc(USN_PAGE_SIZE);
	RtlZeroMemory(g_ioRegion, USN_PAGE_SIZE);
	transPidAndIoRegion(g_targetPid, g_ioRegion);
	printf("[+] 目标进程Pid: %llu(d), IoRegion: %p\n", g_targetPid, g_ioRegion);
	return;
}

VOID addAddressToList()
{
	printf("输入要监控的地址(十六进制)：\n");
	ULONG_PTR address = 0;
	scanf_s("%llX", &address);
	addAddressToMonitor((PVOID)address); //触发VM_EXIT
	printf("[+] 已添加监控地址: %p\n", (PVOID)address);
	return;
}

VOID testMonitoring()
{
	startMonitoring();
	printf("[+] 已开启监控\n");
	return;
}

VOID testEnding()
{
	stopMonitoring();
	printf("[+] 已停止监控并清除所有监控地址\n");
	return;	
}

int main()
{
	definePidAndIoRegion();
	addAddressToList();
	addAddressToList();
	addAddressToList();
	addAddressToList();
	addAddressToList();
	testMonitoring();
	Sleep(10000); //监控10秒
	testEnding();
    return 0;
}