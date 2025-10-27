#include <stdio.h>
#include <Windows.h>

#pragma warning(disable:6387 6001)

extern VOID __fastcall transPidAndIoRegion(ULONG64 pid, PVOID ioRegion);
extern VOID __fastcall addAddressToMonitor(PVOID address);
extern VOID __fastcall removeAddressFromMonitor(PVOID address);
extern VOID __fastcall startMonitoring();
extern VOID __fastcall stopMonitoring();
extern VOID __fastcall clearResourceAndExit();

ULONG64 g_targetPid = 0;

PVOID g_ioRegion = NULL;

VOID displayMonitoredAddresses()
{
	ULONG_PTR* base = (ULONG_PTR*)g_ioRegion;
	for (size_t j = 0; base[j] != 0; j++)
	{
		printf("[*] 监控地址列表[%llu]: %p\n", j, (PVOID)base[j]);
	}
	return;
}

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

VOID removeAddressInList()
{
	printf("输入要移除监控的地址(十六进制)：\n");		
	ULONG_PTR address = 0;
	scanf_s("%llX", &address);
	removeAddressFromMonitor((PVOID)address);
	printf("[-] 已移除监控地址: %p\n", (PVOID)address);
	return;
}

VOID startDebugging()
{
	startMonitoring();
	printf("[!] 已开启监控\n");
	return;
}

VOID endDebugging()
{
	stopMonitoring();
	printf("[-] 已停止监控并清除所有监控地址\n");
	return;	
}

int main()
{
	definePidAndIoRegion();
	int choice = 0;
	while (1)
	{
		printf("\n=================菜单=================\n");
		printf("1. 添加监控地址\n");
		printf("2. 移除监控地址\n");
		printf("3. 显示监控地址列表\n");
		printf("4. 开始监控\n");
		printf("5. 停止监控\n");
		printf("0. 清理资源并退出程序\n");
		printf("=====================================\n");
		printf("请输入选项: ");
		scanf_s("%d", &choice);
		switch (choice)
		{
			case 1:
			{
				addAddressToList();
				break;
			}
			case 2:
			{
				removeAddressInList();
				break;
			}
			case 3:
			{
				displayMonitoredAddresses();
				break;
			}
			case 4:
			{
				startDebugging();
				break;
			}
			case 5:
			{
				endDebugging();
				break;
			}
			case 0:
			{
				clearResourceAndExit();
				free(g_ioRegion);
				printf("退出程序.\n");
				goto EXIT;
			}
			default:
			{
				printf("请重新选择.\n");
				continue;
			}
		}
	}
EXIT:
	system("pause\n");
    return 0;
}
