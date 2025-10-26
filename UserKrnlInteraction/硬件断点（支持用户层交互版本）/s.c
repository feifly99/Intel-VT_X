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
	printf("����ʮ���ƽ���ID: \n");
	g_targetPid = 0;
	scanf_s("%llu", &g_targetPid);
	g_ioRegion = malloc(USN_PAGE_SIZE);
	RtlZeroMemory(g_ioRegion, USN_PAGE_SIZE);
	transPidAndIoRegion(g_targetPid, g_ioRegion);
	printf("[+] Ŀ�����Pid: %llu(d), IoRegion: %p\n", g_targetPid, g_ioRegion);
	return;
}

VOID addAddressToList()
{
	printf("����Ҫ��صĵ�ַ(ʮ������)��\n");
	ULONG_PTR address = 0;
	scanf_s("%llX", &address);
	addAddressToMonitor((PVOID)address); //����VM_EXIT
	printf("[+] ����Ӽ�ص�ַ: %p\n", (PVOID)address);
	return;
}

VOID testMonitoring()
{
	startMonitoring();
	printf("[+] �ѿ������\n");
	return;
}

VOID testEnding()
{
	stopMonitoring();
	printf("[+] ��ֹͣ��ز�������м�ص�ַ\n");
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
	Sleep(10000); //���10��
	testEnding();
    return 0;
}