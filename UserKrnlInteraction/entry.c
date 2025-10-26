#include "IA32.h"

#pragma warning(disable: 28182)
#pragma warning(disable: 6387)
#pragma warning(disable: 6011)
#pragma warning(disable: 4996)
#pragma warning(disable: 6386)

ULONG GUEST_FS_BASE_INDEX = GUEST_FS_BASE_ADDRESS;
ULONG GUEST_CR0_INDEX = GUEST_CR0;
ULONG GUEST_CR3_INDEX = GUEST_CR3;
ULONG GUEST_CR4_INDEX = GUEST_CR4;
ULONG GUEST_RFLAGS_INDEX = GUEST_RFLAGS;
ULONG GUEST_RSP_INDEX = GUEST_RSP;
ULONG GUEST_RIP_INDEX = GUEST_RIP;
ULONG GUEST_GDTR_LIMIT_INDEX = GUEST_GDTR_LIMIT;
ULONG GUEST_IDTR_LIMIT_INDEX = GUEST_IDTR_LIMIT;
ULONG HOST_RIP_INDEX = HOST_RIP;
ULONG HOST_RSP_INDEX = HOST_RSP;
ULONG VECF_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS_INDEX = VECF_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS;
ULONG VECF_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS_INDEX = VECF_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS;
ULONG VM_EXIT_REASON_INDEX = VEIF_EXIT_REASON;
ULONG VM_EXIT_QUALIFICATION_INDEX = VEIF_EXIT_QUALIFICATION;
ULONG VM_INSTRUCTION_LENGTH_INDEX = VEIF_VM_EXIT_INSTRUCTION_LENGTH;

PVCPU vCpu;

PULONG_PTR PER_CPU_REGS;

ULONG_PTR bugCheck;

ULONG totalCpuCount;

ULONG_PTR ept;

ULONG_PTR targetPhysicalAddressAligned;

ULONG_PTR tpPML4T, tpPDPT, tpPDT, tpPT;

ULONG_PTR pV2P;

ULONG64 targetPid;

ULONG_PTR targetCr3, ioRegion;

ULONG_PTR targetLinerAddress;

ULONG uIsMatchedTargetRip;

SIZE_T triggeredTimes;

UCHAR oCacheType;

ULONG_PTR g_faultPteIndex[12], g_physicalAddress[12];

BOOLEAN g_isInMonitorList[12];

LIST_ENTRY g_addressListHead;

typedef struct _MONITOR_ADDRESS_LIST
{
	ULONG_PTR virtualAddress;
	ULONG_PTR physicalAddress;
	LIST_ENTRY listEntry;
}MONITOR_ADDRESS_LIST, *PMONITOR_ADDRESS_LIST;

#define print(s) \
do\
{\
	ULONG64 ______________x = (s);\
	DbgPrint("%s -> [0x%p]\n", #s, (PVOID)______________x);\
}while(0)

#define RWX (0x7ull)
#define RW (0x3ull)
#define X (0x4ull)

NTSTATUS readPhysicalAddress(
	IN PVOID physicalAddress,
	IN PVOID receivedBuffer,
	IN SIZE_T readSize,
	SIZE_T* bytesTransferred
)
{
	MM_COPY_ADDRESS Read = { 0 };
	Read.PhysicalAddress.QuadPart = (LONG64)physicalAddress;
	if (bytesTransferred == NULL)
	{
		SIZE_T ret = 0;
		return MmCopyMemory(receivedBuffer, Read, readSize, MM_COPY_MEMORY_PHYSICAL, &ret);
	}
	else
	{
		return MmCopyMemory(receivedBuffer, Read, readSize, MM_COPY_MEMORY_PHYSICAL, bytesTransferred);
	}
}

ULONG_PTR getPhysicalAddressByCR3AndVirtualAddress(
	IN ULONG64 cr3,
	IN ULONG_PTR VirtualAddress
)
{
	cr3 = (cr3 >> 12) << 12;
	ULONG_PTR ultimatePhysicalAddress = 0;
	ULONG_PTR ultimatePhysicalAddressPageHeader = 0;
	ULONG_PTR VPO = (VirtualAddress << 52) >> 52;
	ULONG_PTR PFN4 = ((VirtualAddress << 43) >> 43) >> 12;
	ULONG_PTR PFN3 = ((VirtualAddress << 34) >> 34) >> 21;
	ULONG_PTR PFN2 = ((VirtualAddress << 25) >> 25) >> 30;
	ULONG_PTR PFN1 = ((VirtualAddress << 16) >> 16) >> 39;
	SIZE_T ret = 0;
	ULONG_PTR a = 0, b = 0, c = 0;
	readPhysicalAddress((PVOID)(cr3 + 8 * PFN1), &a, sizeof(ULONG_PTR), &ret);
	if (ret == 0) return 0;
	a = (((a << 24) >> 24) >> 12) << 12;
	readPhysicalAddress((PVOID)(a + 8 * PFN2), &b, sizeof(ULONG_PTR), &ret);
	if (ret == 0) return 0;
	b = (((b << 24) >> 24) >> 12) << 12;
	readPhysicalAddress((PVOID)(b + 8 * PFN3), &c, sizeof(ULONG_PTR), &ret);
	if (ret == 0) return 0;
	c = (((c << 24) >> 24) >> 12) << 12;
	readPhysicalAddress((PVOID)(c + 8 * PFN4), &ultimatePhysicalAddressPageHeader, sizeof(ULONG_PTR), &ret);
	if (ret == 0) return 0;
	ultimatePhysicalAddressPageHeader = (((ultimatePhysicalAddressPageHeader << 24) >> 24) >> 12) << 12;
	ultimatePhysicalAddress = ultimatePhysicalAddressPageHeader + VPO;
	return ultimatePhysicalAddress;
}

VOID initializeMonitorAddressList()
{
	g_addressListHead.Flink = &g_addressListHead;
	g_addressListHead.Blink = &g_addressListHead;
	return;
}

VOID addAddressToMonitorList(
	IN ULONG_PTR virtualAddress
)
{
	PMONITOR_ADDRESS_LIST newNode = (PMONITOR_ADDRESS_LIST)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(MONITOR_ADDRESS_LIST), 'zzaa');
	RtlZeroMemory(newNode, sizeof(MONITOR_ADDRESS_LIST));
	newNode->virtualAddress = virtualAddress;
	newNode->physicalAddress = getPhysicalAddressByCR3AndVirtualAddress(targetCr3, newNode->virtualAddress);
	g_addressListHead.Blink->Flink = &newNode->listEntry;
	newNode->listEntry.Blink = g_addressListHead.Blink;
	newNode->listEntry.Flink = &g_addressListHead;
	g_addressListHead.Blink = &newNode->listEntry;
	return;
}

VOID removeAddressInMonitorList(
	IN ULONG_PTR virtualAddress
)
{
	PLIST_ENTRY currentEntry = g_addressListHead.Flink;
	while (currentEntry != &g_addressListHead)
	{
		PMONITOR_ADDRESS_LIST currentNode = CONTAINING_RECORD(currentEntry, MONITOR_ADDRESS_LIST, listEntry);
		if (currentNode->virtualAddress == virtualAddress)
		{
			currentEntry->Blink->Flink = currentEntry->Flink;
			currentEntry->Flink->Blink = currentEntry->Blink;
			ExFreePool(currentNode);
			currentNode = NULL;
			return;
		}
		currentEntry = currentEntry->Flink;
	}
	return;
}

VOID freeMonitorAddressList()
{
	PLIST_ENTRY currentEntry = g_addressListHead.Flink;
	while (currentEntry != &g_addressListHead)
	{
		PMONITOR_ADDRESS_LIST currentNode = CONTAINING_RECORD(currentEntry, MONITOR_ADDRESS_LIST, listEntry);
		currentEntry = currentEntry->Flink;
		ExFreePool(currentNode);
		currentNode = NULL;
	}
	g_addressListHead.Flink = &g_addressListHead;
	g_addressListHead.Blink = &g_addressListHead;
	return;
}

static MEMORY_TYPE getPhysicalMemoryCacheType(
	ULONG_PTR physicalAddress //may not aligned!!!!!!!
)
{
	if (physicalAddress <= 0x9FFFFull)
	{
		return 0x6; //WB
	}
	else if (physicalAddress >= 0xA0000ull && physicalAddress <= 0xBFFFFull)
	{
		return 0x0; //UC
	}
	else if (physicalAddress >= 0xC0000ull && physicalAddress <= 0xFFFFFull)
	{
		return 0x5; //WP
	}
	else if (physicalAddress >= 0x7B000000ull && physicalAddress <= 0x7FFFFFFFull)
	{
		return 0x0; //WB
	}
	else if (physicalAddress >= 0x80000000ull && physicalAddress <= 0x8FFFFFFFull)
	{
		return 0x1; //UC
	}
	else if (physicalAddress >= 0x90000000ull && physicalAddress <= 0xFFFFFFFFull)
	{
		return 0x0; //WP
	}
	else
	{
		return 0x6; //WB
	}
}

SIZE_T getPteIndexByPhysicalAddressAligned(
	ULONG_PTR physicalAddressAligned
)
{
	ULONG_PTR alignedAddress = physicalAddressAligned & ~0xFFFull;

	SIZE_T pteIndex = (alignedAddress >> 12) & 0x1FFull;  // [20:12]
	SIZE_T pdtIndex = (alignedAddress >> 21) & 0x1FFull;  // [29:21]  
	SIZE_T pdptIndex = (alignedAddress >> 30) & 0x1FFull; // [38:30]
	SIZE_T pml4Index = (alignedAddress >> 39) & 0x1FFull; // [47:39]

	return (pml4Index * 512 * 512 * 512) + (pdptIndex * 512 * 512) + (pdtIndex * 512) + pteIndex;
}

VOID fixSinglePte(ULONG_PTR pPte, ULONG_PTR physicalAddressAligned, ULONG64 rights)
{
	*(ULONG_PTR*)pPte = physicalAddressAligned | rights | ((ULONG64)getPhysicalMemoryCacheType(physicalAddressAligned) << 3);
	return;
}

VOID fixAllAddressesPteInMonitorList(ULONG64 rights)
{
	PLIST_ENTRY currentEntry = g_addressListHead.Flink;
	while (currentEntry != &g_addressListHead)
	{
		PMONITOR_ADDRESS_LIST currentNode = CONTAINING_RECORD(currentEntry, MONITOR_ADDRESS_LIST, listEntry);
		ULONG_PTR physicalAddress = currentNode->physicalAddress;
		ULONG_PTR physicalAddressAligned = physicalAddress & ~0xFFFull;
		ULONG_PTR pteIndex = getPteIndexByPhysicalAddressAligned(physicalAddressAligned);
		fixSinglePte(tpPT + pteIndex * sizeof(ULONG_PTR), physicalAddressAligned, rights);
		DbgPrint("---0x%llX\n", physicalAddress);
		currentEntry = currentEntry->Flink;
	}
	return;
}

ULONG CPUID_C_HANDLER(
	ULONG_PTR _rbp,
	ULONG_PTR _rip,
	ULONG_PTR _cr3,
	ULONG_PTR _kprcb
)
{
	UNREFERENCED_PARAMETER(_rbp);
	UNREFERENCED_PARAMETER(_rip);
	UNREFERENCED_PARAMETER(_cr3);
	UNREFERENCED_PARAMETER(_kprcb);

	ULONG _eax = *(ULONG*)(_rbp + 0x90);
	ULONG64 _rcx = *(ULONG64*)(_rbp + 0x80);
	ULONG64 _rdx = *(ULONG64*)(_rbp + 0x78);
	//DbgPrint("eax: 0x%lX\n", _eax);
	//DbgPrint("rcx: 0x%llX\n", _rcx);
	//DbgPrint("rdx: 0x%llX\n", _rdx);
	//不用跳过CPUID
	switch (_eax)
	{
		case 0xBCCCF000:
		{
			DbgPrint("[+] 目标进程pid: %llu, ioRegion: 0x%llX\n", _rcx, _rdx);
			targetPid = _rcx;
			ioRegion = _rdx;
			PEPROCESS pe = NULL;
			KAPC_STATE apc = { 0 };
			PsLookupProcessByProcessId((HANDLE)targetPid, &pe);
			KeStackAttachProcess(pe, &apc);
			targetCr3 = __readcr3();
			KeUnstackDetachProcess(&apc);
			ObDereferenceObject(pe);
			//DbgPrint("%llX, %llX\n", _cr3, targetCr3); 有问题，前后不一致
			return 0;
		}
		case 0xCCCCE000:
		{
			DbgPrint("[+] 加入的监控地址: 0x%llX\n", _rcx);
			addAddressToMonitorList(_rcx);
			return 0;
		}
		case 0xAAAAAAAA:
		{
			DbgPrint("[+] 准备启动监控\n");
			fixAllAddressesPteInMonitorList(X);
			return 1;
		}
		case 0xBBBBBBBB:
		{
			DbgPrint("[+] 准备停止监控\n");
			fixAllAddressesPteInMonitorList(RWX); 
			__vmx_vmwrite(VECF_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, 0x84006172ul);
			freeMonitorAddressList();
			return 1;
		}
		default:
		{
			return 0;
		}
	}
}

VOID MTF_C_HANDLER(
	ULONG_PTR _rbp,
	ULONG_PTR _rip,
	ULONG_PTR _cr3,
	ULONG_PTR _kprcb
)
{
	UNREFERENCED_PARAMETER(_rbp);
	UNREFERENCED_PARAMETER(_rip);
	UNREFERENCED_PARAMETER(_cr3);
	UNREFERENCED_PARAMETER(_kprcb);

	fixSinglePte(tpPT + g_faultPteIndex[KeGetCurrentProcessorNumber()] * sizeof(ULONG_PTR), g_physicalAddress[KeGetCurrentProcessorNumber()] & ~0xFFFull, X);
	__vmx_vmwrite(VECF_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, 0x84006172ul); 

	return;
}

VOID EPT_VIOLATION_C_HANDLER(
	ULONG_PTR _rbp,
	ULONG_PTR _rip,
	ULONG_PTR _cr3,
	ULONG_PTR _kprcb
)
{
	UNREFERENCED_PARAMETER(_rbp);
	UNREFERENCED_PARAMETER(_rip);
	UNREFERENCED_PARAMETER(_cr3);
	UNREFERENCED_PARAMETER(_kprcb);

	ULONG_PTR guestLinerAddress = 0;
	__vmx_vmread(VEIF_GUEST_LINER_ADDRESS, &guestLinerAddress);

	ULONG_PTR guestPhysicalAddress = 0;
	__vmx_vmread(VEIF_GUEST_PHYSICAL_ADDRESS, &guestPhysicalAddress);

	ULONG_PTR exitQualification = 0;
	__vmx_vmread(VEIF_EXIT_QUALIFICATION, &exitQualification);

	g_faultPteIndex[KeGetCurrentProcessorNumber()] = getPteIndexByPhysicalAddressAligned(guestPhysicalAddress & ~0xFFFull);
	g_physicalAddress[KeGetCurrentProcessorNumber()] = guestPhysicalAddress;
	g_isInMonitorList[KeGetCurrentProcessorNumber()] = FALSE;

	PLIST_ENTRY currentEntry = g_addressListHead.Flink;
	while (currentEntry != &g_addressListHead)
	{
		PMONITOR_ADDRESS_LIST currentNode = CONTAINING_RECORD(currentEntry, MONITOR_ADDRESS_LIST, listEntry);
		if (currentNode->virtualAddress == guestLinerAddress)
		{
			g_isInMonitorList[KeGetCurrentProcessorNumber()] = TRUE;
			break;
		}
		currentEntry = currentEntry->Flink;
	}

	if (!g_isInMonitorList[KeGetCurrentProcessorNumber()] || (LONG64)_rip < 0)
	{
		fixSinglePte(tpPT + g_faultPteIndex[KeGetCurrentProcessorNumber()] * sizeof(ULONG_PTR), g_physicalAddress[KeGetCurrentProcessorNumber()] & ~0xFFFull, RWX);
		__vmx_vmwrite(VECF_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, 0x8C006172ul); 
		return;
	}
	else
	{
		fixSinglePte(tpPT + g_faultPteIndex[KeGetCurrentProcessorNumber()] * sizeof(ULONG_PTR), g_physicalAddress[KeGetCurrentProcessorNumber()] & ~0xFFFull, RWX);
		if (exitQualification & 0x1ull)
		{
			DbgPrint("地址0x%llX读取了地址：0x%llX\n", _rip, guestLinerAddress);
		}
		if (exitQualification & 0x2ull)
		{
			DbgPrint("地址0x%llX写入了地址：0x%llX\n", _rip, guestLinerAddress);
		}
		__vmx_vmwrite(VECF_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, 0x8C006172ul); 
		return;
	}
}

ULONG_PTR allocatePages(
	SIZE_T pagesNum
)
{
	ULONG_PTR ret = (ULONG_PTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, pagesNum * PAGE_SIZE, 'zzaa');
	if (ret == 0)
	{
		KeBugCheckEx(0x343F3B34, 0, 0, 0, 0);
	}
	RtlZeroMemory((PVOID)ret, pagesNum * PAGE_SIZE);
	return ret;
}

VOID getSegementRegisterAttributes(
	IN SEGEMENT_TYPE type,
	IN ULONG64 selector,
	IN UCHAR unusable,
	IN OUT SRA* sra
)
{
	ULONG_PTR GDTbase = __vsm__getGDTbase();
	ULONG64 index = selector >> 3;
	ULONG_PTR currentSelectorGdtEntryPointer = GDTbase + index * 8; //8: magic number defined in INTEL® SDL
	ULONG64 currentSelectorGdtEntry = *(ULONG64*)currentSelectorGdtEntryPointer;
	sra->selector = (USHORT)selector;
	sra->baseAddress = 0;
	sra->accessRight = (ULONG)((currentSelectorGdtEntry >> 40) & 0xFFFFull);
	if (type == 'tr')
	{
		sra->baseAddress = (*(ULONG_PTR*)(currentSelectorGdtEntryPointer + 8)) << 32;
		sra->baseAddress += (ULONG_PTR)(((currentSelectorGdtEntry >> 16) & 0xFFFFFFull) + ((currentSelectorGdtEntry & 0xFF00000000000000ull) >> 32));
	}
	if (unusable)
	{
		sra->accessRight |= 0x10000ul;
	}
	ULONG rawLimit = (ULONG)((currentSelectorGdtEntry & 0xFFFFull) | (((currentSelectorGdtEntry >> 48) & 0xFull) << 16));
	if ((currentSelectorGdtEntry << 55) & 1ull)
	{
		sra->segementLimit = (rawLimit << 12) | 0xFFF; //4K
	}
	else
	{
		sra->segementLimit = rawLimit;
	}
	return;
}

ULONG_PTR virtualOff(
	ULONG_PTR arg
)
{
	UNREFERENCED_PARAMETER(arg);
	__vsm__vmxoffSaveRegisters();
	return 0;
}

ULONG_PTR virtualization(
	ULONG_PTR arg
)
{
	UNREFERENCED_PARAMETER(arg);

	SRA h_cs = { 0 }, h_ss = { 0 }, h_ds = { 0 }, h_es = { 0 }, h_fs = { 0 }, h_gs = { 0 }, h_ldtr = { 0 }, h_tr = { 0 };
	SRA g_cs = { 0 }, g_ss = { 0 }, g_ds = { 0 }, g_es = { 0 }, g_fs = { 0 }, g_gs = { 0 }, g_ldtr = { 0 }, g_tr = { 0 };

	ULONG j = KeGetCurrentProcessorNumber();
	//开启CR4.VMXE位
	__vasm__setCR4VMXEBit();
	vCpu[j].currentCr4 = __vsm__getCR4();
	//Vmxon
	__vmx_on(&vCpu[j].VMX_ON_REGION_PHYSICAL_ADDRESS);
	//选择current VMCS
	__vmx_vmclear(&vCpu[j].VMX_VMCS_REGION_PHYSICAL_ADDRESS);
	__vmx_vmptrld(&vCpu[j].VMX_VMCS_REGION_PHYSICAL_ADDRESS);
	//写入VMCS各个字段
	/*1.VM-Exit Control字段*/
	__vmx_vmwrite(VExCF_PRIMARY_VM_EXIT_CONTROLS, 0x36FFBul); //物理机 0x36FFB
	/*2.VM-Entry Control字段*/
	__vmx_vmwrite(VEnCF_VM_ENTRY_CONTROLS, 0x13FBul); //物理机 0x13FBul
	/*3.VM-Execution Control字段*/
	__vmx_vmwrite(VECF_PIN_BASED_VM_EXECUTION_CONTROL, 0x16ul); //物理机 0x16ul
	__vmx_vmwrite(VECF_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, 0x84006172ul); //物理机 0x4006172ul
	__vmx_vmwrite(VECF_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, 0x10100Aul); //物理机 0x10100Aul
	__vmx_vmwrite(VECF_EXTENDED_PAGE_TABLE_POINTER, (ULONG_PTR)ept | 0x1E);
	/*4.Host-State Area字段*/
	getSegementRegisterAttributes('cs', __vsm__getCS(), 0, &h_cs);
	getSegementRegisterAttributes('ss', __vsm__getSS(), 0, &h_ss);
	getSegementRegisterAttributes('ds', __vsm__getDS(), 0, &h_ds);
	getSegementRegisterAttributes('es', __vsm__getES(), 0, &h_es);
	getSegementRegisterAttributes('fs', __vsm__getFS(), 0, &h_fs);
	getSegementRegisterAttributes('gs', __vsm__getGS(), 0, &h_gs);
	getSegementRegisterAttributes('ldtr', __vsm__getLDTR(), 0, &h_ldtr);
	getSegementRegisterAttributes('tr', __vsm__getTR(), 0, &h_tr);
	__vmx_vmwrite(HOST_CR0, __readcr0());
	__vmx_vmwrite(HOST_CR3, __readcr3());
	__vmx_vmwrite(HOST_CR4, __readcr4());
	__vmx_vmwrite(HOST_RSP, (PVOID)vCpu[j].virtualHostStackBottom);
	__vmx_vmwrite(HOST_RIP, (PVOID)__vsm__hostEntry);
	__vmx_vmwrite(HOST_CS_SELECTOR, h_cs.selector & 0xFFF8);
	__vmx_vmwrite(HOST_SS_SELECTOR, h_ss.selector & 0xFFF8);
	__vmx_vmwrite(HOST_DS_SELECTOR, h_ds.selector & 0xFFF8);
	__vmx_vmwrite(HOST_ES_SELECTOR, h_es.selector & 0xFFF8);
	__vmx_vmwrite(HOST_FS_SELECTOR, h_fs.selector & 0xFFF8);
	__vmx_vmwrite(HOST_GS_SELECTOR, h_gs.selector & 0xFFF8);
	__vmx_vmwrite(HOST_TR_SELECTOR, h_tr.selector & 0xFFF8);
	__vmx_vmwrite(HOST_FS_BASE_ADDRESS, __readmsr(IA32_FS_BASE));
	__vmx_vmwrite(HOST_GS_BASE_ADDRESS, __readmsr(IA32_GS_BASE));
	__vmx_vmwrite(HOST_TR_BASE_ADDRESS, (PVOID)h_tr.baseAddress);
	__vmx_vmwrite(HOST_GDTR_BASE_ADDRESS, (PVOID)__vsm__getGDTbase());
	__vmx_vmwrite(HOST_IDTR_BASE_ADDRESS, (PVOID)__vsm__getIDTbase());
	/*5.Guest-State Area字段*/
	getSegementRegisterAttributes('cs', __vsm__getCS(), 1, &g_cs);
	getSegementRegisterAttributes('ss', __vsm__getSS(), 1, &g_ss);
	getSegementRegisterAttributes('ds', __vsm__getDS(), 1, &g_ds);
	getSegementRegisterAttributes('es', __vsm__getES(), 1, &g_es);
	getSegementRegisterAttributes('fs', __vsm__getFS(), 0, &g_fs);
	getSegementRegisterAttributes('gs', __vsm__getGS(), 0, &g_gs);
	getSegementRegisterAttributes('ldtr', __vsm__getLDTR(), 1, &g_ldtr);
	getSegementRegisterAttributes('tr', __vsm__getTR(), 0, &g_tr);
	//选择子
	__vmx_vmwrite(GUEST_FS_SELECTOR, g_fs.selector);
	__vmx_vmwrite(GUEST_GS_SELECTOR, g_gs.selector);
	__vmx_vmwrite(GUEST_TR_SELECTOR, g_tr.selector);
	//基地址
	__vmx_vmwrite(GUEST_FS_BASE_ADDRESS, __readmsr(IA32_FS_BASE));
	__vmx_vmwrite(GUEST_GS_BASE_ADDRESS, __readmsr(IA32_GS_BASE));
	__vmx_vmwrite(GUEST_TR_BASE_ADDRESS, (PVOID)g_tr.baseAddress);
	//限制
	__vmx_vmwrite(GUEST_FS_SEGEMENT_LIMIT, g_fs.segementLimit);
	__vmx_vmwrite(GUEST_GS_SEGEMENT_LIMIT, g_gs.segementLimit);
	__vmx_vmwrite(GUEST_TR_SEGEMENT_LIMIT, g_tr.segementLimit);
	//权限
	__vmx_vmwrite(GUEST_CS_ACCESS_RIGHTS, g_cs.accessRight & ~0xF00ull);
	__vmx_vmwrite(GUEST_SS_ACCESS_RIGHTS, g_ss.accessRight & ~0xF00ull);
	__vmx_vmwrite(GUEST_DS_ACCESS_RIGHTS, g_ds.accessRight & ~0xF00ull);
	__vmx_vmwrite(GUEST_ES_ACCESS_RIGHTS, g_es.accessRight & ~0xF00ull);
	__vmx_vmwrite(GUEST_FS_ACCESS_RIGHTS, g_fs.accessRight & ~0xF00ull);
	__vmx_vmwrite(GUEST_GS_ACCESS_RIGHTS, g_gs.accessRight & ~0xF00ull);
	__vmx_vmwrite(GUEST_LDTR_ACCESS_RIGHTS, g_ldtr.accessRight & ~0xF00ull);
	__vmx_vmwrite(GUEST_TR_ACCESS_RIGHTS, g_tr.accessRight & ~0xF00ull);
	//G/IDT表
	__vmx_vmwrite(GUEST_GDTR_BASE, __vsm__getGDTbase());
	__vmx_vmwrite(GUEST_IDTR_BASE, __vsm__getIDTbase());
	__vmx_vmwrite(GUEST_GDTR_LIMIT, __vsm__getGDTlimit()); //28.3.1.3
	__vmx_vmwrite(GUEST_IDTR_LIMIT, __vsm__getIDTlimit()); //28.3.1.3
	//其他
	__vmx_vmwrite(GUEST_VMCS_LINK_POINTER, 0xFFFFFFFFFFFFFFFFull);
	//寄存器
	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_CR4, __readcr4());
	__vmx_vmwrite(GUEST_DR7, __vsm__getDR7());
	__vmx_vmwrite(GUEST_RFLAGS, __readeflags());
	__vmx_vmwrite(GUEST_RSP, (PVOID)vCpu[j].virtualGuestStackBottom);
	__vmx_vmwrite(GUEST_RIP, (PVOID)__vsm__guestEntry);

	__vsm__vmlaunchSaveRegisters();

	return 0;
}

VOID driverUnload(
	PDRIVER_OBJECT driverObject
)
{
	UNREFERENCED_PARAMETER(driverObject);
	KeIpiGenericCall(virtualOff, 0);
	UCHAR dt[10] = { 0 };
	for (size_t j = 0; j < totalCpuCount; j++)
	{
		KeSetSystemAffinityThread(1ull << j);
		_sgdt(&dt);
		*(USHORT*)dt = 0x57i32;
		_lgdt(&dt);
		__sidt(&dt);
		*(USHORT*)dt = 0xFFFui32;
		__lidt(&dt);
		if (vCpu[j].virtualGuestStack)
		{
			ExFreePool(vCpu[j].virtualGuestStack);
			vCpu[j].virtualGuestStack = NULL;
		}
		if (vCpu[j].virtualHostStack)
		{
			ExFreePool(vCpu[j].virtualHostStack);
			vCpu[j].virtualHostStack = NULL;
		}
		if (vCpu[j].VMX_ON_REGION_VIRTUAL_KERNEL_ADDRESS)
		{
			ExFreePool(vCpu[j].VMX_VMCS_REGION_VIRTUAL_KERNEL_ADDRESS);
			vCpu[j].VMX_VMCS_REGION_VIRTUAL_KERNEL_ADDRESS = NULL;
		}
		if (vCpu[j].VMX_ON_REGION_VIRTUAL_KERNEL_ADDRESS)
		{
			ExFreePool(vCpu[j].VMX_ON_REGION_VIRTUAL_KERNEL_ADDRESS);
			vCpu[j].VMX_ON_REGION_VIRTUAL_KERNEL_ADDRESS = NULL;
		}
	}
	if (vCpu)
	{
		ExFreePool(vCpu);
		vCpu = NULL;
	}
	if (PER_CPU_REGS)
	{
		ExFreePool(PER_CPU_REGS);
		PER_CPU_REGS = NULL;
	}
	if (tpPT)
	{
		ExFreePool((PVOID)tpPT);
		tpPT = 0;
	}
	if (tpPDT)
	{
		ExFreePool((PVOID)tpPDT);
		tpPDT = 0;
	}
	if (tpPDPT)
	{
		ExFreePool((PVOID)tpPDPT);
		tpPDPT = 0;
	}
	if (tpPML4T)
	{
		ExFreePool((PVOID)tpPML4T);
		tpPML4T = 0;
	}
	KeSetSystemAffinityThread(1ull << 0);
	return;
}

NTSTATUS DriverEntry(
	PDRIVER_OBJECT driverObject,
	PUNICODE_STRING regPath
)
{
	UNREFERENCED_PARAMETER(regPath);
	bugCheck = (ULONG_PTR)KeBugCheckEx;
	driverObject->DriverUnload = driverUnload;

	initializeMonitorAddressList();

	totalCpuCount = KeQueryActiveProcessorCount(NULL);
	PER_CPU_REGS = (ULONG_PTR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, totalCpuCount * sizeof(ULONG_PTR), 'zzaa');

	vCpu = (PVCPU)ExAllocatePool2(POOL_FLAG_NON_PAGED, totalCpuCount * sizeof(VCPU), 'zzaa');
	RtlZeroMemory(vCpu, totalCpuCount * sizeof(VCPU));

	SIZE_T regionSizeNeeded = 0x1000;
	ULONG vmcsIdentifier = (ULONG)(__readmsr(IA32_VMX_BASIC) & ~(1ull << 31));
	PHYSICAL_ADDRESS tempVmxon = { 0 };
	PHYSICAL_ADDRESS tempVmcsRegion = { 0 };

	for (size_t j = 0; j < totalCpuCount; j++)
	{
		KeSetSystemAffinityThread(1ull << j);

		vCpu[j].VMX_ON_REGION_VIRTUAL_KERNEL_ADDRESS = ExAllocatePool2(POOL_FLAG_NON_PAGED, regionSizeNeeded, 'zzaa');
		RtlZeroMemory(vCpu[j].VMX_ON_REGION_VIRTUAL_KERNEL_ADDRESS, regionSizeNeeded);
		tempVmxon = MmGetPhysicalAddress(vCpu[j].VMX_ON_REGION_VIRTUAL_KERNEL_ADDRESS);
		vCpu[j].VMX_ON_REGION_PHYSICAL_ADDRESS = tempVmxon.QuadPart;

		vCpu[j].VMX_VMCS_REGION_VIRTUAL_KERNEL_ADDRESS = ExAllocatePool2(POOL_FLAG_NON_PAGED, regionSizeNeeded, 'zzaa');
		RtlZeroMemory(vCpu[j].VMX_VMCS_REGION_VIRTUAL_KERNEL_ADDRESS, regionSizeNeeded);
		tempVmcsRegion = MmGetPhysicalAddress(vCpu[j].VMX_VMCS_REGION_VIRTUAL_KERNEL_ADDRESS);
		vCpu[j].VMX_VMCS_REGION_PHYSICAL_ADDRESS = tempVmcsRegion.QuadPart;

		RtlCopyMemory((PVOID)(vCpu[j].regs + 0x500), (PVOID)&vCpu[j].VMX_VMCS_REGION_PHYSICAL_ADDRESS, sizeof(ULONG_PTR));

		vCpu[j].virtualGuestStackSize = 0x5000;
		vCpu[j].virtualGuestStack = ExAllocatePool2(POOL_FLAG_NON_PAGED, vCpu[j].virtualGuestStackSize, 'zzaa');
		RtlZeroMemory(vCpu[j].virtualGuestStack, vCpu[j].virtualGuestStackSize);
		vCpu[j].virtualGuestStackBottom = (PVOID)((ULONG_PTR)vCpu[j].virtualGuestStack + vCpu[j].virtualGuestStackSize - 0x2000);

		vCpu[j].virtualHostStackSize = 0x5000;
		vCpu[j].virtualHostStack = ExAllocatePool2(POOL_FLAG_NON_PAGED, vCpu[j].virtualHostStackSize, 'zzaa');
		RtlZeroMemory(vCpu[j].virtualHostStack, vCpu[j].virtualHostStackSize);
		vCpu[j].virtualHostStackBottom = (PVOID)((ULONG_PTR)vCpu[j].virtualHostStack + vCpu[j].virtualHostStackSize - 0x2000);

		PER_CPU_REGS[j] = (ULONG_PTR)vCpu[j].regs;

		*(ULONG*)vCpu[j].VMX_ON_REGION_VIRTUAL_KERNEL_ADDRESS = vmcsIdentifier;
		*(ULONG*)vCpu[j].VMX_VMCS_REGION_VIRTUAL_KERNEL_ADDRESS = vmcsIdentifier;
	}

	KeSetSystemAffinityThread(1ull << 0);

	SIZE_T PDTpages = 32;

	ULONG_PTR pPML4T = allocatePages(1);
	ULONG_PTR pPDPT = allocatePages(1);
	ULONG_PTR pPDT = allocatePages(PDTpages);
	ULONG_PTR pPT = allocatePages(PDTpages * 512);

	tpPML4T = pPML4T;
	tpPDPT = pPDPT;
	tpPDT = pPDT;
	tpPT = pPT;

	*(ULONG_PTR*)pPML4T = pPDPT;
	for (size_t i = 0; i < PDTpages; i++)
	{
		((ULONG_PTR*)pPDPT)[i] = pPDT + i * PAGE_SIZE;
	}
	for (size_t i = 0; i < PDTpages * 512; i++)
	{
		((ULONG_PTR*)pPDT)[i] = pPT + i * PAGE_SIZE;
	}
	for (size_t pteIndex = 0; pteIndex < PDTpages * 512 * 512; pteIndex++)
	{
		size_t BIT_20_12 = pteIndex % 512;
		size_t BIT_29_21 = (pteIndex / 512) % 512;
		size_t BIT_38_30 = (pteIndex / 0x40000) % 512;
		ULONG_PTR phyPageAddress = (ULONG_PTR)(((BIT_38_30 << 30) + (BIT_29_21 << 21) + (BIT_20_12 << 12)) & ~0xFFFull);
		UCHAR cacheType = getPhysicalMemoryCacheType((ULONG_PTR)phyPageAddress);
		((ULONG_PTR*)pPT)[pteIndex] = phyPageAddress | RWX | ((ULONG64)cacheType << 3);
	}
	for (size_t i = 0; i < PDTpages * 512; i++)
	{
		((ULONG_PTR*)pPDT)[i] = (ULONG_PTR)MmGetPhysicalAddress((PVOID)((ULONG_PTR*)pPDT)[i]).QuadPart | 0x7;
	}
	for (size_t i = 0; i < PDTpages; i++)
	{
		((ULONG_PTR*)pPDPT)[i] = (ULONG_PTR)MmGetPhysicalAddress((PVOID)((ULONG_PTR*)pPDPT)[i]).QuadPart | 0x7;
	}

	*(ULONG_PTR*)pPML4T = (ULONG_PTR)MmGetPhysicalAddress((PVOID) * (ULONG_PTR*)pPML4T).QuadPart | 0x7;
	pPML4T = (ULONG_PTR)MmGetPhysicalAddress((PVOID)pPML4T).QuadPart;
	ept = pPML4T;

	KeIpiGenericCall(virtualization, 0);

	return STATUS_SUCCESS;
}