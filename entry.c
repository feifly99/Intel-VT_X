#include "IA32.h"
#include "DT.h"

#pragma warning(disable: 28182)
#pragma warning(disable: 6387)
#pragma warning(disable: 6011)
#pragma warning(disable: 4996)

ULONG_PTR bugCheck = 0;
ULONG64 GlobalDebugWindow = 0xBBBBBBBB;

ULONG64 DRIVER_RIP = 0;

ULONG64 tempFLAGS = 0;

ULONG GUEST_RIP_INDEX = GUEST_RIP;
ULONG GUEST_RSP_INDEX = GUEST_RSP;
ULONG GUEST_RFLAGS_INDEX = GUEST_RFLAGS;
ULONG HOST_RIP_INDEX =  HOST_RIP;
ULONG HOST_RSP_INDEX =  HOST_RSP;
ULONG VM_EXIT_REASON_INDEX = VEIF_EXIT_REASON;
ULONG VM_EXIT_QUALIFICATION_INDEX = VEIF_EXIT_QUALIFICATION;
ULONG VM_INSTRUCTION_LENGTH_INDEX = VEIF_VM_EXIT_INSTRUCTION_LENGTH;

ULONG64 __RAX	 = 0;
ULONG64 __RBX	 = 0;
ULONG64 __RCX	 = 0;
ULONG64 __RDX	 = 0;
ULONG64 __RSI	 = 0;
ULONG64 __RDI	 = 0;
ULONG64 __RSP	 = 0;
ULONG64 __RBP	 = 0;
ULONG64 __R8	 = 0;
ULONG64 __R9	 = 0;
ULONG64 __R10	 = 0;
ULONG64 __R11	 = 0;
ULONG64 __R12	 = 0;
ULONG64 __R13	 = 0;
ULONG64 __R14	 = 0;
ULONG64 __R15	 = 0;
ULONG64 __RFLAGS = 0;

int times = 0;
int mss = 0x4F1C7752;

#define print(s) \
do\
{\
	ULONG64 ______________x = (s);\
	DbgPrint("%s [%llu] [0x%p] <- \n", #s, ______________x, (PVOID)______________x);\
}while(0)

PVCPU vCpus = NULL;

VOID driverUnload(PDRIVER_OBJECT driverObject)
{
	UNREFERENCED_PARAMETER(driverObject);
	return;
}

VOID getSegementRegisterAttributes(
	IN SEGEMENT_TYPE type,
	IN ULONG64 selector,
	IN UCHAR usable,
	IN OUT SRA* sra
)
{
	if (type == 'cs' || type == 'ss' || type == 'ds' || type == 'es')
	{
		ULONG_PTR GDTbase = __vsm__getGDTbase();
		ULONG64 index = selector >> 3;
		ULONG_PTR currentSelectorGdtEntryPointer = GDTbase + index * 8; //8: magic number defined in INTEL® SDL
		ULONG64 currentSelectorGdtEntry = *(ULONG64*)currentSelectorGdtEntryPointer;
		sra->selector = (USHORT)selector;
		sra->baseAddress = (ULONG_PTR)(((currentSelectorGdtEntry >> 16) & 0xFFFFFFull) + ((currentSelectorGdtEntry & 0xFF00000000000000ull) >> 32));
		ULONG segementLimitTemp = (ULONG)((currentSelectorGdtEntry & 0xFFFFull));
		if (currentSelectorGdtEntry & 0x000F000000000000ull)
		{
			sra->segementLimit = segementLimitTemp | 0xFFFF0000ul;
		}
		else
		{
			sra->segementLimit = segementLimitTemp;
		}
		sra->accessRight = (ULONG)((currentSelectorGdtEntry >> 40) & 0xFFFFull);
		if (usable)
		{
			sra->accessRight |= 0x10000ul;
		}
	}
	if (type == 'fs' || type == 'gs')
	{
		ULONG_PTR GDTbase = __vsm__getGDTbase();
		ULONG64 index = selector >> 3;
		ULONG_PTR currentSelectorGdtEntryPointer = GDTbase + index * 8; //8: magic number defined in INTEL® SDL
		ULONG64 currentSelectorGdtEntry = *(ULONG64*)currentSelectorGdtEntryPointer;
		sra->selector = (USHORT)selector;
		sra->baseAddress = 0; //需要从MSRs读取
		ULONG segementLimitTemp = (ULONG)((currentSelectorGdtEntry & 0xFFFFull));
		if (currentSelectorGdtEntry & 0x000F000000000000ull)
		{
			sra->segementLimit = segementLimitTemp | 0xFFFF0000ul;
		}
		else
		{
			sra->segementLimit = segementLimitTemp;
		}
		sra->accessRight = (ULONG)((currentSelectorGdtEntry >> 40) & 0xFFFFull);
		if (usable)
		{
			sra->accessRight |= 0x10000ul;
		}
	}
	if (type == 'ldtr')
	{
		ULONG_PTR GDTbase = __vsm__getGDTbase();
		ULONG64 index = selector >> 3;
		ULONG_PTR currentSelectorGdtEntryPointer = GDTbase + index * 8; //8: magic number defined in INTEL® SDL
		ULONG64 currentSelectorGdtEntry = *(ULONG64*)currentSelectorGdtEntryPointer;
		sra->selector = (USHORT)selector;
		sra->baseAddress = (ULONG_PTR)(((currentSelectorGdtEntry >> 16) & 0xFFFFFFull) + ((currentSelectorGdtEntry & 0xFF00000000000000ull) >> 32));
		ULONG segementLimitTemp = (ULONG)((currentSelectorGdtEntry & 0xFFFFull));
		if (currentSelectorGdtEntry & 0x000F000000000000ull)
		{
			sra->segementLimit = segementLimitTemp | 0xFFFF0000ul;
		}
		else
		{
			sra->segementLimit = segementLimitTemp;
		}
		sra->accessRight = (ULONG)((currentSelectorGdtEntry >> 40) & 0xFFFFull);
		if (usable)
		{
			sra->accessRight |= 0x10000ul;
		}
	}
	if (type == 'tr')
	{
		ULONG_PTR GDTbase = __vsm__getGDTbase();
		ULONG64 index = selector >> 3;
		ULONG_PTR currentSelectorGdtEntryPointer = GDTbase + index * 8; //8: magic number defined in INTEL® SDL
		ULONG64 currentSelectorGdtEntry = *(ULONG64*)currentSelectorGdtEntryPointer;
		sra->selector = (USHORT)selector;
		print(currentSelectorGdtEntryPointer);
		print(currentSelectorGdtEntry);
		sra->baseAddress = (*(ULONG_PTR*)(currentSelectorGdtEntryPointer + 8)) << 32;
		print(sra->baseAddress);
		sra->baseAddress += (ULONG_PTR)(((currentSelectorGdtEntry >> 16) & 0xFFFFFFull) + ((currentSelectorGdtEntry & 0xFF00000000000000ull) >> 32));
		print(sra->baseAddress);
		ULONG segementLimitTemp = (ULONG)((currentSelectorGdtEntry & 0xFFFFull));
		if (currentSelectorGdtEntry & 0x000F000000000000ull)
		{
			sra->segementLimit = segementLimitTemp | 0xFFFF0000ul;
		}
		else
		{
			sra->segementLimit = segementLimitTemp;
		}
		sra->accessRight = (ULONG)((currentSelectorGdtEntry >> 40) & 0xFFFFull);
		if (usable)
		{
			sra->accessRight |= 0x10000ul;
		}
	}
	return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING regPath)
{
	bugCheck = (ULONG_PTR)KeBugCheckEx;

	UNREFERENCED_PARAMETER(regPath);
	driverObject->DriverUnload = driverUnload;

	if (__vasm__isVMXOperationsSupported() == 1)
	{
		DbgPrint("此CPU架构支持VMXE模式！\n");
	}
	else
	{
		DbgPrint("此CPU架构不支持VMXE模式！\n");
	}
	ULONG totalCpuCount = KeQueryActiveProcessorCount(NULL);
	vCpus = (PVCPU)ExAllocatePoolWithTag(NonPagedPool, totalCpuCount * sizeof(VCPU), 'z+aa');
	RtlZeroMemory(vCpus, totalCpuCount * sizeof(VCPU));
	print(totalCpuCount);
	SIZE_T regionSizeNeeded = 0x1000;
	ULONG vmcsIdentifier = (ULONG)1;
	//初始化虚拟CPU的属性
	for (size_t j = 0; j < totalCpuCount; j++)
	{
		vCpus[j].currentCr4 = __vsm__getCR4();

		vCpus[j].VMX_ON_REGION_VIRTUAL_KERNEL_ADDRESS = ExAllocatePoolWithTag(NonPagedPool, regionSizeNeeded, 'vmon');
		RtlZeroMemory(vCpus[j].VMX_ON_REGION_VIRTUAL_KERNEL_ADDRESS, regionSizeNeeded);
		PHYSICAL_ADDRESS tempVmxon = { 0 };
		tempVmxon = MmGetPhysicalAddress(vCpus[j].VMX_ON_REGION_VIRTUAL_KERNEL_ADDRESS);
		vCpus[j].VMX_ON_REGION_PHYSICAL_ADDRESS = tempVmxon.QuadPart;

		vCpus[j].VMX_VMCS_REGION_VIRTUAL_KERNEL_ADDRESS = ExAllocatePoolWithTag(NonPagedPool, regionSizeNeeded, 'vmcs');
		RtlZeroMemory(vCpus[j].VMX_VMCS_REGION_VIRTUAL_KERNEL_ADDRESS, regionSizeNeeded);
		PHYSICAL_ADDRESS tempVmcsRegion = { 0 };
		tempVmcsRegion = MmGetPhysicalAddress(vCpus[j].VMX_VMCS_REGION_VIRTUAL_KERNEL_ADDRESS);
		vCpus[j].VMX_VMCS_REGION_PHYSICAL_ADDRESS = tempVmcsRegion.QuadPart;

		vCpus[j].virtualGuestStackSize = 0x5000;
		vCpus[j].virtualGuestStack = ExAllocatePoolWithTag(NonPagedPool, vCpus[j].virtualGuestStackSize, 'gstk');
		RtlZeroMemory(vCpus[j].virtualGuestStack, vCpus[j].virtualGuestStackSize);
		vCpus[j].virtualGuestStackBottom = (PVOID)((ULONG_PTR)vCpus[j].virtualGuestStack + vCpus[j].virtualGuestStackSize - 0x1000);

		vCpus[j].virtualHostStackSize = 0x5000;
		vCpus[j].virtualHostStack = ExAllocatePoolWithTag(NonPagedPool, vCpus[j].virtualHostStackSize, 'hstk');
		RtlZeroMemory(vCpus[j].virtualHostStack, vCpus[j].virtualHostStackSize);
		vCpus[j].virtualHostStackBottom = (PVOID)((ULONG_PTR)vCpus[j].virtualHostStack + vCpus[j].virtualHostStackSize - 0x1000);

		*(ULONG*)vCpus[j].VMX_ON_REGION_VIRTUAL_KERNEL_ADDRESS = vmcsIdentifier;
		*(ULONG*)vCpus[j].VMX_VMCS_REGION_VIRTUAL_KERNEL_ADDRESS = vmcsIdentifier;
	}
	//开启CR4.VMXE位
	for (size_t j = 0; j < totalCpuCount; j++)
	{
		KeSetSystemAffinityThread((KAFFINITY)(1 << j));
		__vasm__setCR4VMXEBit();
		vCpus[j].currentCr4 = __vsm__getCR4();
		__vmx_on(&vCpus[j].VMX_ON_REGION_PHYSICAL_ADDRESS);
	}
	//选择一个虚拟CPU的VMCS作为`current VMCS`
	KAFFINITY currentVMCSCpuIndex = 1;
	KeSetSystemAffinityThread((KAFFINITY)(1 << currentVMCSCpuIndex));
	__vmx_vmclear(&vCpus[currentVMCSCpuIndex].VMX_VMCS_REGION_PHYSICAL_ADDRESS);
	__vmx_vmptrld(&vCpus[currentVMCSCpuIndex].VMX_VMCS_REGION_PHYSICAL_ADDRESS);
	//写入VMCS各个字段
	/*1.VM-Exit Control字段*/
	__vmx_vmwrite(VExCF_PRIMARY_VM_EXIT_CONTROLS, 0x36FFBul); //物理机 0x36FFB
	/*2.VM-Entry Control字段*/
	__vmx_vmwrite(VEnCF_VM_ENTRY_CONTROLS, 0x13FBul); //物理机 0x13FBul
	/*3.VM-Execution Control字段*/
	__vmx_vmwrite(VECF_PIN_BASED_VM_EXECUTION_CONTROL, 0x16ul); //物理机 0x16ul
	__vmx_vmwrite(VECF_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, 0x84026172ul); //物理机 0x4006172ul
	__vmx_vmwrite(VECF_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, 0xC101008ul); //物理机 0x4006172ul
	__vmx_vmwrite(VECF_TERTIARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, 0x40ul); //物理机 0x4006172ul
	/*PVOID msrBitmap = ExAllocatePoolWithTag(NonPagedPool, 0x4000, 'msrs');
	memset(msrBitmap, 0xFF, 0x4000);
	PHYSICAL_ADDRESS msrBitmapPhy = MmGetPhysicalAddress(msrBitmap);
	__vmx_vmwrite(VECF_MSR_BITMAPS, msrBitmapPhy.QuadPart);*/
	/*4.Host-State Area字段*/
	SRA h_cs, h_ss, h_ds, h_es, h_fs, h_gs, h_ldtr, h_tr;
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
	__vmx_vmwrite(HOST_RSP, (PVOID)vCpus[currentVMCSCpuIndex].virtualHostStackBottom);
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
	SRA g_cs = { 0 }, g_ss = { 0 }, g_ds = { 0 }, g_es = { 0 }, g_fs = { 0 }, g_gs = { 0 }, g_ldtr = { 0 }, g_tr = { 0 };
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
	__vmx_vmwrite(GUEST_RSP, (PVOID)vCpus[currentVMCSCpuIndex].virtualGuestStackBottom);
	__vmx_vmwrite(GUEST_RIP, (PVOID)__vsm__guestEntry);

	__vsm__vmlaunchSaveRegisters();
	
	__vsm__trap();

	return STATUS_SUCCESS;	
}
