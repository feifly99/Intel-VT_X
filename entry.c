#include "IA32.h"
#include "DT.h"

#pragma warning(disable: 28182)
#pragma warning(disable: 6387)
#pragma warning(disable: 6011)
#pragma warning(disable: 4996)

ULONG_PTR KeBugCheckExAddress = 0;

#define print(s) \
do\
{\
	ULONG64 ______________x = (s);\
	DbgPrint("[%llu] [0x%p] <- %s\n", ______________x, (PVOID)______________x, #s);\
}while(0)

PVCPU vCpus = NULL;

VOID driverUnload(PDRIVER_OBJECT driverObject)
{
	UNREFERENCED_PARAMETER(driverObject);
	return;
}

VOID getSegementRegisterAttributes(
	IN ULONG64 selector,
	IN UCHAR isSegementUsed,
	IN OUT SRA* sra
)
{
	ULONG_PTR GDTbase = __vsm__getGDTbase();
	ULONG64 index = selector >> 3; 
	ULONG_PTR currentSelectorGdtEntryPointer = GDTbase + index * 8; //8: magic number defined in INTEL® SDL
	ULONG64 currentSelectorGdtEntry = *(ULONG64*)currentSelectorGdtEntryPointer;
	sra->selector = (USHORT)selector;
	sra->baseAddress = (ULONG)(((currentSelectorGdtEntry >> 16) & 0xFFFFFFull) + ((currentSelectorGdtEntry & 0xFF00000000000000ull) >> 32));
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
	sra->accessRight |= (isSegementUsed ? 0x10000ul : 0);
	return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING regPath)
{
	KeBugCheckExAddress = (ULONG_PTR)KeBugCheckEx;
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
	__vmx_vmwrite(VECF_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS, 0x4006172ul); //物理机 0x4006172ul
	/*4.Host-State Area字段*/
	SRA h_cs, h_ss, h_ds, h_es, h_fs, h_gs, h_ldtr, h_tr;
	getSegementRegisterAttributes(__vsm__getCS(), USED, &h_cs);
	getSegementRegisterAttributes(__vsm__getSS(), UNUSED, &h_ss);
	getSegementRegisterAttributes(__vsm__getDS(), UNUSED, &h_ds);
	getSegementRegisterAttributes(__vsm__getES(), UNUSED, &h_es);
	getSegementRegisterAttributes(__vsm__getFS(), USED, &h_fs);
	getSegementRegisterAttributes(__vsm__getGS(), UNUSED, &h_gs);
	getSegementRegisterAttributes(__vsm__getLDTR(), UNUSED, &h_ldtr);
	getSegementRegisterAttributes(__vsm__getTR(), UNUSED, &h_tr);
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
	/*SRA g_cs = { 0 }, g_ss = { 0 }, g_ds = { 0 }, g_es = { 0 }, g_fs = { 0 }, g_gs = { 0 }, g_ldtr = { 0 }, g_tr = { 0 };
	getSegementRegisterAttributes(__vsm__getCS(), USED, &g_cs);
	getSegementRegisterAttributes(__vsm__getSS(), UNUSED, &g_ss);
	getSegementRegisterAttributes(__vsm__getDS(), UNUSED, &g_ds);
	getSegementRegisterAttributes(__vsm__getES(), UNUSED, &g_es);
	getSegementRegisterAttributes(__vsm__getFS(), USED, &g_fs);
	getSegementRegisterAttributes(__vsm__getGS(), UNUSED, &g_gs);
	getSegementRegisterAttributes(__vsm__getLDTR(), UNUSED, &g_ldtr);
	getSegementRegisterAttributes(__vsm__getTR(), UNUSED, &g_tr);
	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_CR4, __readcr4());
	__vmx_vmwrite(GUEST_DR7, __readdr(7));
	__vmx_vmwrite(GUEST_RFLAGS, __readeflags());
	__vmx_vmwrite(GUEST_RSP, (ULONG64)vCpus[currentVMCSCpuIndex].virtualGuestStackBottom);
	__vmx_vmwrite(GUEST_RIP, (ULONG64)guests);
	__vmx_vmwrite(GUEST_CS_SELECTOR, (ULONG64)g_cs.selector);
	__vmx_vmwrite(GUEST_SS_SELECTOR, (ULONG64)g_ss.selector);
	__vmx_vmwrite(GUEST_DS_SELECTOR, (ULONG64)g_ds.selector);
	__vmx_vmwrite(GUEST_ES_SELECTOR, (ULONG64)g_es.selector);
	__vmx_vmwrite(GUEST_FS_SELECTOR, (ULONG64)g_fs.selector);
	__vmx_vmwrite(GUEST_GS_SELECTOR, (ULONG64)g_gs.selector);
	__vmx_vmwrite(GUEST_LDTR_SELECTOR, (ULONG64)g_ldtr.selector);
	__vmx_vmwrite(GUEST_TR_SELECTOR, (ULONG64)g_tr.selector);
	__vmx_vmwrite(GUEST_CS_BASE_ADDRESS, (ULONG64)g_cs.baseAddress & 0xFFFFFFFFull);
	__vmx_vmwrite(GUEST_SS_BASE_ADDRESS, (ULONG64)g_ss.baseAddress & 0xFFFFFFFFull);
	__vmx_vmwrite(GUEST_DS_BASE_ADDRESS, (ULONG64)g_ds.baseAddress & 0xFFFFFFFFull);
	__vmx_vmwrite(GUEST_ES_BASE_ADDRESS, (ULONG64)g_es.baseAddress & 0xFFFFFFFFull);
	__vmx_vmwrite(GUEST_FS_BASE_ADDRESS, (ULONG64)g_fs.baseAddress);
	__vmx_vmwrite(GUEST_GS_BASE_ADDRESS, (ULONG64)g_gs.baseAddress);
	__vmx_vmwrite(GUEST_LDTR_BASE_ADDRESS, (ULONG64)g_ldtr.baseAddress);
	__vmx_vmwrite(GUEST_TR_BASE_ADDRESS, (ULONG64)g_tr.baseAddress);
	__vmx_vmwrite(GUEST_CS_SEGEMENT_LIMIT, (ULONG64)g_cs.segementLimit);
	__vmx_vmwrite(GUEST_SS_SEGEMENT_LIMIT, (ULONG64)g_ss.segementLimit);
	__vmx_vmwrite(GUEST_DS_SEGEMENT_LIMIT, (ULONG64)g_ds.segementLimit);
	__vmx_vmwrite(GUEST_ES_SEGEMENT_LIMIT, (ULONG64)g_es.segementLimit);
	__vmx_vmwrite(GUEST_FS_SEGEMENT_LIMIT, (ULONG64)g_fs.segementLimit);
	__vmx_vmwrite(GUEST_GS_SEGEMENT_LIMIT, (ULONG64)g_gs.segementLimit);
	__vmx_vmwrite(GUEST_LDTR_SEGEMENT_LIMIT, (ULONG64)g_ldtr.segementLimit);
	__vmx_vmwrite(GUEST_TR_SEGEMENT_LIMIT, (ULONG64)g_tr.segementLimit);
	__vmx_vmwrite(GUEST_CS_ACCESS_RIGHTS, (ULONG64)g_cs.accessRight);
	__vmx_vmwrite(GUEST_SS_ACCESS_RIGHTS, (ULONG64)g_ss.accessRight);
	__vmx_vmwrite(GUEST_DS_ACCESS_RIGHTS, (ULONG64)g_ds.accessRight);
	__vmx_vmwrite(GUEST_ES_ACCESS_RIGHTS, (ULONG64)g_es.accessRight);
	__vmx_vmwrite(GUEST_FS_ACCESS_RIGHTS, (ULONG64)g_fs.accessRight);
	__vmx_vmwrite(GUEST_GS_ACCESS_RIGHTS, (ULONG64)g_gs.accessRight);
	__vmx_vmwrite(GUEST_LDTR_ACCESS_RIGHTS, (ULONG64)g_ldtr.accessRight);
	__vmx_vmwrite(GUEST_TR_ACCESS_RIGHTS, (ULONG64)g_tr.accessRight);
	__vmx_vmwrite(GUEST_GDTR_BASE, __vsm__getGDTbase());
	__vmx_vmwrite(GUEST_IDTR_BASE, __vsm__getIDTbase());
	__vmx_vmwrite(GUEST_GDTR_LIMIT, __vsm__getGDTlimit() & ~0xFFFF0000ull);
	__vmx_vmwrite(GUEST_IDTR_LIMIT, __vsm__getIDTlimit() & ~0xFFFF0000ull);
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(IA32_DEBUGCTL));
	__vmx_vmwrite(GUEST_VMCS_LINK_POINTER, 0xFFFFFFFFFFFFFFFFull);*/

	__vsm__NOP();
	print(__vmx_vmlaunch());
	ULONG64 error = 0;
	__vmx_vmread(VEIF_VM_INSTRUCTION_ERROR_FIELD, &error);
	print(error);

	return STATUS_SUCCESS;
}
