#ifndef __INTEL_IA32_BASIC_INDEX__
#define __INTEL_IA32_BASIC_INDEX__

#include "base.h"

#define EACH_CPU_REGS_COUNT 21

extern ULONG64 __vsm__trap();
extern ULONG64 __vsm__vmcall();
extern VOID __vsm__CLI();
extern VOID __vsm__STI();
extern VOID __vsm__checkRSPaligned();
extern VOID __vsm__breakStack(INT a, INT b);
extern VOID __vsm__SetGlobalDebugWindow();
extern VOID __vsm__vmlaunchSaveRegisters();
extern VOID __vsm__vmxoffSaveRegisters();
extern ULONG64 __vasm__isVMXOperationsSupported();
extern ULONG64 __vasm__setCR4VMXEBit();
extern ULONG64 __vsm__getCR4();
extern VOID __vsm__restoreCR4();
extern ULONG64 __vsm__getDR7();
extern USHORT __vsm__getCS();
extern USHORT __vsm__getSS();
extern USHORT __vsm__getDS();
extern USHORT __vsm__getES();
extern USHORT __vsm__getFS();
extern USHORT __vsm__getGS();
extern USHORT __vsm__getLDTR();
extern USHORT __vsm__getTR();
extern ULONG64 __vsm__getGDTbase();
extern ULONG __vsm__getGDTlimit();
extern ULONG64 __vsm__getIDTbase();
extern ULONG __vsm__getIDTlimit();
extern ULONG64 __vsm__vmLaunch();
extern ULONG64 __vsm__guestEntry();
extern ULONG64 __vsm__hostEntry();
extern ULONG64 __vsm__NOP();
extern VOID __vsm__INT3();
extern ULONG64 __vsm__testX2APICmode();

VOID __fastcall runRoutineForAllCpus(
	IN VOID(__fastcall* eachCpuRoutine)(PVOID),
	IN PVOID args
);

VOID __fastcall runRoutineAtPreciseCpu(
	IN VOID(__fastcall* routine)(PVOID),
	IN PVOID args,
	IN ULONG targetCpuIndex
);

VOID __fastcall checkCurrCpuIndex(
	IN PVOID args
);

VOID ExFreeMemory(
	OUT PVOID* mem
);

typedef struct _PAGE
{
	UCHAR page[0x1000];
}PAGE, *PPAGE;

typedef struct _SEGEMENT_REGISTER_ATTRIBUTES
{
	USHORT selector;
	ULONG segementLimit;
	ULONG_PTR baseAddress;
	ULONG accessRight;
}SRA, * PSRA;

typedef enum _SEGEMENT_TYPE
{
	SEG_CS = 'cs',
	SEG_SS = 'ss',
	SEG_DS = 'ds',
	SEG_ES = 'es',
	SEG_FS = 'fs',
	SEG_GS = 'gs',
	SEG_LDTR = 'ldtr',
	SEG_TR = 'tr'
}SEGEMENT_TYPE;

typedef struct _VIRTUAL_CPU_STRUCT
{
	ULONG64 currentCr4;
	LONG_PTR VMX_ON_REGION_PHYSICAL_ADDRESS;
	PVOID VMX_ON_REGION_VIRTUAL_KERNEL_ADDRESS;
	LONG_PTR VMX_VMCS_REGION_PHYSICAL_ADDRESS;
	PVOID VMX_VMCS_REGION_VIRTUAL_KERNEL_ADDRESS;
	PVOID virtualGuestStack;
	SIZE_T virtualGuestStackSize;
	PVOID virtualGuestStackBottom;
	PVOID virtualHostStack;
	SIZE_T virtualHostStackSize;
	PVOID virtualHostStackBottom;
	ULONG64 regs[EACH_CPU_REGS_COUNT];
}VCPU, *PVCPU;

typedef enum _IA32_INDEXES
{
	IA32_APIC_BASE											= 0x001B, //00000000`FEE00C00
	IA32_FEATURE_CONTROL									= 0x003A, //00000000`00020005
	IA32_SPEC_CTRL											= 0x0048, //0
	IA32_SYSENTER_CS										= 0x0174, //0
	IA32_SYSENTER_ESP										= 0x0175, //0
	IA32_SYSENTER_EIP										= 0x0176, //0
	IA32_PERF_STATUS										= 0x0198, //00002420`00002300
	IA32_PERF_CTL											= 0x0199, //00000000`00001A00
	IA32_MISC_ENABLE										= 0x01A0, //00000000`00850089
	IA32_DEBUGCTL											= 0x01D9, //0
	IA32_PAT												= 0x0277, //00070106`00070106
	IA32_FIXED_CTR_CTRL										= 0x038D, //0
	IA32_PERF_GLOBAL_STATUS									= 0x038E, //0
	IA32_PERF_GLOBAL_CTRL									= 0x038F, //00000000`0000000f
	IA32_PERF_GLOBAL_STATUS_RESET							= 0x0390, //0
	IA32_PERF_GLOBAL_STATUS_SET								= 0x0391, //0
	IA32_PERF_GLOBAL_INUSE									= 0x0392, //0
	IA32_VMX_BASIC											= 0x0480, //00DA0400`00000004
	IA32_VMX_PINBASED_CTLS									= 0x0481, //0000007F`00000016
	IA32_VMX_PROCBASED_CTLS									= 0x0482, //FFF9FFFE`0401E172
	IA32_VMX_EXIT_CTLS										= 0x0483, //01FFFFFF`00036DFF
	IA32_VMX_ENTRY_CTLS										= 0x0484, //0003FFFF`000011FF
	IA32_VMX_MISC											= 0x0485, //00000000`7004C1E7
	IA32_VMX_CR0_FIXED0										= 0x0486, //00000000`80000021
	IA32_VMX_CR0_FIXED1										= 0x0487, //00000000`FFFFFFFF
	IA32_VMX_CR4_FIXED0										= 0x0488, //00000000`00002000
	IA32_VMX_CR4_FIXED1										= 0x0489, //00000000`003727FF
	IA32_VMX_VMCS_ENUM										= 0x048A, //00000000`0000002E
	IA32_VMX_PROCBASED_CTLS2								= 0x048B, //005FBCFF`00000000
	IA32_VMX_EPT_VPID_CAP									= 0x048C, //00000F01`06734141
	IA32_VMX_TRUE_PINBASED_CTLS								= 0x048D, //0000007f`00000016
	IA32_VMX_TRUE_PROCBASED_CTLS							= 0x048E, //fff9fffe`04006172
	IA32_VMX_TRUE_EXIT_CTLS									= 0x048F, //01FFFFFF`00036DFB
	IA32_VMX_TRUE_ENTRY_CTLS								= 0x0490, //0003FFFF`000011FB
	IA32_VMX_VMFUNC											= 0x0491, //00000000`00000001
	IA32_RTIT_OUTPUT_BASE									= 0x0560, //0
	IA32_RTIT_OUTPUT_MASK_PTRS								= 0x0561, //00000000`0000007F
	IA32_RTIT_CTL											= 0x0570, //0
	IA32_RTIT_STATUS										= 0x0571, //0
	IA32_RTIT_CR3_MATCH										= 0x0572, //0
	IA32_RTIT_ADDR0_A										= 0x0580, //0
	IA32_RTIT_ADDR0_B										= 0x0581, //0
	IA32_RTIT_ADDR1_A										= 0x0582, //0
	IA32_RTIT_ADDR1_B										= 0x0583, //0
	IA32_PM_ENABLE											= 0x0770, //00000000`00000001
	IA32_BNDCFGS											= 0x0D90, //0
	IA32_XSS												= 0x0DA0, //00000000`00000100
	IA32_EFER												= 0xC0000080, //00000000`00000d01
	IA32_FS_BASE											= 0xC0000100, //00000000`00000000
	IA32_GS_BASE											= 0xC0000101, //FFFFAD01`64090000
	IA32_KERNEL_GS_BASE										= 0xC0000102, //00000000`00350000
	IA32_TSC_AUX											= 0xC0000103  //00000000`00000006
	/*No Such MSRs*/
	//IA32_SMBASE											= 0x009E, //no such msr but VMX region referenced
	//IA32_S_CET											= 0x06A2, //no such msr but VMX region referenced
	//IA32_INTERRUPT_SSP_TABLE_ADDR							= 0x06A8, //no such msr but VMX region referenced
	//IA32_PKRS												= 0x06E1, //no such msr but VMX region referenced
}IA32_INDEXES;

typedef enum _GUEST_STATE_AREA_FIELDS
{
	GUEST_CR0												= 0x6800,
	GUEST_CR3												= 0x6802,
	GUEST_CR4												= 0x6804,

	GUEST_DR7												= 0x681A,

	GUEST_RFLAGS											= 0x6820,
	GUEST_RSP												= 0x681C,
	GUEST_RIP												= 0x681E,

	GUEST_CS_SELECTOR										= 0x0802,  //16
	GUEST_SS_SELECTOR										= 0x0804,  //16
	GUEST_DS_SELECTOR										= 0x0806,  //16
	GUEST_ES_SELECTOR										= 0x0800,  //16
	GUEST_FS_SELECTOR										= 0x0808,  //16
	GUEST_GS_SELECTOR										= 0x080A,  //16
	GUEST_LDTR_SELECTOR										= 0x080C,  //16
	GUEST_TR_SELECTOR										= 0x080E,  //16

	GUEST_CS_BASE_ADDRESS									= 0x6808,
	GUEST_SS_BASE_ADDRESS									= 0x680A,
	GUEST_DS_BASE_ADDRESS									= 0x680C,
	GUEST_ES_BASE_ADDRESS									= 0x6806,
	GUEST_FS_BASE_ADDRESS									= 0x680E,
	GUEST_GS_BASE_ADDRESS									= 0x6810,
	GUEST_LDTR_BASE_ADDRESS									= 0x6812,
	GUEST_TR_BASE_ADDRESS									= 0x6814,

	GUEST_CS_SEGEMENT_LIMIT									= 0x4802, //32
	GUEST_SS_SEGEMENT_LIMIT									= 0x4804, //32
	GUEST_DS_SEGEMENT_LIMIT									= 0x4806, //32
	GUEST_ES_SEGEMENT_LIMIT									= 0x4800, //32
	GUEST_FS_SEGEMENT_LIMIT									= 0x4808, //32
	GUEST_GS_SEGEMENT_LIMIT									= 0x480A, //32
	GUEST_LDTR_SEGEMENT_LIMIT								= 0x480C, //32
	GUEST_TR_SEGEMENT_LIMIT									= 0x480E, //32

	GUEST_CS_ACCESS_RIGHTS									= 0x4816, //32
	GUEST_SS_ACCESS_RIGHTS									= 0x4818, //32
	GUEST_DS_ACCESS_RIGHTS									= 0x481A, //32
	GUEST_ES_ACCESS_RIGHTS									= 0x4814, //32
	GUEST_FS_ACCESS_RIGHTS									= 0x481C, //32
	GUEST_GS_ACCESS_RIGHTS									= 0x481E, //32
	GUEST_LDTR_ACCESS_RIGHTS								= 0x4820, //32
	GUEST_TR_ACCESS_RIGHTS									= 0x4822, //32

	GUEST_GDTR_BASE											= 0x6816,
	GUEST_IDTR_BASE											= 0x6818,
	GUEST_GDTR_LIMIT										= 0x4810, //32
	GUEST_IDTR_LIMIT										= 0x4812, //32

	GUEST_IA32_DEBUGCTL										= 0x2802,
	GUEST_IA32_SYSENTER_CS									= 0x482A, //32
	GUEST_IA32_SYSENTER_ESP									= 0x6824,
	GUEST_IA32_SYSENTER_EIP									= 0x6826,
	GUEST_IA32_PERF_GLOBAL_CTRL								= 0x2808,
	GUEST_IA32_PAT											= 0x2804,
	GUEST_IA32_EFER											= 0x2806,
	GUEST_IA32_BNDCFGS										= 0x2812,
	GUEST_IA32_RTIT_CTL										= 0x2814,
	GUEST_IA32_LBR_CTL										= 0x2816,
  //GUEST_IA32_S_CET										= 0x6828,
  //GUEST_IA32_INTERRUPT_SSP_TABLE_ADDR						= 0x682C,
  //GUEST_IA32_PKRS											= 0x2818,

	GUEST_SHADOW_STACK_POINTER_REGISTER_SSP					= 0x682A,

  //GUEST_SMBASE											= 0x4828,

	GUEST_ACTIVATE_STATE									= 0x4826, //32
	GUEST_INTERRUPTIBILITY_STATE							= 0x4824, //32
	GUEST_PENDING_DEBUG_EXCEPTIONS							= 0x6822,
	GUEST_VMCS_LINK_POINTER									= 0x2800,
	GUEST_VMX_PREEMPTION_TIMER_VALUE						= 0x482E, //32
	GUEST_PDPTE0											= 0x280A,
	GUEST_PDPTE1											= 0x280C,
	GUEST_PDPTE2											= 0x280E,
	GUEST_PDPTE3											= 0x2810,
	GUEST_INTERRUPT_STATUS									= 0x0810,  //16
	GUEST_PML_INDEX											= 0x0812   //16
}GUEST_STATE_AREA_FIELDS;

typedef enum _HOST_STATE_AREA_FIELDS
{
	HOST_CR0												= 0x6C00,
	HOST_CR3												= 0x6C02,
	HOST_CR4												= 0x6C04,

	HOST_RSP												= 0x6C14,
	HOST_RIP												= 0x6C16,

	HOST_CS_SELECTOR										= 0x0C02,  //16
	HOST_SS_SELECTOR										= 0x0C04,  //16
	HOST_DS_SELECTOR										= 0x0C06,  //16
	HOST_ES_SELECTOR										= 0x0C00,  //16
	HOST_FS_SELECTOR										= 0x0C08,  //16
	HOST_GS_SELECTOR										= 0x0C0A,  //16
	HOST_TR_SELECTOR										= 0x0C0C,  //16

	HOST_FS_BASE_ADDRESS									= 0x6C06,
	HOST_GS_BASE_ADDRESS									= 0x6C08,
	HOST_TR_BASE_ADDRESS									= 0x6C0A,
	HOST_GDTR_BASE_ADDRESS									= 0x6C0C,
	HOST_IDTR_BASE_ADDRESS									= 0x6C0E,

	HOST_IA32_SYSENTER_CS									= 0x4C00, //32
	HOST_IA32_SYSENTER_ESP									= 0x6C10,
	HOST_IA32_SYSENTER_EIP									= 0x6C12,
	HOST_IA32_PERF_GLOBAL_CTRL								= 0x2C04,
	HOST_IA32_PAT											= 0x2C00,
	HOST_IA32_EFER											= 0x2C02,
  //HOST_IA32_S_CET											= 0x6C18,
  //HOST_IA32_INTERRUPT_SSP_TABLE_ADDR						= 0x6C1C,
  //HOST_IA32_PKRS											= 0x2C06,

	HOST_SHADOW_STACK_POINTER_REGISTER_SSP					= 0x6C1A
}HOST_STATE_AREA_FIELDS;

typedef enum _VM_EXECUTION_CONTROL_FIELDS
{
	/*Pin-Based VM-Execution Controls*/
	VECF_PIN_BASED_VM_EXECUTION_CONTROL						= 0x4000, //32
	/*Processor-Based VM-Execution Controls*/
	VECF_PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS		= 0x4002, //32
	VECF_SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS	= 0x401E, //32
	VECF_TERTIARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS		= 0x2034,
	/*Exception Bitmap*/
	VECF_EXCEPTION_BITMAP									= 0x4004, //32
	/*I/O-Bitmap Addresses*/
	VECF_IO_BITMAP_A										= 0x2000,
	VECF_IO_BITMAP_B										= 0x2002,
	/*Time-Stamp Counter Offset and Multiplier*/
	VECF_TSC_OFFSET											= 0x2010,
	VECF_TSC_MULTIPLIER										= 0x2032,
	/*Guest/Host Masks and Read Shadows for CR0 and CR4*/
	VECF_CR0_GUEST_HOST_MARK								= 0x6000,
	VECF_CR4_GUEST_HOST_MARK								= 0x6002,
	VECF_CR0_READ_SHADOW									= 0x6004,
	VECF_CR4_READ_SHADOW									= 0x6006,
	/*CR3-Target Controls*/
	VECF_CR3_TARGET_VALUE0									= 0x6008,
	VECF_CR3_TARGET_VALUE1									= 0x600A,
	VECF_CR3_TARGET_VALUE2									= 0x600C,
	VECF_CR3_TARGET_VALUE3									= 0x600E,
	VECF_CR3_TARGET_COUNT									= 0x400A, //32
	/*Controls for APIC Virtualization*/
	VECF_APIC_ACCESS_ADDRESS								= 0x2014,
	VECF_VIRTUAL_APIC_ADDRESS								= 0x2012,
	VECF_TPR_THRESHOLD										= 0x401C, //32
	VECF_EOI_EXIT_BITMAP_0									= 0x201C,
	VECF_EOI_EXIT_BITMAP_1									= 0x201E,
	VECF_EOI_EXIT_BITMAP_2									= 0x2020,
	VECF_EOI_EXIT_BITMAP_3									= 0x2022,
	VECF_POSTED_INTERRUPT_NOTIFICATION_VECTOR				= 0x0002, //16
	VECF_POSTED_INTERRUPT_DESCRIPTOR_ADDRESS				= 0x2016,
	VECF_PID_POINTER_TABLE_ADDRESS							= 0x2042,
	VECF_LAST_PID_POINTER_INDEX								= 0x0008, //16
	/*MSR-Bitmap Address*/
	VECF_MSR_BITMAPS										= 0x2004,
	/*Executive-VMCS Pointer*/
	VECF_EXECUTIVE_VMCS_POINTER								= 0x200C,
	/*Extended-Page-Table Pointer (EPTP)*/
	VECF_EXTENDED_PAGE_TABLE_POINTER						= 0x201A,
	/*Virtual-Processor Identifier (VPID)*/
	VECF_VIRTUAL_PROCESSOR_IDENTIFIER						= 0x0000, //16
	/*Controls for PAUSE-Loop Exiting*/
	VECF_PLE_GAP											= 0x4020, //32
	VECF_PLE_WINDOW											= 0x4022, //32
	/*VM-Function Controls*/
	VECF_VM_FUNCTION_CONTROLS								= 0x2018,
	VECF_EPTP_LIST_ADDRESS									= 0x2024,
	/*VMCS Shadowing Bitmap Addresses*/
	VECF_VMREAD_BITMAP										= 0x2026,
	VECF_VMWRITE_BITMAP										= 0x2028,
	/*ENCLS-Exiting Bitmap*/
	VECF_ENCLS_EXITING_BITMAP								= 0x202E,
	/*ENCLV-Exiting Bitmap*/
	VECF_EXCLV_EXITING_BITMAP								= 0x2036,
	/*PCONFIG-Exiting Bitmap*/
	VECF_PCONFIG_EXITING_BITMAP								= 0x203E,
	/*Control Field for Page-Modification Logging*/
	VECF_PML_ADDRESS										= 0x200E,
	/*Controls for Virtualization Exceptions*/
	VECF_VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS		= 0x202A,
	VECF_EPTP_INDEX											= 0x0004, //16
	/*XSS-Exiting Bitmap*/
	VECF_XSS_EXISTING_BITMAP								= 0x202C,
	/*Sub-Page-Permission-Table Pointer (SPPTP)*/
	VECF_SUB_PAGE_PERMISSION_TABLE_POINTER					= 0x2030,
	/*Fields Related to Hypervisor-Managed Linear-Address Translation*/
	VECF_HLAT_POINTER										= 0x2040,
	VECF_HLAT_PREFIX_SIZE									= 0x0006, //16
	/*Fields Related to PASID Translation*/
	VECF_LOW_PASID_DIRECTORY_ADDRESS						= 0x2038,
	VECF_HIGH_PASID_DIRECTORY_ADDRESS						= 0x203A,
	/*Instruction-Timeout Control*/
	VECF_INSTRUCTION_TIMEOUT_CONTROL						= 0x4024, //32
	/*Fields Controlling Virtualization of the IA32_SPEC_CTRL MSR*/
	VECF_VM_EXECUTION_CONTROL_IA32_SPEC_CTRL_MASK			= 0x204A,
	VECF_VM_EXECUTION_CONTROL_IA32_SPEC_CTRL_SHADOW			= 0x204C
}VM_EXECUTION_CONTROL_FIELDS;

typedef enum _VM_EXIT_CONTROL_FIELDS
{
	/*VM-Exit Controls*/
	VExCF_PRIMARY_VM_EXIT_CONTROLS							= 0x400C, //32
	VExCF_SECONDARY_VM_EXIT_CONTROLS						= 0x2044,
	/*VM-Exit Controls for MSRs*/
	VExCF_VM_EXIT_MSR_STORE_COUNT							= 0x400E, //32
	VExCF_VM_EXIT_MSR_STORE_ADDRESS							= 0x2006,
	VExCF_VM_EXIT_MSR_LOAD_COUNT							= 0x4010, //32
	VExCF_VM_EXIT_MSR_LOAD_ADDRESS							= 0x2008
}VM_EXIT_CONTROL_FIELDS;

typedef enum _VM_ENTRY_CONTROL_FIELDS
{
	/*VM-Entry Controls*/
	VEnCF_VM_ENTRY_CONTROLS									= 0x4012, //32
	/*VM-Entry Controls for MSRs*/
	VEnCF_VM_ENTRY_MSR_LOAD_COUNT							= 0x4014, //32
	VEnCF_VM_ENTRY_MSR_LOAD_ADDRESS							= 0x200A,
	/*VM-Entry Controls for Event Injection*/
	VEnCF_VM_ENTRY_INTERRUPTION_INFORMATION_FIELD			= 0x4016, //32
	VEnCF_VM_ENTRY_EXCEPTION_ERROR_CODE						= 0x4018, //32
	VEnCF_VM_ENTRY_INSTRUCTION_LENGTH						= 0x401A  //32
}VM_ENTRY_CONTROL_FIELDS;

typedef enum _VM_EXIT_INFORMATION_FIELDS //Read Only Commonly
{
	/*Basic VM-Exit Information*/
	VEIF_EXIT_REASON										= 0x4402, //32
	VEIF_EXIT_QUALIFICATION									= 0x6400,
	VEIF_GUEST_LINER_ADDRESS								= 0x640A,
	VEIF_GUEST_PHYSICAL_ADDRESS								= 0x2400, //64 Read Only
	/*Information for VM Exits Due to Vectored Events*/
	VEIF_VM_EXIT_INTERRUPTION_INFORMATION					= 0x4404, //32
	VEIF_VM_EXIT_INTERRUPTION_CODE							= 0x4406, //32
	/*Information for VM Exits That Occur During Event Delivery*/
	VEIF_IDT_VECTORING_INFORMATION_FIELD					= 0x4408, //32
	VEIF_IDT_VECTORING_ERROR_CODE							= 0x440A, //32
	/*Information for VM Exits Due to Instruction Execution*/
	VEIF_VM_EXIT_INSTRUCTION_LENGTH							= 0x440C, //32
	VEIF_VM_EXIT_INSTRUCTION_INFORMATION					= 0x440E, //32
	VEIF_IO_RCX												= 0x6402,
	VEIF_IO_RSI												= 0x6404,
	VEIF_IO_RDI												= 0x6406,
	VEIF_IO_RIP												= 0x6408,
	/*VM-Instruction Error Field*/
	VEIF_VM_INSTRUCTION_ERROR_FIELD							= 0x4400  //32
}VM_EXIT_INFORMATION_FIELDS;

#endif
