#ifndef __INTEL_IA32_BASIC_INDEX__
#define __INTEL_IA32_BASIC_INDEX__

#include <ntifs.h> 
#include <ntddk.h>
#include <wdm.h>

typedef enum _IA32_VMX_INDEXES
{
	IA32_VMX_BASIC									= 0x0480,
	IA32_VMX_PINBASED_CTLS							= 0x0481,
	IA32_VMX_PROCBASED_CTLS							= 0x0482,
	IA32_VMX_PROCBASED_CTLS2						= 0x048B,
	IA32_VMX_PROCBASED_CTLS3						= 0x0492,
	IA32_VMX_EXIT_CTLS								= 0x0483,
	IA32_VMX_EXIT_CTLS2								= 0x0493,
	IA32_VMX_ENTRY_CTLS								= 0x0484,
	IA32_VMX_MISC									= 0x0485,
	IA32_VMX_CR0_FIXED0								= 0x0486,
	IA32_VMX_CR0_FIXED1								= 0x0487,
	IA32_VMX_CR4_FIXED0								= 0x0488,
	IA32_VMX_CR4_FIXED1								= 0x0489,
	IA32_VMX_VMCS_ENUM								= 0x048A,
	IA32_VMX_EPT_VPID_CAP							= 0x048C,
	IA32_VMX_VMFUNC									= 0x0491,
	IA32_VMX_TRUE_ENTRY_CTLS						= 0x0490,
	IA32_VMX_TRUE_EXIT_CTLS							= 0x048F,
}IA32_VMX_INDEXES;

typedef enum _GUEST_STATE_AREA_FIELDS
{
	//Guest Register State

	/*Control registers CR0, CR3 and CR4*/
	GUEST_CR0										= 0x6800,
	GUEST_CR3										= 0x6802,
	GUEST_CR4										= 0x6804,

	/*Debug register DR7*/
	GUEST_DR7										= 0x681A,

	/*RSP, RIP and RFLAGS*/
	GUEST_RSP										= 0x681C,
	GUEST_RIP										= 0x681E,
	GUEST_RFLAGS									= 0x6820,

	/*The following fields for each of the registers CS, SS, DS, ES, FS, GS, LDTR and TR*/
	GUEST_CS_SELECTOR								= 0x0802,  //16
	GUEST_SS_SELECTOR								= 0x0804,  //16
	GUEST_DS_SELECTOR								= 0x0806,  //16
	GUEST_ES_SELECTOR								= 0x0800,  //16
	GUEST_FS_SELECTOR								= 0x0808,  //16
	GUEST_GS_SELECTOR								= 0x080A,  //16
	GUEST_LDTR_SELECTOR								= 0x080C,  //16
	GUEST_TR_SELECTOR								= 0x080E,  //16

	GUEST_CS_BASE_ADDRESS							= 0x6808,
	GUEST_SS_BASE_ADDRESS							= 0x680A,
	GUEST_DS_BASE_ADDRESS							= 0x680C,
	GUEST_ES_BASE_ADDRESS							= 0x6806,
	GUEST_FS_BASE_ADDRESS							= 0x680E,
	GUEST_GS_BASE_ADDRESS							= 0x6810,
	GUEST_LDTR_BASE_ADDRESS							= 0x6812,
	GUEST_TR_BASE_ADDRESS							= 0x6814,

	GUEST_CS_SEGEMENT_LIMIT							= 0x4802, //32
	GUEST_SS_SEGEMENT_LIMIT							= 0x4804, //32
	GUEST_DS_SEGEMENT_LIMIT							= 0x4806, //32
	GUEST_ES_SEGEMENT_LIMIT							= 0x4800, //32
	GUEST_FS_SEGEMENT_LIMIT							= 0x4808, //32
	GUEST_GS_SEGEMENT_LIMIT							= 0x480A, //32
	GUEST_LDTR_SEGEMENT_LIMIT						= 0x480C, //32
	GUEST_TR_SEGEMENT_LIMIT							= 0x480E, //32

	GUEST_CS_ACCESS_RIGHTS							= 0x4816, //32
	GUEST_SS_ACCESS_RIGHTS							= 0x4818, //32
	GUEST_DS_ACCESS_RIGHTS							= 0x481A, //32
	GUEST_ES_ACCESS_RIGHTS							= 0x4814, //32
	GUEST_FS_ACCESS_RIGHTS							= 0x481C, //32
	GUEST_GS_ACCESS_RIGHTS							= 0x481E, //32
	GUEST_LDTR_ACCESS_RIGHTS						= 0x4820, //32
	GUEST_TR_ACCESS_RIGHTS							= 0x4822, //32

	/*The following fields for each of the registers GDTR and IDTR*/
	GUEST_GDTR_BASE									= 0x6816,
	GUEST_IDTR_BASE									= 0x6818,

	GUEST_GDTR_LIMIT								= 0x4810, //32
	GUEST_IDTR_LIMIT								= 0x4812, //32

	/*The following MSRs (Only 'FULL' encoding recorded)*/
	GUEST_IA32_DEBUGCTL								= 0x2802,
	GUEST_IA32_SYSENTER_CS							= 0x482A, //32
	GUEST_IA32_SYSENTER_ESP							= 0x6824,
	GUEST_IA32_SYSENTER_EIP							= 0x6826,
	GUEST_IA32_PERF_GLOBAL_CTRL						= 0x2808,
	GUEST_IA32_PAT									= 0x2804,
	GUEST_IA32_EFER									= 0x2806,
	GUEST_IA32_BNDCFGS								= 0x2812,
	GUEST_IA32_RTIT_CTL								= 0x2814,
	GUEST_IA32_LBR_CTL								= 0x2816,
	GUEST_IA32_S_CET								= 0x6828,
	GUEST_IA32_INTERRUPT_SSP_TABLE_ADDR				= 0x682C,
	GUEST_IA32_PKRS									= 0x2818,

	/*The shadow-stack pointer register SSP*/
	GUEST_SHADOW_STACK_POINTER_REGISTER_SSP			= 0x682A,
	/*The register SMBASE*/
	GUEST_SMBASE									= 0x4828, //32

	//Guest Non-Register State

	GUEST_ACTIVATE_STATE							= 0x4826, //32
	GUEST_INTERRUPTIBILITY_STATE					= 0x4824, //32
	GUEST_PENDING_DEBUG_EXCEPTIONS					= 0x6822,
	GUEST_VMCS_LINK_POINTER							= 0x2800,
	GUEST_VMX_PREEMPTION_TIMER_VALUE				= 0x482E, //32
	GUEST_PDPTE0									= 0x280A,
	GUEST_PDPTE1									= 0x280C,
	GUEST_PDPTE2									= 0x280E,
	GUEST_PDPTE3									= 0x2810,
	GUEST_INTERRUPT_STATUS							= 0x0810,  //16
	GUEST_PML_INDEX									= 0x0812   //16
}GUEST_STATE_AREA_FIELDS;

typedef enum _HOST_STATE_AREA_FIELDS
{
	/*CR0, CR3, and CR4*/
	HOST_CR0										= 0x6C00,
	HOST_CR3										= 0x6C02,
	HOST_CR4										= 0x6C04,

	/*RSP and RIP*/
	HOST_RSP										= 0x6C14,
	HOST_RIP										= 0x6C16,

	/*Selector fields for the segment registers CS, SS, DS, ES, FS, GS and TR.*/
	HOST_CS_SELECTOR								= 0x0C02,  //16
	HOST_SS_SELECTOR								= 0x0C04,  //16
	HOST_DS_SELECTOR								= 0x0C06,  //16
	HOST_ES_SELECTOR								= 0x0C00,  //16
	HOST_FS_SELECTOR								= 0x0C08,  //16
	HOST_GS_SELECTOR								= 0x0C0A,  //16
	HOST_TR_SELECTOR								= 0x0C0C,  //16

	/*Base-address fields for FS, GS, TR, GDTR and IDTR*/
	HOST_FS_BASE_ADDRESS							= 0x6C06,
	HOST_GS_BASE_ADDRESS							= 0x6C08,
	HOST_TR_BASE_ADDRESS							= 0x6C0A,
	HOST_GDTR_BASE_ADDRESS							= 0x6C0C,
	HOST_IDTR_BASE_ADDRESS							= 0x6C0E,

	/*The following MSRs*/
	HOST_IA32_SYSENTER_CS							= 0x4C00, //32
	HOST_IA32_SYSENTER_ESP							= 0x6C10,
	HOST_IA32_SYSENTER_EIP							= 0x6C12,
	HOST_IA32_PERF_GLOBAL_CTRL						= 0x2C04,
	HOST_IA32_PAT									= 0x2C00,
	HOST_IA32_EFER									= 0x2C02,
	HOST_IA32_S_CET									= 0x6C18,
	HOST_IA32_INTERRUPT_SSP_TABLE_ADDR				= 0x6C1C,
	HOST_IA32_PKRS									= 0x2C06,

	/*The shadow-stack pointer register SSP*/
	HOST_SHADOW_STACK_POINTER_REGISTER_SSP			= 0x6C1A
}HOST_STATE_AREA_FIELDS;

typedef enum _VM_EXECUTION_CONTROL_FIELDS
{
	/*Pin-Based VM-Execution Controls*/
	PIN_BASED_VM_EXECUTION_CONTROL										= 0x4000, //32
	/*Processor-Based VM-Execution Controls*/
	PRIMARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS						= 0x4002, //32
	SECONDARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS						= 0x401E, //32
	TERTIARY_PROCESSOR_BASED_VM_EXECUTION_CONTROLS						= 0x2034, //64
	/*Exception Bitmap*/
	EXCEPTION_BITMAP													= 0x4004, //32
	/*I/O-Bitmap Addresses*/
	IO_BITMAP_A															= 0x2000, //64
	IO_BITMAP_B															= 0x2002, //64
	/*Time-Stamp Counter Offset and Multiplier*/
	TSC_OFFSET															= 0x2010, //64
	TSC_MULTIPLIER														= 0x2032, //64
	/*Guest/Host Masks and Read Shadows for CR0 and CR4*/
	CR0_GUEST_HOST_MARK													= 0x6000, //64
	CR4_GUEST_HOST_MARK													= 0x6002, //64
	CR0_READ_SHADOW														= 0x6004, //64
	CR4_READ_SHADOW														= 0x6006, //64
	/*CR3-Target Controls*/
	CR3_TARGET_VALUE0													= 0x6008, //64
	CR3_TARGET_VALUE1													= 0x600A, //64
	CR3_TARGET_VALUE2													= 0x600C, //64
	CR3_TARGET_VALUE3													= 0x600E, //64
	CR3_TARGET_COUNT													= 0x400A, //32
	/*Controls for APIC Virtualization*/
	APIC_ACCESS_ADDRESS													= 0x2014, //64
	VIRTUAL_APIC_ADDRESS												= 0x2012, //64
	TPR_THRESHOLD														= 0x401C, //32
	EOI_EXIT_BITMAP_0													= 0x201C, //64
	EOI_EXIT_BITMAP_1													= 0x201E, //64
	EOI_EXIT_BITMAP_2													= 0x2020, //64
	EOI_EXIT_BITMAP_3													= 0x2022, //64
	POSTED_INTERRUPT_NOTIFICATION_VECTOR								= 0x0002, //16
	POSTED_INTERRUPT_DESCRIPTOR_ADDRESS									= 0x2016, //64
	PID_POINTER_TABLE_ADDRESS											= 0x2042, //64
	LAST_PID_POINTER_INDEX												= 0x0008, //16
	/*MSR-Bitmap Address*/
	MSR_BITMAPS															= 0x2004, //64
	/*Executive-VMCS Pointer*/
	EXECUTIVE_VMCS_POINTER												= 0x200C, //64
	/*Extended-Page-Table Pointer (EPTP)*/
	EXTENDED_PAGE_TABLE_POINTER											= 0x201A, //64
	/*Virtual-Processor Identifier (VPID)*/
	VIRTUAL_PROCESSOR_IDENTIFIER										= 0x0000, //16
	/*Controls for PAUSE-Loop Exiting*/
	PLE_GAP																= 0x4020, //32
	PLE_WINDOW															= 0x4022, //32
	/*VM-Function Controls*/
	VM_FUNCTION_CONTROLS												= 0x2018, //64
	EPTP_LIST_ADDRESS													= 0x2024, //64
	/*VMCS Shadowing Bitmap Addresses*/
	VMREAD_BITMAP														= 0x2026, //64
	VMWRITE_BITMAP														= 0x2028, //64
	/*ENCLS-Exiting Bitmap*/
	ENCLS_EXITING_BITMAP												= 0x202E, //64
	/*ENCLV-Exiting Bitmap*/
	EXCLV_EXITING_BITMAP												= 0x2036, //64
	/*PCONFIG-Exiting Bitmap*/
	PCONFIG_EXITING_BITMAP												= 0x203E, //64
	/*Control Field for Page-Modification Logging*/
	PML_ADDRESS															= 0x200E, //64
	/*Controls for Virtualization Exceptions*/
	VIRTUALIZATION_EXCEPTION_INFORMATION_ADDRESS						= 0x202A, //64
	EPTP_INDEX															= 0x0004, //16
	/*XSS-Exiting Bitmap*/
	XSS_EXISTING_BITMAP													= 0x202C, //64
	/*Sub-Page-Permission-Table Pointer (SPPTP)*/
	SUB_PAGE_PERMISSION_TABLE_POINTER									= 0x2030, //64
	/*Fields Related to Hypervisor-Managed Linear-Address Translation*/
	HLAT_POINTER														= 0x2040, //64
	HLAT_PREFIX_SIZE													= 0x0006, //16
	/*Fields Related to PASID Translation*/
	LOW_PASID_DIRECTORY_ADDRESS											= 0x2038, //64
	HIGH_PASID_DIRECTORY_ADDRESS										= 0x203A, //64
	/*Instruction-Timeout Control*/
	INSTRUCTION_TIMEOUT_CONTROL											= 0x4024, //32
	/*Fields Controlling Virtualization of the IA32_SPEC_CTRL MSR*/
	IA32_SPEC_CTRL_MASK													= 0x204A, //64
	IA32_SPEC_CTRL_SHADOW												= 0x204C //64
}VM_EXECUTION_CONTROL_FIELDS;

typedef enum _VM_EXIT_CONTROL_FIELDS
{
	/*VM-Exit Controls*/
	PRIMARY_VM_EXIT_CONTROLS						= 0x400C, //32
	SECONDARY_VM_EXIT_CONTROLS						= 0x2044,
	/*VM-Exit Controls for MSRs*/
	VM_EXIT_MSR_STORE_COUNT							= 0x400E, //32
	VM_EXIT_MSR_STORE_ADDRESS						= 0x2006,
	VM_EXIT_MSR_LOAD_COUNT							= 0x4010, //32
	VM_EXIT_MSR_LOAD_ADDRESS						= 0x2008
}VM_EXIT_CONTROL_FIELDS;

typedef enum _VM_ENTRY_CONTROL_FIELDS
{
	/*VM-Entry Controls*/
	VM_ENTRY_CONTROLS								= 0x4012, //32
	/*VM-Entry Controls for MSRs*/
	VM_ENTRY_MSR_LOAD_COUNT							= 0x4014, //32
	VM_ENTRY_MSR_LOAD_ADDRESS						= 0x200A,
	/*VM-Entry Controls for Event Injection*/
	VM_ENTRY_INTERRUPTION_INFORMATION_FIELD			= 0x4016, //32
	VM_ENTRY_EXCEPTION_ERROR_CODE					= 0x4018, //32
	VM_ENTRY_INSTRUCTION_LENGTH						= 0x401A  //32
}VM_ENTRY_CONTROL_FIELDS;

typedef enum _VM_EXIT_INFORMATION_FIELDS //Read Only Commonly
{
	/*Basic VM-Exit Information*/
	EXIT_REASON										= 0x4402, //32
	EXIT_QUALIFICATION								= 0x6400,
	GUEST_LINER_ADDRESS								= 0x640A,
	GUEST_PHYSICAL_ADDRESS							= 0x2400, //64 Read Only
	/*Information for VM Exits Due to Vectored Events*/
	VM_EXIT_INTERRUPTION_INFORMATION				= 0x4404, //32
	VM_EXIT_INTERRUPTION_CODE						= 0x4406, //32
	/*Information for VM Exits That Occur During Event Delivery*/
	IDT_VECTORING_INFORMATION_FIELD					= 0x4408, //32
	IDT_VECTORING_ERROR_CODE						= 0x440A, //32
	/*Information for VM Exits Due to Instruction Execution*/
	VM_EXIT_INSTRUCTION_LENGTH						= 0x440C, //32
	VM_EXIT_INSTRUCTION_INFORMATION					= 0x440E, //32
	IO_RCX											= 0x6402,
	IO_RSI											= 0x6404,
	IO_RDI											= 0x6406,
	IO_RIP											= 0x6408,
	/*VM-Instruction Error Field*/
	VM_INSTRUCTION_ERROR_FIELD						= 0x4400  //32
}VM_EXIT_INFORMATION_FIELDS;

#endif
