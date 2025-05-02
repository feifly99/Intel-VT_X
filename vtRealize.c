#include "IA32.h"

VOID __fastcall runRoutineForAllCpus(
	IN VOID(__fastcall* eachCpuRoutine)(PVOID),
	IN PVOID args
)
{
	ULONG initialCpuIndex = KeGetCurrentProcessorIndex();
	ULONG totalCpuCount = KeQueryActiveProcessorCount(NULL);
	for (ULONG loop = 0; loop < totalCpuCount; loop++)
	{
		KeSetSystemAffinityThread((KAFFINITY)(1 << loop));
		eachCpuRoutine(args);
	}
	KeSetSystemAffinityThread((KAFFINITY)(1 << initialCpuIndex));
	return;
}

VOID __fastcall runRoutineAtPreciseCpu(
	IN VOID(__fastcall* routine)(PVOID),
	IN PVOID args,
	IN ULONG targetCpuIndex
)
{
	ULONG initialCpuIndex = KeGetCurrentProcessorIndex();
	if (targetCpuIndex > KeQueryActiveProcessorCount(NULL) - 1)
	{
		DbgPrint("目标CPU编号超过逻辑CPU个数");
		return;
	}
	KeSetSystemAffinityThread((KAFFINITY)(1 << targetCpuIndex));
	routine(args);
	KeSetSystemAffinityThread((KAFFINITY)(1 << initialCpuIndex));
	return;
}

VOID __fastcall checkCurrCpuIndex(
	IN PVOID args
)
{
	UNREFERENCED_PARAMETER(args);
	DbgPrint("current cpu index: %lu -> CR4: %llX", KeGetCurrentProcessorIndex(), __vsm__getCR4());
}

VOID ExFreeMemory(
	OUT PVOID* mem
)
{
	ExFreePool(*mem);
	*mem = NULL;
	return;
}
