#include "IA32.h"



VOID driverUnload(PDRIVER_OBJECT driverObject)
{
	UNREFERENCED_PARAMETER(driverObject);
	return;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT driverObject, PUNICODE_STRING regPath)
{
	UNREFERENCED_PARAMETER(regPath);
	driverObject->DriverUnload = driverUnload;
	return STATUS_SUCCESS;
}