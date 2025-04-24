#ifndef __DT_HEADER__
#define __DT_HEADER__

#include "base.h"

typedef struct _SEGEMENT_REGISTER_ATTRIBUTES
{
	USHORT selector;
	ULONG segementLimit;
	ULONG baseAddress;
	ULONG accessRight;
}SRA, *PSRA;

typedef union _GDT_ENTRY
{
	ULONG64 WHOLE_VALUE;
	struct _PACKAGED
	{
		ULONG64 Limit_0_15		: 16;
		ULONG64 BASE_0_15		: 16;
		ULONG64 BASE_16_23		: 8;
		ULONG64 ACCESS_RIGHT	: 8;
		ULONG64 LIMIT_16_19		: 4;
		ULONG64 FLAGS			: 4;
		ULONG64 BASE_24_31		: 8;
	}PACKAGED;
	struct _DETAILED
	{
		ULONG64 Limit_0_15		: 16;
		ULONG64 BASE_0_15		: 16;
		ULONG64 BASE_16_23		: 8;
		ULONG64 TYPE			: 4;
		ULONG64 S				: 1;
		ULONG64 DPL				: 2;
		ULONG64 P				: 1;
		ULONG64 LIMIT_16_19		: 4;
		ULONG64 FLAGS			: 4;
		ULONG64 BASE_24_31		: 8;
	}DETAILED;	
}GDT_ENTRY, *PGDT_ENTRY;

#endif