.code

	; Software can determine a processor¡¯s physical-address width by executing CPUID with 80000008H in EAX. 
	; The physical-address width is returned in bits 7:0 of EAX.

	__vasm__checkCPUID PROC
		mov eax, 80000008h
		cpuid
		ret
	__vasm__checkCPUID ENDP

END