EXTERN bugCheck: QWORD

EXTERN GUEST_FS_BASE_INDEX: DWORD
EXTERN GUEST_CR0_INDEX: DWORD
EXTERN GUEST_CR3_INDEX: DWORD
EXTERN GUEST_CR4_INDEX: DWORD
EXTERN GUEST_RIP_INDEX: DWORD
EXTERN GUEST_RSP_INDEX: DWORD
EXTERN GUEST_RFLAGS_INDEX: DWORD
EXTERN HOST_RIP_INDEX: DWORD
EXTERN HOST_RSP_INDEX: DWORD
EXTERN VM_EXIT_REASON_INDEX: DWORD
EXTERN VM_EXIT_QUALIFICATION_INDEX: DWORD
EXTERN VM_INSTRUCTION_LENGTH_INDEX: DWORD
EXTERN PER_CPU_REGS: QWORD

.code
	
	__vsm__getRAX PROC
		mov rax, rax
		ret
	__vsm__getRAX ENDP


	__vsm__INT3 PROC
		int 3
		ret
	__vsm__INT3 ENDP

	__vsm__CLI PROC
		cli
		ret
	__vsm__CLI ENDP

	__vsm__STI PROC
		sti
		ret
	__vsm__STI ENDP

	__vasm__isVMXOperationsSupported PROC
		mov eax, 1
		cpuid
		shr ecx, 5
		and ecx, 1
		mov rax, rcx
		ret
	__vasm__isVMXOperationsSupported ENDP

	__vasm__setCR4VMXEBit PROC
		mov rax, cr4
		mov ebx, 1
		shl rbx, 13
		or rax, rbx
		mov cr4, rax
		ret
	__vasm__setCR4VMXEBit ENDP

	__vasm__clearCR4VMXEBit PROC
		mov rax, cr4
		mov ebx, 1
		shl rbx, 13
		not rbx
		and rax, rbx
		mov cr4, rax
		ret
	__vasm__clearCR4VMXEBit ENDP

	__vsm__testX2APICmode PROC
		mov eax, 1
		cpuid
		mov eax, ecx
		ret
	__vsm__testX2APICmode ENDP

	__vsm__vmlaunchSaveRegisters PROC
		sub rsp, 38h
		push rax
		push rcx

		mov rax, gs: [20h]
		mov eax, dword ptr [rax + 24h]
		shl eax, 3
		mov rcx, PER_CPU_REGS
		add rcx, rax
		mov rcx, qword ptr [rcx]

		mov qword ptr [rcx], rsp

		vmlaunch
		mov ecx, 4400h
		vmread rcx, rcx
		or ecx, 0CCDD0000h
		call bugCheck
	__vsm__vmlaunchSaveRegisters ENDP

	__vsm__guestEntry PROC
		mov rax, gs: [20h]
		mov eax, dword ptr [rax + 24h]
		shl eax, 3
		mov rcx, PER_CPU_REGS
		add rcx, rax
		mov rcx, qword ptr [rcx]

		mov rsp, qword ptr [rcx]
		pop rcx
		pop rax
		add rsp, 38h

		ret
	__vsm__guestEntry ENDP

	__vsm__getCR0 PROC
		mov rax, cr0
		ret
	__vsm__getCR0 ENDP

	__vsm__getCR3 PROC
		mov rax, cr3
		ret
	__vsm__getCR3 ENDP		

	__vsm__getCR4 PROC
		mov rax, cr4
		ret
	__vsm__getCR4 ENDP

	__vsm__restoreCR4 PROC
		mov rax, cr4
		mov ecx, 1
		shl ecx, 13
		not ecx
		and rax, rcx
		mov cr4, rax
		ret
	__vsm__restoreCR4 ENDP
		
	__vsm__getDR7 PROC
		mov rax, dr7
		ret
	__vsm__getDR7 ENDP
		
	__vsm__getRSP PROC
		mov rax, rsp
		ret
	__vsm__getRSP ENDP
	
	__vsm__getRFLAGS PROC
		pushfq
		pop rax
		ret
	__vsm__getRFLAGS ENDP
	
	__vsm__getCS PROC
		mov eax, cs
		ret
	__vsm__getCS ENDP
		
	__vsm__getSS PROC
		mov eax, ss
		ret
	__vsm__getSS ENDP
		
	__vsm__getDS PROC
		mov eax, ds
		ret
	__vsm__getDS ENDP
		
	__vsm__getES PROC
		mov eax, es
		ret
	__vsm__getES ENDP
		
	__vsm__getFS PROC
		mov eax, fs
		ret
	__vsm__getFS ENDP
		
	__vsm__getGS PROC
		mov eax, gs
		ret
	__vsm__getGS ENDP
		
	__vsm__getLDTR PROC
		xor eax, eax
		sldt ax
		ret
	__vsm__getLDTR ENDP
		
	__vsm__getTR PROC
		xor eax, eax
		str ax
		ret
	__vsm__getTR ENDP

	__vsm__getGDTbase PROC
		LOCAL gdtr[10]:BYTE
		sgdt gdtr
		mov rax, qword ptr gdtr[2]
		ret
	__vsm__getGDTbase ENDP

	__vsm__getIDTbase PROC
		LOCAL idtr[10]:BYTE
		sidt idtr
		mov	rax, qword ptr idtr[2]
		ret
	__vsm__getIDTbase ENDP

	__vsm__getGDTlimit PROC
		LOCAL gdtr[10]:BYTE
		sgdt gdtr
		xor rax, rax
		mov	ax, word ptr gdtr[0]
		ret
	__vsm__getGDTlimit ENDP

	__vsm__getIDTlimit PROC
		LOCAL idtr[10]:BYTE
		sidt idtr
		xor rax, rax
		mov	ax, word ptr idtr[0]
		ret
	__vsm__getIDTlimit ENDP

	__vsm__readGdtr PROC ;__vsm__readGdtr(ULONG_PTR pGdtrSpace)
		sub rsp, 68h

		sgdt qword ptr [rcx]

		add rsp, 68h
		ret
	__vsm__readGdtr ENDP

	__vsm__writeGdtr PROC ;__vsm__writeGdtr(ULONG_PTR pGdtrSpace)
		sub rsp, 68h

		lgdt fword ptr [rcx]

		add rsp, 68h
		ret
	__vsm__writeGdtr ENDP

	__vsm__readIdtr PROC ;__vsm__readGdtr(ULONG_PTR pGdtrSpace)
		sub rsp, 68h

		sidt qword ptr [rcx]

		add rsp, 68h
		ret
	__vsm__readIdtr ENDP

	__vsm__writeIdtr PROC ;__vsm__writeGdtr(ULONG_PTR pGdtrSpace)
		sub rsp, 68h

		lidt fword ptr [rcx]

		add rsp, 68h
		ret
	__vsm__writeIdtr ENDP

	__vsm__NOP PROC
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		ret
	__vsm__NOP ENDP

	__vsm__trap PROC
		mov ecx, 830h
		rdmsr
		wrmsr
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		nop
		;vmcall
		ret
	__vsm__trap ENDP	

	__vsm__vmxoffSaveRegisters PROC
		vmcall ;for executing vmxoff under root-operation mode
	__vsm__vmxoffSaveRegisters ENDP

	__vsm__hostEntry PROC
		push rax
		push rbx
		push rcx
		push rdx
		push rsi
		push rdi
		push rbp
		push r8
		push r9
		push r10
		push r11
		push r12
		push r13
		push r14
		push r15 ;x8h
		mov ecx, GUEST_RIP_INDEX
		vmread rcx, rcx
		push rcx		
		mov ecx, GUEST_RFLAGS_INDEX
		vmread rcx, rcx
		push rcx
		mov ecx, VM_EXIT_REASON_INDEX
		vmread rcx, rcx
		push rcx
		mov ecx, VM_INSTRUCTION_LENGTH_INDEX
		vmread rcx, rcx
		push rcx ;x8h

		mov rbp, rsp

		;save x87fpu, SSE, AVX states
		sub rsp, 248h ;x0h
		fxsave qword ptr [rsp] ;至少需要200h(= 512)字节的空间
		sub rsp, 60h
		
		;check whether x86 software(by fs register)
		mov ecx, GUEST_FS_BASE_INDEX
		vmread rcx, rcx
		cmp rcx, 0
	jz  NO_NEED_RESET_FS
		mov ax, fs
		mov fs, ax
NO_NEED_RESET_FS:

		call VM_EXIT_HANDLER

		;restore guest Rip pointer
		mov rcx, qword ptr [rbp + 0h]
		mov rax, qword ptr [rbp + 18h]
		add rax, rcx
		mov ecx, GUEST_RIP_INDEX
		vmwrite rcx, rax
		
		;restore guest x87fpu, SSE, AVX states
		add rsp, 60h ;x0h
		fxrstor qword ptr [rsp]
		add rsp, 248h ;x0h		

		;skip vmx-related fields
		add rsp, 20h

		;restore general purpose registers
		pop r15
		pop r14
		pop r13
		pop r12
		pop r11
		pop r10
		pop r9
		pop r8
		pop rbp
		pop rdi
		pop rsi
		pop rdx
		pop rcx
		pop rbx
		pop rax

		;resume guest
		vmresume
	__vsm__hostEntry ENDP

	VM_EXIT_HANDLER PROC
		sub rsp, 48h

		cmp word ptr [rbp + 8h], 10
	jz  REASON_CPUID
		cmp word ptr [rbp + 8h], 18
	jz  REASON_VMCALL
		cmp word ptr [rbp + 8h], 31
	jz  REASON_RDMSR
		cmp word ptr [rbp + 8h], 32
	jz  REASON_WRMSR
		mov rcx, qword ptr [rbp + 8h] ;VM_EXIT_REASON
		or rcx, 0ABCD0000h
		call bugCheck

REASON_CPUID:
		call CPUID_EXIT
	jmp RETURN
REASON_VMCALL:
		call VMCALL_EXIT
	jmp RETURN
REASON_RDMSR:
		call RDMSR_EXIT
	jmp RETURN
REASON_WRMSR:
		call WRMSR_EXIT
	jmp RETURN

RETURN:
		add rsp, 48h
		ret
	VM_EXIT_HANDLER ENDP

	CPUID_EXIT PROC
		sub rsp, 68h
		mov rax, qword ptr [rbp + 90h]
		mov rcx, qword ptr [rbp + 80h]
		cpuid
		mov qword ptr [rbp + 90h], rax
		mov qword ptr [rbp + 88h], rbx
		mov qword ptr [rbp + 80h], rcx
		mov qword ptr [rbp + 78h], rdx
		add rsp, 68h
		ret
	CPUID_EXIT ENDP

	RDMSR_EXIT PROC
		sub rsp, 68h
		mov rcx, qword ptr [rbp + 80h]
		rdmsr
		mov qword ptr [rbp + 90h], rax
		mov qword ptr [rbp + 78h], rdx
		add rsp, 68h
		ret
	RDMSR_EXIT ENDP

	WRMSR_EXIT PROC
		sub rsp, 68h
		mov rax, qword ptr [rbp + 90h]
		mov rcx, qword ptr [rbp + 80h]
		mov rdx, qword ptr [rbp + 78h]
		wrmsr
		add rsp, 68h
		ret
	WRMSR_EXIT ENDP
	
	VMCALL_EXIT PROC
		sub rsp, 68h

		mov rax, qword ptr [rbp + 10h]
		push rax
		popfq

		mov rsp, rbp

		sub rsp, 248h
		fxrstor qword ptr [rsp]  ;至少需要200h字节的空间
		add rsp, 248h	

		add rsp, 20h

		pop r15
		pop r14
		pop r13
		pop r12
		pop r11
		pop r10
		pop r9
		pop r8
		pop rbp
		pop rdi
		pop rsi 
		pop rdx
		pop rcx
		pop rbx

		mov rax, gs: [20h]
		mov eax, dword ptr [rax + 24h] ;cpu index
		shl eax, 3
		add rax, PER_CPU_REGS
		pop qword ptr [rax + 100h]		
		
		mov eax, GUEST_RSP_INDEX
		vmread rsp, rax

		mov rax, gs: [20h]
		mov eax, dword ptr [rax + 24h] ;cpu index
		shl eax, 3
		add rax, PER_CPU_REGS

		vmclear qword ptr [rax + 500h]

		mov rax, qword ptr [rax + 100h]

		vmxoff
		ret
	VMCALL_EXIT ENDP

;一般情况下不会用到的VT-x功能-----------------------------------------------------------------------------------------------------------------------------------------

END
