EXTERN debugPrint: QWORD
EXTERN bugCheck: QWORD
EXTERN GlobalDebugWindow: QWORD
EXTERN IS_CAPABILITY_MODE: QWORD

EXTERN DRIVER_RSP  : QWORD
EXTERN DRIVER_RIP  : QWORD

EXTERN tempFLAGS: QWORD

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

EXTERN __CR0   : QWORD
EXTERN __CR3   : QWORD
EXTERN __CR4   : QWORD
EXTERN __RAX   : QWORD
EXTERN __RBX   : QWORD
EXTERN __RCX   : QWORD
EXTERN __RDX   : QWORD
EXTERN __RSI   : QWORD
EXTERN __RDI   : QWORD
EXTERN __RSP   : QWORD
EXTERN __RBP   : QWORD
EXTERN __RIP   : QWORD
EXTERN __R8    : QWORD
EXTERN __R9    : QWORD
EXTERN __R10   : QWORD
EXTERN __R11   : QWORD
EXTERN __R12   : QWORD
EXTERN __R13   : QWORD
EXTERN __R14   : QWORD
EXTERN __R15   : QWORD
EXTERN __RFLAGS: QWORD
EXTERN EXIT_REASON:	WORD
EXTERN INSTRUCTION_LENGTH: DWORD

PUSHGQ MACRO
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
	push r15
ENDM

POPGQ MACRO
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
ENDM

.code
	
	__vsm__INT3 PROC
		int 3
		ret
	__vsm__INT3 ENDP

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

	__vsm__testX2APICmode PROC
		mov eax, 1
		cpuid
		mov eax, ecx
		ret
	__vsm__testX2APICmode ENDP

	__vsm__vmlaunchSaveRegisters PROC
		mov __RAX, rax
		mov __RBX, rbx
		mov __RCX, rcx
		mov __RDX, rdx
		mov __RSI, rsi
		mov __RDI, rdi
		mov __RSP, rsp
		mov __RBP, rbp
		mov __R8, r8
		mov __R9, r9
		mov __R10, r10
		mov __R11, r11
		mov __R12, r12
		mov __R13, r13
		mov __R14, r14
		mov __R15, r15
		mov rcx, cr0
		mov __CR0, rcx
		mov rcx, cr3
		mov __CR3, rcx
		mov rcx, cr4
		mov __CR4, rcx
		pushfq
		pop rax
		mov __RFLAGS, rax
		mov rax, qword ptr [rsp]
		mov DRIVER_RIP, rax
		vmlaunch
		mov ecx, 2222AAAAh
		call bugCheck
	__vsm__vmlaunchSaveRegisters ENDP

	__vsm__guestEntry PROC
		;当前CPU的RSP为 GUEST_RSP， 是GUEST外部分配的那个栈底
		mov rax, __RFLAGS
		push rax
		popfq
		mov rax, __CR0
		mov cr0, rax
		mov rax, __CR3
		mov cr3, rax
		mov rax, __CR4
		mov cr4, rax
		mov rax, __RAX
		mov rbx, __RBX
		mov rcx, __RCX
		mov rdx, __RDX
		mov rsi, __RSI
		mov rdi, __RDI
		mov rsp, __RSP
		mov rbp, __RBP
		mov r8, __R8
		mov r9, __R9
		mov r10, __R10
		mov r11, __R11
		mov r12, __R12
		mov r13, __R13
		mov r14, __R14
		mov r15, __R15
		add rsp, 8
		jmp DRIVER_RIP
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
		mov __RAX, rax
		mov __RBX, rbx
		mov __RCX, rcx
		mov __RDX, rdx
		mov __RSI, rsi
		mov __RDI, rdi
		mov __RSP, rsp
		mov __RBP, rbp
		mov __R8, r8
		mov __R9, r9
		mov __R10, r10
		mov __R11, r11
		mov __R12, r12
		mov __R13, r13
		mov __R14, r14
		mov __R15, r15
		mov rcx, cr0
		mov __CR0, rcx
		mov rcx, cr3
		mov __CR3, rcx
		mov rcx, cr4
		mov __CR4, rcx
		pushfq
		pop rax
		mov __RFLAGS, rax
		mov rax, qword ptr [rsp]
		mov DRIVER_RIP, rax
		vmcall ;for execute vmxoff under root-operation mode
	__vsm__vmxoffSaveRegisters ENDP

	__vsm__hostEntry PROC
					sub rsp, 300h
					push rsp
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
					push r15
					mov ecx, GUEST_CR0_INDEX
					vmread rcx, rcx
					push rcx
					mov ecx, GUEST_CR3_INDEX
					vmread rcx, rcx
					push rcx
					mov ecx, GUEST_CR4_INDEX
					vmread rcx, rcx
					push rcx
					mov ecx, GUEST_RSP_INDEX
					vmread rcx, rcx
					push rcx
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
					push rcx

					mov ax, word ptr [rsp + 8h]
					mov EXIT_REASON, ax

					mov ecx, GUEST_FS_BASE_INDEX
					vmread rcx, rcx
					test rcx, rcx
jnz	CAPABILITY_MODE
					cmp EXIT_REASON, 10
				jz  CPUID_EXIT
					cmp EXIT_REASON, 11
				jz  GETSEC_EXIT
					cmp EXIT_REASON, 13
				jz  INVD_EXIT
					cmp EXIT_REASON, 18
				jz  VMCALL_EXIT
					cmp EXIT_REASON, 31
				jz  RDMSR_EXIT
					cmp EXIT_REASON, 32
				jz  WRMSR_EXIT
					cmp EXIT_REASON, 50
				jz  INVEPT_EXIT
					cmp EXIT_REASON, 53
				jz  INVVPID_EXIT
					cmp EXIT_REASON, 55
				jz  XSETBV_EXIT
			GETSEC_EXIT:
			INVD_EXIT:
			INVEPT_EXIT:
			INVVPID_EXIT:
			XSETBV_EXIT:
					int 3
					mov rcx, qword ptr [rsp + 18h]
					mov rcx, qword ptr [rcx]
					call bugCheck
					vmxoff 
			CPUID_EXIT:
					cmp qword ptr [rsp + 0B0h], 22224444h
			jz HOOK_CPUID
					mov rax, qword ptr [rsp + 0B0h]
					mov rcx, qword ptr [rsp + 0A0h]
					cpuid
					mov qword ptr [rsp + 0B0h], rax
					mov qword ptr [rsp + 0A8h], rbx
					mov qword ptr [rsp + 0A0h], rcx
					mov qword ptr [rsp + 098h], rdx
					jmp STEP_RIP
			HOOK_CPUID:
					mov qword ptr [rsp + 0B0h], 0FEFEFEFEh
					mov qword ptr [rsp + 0A8h], 0FEFEFEFEh
					mov qword ptr [rsp + 0A0h], 0FEFEFEFEh
					mov qword ptr [rsp + 098h], 0FEFEFEFEh
			STEP_RIP:
					mov rcx, qword ptr [rsp + 0h]
					mov rax, qword ptr [rsp + 18h]
					add rax, rcx
					mov ecx, GUEST_RIP_INDEX
					vmwrite rcx, rax
					add rsp, 40h

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

					add rsp, 308h
					vmresume
			RDMSR_EXIT:
					mov rcx, qword ptr [rsp + 0A0h]
					rdmsr
					mov qword ptr [rsp + 0B0h], rax
					mov qword ptr [rsp + 98h], rdx

					mov rcx, qword ptr [rsp + 0h]
					mov rax, qword ptr [rsp + 18h]
					add rax, rcx
					mov ecx, GUEST_RIP_INDEX
					vmwrite rcx, rax

					add rsp, 40h
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

					add rsp, 308h
					vmresume
			WRMSR_EXIT:
					mov rax, qword ptr [rsp + 0B0h]
					mov rcx, qword ptr [rsp + 0A0h]
					mov rdx, qword ptr [rsp + 98h]
					wrmsr
		
					mov rcx, qword ptr [rsp + 0h]
					mov rax, qword ptr [rsp + 18h]
					add rax, rcx
					mov ecx, GUEST_RIP_INDEX
					vmwrite rcx, rax
	
					add rsp, 40h
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

					add rsp, 308h
					vmresume
			VMCALL_EXIT:
					mov rax, __RFLAGS
					push rax
					popfq
					mov rax, __CR0
					mov cr0, rax
					mov rax, __CR3
					mov cr3, rax
					mov rax, __CR4
					mov cr4, rax
					mov rax, __RAX
					mov rbx, __RBX
					mov rcx, __RCX
					mov rdx, __RDX
					mov rsi, __RSI
					mov rdi, __RDI
					mov rsp, __RSP
					mov rbp, __RBP
					mov r8, __R8
					mov r9, __R9
					mov r10, __R10
					mov r11, __R11
					mov r12, __R12
					mov r13, __R13
					mov r14, __R14
					mov r15, __R15
					add rsp, 8
					vmxoff
					jmp DRIVER_RIP
CAPABILITY_MODE:
					cmp EXIT_REASON, 10
				jz  CPUID_EXIT_CAPABILITY
					cmp EXIT_REASON, 11
				jz  GETSEC_EXIT_CAPABILITY
					cmp EXIT_REASON, 13
				jz  INVD_EXIT_CAPABILITY
					cmp EXIT_REASON, 31
				jz  RDMSR_EXIT_CAPABILITY
					cmp EXIT_REASON, 32
				jz  WRMSR_EXIT_CAPABILITY
					cmp EXIT_REASON, 50
				jz  INVEPT_EXIT_CAPABILITY
					cmp EXIT_REASON, 53
				jz  INVVPID_EXIT_CAPABILITY
					cmp EXIT_REASON, 55
				jz  XSETBV_EXIT_CAPABILITY
			GETSEC_EXIT_CAPABILITY:
			INVD_EXIT_CAPABILITY:
			INVEPT_EXIT_CAPABILITY:
			INVVPID_EXIT_CAPABILITY:
			XSETBV_EXIT_CAPABILITY:
					int 3
					mov rcx, qword ptr [rsp + 18h]
					mov rcx, qword ptr [rcx]
					call bugCheck
					vmxoff 
			CPUID_EXIT_CAPABILITY:
					mov ax, fs
					mov fs, ax

					mov rax, qword ptr [rsp + 0B0h]
					mov rcx, qword ptr [rsp + 0A0h]
					cpuid
					mov qword ptr [rsp + 0B0h], rax
					mov qword ptr [rsp + 0A8h], rbx
					mov qword ptr [rsp + 0A0h], rcx
					mov qword ptr [rsp + 098h], rdx

					mov rcx, qword ptr [rsp + 0h]
					mov rax, qword ptr [rsp + 18h]
					add rax, rcx
					mov ecx, GUEST_RIP_INDEX
					vmwrite rcx, rax

					add rsp, 40h
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

					add rsp, 308h
					vmresume
			RDMSR_EXIT_CAPABILITY:
					mov ax, fs
					mov fs, ax

					mov rcx, qword ptr [rsp + 0A0h]
					rdmsr
					mov qword ptr [rsp + 0B0h], rax
					mov qword ptr [rsp + 98h], rdx

					mov rcx, qword ptr [rsp + 0h]
					mov rax, qword ptr [rsp + 18h]
					add rax, rcx
					mov ecx, GUEST_RIP_INDEX
					vmwrite rcx, rax

					add rsp, 40h
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

					add rsp, 308h
					vmresume
			WRMSR_EXIT_CAPABILITY:
					mov ax, fs
					mov fs, ax

					mov rax, qword ptr [rsp + 0B0h]
					mov rcx, qword ptr [rsp + 0A0h]
					mov rdx, qword ptr [rsp + 98h]
					wrmsr
		
					mov rcx, qword ptr [rsp + 0h]
					mov rax, qword ptr [rsp + 18h]
					add rax, rcx
					mov ecx, GUEST_RIP_INDEX
					vmwrite rcx, rax
	
					add rsp, 40h
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

					add rsp, 308h
					vmresume
	__vsm__hostEntry ENDP

END
