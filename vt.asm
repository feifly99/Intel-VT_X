EXTERN bugCheck: QWORD
EXTERN GlobalDebugWindow: QWORD

EXTERN DRIVER_RIP  : QWORD

EXTERN tempFLAGS: QWORD

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
EXTERN EXIT_REASON:	DWORD
EXTERN INSTRUCTION_LENGTH: DWORD

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

	__vsm__SetGlobalDebugWindow PROC
		mov GlobalDebugWindow, 0EEEEEEEEh
		ret
	__vsm__SetGlobalDebugWindow ENDP

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
		pushfq
		pop rax
		mov __RFLAGS, rax
		mov rax, qword ptr [rsp]
		mov DRIVER_RIP, rax
		add rsp, 8
		vmlaunch
		mov ecx, 2222AAAAh
		call bugCheck
	__vsm__vmlaunchSaveRegisters ENDP

	__vsm__guestEntry PROC
		;当前CPU的RSP为 GUEST_RSP， 是GUEST外部分配的那个栈底
		mov rax, __RFLAGS
		push rax
		popfq
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
		jmp DRIVER_RIP
	__vsm__guestEntry ENDP

	__vsm__trap PROC
		mov eax, 1
		rdmsr
		ret
	__vsm__trap ENDP

	//-----this code is buggy-----//
	__vsm__hostEntry PROC
		;保存调用方所有通用目的寄存器的状态.
		;当前RSP = 外部分配的RSP.
		;当前RIP = __vsm__hostEntry.
		;当前RFLAGS = 10h，因为LOAD HOST STATE后，RFLAGS默认清零，除了第一位保留位.
		mov __RAX, rax
		mov __RBX, rbx
		mov __RCX, rcx
		mov __RDX, rdx
		mov __RSI, rsi
		mov __RDI, rdi
		mov __RBP, rbp
		mov __R8, r8
		mov __R9, r9
		mov __R10, r10
		mov __R11, r11
		mov __R12, r12
		mov __R13, r13
		mov __R14, r14
		mov __R15, r15

		mov ecx, GUEST_RSP_INDEX
		vmread rcx, rcx
		mov __RSP, rcx

		mov ecx, GUEST_RIP_INDEX
		vmread rcx, rcx
		mov __RIP, rcx

		mov ecx, GUEST_RFLAGS_INDEX
		vmread rcx, rcx
		mov __RFLAGS, rcx
		
		mov ecx, GUEST_CR0_INDEX
		vmread rcx, rcx
		mov __CR0, rcx
		
		mov ecx, GUEST_CR3_INDEX
		vmread rcx, rcx
		mov __CR3, rcx
		
		mov ecx, GUEST_CR4_INDEX
		vmread rcx, rcx
		mov __CR4, rcx

		mov ecx, VM_EXIT_REASON_INDEX
		vmread rcx, rcx
		mov EXIT_REASON, ecx

		mov ecx, VM_INSTRUCTION_LENGTH_INDEX
		vmread rcx, rcx
		mov INSTRUCTION_LENGTH, ecx
		
	;	cmp EXIT_REASON, 0Ah
	;jz HANDLE_CPUID
		cmp EXIT_REASON, 1Fh
	jz HANDLE_RDMSR
		cmp EXIT_REASON, 20h
	jz HANDLE_WRMSR

		;以下是异常处理流程，没有EXIT_REASON命中
		mov rsp, __RSP
		push __RFLAGS
		popfq
		mov rcx, __RIP ;恢复GUEST的执行流，包括RIP/RSP和RFLAGS
		mov DRIVER_RIP, rcx ;把RIP保存到全局DRIVER_RIP中准备jmp
		mov rcx, __CR0
		mov cr0, rcx
		mov rcx, __CR3
		mov cr3, rcx
		mov rcx, __CR4
		mov cr4, rcx ;恢复三个控制寄存器
		mov rax, __RAX
		mov rbx, __RBX
		mov rcx, __RCX
		mov rdx, __RDX
		mov rsi, __RSI
		mov rdi, __RDI
		mov rbp, __RBP
		mov r8,  __R8
		mov r9,  __R9
		mov r10, __R10
		mov r11, __R11
		mov r12, __R12
		mov r13, __R13
		mov r14, __R14
		mov r15, __R15 ;恢复所有通用寄存器。由于不准备处理，所以没有任何值发生改动
		;vmxoff
		;int 3
		jmp DRIVER_RIP ;注意不能用VMRESUME，否则会因为没有步进RIP导致无限次执行RIP对应的指令

HANDLE_CPUID:
		mov rcx, __RFLAGS
		push rcx
		popfq ;恢复原来刚进入时的RFLAGS
		mov ecx, INSTRUCTION_LENGTH
		add __RIP, rcx
		mov ecx, GUEST_RIP_INDEX
		vmwrite rcx, __RIP ;步进RIP		
		mov rax, __RAX
		mov rcx, __RCX ;恢复原来刚进入时的RAX, RCX和RDX
		cpuid
		mov __RAX, rax
		mov __RBX, rbx
		mov __RCX, rcx
		mov __RDX, rdx ;WRMSR可能会影响这四个寄存器
		mov rcx, __CR0
		mov cr0, rcx
		mov rcx, __CR3
		mov cr3, rcx
		mov rcx, __CR4
		mov cr4, rcx ;恢复三个控制寄存器
		mov rax, __RAX
		mov rbx, __RBX
		mov rcx, __RCX
		mov rdx, __RDX
		mov rsi, __RSI
		mov rdi, __RDI
		mov rbp, __RBP
		mov r8, __R8
		mov r9, __R9
		mov r10, __R10
		mov r11, __R11
		mov r12, __R12
		mov r13, __R13
		mov r14, __R14
		mov r15, __R15 ;恢复所有寄存器，注意可能会被影响的寄存器已经写入全局__REG了
		vmresume ; 继续
HANDLE_RDMSR:
		mov rcx, __RFLAGS
		push rcx
		popfq ;恢复原来刚进入时的RFLAGS
		mov ecx, INSTRUCTION_LENGTH
		add __RIP, rcx
		mov ecx, GUEST_RIP_INDEX
		vmwrite rcx, __RIP ;步进RIP
		mov rcx, __RCX ;恢复原来刚进入时的RAX, RCX和RDX
		rdmsr
		mov __RAX, rax
		mov __RBX, rbx
		mov __RCX, rcx
		mov __RDX, rdx ;WRMSR可能会影响这四个寄存器
		mov rcx, __CR0
		mov cr0, rcx
		mov rcx, __CR3
		mov cr3, rcx
		mov rcx, __CR4
		mov cr4, rcx ;恢复三个控制寄存器
		mov rax, __RAX
		mov rbx, __RBX
		mov rcx, __RCX
		mov rdx, __RDX
		mov rsi, __RSI
		mov rdi, __RDI
		mov rbp, __RBP
		mov r8, __R8
		mov r9, __R9
		mov r10, __R10
		mov r11, __R11
		mov r12, __R12
		mov r13, __R13
		mov r14, __R14
		mov r15, __R15 ;恢复所有寄存器，注意可能会被影响的寄存器已经写入全局__REG了
		vmresume ; 继续
HANDLE_WRMSR:
		mov rcx, __RFLAGS
		push rcx
		popfq ;恢复原来刚进入时的RFLAGS
		mov ecx, INSTRUCTION_LENGTH
		add __RIP, rcx
		mov ecx, GUEST_RIP_INDEX
		vmwrite rcx, __RIP ;步进RIP
		mov rax, __RAX
		mov rcx, __RCX 
		mov rdx, __RDX ;恢复原来刚进入时的RAX, RCX和RDX
		wrmsr
		mov __RAX, rax
		mov __RBX, rbx
		mov __RCX, rcx
		mov __RDX, rdx ;WRMSR可能会影响这四个寄存器
		mov rcx, __CR0
		mov cr0, rcx
		mov rcx, __CR3
		mov cr3, rcx
		mov rcx, __CR4
		mov cr4, rcx ;恢复三个控制寄存器
		mov rax, __RAX
		mov rbx, __RBX
		mov rcx, __RCX
		mov rdx, __RDX
		mov rsi, __RSI
		mov rdi, __RDI
		mov rbp, __RBP
		mov r8, __R8
		mov r9, __R9
		mov r10, __R10
		mov r11, __R11
		mov r12, __R12
		mov r13, __R13
		mov r14, __R14
		mov r15, __R15 ;恢复所有寄存器，注意可能会被影响的寄存器已经写入全局__REG了
		vmresume ; 继续	
	__vsm__hostEntry ENDP
	//-----this code is buggy-----//

















	;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


















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
	
	;selectors
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
		ret
	__vsm__NOP ENDP

END
