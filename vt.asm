EXTERN bugCheck: QWORD
EXTERN GlobalDebugWindow: QWORD

EXTERN DRIVER_RIP  : QWORD

EXTERN tempFLAGS: QWORD

EXTERN GUEST_RIP_INDEX: DWORD
EXTERN GUEST_RSP_INDEX: DWORD
EXTERN GUEST_RFLAGS_INDEX: DWORD
EXTERN HOST_RIP_INDEX: DWORD
EXTERN HOST_RSP_INDEX: DWORD
EXTERN VM_EXIT_REASON_INDEX: DWORD
EXTERN VM_EXIT_QUALIFICATION_INDEX: DWORD
EXTERN VM_INSTRUCTION_LENGTH_INDEX: DWORD

EXTERN __RAX   : QWORD
EXTERN __RBX   : QWORD
EXTERN __RCX   : QWORD
EXTERN __RDX   : QWORD
EXTERN __RSI   : QWORD
EXTERN __RDI   : QWORD
EXTERN __RSP   : QWORD
EXTERN __RBP   : QWORD
EXTERN __R8    : QWORD
EXTERN __R9    : QWORD
EXTERN __R10   : QWORD
EXTERN __R11   : QWORD
EXTERN __R12   : QWORD
EXTERN __R13   : QWORD
EXTERN __R14   : QWORD
EXTERN __R15   : QWORD
EXTERN __RFLAGS: QWORD

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
		cpuid
		ret
	__vsm__trap ENDP

	__vsm__hostEntry PROC
		;保存调用方除了RSP/RIP/RFLAGS的状态.
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
		;设置当前上下文的RFLAGS为GUEST_RFLAGS
		;防止由于几乎全零的RFLAGS导致某些指令(比如CPUID)无法执行
		mov ecx, GUEST_RFLAGS_INDEX
		vmread rcx, rcx
		push rcx
		popfq
		;判断当前触发VM_EXIT的指令
		mov ecx, VM_EXIT_REASON_INDEX
		vmread rcx,rcx
		cmp rcx, 10
	jnz NZ
		;先把RIP加长度，越过当前指令
		mov ecx, VM_INSTRUCTION_LENGTH_INDEX
		vmread rcx, rcx ;长度
		mov eax, GUEST_RIP_INDEX
		vmread rax, rax ;RIP
		add rax, rcx ;调整后的RIP
		mov ecx, GUEST_RIP_INDEX
		vmwrite rcx, rax ;把调整后的RIP写入GUEST_RIP_INDEX FIELD
		;模拟执行CPUID
		mov rax, __RAX
		mov rcx, __RCX ;恢复原来刚进入时的RAX和RCX
		cpuid
		mov __RAX, rax
		mov __RBX, rbx
		mov __RCX, rcx
		mov __RDX, rdx ;CPUID可能会影响这四个寄存器
		pushfq
		pop rax ;别忘了保存最新的FLAGS寄存器
		mov ecx, GUEST_RFLAGS_INDEX
		vmwrite rcx, rax ;任何指令都可能隐式改变RFLAGS
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
NZ:
		mov ecx, GUEST_RSP_INDEX
		vmread rsp, rcx ;恢复虚拟机的RSP堆栈指针
		mov ecx, GUEST_RFLAGS_INDEX
		vmread rcx, rcx ;读取虚拟机的RFLAGS寄存器
		push rcx ;注意此时操作的堆栈指针是原来GUEST的RSP
		popfq ;恢复虚拟机的RFLAGS寄存器
		mov ecx, GUEST_RIP_INDEX
		vmread rcx, rcx ;恢复虚拟机的RIP指令指针
		mov DRIVER_RIP, rcx ;保存VMXOFF后跳转地址
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
		mov r15, __R15 ;恢复所有通用寄存器。由于准备不处理，所以没有任何值发生改动
		vmxoff
		jmp DRIVER_RIP
	__vsm__hostEntry ENDP

















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
