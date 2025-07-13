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

EXTERN pPte: QWORD
EXTERN realPhyAddAligned: QWORD
EXTERN fakePhyAddAligned: QWORD

.code
	
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

	__vsm__testX2APICmode PROC
		mov eax, 1
		cpuid
		mov eax, ecx
		ret
	__vsm__testX2APICmode ENDP

	__vsm__vmlaunchSaveRegisters PROC
		;cli
		mov qword ptr [rsp + 8h], rax
		mov qword ptr [rsp + 10h], rcx
		mov rax, qword ptr [rsp] ;rip
		mov qword ptr [rsp + 18h], rax

		mov rax, gs: [20h]
		mov eax, dword ptr [rax + 24h] ;cpu index
		shl eax, 3
		mov rcx, PER_CPU_REGS
		add rcx, rax

		mov rcx, qword ptr [rcx] ;PER_CPU_REGS[cpu index]
		mov rax, qword ptr [rsp + 8h]
		mov qword ptr [rcx + 0h], rax  ;0
		mov qword ptr [rcx + 8h], rbx  ;1
		mov rax, qword ptr [rsp + 10h]
		mov qword ptr [rcx + 10h], rax ;rcx (2)
		mov qword ptr [rcx + 18h], rdx ;3
		mov qword ptr [rcx + 20h], rsi ;4
		mov qword ptr [rcx + 28h], rdi ;5
		mov qword ptr [rcx + 30h], rsp ;6
		mov qword ptr [rcx + 38h], rbp ;7
		mov qword ptr [rcx + 40h], r8  ;8
		mov qword ptr [rcx + 48h], r9  ;9
		mov qword ptr [rcx + 50h], r10 ;10
		mov qword ptr [rcx + 58h], r11 ;11
		mov qword ptr [rcx + 60h], r12 ;12
		mov qword ptr [rcx + 68h], r13 ;13
		mov qword ptr [rcx + 70h], r14 ;14
		mov qword ptr [rcx + 78h], r15 ;15
		mov rax, cr0
		mov qword ptr [rcx + 80h], rax ;16
		mov rax, cr3
		mov qword ptr [rcx + 88h], rax ;17
		mov rax, cr4
		mov qword ptr [rcx + 90h], rax ;18
		pushfq
		pop rax
		mov qword ptr [rcx + 98h], rax ;19
		mov rax, qword ptr [rcx + 18h]
		mov qword ptr [rcx + 0A0h], rax ;20
		;sti
		vmlaunch
		mov ecx, 2222AAAAh
		call bugCheck
	__vsm__vmlaunchSaveRegisters ENDP

	__vsm__guestEntry PROC
		;当前CPU的RSP为 GUEST_RSP，是GUEST外部分配的那个栈底
		mov rax, gs: [20h]
		mov eax, dword ptr [rax + 24h]
		shl eax, 3
		mov rcx, PER_CPU_REGS
		add rcx, rax
		mov rcx, qword ptr [rcx]

		mov rbx, qword ptr [rcx + 8h] 
		mov rdx, qword ptr [rcx + 18h]
		mov rsi, qword ptr [rcx + 20h]
		mov rdi, qword ptr [rcx + 28h]
		mov rbp, qword ptr [rcx + 38h]
		mov r8 , qword ptr [rcx + 40h]
		mov r9 , qword ptr [rcx + 48h]
		mov r10, qword ptr [rcx + 50h]
		mov r11, qword ptr [rcx + 58h]
		mov r12, qword ptr [rcx + 60h]
		mov r13, qword ptr [rcx + 68h]
		mov r14, qword ptr [rcx + 70h]
		mov r15, qword ptr [rcx + 78h]
		mov rax, qword ptr [rcx + 80h]
		mov cr0, rax
		mov rax, qword ptr [rcx + 88h]
		mov cr3, rax
		mov rax, qword ptr [rcx + 90h]
		mov cr4, rax
		
		mov rax, qword ptr [rcx + 98h]
		push rax
		popfq

		mov rax, qword ptr [rcx + 0h]
		mov rsp, qword ptr [rcx + 30h]
		mov rcx, qword ptr [rcx + 10h]
		
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
		push r15
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

		mov rbp, rsp
		mov r11, 68h
		sub rsp, r11

		;确保x86模式的兼容性，提前进行fs段寄存器深赋值
		mov ax, fs
		mov fs, ax

		call VM_EXIT_HANDLER

		mov rcx, qword ptr [rbp + 0h]
		mov rax, qword ptr [rbp + 18h]
		add rax, rcx
		mov ecx, GUEST_RIP_INDEX
		vmwrite rcx, rax

		mov rsp, rbp
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
		pop rax

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
		cmp word ptr [rbp + 8h], 48
	jz  REASON_EPT_VIOLATION
		cmp word ptr [rbp + 8h], 49
	jz  REASON_EPT_MISCONFIGURATION
		mov rcx, 66668888h
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
REASON_EPT_VIOLATION:
		call EPT_VIOLATION_EXIT
	jmp RETURN
REASON_EPT_MISCONFIGURATION:
		call EPT_MISCONFIGURATION_EXIT
	jmp RETURN

RETURN:
		add rsp, 48h
		ret
	VM_EXIT_HANDLER ENDP

	CPUID_EXIT PROC
		sub rsp, 48h
		mov rax, qword ptr [rbp + 90h]
		mov rcx, qword ptr [rbp + 80h]
		cpuid
		mov qword ptr [rbp + 90h], rax
		mov qword ptr [rbp + 88h], rbx
		mov qword ptr [rbp + 80h], rcx
		mov qword ptr [rbp + 78h], rdx
		add rsp, 48h
		ret
	CPUID_EXIT ENDP

	RDMSR_EXIT PROC
		sub rsp, 48h
		mov rcx, qword ptr [rbp + 80h]
		rdmsr
		mov qword ptr [rbp + 90h], rax
		mov qword ptr [rbp + 78h], rdx
		add rsp, 48h
		ret
	RDMSR_EXIT ENDP

	WRMSR_EXIT PROC
		sub rsp, 48h
		mov rax, qword ptr [rbp + 90h]
		mov rcx, qword ptr [rbp + 80h]
		mov rdx, qword ptr [rbp + 78h]
		wrmsr
		add rsp, 48h
		ret
	WRMSR_EXIT ENDP

	VMCALL_EXIT PROC
		sub rsp, 48h
		mov rax, qword ptr [rbp + 10h]
		push rax
		popfq

		mov rsp, rbp
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
		pop rax
				
		mov eax, GUEST_RSP_INDEX
		vmread rsp, rax

		vmxoff
		ret ;注意此时的rsp == GUEST_RSP, ret指令返回到的是GUEST.
	VMCALL_EXIT ENDP

	EPT_VIOLATION_EXIT PROC
		sub rsp, 68h
		;EPT不需要步进RIP指针
		mov qword ptr [rbp + 0h], 0

		mov ecx, VM_EXIT_QUALIFICATION_INDEX
		vmread rcx, rcx
		and rcx, 1
		cmp rcx, 1
	jz	WANNA_READ
		mov rax, realPhyAddAligned
		or  rax, 34h
		mov rcx, pPte
		mov qword ptr [rcx], rax
		jmp	EPT_RETURN
	WANNA_READ:
		mov rax, fakePhyAddAligned
		or  rax, 33h
		mov rcx, pPte
		mov qword ptr [rcx], rax
		jmp	EPT_RETURN
	EPT_RETURN:
		add rsp, 68h
		ret
	EPT_VIOLATION_EXIT ENDP
	
	EPT_MISCONFIGURATION_EXIT PROC
		sub rsp, 68h
		mov rcx, 0DEADBEEFh
		call bugCheck
		;never executing...
		add rsp, 68h
		ret
	EPT_MISCONFIGURATION_EXIT ENDP

END
