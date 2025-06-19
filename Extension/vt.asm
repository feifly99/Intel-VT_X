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
EXTERN VEIF_VM_EXIT_INTERRUPTION_INFORMATION_INDEX: DWORD

EXTERN PER_CPU_REGS: QWORD

EXTERN pPte: QWORD
EXTERN fakePhyAddAligned: QWORD
EXTERN realPhyAddAligned: QWORD

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
		vmcall ;for execute vmxoff under root-operation mode
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
					sub rsp, r11 ;因为有call bugCheck，所以不得不减去x8h去对齐堆栈

					mov ecx, GUEST_FS_BASE_INDEX
					vmread rcx, rcx
					test rcx, rcx

			jnz	CAPABILITY_MODE
					cmp word ptr [rbp + 8h], 0
				jz	EXCEPTION_BITMAP_EXIT
					cmp word ptr [rbp + 8h], 2
				jz  TRIPLE_FAULT_EXIT
					cmp word ptr [rbp + 8h], 10
				jz  CPUID_EXIT
					cmp word ptr [rbp + 8h], 11
				jz  GETSEC_EXIT
					cmp word ptr [rbp + 8h], 13
				jz  INVD_EXIT
					cmp word ptr [rbp + 8h], 18
				jz  VMCALL_EXIT
					cmp word ptr [rbp + 8h], 31
				jz  RDMSR_EXIT
					cmp word ptr [rbp + 8h], 32
				jz  WRMSR_EXIT
					cmp word ptr [rbp + 8h], 48
				jz  EPT_VIOLATION
					cmp word ptr [rbp + 8h], 49
				jz  EPT_MISCONFIGURATION
					cmp word ptr [rbp + 8h], 50
				jz  INVEPT_EXIT
					cmp word ptr [rbp + 8h], 53
				jz  INVVPID_EXIT
					cmp word ptr [rbp + 8h], 55
				jz  XSETBV_EXIT
					mov rcx, qword ptr [rbp + 8h]
					shl rcx, 16
					call bugCheck
			EXCEPTION_BITMAP_EXIT:
					mov rcx, qword ptr [rbp + 18h]
					add rcx, 1
					mov eax, GUEST_RIP_INDEX
					vmwrite rax, rcx

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
			TRIPLE_FAULT_EXIT:
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
					mov rcx, 99999999h
					call bugCheck
			EPT_VIOLATION:
					mov ecx, VM_EXIT_QUALIFICATION_INDEX
					vmread rcx, rcx
					and rcx, 1
					cmp rcx, 1
				jz	WANNA_READ
					mov rax, realPhyAddAligned
					or  rax, 34h
					mov rcx, pPte
					mov qword ptr [rcx], rax
					
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
				WANNA_READ:
					mov rax, fakePhyAddAligned
					or  rax, 33h
					mov rcx, pPte
					mov qword ptr [rcx], rax

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
			EPT_MISCONFIGURATION:
					mov rcx, 6400h
					vmread rcx, rcx
					or rcx, 0CE000000h
					call bugCheck
			INVEPT_EXIT:
					mov rcx, 1111a6a6h
					call bugCheck
			INVVPID_EXIT:
					mov rcx, 2A2A2A2Ah
					call bugCheck
					vmxoff
			GETSEC_EXIT:
					mov rax, qword ptr [rbp + 90h]
					getsec

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
			INVD_EXIT:
					invd

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
			XSETBV_EXIT:
					mov rax, qword ptr [rbp + 90h]
					mov rcx, qword ptr [rbp + 80h]
					mov rdx, qword ptr [rbp + 78h]
					xsetbv

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
			CPUID_EXIT:
					cmp qword ptr [rbp + 90h], 22224444h
			jz HOOK_CPUID
					mov rax, qword ptr [rbp + 90h]
					mov rcx, qword ptr [rbp + 80h]
					cpuid
					mov qword ptr [rbp + 90h], rax
					mov qword ptr [rbp + 88h], rbx
					mov qword ptr [rbp + 80h], rcx
					mov qword ptr [rbp + 78h], rdx
					jmp STEP_RIP
			HOOK_CPUID:
					mov rcx, gs: [20h]
					mov ecx, dword ptr [rcx + 24h]
					inc ecx
					shl ecx, 16
					or ecx, 0FFFFh
					mov qword ptr [rbp + 90h], rcx
					mov qword ptr [rbp + 88h], 0ABABABABh
					mov qword ptr [rbp + 80h], 0CDCDCDCDh
					mov qword ptr [rbp + 78h], 0EFEFEFEFh
			STEP_RIP:
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
			RDMSR_EXIT:
					mov rcx, qword ptr [rbp + 80h]
					rdmsr
					mov qword ptr [rbp + 90h], rax
					mov qword ptr [rbp + 78h], rdx

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
			WRMSR_EXIT:
					mov rax, qword ptr [rbp + 90h]
					mov rcx, qword ptr [rbp + 80h]
					mov rdx, qword ptr [rbp + 78h]
					wrmsr
		
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
			VMCALL_EXIT:
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
					ret
CAPABILITY_MODE:
					cmp word ptr [rbp + 8h], 0
				jz	EXCEPTION_BITMAP_EXIT_CAPABILITY
					cmp word ptr [rbp + 8h], 2
				jz  TRIPLE_FAULT_EXIT_CAPABILITY
					cmp word ptr [rbp + 8h], 11
				jz  GETSEC_EXIT_CAPABILITY
					cmp word ptr [rbp + 8h], 13
				jz  INVD_EXIT_CAPABILITY
					cmp word ptr [rbp + 8h], 18
				jz  VMCALL_EXIT_CAPABILITY
					cmp word ptr [rbp + 8h], 31
				jz  RDMSR_EXIT_CAPABILITY
					cmp word ptr [rbp + 8h], 32
				jz  WRMSR_EXIT_CAPABILITY				
					cmp word ptr [rbp + 8h], 48
				jz  EPT_VIOLATION_CAPABILITY				
					cmp word ptr [rbp + 8h], 49
				jz  EPT_MISCONFIGURATION_CAPABILITY
					cmp word ptr [rbp + 8h], 50
				jz  INVEPT_EXIT_CAPABILITY
					cmp word ptr [rbp + 8h], 53
				jz  INVVPID_EXIT_CAPABILITY
					cmp word ptr [rbp + 8h], 55
				jz  XSETBV_EXIT_CAPABILITY
					mov rcx, qword ptr [rbp + 8h]
					shl rcx, 16
					call bugCheck
			EXCEPTION_BITMAP_EXIT_CAPABILITY:
					mov ax, fs
					mov fs, ax

					mov rcx, qword ptr [rbp + 18h]
					add rcx, 1
					mov eax, GUEST_RIP_INDEX
					vmwrite rax, rcx

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
			TRIPLE_FAULT_EXIT_CAPABILITY:
					mov ax, fs
					mov fs, ax

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
					mov rcx, 99999999h
					call bugCheck
			EPT_VIOLATION_CAPABILITY:
					mov ecx, VM_EXIT_QUALIFICATION_INDEX
					vmread rcx, rcx
					and rcx, 1
					cmp rcx, 1
				jz	WANNA_READ_CAPABILITY
					mov ax, fs
					mov fs, ax

					mov rax, realPhyAddAligned
					or  rax, 34h
					mov rcx, pPte
					mov qword ptr [rcx], rax
					
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
				WANNA_READ_CAPABILITY:
					mov ax, fs
					mov fs, ax

					mov rax, fakePhyAddAligned
					or  rax, 33h
					mov rcx, pPte
					mov qword ptr [rcx], rax

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
			EPT_MISCONFIGURATION_CAPABILITY:
					mov rcx, 6400h
					vmread rcx, rcx
					or rcx, 0EC000000h
					call bugCheck
			INVEPT_EXIT_CAPABILITY:
					mov rcx, 7A7A7A7Ah
					call bugCheck
					vmxoff
			INVVPID_EXIT_CAPABILITY:
					mov rcx, 2A2A2A2Ah
					call bugCheck
					vmxoff
			GETSEC_EXIT_CAPABILITY:
					mov ax, fs
					mov fs, ax

					mov rax, qword ptr [rbp + 90h]
					getsec

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
			INVD_EXIT_CAPABILITY:
					mov ax, fs
					mov fs, ax

					invd

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
			XSETBV_EXIT_CAPABILITY:
					mov ax, fs
					mov fs, ax

					mov rax, qword ptr [rbp + 90h]
					mov rcx, qword ptr [rbp + 80h]
					mov rdx, qword ptr [rbp + 78h]
					xsetbv

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
			CPUID_EXIT_CAPABILITY:
					mov ax, fs
					mov fs, ax

					mov rax, qword ptr [rbp + 90h]
					mov rcx, qword ptr [rbp + 80h]
					cpuid
					mov qword ptr [rbp + 90h], rax
					mov qword ptr [rbp + 88h], rbx
					mov qword ptr [rbp + 80h], rcx
					mov qword ptr [rbp + 78h], rdx

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
			RDMSR_EXIT_CAPABILITY:
					mov ax, fs
					mov fs, ax

					mov rcx, qword ptr [rbp + 80h]
					rdmsr
					mov qword ptr [rbp + 90h], rax
					mov qword ptr [rbp + 78h], rdx

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
			WRMSR_EXIT_CAPABILITY:
					mov ax, fs
					mov fs, ax

					mov rax, qword ptr [rbp + 90h]
					mov rcx, qword ptr [rbp + 80h]
					mov rdx, qword ptr [rbp + 78h]
					wrmsr
		
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
			VMCALL_EXIT_CAPABILITY:
					mov ax, fs
					mov fs, ax

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
					ret
	__vsm__hostEntry ENDP

END