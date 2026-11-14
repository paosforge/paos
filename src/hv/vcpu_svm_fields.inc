%ifndef HV_VCPU_SVM_FIELDS_INC
%define HV_VCPU_SVM_FIELDS_INC 1
; VMCB control area (AMD APM vol. 2, appendix B).
VMCB_CR_ICPT        equ 0x000               ; CR read intercepts bits 0-15, CR write intercepts 16-31
VMCB_EXC            equ 0x008               ; exception intercepts, one bit per vector
VMCB_ICPT1          equ 0x00C
VMCB_ICPT2          equ 0x010
VMCB_IOPM           equ 0x040
VMCB_MSRPM          equ 0x048
VMCB_ASID           equ 0x058
VMCB_TLB            equ 0x05C               ; TLB_CONTROL: 1 flush all, 3 flush this ASID
VMCB_VINTR          equ 0x060               ; V_IRQ 8, V_INTR_PRIO 16-19, V_IGN_TPR 20, V_INTR_MASKING 24
VMCB_SHADOW         equ 0x068               ; INTERRUPT_SHADOW bit 0
VMCB_EXITCODE       equ 0x070
VMCB_EXITINFO1      equ 0x078
VMCB_EXITINFO2      equ 0x080
VMCB_EXITINTINFO    equ 0x088
VMCB_NP             equ 0x090               ; NP_ENABLE bit 0
VMCB_EVENTINJ       equ 0x0A8
VMCB_NCR3           equ 0x0B0
VMCB_CLEAN          equ 0x0C0               ; always 0: every field reloads at every VMRUN
VMCB_NRIP           equ 0x0C8
; VMCB state save area.
VMCB_ES             equ 0x400               ; then CS SS DS FS GS GDTR LDTR IDTR TR, 16 B each
VMCB_CS             equ 0x410
VMCB_SS             equ 0x420
VMCB_DS             equ 0x430
VMCB_FS             equ 0x440
VMCB_GS             equ 0x450
VMCB_TR             equ 0x490
VMCB_EFER           equ 0x4D0
VMCB_CR4            equ 0x548
VMCB_CR3            equ 0x550
VMCB_CR0            equ 0x558
VMCB_DR7            equ 0x560
VMCB_DR6            equ 0x568
VMCB_RFLAGS         equ 0x570
VMCB_RIP            equ 0x578
VMCB_RSP            equ 0x5D8
VMCB_CR2            equ 0x640
VMCB_RAX            equ 0x5F8
VMCB_GPAT           equ 0x668

; Intercepts = the VMX baseline plus what SVM needs explicitly (DESIGN §6).
SVM_ICPT1_INTR      equ 1 << 0
SVM_ICPT1_NMI       equ 1 << 1
SVM_ICPT1_SMI       equ 1 << 2              ; leave guest before firmware handling
SVM_ICPT1_INIT      equ 1 << 3              ; an INIT in guest mode would reset the CPU
SVM_ICPT1_VINTR     equ 1 << 4              ; armed only with V_IRQ (interrupt window)
SVM_ICPT1_CPUID     equ 1 << 18
SVM_ICPT1_INVD      equ 1 << 22             ; a guest INVD would drop dirty host lines
SVM_ICPT1_HLT       equ 1 << 24
SVM_ICPT1_INVLPGA   equ 1 << 26
SVM_ICPT1_IOIO      equ 1 << 27
SVM_ICPT1_MSR       equ 1 << 28
SVM_ICPT1_TASKSW    equ 1 << 29
SVM_ICPT1_SHUTDOWN  equ 1 << 31             ; a guest triple fault would shut the CPU down
SVM_ICPT1           equ SVM_ICPT1_INTR | SVM_ICPT1_NMI | SVM_ICPT1_SMI | SVM_ICPT1_INIT | SVM_ICPT1_CPUID | SVM_ICPT1_INVD | SVM_ICPT1_HLT | SVM_ICPT1_INVLPGA | SVM_ICPT1_IOIO | SVM_ICPT1_MSR | SVM_ICPT1_TASKSW | SVM_ICPT1_SHUTDOWN
SVM_ICPT_CR4_WRITE  equ 1 << 20             ; HV-XCR0 V5: every guest MOV to CR4 exits (#VMEXIT 0x14)
SVM_CPUID7_PKX      equ (1 << 3) | (1 << 23) ; CPUID 7.0 ECX: PKU, KL (CR4.PKE / CR4.KL can be set)
SVM_ICPT2           equ 0x7F | (1 << 13)    ; VMRUN (mandatory), VMMCALL, VMLOAD, VMSAVE, STGI, CLGI, SKINIT; XSETBV
; Private S7 additionally traps native counters/cache operations and idle
; instructions; unsupported exits terminate through the closed dispatcher.
VSM_ICPT1          equ SVM_ICPT1 | (1 << 15) ; RDPMC
VSM_ICPT2          equ SVM_ICPT2 | (0xF << 9) ; WBINVD/MONITOR/MWAIT/conditional
SVM_VINTR_MASKING   equ 1 << 24             ; the guest's IF/TPR gate virtual interrupts only
SVM_VIRQ_BITS       equ (1 << 8) | (0xF << 16) | (1 << 20)   ; V_IRQ, V_INTR_PRIO 15, V_IGN_TPR
SVM_EFER_SVME       equ 1 << 12

SVM_EXC_ERRCODE     equ 0x60227D00          ; vectors 8, 10-14, 17, 21, 29, 30 push an error code

; Exit record (hv_svm_rec): the normalised exit, read through hv_svm_guest_read.
SVM_REC_REASON      equ 0                   ; dword, VMX basic exit reason
SVM_REC_INFO        equ 4                   ; dword, VMX exit interruption information
SVM_REC_QUAL        equ 8                   ; qword, VMX exit qualification
SVM_REC_ILEN        equ 16                  ; dword, instruction length (0: none, NPF decodes)
SVM_REC_GPA         equ 24                  ; qword, faulting guest-physical address (NPF)

SVM_RD_D            equ 1 << 12
SVM_RD_W            equ 2 << 12
SVM_RD_BIT0         equ 3 << 12
SVM_RD_REC          equ 1 << 14

%endif
