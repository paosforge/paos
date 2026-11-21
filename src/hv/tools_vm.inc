; Native tools instance constants. No public/guest admission ABI.
%ifndef PAOS_TOOLS_VM_INC
%define PAOS_TOOLS_VM_INC 1
%include "core/abi/memory_budget.inc"
TVM_OWNER equ 0x544f4f4c
TVM_EMPTY equ 0
TVM_PREPARING equ 1
TVM_LOADING equ 2
TVM_READY equ 3
TVM_RUNNING equ 4                     ; shared CPU turn tests AVM_RUNNING on tvm_state
TVM_RETIRING equ 5
TVM_SCRUBBING equ 6
TVM_FAULT equ 7                       ; uncertain teardown: allocation retained
TVM_PREPARE_US equ 60000000           ; PREPARING/LOADING bound, then retire
TVM_TURNS equ 64                      ; closed CPU turns per native tick
TVM_TURN_US equ 2000
; tools_vm_snapshot record (128 bytes, schema 1). Values only, no authority.
TVS_SCHEMA equ 0                      ; u64 1
TVS_INSTANCE equ 8                    ; u64 nonreused instance
TVS_START equ 16                      ; u32 nonreused START
TVS_STATE equ 20                      ; u32 TVM_RUNNING
TVS_OWNER equ 24                      ; u64 local owner identifier (session PID)
TVS_SESSION equ 32                    ; u64 session authority epoch
TVS_DIGEST equ 40                     ; 32 bytes, zero until a signed runtime binds
TVS_DEVICES equ 72                    ; u64 TVM_DEVICES
TVS_SERIAL equ 80                     ; u64 nonreused activation serial
TVS_BYTES equ 128                     ; 88..127 zero
TVM_DEVICE_PIC equ 1
TVM_DEVICE_PIT equ 2
TVM_DEVICE_CMOS equ 4
TVM_DEVICE_UART equ 8                 ; diagnostic only
TVM_DEVICE_STREAM equ 0x10            ; AV hostname stream (tools_vm_stream ports)
TVM_DEVICE_CONSOLE equ 0x20           ; D4b virtio-mmio console (the D4a window)
TVM_DEVICES equ TVM_DEVICE_PIC|TVM_DEVICE_PIT|TVM_DEVICE_CMOS|TVM_DEVICE_UART|TVM_DEVICE_STREAM|TVM_DEVICE_CONSOLE
TVM_CONTROL equ 0x200000
TVM_RAM_DEFAULT equ 0x80000000
TVM_RAM_LARGE equ 0xc0000000
TVM_CLEAR_SLICE equ 0x100000
; Preserve the app CPU/control layout for eventual shared CPU leaves, while
; placing THREE private directory pages away from its HSAVE/host-save pages.
TVM_ROOT equ 0x2000
TVM_PDPT equ 0x3000
TVM_PD equ 0x80000
TVM_PD_COUNT equ 3
; D4a: one trapped 4 KiB register window above tools RAM. The SLAT never maps
; it, so every guest access exits; the hardware GPA and direction decide.
TVM_MMIO_GPA equ 0xd0000000
TVM_MMIO_BYTES equ 0x1000            ; above TVM_RAM_LARGE: asserted in hv/tools_vm_mmio
TVM_CONSOLE_IRQ equ 5                ; private master PIC line of the window's console
TVM_CONSOLE_RING equ 4096            ; each private console ring; power of two
; Per-turn exit decode context, written only by the tools copy of the shared
; vendor exit capture and consumed once by hv/tools_vm_mmio.
TXC_VALID equ 0                       ; byte 1 = captured by this turn's exit
TXC_CPL equ 1                         ; byte, Intel SS.DPL / SVM VMCB CPL
TXC_INSN_N equ 2                      ; byte 0..15, SVM DecodeAssists count
TXC_CS_AR equ 4                       ; dword, CS rights in VMX AR layout
TXC_INSN equ 8                        ; 15 bytes, SVM guest instruction bytes
TXC_BYTES equ 24
TVM_VMCB_INSN_N equ 0x0d0             ; SVM control area: bytes fetched
TVM_VMCB_INSN equ 0x0d1               ; SVM control area: up to 15 bytes
TVM_VMCB_CPL equ 0x4cb                ; SVM save area: CPL
%endif
