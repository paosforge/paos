;; MODULE hv/tools_vm_console
;; LAYER 5
;; EXPORTS tools_vm_console_read, tools_vm_console_write, tools_vm_console_reset, tools_vm_console_pump, tvmc_input, tvmc_drain, tvmc_resize, tvmc_isr, tvmc_status, tvmc_fault, tvmc_ignored, tvmc_malformed, tvmc_tx_full, tvmc_tx_len, tvmc_rx_len, tvmc_state_begin, tvmc_state_end, tvmc_unbind
;; IMPORTS hv/tools_vm_memory
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Claude / rc-vm-claude. Tools D4b: the virtio-mmio v2 console behind
; the D4a register window (SEC 121375 A1, V1-V7; separate from the driver's
; hv_vcon, which is untouched). DeviceID 3, queue 0 RX, queue 1 TX, features
; VERSION_1 and (D5b) SIZE. The device sees only the window offset, the
; direction, the width and the value that hv/tools_vm_mmio hands it (SEC
; 121371, 121716 N5).
; - V1: avail.idx, every ring slot and every descriptor are copied once into
;   private storage, then validated, then used; buffer bytes are read once.
; - V2: (avail.idx - last) above the queue size puts the device in
;   DEVICE_NEEDS_RESET with nothing processed. At most queue size (<=16)
;   heads per serve, each of at most 4 direct descriptors.
; - D5b (SEC 121684 Z1-Z4, 121716 N5/N6): only SIZE (bit 0) is offered besides
;   VERSION_1; MULTIPORT and EMERG_WRITE never are. The config region
;   0x100..0x107 is read-only: cols/rows at 0x100..0x103 by byte, 0x104..0x107
;   read 0, every write is ignored and counted. The size comes only from
;   tvmc_resize (the admitted facade, 1..0xffff each); a change bumps
;   ConfigGeneration (0x0fc) and raises InterruptStatus bit 1 only if SIZE
;   was accepted. Unbind, device reset and retire zero the pair and the
;   generation.
; - V3: FEATURES_OK holds only for exactly VERSION_1 or VERSION_1|SIZE (Z2).
;   QueueReady=1 needs it,
;   a power-of-two size <=16 and aligned rings inside own RAM. Ring and
;   buffer GPAs go through tools_vm_gpa (the tools START/token) on every
;   serve; no host pointer is kept across serves.
; - V4: RX writes only device-writable descriptors, within their lengths;
;   used.len is the bytes written. TX reads only device-readable ones. A
;   direction mismatch, NEXT loop, fifth descriptor, INDIRECT, zero length,
;   a buffer outside own RAM, or a TX chain larger than the ring is retired
;   with used.len 0 and no effect.
; - V5: a TX chain that does not fit stays in avail (not consumed) until the
;   ring drains; nothing wraps over unread bytes. Reset, device reset and the
;   retire path wipe both private rings.
; - V6: bytes are data only. The private rings are reached only through
;   tvmc_input/tvmc_drain, whose only callers are hv/tools_vm's admitted
;   facade. No hv_linux console, CLI, Terminal or remote route exists here.
%include "hv/tools_vm.inc"
%include "core/abi/wdata.inc"

TVMC_QMAX equ 16
TVMC_CHAIN equ 4
TVMC_RING equ TVM_CONSOLE_RING
TVMC_VENDOR equ 0x536f6150           ; 'PaOS'
TVMC_NEXT equ 1
TVMC_WRITE equ 2
TVMC_INDIRECT equ 4
TVMC_DRIVER_OK equ 4
TVMC_FEATURES_OK equ 8
TVMC_NEEDS_RESET equ 0x40

; EDI window offset (4-aligned, <0x1000) ->EAX register value.
tools_vm_console_read:
    lea eax,[rdi-0x100]
    cmp eax,8
    jb .config
    cmp esi,4                        ; N5: every register is 4-byte only
    jne .refused
    cmp edi,0x000
    je .magic
    cmp edi,0x004
    je .version
    cmp edi,0x008
    je .device
    cmp edi,0x00c
    je .vendor
    cmp edi,0x010
    je .features
    cmp edi,0x034
    je .qmax
    cmp edi,0x044
    je .qready
    cmp edi,0x060
    je .isr
    cmp edi,0x070
    je .status
    cmp edi,0x0fc                    ; ConfigGeneration (Z3)
    je .generation
    inc qword [rel tvmc_ignored]
.zero:
    xor eax,eax
    ret
.magic:
    mov eax,0x74726976
    ret
.version:
    mov eax,2
    ret
.device:
    mov eax,3
    ret
.vendor:
    mov eax,TVMC_VENDOR
    ret
.features:
    xor eax,eax                      ; Z1: SIZE (bit 0) and VERSION_1 (bit 32) only
    cmp dword [rel tvmc_dfsel],2
    setb al
    ret
.qmax:
    xor eax,eax
    cmp dword [rel tvmc_qsel],2
    jae .qmax_out
    mov eax,TVMC_QMAX
.qmax_out:
    ret
.qready:
    xor eax,eax
    mov ecx,[rel tvmc_qsel]
    cmp ecx,2
    jae .qready_out
    lea rdx,[rel tvmc_q_ready]
    movzx eax,byte [rdx+rcx]
.qready_out:
    ret
.isr:
    mov eax,[rel tvmc_isr]
    ret
.status:
    mov eax,[rel tvmc_status]
    ret
.generation:
    mov eax,[rel tvmc_cfg_gen]
    ret
.refused:
    inc qword [rel tvmc_ignored]
    xor eax,eax
    ret
; Z3/N6: 0x100..0x103 are cols and rows at the accessed byte; 0x104..0x107
; (max_nr_ports, emerg_wr) read 0. EAX config byte index, ESI width 1, 2 or
; 4, naturally aligned (the decoder's N2, checked again here).
.config:
    cmp esi,1
    je .config_read
    cmp esi,2
    je .config_aligned
    cmp esi,4
    jne .refused
.config_aligned:
    lea ecx,[rsi-1]
    test eax,ecx
    jnz .refused
.config_read:
    lea ecx,[rax*8]
    movzx eax,word [rel tvmc_rows]
    shl eax,16
    movzx edx,word [rel tvmc_cols]
    or eax,edx                       ; cols | rows << 16, zero above
    shr rax,cl
    cmp esi,2
    ja .config_out
    je .config_word
    movzx eax,al
    ret
.config_word:
    movzx eax,ax
.config_out:
    ret

; EDI window offset, ESI value. Device state and own RAM only.
tools_vm_console_write:
    cmp edi,0x014
    je .dfsel
    cmp edi,0x020
    je .drvfeat
    cmp edi,0x024
    je .drvfsel
    cmp edi,0x030
    je .qsel
    cmp edi,0x038
    je .qnum
    cmp edi,0x044
    je .qready
    cmp edi,0x050
    je .notify
    cmp edi,0x064
    je .ack
    cmp edi,0x070
    je .status
    lea eax,[rdi-0x080]
    cmp eax,0x024
    ja .ignored
    test eax,8                       ; 0x80/84, 0x90/94, 0xa0/a4 only
    jnz .ignored
    call tvmc_setup_sel
    cmp ecx,-1
    je .ignored
    lea eax,[rdi-0x080]
    mov edx,eax
    and edx,4                        ; high half
    shr eax,4                        ; 0 desc, 1 avail (driver), 2 used (device)
    lea r8,[rel tvmc_q_desc]
    shl eax,4                        ; 16 bytes per address pair
    add r8,rax
    lea r8,[r8+rcx*8]
    mov [r8+rdx],esi
    ret
.ignored:
    inc qword [rel tvmc_ignored]
    ret
.dfsel:
    mov [rel tvmc_dfsel],esi
    ret
.drvfsel:
    mov [rel tvmc_drvfsel],esi
    ret
.drvfeat:
    test dword [rel tvmc_status],TVMC_FEATURES_OK
    jnz .ignored                     ; fixed once accepted
    mov ecx,[rel tvmc_drvfsel]
    cmp ecx,2
    jae .feat_high
    lea rdx,[rel tvmc_drvfeat]
    mov [rdx+rcx*4],esi
    ret
.feat_high:
    test esi,esi
    jz .done
    mov byte [rel tvmc_feat_bad],1
.done:
    ret
.qsel:
    mov [rel tvmc_qsel],esi
    ret
.qnum:
    call tvmc_setup_sel
    cmp ecx,-1
    je .ignored
    lea rdx,[rel tvmc_q_num]
    mov [rdx+rcx*4],esi
    ret
.qready:
    mov ecx,[rel tvmc_qsel]
    cmp ecx,2
    jae .ignored
    lea rdx,[rel tvmc_q_ready]
    test esi,esi
    jz .queue_off
    cmp esi,1
    jne .ignored
    cmp byte [rdx+rcx],0
    jne .ignored
    push rcx
    mov edi,ecx
    call tvmc_queue_valid
    pop rcx
    test eax,eax
    jz .ignored
    lea rdx,[rel tvmc_q_ready]
    mov byte [rdx+rcx],1
    lea rdx,[rel tvmc_q_last]
    mov word [rdx+rcx*2],0
    lea rdx,[rel tvmc_q_usedidx]
    mov word [rdx+rcx*2],0
    ret
.queue_off:
    mov byte [rdx+rcx],0
    ret
.notify:
    test dword [rel tvmc_status],TVMC_DRIVER_OK
    jz .ignored
    cmp esi,1
    je tvmc_tx_serve
    test esi,esi
    jz tvmc_rx_serve
    jmp .ignored
.ack:
    not esi
    and [rel tvmc_isr],esi
    ret
.status:
    test esi,esi
    jz tools_vm_console_reset
    mov eax,[rel tvmc_status]
    test esi,TVMC_FEATURES_OK
    jz .status_store
    test eax,TVMC_FEATURES_OK
    jnz .status_store
    cmp dword [rel tvmc_drvfeat],1   ; Z2: low word 0 or SIZE
    ja .feat_refuse
    cmp dword [rel tvmc_drvfeat+4],1
    jne .feat_refuse
    cmp byte [rel tvmc_feat_bad],0
    je .status_store
.feat_refuse:
    and esi,~TVMC_FEATURES_OK        ; V3: the driver sees FEATURES_OK unset
.status_store:
    and eax,TVMC_NEEDS_RESET         ; the device's own bit stays
    or esi,eax
    mov [rel tvmc_status],esi
    ret

; ->ECX selected queue still being set up (not ready) /-1. Preserves RDI/RSI.
tvmc_setup_sel:
    mov ecx,[rel tvmc_qsel]
    cmp ecx,2
    jae .no
    lea rax,[rel tvmc_q_ready]
    cmp byte [rax+rcx],0
    jne .no                          ; V7: no setup while ready
    ret
.no:
    mov ecx,-1
    ret

; EDI queue ->EAX 1 the queue may become ready /0.
tvmc_queue_valid:
    test dword [rel tvmc_status],TVMC_FEATURES_OK
    jz .bad
    cmp byte [rel tvmc_fault],0
    jne .bad
    jmp tvmc_map
.bad:
    xor eax,eax
    ret

; EDI queue ->EAX 1 with tvmc_m_* set from this serve's conversion /0.
tvmc_map:
    push rbx
    push r12
    sub rsp,8
    mov ebx,edi
    lea rdx,[rel tvmc_q_num]
    mov eax,[rdx+rbx*4]
    test eax,eax
    jz .bad
    cmp eax,TVMC_QMAX
    ja .bad
    lea ecx,[rax-1]
    test eax,ecx
    jnz .bad                         ; power of two
    mov [rel tvmc_m_num],eax
    mov r12d,eax
    lea rdx,[rel tvmc_q_desc]
    mov rdx,[rdx+rbx*8]
    test rdx,15
    jnz .bad
    mov ecx,r12d
    shl ecx,4
    call tvmc_gpa
    test rax,rax
    jz .bad
    mov [rel tvmc_m_desc],rax
    lea rdx,[rel tvmc_q_avail]
    mov rdx,[rdx+rbx*8]
    test rdx,1
    jnz .bad
    lea ecx,[r12*2+6]
    call tvmc_gpa
    test rax,rax
    jz .bad
    mov [rel tvmc_m_avail],rax
    lea rdx,[rel tvmc_q_used]
    mov rdx,[rdx+rbx*8]
    test rdx,3
    jnz .bad
    lea ecx,[r12*8+6]
    call tvmc_gpa
    test rax,rax
    jz .bad
    mov [rel tvmc_m_used],rax
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; RDX tools GPA, ECX length ->RAX own-RAM HVA /0 (the original allocation join).
tvmc_gpa:
    mov ecx,ecx
    mov rdi,[rel tvm_start]
    mov rsi,[rel tvm_token]
    jmp tools_vm_gpa

; Queue 1 at its notify, or the pump after a drain. At most one queue size
; of heads; a chain that does not fit stays in avail (V5).
tvmc_tx_serve:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp byte [rel tvmc_fault],0
    jne .out
    cmp byte [rel tvmc_q_ready+1],0
    je .out
    mov edi,1
    call tvmc_map
    test eax,eax
    jz .fault
    mov r12,[rel tvmc_m_avail]
    movzx eax,word [r12+2]           ; V1: avail.idx once
    movzx ecx,word [rel tvmc_q_last+2]
    sub eax,ecx
    and eax,0xffff
    cmp eax,[rel tvmc_m_num]
    ja .fault                        ; V2
    mov r13d,eax
    xor r15d,r15d
.head:
    test r13d,r13d
    jz .publish
    movzx eax,word [rel tvmc_q_last+2]
    mov ecx,[rel tvmc_m_num]
    dec ecx
    and eax,ecx
    movzx r14d,word [r12+4+rax*2]    ; V1: the slot once
    mov edi,r14d
    xor esi,esi                      ; device-readable only
    call tvmc_chain
    cmp eax,-1
    je .malformed
    mov ecx,TVMC_RING
    sub ecx,[rel tvmc_tx_len]
    cmp eax,ecx
    ja .full
    call tvmc_tx_take
    xor esi,esi
    jmp .used
.malformed:
    inc qword [rel tvmc_malformed]
    xor esi,esi
.used:
    mov edi,r14d
    mov edx,1
    call tvmc_used_put
    inc word [rel tvmc_q_last+2]
    inc r15d
    dec r13d
    jmp .head
.full:
    inc qword [rel tvmc_tx_full]
    mov byte [rel tvmc_tx_blocked],1
.publish:
    test r15d,r15d
    jz .out
    mov edi,1
    call tvmc_used_idx
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.fault:
    call tvmc_fault_set
    jmp .out

; Queue 0 at its notify or the per-turn pump, while private input waits.
tvmc_rx_serve:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp byte [rel tvmc_fault],0
    jne .out
    cmp byte [rel tvmc_q_ready],0
    je .out
    cmp dword [rel tvmc_rx_len],0
    je .out
    xor edi,edi
    call tvmc_map
    test eax,eax
    jz .fault
    mov r12,[rel tvmc_m_avail]
    movzx eax,word [r12+2]           ; V1: avail.idx once
    movzx ecx,word [rel tvmc_q_last]
    sub eax,ecx
    and eax,0xffff
    cmp eax,[rel tvmc_m_num]
    ja .fault                        ; V2
    mov r13d,eax
    xor r15d,r15d
.head:
    test r13d,r13d
    jz .publish
    cmp dword [rel tvmc_rx_len],0
    je .publish
    movzx eax,word [rel tvmc_q_last]
    mov ecx,[rel tvmc_m_num]
    dec ecx
    and eax,ecx
    movzx r14d,word [r12+4+rax*2]
    mov edi,r14d
    mov esi,TVMC_WRITE               ; device-writable only
    call tvmc_chain
    cmp eax,-1
    je .malformed
    call tvmc_rx_give
    mov esi,eax
    jmp .used
.malformed:
    inc qword [rel tvmc_malformed]
    xor esi,esi
.used:
    mov edi,r14d
    xor edx,edx
    call tvmc_used_put
    inc word [rel tvmc_q_last]
    inc r15d
    dec r13d
    jmp .head
.publish:
    test r15d,r15d
    jz .out
    xor edi,edi
    call tvmc_used_idx
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.fault:
    call tvmc_fault_set
    jmp .out

; EDI head, ESI required WRITE flag (0 TX, TVMC_WRITE RX), tvmc_m_* mapped
; ->EAX chain bytes with tvmc_chain_* filled /-1 malformed. V1: each
; descriptor is copied once and only the private copy is validated and used.
tvmc_chain:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov ebx,edi
    mov r12d,esi
    xor r13d,r13d                    ; descriptors
    xor r14d,r14d                    ; visited
    xor r15d,r15d                    ; bytes
.desc:
    cmp ebx,[rel tvmc_m_num]
    jae .bad
    bts r14d,ebx
    jc .bad                          ; NEXT loop
    cmp r13d,TVMC_CHAIN
    jae .bad                         ; a fifth descriptor
    mov rsi,[rel tvmc_m_desc]
    mov eax,ebx
    shl eax,4
    mov rcx,[rsi+rax]
    mov rdx,[rsi+rax+8]
    lea rdi,[rel tvmc_chain_desc]
    mov eax,r13d
    shl eax,4
    mov [rdi+rax],rcx
    mov [rdi+rax+8],rdx
    mov eax,edx                      ; len
    test eax,eax
    jz .bad
    shr rdx,32                       ; flags | next<<16
    test edx,TVMC_INDIRECT
    jnz .bad
    mov ecx,edx
    and ecx,TVMC_WRITE
    cmp ecx,r12d
    jne .bad                         ; V4 direction
    add r15d,eax
    jc .bad
    test r12d,r12d
    jnz .range
    cmp r15d,TVMC_RING
    ja .bad                          ; a TX chain that can never fit
.range:
    lea rdi,[rel tvmc_chain_desc]
    mov eax,r13d
    shl eax,4
    mov rdx,[rdi+rax]
    mov ecx,[rdi+rax+8]
    call tvmc_gpa                    ; the whole buffer in own RAM
    test rax,rax
    jz .bad
    lea rdi,[rel tvmc_chain_hva]
    mov [rdi+r13*8],rax
    lea rdi,[rel tvmc_chain_desc]
    mov eax,r13d
    shl eax,4
    inc r13d
    movzx ecx,word [rdi+rax+12]
    test ecx,TVMC_NEXT
    jz .done
    movzx ebx,word [rdi+rax+14]
    jmp .desc
.done:
    mov [rel tvmc_chain_n],r13d
    mov eax,r15d
    jmp .out
.bad:
    mov eax,-1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; The validated TX chain's bytes, read once, onto the private TX ring (room
; already checked).
tvmc_tx_take:
    xor r8d,r8d
.desc:
    cmp r8d,[rel tvmc_chain_n]
    jae .out
    lea rax,[rel tvmc_chain_hva]
    mov rsi,[rax+r8*8]
    lea rax,[rel tvmc_chain_desc]
    mov ecx,r8d
    shl ecx,4
    mov r9d,[rax+rcx+8]
    lea r10,[rel tvmc_tx_buf]
.byte:
    test r9d,r9d
    jz .next
    mov eax,[rel tvmc_tx_head]
    add eax,[rel tvmc_tx_len]
    and eax,TVMC_RING-1
    mov dl,[rsi]
    mov [r10+rax],dl
    inc rsi
    inc dword [rel tvmc_tx_len]
    dec r9d
    jmp .byte
.next:
    inc r8d
    jmp .desc
.out:
    ret

; Private input into the validated RX chain, within each descriptor's length
; ->EAX bytes written (used.len).
tvmc_rx_give:
    xor r8d,r8d
    xor r11d,r11d
.desc:
    cmp r8d,[rel tvmc_chain_n]
    jae .out
    lea rax,[rel tvmc_chain_hva]
    mov rdi,[rax+r8*8]
    lea rax,[rel tvmc_chain_desc]
    mov ecx,r8d
    shl ecx,4
    mov r9d,[rax+rcx+8]
    lea r10,[rel tvmc_rx_buf]
.byte:
    test r9d,r9d
    jz .next
    cmp dword [rel tvmc_rx_len],0
    je .out
    mov eax,[rel tvmc_rx_head]
    mov dl,[r10+rax]
    mov byte [r10+rax],0             ; delivered bytes do not stay behind
    mov [rdi],dl
    inc rdi
    inc eax
    and eax,TVMC_RING-1
    mov [rel tvmc_rx_head],eax
    dec dword [rel tvmc_rx_len]
    inc r11d
    dec r9d
    jmp .byte
.next:
    inc r8d
    jmp .desc
.out:
    mov eax,r11d
    ret

; EDI head id, ESI used.len, EDX queue. One used element at the private index.
tvmc_used_put:
    mov r8,[rel tvmc_m_used]
    lea rax,[rel tvmc_q_usedidx]
    movzx ecx,word [rax+rdx*2]
    mov r9d,[rel tvmc_m_num]
    dec r9d
    and ecx,r9d
    mov [r8+4+rcx*8],edi
    mov [r8+8+rcx*8],esi
    inc word [rax+rdx*2]
    ret

; EDI queue: publish used.idx after every element, then the used interrupt.
tvmc_used_idx:
    lea rax,[rel tvmc_q_usedidx]
    movzx ecx,word [rax+rdi*2]
    mov r8,[rel tvmc_m_used]
    sfence
    mov [r8+2],cx
    or dword [rel tvmc_isr],1
    ret

tvmc_fault_set:
    or dword [rel tvmc_status],TVMC_NEEDS_RESET
    mov byte [rel tvmc_fault],1
    or dword [rel tvmc_isr],2        ; configuration change
    ret

; Device reset (status 0), devices reset and the retire path: every register,
; queue and both private rings, wiped.
tools_vm_console_reset:
    lea rdi,[rel tvmc_state_begin]
    xor eax,eax
    mov ecx,(tvmc_state_end-tvmc_state_begin)/8
    cld
    rep stosq
    mov eax,1
    ret

; Original RDI START, RSI token, between turns (CPU stopped): RX from the
; private input ring, and a TX chain held back by backpressure.
tools_vm_console_pump:
    sub rsp,8
    call tvm_memory_stopped
    test eax,eax
    jz .out
    test dword [rel tvmc_status],TVMC_DRIVER_OK
    jz .out
    call tvmc_rx_serve
    cmp byte [rel tvmc_tx_blocked],0
    je .out
    mov byte [rel tvmc_tx_blocked],0
    call tvmc_tx_serve
.out:
    add rsp,8
    ret

; RDI native bytes, ESI length ->EAX bytes taken (bounded by free space).
; Private ring only; hv/tools_vm's admitted facade is the only caller.
tvmc_input:
    mov ecx,TVMC_RING
    sub ecx,[rel tvmc_rx_len]
    cmp esi,ecx
    cmova esi,ecx
    mov eax,esi
    xor edx,edx
    lea r10,[rel tvmc_rx_buf]
.byte:
    cmp edx,eax
    jae .out
    mov r8d,[rel tvmc_rx_head]
    add r8d,[rel tvmc_rx_len]
    and r8d,TVMC_RING-1
    mov r9b,[rdi+rdx]
    mov [r10+r8],r9b
    inc dword [rel tvmc_rx_len]
    inc edx
    jmp .byte
.out:
    ret

; RDI native out, ESI max ->EAX TX bytes moved out, oldest first; their ring
; bytes are wiped. Private ring only, same single caller.
tvmc_drain:
    mov eax,[rel tvmc_tx_len]
    cmp esi,eax
    cmovb eax,esi
    xor edx,edx
    lea r10,[rel tvmc_tx_buf]
.byte:
    cmp edx,eax
    jae .out
    mov r8d,[rel tvmc_tx_head]
    mov r9b,[r10+r8]
    mov byte [r10+r8],0
    mov [rdi+rdx],r9b
    inc r8d
    and r8d,TVMC_RING-1
    mov [rel tvmc_tx_head],r8d
    dec dword [rel tvmc_tx_len]
    inc edx
    jmp .byte
.out:
    ret

; Terminal binding change (attach, detach, a stale binding; SEC 121684 E3):
; both private rings and their indices wiped, nothing else. Queues,
; registers and a held-back TX chain stay, and the next pump retries it.
; hv/tools_vm's binding is the only caller.
tvmc_unbind:
    xor eax,eax
    mov [rel tvmc_tx_head],eax
    mov [rel tvmc_tx_len],eax
    mov [rel tvmc_rx_head],eax
    mov [rel tvmc_rx_len],eax
    mov [rel tvmc_cfg_gen],eax       ; Z4: the size and its generation go too
    mov [rel tvmc_cols],ax
    mov [rel tvmc_rows],ax
    cld
    lea rdi,[rel tvmc_tx_buf]
    mov ecx,TVMC_RING/8
    rep stosq
    lea rdi,[rel tvmc_rx_buf]
    mov ecx,TVMC_RING/8
    rep stosq
    ret

; Z4: EDI cols, ESI rows, each 1..0xffff (the admitted facade checks).
; A change bumps the generation, and raises InterruptStatus bit 1 only when
; the driver accepted SIZE. The same pair again changes nothing.
tvmc_resize:
    cmp di,[rel tvmc_cols]
    jne .changed
    cmp si,[rel tvmc_rows]
    je .out
.changed:
    mov [rel tvmc_cols],di
    mov [rel tvmc_rows],si
    inc dword [rel tvmc_cfg_gen]
    test dword [rel tvmc_status],TVMC_FEATURES_OK
    jz .out
    test dword [rel tvmc_drvfeat],1
    jz .out
    or dword [rel tvmc_isr],2
.out:
    ret

%macro WDATA_hv_tools_vm_console 0
align 8
tvmc_state_begin:
tvmc_q_desc: times 2 dq 0             ; address pairs: desc, avail, used (16 bytes each)
tvmc_q_avail: times 2 dq 0
tvmc_q_used: times 2 dq 0
tvmc_m_desc: dq 0                     ; this serve's conversions only
tvmc_m_avail: dq 0
tvmc_m_used: dq 0
tvmc_ignored: dq 0
tvmc_malformed: dq 0
tvmc_tx_full: dq 0
tvmc_chain_hva: times TVMC_CHAIN dq 0
tvmc_chain_desc: times TVMC_CHAIN*16 db 0
tvmc_q_num: times 2 dd 0
tvmc_drvfeat: times 2 dd 0
tvmc_status: dd 0
tvmc_isr: dd 0
tvmc_dfsel: dd 0
tvmc_drvfsel: dd 0
tvmc_qsel: dd 0
tvmc_m_num: dd 0
tvmc_chain_n: dd 0
tvmc_tx_head: dd 0
tvmc_tx_len: dd 0
tvmc_rx_head: dd 0
tvmc_rx_len: dd 0
tvmc_cfg_gen: dd 0
tvmc_cols: dw 0
tvmc_rows: dw 0
tvmc_q_last: times 2 dw 0
tvmc_q_usedidx: times 2 dw 0
tvmc_q_ready: times 2 db 0
tvmc_fault: db 0
tvmc_feat_bad: db 0
tvmc_tx_blocked: db 0
tvmc_pad: times 7 db 0                ; explicit zero: the rings stay 8-aligned
tvmc_tx_buf: times TVMC_RING db 0
tvmc_rx_buf: times TVMC_RING db 0
tvmc_state_end:
; Snapshot disjointness loads this span with ECX. Reject empty, reversed
; or truncated layouts at WDATA expansion, after both labels are defined.
times (((tvmc_state_end-tvmc_state_begin) <= 0) || ((tvmc_state_end-tvmc_state_begin) > 0xffffffff)) * -1 db 0
%endmacro
WDATA_DEFER WDATA_hv_tools_vm_console
