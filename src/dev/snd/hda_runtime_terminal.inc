; Original foreground diagnostic terminal only. Trusted disjoint 320B, BSP/IF0.
; See HDA_RUNTIME_TERMINAL.md. No reset, engine stop request, DMA release or retry.
%macro HDART_S 2
 mov eax,[rel %2]
 mov [r12+4*%1],eax
%endmacro
%macro HDART_Q 2
 mov rax,[rel %2]
 mov [r12+4*%1],rax
%endmacro
%macro HDART_AV 1
 or dword [r12+20],1 << %1
 or dword [r12+180],1 << %1
%endmacro
; Original failure-snapshot presence predicate. Direct RIP-relative access is
; valid for WDATA_BSS operands; a code/table label difference is not (R6b).
; Keep the original qword width, order and bit meaning without moving storage.
%macro HDARF_LIFETIME 2
 cmp qword [rel %2],0
 je %%zero
 or edx,1 << %1
%%zero:
%endmacro
%macro HDART_BIND 2
 lea rax,[r13+%2]
 cmp [rel %1],rax
 jne .bad
%endmacro
hdart_denied:
 mov rax,-1
 ret
; Empty global child hook slots are checked before installing these exact-owner
; gates. Refuse every operation on the retained original context; foreign owner
; contexts remain governed by their own original admission policy.
hdart_transport_gate:
 lea rax,[rel hdar_transport]
 cmp rdi,rax
 je hdart_denied
 xor eax,eax
 ret
hdart_output_gate:
 lea rax,[rel hdar_output]
 cmp rdi,rax
 je hdart_denied
 xor eax,eax
 ret
hdart_cfg:
 mov edi,[rel hdar_anchor_bdf]
 mov edx,edi
 and edx,7
 mov esi,edi
 shr esi,3
 and esi,31
 shr edi,8
 jmp pci_cfg_read32
hdart_cfg_write:
 mov edi,[rel hdar_anchor_bdf]
 mov edx,edi
 and edx,7
 mov esi,edi
 shr esi,3
 and esi,31
 shr edi,8
 mov ecx,4
 jmp pci_cfg_write32

hda_probe_terminal:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,8                    ; entry8 -> every outgoing call0
 mov r12,rdi
 pushfq
 pop r11
 cld
 xor eax,eax
 mov ecx,80
 rep stosd
 mov dword [r12],1
 mov dword [r12+160],1
 mov dword [r12+164],1
 shr r11d,9
 and r11d,1
 mov [r12+24],r11d
 HDART_S 8,hdar_anchor_bdf
 HDART_S 9,hdar_anchor_id
 HDART_S 10,hda_probe_stage
 HDART_S 11,hda_probe_error
 HDART_S 12,hdar_output+hda_output.state
 HDART_S 13,hdar_transport+hda_transport.pending
 HDART_S 14,hdar_transport+hda_transport.fault
 movzx eax,byte [rel hdar_guest_claimed]
 mov [r12+60],eax
 HDART_Q 16,hdar_mmio
 HDART_Q 18,hdar_dma
 HDART_Q 20,hdar_map_serial
 HDART_Q 22,hdar_transport+hda_transport.mmio
 HDART_Q 24,hdar_transport+hda_transport.corb
 HDART_Q 26,hdar_transport+hda_transport.rirb
 HDART_Q 28,hdar_output+hda_output.mmio
 HDART_Q 30,hdar_output+hda_output.bdl
 HDART_Q 32,hdar_output+hda_output.pcm
 HDART_Q 34,hdar_output+hda_output.position
 HDART_Q 36,hdar_output+hda_output.bdl_dma
 HDART_Q 38,hdar_output+hda_output.pcm_dma
 HDART_Q 46,hdar_output+hda_output.position_dma
 HDART_S 75,hdar_bdf
 HDART_S 76,hdar_pci_id
 HDART_S 77,hdar_anchor_valid
 HDART_S 78,hdar_terminal_latched
 HDART_S 79,hdar_terminal_latched
 HDART_AV 0
 HDART_AV 1
 ; Presence bits match the accepted RAM-only guard, including retained IOVAs.
 xor edx,edx
 mov ecx,13
 lea rsi,[rel hdart_lifetime_offsets]
.life:
 movzx eax,byte [rsi]
 cmp qword [r12+rax],0
 je .life_next
 mov eax,13
 sub eax,ecx
 bts edx,eax
.life_next:
 inc rsi
 loop .life
 mov [r12+28],edx
 cmp qword [rel hda_transport_power_gate],0
 je .hook1
 or dword [r12+272],1
.hook1:
 cmp qword [rel hda_output_power_gate],0
 je .hooks
 or dword [r12+272],2
.hooks:
 mov ebp,1                    ; replay after any latch is uncertainty
 cmp dword [r12+312],0
 jne .uncertain
 mov ebp,2                    ; IF1 is unsupported, never changed here
 cmp dword [r12+24],0
 jne .refuse
 mov ebp,3                    ; original active/fault/unknown context
 cmp dword [r12+52],0
 jne .refuse
 cmp dword [r12+56],0
 jne .refuse
 mov rbx,[rel hdar_mmio]
 mov r13,[rel hdar_dma]
 mov r14,[rel hdar_map_serial]
 test rbx,rbx
 jnz .owned
 ; Positively never-owned RAM; guest claim is history, not native work.
 cmp dword [r12+28],0
 jne .refuse
 cmp dword [r12+308],0
 jne .refuse
 lea rsi,[rel hdar_transport]
 mov ecx,hda_transport_size
.empty_transport:
 cmp byte [rsi],0
 jne .refuse
 inc rsi
 loop .empty_transport
 lea rsi,[rel hdar_output]
 mov ecx,hda_output_size
.empty_output:
 cmp byte [rsi],0
 jne .refuse
 inc rsi
 loop .empty_output
 mov eax,[rel hdar_bdf]
 or eax,[rel hdar_pci_id]
 or eax,[r12+272]
 jnz .refuse
 mov rax,[rel hdar_found]
 or rax,[rel hdar_bar]
 or rax,[rel hdar_pde]
 jnz .refuse
 lea rsi,[rel hdar_anchor_bdf]
 mov ecx,hdar_anchor_end-hdar_anchor_bdf
.empty_anchor:
 cmp byte [rsi],0
 jne .refuse
 inc rsi
 loop .empty_anchor
 xor ebp,ebp
 xor eax,eax
 jmp .out
.owned:
 cmp dword [r12+48],HDAO_BOUND
 je .bound_entry
 cmp dword [r12+48],HDAO_STOPPED
 jne .refuse
 cmp dword [rel hdar_output+hda_output.error],0
 jne .refuse
 cmp dword [r12+44],0
 jne .failed_entry
 cmp dword [r12+40],5
 jne .refuse
 jmp .entry_ok
.failed_entry:
 ; Only the actual no-effect rejected second scan of a completed original owner.
 ; Its original error remains1. Historical failure snapshots are not authority.
 cmp dword [r12+44],1
 jne .refuse
 cmp dword [r12+40],0
 jne .refuse
 mov rax,[rel hdart_failed_attempt]
 test rax,rax
 jz .refuse
 cmp rax,-1
 je .refuse
 cmp rax,[rel hdarf_attempt]
 jne .refuse
 cmp qword [rel hdar_found],0
 jne .refuse
 cmp dword [rel hdart_scan_observed],1
 jne .refuse
 cmp dword [rel hdart_scan_effects],0
 jne .refuse
 cmp dword [rel hdar_pci_candidates],0
 je .empty_failed_scan
 ; A matching candidate may have rejected before enable. The original whole
 ; scan, rather than the final discovery reason, must have attempted no write.
 cmp dword [rel hdar_pci_candidates],0xffffff
 ja .refuse
 cmp dword [rel hdar_discovery_error],2
 jb .refuse
 cmp dword [rel hdar_discovery_error],8
 ja .refuse
 mov dword [r12],4
 mov dword [r12+160],4
 mov [r12+300],rax              ; schema4 actual failed-entry token64
 ; Same320B, distinct schema: actual stage/error low8, actual candidate count
 ; and discovery readbacks plus explicit observed/effect operands above them.
 mov edx,[rel hdar_pci_candidates]
 shl edx,8
 or [r12+40],edx
 mov edx,[rel hdar_discovery_error]
 shl edx,8
 or [r12+44],edx
 mov edx,[rel hdart_scan_effects]
 shl edx,16
 or [r12+44],edx
 mov edx,[rel hdart_scan_observed]
 shl edx,17
 or [r12+44],edx
 jmp .entry_ok
.empty_failed_scan:
 cmp dword [rel hdar_discovery_error],0
 jne .refuse
 mov dword [r12],3
 mov dword [r12+160],3
 mov [r12+300],rax              ; schema3 original failed-entry token64
 jmp .entry_ok
.bound_entry:
 ; Actual original bind completed, then init failed before transport publish.
 ; Historical RAM is provenance only; fresh checks below authorize each effect.
 cmp dword [r12+40],2
 jne .refuse
 cmp dword [r12+44],3          ; outer tone report, not snapshot error2
 jne .refuse
 cmp dword [rel hdar_output+hda_output.error],0
 jne .refuse
 cmp dword [rel hdarf_ready],1
 jne .refuse
 mov rax,[rel hdarf_attempt]
 test rax,rax
 jz .refuse
 cmp rax,-1
 je .refuse
 lea rsi,[rel hdarf_snapshot]
 cmp rax,[rsi+32]
 jne .refuse
 cmp rax,[rsi+264]
 jne .refuse
 cmp dword [rsi],2
 jne .refuse
 cmp dword [rsi+160],2
 jne .refuse
 cmp dword [rsi+164],1
 jne .refuse
 mov edx,[rsi+20]
 and edx,3                    ; observed original RAM/anchor, not old MMIO
 cmp edx,3
 jne .refuse
 cmp dword [rsi+24],1         ; original init-failure boundary
 jne .refuse
 cmp dword [rsi+40],2
 jne .refuse
 cmp dword [rsi+44],2         ; original pre-report failure phase
 jne .refuse
 cmp dword [rsi+56],HDAO_BOUND
 jne .refuse
 cmp dword [rsi+60],0
 jne .refuse
 cmp dword [rsi+64],0
 jne .refuse
 cmp dword [rsi+68],0
 jne .refuse
 cmp dword [rsi+76],0x1fc7
 jne .refuse
 cmp dword [rsi+292],0
 jne .refuse
 cmp dword [rsi+296],0
 jne .refuse
 cmp [rsi+96],rbx
 jne .refuse
 cmp [rsi+104],r13
 jne .refuse
 cmp [rsi+112],r14
 jne .refuse
 mov edx,[rel hdar_anchor_bdf]
 cmp [rsi+80],edx
 jne .refuse
 mov edx,[rel hdar_anchor_id]
 cmp [rsi+84],edx
 jne .refuse
 mov edx,[rel hdar_anchor_class]
 cmp [rsi+88],edx
 jne .refuse
 cmp dword [rsi+92],1
 jne .refuse
 mov rdx,[rel hdar_anchor_bar]
 cmp [rsi+120],rdx
 jne .refuse
 mov rdx,[rel hdar_anchor_pde]
 cmp [rsi+128],rdx
 jne .refuse
 cmp dword [r12+28],0x1fc7
 jne .refuse
 lea rsi,[rel hdar_transport]
 mov ecx,hda_transport_size
.bound_empty_transport:
 cmp byte [rsi],0
 jne .refuse
 inc rsi
 loop .bound_empty_transport
 mov dword [r12],5
 mov dword [r12+160],5
 mov [r12+300],rax             ; schema5 original failed-init token64
.entry_ok:
 cmp byte [rel hdar_guest_claimed],0
 jne .refuse
 mov ebp,4                    ; original anchor/binding, never reconstructed
 cmp dword [rel hdar_anchor_valid],1
 jne .refuse
 cmp dword [rel hdar_anchor_bdf],65535
 ja .refuse
 cmp [rel hdar_anchor_bar],rbx
 jne .refuse
 mov eax,[rel hdar_anchor_bdf]
 cmp [rel hdar_bdf],eax
 jne .refuse
 mov eax,[rel hdar_anchor_id]
 test eax,eax
 jz .refuse
 cmp eax,-1
 je .refuse
 cmp [rel hdar_pci_id],eax
 jne .refuse
 cmp [rel hdar_output+hda_output.pci_id],rax
 jne .refuse
 cmp [rel hdar_output+hda_output.bound_pci_id],rax
 jne .refuse
 test r13,r13
 jz .refuse
 test r13,4095
 jnz .refuse
 lea rax,[r13+131072]
 cmp rax,r13
 jb .refuse
 shr rax,47
 jnz .refuse
 test r14,r14
 jz .refuse
 cmp dword [r12],5
 je .output_mmio               ; entire unpublished transport already zero
 cmp [rel hdar_transport+hda_transport.mmio],rbx
 jne .refuse
.output_mmio:
 cmp [rel hdar_output+hda_output.mmio],rbx
 jne .refuse
 cmp dword [r12],5
 je .output_bindings
 HDART_BIND hdar_transport+hda_transport.corb,0
 HDART_BIND hdar_transport+hda_transport.rirb,0x1000
.output_bindings:
 HDART_BIND hdar_output+hda_output.bdl,0x2000
 HDART_BIND hdar_output+hda_output.bdl_dma,0x2000
 HDART_BIND hdar_output+hda_output.pcm,0x4000
 HDART_BIND hdar_output+hda_output.pcm_dma,0x4000
 HDART_BIND hdar_output+hda_output.position,0x3000
 HDART_BIND hdar_output+hda_output.position_dma,0x3000
 cmp dword [rel hdar_output+hda_output.mmio_bytes],4096
 jne .refuse
 cmp dword [rel hdar_output+hda_output.bdl_bytes],64
 jne .refuse
 cmp dword [rel hdar_output+hda_output.pcm_bytes],16384
 jne .refuse
 cmp dword [rel hdar_output+hda_output.position_bytes],256
 jne .refuse
 HDART_AV 2
 mov ebp,5                    ; do not steal another original owner's hooks
 cmp dword [r12+272],0
 jne .refuse
 mov dword [r12+16],1
 call hdart_validate
 test eax,eax
 jnz .refuse
 ; From this instruction forward, no reset/retry/resume/ordinary entry.
 mov dword [rel hdar_terminal_latched],1
 mov dword [r12+316],1
 lea rax,[rel hdart_transport_gate]
 mov [rel hda_transport_power_gate],rax
 lea rax,[rel hdart_output_gate]
 mov [rel hda_output_power_gate],rax
 mov dword [r12+16],2
 call hdart_validate
 test eax,eax
 jnz .uncertain
 mov dword [rbx+0x20],0
 mov eax,[rbx+0x20]
 mov [r12+248],eax
 HDART_AV 12
 mov ebp,13
 test eax,eax
 jnz .uncertain
 mov dword [r12+16],3
 call hdart_validate
 test eax,eax
 jnz .uncertain
 mov eax,[rbx+0x70]
 and eax,0xfffffffe
 mov [rbx+0x70],eax
 mov eax,[rbx+0x70]
 mov [r12+252],eax
 mov edx,[rbx+0x74]
 mov [r12+256],edx
 HDART_AV 13
 mov ebp,14
 test eax,1
 jnz .uncertain
 shl rdx,32
 or rax,rdx
 lea rdx,[r13+0x3000]
 cmp rax,rdx
 jne .uncertain
 mov dword [r12+16],4
 call hdart_validate
 test eax,eax
 jnz .uncertain
 mov ecx,4
 call hdart_cfg
 mov ebp,15
 cmp eax,-1
 je .uncertain
 ; Preserve all other Command bits; write zero to the W1C Status lanes.
 and eax,0xfffb
 mov r15d,eax
 mov r8d,eax
 call hdart_cfg_write
 mov ecx,4
 call hdart_cfg
 mov [r12+212],eax
 HDART_AV 14
 movzx edx,ax
 cmp edx,r15d
 jne .uncertain
 mov dword [r12+16],5
 call hdart_validate
 test eax,eax
 jnz .uncertain
 xor ebp,ebp
 mov eax,1
 jmp .out
.bad:
 jmp .refuse
.refuse:
 cmp ebp,3
 jne .plain_refusal
 cmp dword [r12],5
 je .plain_refusal            ; selected fresh schema5 must retain actual result
 call hdarf_export              ; failure-only passive schema2, never authority
.plain_refusal:
 mov rax,-1
 jmp .out
.uncertain:
 mov rax,-2
.out:
 mov [r12+8],eax
 mov [r12+168],eax
 mov [r12+12],ebp
 mov [r12+172],ebp
 mov edx,[r12+16]
 mov [r12+176],edx
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; Private validation: original identity, admission, mapping and DID3 before
; EVERY MMIO phase. EAX0 valid/-1 refused, EBP precise reason; preserves owner
; RBX/R12/R13/R14/R15 and uses the same already-qualified embedded contexts.
hdart_validate:
 sub rsp,8
 mov ebp,6
%ifdef PAOS_NATIVE_DRIVER_POLICY_LINKED
 mov edi,7
 mov rsi,-1
 call native_driver_gate
 jc .bad
 HDART_AV 3
%else
 ; Complete PaOS always links this policy. A leaf without it cannot authorize
 ; terminal MMIO. HOST controls explicitly link the real call seam.
 jmp .bad
%endif
 mov ebp,7
 mov eax,1
 push rbx
 cpuid
 pop rbx
 test ecx,0x80000000
 jz .bad
 HDART_AV 4
 mov ebp,8
 xor ecx,ecx
 call hdart_cfg
 mov [r12+192],eax
 cmp eax,[rel hdar_anchor_id]
 jne .bad
 mov ecx,8
 call hdart_cfg
 mov [r12+196],eax
 HDART_AV 5
 cmp eax,[rel hdar_anchor_class]
 jne .bad
 mov ecx,0x10
 call hdart_cfg
 mov [r12+200],eax
 mov edx,eax
 and edx,15
 cmp edx,0
 je .bar32
 cmp edx,4
 jne .bad
 mov ecx,0x14
 call hdart_cfg
 mov [r12+204],eax
 shl rax,32
 mov edx,[r12+200]
 and edx,0xfffffff0
 or rax,rdx
 jmp .bar
.bar32:
 mov eax,[r12+200]
 and eax,0xfffffff0
.bar:
 cmp rax,rbx
 jne .bad
 test rbx,4095
 jnz .bad
 mov rax,rbx
 shr rax,47
 jnz .bad
 mov ecx,4
 call hdart_cfg
 cmp dword [r12+16],2
 jae .command_saved
 mov [r12+208],eax
.command_saved:
 HDART_AV 6
 cmp eax,-1
 je .bad
 test eax,2
 jz .bad
 mov ebp,9
 mov rdi,rbx
 call paging_pd_entry_ptr
 test rax,rax
 jz .bad
 mov rax,[rax]
 mov [r12+276],rax
 HDART_AV 7
 mov rdx,rax
 xor rdx,[rel hdar_anchor_pde]
 and rdx,~0x60                 ; only hardware Accessed/Dirty may differ
 jnz .bad
 mov edx,eax
 and edx,0x93
 cmp edx,0x93
 jne .bad
 bt rax,63
 jnc .bad
 mov rcx,0x000fffffffe00000
 and rax,rcx
 and rcx,rbx
 cmp rax,rcx
 jne .bad
 mov ebp,10
 mov edi,1
 call dma_domain_receipt
 mov [r12+260],eax
 mov [r12+264],rdx
 HDART_AV 8
 cmp eax,1
 jne .bad
 cmp rdx,r14
 jne .bad
 ; No MMIO before all of the preceding checks on each invocation.
 mov ebp,11
 movzx eax,word [rbx]
 mov [r12+216],eax
 cmp eax,65535
 je .bad
 mov ecx,eax
 shr ecx,8
 and ecx,15
 mov edx,eax
 shr edx,12
 and edx,15
 add ecx,edx
 shr eax,3
 and eax,31
 add ecx,eax
 test ecx,ecx
 jz .bad
 cmp ecx,30
 ja .bad
 cmp dword [r12],5
 jne .stream_index
 ; Original bind selected the first dedicated output after the inputs.
 mov eax,[r12+216]
 and eax,6
 cmp eax,6
 je .bad
 mov eax,[r12+216]
 shr eax,12
 and eax,15
 jz .bad
 mov eax,[r12+216]
 shr eax,8
 and eax,15
 cmp [rel hdar_output+hda_output.sd_index],eax
 jne .bad
.stream_index:
 mov eax,[rel hdar_output+hda_output.sd_index]
 cmp eax,ecx
 jae .bad
 xor edx,edx
 mov dword [r12+220],0
.scan:
 imul eax,edx,32
 movzx eax,byte [rbx+rax+0x80]
 cmp eax,255
 je .bad
 test eax,3                    ; actual RUN and SRST, including unused streams
 jz .next
 bts dword [r12+220],edx
.next:
 inc edx
 cmp edx,ecx
 jb .scan
 HDART_AV 9
 cmp dword [r12+220],0
 jne .bad
 movzx eax,byte [rbx+0x4c]
 mov [r12+224],eax
 movzx eax,byte [rbx+0x5c]
 mov [r12+228],eax
 mov eax,[rbx+8]
 mov [r12+232],eax
 mov rax,[rbx+0x40]
 mov [r12+284],rax
 mov rdx,[rbx+0x50]
 mov [r12+292],rdx
 HDART_AV 10
 cmp dword [r12+224],0
 jne .bad
 cmp dword [r12+228],0
 jne .bad
 cmp dword [r12],5
 je .bound_gctl
 cmp dword [r12+232],1          ; original polling controller, no UNSOL/flush
 jne .bad
 jmp .gctl_ok
.bound_gctl:
 cmp dword [r12+232],0          ; actual failed-init reset already observed
 jne .bad
.gctl_ok:
 cmp rax,r13
 jne .bad
 lea rax,[r13+0x1000]
 cmp rdx,rax
 jne .bad
 mov ebp,12
 mov eax,[rbx+0x70]
 mov edx,[rbx+0x74]
 mov ecx,[rbx+0x20]
 cmp dword [r12+16],2
 jae .position_saved
 mov [r12+236],eax
 mov [r12+240],edx
 mov [r12+244],ecx
.position_saved:
 HDART_AV 11
 test ecx,ecx                  ; original diagnostic is polling-only
 jnz .bad
 cmp eax,-1
 je .bad
 cmp edx,-1
 je .bad
 and eax,0xfffffffe
 shl rdx,32
 or rax,rdx
 lea rdx,[r13+0x3000]
 cmp rax,rdx
 jne .bad
 xor eax,eax
 add rsp,8
 ret
.bad:
 mov rax,-1
 add rsp,8
 ret

; Report-relative qword offsets in the exact accepted lifetime-presence order.
hdart_lifetime_offsets: db 64,72,80,88,96,104,112,120,128,136,144,152,184
%macro WDATA_hdart 0
hdar_terminal_latched: resd 1
hdar_anchor_valid: resd 1
hdar_anchor_bdf: resd 1
hdar_anchor_id: resd 1
hdar_anchor_class: resd 1
hdar_anchor_bar: resq 1
hdar_anchor_pde: resq 1
hdar_anchor_end:
%endmacro
WDATA_BSS_DEFER WDATA_hdart


; Passive original failure boundary. This is an observation of the original
; stop/reset writes, never a terminal-success, reset, retry or release rail.
; Exact failure-only schema2 is documented in HDA_RUNTIME_TERMINAL.md.
%macro HDARF_ENTER 0
 pushfq
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
 sub rsp,8
%endmacro
%macro HDARF_LEAVE 0
 add rsp,8
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
 popfq
 ret
%endmacro

hdarf_new_attempt:
 pushfq
 mov dword [rel hdarf_ready],0
 mov qword [rel hdart_entry_attempt],0
 mov qword [rel hdart_failed_attempt],0
 mov dword [rel hdart_scan_effects],0
 mov dword [rel hdart_scan_observed],0
 cmp qword [rel hdarf_attempt],-1
 je .out                      ; saturation disables observation, never wraps
 inc qword [rel hdarf_attempt]
.out:
 popfq
 ret

; EAX1 init failure, EAX2 tone fail_reset. All original registers/flags survive.
hdarf_capture:
 HDARF_ENTER
 mov r15d,eax
 cld
 lea r12,[rel hdarf_snapshot]
 mov rdi,r12
 xor eax,eax
 mov ecx,40
 rep stosq
 mov dword [r12],2
 mov dword [r12+160],2
 mov dword [r12+164],1
 mov [r12+24],r15d
 mov dword [r12+28],1
 mov rax,[rel hdarf_attempt]
 mov [r12+32],rax
 mov [r12+264],rax
 HDART_S 10,hda_probe_stage
 HDART_S 11,hda_probe_error
 HDART_S 14,hdar_output+hda_output.state
 HDART_S 15,hdar_output+hda_output.error
 HDART_S 16,hdar_transport+hda_transport.pending
 HDART_S 17,hdar_transport+hda_transport.fault
 mov eax,[rsp+128]              ; actual incoming IF from saved RFLAGS
 shr eax,9
 and eax,1
 mov [r12+72],eax
 HDART_S 20,hdar_anchor_bdf
 HDART_S 21,hdar_anchor_id
 HDART_S 22,hdar_anchor_class
 HDART_S 23,hdar_anchor_valid
 HDART_Q 24,hdar_mmio
 HDART_Q 26,hdar_dma
 HDART_Q 28,hdar_map_serial
 HDART_Q 30,hdar_anchor_bar
 HDART_Q 32,hdar_anchor_pde
 HDART_S 74,hdar_terminal_latched
 xor edx,edx
 HDARF_LIFETIME 0,hdar_mmio
 HDARF_LIFETIME 1,hdar_dma
 HDARF_LIFETIME 2,hdar_map_serial
 HDARF_LIFETIME 3,hdar_transport+hda_transport.mmio
 HDARF_LIFETIME 4,hdar_transport+hda_transport.corb
 HDARF_LIFETIME 5,hdar_transport+hda_transport.rirb
 HDARF_LIFETIME 6,hdar_output+hda_output.mmio
 HDARF_LIFETIME 7,hdar_output+hda_output.bdl
 HDARF_LIFETIME 8,hdar_output+hda_output.pcm
 HDARF_LIFETIME 9,hdar_output+hda_output.position
 HDARF_LIFETIME 10,hdar_output+hda_output.bdl_dma
 HDARF_LIFETIME 11,hdar_output+hda_output.pcm_dma
 HDARF_LIFETIME 12,hdar_output+hda_output.position_dma
 mov [r12+76],edx
 xor eax,eax
 cmp qword [rel hda_transport_power_gate],0
 je .hook1
 or eax,1
.hook1:
 cmp qword [rel hda_output_power_gate],0
 je .hooks
 or eax,2
.hooks:
 mov [r12+292],eax
 HDART_AV 0
 cmp qword [rel tsc_khz],0
 je .done
 call time_monotonic_now_us
 mov [r12+272],rax
 cmp qword [rel hdarf_attempt],0
 je .done
 cmp qword [rel hdarf_attempt],-1
 je .done
 cmp dword [rel hdar_anchor_valid],1
 jne .done
 cmp dword [rel hdar_terminal_latched],0
 jne .done
 mov rbx,[rel hdar_mmio]
 mov r13,[rel hdar_dma]
 mov r14,[rel hdar_map_serial]
 cmp rbx,[rel hdar_anchor_bar]
 jne .done
 test rbx,rbx
 jz .done
 test rbx,4095
 jnz .done
 mov rax,rbx
 shr rax,47
 jnz .done
 mov eax,[rel hdar_bdf]
 cmp eax,[rel hdar_anchor_bdf]
 jne .done
 mov eax,[rel hdar_pci_id]
 cmp eax,[rel hdar_anchor_id]
 jne .done
 HDART_AV 1
 mov dword [r12+28],2
%ifdef PAOS_NATIVE_DRIVER_POLICY_LINKED
 mov edi,7
 mov rsi,-1
 call native_driver_gate
 jc .done
 HDART_AV 2
%else
 jmp .done
%endif
 mov dword [r12+28],3
 mov eax,1
 push rbx
 cpuid
 pop rbx
 test ecx,0x80000000
 jz .done
 HDART_AV 3
 mov dword [r12+28],4
 xor ecx,ecx
 call hdart_cfg
 mov [r12+144],eax
 mov ecx,8
 call hdart_cfg
 mov [r12+148],eax
 HDART_AV 4
 mov eax,[r12+144]
 cmp eax,-1
 je .done
 cmp eax,[rel hdar_anchor_id]
 jne .done
 mov eax,[r12+148]
 cmp eax,[rel hdar_anchor_class]
 jne .done
 mov ecx,0x10
 call hdart_cfg
 mov [r12+152],eax
 mov edx,eax
 and edx,15
 cmp edx,0
 je .bar32
 cmp edx,4
 jne .done
 mov ecx,0x14
 call hdart_cfg
 mov [r12+156],eax
 shl rax,32
 mov edx,[r12+152]
 and edx,0xfffffff0
 or rax,rdx
 jmp .bar
.bar32:
 mov eax,[r12+152]
 and eax,0xfffffff0
.bar:
 mov r15,rax
 mov ecx,4
 call hdart_cfg
 mov [r12+184],eax
 HDART_AV 5
 cmp r15,rbx
 jne .done
 cmp eax,-1
 je .done
 test eax,2                    ; original MSE required before observer MMIO
 jz .done
 mov dword [r12+28],5
 mov rdi,rbx
 call paging_pd_entry_ptr
 test rax,rax
 jz .done
 mov rax,[rax]
 mov [r12+136],rax
 HDART_AV 6
 xor rax,[rel hdar_anchor_pde]
 and rax,~0x60                 ; only hardware Accessed/Dirty may differ
 jnz .done
 mov rax,[r12+136]
 mov edx,eax
 and edx,0x93
 cmp edx,0x93
 jne .done
 bt rax,63
 jnc .done
 mov rcx,0x000fffffffe00000
 and rax,rcx
 and rcx,rbx
 cmp rax,rcx
 jne .done
 mov dword [r12+28],6
 mov edi,1
 call dma_domain_receipt
 mov [r12+188],eax
 mov [r12+192],rdx
 HDART_AV 7
 cmp eax,1
 jne .done
 test r14,r14
 jz .done
 cmp rdx,r14                   ; preserve the complete original DID3 serial
 jne .done
 ; Every original immutable binding/policy/receipt check precedes MMIO.
 mov dword [r12+28],7
 movzx eax,word [rbx]
 mov [r12+200],eax
 HDART_AV 8
 cmp eax,65535
 je .done
 mov ecx,eax
 shr ecx,8
 and ecx,15
 mov edx,eax
 shr edx,12
 and edx,15
 add ecx,edx
 shr eax,3
 and eax,31
 add ecx,eax
 mov [r12+204],ecx
 test ecx,ecx
 jz .done
 cmp ecx,30
 ja .done
 xor edx,edx
.stream:
 imul eax,edx,32
 movzx eax,byte [rbx+rax+0x80]
 cmp eax,255
 je .done
 bts dword [r12+212],edx
 HDART_AV 9                    ; exact observed prefix, never unobserved zeros
 test eax,3
 jz .stream_next
 bts dword [r12+208],edx
.stream_next:
 inc edx
 cmp edx,ecx
 jb .stream
 cmp dword [r12+208],0
 jne .engines
 or dword [r12+256],8
.engines:
 mov dword [r12+28],8
 movzx eax,byte [rbx+0x4c]
 mov [r12+216],eax
 movzx eax,byte [rbx+0x5c]
 mov [r12+220],eax
 mov eax,[rbx+8]
 mov [r12+224],eax
 HDART_AV 10
 cmp dword [r12+216],255
 je .done
 cmp dword [r12+220],255
 je .done
 cmp eax,-1
 je .done
 cmp dword [r12+216],0
 jne .rirb
 or dword [r12+256],1
.rirb:
 cmp dword [r12+220],0
 jne .reset
 or dword [r12+256],2
.reset:
 test eax,0x101
 jnz .remaining
 or dword [r12+256],4
.remaining:
 mov eax,[rbx+0x20]
 mov [r12+228],eax
 mov eax,[rbx+0x70]
 mov [r12+232],eax
 mov eax,[rbx+0x74]
 mov [r12+236],eax
 mov rax,[rbx+0x40]
 mov [r12+240],rax
 mov rax,[rbx+0x50]
 mov [r12+248],rax
 HDART_AV 11
 mov dword [r12+260],15
 mov dword [r12+28],0           ; observations complete; still terminal refusal
.done:
 cmp qword [rel tsc_khz],0
 je .ready
 call time_monotonic_now_us
 mov [r12+280],rax
 HDART_AV 12
.ready:
 mov dword [rel hdarf_ready],1
 HDARF_LEAVE

; Only called on the old reason3 refusal. No PCI/MMIO or other external calls.
; A new native attempt invalidates the old snapshot before any refusal/effect.
hdarf_export:
 HDARF_ENTER
 cmp dword [rel hdarf_ready],1
 jne .out
 mov rax,[rel hdarf_attempt]
 cmp rax,[rel hdarf_snapshot+32]
 jne .out
 test rax,rax
 jz .out
 cmp rax,-1
 je .out
 cld
 mov rdi,r12
 lea rsi,[rel hdarf_snapshot]
 mov ecx,40
 rep movsq
 HDART_S 12,hda_probe_stage
 HDART_S 13,hda_probe_error
 HDART_S 75,hdar_terminal_latched
 HDART_Q 76,hdarf_attempt
 xor edx,edx
 mov rax,[rel hdar_mmio]
 cmp rax,[r12+96]
 jne .dma
 or edx,1
.dma:
 mov rax,[rel hdar_dma]
 cmp rax,[r12+104]
 jne .serial
 or edx,2
.serial:
 mov rax,[rel hdar_map_serial]
 cmp rax,[r12+112]
 jne .anchor
 or edx,4
.anchor:
 mov eax,[rel hdar_anchor_valid]
 cmp eax,[r12+92]
 jne .equal
 mov eax,[rel hdar_anchor_bdf]
 cmp eax,[r12+80]
 jne .equal
 mov eax,[rel hdar_anchor_id]
 cmp eax,[r12+84]
 jne .equal
 mov eax,[rel hdar_anchor_class]
 cmp eax,[r12+88]
 jne .equal
 mov rax,[rel hdar_anchor_bar]
 cmp rax,[r12+120]
 jne .equal
 mov rax,[rel hdar_anchor_pde]
 cmp rax,[r12+128]
 jne .equal
 or edx,8
.equal:
 mov [r12+288],edx
 HDART_AV 13
.out:
 HDARF_LEAVE

%macro WDATA_hdarf 0
hdarf_attempt: resq 1
hdarf_ready: resd 1
hdarf_snapshot: resb 320
%endmacro
WDATA_BSS_DEFER WDATA_hdarf

; Genuine original failed-scan provenance. Serialized BSP entry; no hardware,
; context mutation, policy decision or effect. Preserve every register/flag.
; A later init/tone entry invalidates both tokens in hdarf_new_attempt.
hdart_entry_prepare:
 pushfq
 push rax
 cmp dword [rel hda_probe_stage],5
 jne .out
 cmp dword [rel hda_probe_error],0
 jne .out
 cmp dword [rel hdar_output+hda_output.state],HDAO_STOPPED
 jne .out
 cmp dword [rel hdar_output+hda_output.error],0
 jne .out
 cmp dword [rel hdar_transport+hda_transport.pending],0
 jne .out
 cmp dword [rel hdar_transport+hda_transport.fault],0
 jne .out
 cmp byte [rel hdar_guest_claimed],0
 jne .out
 mov rax,[rel hdarf_attempt]
 test rax,rax
 jz .out
 cmp rax,-1
 je .out
 mov [rel hdart_entry_attempt],rax
.out:
 pop rax
 popfq
 ret

hdart_scan_failed:
 pushfq
 push rax
 mov rax,[rel hdart_entry_attempt]
 test rax,rax
 jz .out
 cmp rax,-1
 je .out
 cmp rax,[rel hdarf_attempt]
 jne .out
 cmp dword [rel hda_probe_stage],0
 jne .out
 cmp dword [rel hda_probe_error],0
 jne .out
 cmp qword [rel hdar_found],0
 jne .out
 ; A later callback's early rejection cannot hide an earlier unknown Command
 ; operand. Only the original new-attempt boundary clears this status.
 cmp dword [rel hdart_scan_observed],0
 jne .out
 ; The actual scan has returned to the original no-found branch on this
 ; completed-entry attempt. Explicit availability; a zero initializer is not
 ; evidence. The write-attempt operand stayed sticky across every callback.
 mov dword [rel hdart_scan_observed],1
 cmp dword [rel hdart_scan_effects],0
 jne .out
 cmp dword [rel hdar_pci_candidates],0
 je .empty
 cmp dword [rel hdar_pci_candidates],0xffffff
 ja .out
 cmp dword [rel hdar_discovery_error],2
 jb .out
 cmp dword [rel hdar_discovery_error],8
 ja .out
 jmp .mark
.empty:
 cmp dword [rel hdar_discovery_error],0
 jne .out
.mark:
 mov [rel hdart_failed_attempt],rax
.out:
 pop rax
 popfq
 ret

%macro WDATA_hdart_entry 0
alignb 8
hdart_entry_attempt: resq 1
hdart_failed_attempt: resq 1
hdart_scan_effects: resd 1
hdart_scan_observed: resd 1
%endmacro
WDATA_BSS_DEFER WDATA_hdart_entry
