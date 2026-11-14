;; MODULE dev/snd/hda_boot_handoff
;; LAYER 3
;; EXPORTS hda_boot_handoff, hda_handoff_closed, hda_handoff_visited, hda_handoff_stopped, hda_handoff_refused, hda_handoff_disposition, hda_handoff_rows
;; IMPORTS boot/paging, bus/pci, core/time, dev/snd/hda_runtime, dev/snd/hda_loopback_native
;; CAPS mmio
;; OWNER saga:resource
;; CONTEXT: bsp_only
; One normal-boot handoff, after successful EBS and clock calibration, before
; PIT interrupts/SMP/PaOS device owners. Never callable through a command rail.
; The saved pre-EBS PCI census and live mapping are revalidated; no new scan.
; If MEM decode is off, enable only that Command bit and verify readback before
; the first MMIO access. Preserve BME/other Command bits, write Status zero.
; Only idle-stream command engines may be asked to stop. No controller reset,
; stream write, DMA address change, allocation, free or IOMMU/domain grant.
; STOP requests are not proof: read back both engines, with a 2ms deadline and
; 4096-poll ceiling per controller (at most32). Never retry this boot attempt.
; Later native OPEN still independently refuses every foreign engine/stream.
; Retained 64-byte rows contain BDF/BAR/reason/initial+final controls/GCAP/
; active-stream index/observation flags. Readout never calls this boot routine.
; No claim that an observed live engine came from firmware, or that stopping
; command DMA certifies physical cleanup/retirement of any old storage.

%macro HDB_CFG 1
 mov edi,ebp
 mov edx,edi
 and edx,7
 mov esi,edi
 shr esi,3
 and esi,31
 shr edi,8
 mov ecx,%1
 call pci_cfg_read32
%endmacro

hda_boot_handoff:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,24
 cmp dword [rel hda_handoff_closed],0
 jne .out                           ; one boot attempt, including failure
 mov dword [rel hda_handoff_closed],1
 mov dword [rel hda_handoff_disposition],1 ; clock unavailable
 cmp qword [rel tsc_khz],0
 je .out
 mov dword [rel hda_handoff_disposition],2 ; legacy owner
 call hda_probe_controller_busy
 test rax,rax
 jnz .out
 mov dword [rel hda_handoff_disposition],3 ; native owner
 call hda_loopback_native_busy
 test rax,rax
 jnz .out
 mov dword [rel hda_handoff_disposition],4 ; census overflow
 cmp dword [rel paging_hda_overflow],0
 jne .out
 mov dword [rel hda_handoff_disposition],5 ; census count
 mov eax,[rel paging_hda_count]
 cmp eax,32
 ja .out
 mov dword [rel hda_handoff_disposition],6 ; census admitted
 mov [rsp],eax                     ; finite snapshot; no live census loop
 xor r12d,r12d
.next:
 cmp r12d,[rsp]
 jae .out
 inc dword [rel hda_handoff_visited]
 mov eax,r12d
 shl eax,6
 lea rdx,[rel hda_handoff_rows]
 add rdx,rax
 mov [rsp+8],rdx
 mov qword [rdx+48],-1           ; no active stream index observed
 mov dword [rsp+16],1           ; bad saved BDF
 lea rax,[rel paging_hda_bdfs]
 mov ebp,[rax+r12*4]
 mov [rdx],rbp
 lea rax,[rel paging_hda_bars]
 mov r13,[rax+r12*8]
 mov [rdx+8],r13
 cmp ebp,65535
 ja .refuse
 mov dword [rsp+16],2           ; saved BAR geometry
 test r13,r13
 jz .refuse
 test r13,4095
 jnz .refuse
 mov rax,r13
 shr rax,47
 jnz .refuse
 mov dword [rsp+16],3           ; vendor
 HDB_CFG 0
 cmp ax,0x8086
 je .vendor
 cmp ax,0x1022
 jne .refuse
.vendor:
 mov dword [rsp+16],4           ; class/interface
 HDB_CFG 8
 shr eax,8
 and eax,0xffff7f
 cmp eax,0x040300
 jne .refuse
 mov dword [rsp+16],5           ; BAR type
 HDB_CFG 0x10
 mov ebx,eax
 and eax,15
 cmp eax,0
 je .bar32
 cmp eax,4
 jne .refuse
 HDB_CFG 0x14
 shl rax,32
 and ebx,0xfffffff0
 or rbx,rax
 jmp .bar
.bar32:
 and ebx,0xfffffff0
.bar:
 mov dword [rsp+16],6           ; changed saved BAR
 cmp rbx,r13                       ; exact saved BDF/BAR, no replacement
 jne .refuse
 mov dword [rsp+16],8           ; live mapping
 mov rdi,rbx
 call paging_pd_entry_ptr
 test rax,rax
 jz .refuse
 mov rdx,[rax]
 mov eax,edx
 and eax,0x93
 cmp eax,0x93                      ; live P|RW|PCD|PS
 jne .refuse
 bt rdx,63
 jnc .refuse
 mov rcx,0x000fffffffe00000
 and rdx,rcx
 and rcx,rbx
 cmp rdx,rcx
 jne .refuse
 mov dword [rsp+16],7           ; memory decode unavailable after enable/readback
 HDB_CFG 4
 test al,2
 jnz .decoded
 ; Mapping and exact BDF/BAR identity precede even this MEM-only write.
 ; Do not enable bus mastering or echo RW1C PCI Status bits from the read.
 and eax,65535
 or eax,2
 mov r8d,eax
 mov edi,ebp
 mov edx,edi
 and edx,7
 mov esi,edi
 shr esi,3
 and esi,31
 shr edi,8
 mov ecx,4
 call pci_cfg_write32
 HDB_CFG 4
 test al,2
 jz .refuse                       ; no valid MMIO, no STOP, no retry this boot
.decoded:
 mov rdx,[rsp+8]
 mov qword [rdx+56],1           ; validated aperture; saved controls available
 movzx eax,word [rbx]
 mov [rdx+40],rax
 movzx eax,byte [rbx+0x4c]
 movzx ecx,byte [rbx+0x5c]
 shl ecx,8
 or eax,ecx
 mov [rdx+24],rax
 mov dword [rsp+16],9           ; invalid GCAP or active stream
 call hdb_streams_idle
 test eax,eax
 jnz .stream_refuse
 mov dword [rsp+16],10          ; unavailable initial clock
 call time_monotonic_now_us
 test rax,rax
 jz .refuse
 mov r14,rax
 mov dword [rsp+16],11          ; deadline overflow
 add rax,2000
 jc .refuse
 mov r15,rax
 ; Preserve all unrelated control bits. Inherited addresses stay pinned and
 ; untouched; this requests STOP only, never resets an unexplained controller.
 mov rdx,[rsp+8]
 or qword [rdx+56],2            ; STOP requests issued, not a stop proof
 and byte [rbx+0x4c],~2
 and byte [rbx+0x5c],~2
 xor r13d,r13d
.wait:
 mov dword [rsp+16],12          ; poll ceiling
 inc r13d
 cmp r13d,4096
 ja .refuse
 call time_monotonic_now_us
 mov dword [rsp+16],13          ; clock regressed
 cmp rax,r14
 jb .refuse
 mov r14,rax
 mov dword [rsp+16],14          ; deadline reached
 cmp rax,r15
 jae .refuse
 mov dword [rsp+16],15          ; stream became active
 call hdb_streams_idle
 test eax,eax
 jnz .stream_refuse
 test byte [rbx+0x4c],2
 jnz .wait
 test byte [rbx+0x5c],2
 jnz .wait
 mov dword [rsp+16],16          ; both command engines read back stopped
 inc dword [rel hda_handoff_stopped]
 jmp .advance
.stream_refuse:
 mov rax,[rsp+8]
 mov [rax+48],rdx              ; -1 for invalid GCAP; exact index for RUN
.refuse:
 inc dword [rel hda_handoff_refused]
.advance:
 mov rdx,[rsp+8]
 mov eax,[rsp+16]
 mov [rdx+16],rax
 test byte [rdx+56],1
 jz .recorded
 movzx eax,byte [rbx+0x4c]
 movzx ecx,byte [rbx+0x5c]
 shl ecx,8
 or eax,ecx
 mov [rdx+32],rax              ; final observed control bytes, not ownership
.recorded:
 inc r12d
 jmp .next
.out:
 mov eax,[rel hda_handoff_stopped]
 add rsp,24
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; RBX=validated aperture, no writes. All real stream descriptors, no assumed
; input/output layout; GCAP total must fit the same 1..30 native OPEN policy.
hdb_streams_idle:
 movzx eax,word [rbx]
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
 jz .invalid
 cmp ecx,30
 ja .invalid
 xor edx,edx
.sd:
 imul eax,edx,32
 test byte [rbx+rax+0x80],2
 jnz .bad                           ; never stop another stream owner
 inc edx
 cmp edx,ecx
 jb .sd
 xor eax,eax
 ret
.invalid:
 mov rdx,-1
.bad:
 mov eax,-1
 ret

%macro WDATA_dev_snd_hda_boot_handoff 0
align 4
hda_handoff_closed: dd 0
hda_handoff_visited: dd 0
hda_handoff_stopped: dd 0
hda_handoff_refused: dd 0
hda_handoff_disposition: dd 0
align 8
hda_handoff_rows: times 32*8 dq 0
%endmacro
WDATA_DEFER WDATA_dev_snd_hda_boot_handoff
