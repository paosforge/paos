;; MODULE dev/net/ax88179b
;; LAYER 3
;; EXPORTS ax88179b_lifecycle_poll, ax88179b_selftest, ax88179b_port_owned, ax88179b_frame_stats
;; IMPORTS boot/native_driver_gate, dev/net/ax_lifecycle, usb/enum, net/netdev, dev/net/ax88179b_attach, dev/net/ax88179b_control, dev/net/ax88179b_link, dev/net/ax88179b_codec, boot/serial, core/time
;; CAPS
;; OWNER saga:net
%include "boot/native_driver_gate.inc"
;; LOCK: axb_busy PROTECTS axb_runtime
%include "dev/net/ax_lifecycle.inc"
; Exact 0b95:1790/0200 native backend. One original enumerated HC/port;
; no Windows-name, controller-index, endpoint-address or cached-MAC guesses.
; Boot binds before CDC classes. Cached identity narrows the read-only probe;
; fresh18B identity and exact full configuration must agree before SET_CONFIG.
; Wire protocol and ordinary frame policy are in the separately reviewed newer
; helpers; legacy <=0100 remains separate. FS/HS/SS supported; SSP is refused
; until the HC has an explicit matching-speed companion configuration path.
;
; Cooperative USB core/HC callback lifetime, as for the existing USB NICs.
; All runtime operations use a nonblocking private owner. No nested TX/RX/link
; operation may alter the controller selection or our staging/cache buffers.
; The HC owns its DMA bounce/TD; it copies completed RX into our static buffer.
; Never free/reuse HC DMA or synthesize completion, cleanup, reset or retry.
; An uncertain control/TX/RX result retires this attempt and retains ownership.
; Link renegotiation after activation also retires: there may be a pending RX
; TD, so silently reprogramming aggregation would violate its lifetime.
; stop/recover return failure. Only the class-owned root lifecycle below may
; restore health after exact HC retirement and a fresh complete wire bind.
; Uncertain retirement/rebind remains quarantined. Static storage stays allocated.
; Explicit first-traffic diagnostic: NASM_EXTRA=-DPAOS_LAB_AX88179B_PRIMARY=1
; prefers this exact native member BEFORE the normal command/DHCP binding.
; Default remains experimental priority; no runtime switch or authority change.
%ifndef PAOS_LAB_AX88179B_PRIMARY
%define PAOS_LAB_AX88179B_PRIMARY 0
%endif
%if PAOS_LAB_AX88179B_PRIMARY != 0 && PAOS_LAB_AX88179B_PRIMARY != 1
%error PAOS_LAB_AX88179B_PRIMARY_must_be_0_or_1
%endif
; Separate, explicit first-traffic collection aid. Default product emits no
; additional traffic. One broadcast of bounded geometry, never frame bytes;
; no RX delivery, IP configuration, command authority or response is required.
%ifndef PAOS_LAB_AX88179B_RX_BEACON
%define PAOS_LAB_AX88179B_RX_BEACON 0
%endif
%if PAOS_LAB_AX88179B_RX_BEACON != 0 && PAOS_LAB_AX88179B_RX_BEACON != 1
%error PAOS_LAB_AX88179B_RX_BEACON_must_be_0_or_1
%endif

%macro AXB_USB 3
    mov rax,%1
    mov [rel axb_setup],rax
    lea rsi,[rel axb_setup]
    movzx edx,byte [rel axb_port]
%if %3
    lea rcx,[rel %2]
%else
    xor ecx,ecx
%endif
    mov r8d,%3
    call axb_control
%endmacro

ax88179b_selftest:
    NATIVE_DRIVER_REFUSE 6, 0
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    cmp byte [rel axb_state],0
    jne .done                       ; repeated boot callback cannot replay bind
    call usb_dev_count
    mov r13,rax
    xor r12d,r12d
.scan:
    cmp r12,r13
    jae .done
    mov edi,r12d
    call usb_dev_is_null
    test eax,eax
    jnz .next
    mov edi,r12d
    call usb_dev_desc_ptr
    mov rdi,rax
    mov esi,18
    call ax88179b_claims_desc
    test eax,eax
    jz .next
    mov edi,r12d
    call usb_dev_hc
    test rax,rax
    jz .next
    mov r14,rax
    mov r15,[rax+dev.ops]
    test r15,r15
    jz .next
    mov edi,r12d
    call usb_dev_addr
    test rax,rax
    jz .next
    cmp rax,255
    ja .next
    mov rbx,rax
    mov edi,r12d
    call usb_dev_topo_ptr
    test rax,rax
    jz .next
    movzx ebp,byte [rax+usb_topo.speed]
    cmp ebp,1
    je .ops
    cmp ebp,3
    je .ops
    cmp ebp,4
    jne .next
.ops:
    cmp qword [r15+usbhc_ops.control],0
    je .next
    cmp qword [r15+usbhc_ops.bulk_out],0
    je .next
    cmp qword [r15+usbhc_ops.bulk_in_poll],0
    je .next
    cmp qword [r15+usbhc_ops.port_status],0
    je .next
    mov eax,usbhc_ops.configure_ep
    cmp ebp,4
    jne .op_ready
    mov eax,usbhc_ops.configure_ep_ss
.op_ready:
    cmp qword [r15+rax],0
    je .next
    mov [rel axb_hc],r14
    mov [rel axb_hcops],r15
    mov [rel axb_port],bl
    mov [rel axb_speed],bpl
    mov byte [rel axb_state],1       ; sticky claim BEFORE the first transfer
    call axb_bind_wire
    test eax,eax
    jz .failed
    call axb_create
    test rax,rax
    js .failed
    mov byte [rel axb_registered],1
    lea rdi,[rel axb_life]
    mov esi,r12d
    lea rdx,[rel axb_dev]
    lea rcx,[rel axb_rebind_wire]
    lea r8,[rel axb_devbuf]
    lea r9,[rel axb_link]
    call ax_lifecycle_capture
    lea rdi,[rel str_axb_registered]
    call serial_string
%if PAOS_LAB_AX88179B_PRIMARY
    lea rdi,[rel str_axb_primary]
    call serial_string
%endif
    jmp .done
.failed:
    call axb_retire
    lea rdi,[rel str_axb_failed]
    call serial_string
    jmp .done                       ; one claimed lifetime; no next-device replay
.next:
    inc r12
    jmp .scan
.done:
    xor eax,eax
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Blocking control callback: RDI milliseconds; result ignored. A one-ms loop
; avoids multiplication overflow. RBX holds the count across tsc_delay_us and
; is restored; other SysV nonvolatiles are untouched. Zero is a no-op.
axb_delay_ms:
    push rbx
    mov rbx,rdi
    test rbx,rbx
    jz .done
.loop:
    mov edi,1000
    call tsc_delay_us
    dec rbx
    jnz .loop
.done:
    pop rbx
    ret

; Helpers use a self-less synchronous callback; bind self explicitly here.
axb_control:
    mov rdi,[rel axb_hc]
    mov rax,[rel axb_hcops]
    jmp [rax+usbhc_ops.control]
axb_configure:
    NATIVE_DRIVER_REFUSE 6
    mov rdi,[rel axb_hc]
    movzx esi,byte [rel axb_port]
    mov rax,[rel axb_hcops]
    cmp byte [rel axb_speed],4
    jne .legacy
    mov ecx,13
    jmp [rax+usbhc_ops.configure_ep_ss]
.legacy:
    jmp [rax+usbhc_ops.configure_ep]

; Only before any RX TD: parked init, or first link-up after parked link-down.
axb_activate:
    NATIVE_DRIVER_REFUSE 6
    sub rsp,8
    lea rdi,[rel axb_devbuf]
    mov esi,18
    movzx edx,byte [rel axb_port]
    lea rcx,[rel axb_control]
    movzx r8d,byte [rel axb_speed]
    lea r9,[rel axb_link]
    call ax88179b_link_start
    test eax,eax
    jz .done
    mov edx,2
    cmp eax,1
    jne .state
    mov edx,3
.state:
    mov [rel axb_state],dl
.done:
    add rsp,8
    ret

axb_create:
    NATIVE_DRIVER_REFUSE 6
    lea rdi,[rel axb_ops]
%assign ai 0
%rep 8
%if ai=0 || ai=1
    lea rax,[rel axb_start]
%elif ai=2
    lea rax,[rel axb_stop]
%elif ai=3
    lea rax,[rel axb_tx]
%elif ai=4
    lea rax,[rel axb_rx_poll]
%elif ai=5
    lea rax,[rel axb_link_status]
%elif ai=6
    lea rax,[rel axb_get_mac]
%else
    lea rax,[rel axb_recover]
%endif
    mov [rdi+ai*8],rax
%assign ai ai+1
%endrep
    lea rdi,[rel axb_dev]
    lea rax,[rel axb_ops]
    mov [rdi+dev.ops],rax
    lea rax,[rel axb_info]
    mov [rdi+dev.info],rax
    lea rax,[rel str_axb_name]
    mov [rdi+dev.name],rax
    mov [rel axb_info+netdev_info.name],rax
    mov dword [rel axb_info+netdev_info.mtu],1500
    mov byte [rel axb_info+netdev_info.dma_mask],64
    mov dword [rel axb_info+netdev_info.flags],NETF_USB
    mov dword [rdi+dev.class],CLASS_NET
%if PAOS_LAB_AX88179B_PRIMARY
    mov dword [rdi+dev.prio],PRIO_NATIVE+1
%else
    mov dword [rdi+dev.prio],PRIO_NATIVE_EXPERIMENTAL
%endif
    mov dword [rdi+dev.health],HEALTH_OK
    jmp netdev_register

; EAX1 owns busy, connected, registered and parked/active. No nested wait.
; Runtime callers retain their own parameters in nonvolatile registers.
axb_enter:
    lea rax,[rel axb_dev]
    cmp rdi,rax
    jne .no
    cmp byte [rel axb_registered],1
    jne .no
    xor eax,eax
    mov ecx,1
    lock cmpxchg [rel axb_busy],ecx
    jne .no
    cmp byte [rel axb_state],2
    jb .unlock
    cmp dword [rel axb_dev+dev.health],HEALTH_DEAD
    je .unlock
    sub rsp,8
    mov rdi,[rel axb_hc]
    movzx esi,byte [rel axb_port]
    mov rax,[rel axb_hcops]
    call [rax+usbhc_ops.port_status]
    add rsp,8
    test rax,rax
    js .gone
    test al,1
    jz .gone
    mov eax,1
    ret
.gone:
    call axb_retire
.unlock:
    mov dword [rel axb_busy],0
.no:
    xor eax,eax
    ret
axb_retire:
    mov byte [rel axb_state],1
    mov dword [rel axb_dev+dev.health],HEALTH_DEAD
    mov qword [rel axb_rx_iter+24],0
    ret
axb_unlock:
    mov dword [rel axb_busy],0
    ret

axb_start:
    lea rax,[rel axb_dev]
    cmp rdi,rax
    jne axb_recover
    cmp byte [rel axb_registered],1
    jne axb_recover
    cmp byte [rel axb_state],2
    jb axb_recover
    cmp dword [rel axb_dev+dev.health],HEALTH_DEAD
    je axb_recover
    xor eax,eax
    ret
axb_stop:
    sub rsp,8
    call axb_enter
    test eax,eax
    jz .done
    call axb_retire
    call axb_unlock
.done:
    add rsp,8
axb_recover:
    mov rax,-1                     ; no false claim of endpoint quiescence
    ret

axb_tx:
    push rbx
    push r12
    push r13
    mov r12,rsi
    mov r13,rdx
    call axb_enter
    test eax,eax
    jz .failed
    cmp byte [rel axb_state],3
    jne .unavailable
    mov rdi,r12
    mov rsi,r13
    lea rdx,[rel axb_txbuf]
    mov ecx,2048
    call ax88179b_tx_record
    jc .unavailable
    mov rbx,rax
    mov rdi,[rel axb_hc]
    movzx esi,byte [rel axb_port]
    movzx edx,byte [rel axb_plan+11]
    lea rcx,[rel axb_txbuf]
    mov r8,rbx
    mov rax,[rel axb_hcops]
    call [rax+usbhc_ops.bulk_out]
    cmp rax,rbx
    jne .retire
    lock inc qword [rel axb_stat_tx_frames]
    xor eax,eax
    jmp .unlock
.retire:
    call axb_retire
.unavailable:
    mov rax,-1
.unlock:
    call axb_unlock
    jmp .done
.failed:
    mov rax,-1
.done:
    pop r13
    pop r12
    pop rbx
    ret

axb_rx_poll:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rsi
    mov r13,rdx
    test r12,r12
    jz .failed
    mov rax,r12
    add rax,r13
    jc .failed
    call axb_enter
    test eax,eax
    jz .failed
    cmp byte [rel axb_state],3
    jne .none
    cmp qword [rel axb_rx_iter+24],0
    jne .cached
    mov rdi,[rel axb_hc]
    movzx esi,byte [rel axb_port]
    movzx edx,byte [rel axb_plan+10]
    lea rcx,[rel axb_rxbuf]
    mov r8d,49152
    mov rax,[rel axb_hcops]
    call [rax+usbhc_ops.bulk_in_poll]
    test rax,rax
    jz .none
    cmp rax,49152                   ; unsigned full64bit rejects every negative
    ja .retire
    call axb_rx_geometry            ; first actual completion, bounded metadata only
%if PAOS_LAB_AX88179B_RX_BEACON
    cmp byte [rel axb_state],3
    jne .retire                     ; uncertain diagnostic TX retires as normal TX
%endif
    mov rsi,rax
    lea rdi,[rel axb_rxbuf]
    lea rdx,[rel axb_rx_iter]
    call ax88179b_rx_begin
    jc .discard
.cached:
    lea rdi,[rel axb_rx_iter]
    call ax88179b_rx_next
    jc .none
    mov r15,rdx
    cmp r15,r13                     ; caller capacity is also full64bit
    ja .none                        ; consume only this short-caller frame
    ; A caller cannot destroy the immutable cache by using it as output.
    lea rdx,[rel axb_rxbuf+49152]
    cmp r12,rdx
    jae .disjoint
    lea rdx,[r12+r15]
    lea rcx,[rel axb_rxbuf]
    cmp rcx,rdx
    jb .none
.disjoint:
    mov rsi,rax
    mov rdi,r12
    mov ecx,r15d
    cld
    rep movsb
    mov rax,r15
    lock inc qword [rel axb_stat_rx_frames]
    jmp .unlock
.discard:
    mov qword [rel axb_rx_iter+24],0
.none:
    xor eax,eax
    jmp .unlock
.retire:
    call axb_retire
    mov rax,-1
.unlock:
    call axb_unlock
    jmp .done
.failed:
    mov rax,-1
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RAX=already bounded actual bytes. Retain the first footer and at most four
; in-range descriptor qwords for metal format diagnosis (FCS/flags/padding).
; Snapshot ABI (64B, little endian): magic "PaOSAXG1", actual64, footer64,
; entry_count8, flags8 (bit0 footer present, bit1 table bounded), reserved6,
; up to four raw descriptor qwords, zero-filled. Persists after cache recycle.
; No frame-data copy or inferred completion. Explicit lab flag may broadcast
; this record once, after serial output, using the already-held private owner.
; Preserve RAX and all nonvolatiles. A malformed table is never dereferenced.
axb_rx_geometry:
    push rbx
    push r12
    push r13
    mov rbx,rax
    cmp rbx,49152                  ; diagnostic defends its own buffer boundary
    ja .done
    cmp byte [rel axb_rx_seen],0
    jne .done ; first geometry only
    mov byte [rel axb_rx_seen],1
    lea rdi,[rel axb_rx_snapshot]
    xor eax,eax
    mov ecx,8
    cld
    rep stosq
    mov rax,0x31475841534f6150        ; PaOSAXG1
    mov [rel axb_rx_snapshot],rax
    mov [rel axb_rx_snapshot+8],rbx
    lea rdi,[rel str_axb_geometry]
    call serial_string
    mov rdi,rbx
    call serial_hex64
    cmp rbx,8
    jb .eol
    lea r13,[rel axb_rxbuf]
    mov r12,[r13+rbx-8]
    mov [rel axb_rx_snapshot+16],r12
    mov byte [rel axb_rx_snapshot+25],1
    lea rdi,[rel str_axb_footer]
    call serial_string
    mov rdi,r12
    call serial_hex64
    mov eax,r12d
    shr eax,13
    mov ecx,r12d
    and ecx,0x1fff
    test ecx,ecx
    jz .eol
    lea rdx,[rax+rcx*8+8]
    cmp rdx,rbx
    ja .eol
    or byte [rel axb_rx_snapshot+25],2
    add r13,rax
    mov r12d,ecx
    cmp r12d,4
    jbe .entry
    mov r12d,4 ; bounded snapshot entries
.entry:
    movzx eax,byte [rel axb_rx_snapshot+24]
    lea rdx,[rel axb_rx_snapshot+32]
    mov rcx,[r13]
    mov [rdx+rax*8],rcx
    inc byte [rel axb_rx_snapshot+24]
    lea rdi,[rel str_axb_entry]
    call serial_string
    mov rdi,[r13]
    call serial_hex64
    add r13,8
    dec r12d
    jnz .entry
.eol:
    lea rdi,[rel str_axb_eol]
    call serial_string
%if PAOS_LAB_AX88179B_RX_BEACON
    call axb_rx_beacon
%endif
.done:
    mov rax,rbx
    pop r13
    pop r12
    pop rbx
    ret

%if PAOS_LAB_AX88179B_RX_BEACON
; Called ONCE under axb_busy after a positive completed RX has been consumed by
; the HC (not while it is pending). Different OUT endpoint; normal synchronous
; HC ownership and immutable OUT snapshot apply. Do not recursively enter TX.
; Fixed 78B Ethernet frame: broadcast destination, freshly read member MAC,
; experimental EtherType 88b5, 64B snapshot. No ACK, timeout replay or retry.
axb_rx_beacon:
    push rbx
    lea rdi,[rel axb_beacon_frame]
    mov dword [rdi],0xffffffff
    mov word [rdi+4],0xffff
    mov eax,[rel axb_link] ; fresh beacon MAC
    mov [rdi+6],eax
    mov ax,[rel axb_link+4]
    mov [rdi+10],ax
    mov word [rdi+12],0xb588
    add rdi,14
    lea rsi,[rel axb_rx_snapshot]
    mov ecx,8
    cld
    rep movsq
    lea rdi,[rel axb_beacon_frame]
    mov esi,78
    lea rdx,[rel axb_txbuf]
    mov ecx,2048
    call ax88179b_tx_record
    jc .retire
    mov rbx,rax
    mov rdi,[rel axb_hc]
    movzx esi,byte [rel axb_port]
    movzx edx,byte [rel axb_plan+11]
    lea rcx,[rel axb_txbuf]
    mov r8,rbx
    mov rax,[rel axb_hcops]
    call [rax+usbhc_ops.bulk_out]
    cmp rax,rbx ; beacon exact completion
    jne .retire
    lock inc qword [rel axb_stat_tx_frames]
    jmp .done
.retire:
    call axb_retire
.done:
    pop rbx
    ret
%endif

axb_link_status:
    sub rsp,8
    call axb_enter
    test eax,eax
    jz .down_unowned
    cmp byte [rel axb_state],2
    jne .sample
    call axb_activate               ; no RX TD has ever been armed while parked
    test eax,eax
    jz .retire
    cmp byte [rel axb_state],3
    jne .down
    jmp .speed
.sample:
    AXB_USB 0x00020011000302c0,axb_phy,2
    cmp rax,2
    jne .retire
    movzx eax,word [rel axb_phy]
    and eax,0xe400
    movzx edx,word [rel axb_link+8]
    and edx,0xe400
    cmp eax,edx
    jne .retire                    ; never reconfigure across a pending RX TD
.speed:
    movzx edx,word [rel axb_link+8]
    mov eax,(1000<<8)|1
    test dx,0x8000
    jnz .unlock
    mov eax,(100<<8)|1
    test dx,0x4000
    jnz .unlock
    mov eax,(10<<8)|1
    jmp .unlock
.retire:
    call axb_retire
.down:
    xor eax,eax
.unlock:
    call axb_unlock
.down_unowned:
    add rsp,8
    ret

axb_get_mac:
    lea rax,[rel axb_dev]
    cmp rdi,rax
    jne axb_recover
    cmp byte [rel axb_registered],1
    jne axb_recover
    test rsi,rsi
    jz axb_recover
    xor eax,eax
    mov ecx,1
    lock cmpxchg [rel axb_busy],ecx
    jne axb_recover
    mov eax,[rel axb_link]
    mov [rsi],eax
    mov ax,[rel axb_link+4]
    mov [rsi+4],ax
    xor eax,eax
    jmp axb_unlock

; Full HC pointer and full port token; retired attempts retain the claim.
ax88179b_port_owned:
    xor eax,eax
    cmp byte [rel axb_state],0
    je .done
    cmp [rel axb_hc],rdi
    jne .done
    movzx ecx,byte [rel axb_port]
    cmp rsi,rcx
    jne .done
    mov eax,1
.done:
    ret
; BEGIN FRAME STATS
ax88179b_frame_stats:
    lea rax,[rel axb_dev]
    cmp rdi,rax
    jne .bad
    lea rax,[rel axb_ops]
    cmp [rdi+dev.ops],rax
    jne .bad
    mov rdx,[rel axb_stat_rx_frames]
    mov rcx,[rel axb_stat_tx_frames]
    xor eax,eax
    ret
.bad:
    mov rdx,-1
    mov rcx,-1
    mov eax,-1
    ret
; END FRAME STATS

; BEGIN AXB STATIC
align 16
axb_runtime_begin:
axb_state: db 0                     ; 0 free,1 claimed/retired,2 parked,3 active
axb_registered: db 0
axb_port: db 0
axb_speed: db 0
axb_busy: dd 0
axb_rx_seen: dq 0
axb_rx_snapshot: times 64 db 0
%if PAOS_LAB_AX88179B_RX_BEACON
axb_beacon_frame: times 78 db 0
align 8
%endif
axb_hc: dq 0
axb_hcops: dq 0
axb_stat_rx_frames: dq 0
axb_stat_tx_frames: dq 0
axb_rx_iter: times 48 db 0
axb_dev: times dev_size db 0
axb_ops: times netdev_ops_size db 0
axb_info: times netdev_info_size db 0
axb_setup: times 8 db 0
axb_phy: times 2 db 0
axb_plan: times 48 db 0
axb_parked: times 16 db 0
axb_link: times 32 db 0
axb_devbuf: times 18 db 0
axb_ep_in: times 13 db 0
axb_ep_out: times 13 db 0
axb_cfgbuf: times 4096 db 0
align 16
axb_txbuf: times 2048 db 0
axb_rxbuf: times 49152 db 0
align 8
axb_life: times ax_lifetime_size db 0
axb_runtime_end:
str_axb_name: db 'ax88179b',0
str_axb_registered: db '[PAOS64] L2 netdev: native newer ASIX bound [netdev.ax88179b.registered]',13,10,0
str_axb_primary: db '[PAOS64] L2 netdev: explicit AX boot preference [netdev.ax88179b.lab.primary]',13,10,0
str_axb_failed: db '[PAOS64] L2 netdev: newer ASIX attempt retired [netdev.ax88179b.bind.failed]',13,10,0
str_axb_geometry: db '[PAOS64] L2 netdev: [netdev.ax88179b.rx.geometry] actual=',0
str_axb_footer: db ' footer=',0
str_axb_entry: db ' entry=',0
str_axb_eol: db 13,10,0

; One actual wire bind shared by boot and replacement. No registry write here.
axb_bind_wire:
    push rbp
    AXB_USB 0x0012000001000680,axb_devbuf,18
    mov rsi,rax
    lea rdi,[rel axb_devbuf]
    call ax88179b_claims_desc
    test eax,eax
    jz .failed
    cmp qword [rel axb_life+ax_lifetime.incarnation],0
    je .descriptor_ok
    lea rdi,[rel axb_life]
    lea rsi,[rel axb_devbuf]
    call ax_lifecycle_descriptor_same
    test eax,eax
    jz .failed
.descriptor_ok:
    AXB_USB 0x0009000002000680,axb_cfgbuf,9
    cmp rax,9
    jne .failed
    cmp word [rel axb_cfgbuf],0x0209
    jne .failed
    movzx ebp,word [rel axb_cfgbuf+2]
    cmp ebp,9
    jb .failed
    cmp ebp,4096
    ja .failed
    mov rax,0x0000000002000680
    mov edx,ebp
    shl rdx,48
    or rax,rdx
    mov [rel axb_setup],rax
    lea rsi,[rel axb_setup]
    movzx edx,byte [rel axb_port]
    lea rcx,[rel axb_cfgbuf]
    mov r8d,ebp
    call axb_control
    cmp rax,rbp
    jne .failed
    lea rdi,[rel axb_cfgbuf]
    mov rsi,rax
    movzx edx,byte [rel axb_speed]
    lea rcx,[rel axb_plan]
    call ax88179b_config_plan
    cmp eax,1
    jne .failed
    movzx eax,byte [rel axb_plan+8]
    shl rax,16
    or eax,0x0900
    mov [rel axb_setup],rax
    lea rsi,[rel axb_setup]
    movzx edx,byte [rel axb_port]
    xor ecx,ecx
    xor r8d,r8d
    call axb_control
    test rax,rax                    ; zero-data completion is exactly zero
    jnz .failed
    ; Keep descriptor+companion contiguous until both synchronous commands end.
    mov rax,[rel axb_plan+16]
    mov [rel axb_ep_in],rax
    mov eax,[rel axb_plan+32]
    mov [rel axb_ep_in+7],eax
    mov ax,[rel axb_plan+36]
    mov [rel axb_ep_in+11],ax
    mov rax,[rel axb_plan+24]
    mov [rel axb_ep_out],rax
    mov eax,[rel axb_plan+40]
    mov [rel axb_ep_out+7],eax
    mov ax,[rel axb_plan+44]
    mov [rel axb_ep_out+11],ax
    lea rdx,[rel axb_ep_in]
    call axb_configure
    test rax,rax
    jnz .failed
    lea rdx,[rel axb_ep_out]
    call axb_configure
    test rax,rax
    jnz .failed
    lea rdi,[rel axb_devbuf]
    mov esi,18
    movzx edx,byte [rel axb_port]
    lea rcx,[rel axb_control]
    lea r8,[rel axb_delay_ms]
    lea r9,[rel axb_parked]
    call ax88179b_init_parked
    cmp eax,1
    jne .failed
    call axb_activate
    test eax,eax
    jz .failed
    mov eax,1
    pop rbp
    ret
.failed:
    xor eax,eax
    pop rbp
    ret

ax88179b_lifecycle_poll:
    NATIVE_DRIVER_REFUSE 6
    xor eax,eax
    mov ecx,1
    lock cmpxchg [rel axb_busy],ecx
    jne .out
    sub rsp,8
    lea rdi,[rel axb_life]
    call ax_lifecycle_poll
    cmp dword [rel axb_life+ax_lifetime.phase],2
    jb .release
    call axb_retire
.release:
    mov dword [rel axb_busy],0
    add rsp,8
.out:
    ret

axb_rebind_wire:
    push rbx
    mov rbx,rsi
    call usb_dev_topo_ptr
    mov dl,[rax+usb_topo.speed]
    mov [rel axb_speed],dl
    call axb_bind_wire
    test eax,eax
    jz .failed
    mov eax,[rel axb_link]
    cmp eax,[rbx]
    jne .failed
    mov ax,[rel axb_link+4]
    cmp ax,[rbx+4]
    jne .failed
    xor eax,eax
    pop rbx
    ret
.failed:
    mov eax,[rbx]
    mov [rel axb_link],eax
    mov ax,[rbx+4]
    mov [rel axb_link+4],ax
    call axb_retire
    mov rax,-1
    pop rbx
    ret

%unmacro AXB_USB 3
