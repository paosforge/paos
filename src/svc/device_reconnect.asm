;; MODULE svc/device_reconnect
;; LAYER 5
;; EXPORTS device_reconnect_control, device_reconnect_snapshot
;; IMPORTS svc/runtime_failure_sources, dev/usb/hid, dev/usb/xhci, dev/blk/usb_msd, dev/blk/usb_msd_owned, fs/blockdev, fs/vfs, fs/owned_media, core/lib/sha256
;; CAPS
;; OWNER rc-vm-claude
;; CONTEXT: bsp_only
; Original owner SELFTEST control only. One logical selection retains its old
; incarnation and one private power receipt. Public fields never carry pointers.
; No discovery/reset/signer/backend is implemented here. Class leaves own exact
; retirement/rebind; INPUT alone owns the root-power transaction. Logical port
; witnesses do not establish electrical disconnection. Surprise is unsupported.
;
; Per-selection row576: public256, original normalized class96, private power80,
; selected FAT expectation64, consumed serial8, fresh ordinal4/old handle4,
; new handle8/exact media dev8. Unused tail is zero. Rows are BSP-only/no alloc.
device_reconnect_control:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,24
    mov [rsp],edx
    mov [rsp+4],ecx
    mov r15,r8
    mov r14d,edi
    mov r13d,esi
    cmp esi,4
    ja .invalid
%ifidn PAOS_LAB_D8_HID_REJECT,1
    cmp edi,3
    ja .invalid
    jne .selection
    cmp esi,4
    je .invalid
.selection:
%else
    cmp edi,2
    ja .invalid
%endif
    imul eax,esi,576
    lea r12,[rel device_reconnect_rows]
    add r12,rax
    test edi,edi
    jnz .effect
    test dword [r12+24],2
    jz .observe
    cmp dword [r12+8],5
    jne .publish
    cmp r13d,4
    je .publish
    call device_reconnect_fresh_traffic
    test eax,eax
    jz .publish
    mov dword [r12+8],4
    jmp .publish
.observe:
    call device_reconnect_current
    test eax,eax
    jnz .absent
    call device_reconnect_observed
    jmp .publish
.effect:
    ; Never reopen an already consumed or uncertain incarnation. A fresh
    ; original class bind supplies the only possible larger serial.
    test r15,r15
    jz .refuse
    cmp r15,[r12+496]
    jbe .publish
    call device_reconnect_current
    test eax,eax
    jnz .refuse
    test dword [r12+24],2
    jnz .check_identity
    call device_reconnect_observed
.check_identity:
    lea rbx,[rel device_reconnect_class]
    cmp r15,[rbx]
    jne .refuse
    mov eax,[rsp+4]
    cmp eax,[rbx+20]
    jne .refuse
    mov rdi,[rbx+8]
    call xhci_hc_instance
    cmp eax,[rsp]
    jne .refuse
    call device_reconnect_observed
    cmp dword [r12+8],1
    jne .publish
    mov [r12+496],r15          ; consume before any class/VFS mutation
    mov [r12+12],r14d
    or dword [r12+24],2
    cmp r14d,1
%ifidn PAOS_LAB_D8_HID_REJECT,1
    je .orderly
    cmp r14d,3
%endif
    jne .unsupported
.orderly:
    mov dword [r12+8],4       ; all incomplete effects stay uncertain
    cmp r13d,4
    je .media_prepare
    mov edi,[r12+344]         ; actual retained HID ordinal, not logical index
    mov rsi,r15
    lea rdx,[rel device_reconnect_class]
    call usb_hid_owned_prepare
    test eax,eax
    jnz .publish             ; pending release: never power
    jmp .prepared
.media_prepare:
    mov rdi,[r12+520]
    mov rsi,r15
    lea rdx,[r12+432]
    mov ecx,64
    call vfs_selected_fat_snapshot
    cmp rax,-1
    je .publish
    cmp rax,31
    ja .publish
    mov [r12+508],eax
    mov rdi,[r12+520]
    mov rsi,r15
    call vfs_retire_device
    cmp rax,-1
    je .publish
    mov [r12+240],eax
    mov ecx,[r12+508]
    bt eax,ecx
    jnc .publish
    mov edi,ecx
    call vfs_mount_ptr
    test rax,rax
    jnz .publish             ; actual original handle must refuse dispatch
    or dword [r12+24],32
    mov rdi,[r12+520]
    mov rsi,r15
    lea rdx,[rel device_reconnect_media]
    call usb_msd_owned_prepare
    test eax,eax
    jnz .publish
.prepared:
    or dword [r12+24],4
    lea rdi,[r12+352]
    xor eax,eax
    mov ecx,10
    rep stosq
    mov rdi,[r12+264]
    mov esi,[r12+276]
    mov edx,[r12+272]
    lea rcx,[r12+280]
    lea r8,[r12+352]
    call xhci_device_root_power_cycle
    mov ebp,eax
    lea rsi,[r12+352]
    lea rdi,[r12+80]
    mov ecx,10
    rep movsq
    mov qword [r12+96],0      ; retained internal HC pointer is never public
    test ebp,ebp
    jnz .publish
    cmp dword [r12+360],0
    jne .publish
    cmp dword [r12+364],63
    jne .publish
    cmp dword [r12+424],0
    jne .publish
    cmp r13d,4
    je .media_reprobe
%ifidn PAOS_LAB_D8_HID_REJECT,1
    cmp r14d,3
    jne .hid_reprobe
    mov edi,[r12+344]
    mov rsi,r15
    mov edx,[r12+48]
    call usb_hid_owned_reject_arm
    test eax,eax
    jnz .publish             ; no claimed leaf rejection without actual offer
.hid_reprobe:
%endif
    mov edi,[r12+344]
    lea rsi,[r12+352]
    call usb_hid_owned_reprobe
%ifidn PAOS_LAB_D8_HID_REJECT,1
    cmp r14d,3
    jne .hid_result
    push rax
    push rdx
    mov edi,[r12+344]
    mov rsi,r15
    mov edx,[r12+48]
    call usb_hid_owned_reject_status
    cmp eax,2               ; actual leaf reached guarded one-use reject
    pop rdx
    pop rax
    jne .hid_result
    or dword [r12+24],128
    jmp .reprobe_rejected
.hid_result:
%endif
    cmp rax,r15
    jbe .reprobe_rejected
    cmp edx,1
    jb .reprobe_rejected
    cmp edx,4
    ja .reprobe_rejected
    mov [r12+504],edx
    mov [r12+40],rax
    jmp .fresh
.reprobe_rejected:
    ; Exactly the consumed original HID reprobe, never shared preguard .fail.
    pushfq
    push rax
    push rdx
    mov edi,r13d
    mov rsi,r15
    mov edx,[r12+48]
%ifidn PAOS_LAB_D8_HID_REJECT,1
    test dword [r12+24],128
    jz .natural_rejection
    call runtime_failure_reconnect_controlled_source
    jmp .rejection_recorded
.natural_rejection:
%endif
    call runtime_failure_reconnect_source
.rejection_recorded:
    pop rdx
    pop rax
    popfq
    jmp .publish
.media_reprobe:
    lea rdi,[r12+352]
    call usb_msd_owned_reprobe
    cmp rax,r15
    jbe .publish
    mov [r12+40],rax
    mov rbp,rax
    call usb_msd_dev
    test rax,rax
    jz .publish
    mov rdi,rax
    mov rsi,rbp
    lea rdx,[r12+432]
    call vfs_revalidate_fat_media
    cmp rax,-1
    je .publish
    cmp rax,31
    ja .publish
    mov [r12+512],rax
    mov ecx,[r12+508]
    cmp eax,ecx
    je .publish
    bt dword [r12+240],eax
    jc .publish
    mov edi,[r12+508]
    call vfs_mount_ptr
    test rax,rax
    jnz .publish             ; old handle never retargets after fresh bind
    mov rdi,[r12+512]
    call vfs_mount_ptr
    test rax,rax
    jz .publish
    or dword [r12+24],64
.fresh:
    call device_reconnect_current
    test eax,eax
    jnz .publish
    lea rbx,[rel device_reconnect_class]
    mov rax,[rbx]
    cmp rax,[r12+40]
    jne .publish
    mov rax,[rbx+8]
    cmp rax,[r12+264]
    jne .publish
    mov eax,[rbx+16]
    cmp eax,[r12+48]
    jne .publish
    mov eax,[rbx+20]
    cmp eax,[r12+56]
    jne .publish
    mov eax,[rbx+80]
    cmp eax,[r12+16]
    jne .publish
    lea rsi,[rbx+40]
    lea rdi,[r12+192]
    mov ecx,4
    rep movsq
    or dword [r12+24],8
    mov dword [r12+8],5
    cmp r13d,4
    je .publish
    call device_reconnect_fresh_traffic
    jmp .publish
.unsupported:
    mov dword [r12+8],3
    jmp .publish
.refuse:
    ; Identity refusal cannot destroy a retained consumed transaction.
    test dword [r12+24],2
    jnz .publish
    cmp dword [r12],0x43523344
    je .refused_record
    mov rax,0x0100000143523344
    mov [r12],rax
    mov [r12+20],r13d
.refused_record:
    mov dword [r12+8],2
    mov [r12+12],r14d
    jmp .publish
.absent:
    mov rdi,r12
    xor eax,eax
    mov ecx,32
    rep stosq
    mov rax,0x0100000143523344
    mov [r12],rax
    mov [r12+20],r13d
.publish:
    lea rdi,[rel device_reconnect_snapshot]
    mov rsi,r12
    mov ecx,32
    rep movsq
    xor eax,eax
    jmp .out
.invalid:
    mov eax,-1
.out:
    add rsp,24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Capture cached actual class state into normalized96. No IO or consumption.
; Media registry membership precedes the retained device-pointer dereference.
device_reconnect_current:
    push rbx
    lea rdi,[rel device_reconnect_class]
    xor eax,eax
    mov ecx,12
    rep stosq
    cmp r13d,4
    je .media
    mov edi,[r12+504]
    test edi,edi
    jnz .hid
    lea edi,[r13d+1]
.hid:
    lea rsi,[rel device_reconnect_class]
    call usb_hid_owned_snapshot
    jmp .out
.media:
    call usb_msd_dev
    test rax,rax
    jz .fail
    mov [r12+520],rax
    xor ebx,ebx
.member:
    mov rdi,rbx
    mov esi,BLKCAP_READ
    xor edx,edx
    call blk_iter_after
    test rax,rax
    jz .fail
    mov rbx,rax
    cmp rax,[r12+520]
    jne .member
    mov rax,[rax+dev.info]
    test rax,rax
    jz .fail
    mov rsi,[rax+blk_info.media_generation]
    mov rdi,rbx
    lea rdx,[rel device_reconnect_media]
    call usb_msd_owned_query
    test eax,eax
    jnz .fail
    lea rbx,[rel device_reconnect_class]
    lea rsi,[rel device_reconnect_media]
    mov rax,[rsi+16]
    mov [rbx],rax
    mov rax,[rsi+24]
    mov [rbx+8],rax
    mov eax,[rsi+36]
    mov [rbx+16],eax
    mov eax,[rsi+32]
    mov [rbx+20],eax
    mov rax,[rsi+40]
    mov [rbx+24],rax
    mov rax,[rsi+48]
    mov [rbx+32],rax
    add rsi,56
    lea rdi,[rbx+40]
    mov edx,18
    call sha256_hash
    test eax,eax
    jnz .fail
    mov dword [rbx+80],3
    mov dword [rbx+84],9
    xor eax,eax
    jmp .out
.fail:
    mov eax,-1
.out:
    pop rbx
    ret

; Build one available record from a cached normalized actual incarnation.
device_reconnect_observed:
    push rbx
    lea rbx,[rel device_reconnect_class]
    cmp qword [rbx],0
    je .fail
    mov rdi,[rbx+8]
    call xhci_hc_instance
    cmp eax,3
    ja .fail
    mov [r12+52],eax
    mov rdi,r12
    xor eax,eax
    mov ecx,32
    rep stosq
    mov rax,0x0100000143523344
    mov [r12],rax
    mov dword [r12+8],1
    mov eax,[rbx+80]
    mov [r12+16],eax
    mov [r12+20],r13d
    mov dword [r12+24],1
    mov rax,[rbx]
    mov [r12+32],rax
    mov eax,[rbx+16]
    mov [r12+48],eax
    mov rdi,[rbx+8]
    call xhci_hc_instance
    mov [r12+52],eax
    mov eax,[rbx+20]
    mov [r12+56],eax
    mov rax,[rbx+24]
    mov [r12+64],rax
    mov rax,[rbx+32]
    mov [r12+72],rax
    mov rax,[rbx+72]
    mov [r12+224],rax
    lea rdi,[r12+160]
    lea rsi,[rbx+40]
    mov ecx,4
    rep movsq
    lea rdi,[r12+256]
    mov rsi,rbx
    mov ecx,12
    rep movsq
    xor eax,eax
    jmp .out
.fail:
    mov dword [r12+8],2
    mov eax,-1
.out:
    pop rbx
    ret

; Only accepted traffic from the actual fresh bind serial/ordinal is observed.
device_reconnect_fresh_traffic:
    push rbx
    mov edi,[r12+504]
    lea rsi,[rel device_reconnect_class]
    call usb_hid_owned_snapshot
    test eax,eax
    jnz .out
    lea rbx,[rel device_reconnect_class]
    mov rax,[rbx]
    cmp rax,[r12+40]
    jne .fail
    mov rax,[rbx+8]
    cmp rax,[r12+264]
    jne .fail
    mov eax,[rbx+16]
    cmp eax,[r12+48]
    jne .fail
    mov eax,[rbx+20]
    cmp eax,[r12+56]
    jne .fail
    mov eax,[rbx+80]
    cmp eax,[r12+16]
    jne .fail
    lea rdi,[rbx+40]
    lea rsi,[r12+192]
    mov ecx,4
    repe cmpsq
    jne .fail
    mov rax,[rbx+72]
    mov [r12+232],rax
    and dword [r12+24],~16
    test rax,rax
    jz .ok
    or dword [r12+24],16
.ok:
    xor eax,eax
    jmp .out
.fail:
    mov eax,-1
.out:
    pop rbx
    ret

%macro WDATA_reconnect 0
align 16
device_reconnect_snapshot: times 256 db 0
device_reconnect_rows: times 2880 db 0
device_reconnect_class: times 96 db 0
device_reconnect_media: times 96 db 0
%endmacro
WDATA_DEFER WDATA_reconnect
