;; MODULE dev/net/ax88179b_attach
;; LAYER 3
;; EXPORTS ax88179b_claims_desc, ax88179b_feature_match, ax88179b_config_plan
;; IMPORTS
;; CAPS
;; OWNER saga:net
; Newer AX attachment planning, separate from the legacy <=0100 driver.
; ASIXElectronics/asix-usb-nic-linux-driver at
; 42feb1252fe0669845a8d6714bcc77bfc19eea1d: ax_main.c:2357..2402,
; 2454..2497,2996..3030; ax_main.h:62..69,172..174,399..407.
; USB 2.0 9.6.3/9.6.5/9.6.6 and USB3 endpoint companion geometry.
; Independent implementation, not a live backend. No USB transfer, selection,
; ownership, chip write or registration here. A caller must freshly read the
; device/config and CHIP_STATUS and check each completion, then use the newer
; init, codec and link path. Do not infer any of these from Windows names.

; RDI=immutable DEVICE descriptor,RSI=actual completed length -> EAX=0/1.
; Only exact observed target profile 0b95:1790 bcdDevice0200 is implemented.
; ASIX table ranges overlap (772D0300 precedes179A0200); this does not widen
; either driver or imply another revision has the same native protocol.
; RAX/flags only clobbered; complete shape is checked before identity reads.
ax88179b_claims_desc:
    xor eax, eax
    cmp rsi, 18
    jne .out
    test rdi, rdi
    jz .out
    cmp word [rdi], 0x0112
    jne .out
    cmp word [rdi + 8], 0x0b95
    jne .out
    cmp word [rdi + 10], 0x1790
    jne .out
    cmp word [rdi + 12], 0x0200
    jne .out
    mov eax, 1
.out:
    ret

; RDI=exact one-byte CHIP_STATUS read result, expanded unsigned -> EAX=0/1.
; Status request is C0/01/value0005/index0001/length0001. Future backend must
; require actual count1 before this call. Accept only CHIP_CODE6 (179A/772D),
; not older4 or newer88279/279A code. Low nibble is revision, not chip family.
ax88179b_feature_match:
    xor eax, eax
    cmp rdi, 255
    ja .out
    mov eax, edi
    and eax, 0xf0
    cmp eax, 0x60
    sete al
    movzx eax, al
.out:
    ret

; RDI=complete immutable CONFIG bytes,RSI=actual bytes (9..4096),
; RDX=xHCI speed1 FS/3 HS/4 SS/5 SSP,RCX=trusted distinct48B output.
; EAX1 succeeds,0 refuses. Preserves RBX/RBP/R12-R15; volatile GPRs/flags may
; change. Whole stream validated before output writes; refusal leaves output
; untouched. Caller retains descriptor bytes until endpoint setup completes.
;
; Supported vendor config1: one interface0/alt0,classFF; exactly one bulk IN
; and one bulk OUT, optionally one interrupt endpoint. Class/NCM, alternate
; and composite configurations need their own binding path, never a guessed
; cross-interface pairing. Endpoint addresses come from descriptors.
; Also accepts observed four-endpoint SS config: interrupt81, bulk82 IN,
; primary bulk03 OUT, auxiliary bulk05 OUT. Only82/03 are published;05 and81
; remain unconfigured. ASIX ax88179a_772d.c:3721 selects03 for default TX,
; 05 only for priority queue1. Caller must leave priority routing disabled.
; The observed unused interrupt companion has wBytesPerInterval=0; tolerate
; that quirk only for this profile with packet16,interval11,burst0. Captured
; Reatan descriptor provenance is pinned in the host test. This is not an
; interrupt endpoint configuration plan or evidence of a hardware transfer.
;
; Output: qword schema1; bytes8=config,9=interface,10=IN,11=OUT;
; words12/14=IN/OUT maxpacket; bytes16/24=7B IN/OUT endpoint+zero;
; bytes32/40=6B IN/OUT SS companion+2zeros (all zero below SS).
; SS caller must use configure_ep_ss with these companions, not discard burst
; geometry. Only non-stream bulk endpoints are supported. No DMA size follows
; from wMaxPacketSize: the backend must separately bound actual completions.
ax88179b_config_plan:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 104
    xor eax, eax
    test rdi, rdi
    jz .out
    test rcx, rcx
    jz .out
    cmp rsi, 9
    jb .out
    cmp rsi, 4096
    ja .out
    mov r12, rdi
    add r12, rsi
    jc .out
    mov r14, rdx
    cmp rdx, 1
    je .speed
    cmp rdx, 3
    jb .out
    cmp rdx, 5
    ja .out
.speed:
    cmp word [rdi], 0x0209
    jne .out
    movzx eax, word [rdi + 2]
    cmp rax, rsi
    jne .bad
    cmp word [rdi + 4], 0x0101         ; bNumInterfaces1,bConfigurationValue1
    jne .bad
    mov al, [rdi + 7]
    and al, 0x9f
    cmp al, 0x80
    jne .bad
    mov r13, rcx
    lea rbx, [rdi + 9]
    mov rdi, rsp
    xor eax, eax
    mov ecx, 104 / 8
    cld
    rep stosq
    mov qword [rsp], 1
    mov byte [rsp + 8], 1
    ; locals48=seen interface,52=expected eps,56=seen eps,60=address mask,
    ; 64=interrupt count,68=pending SS,72=companion dest,80=last kind,
    ; 84=last packet,88=last interval. All local, no global mutable state.
.row:
    cmp rbx, r12
    jae .done
    mov rax, r12
    sub rax, rbx
    cmp rax, 2
    jb .bad
    movzx ebp, byte [rbx]
    cmp ebp, 2
    jb .bad
    cmp rbp, rax
    ja .bad
    movzx edx, byte [rbx + 1]
    cmp dword [rsp + 68], 0
    je .type
    cmp edx, 0x30
    jne .bad
.type:
    cmp edx, 4
    je .interface
    cmp edx, 5
    je .endpoint
    cmp edx, 0x30
    je .companion
    cmp edx, 2                       ; second config cannot hide in this stream
    je .bad
    jmp .next
.interface:
    cmp ebp, 9
    jne .bad
    cmp dword [rsp + 48], 0
    jne .bad
    cmp word [rbx + 2], 0            ; interface0,alternate0
    jne .bad
    cmp byte [rbx + 5], 0xff
    jne .bad
    movzx eax, byte [rbx + 4]
    cmp eax, 2
    jb .bad
    cmp eax, 4
    ja .bad
    jne .interface_count
    cmp r14d, 4                     ; observed dual-queue layout is SS only
    jb .bad
.interface_count:
    mov [rsp + 52], eax
    mov dword [rsp + 48], 1
    jmp .next
.endpoint:
    cmp ebp, 7
    jne .bad
    cmp dword [rsp + 48], 1
    jne .bad
    inc dword [rsp + 56]
    mov eax, [rsp + 56]
    cmp eax, [rsp + 52]
    ja .bad
    movzx edx, byte [rbx + 2]
    test dl, 0x70
    jnz .bad
    mov ecx, edx
    and ecx, 15
    jz .bad
    test dl, 0x80
    jz .bit
    add ecx, 16
.bit:
    bts dword [rsp + 60], ecx
    jc .bad
    movzx eax, byte [rbx + 3]
    mov [rsp + 80], eax
    cmp dword [rsp + 52], 4
    jne .endpoint_kind
    cmp eax, 3
    jne .four_bulk
    cmp dl, 0x81
    jne .bad
    jmp .endpoint_kind
.four_bulk:
    cmp eax, 2
    jne .bad
    cmp dl, 0x82
    je .endpoint_kind
    cmp dl, 3
    je .endpoint_kind
    cmp dl, 5
    jne .bad
.endpoint_kind:
    movzx ecx, word [rbx + 4]
    mov [rsp + 84], ecx
    movzx eax, byte [rbx + 6]
    mov [rsp + 88], eax
    mov eax, [rsp + 80]
    mov dword [rsp + 72], 0
    cmp eax, 2
    je .bulk
    cmp eax, 3
    jne .bad
    inc dword [rsp + 64]
    cmp dword [rsp + 64], 1
    ja .bad
    test ecx, ecx
    jz .bad
    cmp ecx, 1024
    ja .bad
    cmp r14d, 1
    jne .intr_interval
    cmp ecx, 64
    ja .bad
.intr_interval:
    cmp byte [rbx + 6], 0
    je .bad
    cmp r14d, 1
    je .geometry
    cmp byte [rbx + 6], 16
    ja .bad
    jmp .geometry
.bulk:
    cmp byte [rbx + 6], 0
    jne .bad
    cmp r14d, 1
    jne .high
    cmp ecx, 8
    je .bulk_size
    cmp ecx, 16
    je .bulk_size
    cmp ecx, 32
    je .bulk_size
    cmp ecx, 64
    jne .bad
    jmp .bulk_size
.high:
    cmp r14d, 3
    jne .super
    cmp ecx, 512
    jne .bad
    jmp .bulk_size
.super:
    cmp ecx, 1024
    jne .bad
.bulk_size:
    cmp dword [rsp + 52], 4
    jne .selected_bulk
    cmp dl, 5
    je .geometry                    ; validate aux descriptor, never select
.selected_bulk:
    test dl, 0x80
    jz .out_ep
    cmp byte [rsp + 10], 0
    jne .bad
    mov [rsp + 10], dl
    mov [rsp + 12], cx
    lea rdi, [rsp + 16]
    mov dword [rsp + 72], 32
    jmp .copy_ep
.out_ep:
    cmp byte [rsp + 11], 0
    jne .bad
    mov [rsp + 11], dl
    mov [rsp + 14], cx
    lea rdi, [rsp + 24]
    mov dword [rsp + 72], 40
.copy_ep:
    mov eax, [rbx]
    mov [rdi], eax
    mov ax, [rbx + 4]
    mov [rdi + 4], ax
    mov al, [rbx + 6]
    mov [rdi + 6], al
.geometry:
    cmp r14d, 4
    jb .next
    mov dword [rsp + 68], 1
    jmp .next
.companion:
    cmp dword [rsp + 68], 1
    jne .bad
    cmp ebp, 6
    jne .bad
    cmp byte [rbx + 2], 15
    ja .bad
    cmp byte [rbx + 3], 0
    jne .bad
    movzx eax, word [rbx + 4]
    cmp dword [rsp + 80], 2
    jne .intr_ss
    test eax, eax
    jnz .bad
    jmp .copy_ss
.intr_ss:
    test eax, eax
    jnz .intr_ss_nonzero
    cmp dword [rsp + 52], 4
    jne .bad
    cmp dword [rsp + 84], 16
    jne .bad
    cmp dword [rsp + 88], 11
    jne .bad
    cmp byte [rbx + 2], 0
    jne .bad
    jmp .copy_ss
.intr_ss_nonzero:
    movzx edx, byte [rbx + 2]
    inc edx
    imul edx, [rsp + 84]
    cmp eax, edx
    ja .bad
.copy_ss:
    mov edx, [rsp + 72]
    test edx, edx
    jz .ss_done
    mov eax, [rbx]
    mov [rsp + rdx], eax
    mov ax, [rbx + 4]
    mov [rsp + rdx + 4], ax
.ss_done:
    mov dword [rsp + 68], 0
.next:
    add rbx, rbp
    jmp .row
.done:
    cmp dword [rsp + 68], 0
    jne .bad
    cmp dword [rsp + 48], 1
    jne .bad
    mov eax, [rsp + 52]
    cmp [rsp + 56], eax
    jne .bad
    cmp byte [rsp + 10], 0
    je .bad
    cmp byte [rsp + 11], 0
    je .bad
    mov rsi, rsp
    mov rdi, r13
    mov ecx, 48 / 8
    rep movsq
    mov eax, 1
    jmp .out
.bad:
    xor eax, eax
.out:
    add rsp, 104
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
