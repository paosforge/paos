;; MODULE hv/a1_transaction
;; LAYER 5
;; EXPORTS nd_a1_transaction_freeze, nd_a1_transaction_check
;; IMPORTS hv/driver_domain, hv/a1_policy, hv/a1_service_selection, core/lib/sha256
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Held original START evidence, not a reset/DMA grant. A1TX/880:
; 0 magic4/version2/size2; 8 generation8; 16 attempt8; 24 nonce17; 41 zero7;
; 48 profileSHA32; 80 policySHA32; 112 kernelSHA32; 144 initrdSHA32;
; 176 A1NSSHA32; 208 selectionSHA32 (zero for old network_guest selector);
; 240 requester_count4=1; 244 requester BDF4; 248 segment2=0; 250 zero6;
; 256 kernel_bytes8; 264 initrd_bytes8; 272 original A1NS608.
; Payload hashes/lengths are the exact signed pins; loader validation remains
; responsible for checking the actual loaded bytes. No readiness is inferred.
; Current A1 rejects requester aliases, so the set is precisely the selected
; endpoint. Shared/protected host peers stay in A1NS, never in this guest set.

nd_a1_transaction_freeze:
    lea rdi,[rel nd_a1_transaction]
    jmp nd_a1_transaction_make

nd_a1_transaction_check:
    push rbx
    lea rdi,[rel nd_a1_transaction_check_bytes]
    call nd_a1_transaction_make
    test eax,eax
    jnz .out
    lea rdi,[rel nd_a1_transaction]
    lea rsi,[rel nd_a1_transaction_check_bytes]
    mov ecx,110
    cld
    repe cmpsq
    mov eax,43                     ; existing A1N_E_CHANGED
    jne .out
    xor eax,eax
.out:
    pop rbx
    ret

; Private builder from native original custody only. Output cleared on error.
nd_a1_transaction_make:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    xor eax,eax
    mov ecx,110
    cld
    rep stosq
%ifdef PAOS_DRIVER_DOMAIN_PROFILE_INC
    cmp dword [rel nd_mode],1
    jne .bad
    cmp qword [rel nd_generation],0
    je .bad
    cmp qword [rel nd_attempt],0
    je .bad
%ifdef PAOS_A1_SERVICE_SELECTION_INC
    cmp dword [rel a1_service_state],1
    jne .bad
    mov eax,[rel nd_bdf]
    cmp eax,[rel a1_service_guest]
    jne .bad
    cmp eax,[rel a1_service_policy+48]
    jne .bad
%endif
    lea rdi,[rel nd_nonce]
    call nd_nonce_valid
    test eax,eax
    jz .bad
    lea rdi,[rel a1_policy_network]
    mov esi,312
    mov rdx,[rel nd_profile]
    mov ecx,280
    call a1_policy_check
    test eax,eax
    jnz .bad
    lea r12,[rel nd_a1_original]
    cmp dword [r12],'A1NS'
    jne .bad
    cmp dword [r12+4],(608<<16)|1
    jne .bad
    cmp dword [r12+596],1
    jne .bad
    cmp dword [r12+48],0            ; any native claim of guest refuses
    jne .bad
    mov eax,[r12+8]
    cmp eax,0xffff
    ja .bad
    cmp eax,[rel nd_bdf]
    jne .bad
    ; Explicit requester comes from the original common record, not every
    ; member of the shared physical group. No segment/alias truncation.
    movzx ecx,byte [r12+324]
    cmp cl,[r12+323]
    jae .bad
    cmp byte [r12+323],32
    ja .bad
    lea r13,[r12+rcx*8+336]
    cmp word [r13],0
    jne .bad
    movzx ecx,byte [r13+2]         ; DA stores bus,devfn bytes, not LE BDF
    shl ecx,8
    movzx edx,byte [r13+3]
    or ecx,edx
    cmp eax,ecx
    jne .bad
    cmp byte [r13+5],0             ; endpoint, not bridge
    jne .bad
    cmp byte [r13+6],1             ; DMA, no RMRR/protected/alias
    jne .bad
    mov [rbx+244],eax
    mov dword [rbx+240],1
    mov rax,[rel nd_generation]
    mov [rbx+8],rax
    mov rax,[rel nd_attempt]
    mov [rbx+16],rax
    lea rdi,[rbx+24]
    lea rsi,[rel nd_nonce]
    mov ecx,17
    rep movsb
    lea rdi,[rbx+272]
    mov rsi,r12
    mov ecx,76
    rep movsq
    lea rdi,[rbx+48]
    mov rsi,[rel nd_profile]
    mov edx,280
    call sha256_hash
    test eax,eax
    jnz .bad
    lea rdi,[rbx+80]
    lea rsi,[rel a1_policy_network]
    mov edx,312
    call sha256_hash
    test eax,eax
    jnz .bad
    lea rdi,[rbx+176]
    mov rsi,r12
    mov edx,608
    call sha256_hash
    test eax,eax
    jnz .bad
%ifdef PAOS_A1_SERVICE_SELECTION_INC
    lea rdi,[rbx+208]
    lea rsi,[rel a1_service_policy]
    mov edx,96
    call sha256_hash
    test eax,eax
    jnz .bad
%endif
    ; Network service has exactly one kernel and one initramfs. Do not silently
    ; pick the first dependency or confuse the two signed artifact pins.
    mov r12,[rel nd_profile]
    cmp byte [r12+34],2
    jne .bad
    add r12,56
    xor r13d,r13d
.dep:
    movzx eax,byte [r12]
    cmp eax,1
    je .kernel
    cmp eax,2
    jne .bad
    test r13d,2
    jnz .bad
    or r13d,2
    lea rdi,[rbx+144]
    mov rax,[r12+16]
    mov [rbx+264],rax
    jmp .pin
.kernel:
    test r13d,1
    jnz .bad
    or r13d,1
    lea rdi,[rbx+112]
    mov rax,[r12+16]
    mov [rbx+256],rax
.pin:
    lea rsi,[r12+24]
    mov ecx,4
    rep movsq
    add r12,56
    cmp r13d,3
    jne .dep
    mov dword [rbx+4],(880<<16)|1
    mov dword [rbx],'A1TX'        ; complete publication last
    xor eax,eax
    jmp .out
%endif
.bad:
    mov rdi,rbx
    xor eax,eax
    mov ecx,110
    rep stosq
    mov eax,43
.out:
    pop r13
    pop r12
    pop rbx
    ret

%include "core/abi/wdata.inc"
%macro WDATA_a1_transaction 0
align 16
nd_a1_transaction: times 880 db 0
nd_a1_transaction_check_bytes: times 880 db 0
%endmacro
WDATA_DEFER WDATA_a1_transaction
