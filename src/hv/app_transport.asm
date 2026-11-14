;; MODULE hv/app_transport
;; LAYER 5
;; PURPOSE Closed app-vCPU PIO into its actual prebound typed WAIT principal.
;; EXPORTS guest_transport_app_pio, guest_transport_app_retire, guest_transport_app_init
;; IMPORTS hv/guest_request, hv/guest_transport, hv/app_vm, hv/chat_transport, core/smp
;; CAPS
;; OWNER saga:guest_transport
; Codex / rc-live-claude. Stopped-vCPU cooperative BSP only; no yield or guest
; pointer. Ports are an endpoint, NOT process/bundle/grant authentication.
GAT_CONTROL equ 0x5040
GAT_DATA equ 0x5044
GAT_MAGIC equ 0x31545747                ; GWT1
GAT_FRAME_BYTES equ 40
GAT_REPLY_BYTES equ 128

guest_transport_app_init:
    lea rdi,[rel gat_retire_all]
    jmp guest_request_configure_transport

; One configured adapter callback retires both producers. Neither leaf calls
; the adapter; all registers and flags survive. Install once at native init,
; after driver transport init and before the first app prepare/binding.
gat_retire_all:
    call chat_vm_retire
    call app_widget_transport_retire
    call guest_transport_retire
    jmp guest_transport_app_retire

; Register-preserving native retirement. Keep nonwrapping adapter serial floor;
; guest reset/config/session retirement cannot resurrect this binding.
guest_transport_app_retire:
    pushfq
    push rax
    push rcx
    push rdi
    mov byte [rel gat_bound],0
    mov byte [rel gat_pending],0
    mov byte [rel gat_poll_mode],0
    mov dword [rel gat_poll_status],0
    push rdx
    lea rdi,[rel gat_binding]
    xor eax,eax
    mov ecx,12
    cld
    rep stosq                      ; binding + candidate, native pointers erased
    pop rdx
    mov dword [rel gat_count],0
    mov dword [rel gat_read],GAT_REPLY_BYTES
    mov byte [rel gat_receiving],0
    lea rdi,[rel gat_frame]
    xor eax,eax
    mov ecx,(GAT_FRAME_BYTES+48+GAT_REPLY_BYTES)/8
    cld
    rep stosq
    pop rdi
    pop rcx
    pop rax
    popfq
    ret

; EDI=VMX-normalized PIO qualification from actual app closed exit only,
; ESI=guest EAX -> EAX 1 claimed/0 unrelated, EDX bounded IN dword.
; VM-owned app devices dispatch copies only the width-correct IN result.
; Driver PIO remains on its separate unchanged producer; no app identity switch.
guest_transport_app_pio:
    push rbx
    push r12
    push r13
    mov ebx,edi
    mov r12d,esi
    mov r13d,edi
    shr r13d,16
    cmp r13d,GAT_CONTROL
    je .ours
    cmp r13d,GAT_DATA
    jne .unrelated
.ours:
    ; No AP/deferred-vCPU executor, interrupt or reentrant producer.
    cmp dword [rel vcb_handoff_active],0
    jne .refuse
    cmp byte [rel gat_busy],0
    jne .refuse
    call smp_current_logical
    test eax,eax
    jnz .refuse
    mov eax,ebx
    and eax,0xffff
    and eax,~0x40                    ; immediate/DX addressing immaterial
    cmp eax,3                       ; OUT dword, neither REP nor string
    je .width_ok
    cmp eax,11                      ; IN dword
    jne .invalidate
.width_ok:
    call gat_lifetime
    test eax,eax
    jz .invalidate
    test ebx,8
    jnz .input
    mov byte [rel gat_poll_mode],0
    cmp r13d,GAT_CONTROL
    jne .out_data
    cmp r12d,3
    je .poll
    cmp byte [rel gat_pending],0
    jne .refuse                     ; handshake cannot abandon original ASK
    cmp r12d,0
    je .clear
    cmp r12d,GAT_FRAME_BYTES
    je .begin
    cmp r12d,1
    je .submit
    cmp r12d,2
    je .sequence
    jmp .invalidate
.poll:
    mov byte [rel gat_poll_mode],1
    mov dword [rel gat_poll_status],0
    cmp dword [rel gat_read],0
    je .poll_whole
    cmp dword [rel gat_read],GAT_REPLY_BYTES
    jne .claimed                    ; never replace a partially read frame
.poll_whole:
    call gat_refresh
    movzx eax,byte [rel gat_pending]
    mov [rel gat_poll_status],eax
    cmp eax,2
    jne .claimed
    mov dword [rel gat_read],0
    jmp .claimed
.clear:
    call gat_clear
    jmp .claimed
.begin:
    call gat_clear
    mov byte [rel gat_receiving],1
    jmp .claimed
.sequence:
    call gat_clear
    mov rax,[rel gat_last_seq]
    mov [rel gat_reply+8],rax
    mov dword [rel gat_read],0
    jmp .claimed
.out_data:
    cmp byte [rel gat_pending],0
    jne .refuse
.data:
    cmp byte [rel gat_receiving],1
    jne .invalidate
    mov eax,[rel gat_count]
    cmp eax,GAT_FRAME_BYTES
    jae .invalidate
    lea rdx,[rel gat_frame]
    mov [rdx+rax],r12d
    add dword [rel gat_count],4
    jmp .claimed
.submit:
    cmp byte [rel gat_receiving],1
    jne .invalidate
    mov byte [rel gat_receiving],0
    cmp dword [rel gat_count],GAT_FRAME_BYTES
    jne .invalidate
    cmp dword [rel gat_frame],1
    jne .invalidate
    mov eax,[rel gat_frame+4]
    dec eax
    cmp eax,3
    ja .invalidate
    mov rax,[rel gat_frame+8]
    test rax,rax
    jz .invalidate
    cmp rax,[rel gat_last_seq]
    jbe .invalidate
    mov [rel gat_last_seq],rax       ; burn before adapter, including DENY
    mov [rel gat_reply+8],rax
    cmp qword [rel gat_frame+16],0
    je .invalidate
    cmp dword [rel gat_frame+4],2
    je .check_begin
    cmp qword [rel gat_frame+32],0
    jne .invalidate
    cmp dword [rel gat_frame+4],1
    jne .check_token
    cmp qword [rel gat_frame+24],0
    jne .invalidate
    jmp .dispatch
.check_token:
    cmp qword [rel gat_frame+24],0
    je .invalidate
    jmp .dispatch
.check_begin:
    cmp qword [rel gat_frame+32],5000
    ja .invalidate
.dispatch:
    mov byte [rel gat_busy],1
    mov r13,[rel gat_frame+8]         ; keep exact sequence across native retirement
    mov rdi,[rel gat_binding+16]      ; native endpoint, never guest bytes
    mov esi,[rel gat_start]               ; captured consumed START
    lea rdx,[rel gat_frame]               ; private complete native snapshot
    mov ecx,GAT_FRAME_BYTES
    lea r8,[rel gat_response]             ; private envelope; NEVER put on wire
    call guest_request_submit
    cmp byte [rel gat_bound],1
    jne .no_result
    mov eax,[rel gat_response+RSP_CODE]
    mov [rel gat_reply+4],eax
    test eax,eax
    jz .copy_result
    cmp eax,CMDE_AUTHDENY
    jne .redact
    mov rdi,[rel gat_binding+16]
    mov esi,[rel gat_start]
    mov rdx,r13
    call guest_request_completion_state
    cmp eax,1
    jne .redact
    mov byte [rel gat_pending],1      ; exact original, no resubmission
    jmp .redact
.copy_result:
    mov rdi,[rel gat_binding+16]
    mov esi,[rel gat_start]
    mov rdx,r13
    lea rcx,[rel gat_reply]
    mov r8d,GAT_REPLY_BYTES
    call guest_request_result_copy       ; approved fixed wire snapshot, one shot
    test eax,eax
    jnz .no_result
    cmp byte [rel gat_bound],1
    jne .no_result
    jmp .ready
.no_result:
    mov dword [rel gat_reply],1
    mov dword [rel gat_reply+4],CMDE_AUTHDENY
.redact:
    lea rdi,[rel gat_reply+16]
    xor eax,eax
    mov ecx,(GAT_REPLY_BYTES-16)/8
    rep stosq
.ready:
    mov dword [rel gat_reply],1       ; retain exact adapter/result code
    mov [rel gat_reply+8],r13
    mov byte [rel gat_busy],0
    mov dword [rel gat_read],0
    jmp .claimed
.input:
    cmp r13d,GAT_CONTROL
    jne .read
    mov edx,GAT_MAGIC
    cmp byte [rel gat_poll_mode],1
    jne .out_claimed
    mov edx,[rel gat_poll_status]
    mov byte [rel gat_poll_mode],0    ; next client sees the ordinary magic
    jmp .out_claimed
.read:
    cmp dword [rel gat_read],0
    jne .read_word
    call gat_refresh                ; approval before first read delivers original
.read_word:
    mov eax,[rel gat_read]
    cmp eax,GAT_REPLY_BYTES
    jae .refuse
    lea rdx,[rel gat_reply]
    mov edx,[rdx+rax]
    add dword [rel gat_read],4
    cmp dword [rel gat_read],GAT_REPLY_BYTES
    jne .out_claimed
    cmp byte [rel gat_pending],2
    jne .out_claimed
    mov byte [rel gat_pending],0      ; completed response delivered only once
    mov dword [rel gat_poll_status],0
    jmp .out_claimed
.invalidate:
    call gat_clear
    mov dword [rel gat_reply+4],CMDE_BADARG
    mov dword [rel gat_read],0
.refuse:
    mov edx,-1
    jmp .out_claimed
.claimed:
    xor edx,edx
.out_claimed:
    mov eax,1
    jmp .out
.unrelated:
    xor eax,eax
    xor edx,edx
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Actual closed app exit + readonly actual adapter binding on EVERY port access.
; Never call guest_request_bind: INPUT installed grants against the prebound
; identity before activation. Wire reset/handshake cannot retire those grants.
gat_lifetime:
    push rbx
    push r12
    sub rsp,8
    call app_vm_exit_endpoint
    test rax,rax
    jz .bad
    test edx,edx
    jz .bad
    mov rbx,rax
    mov r12d,edx
    mov rdi,rax
    mov esi,edx
    lea rdx,[rel gat_candidate]
    mov ecx,48
    call guest_request_binding_copy
    cmp eax,1
    jne .bad
    cmp [rel gat_candidate+16],rbx
    jne .bad
    cmp [rel gat_candidate+24],r12
    jne .bad
    cmp qword [rel gat_candidate],0
    je .bad
    cmp qword [rel gat_candidate+8],0
    je .bad
    cmp qword [rel gat_candidate+32],0
    je .bad
    cmp qword [rel gat_candidate+40],0
    je .bad
    cmp byte [rel gat_bound],1
    jne .new
    lea rsi,[rel gat_candidate]
    lea rdi,[rel gat_binding]
    mov ecx,6
    cld
    repe cmpsq
    jne .bad
    jmp .ok
.new:
    mov rax,[rel gat_candidate+8]
    cmp rax,[rel gat_seen_serial]
    jbe .bad                       ; same retired binding never reattaches
    mov [rel gat_seen_serial],rax
    lea rsi,[rel gat_candidate]
    lea rdi,[rel gat_binding]
    mov ecx,6
    cld
    rep movsq
    mov [rel gat_start],r12d
    mov qword [rel gat_last_seq],0
    mov byte [rel gat_bound],1
    call gat_clear
.ok:
    mov eax,1
    jmp .out
.bad:
    call guest_transport_app_retire
    xor eax,eax
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; Refresh only a complete original pending response at stopped-vCPU BSP.
; No blocking, submission, approval or effect. Actual native callbacks recheck
; binding/policy/expiry; successful copy consumes exactly that original result.
gat_refresh:
    cmp byte [rel gat_pending],1
    jne .out
    push r13
    mov byte [rel gat_busy],1
    mov r13,[rel gat_last_seq]
    mov rdi,[rel gat_binding+16]
    mov esi,[rel gat_start]
    mov rdx,r13
    call guest_request_completion_state
    cmp byte [rel gat_bound],1
    jne .retired
    cmp eax,1
    je .done
    cmp eax,2
    jne .denied
    mov rdi,[rel gat_binding+16]
    mov esi,[rel gat_start]
    mov rdx,r13
    lea rcx,[rel gat_reply]
    mov r8d,GAT_REPLY_BYTES
    call guest_request_result_copy
    test eax,eax
    jnz .denied
    cmp byte [rel gat_bound],1
    jne .retired
    cmp dword [rel gat_reply+4],0
    je .available
    lea rdi,[rel gat_reply+16]
    xor eax,eax
    mov ecx,(GAT_REPLY_BYTES-16)/8
    cld
    rep stosq                       ; exact nonzero code, no result body
    jmp .available
.denied:
    lea rdi,[rel gat_reply]
    xor eax,eax
    mov ecx,GAT_REPLY_BYTES/8
    cld
    rep stosq
    mov dword [rel gat_reply],1
    mov dword [rel gat_reply+4],CMDE_AUTHDENY
    mov [rel gat_reply+8],r13
.available:
    mov byte [rel gat_pending],2
    mov dword [rel gat_read],0
    jmp .done
.retired:
    mov byte [rel gat_pending],0
.done:
    mov byte [rel gat_busy],0
    pop r13
.out:
    ret

gat_clear:
    push rdi
    push rcx
    push rax
    lea rdi,[rel gat_frame]
    xor eax,eax
    mov ecx,(GAT_FRAME_BYTES+48+GAT_REPLY_BYTES)/8
    cld
    rep stosq
    mov dword [rel gat_reply],1
    mov dword [rel gat_count],0
    mov dword [rel gat_read],GAT_REPLY_BYTES
    mov byte [rel gat_receiving],0
    mov byte [rel gat_pending],0
    mov byte [rel gat_poll_mode],0
    mov dword [rel gat_poll_status],0
    pop rax
    pop rcx
    pop rdi
    ret

%include "core/abi/wdata.inc"
%macro WDATA_guest_transport_app 0
alignb 8
gat_start: resd 1
gat_count: resd 1
gat_read: resd 1
gat_bound: resb 1
gat_busy: resb 1
gat_receiving: resb 1
gat_pending: resb 1
gat_poll_mode: resb 1
alignb 4
gat_poll_status: resd 1
alignb 8
gat_seen_serial: resq 1
gat_binding: resq 6
gat_candidate: resq 6
gat_last_seq: resq 1
; Contiguous private buffers, zeroed together; no alignment gaps.
gat_frame: resb GAT_FRAME_BYTES
gat_response: resb 48
gat_reply: resb GAT_REPLY_BYTES
%endmacro
WDATA_BSS_DEFER WDATA_guest_transport_app
