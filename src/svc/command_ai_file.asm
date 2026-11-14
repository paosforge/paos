;; MODULE svc/command_ai_file
;; LAYER 5
;; EXPORTS command_ai_file_command
;; IMPORTS svc/command, svc/command_auth, svc/command_aihook, svc/command_card, sec/principal, fs/vfs, security/sensitive_classifier, core/lib/mem
;; CAPS PMCAP_COMPUTE
;; OWNER saga:agent_privacy
;; CONTEXT: bsp_only
; MODELRUN ADVISEFILE <registered-verb> <VFS-path>.
; The existing MODELRUN registry route owns ingress/authentication/redaction.
; This handler independently requires its actual OWNER ticket and compute cap.
; It reads the selected VFS through the installed path API (no text fixture or
; model-ready override). The proposal verb comes from the typed caller, never
; the file. Text and PII spans are bounded, private scratch and wiped on exit.
; The native producer taints ADVISOR before the first file read. PII detection
; is optional advice only: absent/wrong/malformed results never grant authority.
; Actual file bytes/length reach the typed advisory API. Its fixed FILE reason
; and ADVISOR principal survive into the native audit/Guardian refusal source.
; There is no LLM inference or browser-handover claim. No command is executed.
%include "core/abi/wdata.inc"

AIF_TEXT_CAP equ 4096
AIF_PATH_CAP equ 255
AIF_VERB_CAP equ 31

; RDI=req, RSI=rsp, RDX=suffix after exact "ADVISEFILE ".
command_ai_file_command:
    call cmd_handler_prologue
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov ebp,CMDE_AUTHDENY
    call command_auth_ticket_owner
    test eax,eax
    jz .done
    mov rdi,[r12+REQ_PRINCIPAL]
    call principal_capabilities
    test rax,PMCAP_COMPUTE
    jz .done
    mov ebp,CMDE_BADARG
    test r14,r14
    jz .done
    xor ecx,ecx
.verb:
    mov al,[r14+rcx]
    cmp al,' '
    je .verb_end
    cmp al,'!'
    jb .done
    cmp ecx,AIF_VERB_CAP
    jae .done
    lea rdx,[rel aif_verb]
    mov [rdx+rcx],al
    inc ecx
    jmp .verb
.verb_end:
    test ecx,ecx
    jz .done
    lea rax,[rel aif_verb]
    mov byte [rax+rcx],0
    lea r14,[r14+rcx+1]
    lea rdi,[rel aif_verb]
    call command_lookup
    cmp eax,-1
    je .done
    mov rbx,rax
    xor ecx,ecx
.path:
    mov al,[r14+rcx]
    test al,al
    jz .path_end
    cmp al,'!'
    jb .done                          ; one bounded path, no extra arguments
    cmp ecx,AIF_PATH_CAP
    jae .done
    lea rdx,[rel aif_path]
    mov [rdx+rcx],al
    inc ecx
    jmp .path
.path_end:
    test ecx,ecx
    jz .done
    lea rax,[rel aif_path]
    mov byte [rax+rcx],0
    mov [rel aif_path_len],ecx
    mov r15d,[rel vfs_disk_handle]     ; one selected mount for this whole read
    mov edi,PRIN_ADVISOR
    call ai_web_taint_set             ; before untrusted bytes enter the consumer
    ; Installed path backends use exact bounded ranges, not POSIX EOF probes.
    ; Establish the actual size before reading; missing/oversize/directory fail.
    mov edi,r15d
    lea rsi,[rel aif_path]
    mov edx,[rel aif_path_len]
    lea rcx,[rel aif_stat]
    call vfs_stat_path
    test rax,rax
    jnz .done
    test dword [rel aif_stat+fs_stat.reserved],1
    jnz .done
    cmp qword [rel aif_stat+fs_stat.size],AIF_TEXT_CAP
    ja .done
    xor r14d,r14d
.read:
    cmp r14,[rel aif_stat+fs_stat.size]
    je .inspect
    mov edi,r15d
    lea rsi,[rel aif_path]
    mov edx,[rel aif_path_len]
    mov rcx,r14
    lea r8,[rel aif_text]
    add r8,r14
    mov r9,[rel aif_stat+fs_stat.size]
    sub r9,r14
    call vfs_read_at_path
    test rax,rax
    js .done
    test rax,rax
    jz .done                          ; early EOF is incomplete, never advice
    mov rcx,[rel aif_stat+fs_stat.size]
    sub rcx,r14
    cmp rax,rcx
    ja .done                          ; invalid backend byte count
    add r14,rax
    jmp .read                         ; accept valid short reads to stat size
.inspect:
    ; The real bounded PII classifier inspects these exact bytes. Its status
    ; and spans are never used as an authority predicate, even on failure.
    lea rdi,[rel aif_text]
    mov rsi,r14
    lea rdx,[rel aif_spans]
    mov ecx,SC_MATCH_CAP
    xor r8d,r8d
    xor r9d,r9d
    call sensitive_classify
    mov rdi,rbx
    lea rsi,[rel aif_text]
    mov rdx,r14
    call command_aihook_submit_file_advisory
    mov ebp,edx
.done:
    ; No raw file bytes or detected values enter command replies/audit.
    ; The normal UDP envelope may echo caller-supplied bounded path metadata.
    lea rdi,[rel aif_text]
    xor esi,esi
    mov edx,AIF_TEXT_CAP+1
    call memset
    lea rdi,[rel aif_spans]
    xor esi,esi
    mov edx,SC_MATCH_CAP*SC_SPAN_SIZE
    call memset
    lea rdi,[rel aif_path]
    xor esi,esi
    mov edx,AIF_PATH_CAP+1
    call memset
    lea rdi,[rel aif_verb]
    xor esi,esi
    mov edx,AIF_VERB_CAP+1
    call memset
    lea rdi,[rel aif_stat]
    xor esi,esi
    mov edx,fs_stat_size
    call memset
    mov dword [rel aif_path_len],0
    mov [r13+RSP_CODE],rbp
    mov qword [r13+RSP_VAL],0
    mov qword [r13+RSP_ACCEPTED],0
    mov qword [r13+RSP_HINT],0
    mov rax,rbp
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

%macro WDATA_svc_command_ai_file_0 0
align 8
aif_stat: times fs_stat_size db 0
aif_text: times AIF_TEXT_CAP+1 db 0
aif_spans: times SC_MATCH_CAP*SC_SPAN_SIZE db 0
aif_path: times AIF_PATH_CAP+1 db 0
aif_verb: times AIF_VERB_CAP+1 db 0
aif_path_len: dd 0
%endmacro
WDATA_DEFER WDATA_svc_command_ai_file_0
