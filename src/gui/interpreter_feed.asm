;; MODULE gui/interpreter_feed
;; LAYER 6
;; EXPORTS interpreter_ansi_feed, interpreter_vt_feed
;; IMPORTS hv/interpreter_execution, gui/ansi_interp, gui/vt/vt_engine
;; CAPS
;; OWNER saga:security
; Stack-owned phase pairing around the actual native parser. Original input
; and complete parser return state preserved; no interrupt exclusion while
; parsing. The public producer has no input/pointer fields.
%include "hv/interpreter_execution.inc"
%macro IPE_SAVE 0
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
%endmacro
%macro IPE_RESTORE 0
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
%endmacro
%macro IPE_FEED 2
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,IPE_FRAME
    mov r12,rsp
    mov [r12+608],rdi
    mov [r12+616],rsi
    mov [r12+624],rdx
    mov rdi,r12
    xor eax,eax
    mov ecx,IPE_PAIR/8
    cld
    rep stosq
    mov qword [r12+40],%1
    mov qword [r12+48],1
    mov rdi,r12
    xor esi,esi
    call interpreter_phase
    mov rdi,[r12+608]
    mov rsi,[r12+616]
    mov rdx,[r12+624]
    call %2                         ; actual existing parser, exactly once
    IPE_SAVE                        ; preserve its complete return state
    mov rax,[r12+40]
    mov [r12+IPE_PHASE+40],rax
    mov qword [r12+IPE_PHASE+48],2
    lea rdi,[r12+IPE_PHASE]
    mov rsi,r12
    call interpreter_phase
    mov qword [r12+8],1             ; completed feed AND return phase
    mov qword [r12+IPE_PHASE+8],1
    mov rdi,r12
    call interpreter_publish
    IPE_RESTORE
    lea rsp,[rsp+IPE_FRAME]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
%endmacro
interpreter_ansi_feed:
IPE_FEED 1,ansi_grid_feed
interpreter_vt_feed:
IPE_FEED 2,vt_feed
