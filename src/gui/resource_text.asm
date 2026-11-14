;; MODULE gui/resource_text
;; LAYER 6
;; EXPORTS res_catalog_load, res_map_load, res_text_bind, res_text
;; IMPORTS core/localization, core/lib/mem, gui/lang_prefs
;; CAPS
;; OWNER rc-codex-relops
;; CONTEXT: bsp_only
; RCQ-38 S1 cstr adapter per rc-input00:47:30. Standalone, NOwidget wiring.
; Private runtime context88 bytes: verified mapped-image base qword@0,
; catalog view32@8, map view32@40, owned8193-byte output buffer pointer@72,
; output capacity u32@80=8193, reserved u32@84=0. Context/buffers are allocated
; ONCE inside the future fixed resource arena, explicitly initialized, immutable
; after bind except the output buffer. Never construct this from resource bytes.

; RDI pack, ESI bytes, RDX trusted expectations, RCX private runtime context.
; -> EAX0 success,-1 unavailable. Core clears view on failure.
res_catalog_load:
    add rcx, 8
    sub rsp, 8
    call l10n_catalog_validate
    add rsp, 8
    dec eax
    ret

; Same ABI for PRVA + trusted image/map context.
res_map_load:
    add rcx, 40
    sub rsp, 8
    call l10n_map_validate
    add rsp, 8
    dec eax
    ret

; RDI private runtime context/0 ->0 bound/unbound,-1 unavailable.
; Failed replacement unbinds first; no stale context can survive it.
res_text_bind:
    mov qword [rel res_text_context], 0
    test rdi, rdi
    jz .yes
    cmp qword [rdi], 0
    je .bad
    cmp dword [rdi+8+24], 1
    jne .bad
    cmp dword [rdi+40+24], 1
    jne .bad
    cmp qword [rdi+72], 0
    je .bad
    cmp dword [rdi+80], 8193
    jne .bad
    cmp dword [rdi+84], 0
    jne .bad
    mov [rel res_text_context], rdi
.yes:
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

; RSI original native English cstr -> RSI display cstr. EAX1 translated/0 native.
; Bounded translation is copied and NUL-terminated; original pointer is NEVER
; scanned. The caller consumes/copies the transient output before the next call.
; Native UTF16 callsites use the explicit-length core API, not this cstr adapter.
res_text:
    push rbx
    push r12
    push r13
    mov r12, rsi
    mov r13, [rel res_text_context]
    test r13, r13
    jz .fallback
    cmp dword [r13+8+24], 1
    jne .fallback
    cmp dword [r13+40+24], 1
    jne .fallback
    call lang_prefs_get
    test eax, eax
    jz .fallback
    cmp eax, [r13+8+16]
    jne .fallback                       ; keep saved choice; wrong pack unusable
    mov rax, r12
    sub rax, [r13]
    jc .fallback
    mov edx, 0xffffffff
    cmp rax, rdx
    ja .fallback
    mov ebx, eax
    mov r9, [r13+40]
    mov r10d, [r13+40+12]
    xor ecx, ecx
.search:
    cmp ecx, r10d
    jae .fallback
    lea edx, [rcx+r10]
    shr edx, 1
    mov eax, edx
    shl rax, 4
    lea rax, [r9+rax+96]
    cmp ebx, [rax]
    je .found
    jb .lower
    lea ecx, [rdx+1]
    jmp .search
.lower:
    mov r10d, edx
    jmp .search
.found:
    cmp dword [rax+12], 0
    jne .fallback
    mov ecx, [rax+8]
    lea rdi, [r13+8]
    lea rsi, [r13+40]
    mov rdx, r12
    xor r8d, r8d
    mov r9, [r13]
    call l10n_resolve
    test r8d, r8d
    jz .fallback
    cmp edx, 8192
    ja .fallback
    cmp edx, [r13+80]
    jae .fallback
    mov rbx, [r13+72]
    mov r12d, edx
    mov rdi, rbx
    mov rsi, rax
    call memcpy
    mov byte [rbx+r12], 0
    mov rsi, rbx
    mov eax, 1
    jmp .out
.fallback:
    mov rsi, r12
    xor eax, eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

%include "core/abi/wdata.inc"
%macro WDATA_gui_resource_text 0
align 8, db 0
res_text_context: dq 0
%endmacro
WDATA_DEFER WDATA_gui_resource_text
