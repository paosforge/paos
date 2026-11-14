;; MODULE fs/app_store_data
;; LAYER 4
;; EXPORTS app_store_data_bind, app_store_data_read
;; IMPORTS fs/data_config_provider, fs/data_config_authority, core/heap, core/lib/mem
;; CAPS
;; OWNER saga:fs_wave
;; CONTEXT: bsp_only
; Fixed app record transport. This leaf does not authenticate or parse a catalog.
; All pointers are trusted native private buffers; calls serialize on the BSP.
APP_STORE_DATA_MAX equ 1024 * 1024

; RDI=out112 -> EAX1 bound /0 refused. Existing unique adopted DATA role only.
app_store_data_bind:
    call data_config_bind_provisioned
    test rax, rax
    setz al
    movzx eax, al
    ret

; RDI=token112, RSI=dst, RDX=capacity1..1MiB -> exact length /-4 absent /-1.
; Negative results leave dst unchanged, including partial IO or stale final read.
; One reusable private staging allocation; no per-read bump allocation leak.
app_store_data_read:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    mov rbx, rdx
    test r12, r12
    jz .no
    test r13, r13
    jz .no
    test rbx, rbx
    jz .no
    cmp rbx, APP_STORE_DATA_MAX
    ja .no
    mov al, 1
    xchg al, [rel asd_read_active]
    test al, al
    jnz .no
    cmp qword [rel asd_read_buffer], 0
    jne .allocated
    mov edi, APP_STORE_DATA_MAX
    call kmalloc
    test rax, rax
    jz .failed
    mov [rel asd_read_buffer], rax
.allocated:
    mov rdi, r12
    lea rsi, [rel asd_name]
    mov rdx, [rel asd_read_buffer]
    mov rcx, rbx
    call data_config_read
    test rax, rax
    js .out_active
    mov rbx, rax
    mov rdi, r13
    mov rsi, [rel asd_read_buffer]
    mov rdx, rbx
    call memcpy
    mov rax, rbx
.out_active:
    mov byte [rel asd_read_active], 0
    jmp .out
.failed:
    mov byte [rel asd_read_active], 0
.no:
    mov rax, -1
.out:
    pop r13
    pop r12
    pop rbx
    ret

asd_name: db 'PAOSAPPSBIN'
%include "core/abi/wdata.inc"
%macro WDATA_BSS_fs_app_store_data 0
alignb 8
asd_read_buffer: resq 1
asd_read_active: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_app_store_data
