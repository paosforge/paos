; Image workers have a single, fixed cooperative owner. Standalone synchronous
; codec consumers retain their ordinary ABI. The live image owner enables these
; hooks only together with exclusive codec-state ownership and private scratch.
%ifndef PAOS_IMG_COLD_HOOKS_INC
%define PAOS_IMG_COLD_HOOKS_INC 1
%macro IMG_COLD_STEP 0
%ifdef PAOS_IMG_COLD_WORK
    call img_cold_checkpoint
%endif
%endmacro
%macro IMG_COLD_MEMORY 1
%ifdef PAOS_IMG_COLD_WORK
    call img_cold_%1
%else
    rep %1
%endif
%endmacro
%macro IMG_COLD_DIGEST 0
%ifdef PAOS_IMG_COLD_WORK
    call img_cold_hash
%else
    call sha256_hash
%endif
%endmacro
%macro IMG_COLD_CRC 0
%ifdef PAOS_IMG_COLD_WORK
    call img_cold_crc
%else
    call hotpatch_crc32
%endif
%endmacro
%macro IMG_COLD_FS_CALL 1
%ifdef PAOS_IMG_COLD_FAT
    call img_cold_fat_begin
    jc %%refused
    call %1
    call img_cold_fat_end
    jmp %%done
%%refused:
    mov rax,-1
%%done:
%else
    call %1
%endif
%endmacro
%macro IMG_COLD_HEAP_NOW 0
%ifdef PAOS_IMG_COLD_WORK
    call img_cold_heap_now
%else
    mov rax,[rel heap_next]
%endif
%endmacro
%macro IMG_COLD_HEAP_ALLOC 0
%ifdef PAOS_IMG_COLD_WORK
    call img_cold_heap_alloc
%else
    call kmalloc
%endif
%endmacro
; The static codec workspace belongs to the suspended worker until it retires.
; An ordinary caller cannot probe, decode or clear it between idle turns.
; These guards do not yield or poll. The normal synchronous build is unchanged.
%macro IMG_COLD_BUSY_JUMP 1
%ifdef PAOS_IMG_COLD_WORK
    pushfq
    cmp byte [rel img_cold_pending],0
    je %%free
    cmp byte [rel img_cold_running],1
    je %%free
    popfq
    jmp %1
%%free:
    popfq
%endif
%endmacro
%macro IMG_COLD_PUBLIC_GUARD 0
%ifdef PAOS_IMG_COLD_WORK
    IMG_COLD_BUSY_JUMP %%busy
    jmp %%free
%%busy:
    mov eax,IMG_E_OOM
    xor ebx,ebx
    xor ecx,ecx
    xor edx,edx
    xor r8d,r8d
    cld
    ret
%%free:
%endif
%endmacro
%macro IMG_COLD_OWNER_ONLY 0
%ifdef PAOS_IMG_COLD_WORK
    IMG_COLD_BUSY_JUMP %%busy
    jmp %%free
%%busy:
    ret
%%free:
%endif
%endmacro
%endif
