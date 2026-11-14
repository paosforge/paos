;; MODULE fs/nvme_geometry_probe
;; LAYER 4
;; EXPORTS nvg_probe, nvg_probe_file, nvg_record
;; IMPORTS fs/blockdev, fs/storage_access, fs/fat32_probe_window, core/lib/sha256
;; CAPS
;; OWNER saga:storage
; Finite BSP-only native whole-block test. RDI=exact registered nvme dev*,
; RSI=count(1|2), RDX=fresh nonzero caller nonce. No arbitrary LBA or disk grant.
; Only GPT-free TEST_SCRATCH, current OWNER and ordinary request gate admit
; writes. All IO uses the class; no backend/vtable bypass or persistent grant.
; Refused DEGRADED namespaces exercise class read/write errors without a grant.
; RAX=0 complete,1 refused,2 observed failure; record384 retains every actual rc.
nvg_probe:
    xor r10d,r10d
    jmp nvg_probe_entry
nvg_probe_file:
    mov r10d,1
nvg_probe_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    lea rdi,[rel nvg_record]
    xor eax,eax
    mov ecx,384/8
    rep stosq
    mov rax,0x0000314f4547564e ; "NVGEO1\0\0"
    mov [rel nvg_record],rax
    mov dword [rel nvg_record+8],1
    mov dword [rel nvg_record+12],384
    mov [rel nvg_record+356],r10d
    mov qword [rel nvg_file_handle],0
    mov [rel nvg_record+16],r13
    mov qword [rel nvg_record+24],8
    mov [rel nvg_record+32],r12
    lea rdi,[rel nvg_record+80]
    mov rax,-2
    mov ecx,8
    rep stosq
    mov qword [rel nvg_record+336],-2
    mov qword [rel nvg_record+344],1
    cmp r10d,1
    je .has_device
    test rbx,rbx
    jz .refused
.has_device:
    cmp r12,1
    jb .refused
    cmp r12,2
    ja .refused
    test r13,r13
    jz .refused
    cmp dword [rel nvg_record+356],1
    jne .owner_check
    mov [rel nvg_record+352],ebx
.owner_check:
    call storage_access_request_owner
    cmp eax,1
    jne .refused
    cmp dword [rel nvg_record+356],1
    jne .actual_device
    mov eax,0xffffffff
    cmp rbx,rax
    jae .refused
    mov [rel nvg_record+352],ebx
    lea rdi,[rel nvg_initial]
    mov ecx,2048/8
    mov rax,r13
    rep stosq
    mov edi,ebx
    mov rsi,r13
    lea rdx,[rel nvg_initial]
    lea rcx,[rel nvg_file_descriptor]
    call fat32_probe_window_begin
    cmp rax,-3
    je .failed
    test rax,rax
    jz .refused
    cmp rax,0
    jl .refused
    mov [rel nvg_file_handle],rax
    mov rbx,[rel nvg_file_descriptor]
    mov rax,[rel nvg_file_descriptor+8]
    mov [rel nvg_record+360],rax
    inc rax
    mov [rel nvg_record+24],rax
    lea rsi,[rel nvg_file_descriptor+48]
    lea rdi,[rel nvg_record+368]
    mov ecx,11
    rep movsb
.actual_device:
    mov rdi,rbx
    call storage_access_vmd_member
    test eax,eax
    jnz .refused
    mov rbp,[rbx+dev.info]
    test rbp,rbp
    jz .refused
    mov eax,[rbx+dev.health]
    mov [rel nvg_record+56],eax
    mov rax,[rbp+blk_info.media_generation]
    mov [rel nvg_record+48],rax
    mov eax,[rbp+blk_info.logical_sector_bytes]
    mov [rel nvg_record+60],eax
    mov eax,[rbp+blk_info.physical_sector_bytes]
    mov [rel nvg_record+64],eax
    mov rax,[rbp+blk_info.capabilities]
    mov [rel nvg_record+72],rax
    ; Actual default, named and write-capability iteration selectors. Bits
    ; 0/1/2 record whether any shared filesystem/verb class selector offers it.
    call blk_select
    xor ecx,ecx
    cmp rax,rbx
    sete cl
    mov [rel nvg_record+68],ecx
    mov rdi,[rbx+dev.name]
    test rdi,rdi
    jz .iteration
    xor esi,esi
.name_length:
    cmp esi,64
    jae .failed
    cmp byte [rdi+rsi],0
    je .named
    inc esi
    jmp .name_length
.named:
    call blk_find_named
    cmp rax,rbx
    jne .iteration
    or dword [rel nvg_record+68],2
.iteration:
    xor r14d,r14d
    xor edi,edi
.iter_next:
    mov esi,BLKCAP_WRITE
    xor edx,edx
    call blk_iter_after
    test rax,rax
    jz .iter_done
    cmp rax,rbx
    jne .iter_continue
    or dword [rel nvg_record+68],4
.iter_continue:
    mov rdi,rax
    inc r14d
    cmp r14d,BLK_REGISTRY_LIMIT
    jb .iter_next
    jmp .failed
.iter_done:
    cmp dword [rbx+dev.health],HEALTH_DEGRADED
    je .degraded
    cmp dword [rbx+dev.health],HEALTH_OK
    jne .refused
    mov r14d,[rbp+blk_info.logical_sector_bytes]
    cmp r14d,512
    je .size
    cmp r14d,4096
    jne .refused
.size:
    mov rax,r12
    imul rax,r14
    mov [rel nvg_record+40],rax
    mov r15,rax
    mov rdi,rbx
    mov rsi,[rel nvg_record+24]
    dec rsi
    lea rdx,[r12+2]
    call blk_validate_range
    mov [rel nvg_record+80],rax
    test rax,rax
    jnz .failed
    cmp dword [rel nvg_record+356],1
    je .file_authorized
    ; A live GPT or non-QEMU physical disk cannot pass this raw test slice.
    mov rdi,rbx
    mov rsi,[rel nvg_record+24]
    mov rdx,r12
    call storage_access_classify
    cmp eax,SA_CLASS_TEST_SCRATCH
    jne .refused
    mov rdi,rbx
    mov rsi,[rel nvg_record+24]
    mov rdx,r12
    lea r8,[rel nvg_caller]
    call storage_access_require_request
    mov [rel nvg_record+88],rax
    test rax,rax
    jnz .refused
    jmp .buffers
.file_authorized:
    mov qword [rel nvg_record+88],0
.buffers:
    ; Separate guarded read buffers; exact tail immediately after valid bytes.
    lea rdi,[rel nvg_before_guard]
    mov ecx,(16384+32)/8
    mov rax,0xa5a5a5a5a5a5a5a5
    rep stosq
    lea rdi,[rel nvg_after_guard]
    mov ecx,(16384+32)/8
    rep stosq
    lea rdi,[rel nvg_expected_guard]
    mov ecx,(8192+32)/8
    rep stosq
    lea rdi,[rel nvg_expected]
    xor ecx,ecx
.pattern:
    mov rax,r13
    xor rax,rcx
    mov [rdi+rcx],rax
    add rcx,8
    cmp rcx,r15
    jb .pattern
    mov rdi,rbx
    mov rsi,[rel nvg_record+24]
    dec rsi
    lea rdx,[r12+2]
    lea rcx,[rel nvg_before]
    call nvg_read
    mov [rel nvg_record+96],rax
    test rax,rax
    jnz .failed
    mov rdi,rbx
    mov rsi,[rel nvg_record+24]
    mov rdx,r12
    lea rcx,[rel nvg_expected]
    call nvg_write
    mov [rel nvg_record+104],rax
    test rax,rax
    jnz .failed
    mov rdi,rbx
    call nvg_flush
    mov [rel nvg_record+112],rax
    test rax,rax
    jnz .failed
    mov rdi,rbx
    mov rsi,[rel nvg_record+24]
    dec rsi
    lea rdx,[r12+2]
    lea rcx,[rel nvg_after]
    call nvg_read
    mov [rel nvg_record+120],rax
    test rax,rax
    jnz .failed
    ; Deliberate overlength actual class calls, not a summary refusal flag.
    ; Both class and NVMe backend independently reject UINT64_MAX count before
    ; copying; selected throwaway window remains the only permitted write grant.
    mov rdi,rbx
    mov rsi,[rel nvg_record+24]
    mov rdx,-1
    lea rcx,[rel nvg_after]
    call nvg_read
    mov [rel nvg_record+128],rax
    test rax,rax
    jz .failed
    mov rdi,rbx
    mov rsi,[rel nvg_record+24]
    mov rdx,-1
    lea rcx,[rel nvg_expected]
    call nvg_write
    mov [rel nvg_record+136],rax
    test rax,rax
    jz .failed
    ; Six actual SHA256 digests. No nonce-only/partial-block equality.
    lea rdi,[rel nvg_record+144]
    lea rsi,[rel nvg_expected]
    mov rdx,r15
    call sha256_hash
    test rax,rax
    jnz .failed
    lea rdi,[rel nvg_record+176]
    lea rsi,[rel nvg_after]
    add rsi,r14
    mov rdx,r15
    call sha256_hash
    test rax,rax
    jnz .failed
    lea rdi,[rel nvg_record+208]
    lea rsi,[rel nvg_before]
    mov rdx,r14
    call sha256_hash
    test rax,rax
    jnz .failed
    lea rdi,[rel nvg_record+240]
    lea rsi,[rel nvg_after]
    mov rdx,r14
    call sha256_hash
    test rax,rax
    jnz .failed
    lea rdi,[rel nvg_record+272]
    lea rsi,[rel nvg_before]
    add rsi,r14
    add rsi,r15
    mov rdx,r14
    call sha256_hash
    test rax,rax
    jnz .failed
    lea rdi,[rel nvg_record+304]
    lea rsi,[rel nvg_after]
    add rsi,r14
    add rsi,r15
    mov rdx,r14
    call sha256_hash
    test rax,rax
    jnz .failed
    lea rsi,[rel nvg_record+144]
    lea rdi,[rel nvg_record+176]
    mov ecx,32
    repe cmpsb
    jne .failed
    lea rsi,[rel nvg_record+208]
    lea rdi,[rel nvg_record+240]
    mov ecx,32
    repe cmpsb
    jne .failed
    lea rsi,[rel nvg_record+272]
    lea rdi,[rel nvg_record+304]
    mov ecx,32
    repe cmpsb
    jne .failed
    lea rdi,[rel nvg_before_guard]
    lea rsi,[rel nvg_before]
    lea rdx,[r15+r14*2]
    call nvg_guard_check
    test eax,eax
    jnz .failed
    lea rdi,[rel nvg_after_guard]
    lea rsi,[rel nvg_after]
    lea rdx,[r15+r14*2]
    call nvg_guard_check
    test eax,eax
    jnz .failed
    lea rdi,[rel nvg_expected_guard]
    lea rsi,[rel nvg_expected]
    mov rdx,r15
    call nvg_guard_check
    mov [rel nvg_record+336],rax
    test eax,eax
    jnz .failed
    mov qword [rel nvg_record+344],0
    xor eax,eax
    jmp .out
.degraded:
    ; These fail at the class health gate; no storage grant, trace must show
    ; no actual device command. Fresh record distinguishes not-attempted -2.
    mov rdi,rbx
    mov rsi,[rel nvg_record+24]
    mov edx,1
    lea rcx,[rel nvg_after]
    call nvg_read
    mov [rel nvg_record+96],rax
    mov rdi,rbx
    mov rsi,[rel nvg_record+24]
    mov edx,1
    lea rcx,[rel nvg_expected]
    call nvg_write
    mov [rel nvg_record+104],rax
    cmp qword [rel nvg_record+96],0
    je .failed
    test rax,rax
    jz .failed
.refused:
    mov eax,1
    jmp .out
.failed:
    mov qword [rel nvg_record+344],2
    mov eax,2
.out:
    mov r12,rax
    mov rdi,[rel nvg_file_handle]
    test rdi,rdi
    jz .ended
    call fat32_probe_window_end
    test rax,rax
    jz .ended
    mov qword [rel nvg_record+344],2
    mov r12d,2
.ended:
    mov qword [rel nvg_file_handle],0
    mov rax,r12
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Shared raw/file operation adapters. File writes never use the raw grant.
nvg_read:
    cmp dword [rel nvg_record+356],1
    jne blk_read
    mov rdi,[rel nvg_file_handle]
    sub rsi,[rel nvg_record+360]
    jmp fat32_probe_window_read
nvg_write:
    cmp dword [rel nvg_record+356],1
    jne blk_write
    mov rdi,[rel nvg_file_handle]
    mov rsi,rdx
    mov rdx,rcx
    jmp fat32_probe_window_write
nvg_flush:
    cmp dword [rel nvg_record+356],1
    jne blk_flush
    mov rdi,[rel nvg_file_handle]
    jmp fat32_probe_window_flush

; RDI=16-byte head guard,RSI=payload,RDX=exact bytes. Return0 intact,1 changed.
nvg_guard_check:
    mov rax,0xa5a5a5a5a5a5a5a5
    cmp [rdi],rax
    jne .bad
    cmp [rdi+8],rax
    jne .bad
    cmp [rsi+rdx],rax
    jne .bad
    cmp [rsi+rdx+8],rax
    jne .bad
    xor eax,eax
    ret
.bad:
    mov eax,1
    ret

nvg_caller: db "BLKGEOM",0
%include "core/abi/wdata.inc"
%macro WDATA_nvg_probe 0
align 16
nvg_record: times 384 db 0
nvg_file_handle: dq 0
nvg_file_descriptor: times 64 db 0
%endmacro
WDATA_DEFER WDATA_nvg_probe
%macro BSS_nvg_probe 0
alignb 16
nvg_initial: resb 2048
nvg_before_guard: resb 16
nvg_before: resb 16384+16
nvg_after_guard: resb 16
nvg_after: resb 16384+16
nvg_expected_guard: resb 16
nvg_expected: resb 8192+16
%endmacro
WDATA_BSS_DEFER BSS_nvg_probe
