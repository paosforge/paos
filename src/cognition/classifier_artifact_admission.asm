;; MODULE cognition/classifier_artifact_admission
;; LAYER 6
;; EXPORTS cog_classifier_owned_begin_advisory, cog_classifier_owned_step_advisory, cog_classifier_owned_cancel_advisory, cog_classifier_owned_result_advisory
;; IMPORTS vfs, fat32_disk, core/heap, core/lib/sha256, cog_encoder_bound_coop_begin_advisory, cog_encoder_bound_coop_step_advisory, cog_encoder_bound_coop_cancel_advisory, cog_encoder_ascii_cls_shape_prepare_advisory
;; CAPS
;; OWNER saga:cognition
;; CONTEXT: bsp_only (canonical SHA static scratch; caller serializes, never AP/IRQ)
; Native singleton admission/consumer. No command, authority or scheduler binding.
; SysV begin(owner64,generation64,text,textbytes,selected_handle)->3 pending/2 refuse.
; step(owner,generation,ordinal64)->3 pending/0 choose/1 abstain/2 refuse/4 cancelled.
; cancel(owner,generation)->3 cleanup pending/2 refuse. result(owner,generation,out20)
; copies advice ONLY at choose/abstain and returns 0/1; otherwise2, no writes.
; Owner is an authenticated native caller's execution identity, NOT an auth grant.
; The caller supplies no paths, artifact pointers, digests, thresholds or labels.
; Text is a trusted mapped caller span for begin only, copied <=4096 bytes. Text
; provenance must already be assigned by the ingesting owner; this is no ingress.
;
; Private immutable COPIES (not page protections) live until explicit cancellation
; and complete scrub. All five trusted sizes/digests precede parsing. Each step
; does <=65536 bytes of I/O+hash or scrub, one map, final digest, shape preparation,
; or one existing bounded child stage. VFS/backend latency is not a time promise.
; Selected mount is the EXISTING explicit read-only FAT selection, never rebound.
; Save its extent identity (including namespace/media generation); check before AND
; after each exact bounded read. No fallback path/volume or short-read acceptance.
; Any acquisition failure enters bounded cleanup, cannot publish partial advice.
; After acquisition, device changes cannot alter our owned copies.
;
; The high model heap is bump-only. Reserve ONCE, max128MiB/boot; cancellation,
; errors and replacements scrub that entire reservation, then reuse it. No fake
; kfree, shared bump rewind or accumulating generation allocations. Active begin
; refuses; explicitly cancel and drain cleanup before same-owner strictly newer
; generation. No replacement before old mappings/child are retired. Completed
; advice stays available until cancel; result never exposes artifact addresses.
; Metadata and scratch are private native state, not attacker serialization.
;
; Production POLICY REMAINS UNFROZEN: four adopted BGE pins below, NO adopted fifth
; prototype/schema/order/calibration artifact. ready=0 refuses before I/O/alloc.
; Enabling requires reviewed native manifest AND frozen policy, not a caller's
; matching digest. Arithmetic test manifests confer no BGE/quality admission.
; Existing GPT2 model_base and native deterministic authorization are untouched.
%include "core/abi/wdata.inc"
COG_CLASSIFIER_RESERVE equ 134217728

cog_classifier_owned_begin_advisory:
    xor r9d,r9d
    jmp cog_classifier_owned_dispatch
cog_classifier_owned_step_advisory:
    mov r9d,1
    jmp cog_classifier_owned_dispatch
cog_classifier_owned_cancel_advisory:
    mov r9d,2
    jmp cog_classifier_owned_dispatch
cog_classifier_owned_result_advisory:
    mov r9d,3
cog_classifier_owned_dispatch:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,40
    pushfq
    pop qword [rsp]
    cld
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov r15,rcx
    mov rbp,r8
    mov ebx,r9d
    test r12,r12
    jz .refuse
    test r13,r13
    jz .refuse
    test ebx,ebx
    jz .begin
    cmp [rel cog_classifier_owned_owner],r12
    jne .refuse
    cmp [rel cog_classifier_owned_generation],r13
    jne .refuse
    cmp ebx,3
    je .result
    cmp ebx,2
    je .cancel
    cmp [rel cog_classifier_owned_ordinal],r14
    jne .refuse
    mov eax,[rel cog_classifier_owned_phase]
    cmp eax,1
    je .initial_clear
    cmp eax,2
    je .map
    cmp eax,3
    je .read
    cmp eax,4
    je .final
    cmp eax,5
    je .prepare
    cmp eax,6
    je .child_begin
    cmp eax,7
    je .child_step
    cmp eax,8
    je .cleanup
    jmp .refuse
.begin:
    cmp qword [rel cog_classifier_manifest_ready],1
    jne .refuse
    mov rax,[rel cog_classifier_owned_phase]
    test rax,rax
    jz .virgin
    cmp rax,11
    jb .refuse                  ; active OR published mappings still owned
    cmp [rel cog_classifier_owned_owner],r12
    jne .refuse
    cmp r13,[rel cog_classifier_owned_generation]
    jbe .refuse                 ; full64 strictly newer generation
.virgin:
    cmp r15,4096
    ja .refuse
    test r14,r14
    jz .refuse
    mov rax,r14
    add rax,r15
    jc .refuse
    ; Do not allow the source to overlap our singleton or retained reservation.
    lea rdx,[rel cog_classifier_owned_state_end]
    cmp r14,rdx
    jae .text_heap
    lea rdx,[rel cog_classifier_owned_base]
    cmp rax,rdx
    ja .refuse
.text_heap:
    mov rdx,[rel cog_classifier_owned_base]
    test rdx,rdx
    jz .selection
    cmp rax,rdx
    jbe .selection
    add rdx,COG_CLASSIFIER_RESERVE
    cmp r14,rdx
    jb .refuse
.selection:
    cmp rbp,0x7fffffff
    ja .refuse
    cmp [rel vfs_disk_handle],ebp
    jne .refuse
    mov edi,ebp
    call vfs_mount_ptr
    test rax,rax
    jz .refuse
    lea rdx,[rel fd_selected_ops]
    cmp [rax],rdx
    jne .refuse                 ; only existing exact read-only selected FAT mount
    ; Validate trusted sizes and bounded aggregate before allocating anything.
    mov eax,[rel cog_classifier_policy]
    cmp eax,2
    jb .refuse
    cmp eax,256
    ja .refuse
    cmp dword [rel cog_classifier_policy+4],384
    jne .refuse
    imul eax,1536
    lea rdx,[rel cog_classifier_manifest]
    cmp [rdx+4*56+16],rax
    jne .refuse
    cmp qword [rdx+16],20
    jb .refuse
    cmp qword [rdx+16],8388608
    ja .refuse
    cmp qword [rdx+56+16],47671320
    jne .refuse
    cmp qword [rdx+112+16],21234832
    jne .refuse
    cmp qword [rdx+168+16],243376
    jne .refuse
    xor ecx,ecx
    xor r8d,r8d
.manifest:
    cmp qword [rdx],0
    je .refuse
    cmp qword [rdx+8],1
    jb .refuse
    cmp qword [rdx+8],255
    ja .refuse
    mov rax,[rdx+24]
    or rax,[rdx+32]
    or rax,[rdx+40]
    or rax,[rdx+48]
    jz .refuse
    add r8,[rdx+16]
    jc .refuse
    add r8,15
    and r8,-16
    add rdx,56
    inc ecx
    cmp ecx,5
    jb .manifest
    add r8,48771232             ; largest exact child arena
    cmp r8,COG_CLASSIFIER_RESERVE
    ja .refuse
    cmp qword [rel cog_classifier_owned_base],0
    jne .allocated
    mov edi,COG_CLASSIFIER_RESERVE
    call kmalloc_model
    test rax,rax
    jz .refuse
    test al,15
    jnz .refuse
    mov rdx,rax
    add rdx,COG_CLASSIFIER_RESERVE
    jc .refuse
    mov [rel cog_classifier_owned_base],rax
.allocated:
    lea rdi,[rel cog_classifier_owned_scratch]
    mov ecx,cog_classifier_owned_scratch_end-cog_classifier_owned_scratch
    xor eax,eax
    rep stosb
    mov [rel cog_classifier_owned_owner],r12
    mov [rel cog_classifier_owned_generation],r13
    mov qword [rel cog_classifier_owned_ordinal],0
    mov qword [rel cog_classifier_owned_cursor],0
    mov qword [rel cog_classifier_owned_index],0
    mov [rel cog_classifier_owned_handle],rbp
    mov rax,[rel vfs_write_generation]
    mov [rel cog_classifier_owned_writegen],rax
    mov [rel cog_classifier_owned_textbytes],r15
    lea rdi,[rel cog_classifier_owned_text]
    mov rsi,r14
    mov rcx,r15
    rep movsb
    mov qword [rel cog_classifier_owned_phase],1
    mov eax,3
    jmp .out
.initial_clear:
    call .scrub_chunk
    jne .pending
    mov qword [rel cog_classifier_owned_phase],2
    jmp .pending
.map:
    ; Map snapshots use cap1; returned total may exceed cap for fragmented files.
    mov rdi,[rel cog_classifier_owned_handle]
    cmp [rel vfs_disk_handle],edi
    jne .fail
    mov rax,[rel vfs_write_generation]
    cmp rax,[rel cog_classifier_owned_writegen]
    jne .fail
    mov rax,[rel cog_classifier_owned_index]
    imul rax,56
    lea rbx,[rel cog_classifier_manifest]
    add rbx,rax
    lea rsi,[rel cog_classifier_manifest]
    add rsi,[rbx]
    mov edx,[rbx+8]
    lea rcx,[rel cog_classifier_owned_map_temp]
    mov r8d,1
    call vfs_file_extents
    test rax,rax
    jle .fail
    mov rax,[rel cog_classifier_owned_map_temp+48]
    cmp rax,[rbx+16]
    jne .fail
    cmp qword [rel cog_classifier_owned_index],0
    jne .compare_map
    lea rsi,[rel cog_classifier_owned_map_temp]
    lea rdi,[rel cog_classifier_owned_map]
    mov ecx,96
    rep movsb
    jmp .mapped
.compare_map:
    lea rsi,[rel cog_classifier_owned_map_temp]
    lea rdi,[rel cog_classifier_owned_map]
    mov ecx,6                    ; mount/ops/priv/device/media/ns, exclude file size
    repe cmpsq
    jne .fail
    mov rax,[rel cog_classifier_owned_map_temp+56]
    cmp rax,[rel cog_classifier_owned_map+56]
    jne .fail                    ; volume identity AND sector size
.mapped:
    call cog_classifier_owned_volume_ok
    test eax,eax
    jnz .fail
    mov rdx,[rel cog_classifier_owned_index]
    lea rcx,[rel cog_classifier_owned_artifacts]
    test edx,edx
    jnz .next_pointer
    mov rax,[rel cog_classifier_owned_base]
    jmp .pointer
.next_pointer:
    mov rax,[rcx+rdx*8-8]
    add rax,[rbx-56+16]
    add rax,15
    and rax,-16
.pointer:
    mov [rcx+rdx*8],rax
    mov qword [rel cog_classifier_owned_cursor],0
    lea rdi,[rel cog_classifier_owned_sha]
    call sha256_stream_init
    test rax,rax
    jnz .fail
    mov qword [rel cog_classifier_owned_phase],3
    jmp .pending
.read:
    call cog_classifier_owned_volume_ok
    test eax,eax
    jnz .fail
    mov rax,[rel cog_classifier_owned_index]
    imul rax,56
    lea rbx,[rel cog_classifier_manifest]
    add rbx,rax
    mov r9,[rbx+16]
    sub r9,[rel cog_classifier_owned_cursor]
    mov eax,65536
    cmp r9,rax
    cmova r9,rax
    mov [rsp+8],r9
    mov rdi,[rel cog_classifier_owned_handle]
    lea rsi,[rel cog_classifier_manifest]
    add rsi,[rbx]
    mov edx,[rbx+8]
    mov rcx,[rel cog_classifier_owned_cursor]
    mov rax,[rel cog_classifier_owned_index]
    lea r8,[rel cog_classifier_owned_artifacts]
    mov r8,[r8+rax*8]
    add r8,rcx
    mov [rsp+16],r8
    call vfs_read_at_path
    cmp rax,[rsp+8]
    jne .fail                   ; short/error never hashes or advances
    call cog_classifier_owned_volume_ok ; after read, before hash/advance
    test eax,eax
    jnz .fail
    lea rdi,[rel cog_classifier_owned_sha]
    mov rsi,[rsp+16]
    mov rdx,[rsp+8]
    call sha256_stream_update
    test rax,rax
    jnz .fail
    mov rax,[rsp+8]
    add rax,[rel cog_classifier_owned_cursor]
    mov [rel cog_classifier_owned_cursor],rax
    cmp rax,[rbx+16]
    jne .pending
    mov qword [rel cog_classifier_owned_phase],4
    jmp .pending
.final:
    call cog_classifier_owned_volume_ok
    test eax,eax
    jnz .fail
    lea rdi,[rel cog_classifier_owned_sha]
    lea rsi,[rel cog_classifier_owned_digest]
    call sha256_stream_final
    test rax,rax
    jnz .fail
    mov rax,[rel cog_classifier_owned_index]
    imul rax,56
    lea rdx,[rel cog_classifier_manifest+24]
    add rdx,rax
    lea rsi,[rel cog_classifier_owned_digest]
    xor ecx,ecx
    xor r8d,r8d
.digest:
    mov rax,[rsi+rcx*8]
    xor rax,[rdx+rcx*8]
    or r8,rax
    inc ecx
    cmp ecx,4
    jb .digest
    test r8,r8
    jnz .fail
    inc qword [rel cog_classifier_owned_index]
    mov qword [rel cog_classifier_owned_phase],2
    cmp qword [rel cog_classifier_owned_index],5
    jne .pending
    mov qword [rel cog_classifier_owned_phase],5
    jmp .pending
.prepare:
    lea rdi,[rel cog_classifier_owned_text]
    mov rsi,[rel cog_classifier_owned_artifacts]
    lea rdx,[rel cog_classifier_owned_prepared]
    lea rcx,[rel cog_classifier_owned_shape_config]
    mov rax,[rel cog_classifier_owned_textbytes]
    mov [rcx],rax
    mov rax,[rel cog_classifier_manifest+16]
    mov [rcx+8],rax
    mov qword [rcx+16],2096
    call cog_encoder_ascii_cls_shape_prepare_advisory
    test eax,eax
    jnz .fail
    lea rdi,[rel cog_classifier_owned_request]
    lea rax,[rel cog_classifier_owned_text]
    mov [rdi],rax
    lea rax,[rel cog_classifier_owned_advice]
    mov [rdi+8],rax
    mov [rdi+16],r12
    mov [rdi+24],r13
    mov qword [rdi+32],7224
    lea rax,[rel cog_classifier_owned_prepared]
    mov [rdi+40],rax
    mov rax,[rel cog_classifier_owned_textbytes]
    mov [rdi+48],rax
    lea rbx,[rel cog_classifier_owned_artifacts]
    lea rdx,[rel cog_classifier_manifest]
    mov ecx,4
    lea rsi,[rdi+56]
.req_pairs:
    mov rax,[rbx]
    mov [rsi],rax
    mov rax,[rdx+16]
    mov [rsi+8],rax
    add rbx,8
    add rdx,56
    add rsi,16
    dec ecx
    jnz .req_pairs
    mov qword [rdi+120],20
    mov rax,[rel cog_classifier_owned_artifacts+32]
    mov [rdi+144],rax
    mov rdx,[rel cog_classifier_manifest+4*56+16]
    mov [rdi+152],rdx
    add rax,rdx
    add rax,15
    and rax,-16
    mov [rdi+128],rax
    mov rax,[rel cog_classifier_owned_prepared+8]
    add rax,7
    and rax,-8
    add rax,6816
    mov edx,[rel cog_classifier_policy]
    lea rax,[rax+rdx*4]
    cmp rax,48771232
    ja .fail
    mov [rdi+136],rax
    mov rax,[rel cog_classifier_policy]
    mov [rdi+160],rax
    mov rax,[rel cog_classifier_policy+8]
    mov [rdi+168],rax
    lea rsi,[rel cog_classifier_manifest+24]
    lea rdi,[rdi+176]
    mov ebx,5
.req_pins:
    mov ecx,4
    rep movsq
    add rsi,24
    dec ebx
    jnz .req_pins
    mov qword [rel cog_classifier_owned_phase],6
    jmp .pending
.child_begin:
    lea rdi,[rel cog_classifier_owned_request]
    lea rsi,[rel cog_classifier_owned_child]
    call cog_encoder_bound_coop_begin_advisory
    cmp eax,3
    jne .fail
    mov qword [rel cog_classifier_owned_phase],7
    jmp .pending
.child_step:
    lea rdi,[rel cog_classifier_owned_request]
    lea rsi,[rel cog_classifier_owned_child]
    mov edx,[rsi+44]
    call cog_encoder_bound_coop_step_advisory
    cmp eax,3
    je .pending
    cmp eax,1
    ja .fail
    lea edx,[eax+9]
    mov [rel cog_classifier_owned_phase],rdx
    inc qword [rel cog_classifier_owned_ordinal]
    jmp .out
.cancel:
    mov eax,[rel cog_classifier_owned_phase]
    test eax,eax
    jz .refuse
    cmp eax,8
    je .refuse                  ; pending cleanup is drained with step, not reset
    cmp eax,10
    ja .refuse
    cmp eax,7
    jne .cancelled
    lea rdi,[rel cog_classifier_owned_request]
    lea rsi,[rel cog_classifier_owned_child]
    call cog_encoder_bound_coop_cancel_advisory
    ; Even if a child refuses retirement, private buffers are never reused until
    ; full cleanup, and no further child entry occurs after changing our phase.
.cancelled:
    mov qword [rel cog_classifier_owned_terminal],11
    jmp .retire
.fail:
    mov qword [rel cog_classifier_owned_terminal],12
.retire:
    mov qword [rel cog_classifier_owned_phase],8
    mov qword [rel cog_classifier_owned_cursor],0
    ; No publication during cleanup, including any advice staged by a child.
    mov qword [rel cog_classifier_owned_advice],0
    mov qword [rel cog_classifier_owned_advice+8],0
    mov dword [rel cog_classifier_owned_advice+16],0
    cmp ebx,2
    je .pending_no_ordinal       ; cancel is not a step
    jmp .pending
.cleanup:
    cmp qword [rel cog_classifier_owned_cursor],COG_CLASSIFIER_RESERVE
    je .cleanup_metadata
    call .scrub_chunk
    jmp .pending
.cleanup_metadata:
    lea rdi,[rel cog_classifier_owned_scratch]
    mov ecx,cog_classifier_owned_scratch_end-cog_classifier_owned_scratch
    xor eax,eax
    rep stosb
    mov rax,[rel cog_classifier_owned_terminal]
    mov [rel cog_classifier_owned_phase],rax
    inc qword [rel cog_classifier_owned_ordinal]
    mov eax,2
    cmp qword [rel cog_classifier_owned_phase],11
    jne .out
    mov eax,4
    jmp .out
.result:
    mov eax,[rel cog_classifier_owned_phase]
    sub eax,9
    cmp eax,1
    ja .refuse
    test r14,r14
    jz .refuse
    mov rdx,r14
    add rdx,20
    jc .refuse
    ; Result must not alias private state or reservation.
    lea rcx,[rel cog_classifier_owned_state_end]
    cmp r14,rcx
    jae .result_heap
    lea rcx,[rel cog_classifier_owned_base]
    cmp rdx,rcx
    ja .refuse
.result_heap:
    mov rcx,[rel cog_classifier_owned_base]
    cmp rdx,rcx
    jbe .copy_result
    add rcx,COG_CLASSIFIER_RESERVE
    cmp r14,rcx
    jb .refuse
.copy_result:
    lea rsi,[rel cog_classifier_owned_advice]
    mov rdi,r14
    mov ecx,20
    rep movsb
    jmp .out
.pending:
    inc qword [rel cog_classifier_owned_ordinal]
.pending_no_ordinal:
    mov eax,3
    jmp .out
.refuse:
    mov eax,2
.out:
    push qword [rsp]
    popfq
    add rsp,40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.scrub_chunk:
    mov rdx,[rel cog_classifier_owned_cursor]
    mov rdi,[rel cog_classifier_owned_base]
    add rdi,rdx
    xor eax,eax
    mov ecx,65536
    rep stosb
    add rdx,65536
    mov [rel cog_classifier_owned_cursor],rdx
    cmp rdx,COG_CLASSIFIER_RESERVE
    ret

; 0 means same selected read-only volume/namespace/media, anything else refuses.
cog_classifier_owned_volume_ok:
    sub rsp,8
    mov rdi,[rel cog_classifier_owned_handle]
    cmp [rel vfs_disk_handle],edi
    jne .bad
    mov rax,[rel vfs_write_generation]
    cmp rax,[rel cog_classifier_owned_writegen]
    jne .bad
    lea rsi,[rel cog_classifier_owned_map]
    call vfs_file_extents_current
    test eax,eax
    jnz .bad                    ; namespace movement (1) is also refusal
    xor eax,eax
    add rsp,8
    ret
.bad:
    mov eax,1
    add rsp,8
    ret

align 8,db 0
; TRUSTED_MANIFEST_BEGIN
cog_classifier_manifest_ready: dq 0
cog_classifier_policy: dd 0,384,0,0 ; count, width, thresholds UNFROZEN
cog_classifier_manifest:
    dq cog_classifier_path0-cog_classifier_manifest,cog_classifier_path0_end-cog_classifier_path0,987438
    db 0x95,0xe9,0xb6,0x5f,0xe4,0x33,0x69,0xac,0xc1,0x42,0x08,0x45,0x3a,0x3f,0x9a,0xf9,0x91,0xb5,0x77,0x7e,0xb6,0x19,0xb0,0xca,0xef,0x75,0x55,0xce,0xc2,0xab,0xe7,0x14
    dq cog_classifier_path1-cog_classifier_manifest,cog_classifier_path1_end-cog_classifier_path1,47671320
    db 0x08,0x72,0x17,0x6e,0x7c,0xf9,0x10,0x73,0xc2,0xad,0x3e,0x9b,0x82,0xb9,0x72,0x45,0xbc,0xba,0xd1,0x28,0x31,0x3d,0x3e,0x2a,0xd4,0x00,0x47,0x7f,0x7d,0x88,0x8d,0x6a
    dq cog_classifier_path2-cog_classifier_manifest,cog_classifier_path2_end-cog_classifier_path2,21234832
    db 0xa7,0xfd,0x6a,0x40,0x0c,0x75,0x79,0x11,0x5e,0x7c,0x32,0x0e,0xd0,0xde,0x32,0xb0,0x7f,0x74,0x05,0x42,0x49,0x63,0x8f,0x3f,0x66,0x91,0xc4,0x8d,0x26,0x58,0xb7,0xd4
    dq cog_classifier_path3-cog_classifier_manifest,cog_classifier_path3_end-cog_classifier_path3,243376
    db 0x0b,0xf4,0x22,0x03,0xee,0xd1,0xff,0x59,0xcf,0x17,0xb2,0xf4,0xaf,0xcd,0x68,0x4e,0x7a,0x2f,0x0e,0x73,0xf4,0x2f,0x4c,0x3e,0x0b,0x9f,0x17,0xe8,0x5c,0x93,0x0a,0xa7
    dq 0,0,0
    times 32 db 0               ; no adopted prototype/schema/order/calibration pin
cog_classifier_path0: db '/paos_classifier_wordpiece_vocab_v1.bin'
cog_classifier_path0_end:
cog_classifier_path1: db '/paos_classifier_bge_embedding_pack_v1/embeddings.bin'
cog_classifier_path1_end:
cog_classifier_path2: db '/paos_classifier_bge_matmul_pack_v1/weights.bin'
cog_classifier_path2_end:
cog_classifier_path3: db '/paos_classifier_bge_layer_params_v1/layers.bin'
cog_classifier_path3_end:
; TRUSTED_MANIFEST_END

%macro WDATA_cognition_classifier_artifact_admission_0 0
align 16,db 0
cog_classifier_owned_base: dq 0
cog_classifier_owned_owner: dq 0
cog_classifier_owned_generation: dq 0
cog_classifier_owned_ordinal: dq 0
cog_classifier_owned_phase: dq 0 ; 1zero,2map,3read,4final,5shape,6begin,7child,
                                ; 8scrub,9choose,10abstain,11cancelled,12refused
cog_classifier_owned_terminal: dq 0
cog_classifier_owned_cursor: dq 0
cog_classifier_owned_index: dq 0
cog_classifier_owned_scratch:
cog_classifier_owned_handle: dq 0
cog_classifier_owned_writegen: dq 0
cog_classifier_owned_textbytes: dq 0
cog_classifier_owned_artifacts: times 5 dq 0
cog_classifier_owned_map: times 96 db 0
cog_classifier_owned_map_temp: times 96 db 0
cog_classifier_owned_sha: times 112 db 0
cog_classifier_owned_digest: times 32 db 0
cog_classifier_owned_shape_config: times 24 db 0
cog_classifier_owned_request: times 336 db 0
cog_classifier_owned_prepared: times 2096 db 0
cog_classifier_owned_child: times 7224 db 0
cog_classifier_owned_advice: times 24 db 0
cog_classifier_owned_text: times 4096 db 0
cog_classifier_owned_scratch_end:
cog_classifier_owned_state_end:
%endmacro
WDATA_DEFER WDATA_cognition_classifier_artifact_admission_0
