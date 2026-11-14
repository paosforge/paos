;; MODULE svc/app_script
;; LAYER 5
;; EXPORTS app_script_observe, app_script_stage_installed, app_script_stage, app_script_descriptor, app_script_native_descriptor, app_script_copy, app_script_retire, app_script_members, app_script_icon_copy
;; IMPORTS svc/app_store, svc/app_execution_state, svc/command, svc/app_package, svc/app_bundle, core/lib/sha256, bootmgr/rsa2048_verify, core/heap, sec/session, core/smp, gui/img/img_png_surface_decode
;; CAPS
;; OWNER saga:command
; Container-2 bash DATA, never native code or a VM identity assertion.
; Public byte staging is signed-only; owner staging owns its catalog lookup.
; Native BSP/non-yielding callers only; VFS must supply native-owned bytes.
; Snapshot storage is private: no pointer escapes, no caller buffer retained.
; VM must separately enforce an isolated instance, START and retirement binding.

%include "fs/app_store_layout.inc"

AS_MAX equ 65536
AS_DESC equ 384
AS_ICON48 equ 9216
AS_ICON96 equ 36864
AS_PIXELS equ AS_ICON48+AS_ICON96
; Each private slot holds original signed bytes, decoded pixels, presence flags.
; Same double-buffer transaction for bytes and icons; no PNG on the copy path.
AS_FLAGS equ AS_MAX+AS_PIXELS
AS_SLOT equ AS_FLAGS+16

; RDI native bytes, RSI exact length -> RAX fresh snapshot handle, or zero.
; Two private heap buffers: failed verify/parse cannot replace a valid snapshot.
app_script_stage:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13,rsi
    xor r14d,r14d                  ; public stage never supplies owner authority
.enter:
    call smp_current_logical
    test eax,eax
    jnz .refuse
    cmp byte [rel as_busy],0
    jne .refuse
    cmp r14d,1
    je .owner_entry
    cmp byte [rel assi_busy],0
    jne .refuse
    jmp .claim
.owner_entry:
    cmp byte [rel assi_busy],1
    jne .refuse
.claim:
    mov byte [rel as_busy],1
    mov [rel as_stage_kind],r14b
    test r12,r12
    jz .fail
    cmp r13,AS_MAX
    ja .fail
    cmp r13,656                     ; header + manifest + two rows + signature
    jb .fail
    call session_shell_require_unlocked
    test eax,eax
    jnz .fail
    mov r15,[rel session_authority_epoch]
    test r15,r15
    jz .fail
    cmp qword [rel as_sequence],-1
    je .fail
    cmp qword [rel as_stage],0
    jne .allocated
    mov edi,2*AS_SLOT
    call kmalloc
    test rax,rax
    jz .fail
    mov [rel as_stage],rax
    add rax,AS_SLOT
    mov [rel as_resident],rax
.allocated:
    mov rdi,[rel as_stage]
    mov rsi,r12
    mov rcx,r13
    cld
    rep movsb                      ; copy BEFORE verify; source is never reused
    mov r12,[rel as_stage]
    call as_verify
    test eax,eax
    jz .fail
    call as_decode_icons
    test eax,eax
    jz .fail
    ; Trust/epoch still current at publication. No callbacks or yields below.
    call session_shell_require_unlocked
    test eax,eax
    jnz .fail
    cmp r15,[rel session_authority_epoch]
    jne .fail
    cmp byte [rel as_stage_kind],0
    je .signed_publication
    cmp byte [rel as_stage_kind],1
    jne .fail
    call as_owner_candidate_current
    test eax,eax
    jz .fail
    jmp .hash
.signed_publication:
    lea rdi,[r12+48]
    call app_trust_find
    test rax,rax
    jz .fail
.hash:
    lea rdi,[rel as_stage_digest]
    mov rsi,r12
    mov rdx,r13
    call sha256_hash
    cmp byte [rel as_stage_kind],0
    je .publish
    cmp r13,[rel assi_row+ASL_LENGTH]
    jne .fail
    lea rdi,[rel as_stage_digest]
    lea rsi,[rel assi_row+ASL_DIGEST]
    mov ecx,4
    cld
    repe cmpsq
    jne .fail
    lea rsi,[rel assi_row+ASL_BUNDLE_ID]
    lea rdi,[r12+80]
    mov ecx,8
    repe cmpsq
    jne .fail
.publish:
    lea rdi,[rel as_digest]
    lea rsi,[rel as_stage_digest]
    mov ecx,4
    cld
    rep movsq
    lea rdi,[rel as_owner_row]
    xor eax,eax
    mov ecx,ASL_SLOT_BYTES/8
    rep stosq
    mov qword [rel as_owner_serial],0
    mov al,[rel as_stage_kind]
    mov [rel as_owner_kind],al
    test al,al
    jz .swap
    lea rdi,[rel as_owner_row]
    lea rsi,[rel assi_row]
    mov ecx,ASL_SLOT_BYTES/8
    rep movsq
    mov rax,[rel assi_serial]
    mov [rel as_owner_serial],rax
.swap:
    mov rax,[rel as_resident]
    mov [rel as_stage],rax
    mov [rel as_resident],r12
    inc qword [rel as_sequence]     ; nonwrapping native handle, not bundle proof
    mov rax,[rel as_sequence]
    mov [rel as_handle],rax
    mov [rel as_epoch],r15
    mov rdx,[rel session_bound_pid]
    mov [rel as_owner],rdx          ; native session owner, never ambient request PID
    mov [rel as_length],r13
    call as_wipe_stage
    mov rax,[rel as_handle]
    mov byte [rel as_busy],0
    jmp .out
.fail:
    call as_wipe_stage
    mov byte [rel as_busy],0
.refuse:
    xor eax,eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RDI nonreused installed entry ID -> fresh handle/0. Native BSP/depth0 only.
; Own authenticated snapshot, full row and epoch/generation; no caller receipt.
; Any REMOVING denies the catalog. No signed fallback or implicit adoption.
app_script_stage_installed:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cld
    mov r13,rdi
    xor ebx,ebx
    call smp_current_logical
    test eax,eax
    jnz .refuse
    cmp dword [rel cmd_dispatch_depth],0
    jne .refuse
    cmp byte [rel as_busy],0
    jne .refuse
    cmp byte [rel assi_busy],0
    jne .refuse
    test r13,r13
    jz .refuse
    cmp r13,-1
    je .refuse
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .refuse
    test rdx,rdx
    jz .refuse
    cmp rdx,-1
    je .refuse
    mov byte [rel assi_busy],1
    mov [rel assi_epoch],rdx
    mov [rel assi_id],r13
    call app_execution_generation
    cmp edx,1
    jne .done
    mov [rel assi_serial],rax
    cmp qword [rel assi_image],0
    jne .allocated
    mov edi,ASL_MAX
    call kmalloc
    test rax,rax
    jz .done
    mov [rel assi_image],rax
.allocated:
    mov rdi,[rel assi_image]
    mov esi,ASL_MAX
    lea rdx,[rel assi_token]
    lea rcx,[rel assi_length]
    call app_store_snapshot
    cmp eax,1
    jne .done
    cmp qword [rel assi_length],ASL_PAYLOAD
    jb .done
    cmp qword [rel assi_length],ASL_MAX
    ja .done
    mov r14,[rel assi_image]
    cmp dword [r14+ASL_VERSION],2
    jne .done
    lea r12,[r14+ASL_HEADER]
    mov r15d,ASL_SLOTS
.denials:
    cmp dword [r12+ASL_STATE],ASL_REMOVING
    je .done
    add r12,ASL_SLOT_BYTES
    dec r15d
    jnz .denials
    lea r12,[r14+ASL_HEADER]
    mov r15d,ASL_SLOTS
.find:
    cmp dword [r12+ASL_STATE],ASL_LIVE
    jne .next
    mov rax,[rel assi_id]
    cmp [r12+ASL_ID],rax
    je .found
.next:
    add r12,ASL_SLOT_BYTES
    dec r15d
    jnz .find
    jmp .done
.found:
    cmp dword [r12+ASL_PROFILE],2
    jne .done
    cmp qword [r12+ASL_EXEC_POLICY],ASL_EXEC_OWNER_UNSIGNED
    jne .done
    mov rax,[r12+ASL_EXEC_GENERATION]
    test rax,rax
    jz .done
    cmp rax,[r14+ASL_GENERATION]
    ja .done
    mov r13,[r12+ASL_LENGTH]
    cmp r13,AS_MAX
    ja .done
    cmp r13,769
    jb .done
    mov r15,[r12+ASL_OFFSET]
    cmp r15,ASL_PAYLOAD
    jb .done
    mov rax,r15
    add rax,r13
    jc .done
    cmp rax,[rel assi_length]
    ja .done
    add r15,r14
    lea rdi,[rel assi_row]
    mov rsi,r12
    mov ecx,ASL_SLOT_BYTES/8
    rep movsq
    mov r12,r15
    cmp dword [r12+20],512
    jne .done
    cmp dword [r12+40],1
    jne .done
    call as_owner_candidate_current
    test eax,eax
    jz .done
    mov rdi,r12
    mov rsi,r13
    call as_stage_installed_entry
    mov rbx,rax
.done:
    mov rdi,[rel assi_image]
    test rdi,rdi
    jz .scratch
    xor eax,eax
    mov ecx,ASL_MAX/8
    cld
    rep stosq
.scratch:
    lea rdi,[rel assi_scratch]
    xor eax,eax
    mov ecx,(assi_scratch_end-assi_scratch)/8
    cld
    rep stosq
    mov byte [rel assi_busy],0
.refuse:
    mov rax,rbx
    cld
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Private direct continuation, reachable only after the fixed native lookup.
; Reuse the exact original copy/verify/icon/handle/swap transaction.
as_stage_installed_entry:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13,rsi
    mov r14d,1
    jmp app_script_stage.enter

; Native fixed lookup remains current at verification/publication, no IO.
as_owner_candidate_current:
    sub rsp,8
    cmp byte [rel assi_busy],1
    jne .bad
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .bad
    cmp rdx,[rel assi_epoch]
    jne .bad
    mov rdi,[rel assi_serial]
    call app_execution_current
    test eax,eax
    jz .bad
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,8
    ret

; All currentness paths use this same private class. Signed class0 retains
; original exact current APPKEY lookup. Owner class1 never asserts author trust.
; Cached immutable row is bound to native generation; no DATA IO in GUES frames.
as_trust_current:
    cmp byte [rel as_owner_kind],0
    je app_trust_find
    cmp byte [rel as_owner_kind],1
    jne .bad
    sub rsp,8
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .no
    cmp qword [rel session_key_handle],0
    je .no
    cmp qword [rel as_owner],PRIN_OWNER
    jne .no
    cmp qword [rel session_bound_pid],PRIN_OWNER
    jne .no
    mov rax,[rel as_epoch]
    test rax,rax
    jz .no
    cmp rax,[rel session_authority]
    jne .no
    cmp rax,[rel session_authority_epoch]
    jne .no
    cmp dword [rbx+40],1
    jne .no
    cmp dword [rbx+20],512
    jne .no
    cmp qword [rel as_owner_row+ASL_EXEC_POLICY],ASL_EXEC_OWNER_UNSIGNED
    jne .no
    cmp qword [rel as_owner_row+ASL_EXEC_GENERATION],0
    je .no
    mov rax,[rel as_length]
    cmp rax,[rel as_owner_row+ASL_LENGTH]
    jne .no
    lea rdi,[rel as_digest]
    lea rsi,[rel as_owner_row+ASL_DIGEST]
    mov ecx,4
    cld
    repe cmpsq
    jne .no
    mov rdi,[rel as_owner_serial]
    call app_execution_current
    test eax,eax
    jz .no
    mov eax,1
    add rsp,8
    ret
.no:
    add rsp,8
.bad:
    xor eax,eax
    ret

; RSI output/RDX whole capacity. Protect own authority/scratch and installed
; heap independently of snapshot existence. Observe uses the same exclusion.
; Does not change RDI/RSI/RDX. No caller output may overwrite this private class.
as_private_output:
    test rsi,rsi
    jz .bad
    cmp byte [rel assi_busy],0
    jne .bad
    mov rax,rsi
    add rax,rdx
    jc .bad
    lea rcx,[rel as_private_end]
    cmp rsi,rcx
    jae .heap
    lea rcx,[rel as_stage]
    cmp rax,rcx
    ja .bad
.heap:
    mov rcx,[rel assi_image]
    test rcx,rcx
    jz .ok
    cmp rax,rcx
    jbe .ok
    add rcx,ASL_MAX
    cmp rsi,rcx
    jb .bad
.ok:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; R12 private stage, R13 exact bounded size -> EAX boolean.
; Only header/bounds/trusted key are touched before the strict RSA check.
as_verify:
    cmp byte [rel as_stage_kind],0
    je .signed
    cmp byte [rel as_stage_kind],1
    jne .bad
    cmp dword [r12+20],512
    jne .bad
    jmp app_package_verify_unsigned_script
.signed:
    cmp dword [r12+20],512
    je app_package_verify_trusted_script
    mov rax,'PAOSAPP1'
    cmp [r12],rax
    jne .bad
    cmp dword [r12+8],0x00400002
    jne .bad
    cmp [r12+12],r13d
    jne .bad
    cmp dword [r12+16],64
    jne .bad
    cmp dword [r12+20],256
    jne .bad
    cmp dword [r12+24],320
    jne .bad
    mov eax,[r12+28]
    cmp eax,160
    jb .bad
    cmp eax,1280
    ja .bad
    xor edx,edx
    mov ecx,80
    div ecx
    test edx,edx
    jnz .bad
    mov ebx,eax                    ; bounded count, at least script + grants
    mov eax,[r12+28]
    add eax,320
    cmp [r12+32],eax
    jne .bad
    mov edx,[r12+36]
    cmp edx,AS_MAX
    ja .bad
    add eax,edx
    mov r14d,eax                   ; signature offset, sums cannot wrap
    add eax,256
    cmp eax,r13d
    jne .bad
    cmp qword [r12+40],0
    jne .bad
    lea rdi,[r12+48]
    call app_trust_find
    test rax,rax
    jz .bad
    mov rcx,rax
    lea rdi,[r12+r14]
    mov rsi,r12
    mov edx,r14d
    call rsa2048_verify_sha256
    test eax,eax
    jnz .bad
    mov rax,'BASHAPP1'
    cmp [r12+64],rax
    jne .bad
    jmp app_script_members
.bad:
    xor eax,eax
    ret

; Internal checked-manifest parser. Callers must authenticate the complete
; envelope before this entry. R12 immutable bytes, header extents already checked.
; Existing trusted stage and separate sharing candidate use the same role rules.
app_script_members:
    mov rax,0x100000001
    cmp [r12+72],rax                ; contract1/runtime bash1
    jne .bad
    cmp [r12+304],rax               ; forms1/verbs1
    jne .bad
    cmp qword [r12+312],0
    jne .bad
    lea rdi,[r12+80]
    mov ecx,64
    mov edx,1                      ; id grammar
    call as_text
    test eax,eax
    jz .bad
    lea rdi,[r12+144]
    mov ecx,64
    xor edx,edx
    call as_text
    test eax,eax
    jz .bad
    cmp byte [r12+208],0
    jne .icon_path
    lea rdi,[r12+208]
    mov ecx,64
    xor eax,eax
    repe scasb
    jne .bad
    jmp .data_path
.icon_path:
    lea rdi,[r12+208]
    mov ecx,64
    xor edx,edx
    call as_text
    test eax,eax
    jz .bad
    mov rax,'icon.png'
    cmp [r12+208],rax
    jne .bad
    cmp byte [r12+216],0
    jne .bad
.data_path:
    lea rdi,[r12+272]
    mov ecx,32
    xor edx,edx
    call as_text
    test eax,eax
    jz .bad
    lea rdi,[rel as_counts]
    xor eax,eax
    mov ecx,5                      ; kinds 0..8 (+pad): the whole as_counts
    rep stosq
    mov r14d,[r12+24]
    add r14,r12
    xor r10d,r10d                  ; contiguous asset offset
.member:
    mov eax,[r14]
    cmp eax,1
    jb .bad
    cmp eax,8                      ; 8 = app image (widgets-01 A4)
    ja .bad
    cmp dword [r14+12],0
    jne .bad
    lea rcx,[rel as_counts]
    inc dword [rcx+rax*4]
    cmp [r14+4],r10d
    jne .bad
    mov r11d,[r14+8]
    test r11d,r11d
    jz .bad
    mov ecx,8192
    cmp eax,3
    jne .large_cap
    mov ecx,12288
.large_cap:
    cmp eax,6
    je .cap_image
    cmp eax,8
    jne .cap_ready
.cap_image:
    mov ecx,40960
.cap_ready:
    cmp r11d,ecx
    ja .bad
    add r10d,r11d
    cmp r10d,[r12+36]
    ja .bad
    lea rdi,[r14+16]
    cmp dword [r14],6
    je .name2x
    cmp dword [r14],7
    je .name_notices
    mov ecx,64
    xor edx,edx
    call as_text
    test eax,eax
    jz .bad
    jmp .name_ok
.name2x:
    lea rsi,[rel as_icon2x_name]
    jmp .reserved_name
.name_notices:
    lea rsi,[rel as_notices_name]
.reserved_name:
    mov ecx,64
    repe cmpsb
    jne .bad
.name_ok:
    ; Full canonical path uniqueness, not merely role uniqueness.
    mov r8d,[r12+24]
    add r8,r12
.duplicate:
    cmp r8,r14
    je .body
    lea rsi,[r8+16]
    lea rdi,[r14+16]
    mov ecx,64
    repe cmpsb
    je .bad
    add r8,80
    jmp .duplicate
.body:
    mov esi,[r12+32]
    add rsi,r12
    mov eax,[r14+4]
    add rsi,rax                    ; bounded exact body
    mov eax,[r14]
    cmp eax,1
    je .script
    cmp eax,2
    je .form
    cmp eax,3
    je .icon
    cmp eax,4
    je .data
    cmp eax,6
    je .icon2x
    cmp eax,7
    je .notices
    cmp eax,8
    je .image
    cmp dword [rel as_counts+20],1
    jne .bad
    cmp r11d,4
    jne .bad
    mov rax,'grants'
    cmp [r14+16],rax
    jne .bad
    lea rdi,[r14+24]
    mov ecx,56
    xor eax,eax
    repe scasb
    jne .bad
    mov ecx,4
.grants:
    cmp byte [rsi],2
    ja .bad
    inc rsi
    loop .grants
    jmp .next
.script:
    cmp dword [rel as_counts+4],1
    jne .bad
    lea rdi,[r12+144]
    push rsi
    lea rsi,[r14+16]
    mov ecx,64
    repe cmpsb
    pop rsi
    jne .bad
    mov edx,1                      ; bash allows TAB, forms do not
    jmp .text_body
.form:
    cmp dword [rel as_counts+8],4
    ja .bad
    cmp r11d,4096
    ja .bad
    ; Canonical path length from as_text is not retained; bounded suffix scan.
    lea rdi,[r14+16]
    xor ecx,ecx
.suffix:
    cmp byte [rdi+rcx],0
    je .suffix_end
    inc ecx
    jmp .suffix
.suffix_end:
    cmp ecx,4
    jb .bad
    cmp dword [rdi+rcx-4],'.frm'
    jne .bad
    xor edx,edx
.text_body:
    cmp byte [rsi+r11-1],10
    jne .bad
    mov ecx,r11d
.ascii:
    lodsb
    cmp al,10
    je .ascii_next
    test edx,edx
    jz .printable
    cmp al,9
    je .ascii_next
.printable:
    cmp al,32
    jb .bad
    cmp al,126
    ja .bad
.ascii_next:
    loop .ascii
    jmp .next
.icon:
    cmp dword [rel as_counts+12],1
    jne .bad
    push rsi
    lea rdi,[r12+208]
    lea rsi,[r14+16]
    mov ecx,64
    repe cmpsb
    pop rsi
    jne .bad
    mov ecx,48
    jmp .png
.icon2x:
    cmp dword [rel as_counts+24],1
    jne .bad
    mov ecx,96
.png:
    call as_png_header
    test eax,eax
    jz .bad
    jmp .next
.notices:
    ; Bounded authenticated credits bytes; never executed/interpreted natively.
    ; Public SDK performs JSON syntax lint. No credit content grants authority.
    cmp dword [rel as_counts+28],1
    jne .bad
    jmp .next
.image:
    ; widgets-01 A4: at most four app images, exactly images/<seg>.<ext> with
    ; <seg> from the as_text member grammar and no '.' or '/' inside it, and
    ; leading bytes naming the extension. Native img_probe/decoders validate
    ; the rest at bind; nothing here decodes. Its own arm: data stays text-only.
    cmp dword [rel as_counts+32],4
    ja .bad
    lea rdi,[r14+16]
    mov rax,[rdi]
    mov rcx,0x00ffffffffffffff
    and rax,rcx
    mov rcx,'images/'
    cmp rax,rcx
    jne .bad
    mov ecx,7
.image_seg:
    mov al,[rdi+rcx]
    cmp al,'.'
    je .image_ext
    test al,al
    jz .bad
    cmp al,'/'
    je .bad
    inc ecx
    jmp .image_seg
.image_ext:
    cmp ecx,7
    je .bad
    mov eax,[rdi+rcx+1]            ; extension plus its NUL; as_text pinned padding
    cmp eax,'png'
    je .image_png
    cmp eax,'bmp'
    je .image_bmp
    cmp eax,'jpg'
    je .image_jpg
    cmp eax,'gif'
    jne .bad
    cmp r11d,6
    jb .bad
    cmp dword [rsi],'GIF8'
    jne .bad
    cmp word [rsi+4],'7a'
    je .next
    cmp word [rsi+4],'9a'
    je .next
    jmp .bad
.image_png:
    cmp r11d,8
    jb .bad
    mov rax,0x0a1a0a0d474e5089
    cmp [rsi],rax
    je .next
    jmp .bad
.image_bmp:
    cmp r11d,2
    jb .bad
    cmp word [rsi],'BM'
    je .next
    jmp .bad
.image_jpg:
    cmp r11d,2
    jb .bad
    cmp word [rsi],0xd8ff
    je .next
    jmp .bad
.data:
    lea rdi,[r12+272]
    lea rsi,[r14+16]
.namespace:
    mov al,[rdi]
    test al,al
    jz .slash
    cmp al,[rsi]
    jne .bad
    inc rdi
    inc rsi
    jmp .namespace
.slash:
    cmp byte [rsi],'/'
    jne .bad
    cmp dword [r12+40],0            ; legacy profile retains opaque data
    je .next
    mov esi,[r12+32]
    add rsi,r12
    mov eax,[r14+4]
    add rsi,rax
    mov ecx,r11d                    ; sharing data is bounded ASCII text
.data_ascii:
    lodsb
    cmp al,9
    je .data_next
    cmp al,10
    je .data_next
    cmp al,32
    jb .bad
    cmp al,126
    ja .bad
.data_next:
    loop .data_ascii
.next:
    add r14,80
    dec ebx
    jnz .member
    cmp r10d,[r12+36]
    jne .bad
    cmp dword [rel as_counts+4],1
    jne .bad
    cmp dword [rel as_counts+20],1
    jne .bad
    xor eax,eax
    cmp byte [r12+208],0
    setne al
    cmp eax,[rel as_counts+12]
    jne .bad
    cmp [rel as_counts+24],eax      ; optional2x requires base48
    ja .bad
    test eax,eax
    jz .ok
    cmp dword [rel as_counts+28],1 ; icon credits travel with the signed bundle
    jne .bad
.ok:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; R11 size, RSI bounded signed PNG bytes, ECX expected48/96 -> bool.
; Before the generic decoder allocates: strict RGBA8 IHDR bounds its raw area,
; filtered rows/Adam7 and orientation scratch. Full CRC/grammar/deflate follows.
as_png_header:
    cmp r11d,33
    jb .bad
    cmp dword [rsi],0x474e5089
    jne .bad
    cmp dword [rsi+4],0x0a1a0a0d
    jne .bad
    cmp dword [rsi+8],0x0d000000
    jne .bad
    cmp dword [rsi+12],'IHDR'
    jne .bad
    mov eax,[rsi+16]
    bswap eax
    cmp eax,ecx
    jne .bad
    mov eax,[rsi+20]
    bswap eax
    cmp eax,ecx
    jne .bad
    cmp dword [rsi+24],0x00000608 ; depth8,type6,compression0,filter0
    jne .bad
    cmp byte [rsi+28],1         ; existing decoder handles both Adam7 and plain
    ja .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Decode ONLY after complete signature/member verification, into private stage.
; Per-image request48 lives on the native stack, never on caller/guest memory.
; Any failure is rolled back by stage wipe; resident pixels remain untouched.
as_decode_icons:
    push rbx
    push r14
    sub rsp,56
    mov ebx,[r12+24]
    add rbx,r12
    mov r14d,[r12+28]
    add r14,rbx
    mov qword [r12+AS_FLAGS],0
.loop:
    cmp rbx,r14
    jae .ok
    mov eax,[rbx]
    mov ecx,48
    lea rdx,[r12+AS_MAX]
    mov r8d,AS_ICON48
    cmp eax,3
    je .decode
    cmp eax,6
    jne .next
    mov ecx,96
    add rdx,AS_ICON48
    mov r8d,AS_ICON96
.decode:
    mov eax,[r12+32]
    add rax,r12
    mov esi,[rbx+4]
    add rax,rsi
    mov [rsp],rax
    mov eax,[rbx+8]
    mov [rsp+8],rax
    mov [rsp+16],rdx
    mov [rsp+24],r8
    mov [rsp+32],ecx
    mov [rsp+36],ecx
    shl rcx,2
    mov [rsp+40],rcx
    mov rdi,rsp
    call img_png_decode_surface_into
    test eax,eax
    jnz .bad
    mov eax,1
    cmp dword [rbx],3
    je .flag
    mov eax,2
.flag:
    or [r12+AS_FLAGS],rax
.next:
    add rbx,80
    jmp .loop
.ok:
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    mov r8d,eax
    mov rdi,rsp
    xor eax,eax
    mov ecx,7
    rep stosq
    mov eax,r8d
    add rsp,56
    pop r14
    pop rbx
    ret

; Exact reserved member names; other role/path grammars remain unchanged.
as_icon2x_name: db 'icon@2x.png',0
    times 64-11 db 0
as_notices_name: db 'NOTICES.json',0
    times 64-13 db 0

; Fixed NUL-padded id/path, rejects traversal/empty components/absolute paths.
; RDI bytes ECX capacity EDX id=1/path=0. Preserves RBX/R10-R15, returns bool.
as_text:
    xor eax,eax
    xor r9d,r9d
    xor r8d,r8d                    ; last char delimiter
.char:
    mov al,[rdi+r9]
    test al,al
    jz .end
    cmp al,'a'
    jb .number
    cmp al,'z'
    jbe .ordinary
.number:
    cmp al,'0'
    jb .separator
    cmp al,'9'
    jbe .ordinary
.separator:
    cmp al,'-'
    je .ordinary
    test edx,edx
    jnz .id_dot
    cmp al,'_'
    je .ordinary
    cmp al,'/'
    je .delimiter
.id_dot:
    cmp al,'.'
    jne .bad
    test edx,edx
    jnz .ordinary
.delimiter:
    test r9d,r9d
    jz .bad
    test r8d,r8d
    jnz .bad
    mov r8d,1
    jmp .advance
.ordinary:
    ; IDs must start with lower-case letter or digit.
    test edx,edx
    jz .reset
    test r9d,r9d
    jnz .reset
    cmp al,'-'
    je .bad
    cmp al,'.'
    je .bad
.reset:
    xor r8d,r8d
.advance:
    inc r9d
    cmp r9d,ecx
    jb .char
    jmp .bad
.end:
    test r9d,r9d
    jz .bad
    test r8d,r8d
    jnz .bad
    test edx,edx
    jz .padding
    cmp r9d,3
    jb .bad
.padding:
    cmp byte [rdi+r9],0
    jne .bad
    inc r9d
    cmp r9d,ecx
    jb .padding
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; RDI handle -> EAX bool. Revoked trust/session synchronously wipes snapshot.
as_current:
    test rdi,rdi
    jz .bad
    cmp rdi,[rel as_handle]
    jne .bad
    push rbx
    call session_shell_require_unlocked
    test eax,eax
    jnz .retire
    mov rax,[rel as_epoch]
    cmp rax,[rel session_authority_epoch]
    jne .retire
    mov rbx,[rel as_resident]
    lea rdi,[rbx+48]
    call as_trust_current
    test rax,rax
    jz .retire
    mov eax,1
    pop rbx
    ret
.retire:
    call as_retire
    pop rbx
.bad:
    xor eax,eax
    ret

; RDI handle, RSI native output, RDX exact384 -> EAX1/0; no pointers serialized.
app_script_descriptor:
    push rbx
    push r12
    sub rsp,8
    mov r12,rsi
    cmp rdx,AS_DESC
    jne .bad
    call as_output
    test eax,eax
    jz .bad
    call as_current
    test eax,eax
    jz .bad
    call as_descriptor_write
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; Native VM/resolver observation only, including inside an active GUES frame.
; Same exact ABI/output discipline, but never borrows the request's principal.
; Does not stage/copy bytes, authorize a verb, install grants or expose an API
; to the guest. No yield/callback between this check and descriptor serialization.
app_script_native_descriptor:
    push rbx
    push r12
    sub rsp,8
    mov r12,rsi
    cmp rdx,AS_DESC
    jne .bad
    call as_output
    test eax,eax
    jz .bad
    call as_native_current
    test eax,eax
    jz .bad
    call as_descriptor_write
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; Check the resident's actual bound OWNER session, independent of active PID,
; remote ticket or injected-input provenance. This is observation, not authority
; to act as OWNER. Local stage/copy/descriptor keep their existing session gate.
as_native_current:
    test rdi,rdi
    jz .bad
    cmp rdi,[rel as_handle]
    jne .bad
    push rbx
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .retire
    cmp qword [rel session_key_handle],0
    je .retire
    cmp qword [rel as_owner],PRIN_OWNER
    jne .retire
    mov rax,[rel as_owner]
    cmp rax,[rel session_bound_pid]
    jne .retire
    mov rax,[rel as_epoch]
    test rax,rax
    jz .retire
    cmp rax,[rel session_authority_epoch]
    jne .retire
    cmp rax,[rel session_authority]
    jne .retire
    mov rbx,[rel as_resident]
    test rbx,rbx
    jz .retire
    lea rdi,[rbx+48]
    call as_trust_current
    test rax,rax
    jz .retire
    mov eax,1
    pop rbx
    ret
.retire:
    call as_retire
    pop rbx
.bad:
    xor eax,eax
    ret

; R12 native output already validated; caller preserves RBX/R12. Both getters
; use this exact serialization after their respective currentness check.
as_descriptor_write:
    cld
    mov rbx,[rel as_resident]
    mov rdi,r12
    xor eax,eax
    mov ecx,AS_DESC/8
    rep stosq
    mov qword [r12],1
    mov rax,[rel as_handle]
    mov [r12+8],rax
    mov rax,[rel as_length]
    mov [r12+16],rax
    mov eax,[rbx+28]
    xor edx,edx
    mov ecx,80
    div ecx
    mov [r12+24],rax
    lea rsi,[rel as_digest]
    lea rdi,[r12+32]
    mov ecx,4
    rep movsq
    lea rsi,[rbx+48]
    mov ecx,2
    rep movsq
    lea rsi,[rbx+64]
    mov ecx,32
    rep movsq
    mov eax,[rbx+24]
    mov [r12+336],rax
    mov eax,[rbx+28]
    mov [r12+344],rax
    mov eax,[rbx+32]
    mov [r12+352],rax
    mov eax,[rbx+36]
    mov [r12+360],rax
    mov qword [r12+368],1
    mov eax,1
    ret

; RDI handle, RSI offset, RDX native destination, RCX count1..AS_MAX ->1/0.
; Exact immutable bytes only; executor must revalidate handle before activation.
app_script_copy:
    push rbx
    push r12
    push r13
    mov rbx,rsi
    mov r12,rdx
    mov r13,rcx
    test rcx,rcx
    jz .bad
    cmp rcx,AS_MAX
    ja .bad
    cmp rsi,AS_MAX
    ja .bad
    lea rax,[rsi+rcx]
    cmp rax,[rel as_length]
    ja .bad
    mov rsi,r12
    mov rdx,r13
    call as_output
    test eax,eax
    jz .bad
    call as_current
    test eax,eax
    jz .bad
    mov rsi,[rel as_resident]
    add rsi,rbx
    mov rdi,r12
    mov rcx,r13
    cld
    rep movsb
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; RDI current handle, RSI native destination, RDX capacity(required..36864),
; ECX48/96 -> EAX1 present/RDX bytes,2 absent/RDX0,0 refused/RDX0.
; Absent/refused preserve the full destination; success preserves slack.
; Top-down straight RGBA8888, no pointers/PNG decode/rescale on this path.
app_script_icon_copy:
    cld
    push rbx
    push r12
    push r13
    mov r12,rsi
    cmp rdx,AS_ICON96
    ja .bad
    xor ebx,ebx
    mov r13d,AS_ICON48
    cmp ecx,48
    je .validate
    cmp ecx,96
    jne .bad
    mov r13d,AS_ICON96
    mov ebx,AS_ICON48
.validate:
    cmp rdx,r13
    jb .bad
    call as_output
    test eax,eax
    jz .bad
    call as_current
    test eax,eax
    jz .bad
    mov rsi,[rel as_resident]
    add rsi,AS_MAX
    mov rax,[rsi+AS_PIXELS]
    cmp rax,3
    ja .bad
    cmp eax,2
    je .bad
    mov eax,1
    test ebx,ebx
    jz .presence
    mov eax,2
.presence:
    test [rsi+AS_PIXELS],rax
    jz .absent
    add rsi,rbx
    mov rdi,r12
    mov rcx,r13
    cld
    rep movsb
    mov rdx,r13
    mov eax,1
    jmp .out
.absent:
    mov eax,2
    xor edx,edx
    jmp .out
.bad:
    xor eax,eax
    xor edx,edx
.out:
    cld
    pop r13
    pop r12
    pop rbx
    ret

; Reject outputs aliasing either private allocation; do not expose an update API.
; RSI start RDX size; preserves RDI (handle).
as_output:
    push rdi
    push rsi
    push rdx
    call smp_current_logical
    pop rdx
    pop rsi
    pop rdi
    test eax,eax
    jnz .bad
    cmp byte [rel as_busy],0
    jne .bad
    test rsi,rsi
    jz .bad
    mov rax,rsi
    add rax,rdx
    jc .bad
    call as_private_output
    test eax,eax
    jz .bad
    mov rax,rsi
    add rax,rdx
    mov rcx,[rel as_stage]
    test rcx,rcx
    jz .bad
    mov r8,[rel as_resident]
    cmp rcx,r8
    cmova rcx,r8
    cmp rax,rcx
    jbe .ok
    add rcx,2*AS_SLOT
    cmp rsi,rcx
    jb .bad
.ok:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Native lifecycle caller: depth zero, before replacement/STOP/revoke/teardown.
; Session/trust changes also invalidate on every descriptor/copy access.
app_script_retire:
    sub rsp,8
    call smp_current_logical
    add rsp,8
    test eax,eax
    jnz .bad
    cmp byte [rel as_busy],0
    jne .bad
    call as_retire
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret
as_retire:
    mov byte [rel as_owner_kind],0
    mov qword [rel as_owner_serial],0
    lea rdi,[rel as_owner_row]
    xor eax,eax
    mov ecx,ASL_SLOT_BYTES/8
    cld
    rep stosq
    mov qword [rel as_handle],0
    mov qword [rel as_length],0
    mov qword [rel as_epoch],0
    mov qword [rel as_owner],0
    mov rdi,[rel as_resident]
    test rdi,rdi
    jz .digest
    xor eax,eax
    mov ecx,AS_SLOT/8
    cld
    rep stosq
.digest:
    lea rdi,[rel as_digest]
    xor eax,eax
    mov ecx,4
    rep stosq
    ret
as_wipe_stage:
    mov byte [rel as_stage_kind],0
    lea rdi,[rel as_stage_digest]
    xor eax,eax
    mov ecx,4
    cld
    rep stosq
    mov rdi,[rel as_stage]
    test rdi,rdi
    jz .out
    xor eax,eax
    mov ecx,AS_SLOT/8
    cld
    rep stosq
.out:
    ret

%macro WDATA_BSS_app_script 0
alignb 8
as_stage: resq 1
as_resident: resq 1
as_sequence: resq 1
as_handle: resq 1
as_epoch: resq 1
as_owner: resq 1
as_length: resq 1
as_digest: resb 32
as_counts: resd 10                ; per-kind counts 0..8, cleared as 5 qwords
as_busy: resb 1
as_stage_kind: resb 1
as_owner_kind: resb 1
assi_busy: resb 1
alignb 8
as_stage_digest: resb 32
as_owner_serial: resq 1
as_owner_row: resb ASL_SLOT_BYTES
assi_image: resq 1
assi_scratch:
assi_row: resb ASL_SLOT_BYTES
assi_epoch: resq 1
assi_serial: resq 1
assi_id: resq 1
assi_length: resq 1
assi_token: resb 112
assi_scratch_end:
as_private_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_app_script

; Native read-only cache observation. RDI digest32, RSI output96 (12 qwords).
; match, copy48 state, copy96 state, SHA48[32], SHA96[32], retired slot all-zero.
; Uses the maintained copy ABI; never invokes PNG decode or stages a candidate.
app_script_observe:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12,rsi
    mov edx,96
    cmp qword [rel as_stage],0
    je .private_only
    call as_output
    jmp .checked
.private_only:
    call as_private_output
.checked:
    test eax,eax
    jz .pop
    mov rdi,r12
    xor eax,eax
    mov ecx,12
    cld
    rep stosq
    cmp qword [rel as_handle],0
    je .retired
    mov rdi,[rel as_handle]
    call as_current
    test eax,eax
    jz .out
    lea rdi,[rel as_digest]
    mov rsi,rbx
    mov ecx,4
    repe cmpsq
    jne .out
    mov qword [r12],1
    mov r13d,48
.copy:
    mov rdi,[rel as_handle]
    lea rsi,[rel as_observe_pixels]
    mov edx,AS_ICON96
    mov ecx,r13d
    call app_script_icon_copy
    mov ecx,1
    cmp r13d,48
    je .state
    inc ecx
.state:
    mov [r12+rcx*8],rax
    cmp eax,1
    jne .next
    lea rdi,[r12+24]
    cmp r13d,48
    je .hash
    add rdi,32
.hash:
    lea rsi,[rel as_observe_pixels]
    call sha256_hash
.next:
    cmp r13d,96
    je .out
    mov r13d,96
    jmp .copy
.retired:
    mov rdi,[rel as_resident]
    test rdi,rdi
    jz .zero
    xor eax,eax
    mov ecx,AS_SLOT/8
    repe scasq
    jne .out
.zero:
    mov qword [r12+88],1
.out:
    lea rdi,[rel as_observe_pixels]
    xor eax,eax
    mov ecx,AS_ICON96/8
    rep stosq
.pop:
    pop r13
    pop r12
    pop rbx
    ret
%macro WDATA_BSS_app_script_observe 0
alignb 8
as_observe_pixels: resb AS_ICON96
%endmacro
WDATA_BSS_DEFER WDATA_BSS_app_script_observe
