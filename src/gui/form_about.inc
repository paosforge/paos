; About this PC: stock listview bindings and ordinary button click chain.
; Built-in form3 only. No firmware calls, allocator guesses, commands or signer.
; Each bounded card is also its Copy source; commas delimit painted rows, LF
; delimits clipboard rows. Hardware commas/control bytes cannot inject rows.
ABOUT_CAP equ 768
ABOUT_COLS equ 45
ABOUT_BUILD_HEX equ 12
ABOUT_NAME_CHARS equ 7

form_about_device:
    push rbx
    push r12
    call boot_ms_now
    mov rdx, [rel about_device_ms]
    test rdx, rdx
    jz .refresh
    sub rax, rdx
    cmp rax, FORM_SYSPROPS_SNAPSHOT_MS
    jb .cached
.refresh:
    call boot_ms_now
    mov [rel about_device_ms], rax
    lea rdi, [rel about_device_buf]
    call about_reset
    lea rdi, [rel about_maker]
    call about_put
    lea rdi, [rel smbios_sys_vendor]
    call about_value
    call about_row
    lea rdi, [rel about_model]
    call about_put
    lea rdi, [rel smbios_sys_product]
    call about_value
    call about_row
    lea rdi, [rel about_processor]
    call about_put
    call about_cpu_brand
    mov rdi, rax
    call about_value
    call about_row
    lea rdi, [rel about_cores]
    call about_put
    mov edi, [rel smp_physical_core_count]
    call about_count
    lea rdi, [rel about_threads]
    call about_put
    mov edi, [rel smp_topology_online]
    call about_count
    call about_row
    lea rdi, [rel about_ram]
    call about_put
    cmp byte [rel smbios_mem_complete], 1
    jne .no_installed
    cmp dword [rel smbios_mem_seen], 0
    je .no_installed
    cmp dword [rel smbios_mem_unknown], 0
    jne .no_installed
    cmp byte [rel smbios_mem_overflow], 0
    jne .no_installed
    mov rdi, [rel smbios_mem_bytes]
    call about_gb
    jmp .usable
.no_installed:
    lea rdi, [rel about_unavailable]
    call about_put
.usable:
    lea rdi, [rel about_usable_open]
    call about_put
    lea rdi, [rel about_map]
    call memmap_inventory
    cmp dword [rel about_map], 1
    jne .no_usable
    ; Firmware conventional + reclaimable loader/boot-services, as reported
    ; separately by HW memory. Never heap size or current allocator free RAM.
    mov rdi, [rel about_map + 8]
    add rdi, [rel about_map + 16]
    jc .no_usable
    call about_gb
    jmp .ram_done
.no_usable:
    lea rdi, [rel about_unavailable]
    call about_put
.ram_done:
    lea rdi, [rel about_usable_close]
    call about_put
    call about_row
    lea rdi, [rel about_system]
    call about_put
    call about_row
    lea rdi, [rel about_native]
    call about_put
    mov edi, [rel res_native_w]
    mov esi, [rel res_native_h]
    call about_resolution
    call about_row
    lea rdi, [rel about_active]
    call about_put
    mov edi, [rel fb_width]
    mov esi, [rel fb_height]
    call about_resolution
.cached:
    lea rax, [rel about_device_buf]
    pop r12
    pop rbx
    ret

form_about_os:
    push rbx
    call boot_ms_now
    mov rdx, [rel about_os_ms]
    test rdx, rdx
    jz .refresh
    sub rax, rdx
    cmp rax, FORM_SYSPROPS_SNAPSHOT_MS
    jb .cached
.refresh:
    call boot_ms_now
    mov [rel about_os_ms], rax
    lea rdi, [rel about_os_buf]
    call about_reset
    lea rdi, [rel about_version]
    call about_put
    lea rdi, [rel str_udp_r_pre + 13]
    lea rsi, [rel about_number]
    xor ecx, ecx
.version:
    mov al, [rdi + rcx]
    test al, al
    jz .version_done
    cmp al, ' '
    je .version_done
    cmp ecx, 31
    jae .version_done
    mov [rsi + rcx], al
    inc ecx
    jmp .version
.version_done:
    mov byte [rsi + rcx], 0
    mov rdi, rsi
    call about_value
    call about_row
    ; Build (Peter 107784): the first 12 hex of this image's own measured build
    ; id, only when it matches its stamp. Its own row, parsed by T5-13 OS_ROWS.
    lea rdi, [rel about_build]
    call about_put
    cmp byte [rel paos_build_state], BID_ST_MATCH
    jne .no_build
    lea rsi, [rel paos_build_hex]
    lea rdi, [rel about_number]
    xor ecx, ecx
.build_hex:
    mov al, [rsi + rcx]
    test al, al
    jz .build_end
    mov [rdi + rcx], al
    inc ecx
    cmp ecx, ABOUT_BUILD_HEX
    jb .build_hex
.build_end:
    mov byte [rdi + rcx], 0
    call about_value
    jmp .build_done
.no_build:
    lea rdi, [rel about_unavailable]
    call about_put
.build_done:
    call about_row
    lea rdi, [rel about_since]
    call about_put
    call boot_ms_now
    xor edx, edx
    mov ecx, 1000
    div rcx
    mov rdi, rax
    call about_dec
    lea rdi, [rel about_seconds]
    call about_put
    call about_row
    lea rdi, [rel about_firmware_vendor]
    call about_put
    lea rdi, [rel smbios_bios_vendor]
    call about_firmware_value
    call about_row
    lea rdi, [rel about_firmware_version]
    call about_put
    lea rdi, [rel smbios_bios_version]
    call about_firmware_value
    call about_row
    lea rdi, [rel about_firmware_date]
    call about_put
    lea rdi, [rel smbios_bios_date]
    call about_firmware_value
    call about_row
    call settings_updates_status_text
    mov rdi, rax
    call about_put
.cached:
    lea rax, [rel about_os_buf]
    pop rbx
    ret

about_firmware_value:
    cmp byte [rel smbios_have_t0], 1
    je about_value
    lea rdi, [rel about_unavailable]
    jmp about_put
about_value:
    cmp byte [rdi], 0
    jne about_put
    lea rdi, [rel about_unavailable]
    jmp about_put
about_count:
    test rdi, rdi
    jnz about_dec
    lea rdi, [rel about_unavailable]
    jmp about_put
about_resolution:
    push rbx
    mov ebx, esi
    test edi, edi
    jz .unknown
    test ebx, ebx
    jz .unknown
    call about_dec
    lea rdi, [rel about_x]
    call about_put
    mov edi, ebx
    call about_dec
    pop rbx
    ret
.unknown:
    lea rdi, [rel about_unavailable]
    call about_put
    pop rbx
    ret
; Binary GiB quantities labelled GB by the requested native About convention.
; Two fractional digits, rounded down; the remainder multiply cannot overflow.
about_gb:
    push rbx
    mov rax, rdi
    xor edx, edx
    mov ecx, 1073741824
    div rcx
    mov rbx, rdx
    mov rdi, rax
    call about_dec
    lea rdi, [rel about_dot]
    call about_put
    imul rax, rbx, 100
    xor edx, edx
    mov ecx, 1073741824
    div rcx
    xor edx, edx
    mov ecx, 10
    div ecx
    add al, '0'
    add dl, '0'
    mov [rel about_fraction], al
    mov [rel about_fraction + 1], dl
    lea rdi, [rel about_fraction]
    call about_put
    lea rdi, [rel about_gb_unit]
    call about_put
    pop rbx
    ret
about_dec:
    lea rsi, [rel about_number]
    push rsi
    call fmt_dec
    pop rdi
    mov byte [rdi + rax], 0
    jmp about_put
about_reset:
    mov [rel about_cur], rdi
    lea rax, [rdi + ABOUT_CAP - 1]
    mov [rel about_end], rax
    mov dword [rel about_col], 0
    mov byte [rdi], 0
    ret
about_row:
    mov rax, [rel about_cur]
    cmp rax, [rel about_end]
    jae .out
    mov byte [rax], ','
    inc rax
    mov byte [rax], 0
    mov [rel about_cur], rax
    mov dword [rel about_col], 0
.out:
    ret
about_put:
    mov rsi, rdi
    mov rdx, [rel about_cur]
    mov ecx, [rel about_col]
    mov r8d, 128                       ; independent input-string bound
.next:
    dec r8d
    js .done
    mov al, [rsi]
    test al, al
    jz .done
    cmp rdx, [rel about_end]
    jae .done
    cmp ecx, ABOUT_COLS
    jb .char
    mov byte [rdx], ','
    inc rdx
    xor ecx, ecx
    cmp rdx, [rel about_end]
    jae .done
.char:
    cmp al, 32
    jb .replace
    cmp al, 126
    ja .replace
    cmp al, ','
    jne .store
    mov al, ';'
    jmp .store
.replace:
    mov al, '?'
.store:
    mov [rdx], al
    inc rdx
    inc ecx
    inc rsi
    jmp .next
.done:
    mov byte [rdx], 0
    mov [rel about_cur], rdx
    mov [rel about_col], ecx
    ret

; Three bounded CPUID brand leaves, no privileged instruction. Trim outer
; spaces only; actual producer sanitises controls and commas like other facts.
about_cpu_brand:
    push rbx
    push r12
    mov eax, 0x80000000
    call about_cpuid
    cmp eax, 0x80000004
    jb .unknown
    xor r12d, r12d
.leaf:
    lea eax, [r12d + 0x80000002]
    call about_cpuid
    imul r8d, r12d, 16
    lea r9, [rel about_brand]
    mov [r9 + r8], eax
    mov [r9 + r8 + 4], ebx
    mov [r9 + r8 + 8], ecx
    mov [r9 + r8 + 12], edx
    inc r12d
    cmp r12d, 3
    jb .leaf
    mov byte [rel about_brand + 48], 0
    lea rax, [rel about_brand]
.leading:
    cmp byte [rax], ' '
    jne .trim
    inc rax
    jmp .leading
.trim:
    lea rcx, [rel about_brand + 48]
.trailing:
    cmp rcx, rax
    jbe .out
    cmp byte [rcx - 1], ' '
    jne .out
    dec rcx
    mov byte [rcx], 0
    jmp .trailing
.unknown:
    lea rax, [rel about_unavailable]
.out:
    pop r12
    pop rbx
    ret
about_cpuid:
    xor ecx, ecx
    cpuid
    ret

; Called only after built-in form3 commits its own widgets, before any paint.
form_about_loaded:
    ; The boot form self-test precedes lock_screen_init, which replaces the
    ; hook root. Leave installation until the first actual desktop About load.
    cmp byte [rel lock_surface_ready], 1
    jne .hooked
    cmp byte [rel about_hooked], 1
    je .hooked
    mov rax, [rel wgt_click_hook]
    mov [rel about_click_prev], rax
    lea rax, [rel form_about_click]
    mov [rel wgt_click_hook], rax
    mov byte [rel about_hooked], 1
.hooked:
    call about_name_label
    mov eax, [rel form_active_slot + 3*4]
    lea rcx, [rel wm_h]
    mov dword [rcx + rax*4], 390
    xor esi, esi
    jmp about_details_visible

; ESI=0 collapsed/1 expanded. Flags belong to this exact live form window.
about_details_visible:
    push rbx
    push r12
    mov r12d, esi
    mov dword [rel about_detail_first], 0
    mov dword [rel about_detail_next], 0
    xor ebx, ebx
.next:
    cmp ebx, WGT_MAX
    jae .done
    mov edi, ebx
    call wgt_slot_ptr
    cmp dword [rax + WGI_TYPE], 0
    je .skip
    mov ecx, [rel form_active_slot + 3*4]
    cmp [rax + WGI_WIN], ecx
    jne .skip
    mov rdi, [rax + WGI_ID]
    test rdi, rdi
    jz .skip
    push rax
    lea rsi, [rel about_facts_id]
    call strcmp
    mov edx, eax
    pop rax
    test edx, edx
    jz .owned
    push rax
    mov rdi, [rax + WGI_ID]
    lea rsi, [rel about_next_id]
    call strcmp
    mov edx, eax
    pop rax
    test edx, edx
    jnz .skip
.owned:
    and dword [rax + WGI_FLAGS], ~1
    or [rax + WGI_FLAGS], r12d
.skip:
    inc ebx
    jmp .next
.done:
    mov [rel about_expanded], r12b
    call about_details_size
    pop r12
    pop rbx
    ret

form_about_click:
    push rbx
    push r12
    push r13
    mov r12d, edi
    cmp edi, WGT_MAX
    jae .chain
    cmp byte [rel session_locked], SESSION_LOCKED
    je .chain
    call wgt_slot_ptr
    cmp dword [rax + WGI_TYPE], WGT_TYPE_BUTTON
    jne .chain
    test dword [rax + WGI_FLAGS], 1
    jz .chain
    test dword [rax + WGI_EDIT], WGT_EDIT_DISABLED
    jnz .chain
    mov ebx, [rax + WGI_WIN]
    cmp ebx, WM_MAX
    jae .chain
    cmp ebx, [rel form_active_slot + 3*4]
    jne .chain
    mov r13, [rax + WGI_ID]
    lea rcx, [rel wm_state]
    cmp dword [rcx + rbx*4], WM_VISIBLE
    jne .chain
    lea rcx, [rel wm_title]
    lea rdx, [rel form_titles + 3*FORM_TITLE_MAX]
    cmp [rcx + rbx*8], rdx
    jne .chain
    lea rcx, [rel wm_owner]
    cmp qword [rcx + rbx*8], WM_OWNER_CHROME
    jne .chain
    test r13, r13
    jz .chain
    mov rdi, r13
    lea rsi, [rel about_device_copy_id]
    call strcmp
    test eax, eax
    jz .device
    mov rdi, r13
    lea rsi, [rel about_os_copy_id]
    call strcmp
    test eax, eax
    jz .os
    mov rdi, r13
    lea rsi, [rel about_next_id]
    call strcmp
    test eax, eax
    jz .next_details
    mov rdi, r13
    lea rsi, [rel about_advanced_id]
    call strcmp
    test eax, eax
    jnz .chain
    movzx esi, byte [rel about_expanded]
    xor esi, 1
    call about_details_visible
    lea rsi, [rel about_show]
    cmp byte [rel about_expanded], 0
    je .caption
    lea rsi, [rel about_hide]
.caption:
    mov edi, r12d
    call wgt_set_text
    call wmx_draw_all
    jmp .chain
.next_details:
    mov eax, [rel about_detail_next]
    mov [rel about_detail_first], eax
    call wmx_draw_all
    jmp .chain
.device:
    call form_about_device
    jmp .copy
.os:
    call form_about_os
.copy:
    mov rsi, rax
    call about_copy_rows
.chain:
    mov edi, r12d
    mov rax, [rel about_click_prev]
    pop r13
    pop r12
    pop rbx
    test rax, rax
    jz .out
    jmp rax
.out:
    ret

 ; Keep cards fixed; only the Advanced viewport grows. On a short display,
; Next details pages the unchanged diagnostic rows through a stock listview.
about_details_size:
    push rbx
    push r12
    mov r12d, 390
    cmp byte [rel about_expanded], 0
    je .height
    mov r12d, [rel fb_height]
    sub r12d, TASKBAR_H
    cmp r12d, 744
    jbe .minimum
    mov r12d, 744
.minimum:
    cmp r12d, 440
    jae .height
    mov r12d, 440
.height:
    mov eax, [rel form_active_slot + 3*4]
    lea rcx, [rel wm_h]
    mov [rcx + rax*4], r12d
    ; A disclosure resize cannot let generic bottom anchors overlap the cards.
    lea rcx, [rel wm_min_h]
    mov [rcx + rax*4], r12d
    mov edi, eax
    mov edx, [rel fb_height]
    sub edx, TASKBAR_H
    sub edx, r12d
    jnc .room
    xor edx, edx
.room:
    lea rcx, [rel wm_y]
    mov eax, [rcx + rdi*4]
    cmp eax, edx
    jbe .placed
    mov [rcx + rdi*4], edx
    sub edx, eax
    xor esi, esi
    call wgt_shift_window
.placed:
    xor ebx, ebx
.find:
    cmp ebx, WGT_MAX
    jae .done
    mov edi, ebx
    call wgt_slot_ptr
    mov ecx, [rel form_active_slot + 3*4]
    cmp [rax + WGI_WIN], ecx
    jne .advance
    mov rdi, [rax + WGI_ID]
    test rdi, rdi
    jz .advance
    push rax
    lea rsi, [rel about_facts_id]
    call strcmp
    mov edx, eax
    pop rax
    test edx, edx
    jnz .advance
    sub r12d, 390
    mov [rax + WGI_H], r12d
    jmp .done
.advance:
    inc ebx
    jmp .find
.done:
    pop r12
    pop rbx
    ret

; Preserve the full1024 diagnostic source and current learned projection,
; then append the live bounded per-core work rows. Stock Advanced/Next pages
; the whole source; CPU/card diagnostics and their original buffers stay intact.
; 1023 + comma + 511 + comma + 6143 + NUL = 7680 bytes.
form_about_details_source:
    push rbx
    push r12
    sub rsp,8
    call form_build_sysprops
    mov rsi,rax
    lea r12,[rel about_learned_source_buf]
    mov ebx,1023
.base:
    test ebx,ebx
    jz .report
    lodsb
    test al,al
    jz .report
    mov [r12],al
    inc r12
    dec ebx
    jmp .base
.report:
%ifdef PAOS_DRIVER_DOMAIN_EVERYBOOT
    call nd_learn_properties_text
    mov rsi,rax
    mov ebx,511
    call .append
%endif
    call form_percore_text
    mov rsi,rax
    mov ebx,6143
    call .append
    mov byte [r12],0
    lea rax,[rel about_learned_source_buf]
    add rsp,8
    pop r12
    pop rbx
    ret
.append:
    cmp byte [rsi],0
    je .appended
    lea rax,[rel about_learned_source_buf]
    cmp r12,rax
    je .extra
    mov byte [r12],','
    inc r12
.extra:
    test ebx,ebx
    jz .appended
    lodsb
    test al,al
    jz .appended
    mov [r12],al
    inc r12
    dec ebx
    jmp .extra
.appended:
    ret

; EDI=listview id; the full native diagnostic source remains byte-for-byte.
form_about_advanced:
    push rbx
    push r12
    call wgt_slot_ptr
    mov r12d, [rax + WGI_H]
    sub r12d, 30
    jbe .one
    mov eax, r12d
    xor edx, edx
    mov ecx, 18
    div ecx
    mov r12d, eax
    test eax, eax
    jnz .rows
.one:
    mov r12d, 1
.rows:
    call form_about_details_source
    mov rsi, rax
    mov ecx, [rel about_detail_first]
    xor ebx, ebx
    mov r8d, 7679
.skip:
    test ecx, ecx
    jz .copy
    dec r8d
    js .empty
    lodsb
    test al, al
    jz .empty
    cmp al, ','
    jne .skip
    dec ecx
    inc ebx
    jmp .skip
.copy:
    lea rdi, [rel about_detail_buf]
.next:
    dec r8d
    js .last
    lodsb
    test al, al
    jz .last
    cmp al, ','
    jne .store
    inc ebx
    dec r12d
    jz .page
.store:
    stosb
    jmp .next
.page:
    cmp byte [rsi], 0
    je .last
    mov [rel about_detail_next], ebx
    jmp .end
.empty:
    lea rdi, [rel about_detail_buf]
.last:
    mov dword [rel about_detail_next], 0
.end:
    mov byte [rdi], 0
    lea rax, [rel about_detail_buf]
    pop r12
    pop rbx
    ret

; Built-in known public card -> bounded text/plain. Reuse the clipboard's
; validated, locked commit; no CLIPSET dispatch or ambient command authority.
about_copy_rows:
    lea rdi, [rel about_copy_buf]
    xor ecx, ecx
.next:
    cmp ecx, ABOUT_CAP - 1
    jae .ready
    mov al, [rsi + rcx]
    test al, al
    jz .ready
    cmp al, ','
    jne .store
    mov al, 10
.store:
    mov [rdi + rcx], al
    inc ecx
    jmp .next
.ready:
    mov byte [rdi + rcx], 0
    mov rdx, rdi
    lea rdi, [rel about_media]
    mov esi, CLIP_KIND_INLINE
    xor r8d, r8d
    lea r9, [rel about_provenance]
    jmp clipboard_commit_entry

; ---------------------------------------------------------------------------
; Computer name (Peter 107784, T5-14 0.1: read-only, display only).
; about_device_name -> RAX the NUL name: "PAOS-" + 7 Crockford base32 chars of
; the top 35 bits of SHA-256 over the 16 SMBIOS type-1 UUID bytes as stored, or
; "Unavailable" when firmware gave none (absent, all 00 or all FF). Derived,
; never stored: no NVRAM/ESP/prefs record. Computed once (the UUID is fixed
; after boot) with its own hash context. 0.2 rename = an owner override.
; Clobbers caller-saved registers.
about_device_name:
    cmp byte [rel about_name_state], 0
    jne .done
    push rbx
    lea rbx, [rel about_unavailable]
    cmp byte [rel smbios_sys_uuid_present], 1
    jne .store
    lea rsi, [rel smbios_sys_uuid]
    xor ecx, ecx
    xor edx, edx                        ; OR of the bytes: 0 = all 00
    mov r8d, 0xff                       ; AND of the bytes: ff = all FF
.scan:
    movzx eax, byte [rsi + rcx]
    or edx, eax
    and r8d, eax
    inc ecx
    cmp ecx, 16
    jb .scan
    test edx, edx
    jz .store
    cmp r8d, 0xff
    je .store
    lea rdi, [rel about_name_ctx]
    call sha256_stream_init
    lea rdi, [rel about_name_ctx]
    lea rsi, [rel smbios_sys_uuid]
    mov edx, 16
    call sha256_stream_update
    test rax, rax
    jnz .store
    lea rdi, [rel about_name_ctx]
    lea rsi, [rel about_name_digest]
    call sha256_stream_final
    test rax, rax
    jnz .store
    lea rsi, [rel about_name_digest]
    xor eax, eax
    mov ecx, 5
.bits:
    shl rax, 8
    movzx edx, byte [rsi]
    or rax, rdx
    inc rsi
    dec ecx
    jnz .bits
    shr rax, 5                          ; the top 35 of the first 40 bits
    lea rdi, [rel about_name_text]
    mov dword [rdi], 'PAOS'
    mov byte [rdi + 4], '-'
    mov byte [rdi + 5 + ABOUT_NAME_CHARS], 0
    lea rdi, [rdi + 4 + ABOUT_NAME_CHARS]
    lea rsi, [rel about_name_b32]
    mov ecx, ABOUT_NAME_CHARS
.char:
    mov edx, eax
    and edx, 31
    movzx edx, byte [rsi + rdx]
    mov [rdi], dl
    dec rdi
    shr rax, 5
    dec ecx
    jnz .char
    lea rbx, [rel about_name_text]
.store:
    mov [rel about_name_ptr], rbx
    mov byte [rel about_name_state], 1
    pop rbx
.done:
    mov rax, [rel about_name_ptr]
    ret

; about_device_name_line -> RAX "Device name: <name>" (NUL, at most 25 bytes,
; under wgt_set_text's 31). Settings and About show the same line.
about_device_name_line:
    call about_device_name
    mov rsi, rax
    lea rdi, [rel about_name_line]
    lea rdx, [rel about_name_prefix]
    xor ecx, ecx
.prefix:
    mov al, [rdx + rcx]
    test al, al
    jz .name
    mov [rdi + rcx], al
    inc ecx
    jmp .prefix
.name:
    mov al, [rsi]
    mov [rdi + rcx], al
    test al, al
    jz .out
    inc rsi
    inc ecx
    cmp ecx, ABOUT_NAME_LINE - 1
    jb .name
    mov byte [rdi + rcx], 0
.out:
    lea rax, [rel about_name_line]
    ret

; The About window's device_name label (appended last in sysprops.frm, above
; the cards): found by id in form 3's live slot, as about_details_visible does.
about_name_label:
    push rbx
    xor ebx, ebx
.next:
    cmp ebx, WGT_MAX
    jae .out
    mov edi, ebx
    call wgt_slot_ptr
    cmp dword [rax + WGI_TYPE], 0
    je .skip
    mov ecx, [rel form_active_slot + 3*4]
    cmp [rax + WGI_WIN], ecx
    jne .skip
    mov rdi, [rax + WGI_ID]
    test rdi, rdi
    jz .skip
    lea rsi, [rel about_name_id]
    call strcmp
    test eax, eax
    jnz .skip
    call about_device_name_line
    mov edi, ebx
    mov rsi, rax
    call wgt_set_text
    jmp .out
.skip:
    inc ebx
    jmp .next
.out:
    pop rbx
    ret

about_name_b32: db '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
about_name_prefix: db 'Device name: ',0
about_name_id: db 'device_name',0
about_build: db 'Build: ',0
ABOUT_NAME_LINE equ 32

%include "core/abi/wdata.inc"
%include "gui/form_percore.inc"
%macro WDATA_gui_form_about 0
align 8
about_device_ms: dq 0
about_os_ms: dq 0
about_cur: dq 0
about_end: dq 0
about_click_prev: dq 0
about_map: times 24 db 0
about_col: dd 0
about_hooked: db 0
about_expanded: db 0
about_brand: times 49 db 0
about_number: times 32 db 0
about_fraction: db '00',0
about_device_buf: times ABOUT_CAP db 0
about_os_buf: times ABOUT_CAP db 0
about_copy_buf: times ABOUT_CAP db 0
about_unavailable: db 'Unavailable',0
about_maker: db 'Manufacturer: ',0
about_model: db 'Model: ',0
about_processor: db 'Processor: ',0
about_cores: db 'Cores: ',0
about_threads: db ' / Threads online: ',0
about_ram: db 'Installed RAM: ',0
about_usable_open: db ' (',0
about_usable_close: db ' usable)',0
about_system: db 'System type: 64-bit (x86-64)',0
about_native: db 'Display native: ',0
about_active: db 'Display active: ',0
about_x: db ' x ',0
about_dot: db '.',0
about_gb_unit: db ' GB',0
about_version: db 'Version: ',0
about_since: db 'Running since: ',0
about_seconds: db ' s ago',0
about_firmware_vendor: db 'Firmware vendor: ',0
about_firmware_version: db 'Firmware version: ',0
about_firmware_date: db 'Firmware date: ',0
about_facts_id: db 'facts',0
about_next_id: db 'details_next',0
about_detail_first: dd 0
about_detail_next: dd 0
about_detail_buf: times 7680 db 0
about_learned_source_buf: times 7680 db 0
about_device_copy_id: db 'device_copy',0
about_os_copy_id: db 'os_copy',0
about_advanced_id: db 'advanced_details',0
about_show: db 'Show Advanced details',0
about_hide: db 'Hide Advanced details',0
about_media: db 'text/plain',0
about_provenance: db 'About_this_PC',0

%endmacro
WDATA_DEFER WDATA_gui_form_about
%macro WDATA_BSS_gui_form_about_name 0
alignb 8
about_name_ptr:    resq 1
about_name_ctx:    resb S256_CTX_SZ
about_name_digest: resb 32
about_name_text:   resb 16
about_name_line:   resb ABOUT_NAME_LINE
about_name_state:  resb 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_form_about_name
