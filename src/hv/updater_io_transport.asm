;; MODULE hv/updater_io_transport
;; LAYER 5
;; EXPORTS updater_io_transport_pio, updater_io_transport_retire
;; IMPORTS hv/app_vm, hv/settings_update_service, fs/update_esp
;; CAPS
;; OWNER rc-vm-claude
;; CONTEXT: bsp_only
; Scalar32 only:50e8 START1/COMMIT2,status0 idle/1 reply/2 collecting/3 terminal.
; 50ec request48+APPEND bytes padded to dword, or op13 exact PCF1/1024;
; op14 FINISH exact zero-input request48. reply48+READ bytes padded0.
; FEED size1CURRENT/2AVAILABLE; FINISH size1/2CHECK or3STAGED native only.
; No guest address/device/path/binding/lease exists in this private protocol.
%include "core/abi/wdata.inc"
%ifndef PAOS_UPDATER_IO_INCLUDED
%define PAOS_UPDATER_IO_INCLUDED 1
UIO_LIMIT equ 67108864
UIO_OBJECTS equ 16

updater_io_transport_pio:
    push rbx
    push r12
    push r13
    mov ebx,edi
    mov r12d,esi
    mov r13d,edi
    shr r13d,16
    cmp r13d,0x50e8
    je .port
    cmp r13d,0x50ec
    jne .bad
.port:
    cmp dword [rel uio_busy],0
    jne .bad
    mov dword [rel uio_busy],1
    cmp dword [rel uio_state],2
    je .zero
    call uio_current
    cmp eax,1
    je .qualified
    cmp dword [rel uio_state],0
    je .zero                       ; an ordinary app cannot poison future role
    jmp .terminal
.qualified:
    mov eax,ebx
    and eax,0xffbf
    cmp eax,3
    je .width
    cmp eax,11
    jne .terminal
.width:
    cmp r13d,0x50ec
    je .data
    test ebx,8
    jnz .status
    cmp r12d,1
    je .start
    cmp r12d,2
    jne .terminal
    cmp dword [rel uio_phase],2
    jne .terminal
    mov eax,[rel uio_received]
    cmp eax,[rel uio_expected]
    jne .terminal
    cmp eax,48
    jb .terminal
    mov rax,[rel uio_last_sequence]
    cmp rax,-1
    je .terminal
    inc rax
    cmp rax,[rel uio_request]
    jne .terminal
    mov [rel uio_last_sequence],rax ; consumed before any effect
    call uio_decode
    call uio_current
    cmp eax,1
    jne .terminal
    mov dword [rel uio_phase],1
    mov dword [rel uio_cursor],0
    mov eax,48
    cmp dword [rel uio_request+28],5
    jne .response
    add eax,[rel uio_reply+40]
    add eax,3
    and eax,~3
.response:
    mov [rel uio_response_bytes],eax
    jmp .zero
.start:
    cmp dword [rel uio_phase],0
    jne .terminal
    lea rdi,[rel uio_request]
    xor eax,eax
    mov ecx,12
    cld
    rep stosd
    call uio_wipe
    mov dword [rel uio_received],0
    mov dword [rel uio_expected],48
    mov dword [rel uio_phase],2
    jmp .zero
.status:
    mov edx,[rel uio_phase]
    jmp .done
.data:
    test ebx,8
    jnz .read
    cmp dword [rel uio_phase],2
    jne .terminal
    mov ecx,[rel uio_received]
    cmp ecx,[rel uio_expected]
    jae .terminal
    cmp ecx,48
    jae .payload
    lea rax,[rel uio_request]
    mov [rax+rcx],r12d
    add ecx,4
    mov [rel uio_received],ecx
    cmp ecx,48
    jne .zero
    cmp dword [rel uio_request+24],1
    jne .terminal
    cmp dword [rel uio_request+28],14
    je .finish_header
    cmp dword [rel uio_request+28],13
    je .feed_header
    cmp dword [rel uio_request+28],7
    jne .zero
    mov eax,[rel uio_request+40]
    cmp eax,4096
    ja .terminal
    add eax,3
    and eax,~3
    add eax,48
    mov [rel uio_expected],eax
    jmp .zero
.finish_header:
    ; No result/flags supplied by worker. One trigger on the original binding;
    ; actual native receiver alone assesses complete delivery, release and media.
    cmp dword [rel uio_finish_attempted],0
    jne .terminal
    cmp dword [rel uio_poison],0
    jne .terminal
    cmp qword [rel uio_request+8],0
    jne .terminal
    cmp qword [rel uio_request+16],0
    jne .terminal
    cmp qword [rel uio_request+32],0
    jne .terminal
    cmp qword [rel uio_request+40],0
    jne .terminal
    mov rax,[rel uio_last_sequence]
    cmp rax,-1
    je .terminal
    inc rax
    cmp rax,[rel uio_request]
    jne .terminal
    mov eax,[rel uio_original+8]
    dec eax
    cmp eax,1
    ja .terminal
    mov dword [rel uio_finish_attempted],1
    jmp .zero
.feed_header:
    ; One attempt for this original: reserve at the canonical complete header,
    ; before any bytes arrive or native callback can run. Never cleared by START.
    cmp dword [rel uio_feed_attempted],0
    jne .terminal
    cmp dword [rel uio_poison],0
    jne .terminal
    cmp qword [rel uio_request+8],0
    jne .terminal
    cmp qword [rel uio_request+16],0
    jne .terminal
    cmp qword [rel uio_request+32],0
    jne .terminal
    cmp dword [rel uio_request+40],1024
    jne .terminal
    cmp dword [rel uio_request+44],0
    jne .terminal
    mov rax,[rel uio_last_sequence]
    cmp rax,-1
    je .terminal
    inc rax
    cmp rax,[rel uio_request]
    jne .terminal
    mov eax,[rel uio_original+8]
    dec eax
    cmp eax,1
    ja .terminal
    mov dword [rel uio_feed_attempted],1
    mov dword [rel uio_expected],1072
    jmp .zero
.payload:
    sub ecx,48
    cmp ecx,4096
    jae .terminal
    lea rax,[rel uio_buffer]
    mov [rax+rcx],r12d
    add ecx,52
    mov [rel uio_received],ecx
    jmp .zero
.read:
    cmp dword [rel uio_phase],1
    jne .terminal
    mov ecx,[rel uio_cursor]
    cmp ecx,[rel uio_response_bytes]
    jae .terminal
    cmp ecx,48
    jae .read_payload
    lea rax,[rel uio_reply]
    jmp .word
.read_payload:
    sub ecx,48
    lea rax,[rel uio_buffer]
.word:
    mov edx,[rax+rcx]
    mov eax,[rel uio_cursor]
    add eax,4
    mov [rel uio_cursor],eax
    cmp eax,[rel uio_response_bytes]
    jne .done
    mov dword [rel uio_phase],0
    push rdx
    call uio_wipe
    pop rdx
    jmp .done
.terminal:
    call uio_terminal
.zero:
    xor edx,edx
    cmp dword [rel uio_state],2
    jne .done
    test ebx,8
    jz .done
    cmp r13d,0x50e8
    jne .done
    mov edx,3
.done:
    mov dword [rel uio_busy],0
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
    xor edx,edx
.out:
    pop r13
    pop r12
    pop rbx
    ret

; All original168 bytes native-owned, independently obtained on every word.
uio_current:
    sub rsp,8
    lea rdi,[rel uio_exit]
    mov esi,128
    call app_vm_updater_exit
    cmp eax,1
    jne .no
    lea rdi,[rel uio_check]
    mov esi,40
    lea rdx,[rel uio_check+40]
    mov ecx,128
    call settings_update_service_original
    cmp eax,1
    jne .no
    lea rdi,[rel uio_exit]
    lea rsi,[rel uio_check+40]
    mov ecx,16
    cld
    repe cmpsq
    jne .no
    cmp dword [rel uio_state],0
    jne .retained
    lea rdi,[rel uio_original]
    lea rsi,[rel uio_check]
    mov ecx,21
    rep movsq
    mov dword [rel uio_state],1
.retained:
    lea rdi,[rel uio_original]
    lea rsi,[rel uio_check]
    mov ecx,21
    repe cmpsq
    jne .no
    cmp qword [rel uio_binding],0
    je .yes
    mov rdi,[rel uio_binding]
    mov esi,2
    call update_esp_current
    cmp eax,1
    jne .no
.yes:
    mov eax,1
    add rsp,8
    ret
.no:
    xor eax,eax
    add rsp,8
    ret
uio_wipe:
    lea rdi,[rel uio_buffer]
    xor eax,eax
    mov ecx,512
    cld
    rep stosq
    ret
uio_terminal:
    sub rsp,8
    mov dword [rel uio_state],2
    mov dword [rel uio_phase],0
    mov dword [rel uio_poison],1
    call uio_wipe
    call uio_restore_ro
    call uio_freeze
    add rsp,8
    ret
; Existing device retirement or failed actual closed exit. No reset/rebind,
; CPU mutation or lease release. An unbound ordinary app remains harmless.
updater_io_transport_retire:
    cmp dword [rel uio_state],1
    jne .out
    cmp dword [rel uio_busy],0
    jne .out
    mov dword [rel uio_busy],1
    sub rsp,8
    call uio_terminal
    add rsp,8
    mov dword [rel uio_busy],0
.out: ret
uio_freeze:
    cmp qword [rel uio_binding],0
    je .out
    cmp dword [rel uio_frozen],0
    jne .out
    mov dword [rel uio_frozen],1
    mov rdi,[rel uio_binding]
    jmp update_esp_freeze
.out: ret

; Native table entries id/directory/fixedID0(unpublished temp).
uio_object:
    test rdx,rdx
    jz .no
    lea rax,[rel uio_objects]
    mov ecx,UIO_OBJECTS
.loop:
    cmp [rax],rdx
    je .out
    add rax,24
    loop .loop
.no: xor eax,eax
.out: ret
uio_empty:
    lea rax,[rel uio_objects]
    mov ecx,UIO_OBJECTS
.loop:
    cmp qword [rax],0
    je .out
    add rax,24
    loop .loop
    xor eax,eax
.out: ret
uio_directory:
    cmp eax,1
    jb .no
    cmp eax,8
    ja .no
    cmp eax,2
    jbe .vault
    cmp eax,6
    jbe .state
    mov eax,3
    ret
.vault: mov eax,1
    ret
.state: mov eax,2
    ret
.no: xor eax,eax
    ret
uio_limit:
    mov eax,[rax+16]
uio_file_limit:
    cmp eax,1
    je .manifest
    cmp eax,2
    je .key
    cmp eax,3
    jb .large
    cmp eax,6
    ja .large
    mov eax,512
    ret
.manifest: mov eax,1024
    ret
.key: mov eax,4096
    ret
.large: mov eax,UIO_LIMIT
    ret
uio_stat:
    sub rsp,8
    mov rdi,[rel uio_binding]
    mov esi,2
    mov rax,[rel uio_slot]
    mov rdx,[rax]
    xor ecx,ecx
    lea r8,[rel uio_stat_buffer]
    mov r9d,32
    call uio_fs_io
    test rax,rax
    jnz .no
    mov rax,[rel uio_slot]
    mov rdx,[rax]
    cmp rdx,[rel uio_stat_buffer]
    jne .no
    call uio_limit
    cmp [rel uio_stat_buffer+8],rax
    ja .no
    cmp qword [rel uio_stat_buffer+16],0
    jle .no
    cmp qword [rel uio_stat_buffer+24],1
    jne .no
    mov rax,[rel uio_stat_buffer+8]
    mov [rel uio_reply+16],rax
    mov rax,[rel uio_stat_buffer+16]
    mov [rel uio_reply+24],rax
    mov eax,1
    add rsp,8
    ret
.no:
    xor eax,eax
    add rsp,8
    ret

; C48 data envelope, canonical unused fields0, actual native IO op mapping.
uio_decode:
    push rbx
    push r12
    push r13
    lea rdi,[rel uio_reply]
    xor eax,eax
    mov ecx,6
    cld
    rep stosq
    mov rax,[rel uio_request]
    mov [rel uio_reply],rax
    mov dword [rel uio_reply+32],1
    mov dword [rel uio_reply+36],2
    mov ebx,[rel uio_request+28]
    cmp ebx,1
    jb .refused
    cmp ebx,14
    ja .refused
    je .finish_shape
    cmp ebx,13
    je .feed_shape
    cmp dword [rel uio_request+40],4096
    ja .refused
    cmp qword [rel uio_request+16],UIO_LIMIT
    ja .refused
    cmp ebx,2
    jne .mutation
    cmp dword [rel uio_request+44],1
    je .authority                 ; RO restoration cannot enable effects
.mutation:
    cmp ebx,2
    je .download
    cmp ebx,6
    jb .authority
    cmp ebx,12
    je .authority
.download:
    cmp dword [rel uio_original+8],2
    jne .refused
.authority:
    cmp dword [rel uio_poison],0
    je .shape
    cmp ebx,12
    je .shape
    cmp ebx,2
    jne .refused
    cmp dword [rel uio_request+44],1
    jne .refused
.shape:
    mov r12,[rel uio_request+8]
    mov r13d,[rel uio_request+32]
    cmp ebx,1
    je .no_object
    cmp ebx,2
    je .no_object
    cmp ebx,3
    je .no_object
    cmp ebx,6
    je .no_object
    cmp ebx,9
    je .no_object
    test r12,r12
    jz .refused
    jmp .fields
.no_object:
    test r12,r12
    jnz .refused
.fields:
    cmp ebx,5
    je .offset
    cmp ebx,7
    je .offset
    cmp qword [rel uio_request+16],0
    jne .refused
.offset:
    cmp ebx,3
    je .file
    cmp ebx,10
    je .file
    test r13d,r13d
    jnz .refused
    jmp .dir
.file:
    mov eax,r13d
    call uio_directory
    test eax,eax
    jz .refused
.dir:
    cmp ebx,6
    je .directory
    cmp ebx,9
    je .directory
    cmp ebx,10
    je .directory
    cmp dword [rel uio_request+36],0
    jne .refused
    jmp .count
.directory:
    mov eax,[rel uio_request+36]
    dec eax
    cmp eax,2
    ja .refused
.count:
    cmp ebx,5
    je .ro
    cmp ebx,7
    je .ro
    cmp dword [rel uio_request+40],0
    jne .refused
.ro:
    cmp ebx,1
    je .current_ro
    cmp ebx,2
    je .set_ro
    cmp dword [rel uio_request+44],0
    jne .refused
    jmp .binding
.current_ro:
    cmp dword [rel uio_request+44],2
    ja .refused
    jmp .binding
.set_ro:
    cmp dword [rel uio_request+44],1
    ja .refused
    jmp .binding
.finish_shape:
    cmp dword [rel uio_finish_attempted],1
    jne .refused
    cmp dword [rel uio_poison],0
    jne .refused
    cmp qword [rel uio_request+8],0
    jne .refused
    cmp qword [rel uio_request+16],0
    jne .refused
    cmp qword [rel uio_request+32],0
    jne .refused
    cmp qword [rel uio_request+40],0
    jne .refused
    jmp .binding
.feed_shape:
    cmp dword [rel uio_feed_attempted],1
    jne .refused
    cmp dword [rel uio_poison],0
    jne .refused
    cmp qword [rel uio_request+8],0
    jne .refused
    cmp qword [rel uio_request+16],0
    jne .refused
    cmp qword [rel uio_request+32],0
    jne .refused
    cmp dword [rel uio_request+40],1024
    jne .refused
    cmp dword [rel uio_request+44],0
    jne .refused
.binding:
    cmp qword [rel uio_binding],0
    jne .bound
    cmp dword [rel uio_begin_attempted],0
    jne .refused
    mov dword [rel uio_begin_attempted],1
    call update_esp_begin
    test rax,rax
    jle .refused
    mov [rel uio_binding],rax
.bound:
    call uio_current
    cmp eax,1
    jne .refused
    cmp ebx,14
    je .finish
    cmp ebx,13
    je .feed
    cmp ebx,1
    je .current
    cmp ebx,2
    je .readonly
    cmp ebx,3
    je .open
    cmp ebx,6
    je .temp
    cmp ebx,9
    je .barrier
    mov rdx,r12
    call uio_object
    test rax,rax
    jz .refused
    mov [rel uio_slot],rax
    mov [rel uio_reply+8],r12
    call uio_stat
    cmp eax,1
    jne .uncertain
    cmp ebx,4
    je .ok
    cmp ebx,5
    je .read
    cmp ebx,7
    je .append
    cmp ebx,8
    je .sync
    cmp ebx,10
    je .replace
    cmp ebx,11
    je .discard
    mov esi,9                    ; C CLOSE12 -> FS CLOSE9
    jmp .close
.finish:
    mov rdi,[rel uio_binding]
    call update_esp_finish
    cmp rax,-1
    je .refused
    cmp rax,-2
    je .refused
    cmp dword [rel uio_original+8],1
    jne .finish_download
    cmp rax,1
    je .feed_class
    cmp rax,2
    je .feed_class
    jmp .uncertain
.finish_download:
    cmp dword [rel uio_original+8],2
    jne .uncertain
    cmp rax,3
    je .feed_class
    jmp .uncertain
.feed:
    ; Actual original/custody guard above is adjacent to this fixed native call.
    ; Original bytes only; the native receiver authenticates/classifies them.
    mov rdi,[rel uio_binding]
    lea rsi,[rel uio_buffer]
    mov edx,1024
    call update_esp_feed
    cmp rax,1
    je .feed_class
    cmp rax,2
    je .feed_class
    cmp rax,-1
    je .refused
    cmp rax,-2
    je .refused
    jmp .uncertain
.feed_class:
    mov [rel uio_reply+16],rax
    jmp .ok
.current:
    mov rdi,[rel uio_binding]
    mov esi,[rel uio_request+44]
    call update_esp_current
    cmp eax,1
    jne .refused
    jmp .ok
.readonly:
    mov rdi,[rel uio_binding]
    mov esi,[rel uio_request+44]
    call update_esp_readonly
    cmp eax,1
    jne .refused
    jmp .ok
.open:
    call uio_empty
    test rax,rax
    jz .refused
    mov [rel uio_slot],rax
    mov esi,1
    mov edx,r13d
    jmp .create
.temp:
    call uio_empty
    test rax,rax
    jz .refused
    mov [rel uio_slot],rax
    mov esi,4
    mov edx,[rel uio_request+36]
.create:
    mov rdi,[rel uio_binding]
    xor ecx,ecx
    xor r8d,r8d
    xor r9d,r9d
    call uio_fs_io
    test rax,rax
    jle .native_error
    mov rdx,rax
    call uio_object
    test rax,rax
    jnz .uncertain
    mov rax,[rel uio_slot]
    mov [rax],rdx
    mov [rel uio_reply+8],rdx
    mov [rax+16],r13
    cmp ebx,6
    je .temp_directory
    mov eax,r13d
    call uio_directory
    jmp .save_directory
.temp_directory:
    mov eax,[rel uio_request+36]
.save_directory:
    mov rdx,[rel uio_slot]
    mov [rdx+8],rax
    call uio_stat
    cmp eax,1
    jne .uncertain
    jmp .ok
.read:
    mov rcx,[rel uio_request+16]
    mov eax,[rel uio_request+40]
    add rax,rcx
    jc .refused
    cmp rax,UIO_LIMIT
    ja .refused
    mov esi,3
    call uio_data_io
    test rax,rax
    js .native_error
    mov edx,[rel uio_request+40]
    cmp rax,rdx
    ja .uncertain
    mov rdx,[rel uio_request+16]
    test rax,rax
    jz .read_result
    add rdx,rax
    jc .uncertain
    cmp rdx,[rel uio_reply+16]
    ja .uncertain
.read_result:
    mov [rel uio_reply+40],eax
    jmp .ok
.append:
    mov rax,[rel uio_slot]
    cmp qword [rax+16],0
    jne .refused
    mov rcx,[rel uio_request+16]
    cmp rcx,[rel uio_reply+16]
    jne .refused
    mov eax,[rel uio_request+40]
    add rax,rcx
    jc .refused
    cmp rax,UIO_LIMIT
    ja .refused
    mov ecx,[rel uio_request+40]
    mov edx,ecx
    add edx,3
    and edx,~3
    lea rax,[rel uio_buffer]
.padding:
    cmp ecx,edx
    jae .append_io
    cmp byte [rax+rcx],0
    jne .refused
    inc ecx
    jmp .padding
.append_io:
    mov esi,5
    mov rcx,[rel uio_request+16]
    call uio_data_io
    test rax,rax
    js .native_error
    mov edx,[rel uio_request+40]
    cmp rax,rdx
    jne .uncertain
    mov [rel uio_reply+40],eax
    jmp .ok
.sync:
    mov esi,6
    jmp .object_io
.barrier:
    mov esi,7
    mov edx,[rel uio_request+36]
    jmp .simple_io
.replace:
    cmp r13d,2
    je .refused
    mov rax,[rel uio_slot]
    cmp qword [rax+16],0
    jne .refused
    mov eax,r13d
    call uio_directory
    cmp eax,[rel uio_request+36]
    jne .refused
    mov rdx,[rel uio_slot]
    cmp rax,[rdx+8]
    jne .refused
    mov eax,r13d
    call uio_file_limit
    cmp [rel uio_reply+16],rax
    ja .refused
    mov esi,8
    mov ecx,r13d
    call uio_object_io
    test rax,rax
    jnz .native_error
    mov rax,[rel uio_slot]
    mov [rax+16],r13
    call uio_stat
    cmp eax,1
    jne .uncertain
    jmp .ok
.discard:
    mov rax,[rel uio_slot]
    cmp qword [rax+16],0
    jne .refused
    mov esi,10
.close:
    xor ecx,ecx
    call uio_object_io
    test rax,rax
    jnz .native_error
    mov rax,[rel uio_slot]
    mov qword [rax],0
    jmp .ok
.object_io:
    xor ecx,ecx
    call uio_object_io
    jmp .simple_result
.simple_io:
    mov rdi,[rel uio_binding]
    xor ecx,ecx
    xor r8d,r8d
    xor r9d,r9d
    call uio_fs_io
.simple_result:
    test rax,rax
    jnz .native_error
.ok:
    mov dword [rel uio_reply+36],0
    cmp ebx,5
    je .out
    call uio_wipe
    jmp .out
.native_error:
    cmp rax,-4
    jne .not_absent
    cmp ebx,3
    jne .uncertain
    mov dword [rel uio_reply+36],1
    jmp .error_data
.not_absent:
    cmp rax,-3
    je .uncertain
    cmp rax,-1
    je .refused
    cmp rax,-2
    jne .uncertain
.refused:
    mov dword [rel uio_reply+36],2
    cmp ebx,2
    je .poison
    cmp ebx,6
    jb .error_data
    cmp ebx,12
    je .error_data
    jmp .poison
.uncertain:
    mov dword [rel uio_reply+36],3
    mov dword [rel uio_poison],1
    call uio_restore_ro
    call uio_freeze              ; uncertain/contradictory effect quarantined
    jmp .error_data
.poison:
    mov dword [rel uio_poison],1
    call uio_restore_ro
.error_data:
    mov dword [rel uio_reply+40],0
    call uio_wipe
.out:
    pop r13
    pop r12
    pop rbx
    ret

uio_restore_ro:
    cmp qword [rel uio_binding],0
    je .out
    mov rdi,[rel uio_binding]
    mov esi,1
    jmp update_esp_readonly       ; safety attempt; result confers no success
.out: ret
uio_data_io:
    mov rdi,[rel uio_binding]
    mov rdx,[rel uio_request+8]
    lea r8,[rel uio_buffer]
    mov r9d,[rel uio_request+40]
    jmp uio_fs_io
uio_object_io:
    mov rdi,[rel uio_binding]
    mov rax,[rel uio_slot]
    mov rdx,[rax]
    xor r8d,r8d
    xor r9d,r9d
    jmp uio_fs_io

; Preserve the six native scalar/buffer operands across the independent guard.
; A callback that invalidates the original cannot authorize the following IO.
uio_fs_io:
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    sub rsp,8
    call uio_current
    add rsp,8
    pop r9
    pop r8
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    cmp eax,1
    jne .no
    jmp update_esp_io
.no:
    mov rax,-3
    ret

%macro WDATA_hv_updater_io_transport 0
align 8
uio_state_begin:
uio_state: dd 0
uio_busy: dd 0
uio_phase: dd 0
uio_poison: dd 0
uio_frozen: dd 0
uio_begin_attempted: dd 0
uio_feed_attempted: dd 0
uio_finish_attempted: dd 0
uio_received: dd 0
uio_expected: dd 0
uio_cursor: dd 0
uio_response_bytes: dd 0
align 8
uio_last_sequence: dq 0
uio_binding: dq 0
uio_slot: dq 0
uio_original: times 168 db 0
uio_check: times 168 db 0
uio_exit: times 128 db 0
uio_request: times 48 db 0
uio_reply: times 48 db 0
uio_stat_buffer: times 32 db 0
uio_objects: times UIO_OBJECTS*24 db 0
uio_buffer: times 4096 db 0
uio_state_end:
%endmacro
WDATA_DEFER WDATA_hv_updater_io_transport
%endif
