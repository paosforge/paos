;; MODULE dev/usb/uac1_function
;; LAYER 3
;; EXPORTS uac1_fs_function_parse
;; IMPORTS uac1_fs_stream_parse
;; CAPS
;; OWNER rc-codex-av
; Pure selected UAC1 function provenance. No USB transactions or binding.
; RDI complete config*, RSI bytes9..4096, RDX selector (interface|alt<<8|IN<<16),
; RCX rate, R8 channels, R9 caller-owned128B result. EAX0/-1.
; Mapped disjoint caller spans; refusal leaves all output bytes untouched.
; Result first64B is uac1_fs_stream_parse, next64B documented provenance.
uac1_fs_function_parse:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,840                       ; private output, map256*u16, locals
    mov rbp,rsp                       ; 16-byte alignment at every call
    mov r12,rdi
    mov r13,rsi
    mov r14,r9
    mov r15,rdx
    mov rbx,rcx
    test rdi,rdi
    jz .no
    cmp rsi,9
    jb .no
    cmp rsi,4096
    ja .no
    mov rax,rdi
    add rax,rsi
    jc .no
    mov rcx,rax
    dec rcx
    shr rcx,47
    jnz .no
    test r9,r9
    jz .no
    mov r10,r9
    add r10,128
    jc .no
    mov rcx,r10
    dec rcx
    shr rcx,47
    jnz .no
    cmp rdi,r10
    jae .disjoint
    cmp r9,rax
    jb .no
.disjoint:
    cmp rdx,0x1ffff
    ja .no
    test edx,0xff00                    ; nonzero selected alternate
    jz .no
    cmp rbx,8000
    jb .no
    cmp rbx,192000
    ja .no
    cmp r8,1
    jb .no
    cmp r8,2
    ja .no
    mov r10,r8
    mov rdi,rbp
    xor eax,eax
    mov ecx,105
    cld
    rep stosq
    mov [rbp+696],r10                 ; requested channels
    cmp word [r12],0x0209
    jne .no
    movzx eax,word [r12+2]
    cmp rax,r13
    jne .no
    cmp byte [r12+5],0                ; configuration value zero is reserved
    je .no
    movzx eax,byte [r12+7]
    and eax,0x9f
    cmp eax,0x80                      ; mandatory bit7, no reserved low bits
    jne .no
    mov esi,9
.scan:
    cmp rsi,r13
    je .scanned
    lea rax,[rsi+2]
    cmp rax,r13
    ja .no
    movzx r10d,byte [r12+rsi]
    cmp r10d,2
    jb .no
    lea rax,[rsi+r10]
    cmp rax,r13
    ja .no
    cmp byte [r12+rsi+1],2            ; nested config is not an interface member
    je .no
    cmp byte [r12+rsi+1],4
    jne .next
    cmp r10d,9
    jne .no
    cmp qword [rbp+640],0             ; selected AS span ends at next interface
    je .interface
    cmp qword [rbp+648],0
    jne .interface
    mov [rbp+648],rsi
.interface:
    lea rdx,[r12+rsi]
    movzx eax,byte [rdx+2]
    bts dword [rbp+736],eax           ; bounded32B unique-interface census
    jc .seen_interface
    inc dword [rbp+768]
.seen_interface:
    cmp al,r15b
    jne .control
    cmp word [rdx+5],0x0201
    jne .no
    cmp byte [rdx+7],0
    jne .no
    cmp byte [rdx+3],0
    jne .selected_alt
    cmp byte [rdx+4],0
    jne .no
    inc dword [rbp+704]
    cmp dword [rbp+704],1
    ja .no
.selected_alt:
    mov rax,r15
    shr eax,8
    cmp al,[rdx+3]
    jne .control
    inc dword [rbp+708]
    cmp dword [rbp+708],1
    ja .no
    mov [rbp+640],rsi
.control:
    cmp word [rdx+5],0x0101
    jne .next
    cmp byte [rdx+7],0
    je .control_version
    cmp byte [rdx+7],4                ; legacy QEMU basic-audio AC protocol
    jne .next                        ; UAC2/3 remain different descriptor ABIs
.control_version:
    ; Both accepted AC spellings must still declare actual UAC1 bcdADC0100.
    ; Selected AS interfaces independently require protocol0 above.
    lea rdi,[rsi+9]
    lea rax,[rdi+8]
    cmp rax,r13
    ja .no
    add rdi,r12
    cmp word [rdi+1],0x0124
    jne .no
    cmp word [rdi+3],0x0100
    jne .no
    movzx ecx,byte [rdi+7]
    test ecx,ecx
    jz .no
    cmp ecx,32
    ja .no
    lea eax,[rcx+8]
    cmp al,[rdi]
    jne .no
    lea rax,[rsi+9+rax]
    cmp rax,r13
    ja .no
    xor r8d,r8d
    xor r11d,r11d
.collection:
    movzx eax,byte [rdi+r11+8]
    cmp al,[rdx+2]                    ; AC cannot name itself as AS
    je .no
    xor r9d,r9d
.collection_unique:
    cmp r9d,r11d
    je .collection_match
    cmp al,[rdi+r9+8]
    je .no
    inc r9d
    jmp .collection_unique
.collection_match:
    cmp al,r15b
    jne .collection_next
    inc r8d
.collection_next:
    inc r11d
    cmp r11d,ecx
    jb .collection
    test r8d,r8d
    jz .next
    inc dword [rbp+712]
    cmp dword [rbp+712],1
    ja .no                           ; no two functions may claim selection
    cmp byte [rdx+3],0
    jne .no
    cmp byte [rdx+4],0                ; supported AC subset has no status EP
    jne .no
    movzx eax,word [rdi+5]
    movzx ecx,byte [rdi]
    cmp eax,ecx
    jb .no
    lea rcx,[rsi+9]
    mov [rbp+656],rcx
    add rax,rcx
    cmp rax,r13
    ja .no
    mov [rbp+664],rax
    movzx eax,byte [rdx+2]
    mov [rbp+672],rax
.next:
    add rsi,r10
    jmp .scan
.scanned:
    cmp dword [rbp+704],1
    jne .no
    cmp dword [rbp+708],1
    jne .no
    cmp dword [rbp+712],1
    jne .no
    movzx eax,byte [r12+4]
    cmp eax,[rbp+768]
    jne .no
    cmp qword [rbp+648],0
    jne .map_start
    mov [rbp+648],r13
.map_start:
    mov rsi,[rbp+664]
    cmp rsi,r13
    je .map_header
    lea rax,[rsi+2]
    cmp rax,r13
    ja .no
    cmp byte [r12+rsi+1],4            ; declared AC length ends with AC span
    jne .no
.map_header:
    mov rsi,[rbp+656]
    movzx eax,byte [r12+rsi]
    add rsi,rax
.map:
    cmp rsi,[rbp+664]
    je .mapped
    lea rax,[rsi+4]
    cmp rax,[rbp+664]
    ja .no
    lea rdi,[r12+rsi]
    movzx ecx,byte [rdi]
    lea rax,[rsi+rcx]
    cmp rax,[rbp+664]
    ja .no
    cmp byte [rdi+1],0x24
    jne .no
    movzx edx,byte [rdi+3]
    test edx,edx
    jz .no
    cmp word [rbp+128+rdx*2],0
    jne .no
    cmp byte [rdi+2],2
    je .input
    cmp byte [rdi+2],3
    je .output
    cmp byte [rdi+2],6
    jne .no                          ; no selector/mixer/processing/extension
    cmp ecx,9
    jb .no
    cmp byte [rdi+4],0
    je .no
    cmp byte [rdi+5],1
    jb .no
    cmp byte [rdi+5],4
    ja .no
    jmp .entity
.input:
    cmp ecx,12
    jne .no
    cmp byte [rdi+6],0                ; association not supported by this subset
    jne .no
    cmp byte [rdi+7],1
    jb .no
    cmp byte [rdi+7],2
    ja .no
    movzx eax,word [rdi+4]
    cmp eax,0x0101
    je .entity
    cmp eax,0x0402                    ; headset
    je .entity
    sub eax,0x0201                    ; six microphone terminal types
    cmp eax,5
    ja .no
    jmp .entity
.output:
    cmp ecx,9
    jne .no
    cmp byte [rdi+6],0
    jne .no
    cmp byte [rdi+7],0
    je .no
    movzx eax,word [rdi+4]
    cmp eax,0x0101
    je .entity
    cmp eax,0x0402
    je .entity
    sub eax,0x0301                    ; seven speaker/headphone terminal types
    cmp eax,6
    ja .no
.entity:
    inc dword [rbp+716]
    cmp dword [rbp+716],64
    ja .no
    mov [rbp+128+rdx*2],si
    add rsi,rcx
    jmp .map
.mapped:
    mov dword [rbp+780],1
.validate_graph:
    mov eax,[rbp+780]
    movzx ecx,word [rbp+128+rax*2]
    test ecx,ecx
    jz .graph_next
    cmp byte [r12+rcx+2],2
    je .graph_next
    call uac1_fs_function_walk
    test eax,eax
    jz .no                           ; dangling/wrong-kind/cycle/cluster mismatch
.graph_next:
    inc dword [rbp+780]
    cmp dword [rbp+780],256
    jb .validate_graph
    mov rsi,[rbp+648]
    sub rsi,[rbp+640]
    mov [rbp+688],rsi
    mov rdi,[rbp+640]
    add rdi,r12
    mov rdx,r15
    shr edx,16
    mov rcx,rbx
    mov r8,[rbp+696]
    mov r9,rbp
    call uac1_fs_stream_parse          ; reviewed parser writes private prefix
    test eax,eax
    jnz .no
    mov eax,[rbp+8]                   ; selected stream terminal link
    mov [rbp+784],eax
    movzx ecx,word [rbp+128+rax*2]
    test ecx,ecx
    jz .no
    lea rdi,[r12+rcx]
    cmp word [rdi+4],0x0101
    jne .no
    test r15d,0x10000
    jz .output_route
    cmp byte [rdi+2],3                ; IN endpoint links USB Output Terminal
    jne .no
    call uac1_fs_function_walk
    test eax,eax
    jz .no
    cmp edx,[rbp+696]
    jne .no
    mov [rbp+88],eax                  ; physical Input Terminal ID
    mov edx,[rbp+784]
    mov [rbp+92],edx                  ; USB Output Terminal ID
    mov [rbp+100],ecx
    mov [rbp+104],r8d
    movzx eax,word [rbp+128+rax*2]
    movzx eax,word [r12+rax+4]
    cmp eax,0x0101                    ; USB loopback is not microphone capture
    je .no
    mov [rbp+96],eax
    jmp .publish
.output_route:
    cmp byte [rdi+2],2                ; OUT endpoint links USB Input Terminal
    jne .no
    movzx eax,byte [rdi+7]
    cmp eax,[rbp+696]
    jne .no
    mov dword [rbp+780],1
.find_output:
    mov eax,[rbp+780]
    movzx ecx,word [rbp+128+rax*2]
    test ecx,ecx
    jz .output_next
    cmp byte [r12+rcx+2],3
    jne .output_next
    call uac1_fs_function_walk
    cmp eax,[rbp+784]
    jne .output_next
    cmp dword [rbp+92],0
    jne .no                          ; no ambiguous terminal fanout
    mov [rbp+88],eax
    mov eax,[rbp+780]
    mov [rbp+92],eax
    mov [rbp+100],ecx
    mov [rbp+104],r8d
    movzx eax,word [rbp+128+rax*2]
    movzx eax,word [r12+rax+4]
    cmp eax,0x0101
    je .no
    mov [rbp+96],eax
.output_next:
    inc dword [rbp+780]
    cmp dword [rbp+780],256
    jb .find_output
    cmp dword [rbp+92],0
    je .no
.publish:
    movzx eax,byte [r12+5]
    mov [rbp+64],eax
    mov eax,[rbp+672]
    mov [rbp+68],eax
    mov rax,[rbp+656]
    mov [rbp+72],eax
    mov rcx,[rbp+664]
    sub rcx,rax
    mov [rbp+76],ecx
    mov eax,[rbp+640]
    mov [rbp+80],eax
    mov eax,[rbp+688]
    mov [rbp+84],eax
    mov eax,[rbp+696]
    mov [rbp+108],eax
    mov [rbp+112],r13d
    mov eax,[rbp+716]
    mov [rbp+116],eax
    ; Retain raw accepted standard-interface triples before config scratch
    ; reuse. AC CS-span starts immediately after its validated9B interface.
    mov rax,[rbp+656]
    mov eax,[r12+rax-9+5]
    bswap eax
    shr eax,8
    mov [rbp+120],eax
    mov rax,[rbp+640]
    mov eax,[r12+rax+5]
    bswap eax
    shr eax,8
    mov [rbp+124],eax
    mov rsi,rbp
    mov rdi,r14
    mov ecx,16
    cld
    rep movsq
    xor eax,eax
    jmp .done
.no:
    mov eax,-1
.done:
    add rsp,840
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Internal: R12 configuration, RBP private frame, EAX entity ID.
; EAX input terminal ID (0 failure), EDX channels, ECX Feature Units,
; R8D first Feature Unit from output toward input. Volatile registers only.
; Every traversal is bounded by the64-entity limit, including cycles.
uac1_fs_function_walk:
    mov r9d,eax
    mov r10d,eax
    xor ecx,ecx
    xor r8d,r8d
    mov r11d,64
.walk:
    movzx eax,word [rbp+128+r10*2]
    test eax,eax
    jz .bad
    lea rdi,[r12+rax]
    cmp byte [rdi+2],2
    je .input
    cmp byte [rdi+2],6
    je .feature
    cmp r10d,r9d                     ; an Output Terminal cannot source a Unit
    jne .bad
    movzx r10d,byte [rdi+7]
    jmp .advance
.feature:
    inc ecx
    test r8d,r8d
    jnz .feature_source
    mov r8d,r10d
.feature_source:
    movzx r10d,byte [rdi+4]
.advance:
    dec r11d
    jz .bad
    jmp .walk
.input:
    movzx edx,byte [rdi+7]
    mov [rbp+800],r10d
    mov [rbp+804],edx
    mov [rbp+808],ecx
    mov [rbp+812],r8d
    mov r10d,r9d
.cluster:
    cmp r10d,[rbp+800]
    je .ok
    movzx eax,word [rbp+128+r10*2]
    lea rdi,[r12+rax]
    cmp byte [rdi+2],3
    jne .cluster_feature
    movzx r10d,byte [rdi+7]
    jmp .cluster
.cluster_feature:
    mov eax,[rbp+804]
    inc eax
    movzx ecx,byte [rdi+5]
    imul eax,ecx
    add eax,7
    movzx ecx,byte [rdi]
    cmp eax,ecx
    jne .bad
    movzx r10d,byte [rdi+4]
    jmp .cluster
.ok:
    mov eax,[rbp+800]
    mov edx,[rbp+804]
    mov ecx,[rbp+808]
    mov r8d,[rbp+812]
    ret
.bad:
    xor eax,eax
    ret
