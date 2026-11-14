;; MODULE sec/phone_link
;; LAYER 5
;; IMPORTS sec/session, core/csprng, core/time
;; PURPOSE Owner-only boot-RAM phone pins/grants and bounded typed admission.
;; EXPORTS phone_link_reset, phone_link_pair_begin, phone_link_pair_commit, phone_link_grant, phone_link_unpair, phone_link_revoke_all, phone_link_generation, phone_link_event, phone_link_audit_take, phone_link_audit_dropped, phone_link_audit_suppressed
;; CAPS
;; OWNER saga:sec
;; CONTEXT: bsp_only
;
; Unlinked D1 trusted-native policy seam. BSP serialized, no IRQ/AP/yield.
; Valid disjoint native buffers only: a future guest bridge copies and validates
; guest bodies before entry; never expose Settings mutations to that bridge.
; Not a memory-isolation boundary. No socket, JSON parsing, content dispatch,
; persistence, Guardian producer, durable budget, TLS or peer-authentication claim.
;
; SysV integer ABI; statuses 0 OK, 1 bad, 2 forbidden, 3 unpaired, 4 pin,
; 5 stale, 6 off, 7 locked, 8 owner, 9 no pair mode, 10 expired,
; 11 mismatch/alias, 12 time/entropy unavailable, 13 full, 14 exhausted,
; 15 secret, 16 category, 17 size. Pointers/capacity described below.
;
; Four 128-byte boot-RAM registry rows: id16, cert SHA25632, device hash32,
; protocol32, grants32, outbound categories64, refusal last-us64, suppressed64,
; active32, reserved32, paired UTC64. Guest must prove device ID == cert subject
; and pinned TLS; native compares the copied hashes, not the TLS transcript.
; Global generation invalidates ALL old decisions on any Settings mutation.
;
; Admission is a plan, not a bearer capability: trusted consumer must recheck
; native lock/session/generation immediately before bounded commit, with no yield.
; Outbound event origin/SECRET classification must come from native producers;
; guest metadata alone cannot authorize export. All new/repaired grants are OFF.
;
; Pair PLP1 exact128: magic4, version16=1, protocol16>=8, nonce16, id16,
; cert32, devicehash32, expected display8, human confirmation8, peer UTC64.
; Genuine Settings obtains confirmation; module does not prove the human/TLS.
; Pair mode120s, peer timestamp tolerance1800s. Existing source-qualified UTC
; is NTP provenance, NOT cryptographically authenticated time or durable floor.
;
; Event PLK1 exact96: magic4, version16=1, kind16, id16, generation64,
; cert32, flags32, length32, category64, filebytes64, reserved64=0.
; Kinds1..12: battery,ping,find,notify-in,notify-out,file-in,share-in,
; clip-in,clip-out,SMS-in,SFTP-read,limited-media. ALL other kinds forbidden,
; including runcommand/input injection/SMS send/notification actions/SFTP write.
; Decision32: id16,generation64,kind16,projection16,allowed bytes32.
; Projection1 bounded body,2 count only,3 quarantine job plan,4 safe preview,
; 5 read-only mount plan,6 limited media plan. No filename/action parsing here.
;
; Audit64x32 metadata: seq64,mono-us64,id-low32,kind16,verdict8,reason8,gen64.
; No bodies, certs, nonce, device hash, pair key or credentials. Overwrite oldest
; with saturating dropped counter; refused once/5s per phone + unknown bucket.
; audit_take copies once/wipes slot; future Guardian consumer owns durable drain.

%macro PL_ENTER 0
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
%endmacro
%macro PL_LEAVE 0
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
%endmacro

; Only Settings passes a captured expected token in RDI. Real session authority
; also refuses remote command, injected input, locked state and stale epoch.
pl_owner:
    push rdi
    call session_shell_local_authority
    pop rcx
    cmp rax,1
    jne .bad
    test rdx,rdx
    jz .bad
    cmp rdx,rcx
    jne .bad
    xor eax,eax
    ret
.bad:
    mov eax,8
    ret

pl_pair_wipe:
    lea rdi,[rel pl_pair]
    mov ecx,8
    xor eax,eax
    rep stosq
    ret
pl_registry_wipe:
    lea rdi,[rel pl_rows]
    mov ecx,64
    xor eax,eax
    rep stosq
    jmp pl_pair_wipe

; Never leave a pin unrevocable on generation wrap: wipe and seal at UINT64_MAX.
pl_bump:
    cmp qword [rel pl_generation],-2
    jae .seal
    inc qword [rel pl_generation]
    xor eax,eax
    ret
.seal:
    call pl_registry_wipe
    mov qword [rel pl_generation],-1
    mov eax,14
    ret

phone_link_reset:
    lea rdi,[rel pl_state]
    mov ecx,(pl_state_end-pl_state)/8
    xor eax,eax
    rep stosq
    mov qword [rel pl_generation],1
    ret
phone_link_generation:
    mov rax,[rel pl_generation]
    ret
phone_link_audit_dropped:
    mov rax,[rel pl_dropped]
    ret
phone_link_audit_suppressed:
    mov rax,[rel pl_suppressed]
    ret

; RDI=id16 -> RAX row or0. All 16 bytes compared.
pl_find:
    lea rax,[rel pl_rows]
    mov ecx,4
.loop:
    cmp dword [rax+112],1
    jne .next
    mov rdx,[rdi]
    cmp [rax],rdx
    jne .next
    mov rdx,[rdi+8]
    cmp [rax+8],rdx
    je .out
.next:
    add rax,128
    loop .loop
    xor eax,eax
.out:
    ret

; RDI=A RSI=B ECX=bytes -> ZF equal; valid native regions only.
pl_equal:
    repe cmpsb
    ret
; RDI bytes RSI length -> EAX nonzero iff any byte nonzero.
pl_nonzero:
    xor eax,eax
.loop:
    or al,[rdi]
    inc rdi
    dec rsi
    jnz .loop
    test eax,eax
    ret

; RDI=out32 RSI=capacity. Valid output scrubbed on every refusal.
phone_link_pair_begin:
    PL_ENTER
    mov r12,rdi
    cmp rsi,32
    jb .bad
    test rdi,rdi
    jz .bad
    mov ecx,4
    xor eax,eax
    rep stosq
    call pl_pair_wipe
    call session_shell_local_authority
    cmp rax,1
    jne .owner
    test rdx,rdx
    jz .owner
    mov r13,rdx
    cmp qword [rel pl_generation],-1
    je .exhausted
    call time_wall_utc_now_s
    test rax,rax
    jle .time
    mov r14,rax
    call time_monotonic_now_us
    mov r15,rax
    add rax,120000000
    jc .time
    mov rbx,rax
    lea rdi,[rel pl_pair]
    mov esi,16
    call csprng_generate
    test eax,eax
    jnz .time
    mov [rel pl_pair+16],r13
    mov [rel pl_pair+24],r15
    mov [rel pl_pair+32],rbx
    mov [rel pl_pair+40],r14
    mov qword [rel pl_pair+48],1
    mov rax,[rel pl_pair]
    mov [r12],rax
    mov rax,[rel pl_pair+8]
    mov [r12+8],rax
    mov [r12+16],r13
    mov [r12+24],rbx
    xor eax,eax
    jmp .out
.owner:
    mov eax,8
    jmp .out
.exhausted:
    mov eax,14
    jmp .out
.time:
    call pl_pair_wipe
    mov eax,12
    jmp .out
.bad:
    mov eax,1
.out:
    PL_LEAVE

; RDI=request128 RSI=exact size RDX=captured owner token.
; Any commit attempt consumes mode, even malformed/expired/refused attempts.
phone_link_pair_commit:
    PL_ENTER
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov rdi,rdx
    call pl_owner
    test eax,eax
    jnz .finish
    cmp qword [rel pl_pair+48],1
    jne .busy
    cmp [rel pl_pair+16],r14
    jne .owner
    test r12,r12
    jz .bad
    cmp r13,128
    jne .bad
    cmp dword [r12],0x31504c50
    jne .bad
    cmp word [r12+4],1
    jne .bad
    cmp word [r12+6],8
    jb .bad
    lea rdi,[r12+8]
    lea rsi,[rel pl_pair]
    mov ecx,16
    call pl_equal
    jne .mismatch
    lea rdi,[r12+104]
    lea rsi,[r12+112]
    mov ecx,8
    call pl_equal
    jne .mismatch
    mov ecx,8
    lea rdi,[r12+104]
.key:
    mov al,[rdi]
    cmp al,'0'
    jb .mismatch
    cmp al,'9'
    jbe .keyok
    cmp al,'A'
    jb .mismatch
    cmp al,'F'
    ja .mismatch
.keyok:
    inc rdi
    loop .key
    lea rdi,[r12+24]
    mov esi,16
    call pl_nonzero
    jz .bad
    lea rdi,[r12+40]
    mov esi,32
    call pl_nonzero
    jz .bad
    lea rdi,[r12+72]
    mov esi,32
    call pl_nonzero
    jz .bad
    call time_monotonic_now_us
    cmp rax,[rel pl_pair+24]
    jb .time
    cmp rax,[rel pl_pair+32]
    jae .expired
    call time_wall_utc_now_s
    test rax,rax
    jle .time
    cmp rax,[rel pl_pair+40]
    jb .time
    mov r15,rax
    mov rdx,[r12+120]
    test rdx,rdx
    js .time
    sub rax,rdx
    jnc .delta
    neg rax
.delta:
    cmp rax,1800
    ja .time
    xor ebx,ebx
    lea rbp,[rel pl_rows]
    mov r14d,4
.scan:
    cmp dword [rbp+112],1
    jne .free
    lea rdi,[r12+24]
    mov rsi,rbp
    mov ecx,16
    call pl_equal
    je .mismatch
    lea rdi,[r12+40]
    lea rsi,[rbp+16]
    mov ecx,32
    call pl_equal
    je .mismatch
    lea rdi,[r12+72]
    lea rsi,[rbp+48]
    mov ecx,32
    call pl_equal
    je .mismatch
    jmp .next
.free:
    test rbx,rbx
    cmovz rbx,rbp
.next:
    add rbp,128
    dec r14d
    jnz .scan
    test rbx,rbx
    jz .full
    call pl_bump
    test eax,eax
    jnz .finish
    mov rdi,rbx
    mov ecx,16
    xor eax,eax
    rep stosq
    mov rdi,rbx
    lea rsi,[r12+24]
    mov ecx,80
    rep movsb
    movzx eax,word [r12+6]
    mov [rbx+80],eax
    mov [rbx+120],r15
    mov dword [rbx+112],1
    mov rdi,rbx
    xor esi,esi
    mov edx,3
    xor ecx,ecx
    call pl_audit
    xor eax,eax
    jmp .finish
.bad:
    mov eax,1
    jmp .finish
.owner:
    mov eax,8
    jmp .finish
.busy:
    mov eax,9
    jmp .finish
.expired:
    mov eax,10
    jmp .finish
.mismatch:
    mov eax,11
    jmp .finish
.time:
    mov eax,12
    jmp .finish
.full:
    mov eax,13
.finish:
    mov r12d,eax
    call pl_pair_wipe
    mov eax,r12d
    PL_LEAVE

; RDI=id16 RSI=grants mask RDX=categories RCX=expected owner token.
phone_link_grant:
    PL_ENTER
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov rdi,rcx
    call pl_owner
    test eax,eax
    jnz .out
    test r12,r12
    jz .bad
    cmp r13,0xfff
    ja .bad
    cmp r14,7
    ja .bad
    test r13d,16
    jz .find
    test r14,r14
    jz .bad
.find:
    mov rdi,r12
    call pl_find
    test rax,rax
    jz .missing
    mov rbx,rax
    call pl_bump
    test eax,eax
    jnz .out
    mov [rbx+84],r13d
    mov [rbx+88],r14
    mov rdi,rbx
    xor esi,esi
    mov edx,3
    xor ecx,ecx
    call pl_audit
    xor eax,eax
    jmp .out
.bad:
    mov eax,1
    jmp .out
.missing:
    mov eax,3
.out:
    PL_LEAVE

; RDI=id16 RSI=expected owner token.
phone_link_unpair:
    PL_ENTER
    mov r12,rdi
    mov rdi,rsi
    call pl_owner
    test eax,eax
    jnz .out
    test r12,r12
    jz .bad
    mov rdi,r12
    call pl_find
    test rax,rax
    jz .missing
    mov rbx,rax
    call pl_bump
    test eax,eax
    jnz .out
    mov rdi,rbx
    xor esi,esi
    mov edx,3
    xor ecx,ecx
    call pl_audit
    mov rdi,rbx
    mov ecx,16
    xor eax,eax
    rep stosq
    jmp .out
.bad:
    mov eax,1
    jmp .out
.missing:
    mov eax,3
.out:
    PL_LEAVE

; RDI=expected owner token. Key rotation/transport teardown belong to bridge.
phone_link_revoke_all:
    PL_ENTER
    call pl_owner
    test eax,eax
    jnz .out
    call pl_bump
    test eax,eax
    jnz .out
    call pl_registry_wipe
    xor edi,edi
    xor esi,esi
    mov edx,3
    xor ecx,ecx
    call pl_audit
    xor eax,eax
.out:
    PL_LEAVE

; RDI=req96 RSI=exact96 RDX=out32 RCX=capacity>=32.
phone_link_event:
    PL_ENTER
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    xor ebx,ebx
    xor ebp,ebp
    cmp rcx,32
    jb .short
    test rdx,rdx
    jz .short
    mov rdi,rdx
    mov ecx,4
    xor eax,eax
    rep stosq
    test r12,r12
    jz .bad
    cmp r13,96
    jne .bad
    cmp dword [r12],0x314b4c50
    jne .bad
    cmp word [r12+4],1
    jne .bad
    cmp qword [r12+88],0
    jne .bad
    movzx ebp,word [r12+6]
    cmp ebp,1
    jb .forbidden
    cmp ebp,12
    ja .forbidden
    lea rdi,[r12+8]
    call pl_find
    test rax,rax
    jz .missing
    mov rbx,rax
    lea rdi,[r12+32]
    lea rsi,[rbx+16]
    mov ecx,32
    call pl_equal
    jne .pin
    mov rax,[rel pl_generation]
    cmp rax,[r12+24]
    jne .stale
    lea ecx,[rbp-1]
    bt [rbx+84],ecx
    jnc .off
    mov r15d,1
    cmp byte [rel session_locked],0
    je .unlocked
    cmp ebp,1
    je .fields
    cmp ebp,2
    je .fields
    cmp ebp,4
    je .count
    cmp ebp,10
    jne .locked
.count:
    mov r15d,2
    jmp .fields
.unlocked:
    cmp ebp,3
    je .outbound
    cmp ebp,5
    je .outbound
    cmp ebp,9
    je .outbound
    cmp ebp,11
    jne .fields
.outbound:
    call session_shell_local_authority
    cmp rax,1
    jne .owner
    test rdx,rdx
    jz .owner
.fields:
    mov eax,[r12+64]
    test eax,eax
    jz .category
    cmp ebp,9
    jne .bad
    cmp eax,1
    jne .bad
    jmp .secret
.category:
    mov rax,[r12+72]
    cmp ebp,5
    jne .nocategory
    test rax,rax
    jz .catbad
    cmp rax,4
    ja .catbad
    lea rdx,[rax-1]
    test rdx,rax
    jnz .catbad
    test [rbx+88],rax
    jz .catbad
    jmp .filesize
.nocategory:
    test rax,rax
    jnz .bad
.filesize:
    cmp ebp,6
    je .file
    cmp qword [r12+80],0
    jne .bad
    lea rdx,[rel pl_maxlength]
    mov eax,[rdx+rbp*4-4]
    cmp [r12+68],eax
    ja .size
    cmp ebp,7
    jne .sftp
    mov r15d,4
.sftp:
    cmp ebp,11
    jne .media
    mov r15d,5
.media:
    cmp ebp,12
    jne .allow
    mov r15d,6
    jmp .allow
.file:
    cmp qword [r12+80],0
    je .size
    cmp qword [r12+80],67108864
    ja .size
    cmp dword [r12+68],1
    jb .size
    cmp dword [r12+68],255
    ja .size
    mov r15d,3
.allow:
    mov rax,[rbx]
    mov [r14],rax
    mov rax,[rbx+8]
    mov [r14+8],rax
    mov rax,[rel pl_generation]
    mov [r14+16],rax
    mov [r14+24],bp
    mov [r14+26],r15w
    mov eax,[r12+68]
    cmp r15d,2
    jne .length
    xor eax,eax
.length:
    mov [r14+28],eax
    mov rdi,rbx
    mov esi,ebp
    mov edx,1
    xor ecx,ecx
    call pl_audit
    xor eax,eax
    jmp .out
.short:
    mov eax,1
    jmp .out
.bad:
    mov eax,1
    jmp .refuse
.forbidden:
    mov eax,2
    jmp .refuse
.missing:
    mov eax,3
    jmp .refuse
.pin:
    mov eax,4
    jmp .refuse
.stale:
    mov eax,5
    jmp .refuse
.off:
    mov eax,6
    jmp .refuse
.locked:
    mov eax,7
    jmp .refuse
.owner:
    mov eax,8
    jmp .refuse
.secret:
    mov eax,15
    jmp .refuse
.catbad:
    mov eax,16
    jmp .refuse
.size:
    mov eax,17
.refuse:
    mov r15d,eax
    mov rdi,rbx
    mov esi,ebp
    mov edx,2
    mov ecx,eax
    call pl_audit
    mov eax,r15d
.out:
    PL_LEAVE

; RDI=row or0, ESI=kind, EDX=verdict, ECX=reason.
; Preserves all nonvolatile regs; bounded synchronous metadata operation only.
pl_audit:
    PL_ENTER
    mov r12,rdi
    mov r13d,esi
    mov r14d,edx
    mov r15d,ecx
    call time_monotonic_now_us
    mov rbx,rax
    cmp r14d,2
    jne .record
    lea rbp,[rel pl_unknown_last]
    test r12,r12
    jz .rate
    lea rbp,[r12+96]
.rate:
    mov rdx,[rbp]
    test rdx,rdx
    jz .first
    cmp rbx,rdx
    jb .suppress
    mov rax,rbx
    sub rax,rdx
    cmp rax,5000000
    jb .suppress
.first:
    mov rax,rbx
    test rax,rax
    jnz .last
    inc rax
.last:
    mov [rbp],rax
.record:
    cmp qword [rel pl_seq],-1
    je .drop_only
    inc qword [rel pl_seq]
    cmp qword [rel pl_count],64
    jb .room
    mov rax,[rel pl_head]
    inc rax
    and eax,63
    mov [rel pl_head],rax
    lea rdi,[rel pl_dropped]
    call pl_sat_inc
    jmp .slot
.room:
    inc qword [rel pl_count]
.slot:
    mov rax,[rel pl_head]
    add rax,[rel pl_count]
    dec rax
    and eax,63
    shl eax,5
    lea rdi,[rel pl_audit_rows]
    add rdi,rax
    mov rax,[rel pl_seq]
    mov [rdi],rax
    mov [rdi+8],rbx
    xor eax,eax
    test r12,r12
    jz .tag
    mov eax,[r12]
.tag:
    mov [rdi+16],eax
    mov [rdi+20],r13w
    mov [rdi+22],r14b
    mov [rdi+23],r15b
    mov rax,[rel pl_generation]
    mov [rdi+24],rax
    jmp .out
.suppress:
    lea rdi,[rel pl_suppressed]
    call pl_sat_inc
    test r12,r12
    jz .out
    lea rdi,[r12+104]
    call pl_sat_inc
    jmp .out
.drop_only:
    lea rdi,[rel pl_dropped]
    call pl_sat_inc
.out:
    PL_LEAVE
pl_sat_inc:
    cmp qword [rdi],-1
    je .out
    inc qword [rdi]
.out:
    ret

; RDI=out32 RSI=capacity. -1 invalid (untouched),0 empty,1 copied/wiped.
phone_link_audit_take:
    cmp rsi,32
    jb .bad
    test rdi,rdi
    jz .bad
    cmp qword [rel pl_count],0
    je .empty
    mov rax,[rel pl_head]
    shl eax,5
    lea rsi,[rel pl_audit_rows]
    add rsi,rax
    mov rdx,rsi
    mov ecx,4
    rep movsq
    mov rdi,rdx
    mov ecx,4
    xor eax,eax
    rep stosq
    mov rax,[rel pl_head]
    inc rax
    and eax,63
    mov [rel pl_head],rax
    dec qword [rel pl_count]
    mov eax,1
    ret
.empty:
    xor eax,eax
    ret
.bad:
    mov eax,-1
    ret

align 8
pl_maxlength: dd 4,64,0,4096,4096,255,2048,4096,4096,4096,0,16
align 8
pl_state:
pl_rows: times 512 db 0
pl_pair: times 64 db 0
pl_generation: dq 1
pl_head: dq 0
pl_count: dq 0
pl_seq: dq 0
pl_dropped: dq 0
pl_suppressed: dq 0
pl_unknown_last: dq 0
pl_audit_rows: times 2048 db 0
pl_state_end:

%unmacro PL_ENTER 0
%unmacro PL_LEAVE 0
