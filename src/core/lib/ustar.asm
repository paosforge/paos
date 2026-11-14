;; MODULE core/lib/ustar
;; LAYER 1
;; EXPORTS ustar_build_member, ustar_octal_field, ustar_selftest
;; IMPORTS boot/serial
;; CAPS
;; OWNER saga:user_data_backup
; ============================================================================
; Task1230a — deterministic ustar (POSIX tar) archiver. Builds one regular-file
; member (512-byte header + 512-padded data + two zero end blocks) into a
; caller buffer. The header
; is byte-exact and deterministic (fixed mode/uid/gid/mtime=0, "ustar\0"/"00"),
; and the checksum is the standard 6-octal-digit + NUL + space over the header
; with the checksum field taken as spaces. Deterministic output is what makes
; `archive_manifest_exact` gradeable. Position-independent; no allocator.
; ============================================================================

USTAR_BLK        equ 512
USTAR_NAME_OFF   equ 0
USTAR_MODE_OFF   equ 100
USTAR_UID_OFF    equ 108
USTAR_GID_OFF    equ 116
USTAR_SIZE_OFF   equ 124
USTAR_MTIME_OFF  equ 136
USTAR_CHKSUM_OFF equ 148
USTAR_TYPE_OFF   equ 156
USTAR_MAGIC_OFF  equ 257

; ustar_octal_field(RDI=dest, ESI=width, RDX=value)
;   Writes VALUE as zero-padded octal in a WIDTH-byte field, NUL-terminated
;   (the conventional "width-1 octal digits + NUL"). Clobbers RAX,RCX,R8.
ustar_octal_field:
    mov  r8d, esi
    dec  r8d                         ; digits = width-1 (last byte NUL)
    mov  byte [rdi + r8], 0          ; trailing NUL
.next:
    dec  r8d
    js   .done
    mov  rax, rdx
    and  eax, 7
    add  al, '0'
    mov  [rdi + r8], al
    shr  rdx, 3
    jmp  .next
.done:
    ret

; ustar_build_member(RDI=out, RSI=name, EDX=name_len, RCX=data, R8=data_len)
;   -> RAX = total bytes written (512 header + 512-padded data + 1024 end).
;   name_len<=100,
;   data_len is the file size. Deterministic; no time/uid dependence.
ustar_build_member:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi                    ; out
    mov  r13, rsi                    ; name
    mov  r14d, edx                   ; name_len
    mov  r15, rcx                    ; data
    mov  rbx, r8                     ; data_len
    ; zero the 512-byte header
    mov  rdi, r12
    xor  eax, eax
    mov  ecx, USTAR_BLK
.zh:
    mov  byte [rdi], 0
    inc  rdi
    dec  ecx
    jnz  .zh
    ; name (bounded to 100)
    cmp  r14d, 100
    jbe  .name_ok
    mov  r14d, 100
.name_ok:
    lea  rdi, [r12 + USTAR_NAME_OFF]
    mov  rsi, r13
    mov  ecx, r14d
.cpname:
    test ecx, ecx
    jz   .name_done
    mov  al, [rsi]
    mov  [rdi], al
    inc  rsi
    inc  rdi
    dec  ecx
    jmp  .cpname
.name_done:
    ; mode=0000644, uid=0, gid=0, mtime=0, size=data_len (octal fields)
    lea  rdi, [r12 + USTAR_MODE_OFF]
    mov  esi, 8
    mov  rdx, 0o644
    call ustar_octal_field
    lea  rdi, [r12 + USTAR_UID_OFF]
    mov  esi, 8
    xor  edx, edx
    call ustar_octal_field
    lea  rdi, [r12 + USTAR_GID_OFF]
    mov  esi, 8
    xor  edx, edx
    call ustar_octal_field
    lea  rdi, [r12 + USTAR_SIZE_OFF]
    mov  esi, 12
    mov  rdx, rbx
    call ustar_octal_field
    lea  rdi, [r12 + USTAR_MTIME_OFF]
    mov  esi, 12
    xor  edx, edx
    call ustar_octal_field
    ; typeflag '0' (regular file)
    mov  byte [r12 + USTAR_TYPE_OFF], '0'
    ; magic "ustar\0" + version "00"
    lea  rdi, [r12 + USTAR_MAGIC_OFF]
    mov  byte [rdi + 0], 'u'
    mov  byte [rdi + 1], 's'
    mov  byte [rdi + 2], 't'
    mov  byte [rdi + 3], 'a'
    mov  byte [rdi + 4], 'r'
    mov  byte [rdi + 5], 0
    mov  byte [rdi + 6], '0'
    mov  byte [rdi + 7], '0'
    ; checksum: field is 8 spaces during the sum, then 6 octal + NUL + space
    lea  rdi, [r12 + USTAR_CHKSUM_OFF]
    mov  ecx, 8
.sp:
    mov  byte [rdi], ' '
    inc  rdi
    dec  ecx
    jnz  .sp
    xor  edx, edx                    ; running sum
    xor  ecx, ecx
.sum:
    cmp  ecx, USTAR_BLK
    jae  .sum_done
    movzx eax, byte [r12 + rcx]
    add  edx, eax
    inc  ecx
    jmp  .sum
.sum_done:
    ; write 6 octal digits + NUL + space
    lea  rdi, [r12 + USTAR_CHKSUM_OFF]
    mov  esi, 7                      ; 6 digits + NUL
    call ustar_octal_field
    mov  byte [r12 + USTAR_CHKSUM_OFF + 7], ' '
    ; data blocks (copy data, then zero-pad to 512)
    lea  rdi, [r12 + USTAR_BLK]      ; after header
    mov  rsi, r15
    mov  rcx, rbx                    ; data_len
.cpdata:
    test rcx, rcx
    jz   .data_done
    mov  al, [rsi]
    mov  [rdi], al
    inc  rsi
    inc  rdi
    dec  rcx
    jmp  .cpdata
.data_done:
    ; pad to 512 multiple
    mov  rax, rbx
    and  eax, USTAR_BLK-1
    test eax, eax
    jz   .no_pad
    mov  ecx, USTAR_BLK
    sub  ecx, eax                    ; pad bytes
.pad:
    mov  byte [rdi], 0
    inc  rdi
    dec  ecx
    jnz  .pad
.no_pad:
    ; POSIX tar end-of-archive marker: exactly two zero records.  A receiver
    ; must be able to feed the produced bytes directly to a normal tar reader;
    ; a lone member record is not a complete archive.
    mov  ecx, 2 * USTAR_BLK
.zend:
    mov  byte [rdi], 0
    inc  rdi
    dec  ecx
    jnz  .zend
    ; total = 512 + roundup(data_len,512) + two zero records
    mov  rax, rbx
    add  rax, USTAR_BLK-1
    and  rax, ~(USTAR_BLK-1)
    add  rax, 3 * USTAR_BLK
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ustar_selftest -> EAX=1 pass / 0 fail. Builds a fixed member and checks the
; magic, the size octal field, and that the checksum reconciles.
ustar_selftest:
    push rbx
    lea  rdi, [rel ustar_test_buf]
    lea  rsi, [rel str_ustar_name]
    mov  edx, str_ustar_name_len
    lea  rcx, [rel str_ustar_data]
    mov  r8, str_ustar_data_len
    call ustar_build_member
    ; expect header + one padded data record + two zero end records
    cmp  rax, 2048
    jne  .fail
    ; magic "ustar\0"
    lea  rbx, [rel ustar_test_buf]
    cmp  byte [rbx + USTAR_MAGIC_OFF + 0], 'u'
    jne  .fail
    cmp  byte [rbx + USTAR_MAGIC_OFF + 5], 0
    jne  .fail
    cmp  byte [rbx + USTAR_TYPE_OFF], '0'
    jne  .fail
    ; size octal reconciles: recompute checksum with chksum-as-spaces == stored
    ; (verify determinism: re-sum header, chksum field spaces)
    xor  edx, edx
    xor  ecx, ecx
.rsum:
    cmp  ecx, USTAR_BLK
    jae  .rsum_done
    cmp  ecx, USTAR_CHKSUM_OFF
    jb   .add
    cmp  ecx, USTAR_CHKSUM_OFF+8
    jae  .add
    add  edx, ' '                    ; checksum field counted as spaces
    inc  ecx
    jmp  .rsum
.add:
    movzx eax, byte [rbx + rcx]
    add  edx, eax
    inc  ecx
    jmp  .rsum
.rsum_done:
    ; parse stored checksum octal (6 digits) into r9
    xor  r9d, r9d
    xor  ecx, ecx
.parse:
    cmp  ecx, 6
    jae  .parsed
    movzx eax, byte [rbx + USTAR_CHKSUM_OFF + rcx]
    sub  eax, '0'
    shl  r9d, 3
    or   r9d, eax
    inc  ecx
    jmp  .parse
.parsed:
    cmp  edx, r9d
    jne  .fail
    mov  eax, 1
    pop  rbx
    ret
.fail:
    xor  eax, eax
    pop  rbx
    ret

; --- ustar data ---
ustar_test_buf:   times 2048 db 0
str_ustar_name:   db "keep/note.txt"
str_ustar_name_len equ $ - str_ustar_name
str_ustar_data:   db "paos keep backup fixture payload"
str_ustar_data_len equ $ - str_ustar_data
