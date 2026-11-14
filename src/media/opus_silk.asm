;; MODULE media/opus_silk
;; LAYER 4
;; EXPORTS media_opus_silk_decode
;; IMPORTS media_opus_packet_parse, media_opus_range_init, media_opus_range_icdf, media_opus_range_bit, memcpy, memset
;; CAPS
;; OWNER rc-codex-av
; Private native NB/MB/WB mono/stereo10/20/40/60ms SILK -> S16LE48k transaction. Request80 and
; pointer-free state9120, full four-span validation and negative purity.
; RDI=request; RAX=480/960/1920/2880/-1. SysV preserved, DF0, integer-only, no libc/libopus.
; Regeneration: tools/generate_opus_silk.py; glue tools/opus_silk/profile.c.
; Pinned algorithms/data and full notices: LICENSES/XIPH_OPUS_SILK.txt.
; Each function/table below is readable native NASM, never an opaque blob.

; ===== CNG.c =====
section .text
align 16
sn_silk_CNG_Reset:
mov	r8d, dword [rdi+2340]
mov	eax, 32767
xor	edx, edx
lea	ecx, [r8+1]
idiv	ecx
test	r8d, r8d
jle	sn_CNG_L2
xor	ecx, ecx
xor	edx, edx
align 16
align 8
sn_CNG_L3:
movsx	rsi, edx
add	ecx, eax
add	edx, 1
mov	word [rdi+rsi*2+4076], cx
cmp	r8d, edx
jg	sn_CNG_L3
sn_CNG_L2:
mov	rax, 13643290033258496
mov	qword [rdi+4172], rax
ret
align 16
sn_silk_CNG:
push	rbp
mov	rbp, rsp
push	r15
movsx	r15, ecx
push	r14
push	r13
mov	r13, rdi
push	r12
mov	r12, rdx
push	rbx
mov	rbx, rsi
sub	rsp, 184
mov	r8d, dword [rdi+2316]
cmp	r8d, dword [rdi+4180]
jne	sn_CNG_L85
sn_CNG_L7:
cmp	qword [r13+4184], 0
jne	sn_CNG_L20
movsx	rax, dword [r13+2340]
mov	rdx, r13
lea	rdi, [r13+rax*2+0]
test	eax, eax
jle	sn_CNG_L17
align 16
align 8
sn_CNG_L16:
movsx	esi, word [rdx+4076]
movsx	eax, word [rdx+2344]
add	rdx, 2
sub	eax, esi
mov	ecx, esi
cdqe
imul	rax, rax, 16348
sar	rax, 16
add	ecx, eax
mov	word [rdx+4074], cx
cmp	rdx, rdi
jne	sn_CNG_L16
sn_CNG_L17:
mov	esi, dword [r13+2324]
xor	r14d, r14d
test	esi, esi
jle	sn_CNG_L15
movsx	rdi, esi
xor	eax, eax
xor	edx, edx
xor	r14d, r14d
sn_CNG_L19:
mov	ecx, dword [rbx+rax*4+16]
cmp	ecx, edx
cmovg	r14d, eax
cmovg	edx, ecx
add	rax, 1
cmp	rax, rdi
jne	sn_CNG_L19
sn_CNG_L15:
movsx	rax, dword [r13+2332]
lea	edx, [rsi+-1]
lea	rcx, [r13+2796]
mov	rsi, rcx
mov	qword [rbp+-88], rcx
imul	edx, eax
lea	rdi, [rcx+rax*4]
movsx	rdx, edx
shl	rdx, 2
call	sn_move
movsx	rdx, dword [r13+2332]
mov	rdi, qword [rbp+-88]
mov	rax, rdx
shl	rdx, 2
imul	eax, r14d
cdqe
lea	rsi, [r13+rax*4+4]
call	sn_copy
movsx	rax, dword [r13+2324]
test	eax, eax
jle	sn_CNG_L20
mov	edx, dword [r13+4172]
lea	rsi, [rbx+rax*4]
sn_CNG_L22:
mov	ecx, dword [rbx+16]
mov	eax, ecx
sub	eax, edx
cdqe
imul	rax, rax, 4634
sar	rax, 16
add	edx, eax
movsx	rax, edx
imul	rax, rax, 46396
sar	rax, 16
cmp	ecx, eax
cmovl	edx, ecx
add	rbx, 4
mov	dword [r13+4172], edx
cmp	rbx, rsi
jne	sn_CNG_L22
sn_CNG_L20:
mov	eax, dword [r13+4184]
test	eax, eax
je	sn_CNG_L86
lea	eax, [r15+16]
mov	rcx, rsp
mov	qword [rbp+-208], rsp
cdqe
lea	rax, [0+rax*4+15]
mov	rdx, rax
and	rax, -4096
sub	rcx, rax
and	rdx, -16
cmp	rsp, rcx
je	sn_CNG_L24
sn_CNG_L87:
sub	rsp, 4096
or	qword [rsp+4088], 0
cmp	rsp, rcx
jne	sn_CNG_L87
sn_CNG_L24:
and	edx, 4095
sub	rsp, rdx
test	rdx, rdx
jne	sn_CNG_L88
sn_CNG_L25:
movsx	rdx, word [r13+4252]
movsx	rax, dword [r13+4272]
mov	rbx, rsp
imul	rdx, rax
sar	rdx, 16
cmp	rdx, 2097151
jle	sn_CNG_L26
mov	eax, dword [r13+4172]
sn_CNG_L27:
sar	edx, 16
sar	eax, 16
xor	r9d, r9d
imul	edx, edx
imul	eax, eax
shl	edx, 5
sub	eax, edx
test	eax, eax
jle	sn_CNG_L34
bsr	ecx, eax
mov	edx, 24
mov	esi, ecx
xor	esi, 31
sub	edx, esi
je	sn_CNG_L89
lea	ecx, [rsi+-24]
mov	edi, eax
rol	edi, cl
mov	ecx, edx
ror	eax, cl
test	edx, edx
mov	edx, esi
cmovs	eax, edi
and	edx, 1
and	eax, 127
cmp	edx, 1
sbb	edx, edx
and	edx, 13446
add	edx, 32768
sn_CNG_L31:
imul	ax, ax, 213
sar	esi, 1
mov	ecx, esi
sar	edx, cl
movsx	rax, ax
movsx	rcx, edx
imul	rax, rcx
sar	rax, 16
lea	r9d, [rdx+rax]
shl	r9d, 16
sar	r9d, 6
sn_CNG_L34:
mov	edx, dword [r13+4176]
lea	rdi, [r13+2796]
mov	ecx, 255
cmp	r15d, 254
jg	sn_CNG_L40
align 16
align 8
sn_CNG_L41:
sar	ecx, 1
cmp	r15d, ecx
jl	sn_CNG_L41
test	r15d, r15d
jle	sn_CNG_L90
sn_CNG_L40:
xor	esi, esi
align 16
align 8
sn_CNG_L43:
imul	edx, edx, 196314165
add	edx, 907633515
mov	eax, edx
sar	eax, 24
and	eax, ecx
cdqe
mov	eax, dword [rdi+rax*4]
mov	dword [rbx+rsi*4+64], eax
add	rsi, 1
cmp	r15d, esi
jg	sn_CNG_L43
mov	dword [r13+4176], edx
mov	ecx, dword [r13+4192]
lea	rsi, [r13+4076]
lea	rdi, [rbp+-80]
mov	edx, dword [r13+2340]
mov	dword [rbp+-216], r9d
call	sn_silk_NLSF2A
lea	rcx, [r13+4108]
mov	edx, 64
mov	rdi, rbx
mov	rsi, rcx
mov	qword [rbp+-152], rcx
call	sn_copy
mov	eax, dword [r13+2340]
movsx	r14, word [rbp+-80]
xor	edx, edx
movsx	r9, dword [rbp+-216]
movsx	r13, word [rbp+-78]
movsx	r11, word [rbp+-76]
movsx	r10, word [rbp+-74]
mov	dword [rbp+-88], eax
sar	eax, 1
mov	dword [rbp+-140], eax
movsx	rax, word [rbp+-72]
mov	qword [rbp+-96], rax
movsx	rax, word [rbp+-70]
mov	qword [rbp+-104], rax
movsx	rax, word [rbp+-68]
mov	qword [rbp+-112], rax
movsx	rax, word [rbp+-66]
mov	qword [rbp+-120], rax
movsx	rax, word [rbp+-64]
mov	qword [rbp+-128], rax
movsx	rax, word [rbp+-62]
mov	qword [rbp+-136], rax
movsx	rax, word [rbp+-60]
mov	qword [rbp+-160], rax
movsx	rax, word [rbp+-58]
mov	qword [rbp+-168], rax
movsx	rax, word [rbp+-56]
mov	qword [rbp+-176], rax
movsx	rax, word [rbp+-54]
mov	qword [rbp+-184], rax
movsx	rax, word [rbp+-52]
mov	qword [rbp+-192], rax
movsx	rax, word [rbp+-50]
mov	qword [rbp+-200], rax
mov	rcx, qword [rbp+-152]
mov	qword [rbp+-152], r9
mov	qword [rbp+-216], rcx
align 16
align 8
sn_CNG_L54:
lea	eax, [rdx+15]
lea	ecx, [rdx+14]
mov	edi, dword [rbp+-140]
mov	esi, edx
cdqe
movsx	rcx, ecx
movsx	rax, dword [rbx+rax*4]
movsx	rcx, dword [rbx+rcx*4]
imul	rax, r14
imul	rcx, r13
sar	rax, 16
sar	rcx, 16
add	eax, ecx
lea	ecx, [rdx+13]
movsx	rcx, ecx
add	eax, edi
mov	rdi, qword [rbp+-96]
movsx	rcx, dword [rbx+rcx*4]
imul	rcx, r11
sar	rcx, 16
add	eax, ecx
lea	ecx, [rdx+12]
movsx	rcx, ecx
movsx	rcx, dword [rbx+rcx*4]
imul	rcx, r10
sar	rcx, 16
add	eax, ecx
lea	ecx, [rdx+11]
movsx	rcx, ecx
movsx	rcx, dword [rbx+rcx*4]
imul	rcx, rdi
mov	rdi, qword [rbp+-104]
sar	rcx, 16
add	eax, ecx
lea	ecx, [rdx+10]
movsx	rcx, ecx
movsx	rcx, dword [rbx+rcx*4]
imul	rcx, rdi
mov	rdi, qword [rbp+-112]
sar	rcx, 16
add	eax, ecx
lea	ecx, [rdx+9]
movsx	rcx, ecx
movsx	rcx, dword [rbx+rcx*4]
imul	rcx, rdi
mov	rdi, qword [rbp+-120]
sar	rcx, 16
add	eax, ecx
lea	ecx, [rdx+8]
movsx	rcx, ecx
movsx	rcx, dword [rbx+rcx*4]
imul	rcx, rdi
mov	rdi, qword [rbp+-128]
sar	rcx, 16
add	eax, ecx
lea	ecx, [rdx+7]
movsx	rcx, ecx
movsx	rcx, dword [rbx+rcx*4]
imul	rcx, rdi
mov	rdi, qword [rbp+-136]
sar	rcx, 16
add	eax, ecx
lea	ecx, [rdx+6]
movsx	rcx, ecx
movsx	rcx, dword [rbx+rcx*4]
imul	rcx, rdi
sar	rcx, 16
add	eax, ecx
cmp	dword [rbp+-88], 16
jne	sn_CNG_L44
mov	rdi, qword [rbp+-192]
movsx	rcx, dword [rbx+rdx*4+4]
mov	r8, qword [rbp+-200]
imul	rcx, rdi
movsx	rdi, dword [rbx+rdx*4]
imul	rdi, r8
mov	r8, qword [rbp+-160]
sar	rcx, 16
sar	rdi, 16
add	ecx, edi
lea	edi, [rdx+5]
movsx	rdi, edi
movsx	rdi, dword [rbx+rdi*4]
imul	rdi, r8
mov	r8, qword [rbp+-168]
sar	rdi, 16
add	ecx, edi
lea	edi, [rdx+4]
movsx	rdi, edi
movsx	rdi, dword [rbx+rdi*4]
imul	rdi, r8
mov	r8, qword [rbp+-176]
sar	rdi, 16
add	ecx, edi
lea	edi, [rdx+3]
movsx	rdi, edi
movsx	rdi, dword [rbx+rdi*4]
imul	rdi, r8
mov	r8, qword [rbp+-184]
sar	rdi, 16
add	ecx, edi
lea	edi, [rdx+2]
movsx	rdi, edi
movsx	rdi, dword [rbx+rdi*4]
imul	rdi, r8
sar	rdi, 16
add	ecx, edi
add	eax, ecx
sn_CNG_L44:
add	esi, 16
movsx	rsi, esi
mov	edi, dword [rbx+rsi*4]
cmp	eax, 134217727
jg	sn_CNG_L45
cmp	eax, -134217728
jl	sn_CNG_L46
shl	eax, 4
mov	ecx, eax
add	ecx, edi
js	sn_CNG_L48
sn_CNG_L47:
mov	rcx, -2147483648
mov	r8d, -2147483648
test	edi, eax
jns	sn_CNG_L49
sn_CNG_L51:
mov	rax, qword [rbp+-152]
mov	edi, 32767
mov	dword [rbx+rsi*4], r8d
movzx	esi, word [r12+rdx*2]
imul	rcx, rax
mov	eax, -32768
sar	rcx, 16
sar	ecx, 7
add	ecx, 1
sar	ecx, 1
cmp	ecx, eax
cmovge	eax, ecx
cmp	eax, edi
cmovg	eax, edi
movsx	edi, si
add	eax, edi
mov	edi, 32767
cmp	eax, 32767
jg	sn_CNG_L52
mov	edi, -32768
cmp	eax, -32768
jl	sn_CNG_L52
mov	edi, 32767
cmp	ecx, 32767
jg	sn_CNG_L53
cmp	ecx, -32768
mov	edi, -32768
cmovge	edi, ecx
sn_CNG_L53:
add	edi, esi
sn_CNG_L52:
mov	word [r12+rdx*2], di
add	rdx, 1
cmp	r15, rdx
jne	sn_CNG_L54
mov	rcx, qword [rbp+-216]
sn_CNG_L56:
lea	rsi, [rbx+r15*4]
mov	edx, 64
mov	rdi, rcx
call	sn_copy
mov	rsp, qword [rbp+-208]
lea	rsp, [rbp+-40]
pop	rbx
pop	r12
pop	r13
pop	r14
pop	r15
pop	rbp
ret
align 16
align 8
sn_CNG_L26:
movsx	rax, dword [r13+4172]
cmp	eax, 8388608
jg	sn_CNG_L27
imul	rdx, rdx
xor	r9d, r9d
imul	rax, rax
sar	rdx, 16
shl	edx, 5
sar	rax, 16
sub	eax, edx
test	eax, eax
jle	sn_CNG_L34
bsr	esi, eax
mov	edx, 24
xor	esi, 31
sub	edx, esi
je	sn_CNG_L91
lea	ecx, [rsi+-24]
mov	edi, eax
rol	edi, cl
mov	ecx, edx
ror	eax, cl
test	edx, edx
mov	edx, esi
cmovs	eax, edi
and	edx, 1
and	eax, 127
cmp	edx, 1
sbb	edx, edx
and	edx, 13446
add	edx, 32768
sn_CNG_L37:
imul	ax, ax, 213
sar	esi, 1
mov	ecx, esi
sar	edx, cl
movsx	rcx, edx
movsx	rax, ax
imul	rax, rcx
sar	rax, 16
add	edx, eax
lea	r9d, [0+rdx*4+0]
jmp	sn_CNG_L34
align 16
align 8
sn_CNG_L46:
mov	ecx, edi
mov	eax, -2147483648
add	ecx, -2147483648
jns	sn_CNG_L47
sn_CNG_L49:
lea	r8d, [rdi+rax]
movsx	rcx, r8d
jmp	sn_CNG_L51
align 16
align 8
sn_CNG_L45:
mov	ecx, edi
mov	eax, 2147483632
add	ecx, 2147483632
jns	sn_CNG_L49
sn_CNG_L48:
mov	r9d, edi
mov	ecx, 2147483647
mov	r8d, 2147483647
or	r9d, eax
jns	sn_CNG_L51
lea	r8d, [rdi+rax]
movsx	rcx, r8d
jmp	sn_CNG_L51
align 16
align 8
sn_CNG_L85:
mov	edi, dword [rdi+2340]
mov	eax, 32767
xor	edx, edx
lea	ecx, [rdi+1]
idiv	ecx
xor	edx, edx
xor	ecx, ecx
test	edi, edi
jle	sn_CNG_L9
align 16
align 8
sn_CNG_L8:
movsx	rsi, edx
add	ecx, eax
add	edx, 1
mov	word [r13+rsi*2+4076], cx
cmp	edi, edx
jg	sn_CNG_L8
sn_CNG_L9:
mov	rax, 13643290033258496
mov	dword [r13+4180], r8d
mov	qword [r13+4172], rax
jmp	sn_CNG_L7
align 16
align 8
sn_CNG_L86:
movsx	rdx, dword [r13+2340]
lea	rdi, [r13+4108]
xor	esi, esi
shl	rdx, 2
call	sn_set
lea	rsp, [rbp+-40]
pop	rbx
pop	r12
pop	r13
pop	r14
pop	r15
pop	rbp
ret
align 16
align 8
sn_CNG_L88:
or	qword [rsp+rdx+-8], 0
jmp	sn_CNG_L25
align 16
align 8
sn_CNG_L89:
and	eax, 127
mov	edx, 46214
jmp	sn_CNG_L31
align 16
align 8
sn_CNG_L90:
mov	ecx, dword [r13+4192]
mov	edx, dword [r13+2340]
lea	rsi, [r13+4076]
lea	rdi, [rbp+-80]
call	sn_silk_NLSF2A
lea	rcx, [r13+4108]
mov	edx, 64
mov	rdi, rbx
mov	rsi, rcx
mov	qword [rbp+-88], rcx
call	sn_copy
mov	rcx, qword [rbp+-88]
jmp	sn_CNG_L56
sn_CNG_L91:
and	eax, 127
mov	edx, 46214
jmp	sn_CNG_L37

; ===== code_signs.c =====
section .text
align 16
sn_silk_decode_signs:
push	r15
lea	eax, [r8+rcx*2]
add	edx, 8
push	r14
cwde
sar	edx, 4
push	r13
push	r12
mov	r12, rdi
mov	rdi, rsi
lea	esi, [0+rax*8+0]
push	rbp
sub	esi, eax
push	rbx
sub	rsp, 40
mov	byte [rsp+31], 0
test	edx, edx
jle	sn_code_signs_L1
movsx	rsi, esi
lea	rax, [rel sn_silk_sign_iCDF]
movsx	rdx, edx
mov	rbp, r9
add	rax, rsi
lea	r15, [rdi+32]
lea	r14, [r9+rdx*4]
mov	qword [rsp+8], rax
lea	r13, [rsp+30]
jmp	sn_code_signs_L6
align 16
align 8
sn_code_signs_L3:
add	rbp, 4
add	r15, 32
cmp	rbp, r14
je	sn_code_signs_L1
sn_code_signs_L6:
mov	eax, dword [rbp+0]
test	eax, eax
jle	sn_code_signs_L3
and	eax, 31
mov	edx, 6
mov	rcx, qword [rsp+8]
lea	rbx, [r15+-32]
cmp	eax, edx
cmovg	rax, rdx
movzx	eax, byte [rcx+rax]
mov	byte [rsp+30], al
align 16
align 8
sn_code_signs_L5:
cmp	word [rbx], 0
jle	sn_code_signs_L4
mov	edx, 8
mov	rsi, r13
mov	rdi, r12
call	sn_ec_dec_icdf
lea	eax, [rax+rax+-1]
imul	ax, word [rbx]
mov	word [rbx], ax
sn_code_signs_L4:
add	rbx, 2
cmp	rbx, r15
jne	sn_code_signs_L5
add	rbp, 4
add	r15, 32
cmp	rbp, r14
jne	sn_code_signs_L6
sn_code_signs_L1:
add	rsp, 40
pop	rbx
pop	rbp
pop	r12
pop	r13
pop	r14
pop	r15
ret

; ===== init_decoder.c =====
section .text
align 16
sn_silk_reset_decoder:
push	rbx
mov	edx, 4296
mov	rbx, rdi
xor	esi, esi
call	sn_set
mov	dword [rbx], 65536
mov	rdi, rbx
mov	dword [rbx+2376], 1
mov	dword [rbx+4192], 0
call	sn_silk_CNG_Reset
mov	rdi, rbx
call	sn_silk_PLC_Reset
xor	eax, eax
pop	rbx
ret
align 16
sn_silk_init_decoder:
push	rbx
mov	edx, 4296
mov	rbx, rdi
xor	esi, esi
call	sn_set
mov	edx, 4296
xor	esi, esi
mov	rdi, rbx
call	sn_set
mov	dword [rbx], 65536
mov	rdi, rbx
mov	dword [rbx+2376], 1
mov	dword [rbx+4192], 0
call	sn_silk_CNG_Reset
mov	rdi, rbx
call	sn_silk_PLC_Reset
xor	eax, eax
pop	rbx
ret

; ===== decode_core.c =====
section .text
align 16
sn_silk_decode_core:
push	rbp
mov	rax, rdi
mov	rbp, rsp
push	r15
push	r14
mov	r14, rdi
mov	rdi, rcx
push	r13
push	r12
push	rbx
sub	rsp, 264
movsx	rax, dword [rax+2336]
mov	qword [rbp+-264], rdx
mov	qword [rbp+-232], rsi
mov	rsi, rsp
mov	rdx, rax
lea	rax, [rax+rax+15]
mov	dword [rbp+-256], r8d
mov	rcx, rax
and	rax, -4096
sub	rsi, rax
and	rcx, -16
cmp	rsp, rsi
je	sn_decode_core_L3
sn_decode_core_L121:
sub	rsp, 4096
or	qword [rsp+4088], 0
cmp	rsp, rsi
jne	sn_decode_core_L121
sn_decode_core_L3:
and	ecx, 4095
sub	rsp, rcx
test	rcx, rcx
jne	sn_decode_core_L122
sn_decode_core_L4:
mov	eax, dword [r14+2328]
mov	rsi, rsp
mov	qword [rbp+-296], rsp
add	edx, eax
movsx	rdx, edx
lea	rdx, [0+rdx*4+15]
mov	rcx, rdx
and	rdx, -4096
sub	rsi, rdx
and	rcx, -16
cmp	rsp, rsi
je	sn_decode_core_L6
sn_decode_core_L123:
sub	rsp, 4096
or	qword [rsp+4088], 0
cmp	rsp, rsi
jne	sn_decode_core_L123
sn_decode_core_L6:
and	ecx, 4095
sub	rsp, rcx
test	rcx, rcx
jne	sn_decode_core_L124
sn_decode_core_L7:
movsx	rdx, dword [r14+2332]
mov	r8, rsp
mov	qword [rbp+-272], rsp
mov	rcx, rdx
lea	rdx, [0+rdx*4+15]
mov	rsi, rdx
and	rdx, -4096
sub	r8, rdx
and	rsi, -16
cmp	rsp, r8
je	sn_decode_core_L9
sn_decode_core_L125:
sub	rsp, 4096
or	qword [rsp+4088], 0
cmp	rsp, r8
jne	sn_decode_core_L125
sn_decode_core_L9:
and	esi, 4095
sub	rsp, rsi
test	rsi, rsi
je	sn_decode_core_L10
or	qword [rsp+rsi+-8], 0
sn_decode_core_L10:
lea	edx, [rcx+16]
mov	rsi, rsp
mov	qword [rbp+-288], rsp
movsx	rdx, edx
lea	rcx, [0+rdx*4+15]
mov	rdx, rcx
and	rcx, -4096
sub	rsi, rcx
and	rdx, -16
cmp	rsp, rsi
je	sn_decode_core_L12
sn_decode_core_L126:
sub	rsp, 4096
or	qword [rsp+4088], 0
cmp	rsp, rsi
jne	sn_decode_core_L126
sn_decode_core_L12:
and	edx, 4095
sub	rsp, rdx
test	rdx, rdx
je	sn_decode_core_L13
or	qword [rsp+rdx+-8], 0
sn_decode_core_L13:
movzx	esi, byte [r14+2789]
mov	r15, rsp
movsx	r9, eax
mov	r11, r14
movsx	rcx, byte [r14+2790]
mov	edx, esi
mov	byte [rbp+-88], sil
sar	dl, 1
cmp	byte [r14+2791], 3
movsx	rdx, dl
setle	byte [rbp+-297]
lea	rcx, [rcx+rdx*2]
lea	rdx, [rel sn_silk_Quantization_Offsets_Q10]
movsx	r8d, word [rdx+rcx*2]
movsx	edx, byte [r14+2794]
mov	ecx, 1
shl	r8d, 4
test	eax, eax
jg	sn_decode_core_L20
jmp	sn_decode_core_L21
align 16
align 8
sn_decode_core_L127:
sub	eax, 1280
sn_decode_core_L18:
add	eax, r8d
mov	r10d, eax
neg	r10d
test	esi, esi
cmovs	eax, r10d
add	edx, esi
mov	dword [r11+rcx*4], eax
lea	rax, [rcx+1]
cmp	r9, rcx
je	sn_decode_core_L21
mov	rcx, rax
sn_decode_core_L20:
imul	edx, edx, 196314165
lea	esi, [rdx+907633515]
movsx	edx, word [rdi+rcx*2+-2]
mov	eax, edx
shl	eax, 14
test	eax, eax
jg	sn_decode_core_L127
lea	r10d, [rax+1280]
cmovne	eax, r10d
jmp	sn_decode_core_L18
sn_decode_core_L122:
or	qword [rsp+rcx+-8], 0
jmp	sn_decode_core_L4
sn_decode_core_L124:
or	qword [rsp+rcx+-8], 0
jmp	sn_decode_core_L7
align 16
align 8
sn_decode_core_L21:
lea	rbx, [r14+1284]
mov	edx, 64
mov	rdi, r15
mov	rsi, rbx
call	sn_copy
lea	rsi, [r14+4]
mov	qword [rbp+-216], rsi
mov	esi, dword [r14+2324]
test	esi, esi
jle	sn_decode_core_L16
mov	eax, dword [r14+2336]
mov	qword [rbp+-280], rbx
mov	qword [rbp+-160], 0
mov	dword [rbp+-252], eax
mov	rax, qword [rbp+-232]
add	rax, 96
mov	qword [rbp+-240], rax
mov	rax, qword [rbp+-264]
mov	qword [rbp+-88], rax
lea	rax, [rbp+-80]
mov	qword [rbp+-248], rax
align 16
align 8
sn_decode_core_L59:
mov	r12, qword [rbp+-160]
mov	r13, qword [rbp+-232]
movsx	rdx, dword [r14+2340]
mov	rdi, qword [rbp+-248]
mov	eax, r12d
sar	eax, 1
add	rdx, rdx
add	eax, 1
cdqe
shl	rax, 5
lea	rbx, [r13+rax+0]
mov	rsi, rbx
call	sn_copy
mov	edi, dword [r13+r12*4+16]
movzx	r8d, byte [r14+2789]
mov	eax, edi
sar	eax, 6
mov	dword [rbp+-152], eax
test	edi, edi
je	sn_decode_core_L61
mov	esi, edi
mov	r9d, 15
neg	esi
cmovs	esi, edi
bsr	esi, esi
xor	esi, 31
lea	ecx, [rsi+-1]
sub	r9d, esi
sn_decode_core_L22:
mov	eax, edi
xor	edx, edx
shl	eax, cl
mov	r10d, eax
mov	ecx, eax
mov	eax, 536870911
sar	r10d, 16
idiv	r10d
movsx	rdx, ecx
mov	rcx, rdx
movsx	r10, ax
mov	r11d, eax
cdqe
imul	rcx, r10
shl	r11d, 16
sar	rcx, 16
lea	ecx, [0+rcx*8+0]
neg	ecx
movsx	rcx, ecx
imul	rcx, rax
sar	rcx, 16
lea	eax, [r11+rcx]
mov	ecx, r9d
mov	r12d, eax
sar	r12d, cl
test	r9d, r9d
jle	sn_decode_core_L128
sn_decode_core_L26:
mov	eax, dword [r14]
mov	r13d, 65536
cmp	edi, eax
jne	sn_decode_core_L129
sn_decode_core_L27:
mov	ecx, dword [r14+4184]
mov	dword [r14], edi
test	ecx, ecx
je	sn_decode_core_L34
cmp	dword [r14+4188], 2
je	sn_decode_core_L130
sn_decode_core_L34:
movsx	r9, dword [r14+2332]
mov	eax, r9d
cmp	r8b, 2
je	sn_decode_core_L35
sn_decode_core_L39:
movsx	r9, eax
test	eax, eax
jle	sn_decode_core_L46
mov	rbx, qword [rbp+-216]
mov	qword [rbp+-144], rbx
sn_decode_core_L48:
mov	ebx, dword [r14+2340]
movsx	rdx, word [rbp+-60]
movsx	r9, eax
movsx	rsi, word [rbp+-80]
movsx	r10, dword [rbp+-152]
movsx	r13, word [rbp+-68]
movsx	r12, word [rbp+-66]
mov	dword [rbp+-92], ebx
sar	ebx, 1
mov	dword [rbp+-96], ebx
movsx	rbx, word [rbp+-78]
mov	qword [rbp+-168], rdx
movsx	rdx, word [rbp+-58]
mov	qword [rbp+-104], rbx
movsx	rbx, word [rbp+-76]
mov	qword [rbp+-176], rdx
movsx	rdx, word [rbp+-56]
mov	qword [rbp+-112], rbx
movsx	rbx, word [rbp+-74]
mov	qword [rbp+-184], rdx
movsx	rdx, word [rbp+-54]
mov	qword [rbp+-120], rbx
movsx	rbx, word [rbp+-72]
mov	qword [rbp+-192], rdx
movsx	rdx, word [rbp+-52]
mov	qword [rbp+-128], rbx
movsx	rbx, word [rbp+-70]
mov	qword [rbp+-200], rdx
movsx	rdx, word [rbp+-50]
mov	qword [rbp+-136], rbx
movsx	r11, word [rbp+-62]
mov	qword [rbp+-208], rdx
movsx	rbx, word [rbp+-64]
xor	edx, edx
mov	qword [rbp+-152], r10
mov	qword [rbp+-224], r14
mov	r14, rsi
jmp	sn_decode_core_L58
align 16
align 8
sn_decode_core_L132:
cmp	eax, -134217728
jl	sn_decode_core_L51
shl	eax, 4
mov	ecx, eax
add	ecx, edi
js	sn_decode_core_L53
sn_decode_core_L52:
mov	rcx, -2147483648
mov	r8d, -2147483648
test	edi, eax
jns	sn_decode_core_L54
sn_decode_core_L56:
mov	rax, qword [rbp+-152]
add	esi, 16
movsx	rsi, esi
imul	rcx, rax
mov	dword [r15+rsi*4], r8d
mov	eax, 32767
sar	rcx, 16
sar	ecx, 7
add	ecx, 1
mov	esi, ecx
sar	esi, 1
cmp	ecx, 65535
jg	sn_decode_core_L57
cmp	esi, -32768
mov	eax, -32768
cmovge	eax, esi
sn_decode_core_L57:
mov	rsi, qword [rbp+-88]
mov	word [rsi+rdx*2], ax
add	rdx, 1
cmp	rdx, r9
je	sn_decode_core_L131
sn_decode_core_L58:
lea	eax, [rdx+15]
lea	ecx, [rdx+14]
mov	rdi, qword [rbp+-104]
mov	esi, edx
cdqe
movsx	rcx, ecx
movsx	rax, dword [r15+rax*4]
movsx	rcx, dword [r15+rcx*4]
imul	rax, r14
imul	rcx, rdi
mov	edi, dword [rbp+-96]
sar	rax, 16
sar	rcx, 16
add	eax, ecx
lea	ecx, [rdx+13]
movsx	rcx, ecx
add	eax, edi
mov	rdi, qword [rbp+-112]
movsx	rcx, dword [r15+rcx*4]
imul	rcx, rdi
mov	rdi, qword [rbp+-120]
sar	rcx, 16
add	eax, ecx
lea	ecx, [rdx+12]
movsx	rcx, ecx
movsx	rcx, dword [r15+rcx*4]
imul	rcx, rdi
mov	rdi, qword [rbp+-128]
sar	rcx, 16
add	eax, ecx
lea	ecx, [rdx+11]
movsx	rcx, ecx
movsx	rcx, dword [r15+rcx*4]
imul	rcx, rdi
mov	rdi, qword [rbp+-136]
sar	rcx, 16
add	eax, ecx
lea	ecx, [rdx+10]
movsx	rcx, ecx
movsx	rcx, dword [r15+rcx*4]
imul	rcx, rdi
sar	rcx, 16
add	eax, ecx
lea	ecx, [rdx+9]
movsx	rcx, ecx
movsx	rcx, dword [r15+rcx*4]
imul	rcx, r13
sar	rcx, 16
add	eax, ecx
lea	ecx, [rdx+8]
movsx	rcx, ecx
movsx	rcx, dword [r15+rcx*4]
imul	rcx, r12
sar	rcx, 16
add	eax, ecx
lea	ecx, [rdx+7]
movsx	rcx, ecx
movsx	rcx, dword [r15+rcx*4]
imul	rcx, rbx
sar	rcx, 16
add	eax, ecx
lea	ecx, [rdx+6]
movsx	rcx, ecx
movsx	rcx, dword [r15+rcx*4]
imul	rcx, r11
sar	rcx, 16
add	eax, ecx
cmp	dword [rbp+-92], 16
jne	sn_decode_core_L49
mov	rdi, qword [rbp+-200]
movsx	rcx, dword [r15+rdx*4+4]
mov	r8, qword [rbp+-208]
imul	rcx, rdi
movsx	rdi, dword [r15+rdx*4]
imul	rdi, r8
mov	r8, qword [rbp+-168]
sar	rcx, 16
sar	rdi, 16
add	ecx, edi
lea	edi, [rdx+5]
movsx	rdi, edi
movsx	rdi, dword [r15+rdi*4]
imul	rdi, r8
mov	r8, qword [rbp+-176]
sar	rdi, 16
add	ecx, edi
lea	edi, [rdx+4]
movsx	rdi, edi
movsx	rdi, dword [r15+rdi*4]
imul	rdi, r8
mov	r8, qword [rbp+-184]
sar	rdi, 16
add	ecx, edi
lea	edi, [rdx+3]
movsx	rdi, edi
movsx	rdi, dword [r15+rdi*4]
imul	rdi, r8
mov	r8, qword [rbp+-192]
sar	rdi, 16
add	ecx, edi
lea	edi, [rdx+2]
movsx	rdi, edi
movsx	rdi, dword [r15+rdi*4]
imul	rdi, r8
sar	rdi, 16
add	ecx, edi
add	eax, ecx
sn_decode_core_L49:
mov	rdi, qword [rbp+-144]
mov	edi, dword [rdi+rdx*4]
cmp	eax, 134217727
jle	sn_decode_core_L132
mov	ecx, edi
mov	eax, 2147483632
add	ecx, 2147483632
js	sn_decode_core_L53
sn_decode_core_L54:
lea	r8d, [rdi+rax]
movsx	rcx, r8d
jmp	sn_decode_core_L56
align 16
align 8
sn_decode_core_L53:
mov	r10d, edi
mov	ecx, 2147483647
mov	r8d, 2147483647
or	r10d, eax
jns	sn_decode_core_L56
jmp	sn_decode_core_L54
align 16
align 8
sn_decode_core_L51:
mov	ecx, edi
mov	eax, -2147483648
add	ecx, -2147483648
jns	sn_decode_core_L52
jmp	sn_decode_core_L54
align 16
align 8
sn_decode_core_L131:
mov	r14, qword [rbp+-224]
sn_decode_core_L46:
lea	rsi, [r15+r9*4]
mov	edx, 64
mov	rdi, r15
call	sn_copy
movsx	rax, dword [r14+2332]
mov	rbx, qword [rbp+-216]
add	qword [rbp+-160], 1
lea	rbx, [rbx+rax*4]
add	qword [rbp+-240], 10
mov	qword [rbp+-216], rbx
mov	rbx, qword [rbp+-88]
lea	rax, [rbx+rax*2]
mov	qword [rbp+-88], rax
mov	rax, qword [rbp+-160]
cmp	dword [r14+2324], eax
jg	sn_decode_core_L59
mov	rbx, qword [rbp+-280]
sn_decode_core_L16:
mov	rsi, r15
mov	rdi, rbx
mov	edx, 64
call	sn_copy
lea	rsp, [rbp+-40]
pop	rbx
pop	r12
pop	r13
pop	r14
pop	r15
pop	rbp
ret
align 16
align 8
sn_decode_core_L129:
test	eax, eax
je	sn_decode_core_L63
mov	r9d, eax
neg	r9d
cmovs	r9d, eax
bsr	r9d, r9d
xor	r9d, 31
lea	ecx, [r9+-1]
sn_decode_core_L28:
shl	eax, cl
movsx	rcx, eax
imul	rcx, r10
sar	rcx, 16
imul	rdx, rcx
sar	rdx, 32
shl	edx, 3
sub	eax, edx
cdqe
imul	rax, r10
sar	rax, 16
add	eax, ecx
mov	ecx, r9d
sub	ecx, esi
add	ecx, 13
js	sn_decode_core_L133
cmp	ecx, 31
jg	sn_decode_core_L64
sar	eax, cl
movsx	rsi, eax
mov	r13, rsi
sn_decode_core_L32:
mov	rdx, r15
lea	rcx, [r15+64]
align 16
align 8
sn_decode_core_L33:
movsx	rax, dword [rdx]
add	rdx, 4
imul	rax, rsi
sar	rax, 16
mov	dword [rdx+-4], eax
cmp	rcx, rdx
jne	sn_decode_core_L33
jmp	sn_decode_core_L27
align 16
align 8
sn_decode_core_L61:
mov	r9d, -17
mov	ecx, 31
mov	esi, 32
jmp	sn_decode_core_L22
align 16
align 8
sn_decode_core_L128:
lea	ecx, [rsi+-15]
mov	r12d, 2147483647
sar	r12d, cl
cmp	eax, r12d
jg	sn_decode_core_L25
mov	r9d, -2147483648
sar	r9d, cl
cmp	r9d, eax
cmovge	eax, r9d
mov	r12d, eax
sn_decode_core_L25:
shl	r12d, cl
jmp	sn_decode_core_L26
align 16
align 8
sn_decode_core_L130:
cmp	r8b, 2
je	sn_decode_core_L134
cmp	qword [rbp+-160], 1
jbe	sn_decode_core_L135
mov	eax, dword [r14+2332]
jmp	sn_decode_core_L39
align 16
align 8
sn_decode_core_L64:
xor	esi, esi
xor	r13d, r13d
jmp	sn_decode_core_L32
align 16
align 8
sn_decode_core_L63:
mov	ecx, 31
mov	r9d, 32
jmp	sn_decode_core_L28
sn_decode_core_L134:
movsx	r9, dword [r14+2332]
sn_decode_core_L35:
mov	rsi, qword [rbp+-232]
mov	rax, qword [rbp+-160]
mov	r10d, dword [rsi+rax*4]
test	rax, rax
je	sn_decode_core_L37
cmp	eax, 2
jne	sn_decode_core_L38
cmp	byte [rbp+-297], 0
jne	sn_decode_core_L136
sn_decode_core_L38:
cmp	r13d, 65536
jne	sn_decode_core_L137
sn_decode_core_L43:
mov	eax, dword [rbp+-252]
mov	rbx, qword [rbp+-272]
add	eax, 2
sub	eax, r10d
cdqe
lea	rcx, [rbx+rax*4]
mov	eax, r9d
test	r9d, r9d
jle	sn_decode_core_L46
mov	rsi, qword [rbp+-240]
mov	dword [rbp+-92], eax
mov	qword [rbp+-104], r14
mov	r8, qword [rbp+-216]
movsx	r13, word [rsi]
movsx	r12, word [rsi+2]
movsx	rbx, word [rsi+4]
movsx	r11, word [rsi+6]
movsx	r10, word [rsi+8]
mov	esi, dword [rbp+-252]
mov	rdi, qword [rbp+-288]
mov	rdx, qword [rbp+-272]
lea	r9d, [r9+rsi]
align 16
align 8
sn_decode_core_L47:
movsx	r14, dword [rcx]
movsx	rax, dword [rcx+-4]
add	r8, 4
add	rcx, 4
add	rdi, 4
imul	r14, r13
imul	rax, r12
sar	r14, 16
sar	rax, 16
lea	r14d, [r14+rax+2]
movsx	rax, dword [rcx+-12]
imul	rax, rbx
sar	rax, 16
add	r14d, eax
movsx	rax, dword [rcx+-16]
imul	rax, r11
sar	rax, 16
add	r14d, eax
movsx	rax, dword [rcx+-20]
imul	rax, r10
sar	rax, 16
add	eax, r14d
mov	r14d, dword [r8+-4]
lea	eax, [r14+rax*2]
movsx	r14, esi
add	esi, 1
mov	dword [rdi+-4], eax
add	eax, eax
mov	dword [rdx+r14*4], eax
cmp	esi, r9d
jne	sn_decode_core_L47
mov	rbx, qword [rbp+-288]
mov	eax, dword [rbp+-92]
mov	dword [rbp+-252], esi
mov	r14, qword [rbp+-104]
mov	qword [rbp+-144], rbx
jmp	sn_decode_core_L48
align 16
align 8
sn_decode_core_L133:
lea	ecx, [rsi+-13]
mov	r13d, 2147483647
sub	ecx, r9d
sar	r13d, cl
cmp	eax, r13d
jg	sn_decode_core_L31
mov	r13d, -2147483648
sar	r13d, cl
cmp	r13d, eax
cmovl	r13d, eax
sn_decode_core_L31:
shl	r13d, cl
movsx	rsi, r13d
jmp	sn_decode_core_L32
sn_decode_core_L37:
mov	eax, dword [r14+2336]
mov	dword [rbp+-92], r10d
movsx	r12, r12d
mov	r8d, dword [r14+2340]
mov	rdx, qword [rbp+-296]
sub	eax, 2
mov	r9d, dword [rbp+-256]
sub	eax, r8d
lea	ecx, [r10+r8+2]
sub	eax, r10d
cdqe
lea	rdi, [rdx+rax*2]
lea	rsi, [r14+rax*2+1348]
mov	rdx, rbx
call	sn_silk_LPC_analysis_filter
mov	rax, qword [rbp+-232]
mov	r10d, dword [rbp+-92]
movsx	rax, word [rax+136]
imul	rax, r12
sar	rax, 16
lea	r12d, [0+rax*4+0]
sn_decode_core_L40:
lea	eax, [r10+2]
test	eax, eax
jle	sn_decode_core_L119
mov	eax, dword [r14+2336]
mov	edi, dword [rbp+-252]
movsx	r12, r12d
mov	r8, qword [rbp+-296]
mov	r9, qword [rbp+-272]
lea	esi, [rax+-3]
lea	edx, [rax+-1]
sub	edi, eax
sub	esi, r10d
align 16
align 8
sn_decode_core_L42:
movsx	rax, edx
lea	ecx, [rdi+rdx]
sub	edx, 1
movsx	rax, word [r8+rax*2]
movsx	rcx, ecx
imul	rax, r12
sar	rax, 16
mov	dword [r9+rcx*4], eax
cmp	edx, esi
jne	sn_decode_core_L42
sn_decode_core_L119:
movsx	r9, dword [r14+2332]
jmp	sn_decode_core_L43
sn_decode_core_L137:
lea	eax, [r10+2]
test	eax, eax
jle	sn_decode_core_L43
mov	eax, dword [rbp+-252]
mov	rdi, qword [rbp+-272]
movsx	r13, r13d
lea	esi, [rax+-3]
lea	edx, [rax+-1]
sub	esi, r10d
align 16
align 8
sn_decode_core_L45:
movsx	rcx, edx
sub	edx, 1
movsx	rax, dword [rdi+rcx*4]
imul	rax, r13
sar	rax, 16
mov	dword [rdi+rcx*4], eax
cmp	esi, edx
jne	sn_decode_core_L45
jmp	sn_decode_core_L43
sn_decode_core_L136:
movsx	rax, dword [r14+2336]
mov	r13d, dword [r14+2340]
mov	dword [rbp+-92], r10d
mov	rsi, qword [rbp+-264]
lea	ecx, [rax+-2]
lea	rdi, [r14+rax*2+1348]
mov	edx, ecx
mov	dword [rbp+-112], ecx
sub	edx, r13d
sub	edx, r10d
mov	dword [rbp+-104], edx
lea	edx, [r9+r9]
movsx	rdx, edx
add	rdx, rdx
call	sn_copy
movsx	r8, dword [rbp+-104]
mov	ecx, dword [rbp+-112]
mov	rdx, rbx
mov	eax, dword [r14+2332]
mov	r10d, dword [rbp+-92]
add	r13d, dword [r14+2336]
mov	r9d, dword [rbp+-256]
lea	eax, [r8+rax*2]
sub	r13d, ecx
cdqe
lea	ecx, [r13+r10+0]
lea	rsi, [r14+rax*2+1348]
mov	rax, qword [rbp+-296]
lea	rdi, [rax+r8*2]
mov	r8d, dword [r14+2340]
call	sn_silk_LPC_analysis_filter
mov	r10d, dword [rbp+-92]
jmp	sn_decode_core_L40
sn_decode_core_L135:
mov	rdi, qword [rbp+-240]
mov	edx, 10
xor	esi, esi
call	sn_set
mov	rax, qword [rbp+-240]
mov	edx, 4096
mov	r10d, dword [r14+2308]
mov	rsi, qword [rbp+-232]
mov	word [rax+4], dx
mov	rax, qword [rbp+-160]
mov	dword [rsi+rax*4], r10d
test	rax, rax
je	sn_decode_core_L37
movsx	r9, dword [r14+2332]
jmp	sn_decode_core_L38

; ===== decode_frame.c =====
section .text
align 16
sn_silk_decode_frame:
push	rbp
mov	rax, rsi
mov	rbp, rsp
push	r15
push	r14
mov	r14, rcx
mov	ecx, r8d
push	r13
push	r12
mov	r12, rdx
push	rbx
mov	rbx, rdi
sub	rsp, 184
mov	dword [rbp+-52], 0
mov	r13d, dword [rdi+2328]
test	r8d, r8d
je	sn_decode_frame_L2
cmp	r8d, 2
jne	sn_decode_frame_L3
movsx	rdx, dword [rdi+2400]
cmp	dword [rdi+rdx*4+2432], 1
je	sn_decode_frame_L2
sn_decode_frame_L3:
mov	r8d, dword [rbp+16]
mov	ecx, 1
mov	rdx, r12
mov	rdi, rbx
lea	r10, [rbp+-188]
mov	rsi, r10
mov	qword [rbp+-200], r10
call	sn_silk_PLC
movsx	rax, dword [rbx+2328]
mov	r15d, dword [rbx+2336]
lea	rdi, [rbx+1348]
sub	r15d, eax
lea	rsi, [rbx+rax*2+1348]
movsx	r15, r15d
add	r15, r15
mov	rdx, r15
call	sn_move
movsx	rdx, dword [rbx+2328]
lea	rdi, [rbx+r15+1348]
mov	rsi, r12
add	rdx, rdx
call	sn_copy
mov	r10, qword [rbp+-200]
sn_decode_frame_L7:
mov	ecx, r13d
mov	rdx, r12
mov	rsi, r10
mov	rdi, rbx
call	sn_silk_CNG
mov	edx, r13d
mov	rsi, r12
mov	rdi, rbx
call	sn_silk_PLC_glue_frames
mov	eax, dword [rbx+2324]
sub	eax, 1
cdqe
mov	eax, dword [rbp+rax*4+-188]
mov	dword [rbx+2308], eax
xor	eax, eax
mov	dword [r14], r13d
lea	rsp, [rbp+-40]
pop	rbx
pop	r12
pop	r13
pop	r14
pop	r15
pop	rbp
ret
align 16
align 8
sn_decode_frame_L2:
lea	edx, [r13+15]
mov	rsi, rsp
mov	r11, rsp
and	edx, -16
movsx	rdx, edx
add	rdx, rdx
mov	rdi, rdx
and	rdi, -4096
sub	rsi, rdi
cmp	rsp, rsi
je	sn_decode_frame_L5
sn_decode_frame_L16:
sub	rsp, 4096
or	qword [rsp+4088], 0
cmp	rsp, rsi
jne	sn_decode_frame_L16
sn_decode_frame_L5:
and	edx, 4095
sub	rsp, rdx
test	rdx, rdx
je	sn_decode_frame_L6
or	qword [rsp+rdx+-8], 0
sn_decode_frame_L6:
mov	edx, dword [rbx+2400]
mov	r8d, r9d
mov	rsi, rax
mov	rdi, rbx
mov	qword [rbp+-216], r11
mov	r15, rsp
mov	dword [rbp+-204], r9d
mov	qword [rbp+-200], rax
call	sn_silk_decode_indices
movsx	ecx, byte [rbx+2790]
mov	rsi, r15
mov	r8d, dword [rbx+2328]
movsx	edx, byte [rbx+2789]
mov	rdi, qword [rbp+-200]
call	sn_silk_decode_pulses
lea	r10, [rbp+-188]
mov	edx, dword [rbp+-204]
mov	rdi, rbx
mov	rsi, r10
mov	qword [rbp+-200], r10
call	sn_silk_decode_parameters
mov	r8d, dword [rbp+16]
mov	rcx, r15
mov	rdx, r12
mov	rsi, qword [rbp+-200]
mov	rdi, rbx
call	sn_silk_decode_core
movsx	rax, dword [rbx+2328]
mov	r15d, dword [rbx+2336]
lea	rdi, [rbx+1348]
sub	r15d, eax
lea	rsi, [rbx+rax*2+1348]
movsx	r15, r15d
add	r15, r15
mov	rdx, r15
call	sn_move
movsx	rdx, dword [rbx+2328]
lea	rdi, [rbx+r15+1348]
mov	rsi, r12
add	rdx, rdx
call	sn_copy
mov	r8d, dword [rbp+16]
xor	ecx, ecx
mov	rdx, r12
mov	rsi, qword [rbp+-200]
mov	rdi, rbx
call	sn_silk_PLC
movsx	eax, byte [rbx+2789]
mov	dword [rbx+4184], 0
mov	dword [rbx+2376], 0
mov	dword [rbx+4188], eax
mov	rsp, qword [rbp+-216]
mov	r10, qword [rbp+-200]
jmp	sn_decode_frame_L7

; ===== decode_parameters.c =====
section .text
align 16
sn_silk_decode_parameters:
push	r14
xor	ecx, ecx
push	r13
push	r12
mov	r12, rsi
lea	rsi, [rdi+2760]
push	rbp
mov	rbp, rdi
push	rbx
lea	rbx, [r12+64]
sub	rsp, 64
cmp	edx, 2
mov	r8d, dword [rbp+2324]
lea	rdx, [rdi+2312]
sete	cl
lea	rdi, [r12+16]
mov	r13, rsp
call	sn_silk_gains_dequant
mov	rdx, qword [rbp+2752]
lea	rsi, [rbp+2768]
mov	rdi, r13
call	sn_silk_NLSF_decode
mov	ecx, dword [rbp+4192]
mov	rsi, r13
mov	rdi, rbx
mov	edx, dword [rbp+2340]
call	sn_silk_NLSF2A
cmp	dword [rbp+2376], 1
je	sn_decode_parameters_L20
movsx	r8d, byte [rbp+2791]
mov	edi, dword [rbp+2340]
cmp	r8b, 3
jg	sn_decode_parameters_L3
test	edi, edi
jle	sn_decode_parameters_L21
movsx	r9, edi
xor	edx, edx
lea	rsi, [rsp+32]
add	r9, r9
align 16
align 8
sn_decode_parameters_L6:
movsx	r10d, word [rbp+rdx+2344]
movsx	eax, word [r13+rdx+0]
sub	eax, r10d
mov	ecx, r10d
imul	eax, r8d
sar	eax, 2
add	ecx, eax
mov	word [rsi+rdx], cx
add	rdx, 2
cmp	r9, rdx
jne	sn_decode_parameters_L6
sn_decode_parameters_L7:
lea	r14, [r12+32]
mov	ecx, dword [rbp+4192]
mov	edx, edi
mov	rdi, r14
call	sn_silk_NLSF2A
sn_decode_parameters_L5:
movsx	rdx, dword [rbp+2340]
lea	rdi, [rbp+2344]
mov	rsi, r13
add	rdx, rdx
call	sn_copy
mov	eax, dword [rbp+4184]
test	eax, eax
jne	sn_decode_parameters_L22
sn_decode_parameters_L8:
cmp	byte [rbp+2789], 2
movsx	r8, dword [rbp+2324]
je	sn_decode_parameters_L23
lea	rdx, [0+r8*4+0]
xor	esi, esi
mov	rdi, r12
call	sn_set
mov	eax, dword [rbp+2324]
lea	rdi, [r12+96]
xor	esi, esi
lea	edx, [rax+rax*4]
movsx	rdx, edx
add	rdx, rdx
call	sn_set
mov	byte [rbp+2792], 0
xor	eax, eax
sn_decode_parameters_L11:
mov	dword [r12+136], eax
add	rsp, 64
pop	rbx
pop	rbp
pop	r12
pop	r13
pop	r14
ret
align 16
align 8
sn_decode_parameters_L20:
mov	byte [rbp+2791], 4
mov	edi, dword [rbp+2340]
sn_decode_parameters_L3:
movsx	rdx, edi
lea	r14, [r12+32]
mov	rsi, rbx
add	rdx, rdx
mov	rdi, r14
call	sn_copy
jmp	sn_decode_parameters_L5
align 16
align 8
sn_decode_parameters_L23:
mov	ecx, dword [rbp+2316]
movsx	esi, byte [rbp+2788]
mov	rdx, r12
movsx	edi, word [rbp+2786]
call	sn_silk_decode_pitch
movsx	edi, byte [rbp+2792]
call	sn_paos_ltp_vq
mov	r9, rax
mov	eax, dword [rbp+2324]
test	eax, eax
jle	sn_decode_parameters_L14
lea	r8, [rbp+2764]
lea	r10d, [rax+rax*4]
xor	edi, edi
sn_decode_parameters_L13:
movsx	eax, byte [r8]
lea	esi, [rax+rax*4]
xor	eax, eax
movsx	rsi, esi
add	rsi, r9
align 16
align 8
sn_decode_parameters_L12:
movsx	cx, byte [rsi+rax]
lea	edx, [rdi+rax]
add	rax, 1
movsx	rdx, edx
shl	ecx, 7
mov	word [r12+rdx*2+96], cx
cmp	rax, 5
jne	sn_decode_parameters_L12
add	edi, 5
add	r8, 1
cmp	r10d, edi
jne	sn_decode_parameters_L13
sn_decode_parameters_L14:
movsx	rdx, byte [rbp+2793]
lea	rax, [rel sn_silk_LTPScales_table_Q14]
movsx	eax, word [rax+rdx*2]
jmp	sn_decode_parameters_L11
align 16
align 8
sn_decode_parameters_L22:
mov	esi, dword [rbp+2340]
mov	rdi, r14
mov	edx, 63570
call	sn_silk_bwexpander
mov	esi, dword [rbp+2340]
mov	edx, 63570
mov	rdi, rbx
call	sn_silk_bwexpander
jmp	sn_decode_parameters_L8
sn_decode_parameters_L21:
lea	rsi, [rsp+32]
jmp	sn_decode_parameters_L7

; ===== decode_indices.c =====
section .text
align 16
sn_silk_decode_indices:
push	r15
push	r14
mov	r14, rdi
push	r13
mov	r13d, r8d
push	r12
push	rbp
push	rbx
mov	rbx, rsi
sub	rsp, 56
test	ecx, ecx
jne	sn_decode_indices_L2
movsx	rdx, edx
mov	edx, dword [rdi+rdx*4+2416]
test	edx, edx
je	sn_decode_indices_L3
sn_decode_indices_L2:
mov	edx, 8
lea	rsi, [rel sn_silk_type_offset_VAD_iCDF]
mov	rdi, rbx
call	sn_ec_dec_icdf
add	eax, 2
sn_decode_indices_L4:
mov	edx, eax
and	eax, 1
sar	edx, 1
mov	byte [r14+2790], al
mov	byte [r14+2789], dl
cmp	r13d, 2
je	sn_decode_indices_L29
movsx	rdx, dl
lea	rax, [rel sn_silk_gain_iCDF]
mov	rdi, rbx
lea	rsi, [rax+rdx*8]
mov	edx, 8
call	sn_ec_dec_icdf
mov	edx, 8
lea	rsi, [rel sn_silk_uniform8_iCDF]
mov	rdi, rbx
shl	eax, 3
mov	byte [r14+2760], al
call	sn_ec_dec_icdf
add	al, byte [r14+2760]
sn_decode_indices_L9:
cmp	dword [r14+2324], 1
mov	byte [r14+2760], al
mov	ebp, 1
lea	r12, [rel sn_silk_delta_gain_iCDF]
jle	sn_decode_indices_L10
sn_decode_indices_L6:
mov	edx, 8
mov	rsi, r12
mov	rdi, rbx
call	sn_ec_dec_icdf
mov	byte [r14+rbp+2760], al
add	rbp, 1
cmp	dword [r14+2324], ebp
jg	sn_decode_indices_L6
sn_decode_indices_L10:
mov	rax, qword [r14+2752]
mov	rdi, rbx
lea	rbp, [rsp+16]
xor	r15d, r15d
movzx	esi, byte [r14+2789]
lea	r12, [rel sn_silk_NLSF_EXT_iCDF]
movsx	edx, word [rax]
sar	sil, 1
movsx	esi, sil
imul	esi, edx
mov	edx, 8
movsx	rsi, esi
add	rsi, qword [rax+24]
call	sn_ec_dec_icdf
mov	rdx, qword [r14+2752]
mov	rsi, rsp
mov	rdi, rbp
mov	byte [r14+2768], al
movsx	ecx, al
call	sn_silk_NLSF_unpack
mov	rax, qword [r14+2752]
cmp	word [rax+2], 0
jg	sn_decode_indices_L7
jmp	sn_decode_indices_L8
align 16
align 8
sn_decode_indices_L13:
cmp	eax, 8
je	sn_decode_indices_L30
sn_decode_indices_L14:
sub	eax, 4
mov	byte [r14+r15+2769], al
mov	rax, qword [r14+2752]
add	r15, 1
movsx	edx, word [rax+2]
cmp	edx, r15d
jle	sn_decode_indices_L8
sn_decode_indices_L7:
movsx	rsi, word [rbp+r15*2+0]
mov	edx, 8
add	rsi, qword [rax+48]
mov	rdi, rbx
call	sn_ec_dec_icdf
test	eax, eax
jne	sn_decode_indices_L13
mov	edx, 8
mov	rsi, r12
mov	rdi, rbx
call	sn_ec_dec_icdf
neg	eax
jmp	sn_decode_indices_L14
align 16
align 8
sn_decode_indices_L30:
mov	edx, 8
mov	rsi, r12
mov	rdi, rbx
call	sn_ec_dec_icdf
add	eax, 8
jmp	sn_decode_indices_L14
align 16
align 8
sn_decode_indices_L8:
cmp	dword [r14+2324], 4
je	sn_decode_indices_L11
mov	eax, 4
sn_decode_indices_L12:
mov	byte [r14+2791], al
movsx	eax, byte [r14+2789]
cmp	al, 2
je	sn_decode_indices_L31
sn_decode_indices_L15:
mov	dword [r14+2408], eax
mov	rdi, rbx
mov	edx, 8
lea	rsi, [rel sn_silk_uniform4_iCDF]
call	sn_ec_dec_icdf
mov	byte [r14+2794], al
add	rsp, 56
pop	rbx
pop	rbp
pop	r12
pop	r13
pop	r14
pop	r15
ret
align 16
align 8
sn_decode_indices_L3:
mov	edx, 8
lea	rsi, [rel sn_silk_type_offset_no_VAD_iCDF]
mov	rdi, rbx
call	sn_ec_dec_icdf
jmp	sn_decode_indices_L4
align 16
align 8
sn_decode_indices_L31:
cmp	r13d, 2
jne	sn_decode_indices_L16
cmp	dword [r14+2408], 2
je	sn_decode_indices_L32
sn_decode_indices_L16:
mov	edx, 8
lea	rsi, [rel sn_silk_pitch_lag_iCDF]
mov	rdi, rbx
call	sn_ec_dec_icdf
mov	rsi, qword [r14+2384]
mov	rdi, rbx
mov	edx, eax
mov	eax, dword [r14+2316]
sar	eax, 1
imul	eax, edx
mov	edx, 8
mov	word [r14+2786], ax
call	sn_ec_dec_icdf
add	ax, word [r14+2786]
sn_decode_indices_L17:
mov	word [r14+2786], ax
mov	rsi, qword [r14+2392]
mov	edx, 8
mov	rdi, rbx
mov	word [r14+2412], ax
call	sn_ec_dec_icdf
mov	rdi, rbx
mov	edx, 8
lea	rsi, [rel sn_silk_LTP_per_index_iCDF]
mov	byte [r14+2788], al
call	sn_ec_dec_icdf
mov	byte [r14+2792], al
movsx	edi, al
mov	eax, dword [r14+2324]
test	eax, eax
jle	sn_decode_indices_L18
xor	ebp, ebp
sn_decode_indices_L19:
call	sn_paos_ltp_icdf
mov	edx, 8
mov	rdi, rbx
mov	rsi, rax
call	sn_ec_dec_icdf
mov	byte [r14+rbp+2764], al
add	rbp, 1
cmp	dword [r14+2324], ebp
jle	sn_decode_indices_L18
movsx	edi, byte [r14+2792]
jmp	sn_decode_indices_L19
align 16
align 8
sn_decode_indices_L29:
lea	r12, [rel sn_silk_delta_gain_iCDF]
mov	edx, 8
mov	rdi, rbx
mov	rsi, r12
call	sn_ec_dec_icdf
jmp	sn_decode_indices_L9
align 16
align 8
sn_decode_indices_L18:
test	r13d, r13d
je	sn_decode_indices_L33
mov	byte [r14+2793], 0
movsx	eax, byte [r14+2789]
jmp	sn_decode_indices_L15
align 16
align 8
sn_decode_indices_L11:
mov	edx, 8
lea	rsi, [rel sn_silk_NLSF_interpolation_factor_iCDF]
mov	rdi, rbx
call	sn_ec_dec_icdf
jmp	sn_decode_indices_L12
align 16
align 8
sn_decode_indices_L33:
mov	edx, 8
lea	rsi, [rel sn_silk_LTPscale_iCDF]
mov	rdi, rbx
call	sn_ec_dec_icdf
mov	byte [r14+2793], al
movsx	eax, byte [r14+2789]
jmp	sn_decode_indices_L15
sn_decode_indices_L32:
mov	edx, 8
lea	rsi, [rel sn_silk_pitch_delta_iCDF]
mov	rdi, rbx
call	sn_ec_dec_icdf
mov	edx, eax
test	ax, ax
jle	sn_decode_indices_L16
movzx	eax, word [r14+2412]
lea	eax, [rax+rdx+-9]
jmp	sn_decode_indices_L17

; ===== decode_pulses.c =====
section .text
align 16
sn_silk_decode_pulses:
push	r15
mov	eax, edx
push	r14
sar	eax, 1
mov	r14d, r8d
push	r13
cdqe
push	r12
push	rbp
push	rbx
mov	rbx, rdi
sub	rsp, 248
mov	qword [rsp+40], rsi
lea	rsi, [rax+rax*8]
lea	rax, [rel sn_silk_rate_levels_iCDF]
mov	dword [rsp+52], edx
add	rsi, rax
mov	edx, 8
mov	dword [rsp+56], ecx
mov	dword [rsp+60], r8d
call	sn_ec_dec_icdf
mov	ecx, r14d
movsx	rdx, eax
and	ecx, -16
mov	eax, r14d
sar	eax, 4
cmp	ecx, r14d
setl	cl
movzx	ecx, cl
add	eax, ecx
lea	rcx, [rdx+rdx*8]
lea	rdx, [rel sn_silk_pulses_per_block_iCDF]
lea	rcx, [rdx+rcx*2]
mov	qword [rsp], rcx
test	eax, eax
jle	sn_decode_pulses_L33
cdqe
lea	rdx, [rsp+160]
lea	r9, [rsp+80]
lea	rcx, [0+rax*4+0]
mov	qword [rsp+16], r9
mov	rbp, rdx
mov	r12, r9
lea	rdi, [rdx+rcx]
mov	qword [rsp+24], rax
lea	r14, [rel sn_silk_pulses_per_block_iCDF+162]
mov	qword [rsp+8], rdi
lea	r13, [r14+1]
mov	qword [rsp+32], rcx
mov	qword [rsp+64], rdx
mov	qword [rsp+72], r9
align 16
align 8
sn_decode_pulses_L5:
mov	dword [rbp+0], 0
mov	rsi, qword [rsp]
mov	edx, 8
mov	rdi, rbx
mov	r15d, 1
call	sn_ec_dec_icdf
mov	dword [r12], eax
cmp	eax, 17
jne	sn_decode_pulses_L8
align 16
align 8
sn_decode_pulses_L4:
cmp	r15d, 10
mov	dword [rbp+0], r15d
mov	rsi, r13
mov	edx, 8
cmovne	rsi, r14
mov	rdi, rbx
add	r15d, 1
call	sn_ec_dec_icdf
mov	dword [r12], eax
cmp	eax, 17
je	sn_decode_pulses_L4
sn_decode_pulses_L8:
mov	rax, qword [rsp+8]
add	rbp, 4
add	r12, 4
cmp	rbp, rax
jne	sn_decode_pulses_L5
mov	rax, qword [rsp+24]
mov	r15, qword [rsp+16]
mov	rcx, qword [rsp+32]
mov	rdx, qword [rsp+64]
mov	r9, qword [rsp+72]
mov	r12, qword [rsp+40]
shl	rax, 5
mov	r13, r15
mov	qword [rsp], rcx
mov	r14, rdx
lea	rbp, [rax+r12]
mov	r15, r9
jmp	sn_decode_pulses_L11
align 16
align 8
sn_decode_pulses_L35:
mov	rdi, r12
mov	rsi, rbx
add	r12, 32
add	r13, 4
call	sn_silk_shell_decoder
cmp	r12, rbp
je	sn_decode_pulses_L34
sn_decode_pulses_L11:
mov	edx, dword [r13+0]
test	edx, edx
jg	sn_decode_pulses_L35
mov	rdi, r12
mov	edx, 32
xor	esi, esi
add	r12, 32
call	sn_set
add	r13, 4
cmp	r12, rbp
jne	sn_decode_pulses_L11
sn_decode_pulses_L34:
mov	rax, qword [rsp+40]
xor	r13d, r13d
mov	rdx, r14
mov	rcx, qword [rsp]
mov	r14, r13
mov	r9, r15
lea	r12, [rel sn_silk_lsb_iCDF]
add	rax, 32
mov	r13, rax
jmp	sn_decode_pulses_L15
align 16
align 8
sn_decode_pulses_L12:
add	r14, 4
add	r13, 32
cmp	r14, rcx
je	sn_decode_pulses_L16
sn_decode_pulses_L15:
mov	r15d, dword [rdx+r14]
test	r15d, r15d
jle	sn_decode_pulses_L12
mov	qword [rsp], r13
lea	rbp, [r13+-32]
mov	qword [rsp+16], rcx
mov	qword [rsp+24], rdx
mov	qword [rsp+32], r9
mov	qword [rsp+8], r14
mov	r14, rbp
align 16
align 8
sn_decode_pulses_L14:
movsx	ebp, word [r14]
xor	r13d, r13d
align 16
align 8
sn_decode_pulses_L13:
mov	edx, 8
mov	rsi, r12
mov	rdi, rbx
add	ebp, ebp
call	sn_ec_dec_icdf
add	r13d, 1
add	ebp, eax
cmp	r15d, r13d
jne	sn_decode_pulses_L13
mov	word [r14], bp
add	r14, 2
cmp	qword [rsp], r14
jne	sn_decode_pulses_L14
mov	r14, qword [rsp+8]
mov	r9, qword [rsp+32]
shl	r15d, 5
mov	r13, qword [rsp]
mov	rcx, qword [rsp+16]
or	dword [r9+r14], r15d
add	r14, 4
mov	rdx, qword [rsp+24]
add	r13, 32
cmp	r14, rcx
jne	sn_decode_pulses_L15
sn_decode_pulses_L16:
mov	r8d, dword [rsp+56]
mov	ecx, dword [rsp+52]
mov	rdi, rbx
mov	edx, dword [rsp+60]
mov	rsi, qword [rsp+40]
call	sn_silk_decode_signs
add	rsp, 248
pop	rbx
pop	rbp
pop	r12
pop	r13
pop	r14
pop	r15
ret
sn_decode_pulses_L33:
lea	r9, [rsp+80]
jmp	sn_decode_pulses_L16

; ===== decoder_set_fs.c =====
section .text
align 16
sn_silk_decoder_set_fs:
push	r15
push	r14
movsx	r14d, si
push	r13
lea	r15d, [0+r14*4+0]
push	r12
lea	eax, [r15+r14]
mov	r12d, edx
push	rbp
mov	ebp, esi
push	rbx
mov	rbx, rdi
sub	rsp, 24
movsx	edx, word [rdi+2324]
mov	dword [rdi+2332], eax
cwde
imul	edx, eax
mov	r13d, edx
cmp	dword [rdi+2316], esi
jne	sn_decoder_set_fs_L2
cmp	dword [rdi+2320], r12d
je	sn_decoder_set_fs_L19
sn_decoder_set_fs_L2:
imul	esi, r14d, 1000
xor	ecx, ecx
lea	rdi, [rbx+2448]
mov	edx, r12d
call	sn_silk_resampler_init
mov	dword [rbx+2320], r12d
mov	ecx, eax
mov	eax, dword [rbx+2316]
cmp	eax, ebp
je	sn_decoder_set_fs_L3
mov	edx, dword [rbx+2324]
cmp	ebp, 8
je	sn_decoder_set_fs_L28
cmp	edx, 4
lea	rax, [rel sn_silk_pitch_contour_iCDF]
lea	rdx, [rel sn_silk_pitch_contour_10_ms_iCDF]
cmovne	rax, rdx
mov	qword [rbx+2392], rax
lea	eax, [r15+r14]
shl	eax, 2
mov	dword [rbx+2336], eax
mov	eax, ebp
and	eax, -5
cmp	eax, 8
je	sn_decoder_set_fs_L29
mov	dword [rbx+2340], 16
cmp	ebp, 16
je	sn_decoder_set_fs_L30
sn_decoder_set_fs_L16:
mov	byte [rbx+2312], 10
mov	edx, 960
xor	esi, esi
lea	rdi, [rbx+1348]
mov	dword [rbx+2376], 1
mov	dword [rbx+2308], 100
mov	dword [rbx+4188], 0
mov	dword [rsp+12], ecx
call	sn_set
lea	rdi, [rbx+1284]
mov	edx, 64
xor	esi, esi
call	sn_set
mov	ecx, dword [rsp+12]
sn_decoder_set_fs_L15:
mov	dword [rbx+2316], ebp
mov	dword [rbx+2328], r13d
sn_decoder_set_fs_L1:
add	rsp, 24
mov	eax, ecx
pop	rbx
pop	rbp
pop	r12
pop	r13
pop	r14
pop	r15
ret
align 16
align 8
sn_decoder_set_fs_L28:
cmp	edx, 4
je	sn_decoder_set_fs_L5
lea	rax, [rel sn_silk_pitch_contour_10_ms_NB_iCDF]
mov	qword [rbx+2392], rax
mov	rax, 42949673120
mov	qword [rbx+2336], rax
sn_decoder_set_fs_L6:
lea	rax, [rel sn_silk_uniform4_iCDF]
mov	qword [rbx+2384], rax
jmp	sn_decoder_set_fs_L16
align 16
align 8
sn_decoder_set_fs_L19:
xor	ecx, ecx
sn_decoder_set_fs_L3:
cmp	dword [rbx+2328], r13d
je	sn_decoder_set_fs_L1
mov	eax, dword [rbx+2324]
cmp	ebp, 8
je	sn_decoder_set_fs_L31
cmp	eax, 4
lea	rdx, [rel sn_silk_pitch_contour_iCDF]
lea	rax, [rel sn_silk_pitch_contour_10_ms_iCDF]
cmove	rax, rdx
mov	qword [rbx+2392], rax
jmp	sn_decoder_set_fs_L15
align 16
align 8
sn_decoder_set_fs_L30:
lea	rax, [rel sn_silk_uniform8_iCDF]
mov	qword [rbx+2384], rax
jmp	sn_decoder_set_fs_L16
align 16
align 8
sn_decoder_set_fs_L5:
lea	rsi, [rel sn_silk_pitch_contour_NB_iCDF]
mov	qword [rbx+2392], rsi
cmp	eax, 8
je	sn_decoder_set_fs_L15
mov	rax, 42949673120
mov	qword [rbx+2336], rax
jmp	sn_decoder_set_fs_L6
align 16
align 8
sn_decoder_set_fs_L31:
cmp	eax, 4
lea	rdx, [rel sn_silk_pitch_contour_NB_iCDF]
lea	rax, [rel sn_silk_pitch_contour_10_ms_NB_iCDF]
cmove	rax, rdx
mov	qword [rbx+2392], rax
jmp	sn_decoder_set_fs_L15
align 16
align 8
sn_decoder_set_fs_L29:
lea	rax, [rel sn_silk_uniform6_iCDF]
mov	dword [rbx+2340], 10
mov	qword [rbx+2384], rax
jmp	sn_decoder_set_fs_L16

; ===== gain_quant.c =====
section .text
align 16
sn_silk_gains_quant:
push	r15
push	r14
push	r13
push	r12
push	rbp
push	rbx
sub	rsp, 24
mov	dword [rsp+12], ecx
test	r8d, r8d
jle	sn_gain_quant_L1
mov	rbx, rsi
mov	r15, rdx
mov	rbp, rdi
movsx	r12, r8d
xor	r13d, r13d
jmp	sn_gain_quant_L10
align 16
align 8
sn_gain_quant_L17:
movsx	esi, byte [r15]
sub	esi, 4
cmp	esi, 63
jg	sn_gain_quant_L12
movsx	eax, al
cmp	eax, esi
cmovl	eax, esi
movsx	rdi, eax
mov	esi, eax
imul	rdi, rdi, 1907825
sar	rdi, 16
add	edi, 2090
sn_gain_quant_L5:
mov	byte [rbp+0], sil
mov	byte [r15], sil
sn_gain_quant_L6:
call	sn_silk_log2lin
add	rbp, 1
mov	dword [rbx+r13*4], eax
add	r13, 1
cmp	r13, r12
je	sn_gain_quant_L1
sn_gain_quant_L10:
mov	edi, dword [rbx+r13*4]
mov	r14d, r13d
call	sn_silk_lin2log
lea	esi, [rax+-2090]
movsx	rsi, si
imul	rsi, rsi, 2251
sar	rsi, 16
mov	byte [rbp+0], sil
cmp	byte [r15], sil
setg	al
add	eax, esi
xor	esi, esi
test	al, al
cmovs	eax, esi
mov	esi, 63
cmp	al, sil
cmovg	eax, esi
or	r14d, dword [rsp+12]
mov	byte [rbp+0], al
je	sn_gain_quant_L17
sub	al, byte [r15]
mov	byte [rbp+0], al
movsx	esi, byte [r15]
movsx	edi, al
mov	r8d, esi
add	esi, 8
cmp	edi, esi
jle	sn_gain_quant_L7
mov	eax, 1
sub	eax, esi
add	eax, edi
sar	eax, 1
lea	eax, [r8+rax+8]
sn_gain_quant_L7:
mov	edi, -4
cmp	al, dil
cmovl	eax, edi
mov	edi, 36
cmp	al, dil
cmovg	eax, edi
movsx	edi, al
mov	byte [rbp+0], al
cmp	edi, esi
jle	sn_gain_quant_L8
movzx	ecx, byte [r15]
lea	esi, [rcx+-8]
sub	esi, r8d
lea	eax, [rsi+rax*2]
mov	esi, 63
cmp	al, sil
cmovg	eax, esi
sn_gain_quant_L9:
mov	byte [r15], al
mov	eax, 3967
add	byte [rbp+0], 4
movsx	rdi, byte [r15]
imul	rdi, rdi, 1907825
sar	rdi, 16
add	edi, 2090
cmp	edi, eax
cmovg	edi, eax
jmp	sn_gain_quant_L6
align 16
align 8
sn_gain_quant_L12:
mov	edi, 3923
mov	esi, 63
jmp	sn_gain_quant_L5
align 16
align 8
sn_gain_quant_L8:
add	al, byte [r15]
jmp	sn_gain_quant_L9
align 16
align 8
sn_gain_quant_L1:
add	rsp, 24
pop	rbx
pop	rbp
pop	r12
pop	r13
pop	r14
pop	r15
ret
align 16
sn_silk_gains_dequant:
test	r8d, r8d
jle	sn_gain_quant_L28
push	r15
xor	r15d, r15d
push	r14
mov	r14, rdx
push	r13
movsx	r13, r8d
push	r12
mov	r12, rdi
push	rbp
mov	rbp, rsi
push	rbx
mov	ebx, ecx
sub	rsp, 8
jmp	sn_gain_quant_L23
align 16
align 8
sn_gain_quant_L32:
movsx	eax, byte [rbp+0]
sub	edx, 16
cmp	edx, eax
cmovge	eax, edx
sn_gain_quant_L21:
xor	edx, edx
test	al, al
cmovs	eax, edx
mov	edx, 63
cmp	al, dl
cmovg	eax, edx
movsx	rdi, al
mov	byte [r14], al
imul	rdi, rdi, 1907825
sar	rdi, 16
add	edi, 2090
call	sn_silk_log2lin
mov	dword [r12+r15*4], eax
add	r15, 1
cmp	r15, r13
je	sn_gain_quant_L31
sn_gain_quant_L23:
movsx	edx, byte [r14]
mov	esi, ebx
or	esi, r15d
mov	eax, edx
je	sn_gain_quant_L32
movsx	esi, byte [rbp+r15+0]
add	edx, 8
mov	ecx, esi
sub	esi, 4
lea	eax, [rcx+rax+-4]
cmp	esi, edx
lea	ecx, [rcx+rcx+-16]
cmovg	eax, ecx
jmp	sn_gain_quant_L21
align 16
align 8
sn_gain_quant_L31:
add	rsp, 8
pop	rbx
pop	rbp
pop	r12
pop	r13
pop	r14
pop	r15
ret
align 16
align 8
sn_gain_quant_L28:
ret
align 16
sn_silk_gains_ID:
test	esi, esi
jle	sn_gain_quant_L36
movsx	rsi, esi
xor	eax, eax
lea	rcx, [rdi+rsi]
align 16
align 8
sn_gain_quant_L35:
movsx	edx, byte [rdi]
shl	eax, 8
add	rdi, 1
add	eax, edx
cmp	rcx, rdi
jne	sn_gain_quant_L35
ret
align 16
align 8
sn_gain_quant_L36:
xor	eax, eax
ret

; ===== interpolate.c =====
section .text
align 16
sn_silk_interpolate:
mov	r9, rsi
mov	r10, rdx
test	r8d, r8d
jle	sn_interpolate_L1
movsx	r8, r8d
movsx	ecx, cx
xor	edx, edx
lea	rsi, [r8+r8]
align 16
align 8
sn_interpolate_L3:
movzx	eax, word [r10+rdx]
sub	ax, word [r9+rdx]
cwde
imul	eax, ecx
sar	eax, 2
add	ax, word [r9+rdx]
mov	word [rdi+rdx], ax
add	rdx, 2
cmp	rsi, rdx
jne	sn_interpolate_L3
sn_interpolate_L1:
ret

; ===== NLSF_decode.c =====
section .text
align 16
sn_silk_NLSF_decode:
push	r13
push	r12
mov	r12, rsi
push	rbp
mov	rbp, rdi
push	rbx
mov	rbx, rdx
sub	rsp, 88
movsx	ecx, byte [rsi]
mov	r13, rsp
lea	rdi, [rsp+16]
mov	rsi, r13
call	sn_silk_NLSF_unpack
movsx	edi, word [rbx+2]
movsx	r9, word [rbx+4]
mov	eax, edi
sub	eax, 1
js	sn_NLSF_decode_L2
movsx	rcx, eax
mov	eax, eax
lea	r8, [rsp+48]
xor	edx, edx
lea	rsi, [rcx+-1]
mov	r10, rsi
sub	r10, rax
jmp	sn_NLSF_decode_L5
align 16
align 8
sn_NLSF_decode_L18:
sub	eax, 102
cdqe
imul	rax, r9
sar	rax, 16
add	edx, eax
sn_NLSF_decode_L4:
mov	word [r8+rcx*2], dx
mov	rcx, rsi
cmp	rsi, r10
je	sn_NLSF_decode_L15
sn_NLSF_decode_L19:
sub	rsi, 1
sn_NLSF_decode_L5:
movzx	eax, byte [r13+rcx+0]
movsx	edx, dx
imul	edx, eax
movsx	eax, byte [r12+rcx+1]
shl	eax, 10
sar	edx, 8
test	eax, eax
jg	sn_NLSF_decode_L18
je	sn_NLSF_decode_L4
add	eax, 102
cdqe
imul	rax, r9
sar	rax, 16
add	edx, eax
mov	word [r8+rcx*2], dx
mov	rcx, rsi
cmp	rsi, r10
jne	sn_NLSF_decode_L19
sn_NLSF_decode_L15:
movsx	esi, byte [r12]
mov	rax, qword [rbx+16]
xor	ecx, ecx
xor	r10d, r10d
imul	esi, edi
movsx	rsi, esi
lea	r9, [rax+rsi*2]
add	rsi, qword [rbx+8]
align 16
align 8
sn_NLSF_decode_L7:
movsx	eax, word [r8+rcx*2]
movsx	edi, word [r9+rcx*2]
shl	eax, 14
cdq
idiv	edi
movzx	edx, byte [rsi+rcx]
shl	edx, 7
add	eax, edx
mov	edx, 32767
cmp	eax, 32767
jg	sn_NLSF_decode_L6
test	eax, eax
mov	edx, eax
cmovs	edx, r10d
sn_NLSF_decode_L6:
mov	word [rbp+rcx*2+0], dx
movsx	edi, word [rbx+2]
add	rcx, 1
cmp	edi, ecx
jg	sn_NLSF_decode_L7
sn_NLSF_decode_L2:
mov	rsi, qword [rbx+64]
mov	edx, edi
mov	rdi, rbp
call	sn_silk_NLSF_stabilize
add	rsp, 88
pop	rbx
pop	rbp
pop	r12
pop	r13
ret

; ===== PLC.c =====
section .text
align 16
sn_silk_PLC_Reset:
mov	eax, dword [rdi+2328]
shl	eax, 7
mov	dword [rdi+4196], eax
mov	rax, 281474976776192
mov	qword [rdi+4268], rax
mov	rax, 85899345922
mov	qword [rdi+4280], rax
ret
align 16
sn_silk_PLC:
push	rbp
mov	rbp, rsp
push	r15
push	r14
push	r13
mov	r13, rsi
push	r12
push	rbx
sub	rsp, 264
mov	qword [rbp+-168], rdi
mov	eax, dword [rdi+2316]
mov	qword [rbp+-272], rdx
mov	dword [rbp+-136], r8d
cmp	eax, dword [rdi+4276]
je	sn_PLC_L4
mov	esi, dword [rdi+2328]
mov	dword [rdi+4276], eax
mov	edx, esi
mov	dword [rbp+-120], esi
mov	rsi, 281474976776192
mov	qword [rdi+4268], rsi
shl	edx, 7
mov	rsi, 85899345922
mov	dword [rdi+4196], edx
mov	qword [rdi+4280], rsi
sn_PLC_L4:
test	ecx, ecx
je	sn_PLC_L5
mov	rax, qword [rbp+-168]
mov	rsi, rsp
mov	qword [rbp+-280], rsp
movsx	rdx, dword [rax+2336]
mov	ebx, dword [rax+2328]
add	ebx, edx
movsx	rax, ebx
lea	rax, [0+rax*4+15]
mov	rcx, rax
and	rax, -4096
sub	rsi, rax
and	rcx, -16
cmp	rsp, rsi
je	sn_PLC_L7
sn_PLC_L109:
sub	rsp, 4096
or	qword [rsp+4088], 0
cmp	rsp, rsi
jne	sn_PLC_L109
sn_PLC_L7:
and	ecx, 4095
sub	rsp, rcx
test	rcx, rcx
je	sn_PLC_L8
or	qword [rsp+rcx+-8], 0
sn_PLC_L8:
lea	rax, [rdx+rdx+15]
mov	rcx, rsp
mov	r15, rsp
mov	rdx, rax
and	rax, -4096
sub	rcx, rax
and	rdx, -16
cmp	rsp, rcx
je	sn_PLC_L10
sn_PLC_L110:
sub	rsp, 4096
or	qword [rsp+4088], 0
cmp	rsp, rcx
jne	sn_PLC_L110
sn_PLC_L10:
and	edx, 4095
sub	rsp, rdx
test	rdx, rdx
je	sn_PLC_L11
or	qword [rsp+rdx+-8], 0
sn_PLC_L11:
mov	rbx, qword [rbp+-168]
mov	qword [rbp+-152], rsp
mov	eax, dword [rbx+4268]
sar	eax, 6
mov	dword [rbp+-88], eax
mov	rax, rbx
mov	ebx, dword [rbx+4272]
mov	r10d, dword [rax+2376]
mov	dword [rbp+-120], ebx
sar	ebx, 6
mov	dword [rbp+-292], ebx
mov	dword [rbp+-84], ebx
lea	rbx, [rax+4210]
mov	qword [rbp+-224], rbx
test	r10d, r10d
je	sn_PLC_L12
mov	edx, 32
xor	esi, esi
mov	rdi, rbx
call	sn_set
sn_PLC_L12:
mov	rax, qword [rbp+-168]
mov	rsi, rsp
mov	qword [rbp+-144], rsp
mov	ebx, dword [rax+2332]
mov	edx, dword [rax+2324]
lea	r10, [rax+4]
lea	eax, [rbx+rbx]
cdqe
lea	rax, [rax+rax+15]
mov	rcx, rax
and	rax, -4096
sub	rsi, rax
and	rcx, -16
cmp	rsp, rsi
je	sn_PLC_L14
sn_PLC_L111:
sub	rsp, 4096
or	qword [rsp+4088], 0
cmp	rsp, rsi
jne	sn_PLC_L111
sn_PLC_L14:
and	ecx, 4095
sub	rsp, rcx
test	rcx, rcx
je	sn_PLC_L15
or	qword [rsp+rcx+-8], 0
sn_PLC_L15:
movsx	rax, ebx
sub	edx, 2
mov	rdi, rsp
mov	r12d, -32768
imul	edx, ebx
lea	r14, [rax+rax]
mov	r9, r13
mov	qword [rbp+-160], rdi
lea	r11, [rbp+-80]
mov	qword [rbp+-128], r14
lea	rsi, [rbp+-88]
mov	qword [rbp+-248], r11
lea	r8d, [rdx+rbx]
align 16
align 8
sn_PLC_L16:
test	ebx, ebx
jle	sn_PLC_L21
mov	dword [rbp+-120], ebx
mov	edx, r8d
movsx	r13, dword [rsi]
mov	rcx, rdi
sub	edx, ebx
align 16
align 8
sn_PLC_L18:
movsx	rax, edx
mov	ebx, 32767
movsx	rax, dword [r10+rax*4]
imul	rax, r13
sar	rax, 16
mov	r14d, eax
sar	r14d, 8
cmp	eax, 8388607
jg	sn_PLC_L17
cmp	r14d, -32768
mov	ebx, r14d
cmovl	ebx, r12d
sn_PLC_L17:
add	edx, 1
mov	word [rcx], bx
add	rcx, 2
cmp	r8d, edx
jne	sn_PLC_L18
mov	ebx, dword [rbp+-120]
sn_PLC_L21:
mov	rax, qword [rbp+-128]
add	rsi, 4
add	r8d, ebx
add	rdi, rax
cmp	r11, rsi
jne	sn_PLC_L16
mov	r12, qword [rbp+-160]
mov	ecx, ebx
mov	r14, qword [rbp+-128]
mov	r13, r9
lea	rsi, [rbp+-104]
lea	rdi, [rbp+-96]
mov	rdx, r12
call	sn_silk_sum_sqr_shift
mov	rdx, r12
mov	ecx, ebx
lea	rsi, [rbp+-100]
add	rdx, r14
lea	rdi, [rbp+-92]
call	sn_silk_sum_sqr_shift
mov	ecx, dword [rbp+-100]
mov	edx, dword [rbp+-96]
mov	eax, dword [rbp+-92]
mov	rbx, qword [rbp+-168]
sar	edx, cl
mov	ecx, dword [rbp+-104]
mov	rsp, qword [rbp+-144]
sar	eax, cl
cmp	edx, eax
mov	eax, dword [rbx+4280]
jge	sn_PLC_L22
mov	dword [rbp+-120], eax
sub	eax, 1
sn_PLC_L22:
imul	eax, dword [rbx+4284]
mov	edx, 0
mov	rcx, qword [rbp+-168]
add	eax, -128
cmovs	eax, edx
mov	edx, 1
cdqe
lea	rax, [rbx+rax*4+4]
mov	qword [rbp+-160], rax
movzx	eax, word [rcx+4252]
mov	word [rbp+-204], ax
movsx	rax, dword [rcx+4184]
test	eax, eax
cmovg	rax, rdx
lea	rdx, [rel sn_HARM_ATT_Q15]
cmp	dword [rcx+4188], 2
movzx	ebx, word [rdx+rax*2]
je	sn_PLC_L112
lea	rdx, [rel sn_PLC_RAND_ATTENUATE_UV_Q15]
movsx	eax, word [rdx+rax*2]
mov	dword [rbp+-236], eax
sn_PLC_L25:
mov	r14, qword [rbp+-168]
mov	r12, qword [rbp+-224]
mov	edx, 64881
mov	esi, dword [r14+2340]
mov	rdi, r12
call	sn_silk_bwexpander
movsx	rdx, dword [r14+2340]
mov	rdi, qword [rbp+-248]
mov	rsi, r12
add	rdx, rdx
call	sn_copy
mov	r9d, dword [r14+4184]
test	r9d, r9d
jne	sn_PLC_L26
cmp	dword [r14+4188], 2
jne	sn_PLC_L27
lea	rdx, [r14+4200]
mov	rcx, r12
mov	eax, 16384
sub	rcx, rdx
and	ecx, 2
mov	rcx, r12
je	sn_PLC_L28
mov	rcx, qword [rbp+-168]
sub	ax, word [rdx]
lea	rdx, [rcx+4202]
mov	rcx, qword [rbp+-224]
cmp	qword [rbp+-224], rdx
je	sn_PLC_L106
sn_PLC_L28:
sub	ax, word [rdx]
add	rdx, 4
sub	ax, word [rdx+-2]
cmp	rcx, rdx
jne	sn_PLC_L28
sn_PLC_L106:
mov	edx, 3277
mov	rcx, qword [rbp+-168]
cmp	ax, dx
cmovl	eax, edx
movsx	edx, word [rcx+4264]
cwde
imul	eax, edx
sar	eax, 14
mov	word [rbp+-204], ax
sn_PLC_L26:
mov	rsi, qword [rbp+-168]
mov	rdi, qword [rbp+-152]
mov	rdx, qword [rbp+-248]
mov	r9d, dword [rbp+-136]
mov	eax, dword [rsi+4196]
mov	r8d, dword [rsi+2340]
mov	r14d, dword [rsi+4248]
sar	eax, 7
add	eax, 1
sar	eax, 1
mov	r11d, eax
mov	eax, dword [rsi+2336]
lea	ecx, [r8+r11+2]
mov	dword [rbp+-120], r11d
mov	dword [rbp+-128], eax
sub	eax, 2
sub	eax, r8d
sub	eax, r11d
mov	r12d, eax
cdqe
lea	rax, [rax+rax+1348]
add	rsi, rax
lea	rdi, [rdi+rax+-1348]
call	sn_silk_LPC_analysis_filter
mov	rsi, qword [rbp+-168]
mov	r11d, dword [rbp+-120]
mov	edx, dword [rsi+4272]
test	edx, edx
je	sn_PLC_L72
mov	eax, edx
mov	edi, 16
neg	eax
cmovs	eax, edx
bsr	esi, eax
xor	esi, 31
lea	ecx, [rsi+-1]
sub	edi, esi
sn_PLC_L29:
shl	edx, cl
mov	eax, 536870911
mov	ecx, edx
mov	r8d, edx
xor	edx, edx
sar	ecx, 16
idiv	ecx
movsx	rdx, r8d
movsx	r8, ax
mov	ecx, eax
cdqe
imul	rdx, r8
shl	ecx, 16
sar	rdx, 16
lea	edx, [0+rdx*8+0]
neg	edx
movsx	rdx, edx
imul	rdx, rax
sar	rdx, 16
add	edx, ecx
mov	ecx, edi
mov	eax, edx
sar	eax, cl
test	edi, edi
jle	sn_PLC_L113
sn_PLC_L33:
mov	edx, 1073741823
cmp	eax, edx
mov	esi, edx
cmovle	esi, eax
mov	rax, qword [rbp+-168]
add	r12d, dword [rax+2340]
mov	eax, dword [rax+2336]
cmp	r12d, eax
jge	sn_PLC_L38
mov	rcx, qword [rbp+-152]
mov	r9d, eax
movsx	rsi, esi
sub	r9d, r12d
movsx	r12, r12d
lea	r8, [rcx+r12*2]
lea	rdi, [r15+r12*4]
xor	ecx, ecx
align 16
align 8
sn_PLC_L37:
movsx	rdx, word [r8+rcx*2]
imul	rdx, rsi
sar	rdx, 16
mov	dword [rdi+rcx*4], edx
add	rcx, 1
cmp	r9, rcx
jne	sn_PLC_L37
sn_PLC_L38:
mov	rcx, qword [rbp+-168]
mov	ecx, dword [rcx+2324]
mov	dword [rbp+-240], ecx
test	ecx, ecx
jle	sn_PLC_L36
mov	rcx, qword [rbp+-168]
movsx	edx, bx
mov	qword [rbp+-288], r13
movzx	r8d, word [rbp+-204]
mov	dword [rbp+-256], eax
mov	eax, r11d
mov	rbx, rcx
mov	edi, dword [rcx+2332]
mov	ecx, dword [rcx+4196]
movsx	esi, word [rbx+2316]
lea	r10, [rbx+4200]
mov	qword [rbp+-232], r10
lea	esi, [rsi+rsi*8]
mov	dword [rbp+-176], edi
shl	esi, 9
mov	r9d, esi
movsx	rsi, edi
shl	rsi, 2
mov	dword [rbp+-252], r9d
mov	r9d, dword [rbp+-128]
mov	qword [rbp+-264], rsi
xor	esi, esi
mov	r11d, esi
mov	esi, ecx
mov	rcx, rbx
mov	rbx, r15
align 16
align 8
sn_PLC_L42:
lea	r10d, [r9+2]
mov	edi, dword [rbp+-176]
sub	r10d, eax
movsx	r10, r10d
lea	rax, [rbx+r10*4]
movzx	r10d, word [rcx+4200]
test	edi, edi
jle	sn_PLC_L39
movsx	rdi, r10w
movsx	r12, r8w
mov	r10d, r9d
mov	word [rbp+-184], r8w
mov	qword [rbp+-120], rdi
movsx	rdi, word [rcx+4202]
mov	dword [rbp+-192], esi
movsx	r15, word [rcx+4206]
mov	qword [rbp+-128], rdi
movsx	rdi, word [rcx+4204]
mov	dword [rbp+-200], r11d
movsx	r13, word [rcx+4208]
mov	qword [rbp+-136], rdi
mov	rdi, qword [rbp+-264]
mov	dword [rbp+-204], r9d
add	rdi, rax
mov	dword [rbp+-208], edx
mov	qword [rbp+-144], rdi
mov	qword [rbp+-152], r12
mov	qword [rbp+-216], rcx
align 16
align 8
sn_PLC_L40:
movsx	r8, dword [rax]
mov	rdi, qword [rbp+-120]
movsx	r11, r10d
add	rax, 4
imul	r14d, r14d, 196314165
mov	rcx, qword [rbp+-128]
movsx	rsi, dword [rax+-12]
add	r10d, 1
mov	r12, qword [rbp+-160]
imul	r8, rdi
movsx	rdi, dword [rax+-8]
movsx	rdx, dword [rax+-20]
add	r14d, 907633515
imul	rdi, rcx
mov	rcx, qword [rbp+-136]
mov	r9d, r14d
sar	r8, 16
imul	rdx, r13
shr	r9d, 25
imul	rsi, rcx
movsx	rcx, dword [rax+-16]
movsx	r9, dword [r12+r9*4]
mov	r12, qword [rbp+-152]
sar	rdi, 16
imul	rcx, r15
sar	rdx, 16
imul	r9, r12
sar	rsi, 16
sar	rcx, 16
sar	r9, 16
lea	r8d, [r9+r8+2]
add	r8d, edi
mov	rdi, qword [rbp+-144]
add	r8d, esi
add	r8d, ecx
add	r8d, edx
shl	r8d, 2
mov	dword [rbx+r11*4], r8d
cmp	rax, rdi
jne	sn_PLC_L40
mov	r9d, dword [rbp+-204]
mov	eax, dword [rbp+-176]
movzx	r8d, word [rbp+-184]
mov	esi, dword [rbp+-192]
mov	r11d, dword [rbp+-200]
mov	edx, dword [rbp+-208]
add	r9d, eax
mov	rcx, qword [rbp+-216]
sn_PLC_L39:
mov	r10, qword [rbp+-232]
mov	rdi, qword [rbp+-224]
align 16
align 8
sn_PLC_L41:
movsx	eax, word [r10]
add	r10, 2
imul	eax, edx
sar	eax, 15
mov	word [r10+-2], ax
cmp	rdi, r10
jne	sn_PLC_L41
mov	edi, dword [rbp+-236]
movsx	eax, r8w
imul	eax, edi
mov	edi, dword [rbp+-252]
sar	eax, 15
mov	r8d, eax
movsx	rax, esi
imul	rax, rax, 655
sar	rax, 16
add	eax, esi
cmp	eax, edi
cmovg	eax, edi
mov	edi, dword [rbp+-240]
add	r11d, 1
mov	dword [rcx+4196], eax
mov	esi, eax
sar	eax, 7
add	eax, 1
sar	eax, 1
cmp	r11d, edi
jne	sn_PLC_L42
mov	word [rbp+-204], r8w
mov	r11d, eax
mov	r13, qword [rbp+-288]
mov	r15, rbx
mov	eax, dword [rbp+-256]
sn_PLC_L36:
sub	eax, 16
mov	edx, 64
mov	dword [rbp+-120], r11d
cdqe
lea	r12, [r15+rax*4]
mov	r15, qword [rbp+-168]
mov	rdi, r12
lea	rbx, [r15+1284]
mov	rsi, rbx
call	sn_copy
movsx	r10, dword [r15+2328]
mov	r11d, dword [rbp+-120]
test	r10d, r10d
jle	sn_PLC_L56
mov	rax, qword [rbp+-168]
mov	dword [rbp+-208], r14d
xor	edi, edi
mov	r9d, 15
mov	dword [rbp+-216], r11d
movsx	rcx, dword [rbp+-292]
mov	r15d, dword [rax+2340]
mov	qword [rbp+-232], r13
mov	r13, qword [rbp+-272]
mov	qword [rbp+-224], rbx
mov	eax, r15d
sub	r9d, r15d
sar	eax, 1
mov	dword [rbp+-120], eax
movsx	rax, word [rbp+-80]
mov	qword [rbp+-128], rax
movsx	rax, word [rbp+-78]
mov	qword [rbp+-136], rax
movsx	rax, word [rbp+-76]
mov	qword [rbp+-144], rax
movsx	rax, word [rbp+-74]
mov	qword [rbp+-152], rax
movsx	rax, word [rbp+-72]
mov	qword [rbp+-160], rax
movsx	rax, word [rbp+-70]
mov	qword [rbp+-176], rax
movsx	rax, word [rbp+-68]
mov	qword [rbp+-184], rax
movsx	rax, word [rbp+-66]
mov	qword [rbp+-192], rax
movsx	rax, word [rbp+-64]
mov	qword [rbp+-200], rax
movsx	rax, word [rbp+-62]
mov	rbx, rax
align 16
align 8
sn_PLC_L55:
lea	eax, [rdi+15]
mov	rsi, qword [rbp+-128]
lea	edx, [rdi+14]
mov	r14d, edi
cdqe
movsx	rdx, edx
movsx	rax, dword [r12+rax*4]
movsx	rdx, dword [r12+rdx*4]
imul	rax, rsi
mov	rsi, qword [rbp+-136]
imul	rdx, rsi
mov	esi, dword [rbp+-120]
sar	rax, 16
sar	rdx, 16
add	eax, edx
lea	edx, [rdi+13]
movsx	rdx, edx
add	eax, esi
mov	rsi, qword [rbp+-144]
movsx	rdx, dword [r12+rdx*4]
imul	rdx, rsi
mov	rsi, qword [rbp+-152]
sar	rdx, 16
add	eax, edx
lea	edx, [rdi+12]
movsx	rdx, edx
movsx	rdx, dword [r12+rdx*4]
imul	rdx, rsi
mov	rsi, qword [rbp+-160]
sar	rdx, 16
add	eax, edx
lea	edx, [rdi+11]
movsx	rdx, edx
movsx	rdx, dword [r12+rdx*4]
imul	rdx, rsi
mov	rsi, qword [rbp+-176]
sar	rdx, 16
add	eax, edx
lea	edx, [rdi+10]
movsx	rdx, edx
movsx	rdx, dword [r12+rdx*4]
imul	rdx, rsi
mov	rsi, qword [rbp+-184]
sar	rdx, 16
add	eax, edx
lea	edx, [rdi+9]
movsx	rdx, edx
movsx	rdx, dword [r12+rdx*4]
imul	rdx, rsi
mov	rsi, qword [rbp+-192]
sar	rdx, 16
add	eax, edx
lea	edx, [rdi+8]
movsx	rdx, edx
movsx	rdx, dword [r12+rdx*4]
imul	rdx, rsi
mov	rsi, qword [rbp+-200]
sar	rdx, 16
add	eax, edx
lea	edx, [rdi+7]
movsx	rdx, edx
movsx	rdx, dword [r12+rdx*4]
imul	rdx, rsi
sar	rdx, 16
add	eax, edx
lea	edx, [rdi+6]
movsx	rdx, edx
movsx	rdx, dword [r12+rdx*4]
imul	rdx, rbx
sar	rdx, 16
add	eax, edx
cmp	r15d, 10
jle	sn_PLC_L45
mov	r8, qword [rbp+-248]
lea	esi, [rdi+5]
align 16
align 8
sn_PLC_L46:
movsx	rdx, esi
movsx	r11, word [r8+20]
sub	esi, 1
add	r8, 2
movsx	rdx, dword [r12+rdx*4]
imul	rdx, r11
sar	rdx, 16
add	eax, edx
cmp	esi, r9d
jne	sn_PLC_L46
sn_PLC_L45:
add	r14d, 16
movsx	r14, r14d
lea	r8, [r12+r14*4]
mov	esi, dword [r8]
cmp	eax, 134217727
jg	sn_PLC_L47
cmp	eax, -134217728
jl	sn_PLC_L48
shl	eax, 4
mov	edx, eax
add	edx, esi
js	sn_PLC_L50
sn_PLC_L49:
mov	rdx, -2147483648
mov	r11d, -2147483648
test	esi, eax
jns	sn_PLC_L51
sn_PLC_L53:
mov	rax, rdx
mov	dword [r8], r11d
mov	edx, 32767
imul	rax, rcx
sar	rax, 16
sar	eax, 7
add	eax, 1
mov	esi, eax
sar	esi, 1
cmp	eax, 65535
jg	sn_PLC_L54
cmp	esi, -32768
mov	edx, -32768
cmovge	edx, esi
sn_PLC_L54:
mov	word [r13+rdi*2+0], dx
add	rdi, 1
add	r9d, 1
cmp	rdi, r10
jne	sn_PLC_L55
mov	r14d, dword [rbp+-208]
mov	r11d, dword [rbp+-216]
mov	rbx, qword [rbp+-224]
mov	r13, qword [rbp+-232]
sn_PLC_L56:
lea	rsi, [r12+r10*4]
mov	rdi, rbx
mov	edx, 64
mov	dword [rbp+-120], r11d
call	sn_copy
mov	r11d, dword [rbp+-120]
mov	rax, qword [rbp+-168]
movzx	ebx, word [rbp+-204]
mov	dword [rax+4248], r14d
mov	word [rax+4252], bx
mov	dword [r13+0], r11d
mov	dword [r13+4], r11d
mov	dword [r13+8], r11d
mov	dword [r13+12], r11d
mov	rsp, qword [rbp+-280]
add	dword [rax+4184], 1
lea	rsp, [rbp+-40]
pop	rbx
pop	r12
pop	r13
pop	r14
pop	r15
pop	rbp
ret
align 16
align 8
sn_PLC_L5:
mov	rbx, qword [rbp+-168]
movsx	ecx, byte [rbx+2789]
mov	dword [rbx+4188], ecx
cmp	cl, 2
jne	sn_PLC_L57
mov	esi, dword [rbx+2324]
lea	edx, [rsi+-1]
movsx	rax, edx
mov	ecx, dword [r13+rax*4+0]
test	ecx, ecx
jle	sn_PLC_L58
test	esi, esi
je	sn_PLC_L58
lea	r15, [rbx+4200]
xor	r12d, r12d
xor	r14d, r14d
mov	qword [rbp+-232], r15
mov	edi, r12d
mov	r12, rbx
align 16
align 8
sn_PLC_L59:
sub	edx, r14d
xor	ebx, ebx
lea	eax, [rdx+rdx*4]
lea	ecx, [rdx+rdx*4+5]
align 16
align 8
sn_PLC_L60:
movsx	rdx, eax
add	eax, 1
movsx	edx, word [r13+rdx*2+96]
add	ebx, edx
cmp	ecx, eax
jne	sn_PLC_L60
lea	edx, [rsi+-1]
cmp	ebx, edi
jg	sn_PLC_L114
sn_PLC_L62:
mov	ecx, dword [r12+2332]
add	r14d, 1
movsx	rax, edx
imul	ecx, r14d
cmp	ecx, dword [r13+rax*4+0]
jge	sn_PLC_L63
cmp	r14d, esi
jne	sn_PLC_L59
sn_PLC_L63:
mov	r12d, edi
mov	rdi, qword [rbp+-232]
mov	edx, 10
xor	esi, esi
call	sn_set
mov	rax, qword [rbp+-168]
mov	word [rax+4204], r12w
cmp	r12d, 11468
jle	sn_PLC_L115
mov	rax, qword [rbp+-168]
lea	rsi, [rax+4210]
mov	qword [rbp+-224], rsi
cmp	r12d, 15565
jle	sn_PLC_L67
mov	eax, 255016960
xor	edx, edx
idiv	r12d
mov	rdx, qword [rbp+-232]
sn_PLC_L69:
movsx	ecx, word [rdx]
imul	ecx, eax
add	rdx, 2
sar	ecx, 14
mov	word [rdx+-2], cx
cmp	rsi, rdx
jne	sn_PLC_L69
jmp	sn_PLC_L67
sn_PLC_L57:
cwde
mov	rbx, qword [rbp+-168]
mov	edx, 10
xor	esi, esi
lea	eax, [rax+rax*8]
shl	eax, 9
lea	rdi, [rbx+4200]
mov	dword [rbx+4196], eax
call	sn_set
lea	rax, [rbx+4210]
mov	qword [rbp+-224], rax
sn_PLC_L67:
mov	rbx, qword [rbp+-168]
mov	rdi, qword [rbp+-224]
lea	rsi, [r13+64]
movsx	rdx, dword [rbx+2340]
add	rdx, rdx
call	sn_copy
mov	eax, dword [r13+136]
mov	edx, 8
lea	rdi, [rbx+4268]
mov	word [rbx+4264], ax
mov	eax, dword [rbx+2324]
mov	dword [rbp+-120], eax
sub	eax, 2
cdqe
lea	rsi, [r13+rax*4+16]
call	sn_copy
mov	edx, dword [rbx+2332]
mov	eax, dword [rbx+2324]
shl	rdx, 32
or	rax, rdx
mov	qword [rbx+4280], rax
lea	rsp, [rbp+-40]
pop	rbx
pop	r12
pop	r13
pop	r14
pop	r15
pop	rbp
ret
align 16
align 8
sn_PLC_L114:
sub	esi, 1
mov	edx, 10
mov	rdi, r15
sub	esi, r14d
movsx	eax, si
lea	eax, [rax+rax*4+48]
cdqe
lea	rsi, [r13+rax*2+0]
call	sn_copy
mov	esi, dword [r12+2324]
mov	edi, ebx
lea	edx, [rsi+-1]
mov	eax, edx
sub	eax, r14d
cdqe
mov	eax, dword [r13+rax*4+0]
shl	eax, 8
mov	dword [r12+4196], eax
jmp	sn_PLC_L62
sn_PLC_L115:
test	r12d, r12d
mov	ecx, 1
mov	eax, 11744256
cmovg	ecx, r12d
xor	edx, edx
idiv	ecx
movsx	ecx, ax
sn_PLC_L64:
mov	rax, qword [rbp+-168]
mov	rdx, qword [rbp+-232]
lea	rsi, [rax+4210]
mov	qword [rbp+-224], rsi
align 16
align 8
sn_PLC_L66:
movsx	eax, word [rdx]
add	rdx, 2
imul	eax, ecx
sar	eax, 10
mov	word [rdx+-2], ax
cmp	rsi, rdx
jne	sn_PLC_L66
jmp	sn_PLC_L67
align 16
align 8
sn_PLC_L48:
mov	edx, esi
mov	eax, -2147483648
add	edx, -2147483648
jns	sn_PLC_L49
sn_PLC_L51:
lea	r11d, [rsi+rax]
movsx	rdx, r11d
jmp	sn_PLC_L53
align 16
align 8
sn_PLC_L47:
mov	edx, esi
mov	eax, 2147483632
add	edx, 2147483632
jns	sn_PLC_L51
sn_PLC_L50:
mov	r14d, esi
mov	edx, 2147483647
mov	r11d, 2147483647
or	r14d, eax
jns	sn_PLC_L53
lea	r11d, [rsi+rax]
movsx	rdx, r11d
jmp	sn_PLC_L53
sn_PLC_L72:
mov	edi, -16
mov	ecx, 31
mov	esi, 32
jmp	sn_PLC_L29
sn_PLC_L112:
lea	rdx, [rel sn_PLC_RAND_ATTENUATE_V_Q15]
movsx	eax, word [rdx+rax*2]
mov	dword [rbp+-236], eax
jmp	sn_PLC_L25
sn_PLC_L113:
lea	ecx, [rsi+-16]
mov	eax, 2147483647
sar	eax, cl
cmp	edx, eax
jg	sn_PLC_L32
mov	eax, -2147483648
sar	eax, cl
cmp	eax, edx
cmovl	eax, edx
sn_PLC_L32:
shl	eax, cl
jmp	sn_PLC_L33
sn_PLC_L27:
mov	rax, qword [rbp+-168]
mov	rdi, qword [rbp+-224]
mov	esi, dword [rax+2340]
call	sn_silk_LPC_inverse_pred_gain_c
mov	edx, 134217728
mov	r8d, 16384
cmp	eax, edx
mov	word [rbp+-204], r8w
cmovg	eax, edx
mov	edx, 4194304
cmp	eax, edx
cmovl	eax, edx
movsx	rdx, dword [rbp+-236]
shl	eax, 3
cdqe
imul	rax, rdx
sar	rax, 16
sar	eax, 14
mov	dword [rbp+-236], eax
jmp	sn_PLC_L26
sn_PLC_L58:
mov	rbx, qword [rbp+-168]
mov	edx, 10
xor	esi, esi
lea	rax, [rbx+4200]
mov	rdi, rax
mov	qword [rbp+-232], rax
call	sn_set
xor	eax, eax
mov	ecx, 13312
mov	word [rbx+4204], ax
jmp	sn_PLC_L64
align 16
sn_silk_PLC_glue_frames:
push	r13
push	r12
mov	r12d, edx
push	rbp
mov	rbp, rdi
push	rbx
mov	rbx, rsi
sub	rsp, 24
mov	r13d, dword [rdi+4184]
test	r13d, r13d
jne	sn_PLC_L136
mov	eax, dword [rdi+4244]
test	eax, eax
jne	sn_PLC_L137
sn_PLC_L118:
mov	dword [rbp+4244], r13d
add	rsp, 24
pop	rbx
pop	rbp
pop	r12
pop	r13
ret
align 16
align 8
sn_PLC_L137:
lea	rdi, [rsp+12]
mov	ecx, edx
lea	rsi, [rsp+8]
mov	rdx, rbx
call	sn_silk_sum_sqr_shift
mov	edi, dword [rbp+4260]
mov	edx, dword [rsp+8]
cmp	edi, edx
jl	sn_PLC_L138
mov	eax, dword [rbp+4256]
mov	esi, dword [rsp+12]
jle	sn_PLC_L121
mov	ecx, edi
sub	ecx, edx
sar	esi, cl
sn_PLC_L121:
cmp	eax, esi
jge	sn_PLC_L118
test	eax, eax
je	sn_PLC_L123
bsr	edx, eax
mov	edi, 24
xor	edx, 31
sub	edx, 1
mov	ecx, edx
shl	eax, cl
mov	ecx, edi
sub	ecx, edx
mov	edx, 0
mov	dword [rbp+4256], eax
cmovs	ecx, edx
mov	edx, 1
sar	esi, cl
test	esi, esi
cmovle	esi, edx
cdq
idiv	esi
test	eax, eax
jle	sn_PLC_L132
bsr	edx, eax
xor	edx, 31
sub	edi, edx
je	sn_PLC_L139
lea	ecx, [rdx+-24]
mov	esi, eax
rol	esi, cl
mov	ecx, edi
ror	eax, cl
test	edi, edi
mov	ecx, edx
cmovs	eax, esi
and	ecx, 1
and	eax, 127
cmp	ecx, 1
sbb	esi, esi
and	esi, 13446
add	esi, 32768
sn_PLC_L127:
mov	ecx, edx
imul	ax, ax, 213
sar	ecx, 1
sar	esi, cl
movsx	rdx, esi
movsx	rax, ax
imul	rax, rdx
sar	rax, 16
add	esi, eax
mov	eax, 65536
shl	esi, 4
sub	eax, esi
sn_PLC_L125:
cdq
idiv	r12d
shl	eax, 2
test	r12d, r12d
jle	sn_PLC_L118
movsx	rdx, word [rbx]
movsx	rcx, esi
add	esi, eax
imul	rdx, rcx
sar	rdx, 16
mov	word [rbx], dx
cmp	esi, 65536
jg	sn_PLC_L118
lea	rcx, [rbx+2]
lea	edx, [r12+-1]
lea	r8, [rcx+rdx*2]
jmp	sn_PLC_L130
align 16
align 8
sn_PLC_L131:
movsx	rdx, word [rcx]
movsx	rdi, esi
add	esi, eax
add	rcx, 2
imul	rdx, rdi
sar	rdx, 16
mov	word [rcx+-2], dx
cmp	esi, 65536
jg	sn_PLC_L118
sn_PLC_L130:
cmp	rcx, r8
jne	sn_PLC_L131
jmp	sn_PLC_L118
align 16
align 8
sn_PLC_L136:
lea	rsi, [rdi+4260]
mov	ecx, edx
mov	rdx, rbx
mov	r13d, 1
lea	rdi, [rdi+4256]
call	sn_silk_sum_sqr_shift
jmp	sn_PLC_L118
align 16
align 8
sn_PLC_L138:
mov	eax, dword [rbp+4256]
mov	ecx, edx
mov	esi, dword [rsp+12]
sub	ecx, edi
sar	eax, cl
mov	dword [rbp+4256], eax
jmp	sn_PLC_L121
align 16
align 8
sn_PLC_L139:
and	eax, 127
mov	esi, 46214
jmp	sn_PLC_L127
align 16
align 8
sn_PLC_L123:
mov	dword [rbp+4256], 0
sn_PLC_L132:
xor	esi, esi
mov	eax, 65536
jmp	sn_PLC_L125
section .rodata
align 2
sn_PLC_RAND_ATTENUATE_UV_Q15:
dw 32440
dw 29491
align 2
sn_PLC_RAND_ATTENUATE_V_Q15:
dw 31130
dw 26214
align 2
sn_HARM_ATT_Q15:
dw 32440
dw 31130

; ===== shell_coder.c =====
section .text
align 16
sn_silk_shell_decoder:
push	r15
xor	eax, eax
mov	r15, rdi
push	r14
push	r13
xor	r13d, r13d
push	r12
push	rbp
push	rbx
mov	rbx, rsi
sub	rsp, 24
mov	word [rsp+10], ax
test	edx, edx
jg	sn_shell_coder_L32
sn_shell_coder_L2:
xor	r8d, r8d
xor	ebp, ebp
sn_shell_coder_L6:
mov	dword [r15], 0
sn_shell_coder_L9:
xor	edx, edx
xor	r14d, r14d
mov	word [r15+4], dx
mov	word [r15+6], r14w
test	r8d, r8d
jg	sn_shell_coder_L33
sn_shell_coder_L11:
mov	dword [r15+8], 0
sn_shell_coder_L14:
xor	edx, edx
xor	ebp, ebp
mov	word [r15+12], dx
mov	word [r15+14], bp
test	r13d, r13d
jg	sn_shell_coder_L16
sn_shell_coder_L35:
mov	qword [r15+16], 0
sn_shell_coder_L17:
mov	dword [r15+24], 0
sn_shell_coder_L25:
xor	edx, edx
xor	r13d, r13d
sn_shell_coder_L26:
mov	word [r15+28], dx
mov	word [r15+30], r13w
add	rsp, 24
pop	rbx
pop	rbp
pop	r12
pop	r13
pop	r14
pop	r15
ret
align 16
align 8
sn_shell_coder_L32:
movsx	rax, edx
lea	r12, [rel sn_silk_shell_code_table_offsets]
mov	r14d, edx
mov	rdi, rbx
movzx	esi, byte [r12+rax]
lea	rax, [rel sn_silk_shell_code_table3]
mov	edx, 8
mov	r13d, r14d
add	rsi, rax
call	sn_ec_dec_icdf
sub	r13d, eax
mov	ebp, eax
movsx	rax, ax
mov	word [rsp+10], r13w
test	eax, eax
jle	sn_shell_coder_L3
movzx	esi, byte [r12+rax]
mov	edx, 8
mov	rdi, rbx
movsx	r13d, r13w
lea	rax, [rel sn_silk_shell_code_table2]
add	rsi, rax
call	sn_ec_dec_icdf
mov	r14d, eax
sub	ebp, eax
movsx	rax, ax
test	eax, eax
jle	sn_shell_coder_L34
movzx	esi, byte [r12+rax]
lea	rax, [rel sn_silk_shell_code_table1]
mov	edx, 8
mov	rdi, rbx
add	rsi, rax
call	sn_ec_dec_icdf
mov	r8d, eax
sub	r14d, eax
movsx	rax, ax
test	eax, eax
jg	sn_shell_coder_L7
xor	edx, edx
xor	r8d, r8d
sn_shell_coder_L8:
movsx	rax, r14w
mov	word [r15+2], r8w
movsx	r8d, bp
mov	word [r15], dx
test	eax, eax
jle	sn_shell_coder_L9
movzx	esi, byte [r12+rax]
lea	rax, [rel sn_silk_shell_code_table0]
mov	edx, 8
mov	rdi, rbx
mov	dword [rsp+12], r8d
add	rsi, rax
call	sn_ec_dec_icdf
mov	r8d, dword [rsp+12]
mov	edx, eax
sub	r14d, eax
mov	word [r15+4], dx
mov	word [r15+6], r14w
test	r8d, r8d
jle	sn_shell_coder_L11
sn_shell_coder_L33:
movsx	rax, r8d
lea	r12, [rel sn_silk_shell_code_table_offsets]
mov	edx, 8
mov	rdi, rbx
movzx	esi, byte [r12+rax]
lea	rax, [rel sn_silk_shell_code_table1]
add	rsi, rax
call	sn_ec_dec_icdf
mov	r14d, eax
sub	ebp, eax
movsx	rax, ax
test	eax, eax
jg	sn_shell_coder_L12
xor	edx, edx
xor	r14d, r14d
sn_shell_coder_L13:
movsx	rax, bp
mov	word [r15+8], dx
mov	word [r15+10], r14w
test	eax, eax
jle	sn_shell_coder_L14
movzx	esi, byte [r12+rax]
lea	rax, [rel sn_silk_shell_code_table0]
mov	edx, 8
mov	rdi, rbx
add	rsi, rax
call	sn_ec_dec_icdf
mov	edx, eax
sub	ebp, eax
mov	word [r15+12], dx
mov	word [r15+14], bp
test	r13d, r13d
jle	sn_shell_coder_L35
sn_shell_coder_L16:
movsx	rax, r13d
lea	r12, [rel sn_silk_shell_code_table_offsets]
mov	edx, 8
mov	rdi, rbx
movzx	esi, byte [r12+rax]
lea	rax, [rel sn_silk_shell_code_table2]
add	rsi, rax
call	sn_ec_dec_icdf
movzx	r13d, word [rsp+10]
mov	ebp, eax
sub	r13d, eax
movsx	rax, ax
test	eax, eax
jle	sn_shell_coder_L18
movzx	esi, byte [r12+rax]
lea	rax, [rel sn_silk_shell_code_table1]
mov	edx, 8
mov	rdi, rbx
add	rsi, rax
call	sn_ec_dec_icdf
mov	r14d, eax
sub	ebp, eax
movsx	rax, ax
test	eax, eax
jg	sn_shell_coder_L19
xor	esi, esi
xor	edx, edx
sn_shell_coder_L20:
movsx	rax, bp
mov	word [r15+16], si
movsx	r14d, r13w
mov	word [r15+18], dx
test	eax, eax
jle	sn_shell_coder_L21
movzx	esi, byte [r12+rax]
lea	rax, [rel sn_silk_shell_code_table0]
mov	edx, 8
mov	rdi, rbx
add	rsi, rax
call	sn_ec_dec_icdf
mov	edx, eax
sub	ebp, eax
sn_shell_coder_L22:
mov	word [r15+20], dx
mov	word [r15+22], bp
test	r14d, r14d
jle	sn_shell_coder_L17
movsx	rax, r14d
mov	edx, 8
mov	rdi, rbx
movzx	esi, byte [r12+rax]
lea	rax, [rel sn_silk_shell_code_table1]
add	rsi, rax
call	sn_ec_dec_icdf
mov	ebp, eax
sub	r13d, eax
movsx	rax, ax
test	eax, eax
jg	sn_shell_coder_L23
xor	esi, esi
xor	edx, edx
sn_shell_coder_L24:
movsx	rax, r13w
mov	word [r15+24], si
mov	word [r15+26], dx
test	eax, eax
jle	sn_shell_coder_L25
movzx	esi, byte [r12+rax]
lea	rax, [rel sn_silk_shell_code_table0]
mov	edx, 8
mov	rdi, rbx
add	rsi, rax
call	sn_ec_dec_icdf
mov	edx, eax
sub	r13d, eax
jmp	sn_shell_coder_L26
align 16
align 8
sn_shell_coder_L7:
movzx	esi, byte [r12+rax]
lea	rax, [rel sn_silk_shell_code_table0]
mov	edx, 8
mov	rdi, rbx
mov	dword [rsp+12], r8d
add	rsi, rax
call	sn_ec_dec_icdf
mov	r8d, dword [rsp+12]
mov	edx, eax
sub	r8d, eax
jmp	sn_shell_coder_L8
align 16
align 8
sn_shell_coder_L12:
movzx	esi, byte [r12+rax]
lea	rax, [rel sn_silk_shell_code_table0]
mov	edx, 8
mov	rdi, rbx
add	rsi, rax
call	sn_ec_dec_icdf
mov	edx, eax
sub	r14d, eax
jmp	sn_shell_coder_L13
align 16
align 8
sn_shell_coder_L23:
movzx	esi, byte [r12+rax]
lea	rax, [rel sn_silk_shell_code_table0]
mov	edx, 8
mov	rdi, rbx
add	rsi, rax
call	sn_ec_dec_icdf
mov	edx, ebp
mov	esi, eax
sub	edx, eax
jmp	sn_shell_coder_L24
align 16
align 8
sn_shell_coder_L19:
movzx	esi, byte [r12+rax]
lea	rax, [rel sn_silk_shell_code_table0]
mov	edx, 8
mov	rdi, rbx
add	rsi, rax
call	sn_ec_dec_icdf
mov	edx, r14d
mov	esi, eax
sub	edx, eax
jmp	sn_shell_coder_L20
align 16
align 8
sn_shell_coder_L3:
movsx	r13d, word [rsp+10]
jmp	sn_shell_coder_L2
align 16
align 8
sn_shell_coder_L18:
mov	dword [r15+16], 0
movsx	r14d, r13w
sn_shell_coder_L21:
xor	edx, edx
xor	ebp, ebp
jmp	sn_shell_coder_L22
align 16
align 8
sn_shell_coder_L34:
movsx	r8d, bp
jmp	sn_shell_coder_L6

; ===== tables_gain.c =====
section .text
section .rodata
align 32
sn_silk_delta_gain_iCDF:
db 250,245,234,203,71,50,42,38,35,33,31,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0
align 16
sn_silk_gain_iCDF:
db 224,112,44,15,3,2,1,0
db 254,237,192,132,70,23,4,0
db 255,252,226,155,61,11,2,0

; ===== tables_LTP.c =====
section .text
section .rodata
sn_silk_LTP_vq_sizes:
db 8,16,32
align 32
sn_silk_LTP_gain_vq_2_gain:
db 126,124,125,124,129,121,126,23,132,127,127,127,126,127,122,133,130,134,101,118,119,145,126,86,124,120,123
db 119,170,173,107,109
align 16
sn_silk_LTP_gain_vq_1_gain:
db 109,120,118,12,113,115,117,119,99,59,87,111,63,111,112,80
align 8
sn_silk_LTP_gain_vq_0_gain:
db 46,2,90,87,93,91,82,98
align 32
sn_silk_LTP_gain_vq_2:
db 250,27,61,39,5
db 245,42,88,4,1
db 254,60,65,6,252
db 255,251,73,56,1
db 247,19,94,29,247
db 0
db 12,99,6,4
db 8,237,102,46,243
db 3,2,13,3,2
db 9,235,84,72,238
db 245,46,104,234,8
db 18,38,48,23,0
db 240,70,83,235,11
db 5,245,117,22,248
db 250,23,117,244,3
db 3,248,95,28,4
db 246,15,77,60,241
db 255,4,124,2,252
db 3,38,84,24,231
db 2,13,42,13,31
db 21,252,56,46,255
db 255,35,79,243,19
db 249,65,88,247,242
db 20,4,81,49,227
db 20,0
db 75,3,239
db 5,247,44,92,248
db 1,253,22,69,31
db 250,95,41,244,5
db 39,67,16,252,1
db 0
db 250,120,55,220
db 243,44,122,4,232
db 81,5,11,3,7
db 2,0
db 9,10,88
align 32
sn_silk_LTP_gain_vq_1:
db 13,22,39,23,12
db 255,36,64,27,250
db 249,10,55,43,17
db 1,1,8,1,1
db 6,245,74,53,247
db 244,55,76,244,8
db 253,3,93,27,252
db 26,39,59,3,248
db 2,0
db 77,11,9
db 248,22,44,250,7
db 40,9,26,3,9
db 249,20,101,249,4
db 3,248,42,26,0
db 241,33,68,2,23
db 254,55,46,254,15
db 3,255,21,16,41
align 32
sn_silk_LTP_gain_vq_0:
db 4,6,24,7,5
db 0
db 0
db 2,0
db 0
db 12,28,41,13,252
db 247,15,42,25,14
db 1,254,62,41,247
db 246,37,65,252,3
db 250,4,66,7,248
db 16,14,38,253,33
align 32
sn_silk_LTP_gain_BITS_Q5_2:
db 131,128,134,141,141,141,145,145,145,150,155,155,155,155,160
db 160,160,160,166,166,173,173,182,192,182,192,192,192,205,192
db 205,224
align 16
sn_silk_LTP_gain_BITS_Q5_1:
db 69,93,115,118,131,138,141,138,150,150,155,150,155,160,166,160
align 8
sn_silk_LTP_gain_BITS_Q5_0:
db 15,131,138,138,155,155,173,173
align 32
sn_silk_LTP_gain_iCDF_2:
db 241,225,211,199,187,175,164,153,142,132,123,114,105,96,88,80,72,64,57,50,44,38,33,29,24,20,16,12,9,5,2,0
align 16
sn_silk_LTP_gain_iCDF_1:
db 199,165,144,124,109,96,84,71,61,51,42,32,23,15,8,0
align 8
sn_silk_LTP_gain_iCDF_0:
db 71,56,43,30,21,12,6,0
sn_silk_LTP_per_index_iCDF:
db 179,99,0

; ===== tables_NLSF_CB_NB_MB.c =====
section .text
section .rodata
align 16
sn_silk_NLSF_DELTA_MIN_NB_MB_Q15:
dw 250
dw 3
dw 6
dw 3
dw 3
dw 3
dw 4
dw 3
dw 3
dw 3
dw 461
align 16
sn_silk_NLSF_PRED_NB_MB_Q8:
db 179,138,140,148,151,149,153,151,163,116,67,82,59,92,72,100,89,92
align 32
sn_silk_NLSF_CB2_BITS_NB_MB_Q5:
db 255,255,255,131,6,145,255,255,255,255,255,236,93,15,96,255,255
db 255,255,255,194,83,25,71,221,255,255,255,255,162,73,34,66,162,255,255
db 255,210,126,73,43,57,173,255,255,255,201,125,71,48,58,130,255,255,255,166,110,73,57,62
db 104,210,255,255,251,123,65,55,68,100,171,255
align 32
sn_silk_NLSF_CB2_iCDF_NB_MB:
db 255,254,253,238,14,3,2,1,0
db 255,254,252,218,35,3,2,1,0
db 255,254,250,208,59,4,2,1,0
db 255,254,246,194,71,10,2,1,0
db 255,252,236,183,82,8,2,1,0
db 255,252,235,180,90,17,2,1,0
db 255,248,224,171,97,30,4,1,0
db 255,254,236,173,95,37,7,1,0
align 32
sn_silk_NLSF_CB2_SELECT_NB_MB:
db 16,0
db 0
db 0
db 0
db 99,66,36,36,34,36,34,34,34,34,83,69,36,52,34,116,102,70,68,68,176,102,68,68,34,65,85,68,84,36,116,141,152,139,170,132
db 187,184,216,137,132,249,168,185,139,104,102,100,68,68,178,218,185,185,170
db 244,216,187,187,170,244,187,187,219,138,103,155,184,185,137,116,183
db 155,152,136,132,217,184,184,170,164,217,171,155,139,244,169
db 184,185,170,164,216,223,218,138,214,143,188,218,168,244,141
db 136,155,170,168,138,220,219,139,164,219,202,216,137,168,186
db 246,185,139,116,185,219,185,138,100,100,134,100,102,34,68,68,100,68,168,203,221,218,168
db 167,154,136,104,70,164,246,171,137,139,137,155,218,219,139
align 32
sn_silk_NLSF_CB1_iCDF_NB_MB:
db 212,178,148,129,108,96,85,82,79,77,61,59,57,56,51,49,48,45,42,41,40,38,36,34,31,30,21,12,10,3,1,0
db 255,245,244,236,233,225,217,203,190,176,175,161,149,136,125,114,102,91,81,71,60,52,43,35,28,20,19,18,12,11,5,0
align 32
sn_silk_NLSF_CB1_Wght_Q9:
dw 2897
dw 2314
dw 2314
dw 2314
dw 2287
dw 2287
dw 2314
dw 2300
dw 2327
dw 2287
dw 2888
dw 2580
dw 2394
dw 2367
dw 2314
dw 2274
dw 2274
dw 2274
dw 2274
dw 2194
dw 2487
dw 2340
dw 2340
dw 2314
dw 2314
dw 2314
dw 2340
dw 2340
dw 2367
dw 2354
dw 3216
dw 2766
dw 2340
dw 2340
dw 2314
dw 2274
dw 2221
dw 2207
dw 2261
dw 2194
dw 2460
dw 2474
dw 2367
dw 2394
dw 2394
dw 2394
dw 2394
dw 2367
dw 2407
dw 2314
dw 3479
dw 3056
dw 2127
dw 2207
dw 2274
dw 2274
dw 2274
dw 2287
dw 2314
dw 2261
dw 3282
dw 3141
dw 2580
dw 2394
dw 2247
dw 2221
dw 2207
dw 2194
dw 2194
dw 2114
dw 4096
dw 3845
dw 2221
dw 2620
dw 2620
dw 2407
dw 2314
dw 2394
dw 2367
dw 2074
dw 3178
dw 3244
dw 2367
dw 2221
dw 2553
dw 2434
dw 2340
dw 2314
dw 2167
dw 2221
dw 3338
dw 3488
dw 2726
dw 2194
dw 2261
dw 2460
dw 2354
dw 2367
dw 2207
dw 2101
dw 2354
dw 2420
dw 2327
dw 2367
dw 2394
dw 2420
dw 2420
dw 2420
dw 2460
dw 2367
dw 3779
dw 3629
dw 2434
dw 2527
dw 2367
dw 2274
dw 2274
dw 2300
dw 2207
dw 2048
dw 3254
dw 3225
dw 2713
dw 2846
dw 2447
dw 2327
dw 2300
dw 2300
dw 2274
dw 2127
dw 3263
dw 3300
dw 2753
dw 2806
dw 2447
dw 2261
dw 2261
dw 2247
dw 2127
dw 2101
dw 2873
dw 2981
dw 2633
dw 2367
dw 2407
dw 2354
dw 2194
dw 2247
dw 2247
dw 2114
dw 3225
dw 3197
dw 2633
dw 2580
dw 2274
dw 2181
dw 2247
dw 2221
dw 2221
dw 2141
dw 3178
dw 3310
dw 2740
dw 2407
dw 2274
dw 2274
dw 2274
dw 2287
dw 2194
dw 2114
dw 3141
dw 3272
dw 2460
dw 2061
dw 2287
dw 2500
dw 2367
dw 2487
dw 2434
dw 2181
dw 3507
dw 3282
dw 2314
dw 2700
dw 2647
dw 2474
dw 2367
dw 2394
dw 2340
dw 2127
dw 3423
dw 3535
dw 3038
dw 3056
dw 2300
dw 1950
dw 2221
dw 2274
dw 2274
dw 2274
dw 3404
dw 3366
dw 2087
dw 2687
dw 2873
dw 2354
dw 2420
dw 2274
dw 2474
dw 2540
dw 3760
dw 3488
dw 1950
dw 2660
dw 2897
dw 2527
dw 2394
dw 2367
dw 2460
dw 2261
dw 3028
dw 3272
dw 2740
dw 2888
dw 2740
dw 2154
dw 2127
dw 2287
dw 2234
dw 2247
dw 3695
dw 3657
dw 2025
dw 1969
dw 2660
dw 2700
dw 2580
dw 2500
dw 2327
dw 2367
dw 3207
dw 3413
dw 2354
dw 2074
dw 2888
dw 2888
dw 2340
dw 2487
dw 2247
dw 2167
dw 3338
dw 3366
dw 2846
dw 2780
dw 2327
dw 2154
dw 2274
dw 2287
dw 2114
dw 2061
dw 2327
dw 2300
dw 2181
dw 2167
dw 2181
dw 2367
dw 2633
dw 2700
dw 2700
dw 2553
dw 2407
dw 2434
dw 2221
dw 2261
dw 2221
dw 2221
dw 2340
dw 2420
dw 2607
dw 2700
dw 3038
dw 3244
dw 2806
dw 2888
dw 2474
dw 2074
dw 2300
dw 2314
dw 2354
dw 2380
dw 2221
dw 2154
dw 2127
dw 2287
dw 2500
dw 2793
dw 2793
dw 2620
dw 2580
dw 2367
dw 3676
dw 3713
dw 2234
dw 1838
dw 2181
dw 2753
dw 2726
dw 2673
dw 2513
dw 2207
dw 2793
dw 3160
dw 2726
dw 2553
dw 2846
dw 2513
dw 2181
dw 2394
dw 2221
dw 2181
align 32
sn_silk_NLSF_CB1_NB_MB_Q8:
db 12,35,60,83,108,132,157,180,206,228,15,32,55,77,101,125,151,175,201,225,19,42,66,89,114,137
db 162,184,209,230,12,25,50,72,97,120,147,172,200,223,26,44,69,90,114,135,159,180
db 205,225,13,22,53,80,106,130,156,180,205,228,15,25,44,64,90,115,142,168,196
db 222,19,24,62,82,100,120,145,168,190,214,22,31,50,79,103,120,151,170,203,227
db 21,29,45,65,106,124,150,171,196,224,30,49,75,97,121,142,165,186,209,229,19
db 25,52,70,93,116,143,166,192,219,26,34,62,75,97,118,145,167,194,217,25,33,56,70,91,113,143
db 165,196,223,21,34,51,72,97,117,145,171,196,222,20,29,50,67,90,117,144,168,197
db 221,22,31,48,66,95,117,146,168,196,222,24,33,51,77,116,134,158,180,200,224
db 21,28,70,87,106,124,149,170,194,217,26,33,53,64,83,117,152,173,204,225,27,34,65
db 95,108,129,155,174,210,225,20,26,72,99,113,131,154,176,200,219,34,43,61,78,93,114
db 155,177,205,229,23,29,54,97,124,138,163,179,209,229,30,38,56,89,118,129,158
db 178,200,231,21,29,49,63,85,111,142,163,193,222,27,48,77,103,133,158,179,196
db 215,232,29,47,74,99,124,151,176,198,220,237,33,42,61,76,93,121,155,174,207,225,29
db 53,87,112,136,154,170,188,208,227,24,30,52,84,131,150,166,186,203,229
db 37,48,64,84,104,118,156,177,201,230

; ===== tables_NLSF_CB_WB.c =====
section .text
section .rodata
align 32
sn_silk_NLSF_DELTA_MIN_WB_Q15:
dw 100
dw 3
dw 40
dw 3
dw 3
dw 3
dw 5
dw 14
dw 14
dw 10
dw 11
dw 3
dw 8
dw 9
dw 7
dw 3
dw 347
align 16
sn_silk_NLSF_PRED_WB_Q8:
db 175,148,160,176,178,173,174,164,177,174,196,182,198,192,182
db 68,62,66,60,72,117,85,90,118,136,151,142,160,142,155
align 32
sn_silk_NLSF_CB2_BITS_WB_Q5:
db 255,255,255,156,4,154,255,255,255,255,255,227,102,15,92,255,255
db 255,255,255,213,83,24,72,236,255,255,255,255,150,76,33,63,214,255,255
db 255,190,121,77,43,55,185,255,255,255,245,137,71,43,59,139,255,255,255,255,131
db 66,50,66,107,194,255,255,166,116,76,55,53,125,255,255
align 32
sn_silk_NLSF_CB2_iCDF_WB:
db 255,254,253,244,12,3,2,1,0
db 255,254,252,224,38,3,2,1,0
db 255,254,251,209,57,4,2,1,0
db 255,254,244,195,69,4,2,1,0
db 255,251,232,184,84,7,2,1,0
db 255,254,240,186,86,14,2,1,0
db 255,254,239,178,91,30,5,1,0
db 255,248,227,177,100,19,2,1,0
align 32
sn_silk_NLSF_CB2_SELECT_WB:
db 0
db 0
db 0
db 0
db 0
db 0
db 0
db 1,100,102,102,68,68,36,34,96,164,107,158,185,180,185,139,102,64,66,36,34,34,0
db 1,32,208,139,141,191,152,185,155,104,96,171,104,166,102,102,102,132,1,0
db 0
db 0
db 0
db 16,16,0
db 80,109,78,107,185,139,103,101,208,212,141,139,173,153,123,103,36,0
db 0
db 0
db 0
db 0
db 0
db 1,48,0
db 0
db 0
db 0
db 0
db 0
db 32,68,135,123,119,119,103,69,98,68,103,120,118,118,102,71,98,134,136,157,184,182,153,139,134,208,168,248,75,189,143,121,107,32,49,34,34,34,0
db 17,2,210,235,139,123,185,137,105,134,98,135,104,182,100,183,171,134,100,70,68,70,66,66,34,131,64,166,102,68,36,2,1,0
db 134,166,102,68,34,34,66,132,212,246,158,139,107,107,87,102,100,219,125,122,137,118,103,132,114,135,137,105,171,106,50,34,164,214,141,143,185,151,121,103,192,34,0
db 0
db 0
db 0
db 0
db 1,208,109,74,187,134,249,159,137,102,110,154,118,87,101,119,101,0
db 2,0
db 36,36,66,68,35,96,164,102,100,36,0
db 2,33,167,138,174,102,100,84,2,2,100,107,120,119,36,197,24,0
align 32
sn_silk_NLSF_CB1_iCDF_WB:
db 225,204,201,184,183,175,158,154,153,135,119,115,113,110,109,99,98,95,79,68,52,50,48,45,43,32,31,27,18,10,3,0
db 255,251,235,230,212,201,196,182,167,166,163,151,138,124,110,104,90,78,76,70,69,57,45,34,24,21,11,6,5,4,3,0
align 32
sn_silk_NLSF_CB1_WB_Wght_Q9:
dw 3657
dw 2925
dw 2925
dw 2925
dw 2925
dw 2925
dw 2925
dw 2925
dw 2925
dw 2925
dw 2925
dw 2925
dw 2963
dw 2963
dw 2925
dw 2846
dw 3216
dw 3085
dw 2972
dw 3056
dw 3056
dw 3010
dw 3010
dw 3010
dw 2963
dw 2963
dw 3010
dw 2972
dw 2888
dw 2846
dw 2846
dw 2726
dw 3920
dw 4014
dw 2981
dw 3207
dw 3207
dw 2934
dw 3056
dw 2846
dw 3122
dw 3244
dw 2925
dw 2846
dw 2620
dw 2553
dw 2780
dw 2925
dw 3516
dw 3197
dw 3010
dw 3103
dw 3019
dw 2888
dw 2925
dw 2925
dw 2925
dw 2925
dw 2888
dw 2888
dw 2888
dw 2888
dw 2888
dw 2753
dw 5054
dw 5054
dw 2934
dw 3573
dw 3385
dw 3056
dw 3085
dw 2793
dw 3160
dw 3160
dw 2972
dw 2846
dw 2513
dw 2540
dw 2753
dw 2888
dw 4428
dw 4149
dw 2700
dw 2753
dw 2972
dw 3010
dw 2925
dw 2846
dw 2981
dw 3019
dw 2925
dw 2925
dw 2925
dw 2925
dw 2888
dw 2726
dw 3620
dw 3019
dw 2972
dw 3056
dw 3056
dw 2873
dw 2806
dw 3056
dw 3216
dw 3047
dw 2981
dw 3291
dw 3291
dw 2981
dw 3310
dw 2991
dw 5227
dw 5014
dw 2540
dw 3338
dw 3526
dw 3385
dw 3197
dw 3094
dw 3376
dw 2981
dw 2700
dw 2647
dw 2687
dw 2793
dw 2846
dw 2673
dw 5081
dw 5174
dw 4615
dw 4428
dw 2460
dw 2897
dw 3047
dw 3207
dw 3169
dw 2687
dw 2740
dw 2888
dw 2846
dw 2793
dw 2846
dw 2700
dw 3122
dw 2888
dw 2963
dw 2925
dw 2925
dw 2925
dw 2925
dw 2963
dw 2963
dw 2963
dw 2963
dw 2925
dw 2925
dw 2963
dw 2963
dw 2963
dw 4202
dw 3207
dw 2981
dw 3103
dw 3010
dw 2888
dw 2888
dw 2925
dw 2972
dw 2873
dw 2916
dw 3019
dw 2972
dw 3010
dw 3197
dw 2873
dw 3760
dw 3760
dw 3244
dw 3103
dw 2981
dw 2888
dw 2925
dw 2888
dw 2972
dw 2934
dw 2793
dw 2793
dw 2846
dw 2888
dw 2888
dw 2660
dw 3854
dw 4014
dw 3207
dw 3122
dw 3244
dw 2934
dw 3047
dw 2963
dw 2963
dw 3085
dw 2846
dw 2793
dw 2793
dw 2793
dw 2793
dw 2580
dw 3845
dw 4080
dw 3357
dw 3516
dw 3094
dw 2740
dw 3010
dw 2934
dw 3122
dw 3085
dw 2846
dw 2846
dw 2647
dw 2647
dw 2846
dw 2806
dw 5147
dw 4894
dw 3225
dw 3845
dw 3441
dw 3169
dw 2897
dw 3413
dw 3451
dw 2700
dw 2580
dw 2673
dw 2740
dw 2846
dw 2806
dw 2753
dw 4109
dw 3789
dw 3291
dw 3160
dw 2925
dw 2888
dw 2888
dw 2925
dw 2793
dw 2740
dw 2793
dw 2740
dw 2793
dw 2846
dw 2888
dw 2806
dw 5081
dw 5054
dw 3047
dw 3545
dw 3244
dw 3056
dw 3085
dw 2944
dw 3103
dw 2897
dw 2740
dw 2740
dw 2740
dw 2846
dw 2793
dw 2620
dw 4309
dw 4309
dw 2860
dw 2527
dw 3207
dw 3376
dw 3376
dw 3075
dw 3075
dw 3376
dw 3056
dw 2846
dw 2647
dw 2580
dw 2726
dw 2753
dw 3056
dw 2916
dw 2806
dw 2888
dw 2740
dw 2687
dw 2897
dw 3103
dw 3150
dw 3150
dw 3216
dw 3169
dw 3056
dw 3010
dw 2963
dw 2846
dw 4375
dw 3882
dw 2925
dw 2888
dw 2846
dw 2888
dw 2846
dw 2846
dw 2888
dw 2888
dw 2888
dw 2846
dw 2888
dw 2925
dw 2888
dw 2846
dw 2981
dw 2916
dw 2916
dw 2981
dw 2981
dw 3056
dw 3122
dw 3216
dw 3150
dw 3056
dw 3010
dw 2972
dw 2972
dw 2972
dw 2925
dw 2740
dw 4229
dw 4149
dw 3310
dw 3347
dw 2925
dw 2963
dw 2888
dw 2981
dw 2981
dw 2846
dw 2793
dw 2740
dw 2846
dw 2846
dw 2846
dw 2793
dw 4080
dw 4014
dw 3103
dw 3010
dw 2925
dw 2925
dw 2925
dw 2888
dw 2925
dw 2925
dw 2846
dw 2846
dw 2846
dw 2793
dw 2888
dw 2780
dw 4615
dw 4575
dw 3169
dw 3441
dw 3207
dw 2981
dw 2897
dw 3038
dw 3122
dw 2740
dw 2687
dw 2687
dw 2687
dw 2740
dw 2793
dw 2700
dw 4149
dw 4269
dw 3789
dw 3657
dw 2726
dw 2780
dw 2888
dw 2888
dw 3010
dw 2972
dw 2925
dw 2846
dw 2687
dw 2687
dw 2793
dw 2888
dw 4215
dw 3554
dw 2753
dw 2846
dw 2846
dw 2888
dw 2888
dw 2888
dw 2925
dw 2925
dw 2888
dw 2925
dw 2925
dw 2925
dw 2963
dw 2888
dw 5174
dw 4921
dw 2261
dw 3432
dw 3789
dw 3479
dw 3347
dw 2846
dw 3310
dw 3479
dw 3150
dw 2897
dw 2460
dw 2487
dw 2753
dw 2925
dw 3451
dw 3685
dw 3122
dw 3197
dw 3357
dw 3047
dw 3207
dw 3207
dw 2981
dw 3216
dw 3085
dw 2925
dw 2925
dw 2687
dw 2540
dw 2434
dw 2981
dw 3010
dw 2793
dw 2793
dw 2740
dw 2793
dw 2846
dw 2972
dw 3056
dw 3103
dw 3150
dw 3150
dw 3150
dw 3103
dw 3010
dw 3010
dw 2944
dw 2873
dw 2687
dw 2726
dw 2780
dw 3010
dw 3432
dw 3545
dw 3357
dw 3244
dw 3056
dw 3010
dw 2963
dw 2925
dw 2888
dw 2846
dw 3019
dw 2944
dw 2897
dw 3010
dw 3010
dw 2972
dw 3019
dw 3103
dw 3056
dw 3056
dw 3010
dw 2888
dw 2846
dw 2925
dw 2925
dw 2888
dw 3920
dw 3967
dw 3010
dw 3197
dw 3357
dw 3216
dw 3291
dw 3291
dw 3479
dw 3704
dw 3441
dw 2726
dw 2181
dw 2460
dw 2580
dw 2607
align 32
sn_silk_NLSF_CB1_WB_Q8:
db 7,23,38,54,69,85,100,116,131,147,162,178,193,208,223,239,13,25,41,55,69,83,98,112,127
db 142,157,171,187,203,220,236,15,21,34,51,61,78,92,106,126,136,152,167,185
db 205,225,240,10,21,36,50,63,79,95,110,126,141,157,173,189,205,221,237,17,20
db 37,51,59,78,89,107,123,134,150,164,184,205,224,240,10,15,32,51,67,81,96,112,129,142,158,173
db 189,204,220,236,8,21,37,51,65,79,98,113,126,138,155,168,179,192,209,218,12,15
db 34,55,63,78,87,108,118,131,148,167,185,203,219,236,16,19,32,36,56,79,91,108,118,136,154,171
db 186,204,220,237,11,28,43,58,74,89,105,120,135,150,165,180,196,211,226,241
db 6,16,33,46,60,75,92,107,123,137,156,169,185,199,214,225,11,19,30,44,57,74,89
db 105,121,135,152,169,186,202,218,234,12,19,29,46,57,71,88,100,120,132,148,165,182
db 199,216,233,17,23,35,46,56,77,92,106,123,134,152,167,185,204,222,237,14
db 17,45,53,63,75,89,107,115,132,151,171,188,206,221,240,9,16,29,40,56,71,88,103,119,137,154
db 171,189,205,222,237,16,19,36,48,57,76,87,105,118,132,150,167,185,202,218,236
db 12,17,29,54,71,81,94,104,126,136,149,164,182,201,221,237,15,28,47,62,79,97,115,129
db 142,155,168,180,194,208,223,238,8,14,30,45,62,78,94,111,127,143,159,175
db 192,207,223,239,17,30,49,62,79,92,107,119,132,145,160,174,190,204,220,235
db 14,19,36,45,61,76,91,108,121,138,154,172,189,205,222,238,12,18,31,45,60,76,91,107,123,138
db 154,171,187,204,221,236,13,17,31,43,53,70,83,103,114,131,149,167,185,203
db 220,237,17,22,35,42,58,78,93,110,125,139,155,170,188,206,224,240,8,15,34,50
db 67,83,99,115,131,146,162,178,193,209,224,239,13,16,41,66,73,86,95,111,128,137,150
db 163,183,206,225,241,17,25,37,52,63,75,92,102,119,132,144,160,175,191,212
db 231,19,31,49,65,83,100,117,133,147,161,174,187,200,213,227,242,18,31
db 52,68,88,103,117,126,138,149,163,177,192,207,223,239,16,29,47,61,76,90,106,119,133,147
db 161,176,193,209,224,240,15,21,35,50,61,73,86,97,110,119,129,141,175,198,218
db 237

; ===== tables_other.c =====
section .text
section .rodata
align 32
sn_silk_Transition_LP_A_Q28:
dd 506393414
dd 239854379
dd 411067935
dd 169683996
dd 306733530
dd 116694253
dd 185807084
dd 77959395
dd 35497197
dd 57401098
align 32
sn_silk_Transition_LP_B_Q28:
dd 250767114
dd 501534038
dd 250767114
dd 209867381
dd 419732057
dd 209867381
dd 170987846
dd 341967853
dd 170987846
dd 131531482
dd 263046905
dd 131531482
dd 89306658
dd 178584282
dd 89306658
sn_silk_NLSF_EXT_iCDF:
db 100,40,16,7,3,1,0
align 8
sn_silk_uniform8_iCDF:
db 224,192,160,128,96,64,32,0
sn_silk_uniform6_iCDF:
db 213,171,128,85,43,0
sn_silk_uniform5_iCDF:
db 205,154,102,51,0
sn_silk_uniform4_iCDF:
db 192,128,64,0
sn_silk_uniform3_iCDF:
db 171,85,0
align 2
sn_silk_LTPScales_table_Q14:
dw 15565
dw 12288
dw 8192
align 8
sn_silk_Quantization_Offsets_Q10:
dw 100
dw 240
dw 32
dw 100
sn_silk_NLSF_interpolation_factor_iCDF:
db 243,221,192,181,0
sn_silk_type_offset_no_VAD_iCDF:
db 230,0
sn_silk_type_offset_VAD_iCDF:
db 232,158,10,0
sn_silk_LTPscale_iCDF:
db 128,64,0
sn_silk_lsb_iCDF:
db 120,0
sn_silk_LBRR_flags_3_iCDF:
db 215,195,166,125,110,82,0
sn_silk_LBRR_flags_2_iCDF:
db 203,150,0
sn_silk_stereo_only_code_mid_iCDF:
db 64,0
align 16
sn_silk_stereo_pred_joint_iCDF:
db 249,247,246,245,244,234,210,202,201,200,197,174,82,59,56,55,54,46,22,12,11,10,9,7,0
align 32
sn_silk_stereo_pred_quant_Q13:
dw -13732
dw -10050
dw -8266
dw -7526
dw -6500
dw -5000
dw -2950
dw -820
dw 820
dw 2950
dw 5000
dw 6500
dw 7526
dw 8266
dw 10050
dw 13732

; ===== tables_pitch_lag.c =====
section .text
section .rodata
sn_silk_pitch_contour_10_ms_NB_iCDF:
db 113,63,0
align 8
sn_silk_pitch_contour_10_ms_iCDF:
db 165,119,80,61,47,35,27,20,14,9,4,0
align 8
sn_silk_pitch_contour_NB_iCDF:
db 188,176,155,138,119,97,67,43,26,10,0
align 32
sn_silk_pitch_contour_iCDF:
db 223,201,183,167,152,138,124,111,98,88,79,70,62,56,50,44,39,35,31,27,24,21,18,16,14,12,10,8,6,4,3,2,1,0
align 16
sn_silk_pitch_delta_iCDF:
db 210,208,206,203,199,193,183,168,142,104,74,52,37,27,20,14,10,6,4,2,0
align 32
sn_silk_pitch_lag_iCDF:
db 253,250,244,233,212,182,150,131,120,110,98,85,72,60,49,40,32,25,19,15,13,11,9,8,7,6,5,4,3,2,1,0

; ===== tables_pulses_per_block.c =====
section .text
section .rodata
align 32
sn_silk_sign_iCDF:
db 254,49,67,77,82,93,99,198,11,18,24,31,36,45,255,46,66,78,87,94,104,208,14,21,32,42,51,66,255
db 94,104,109,112,115,118,248,53,69,80,88,95,102
align 16
sn_silk_shell_code_table_offsets:
db 0
db 0
db 2,5,9,14,20,27,35,44,54,65,77,90,104,119,135
align 32
sn_silk_shell_code_table3:
db 130,0
db 200,58,0
db 231,130,26,0
db 244,184,76,12,0
db 249,214,130,43,6,0
db 252,232,173,87,24,3,0
db 253,241,203,131,56,14,2,0
db 254,246,221,167,94,35,8,1,0
db 254,249,232,193,130,65,23,5,1,0
db 255,251,239,211,162,99,45,15,4,1,0
db 255,251,243,223,186,131,74,33,11,3,1,0
db 255,252,245,230,202,158,105,57,24,8,2,1,0
db 255,253,247,235,214,179,132,84,44,19,7,2,1,0
db 255,254,250,240,223,196,159,112,69,36,15,6,2,1,0
db 255,254,253,245,231,209,176,136,93,55,27,11,3,2,1,0
db 255,254,253,252,239,221,194,158,117,76,42,18,4,3,2,1,0
align 32
sn_silk_shell_code_table2:
db 129,0
db 203,54,0
db 234,129,23,0
db 245,184,73,10,0
db 250,215,129,41,5,0
db 252,232,173,86,24,3,0
db 253,240,200,129,56,15,2,0
db 253,244,217,164,94,38,10,1,0
db 253,245,226,189,132,71,27,7,1,0
db 253,246,231,203,159,105,56,23,6,1,0
db 255,248,235,213,179,133,85,47,19,5,1,0
db 255,254,243,221,194,159,117,70,37,12,2,1,0
db 255,254,248,234,208,171,128,85,48,22,8,2,1,0
db 255,254,250,240,220,189,149,107,67,36,16,6,2,1,0
db 255,254,251,243,227,201,166,128,90,55,29,13,5,2,1,0
db 255,254,252,246,234,213,183,147,109,73,43,22,10,4,2,1,0
align 32
sn_silk_shell_code_table1:
db 129,0
db 207,50,0
db 236,129,20,0
db 245,185,72,10,0
db 249,213,129,42,6,0
db 250,226,169,87,27,4,0
db 251,233,194,130,62,20,4,0
db 250,236,207,160,99,47,17,3,0
db 255,240,217,182,131,81,41,11,1,0
db 255,254,233,201,159,107,61,20,2,1,0
db 255,249,233,206,170,128,86,50,23,7,1,0
db 255,250,238,217,186,148,108,70,39,18,6,1,0
db 255,252,243,226,200,166,128,90,56,30,13,4,1,0
db 255,252,245,231,209,180,146,110,76,47,25,11,4,1,0
db 255,253,248,237,219,194,163,128,93,62,37,19,8,3,1,0
db 255,254,250,241,226,205,177,145,111,79,51,30,15,6,2,1,0
align 32
sn_silk_shell_code_table0:
db 128,0
db 214,42,0
db 235,128,21,0
db 244,184,72,11,0
db 248,214,128,42,7,0
db 248,225,170,80,25,5,0
db 251,236,198,126,54,18,3,0
db 250,238,211,159,82,35,15,5,0
db 250,231,203,168,128,88,53,25,6,0
db 252,238,216,185,148,108,71,40,18,4,0
db 253,243,225,199,166,128,90,57,31,13,3,0
db 254,246,233,212,183,147,109,73,44,23,10,2,0
db 255,250,240,223,198,166,128,90,58,33,16,6,1,0
db 255,251,244,231,210,181,146,110,75,46,25,12,5,1,0
db 255,253,248,238,221,196,164,128,92,60,35,18,8,3,1,0
db 255,253,249,242,229,208,180,146,110,76,48,27,14,7,3,1,0
align 16
sn_silk_rate_levels_BITS_Q5:
db 131,74,141,79,80,138,95,104,134
db 95,99,91,125,93,76,123,115,123
align 16
sn_silk_rate_levels_iCDF:
db 241,190,178,132,87,74,41,14,0
db 223,193,157,140,106,57,39,18,0
align 32
sn_silk_pulses_per_block_BITS_Q5:
db 31,57,107,160,205,205,255,255,255,255,255,255,255,255,255,255,255
db 255
db 69,47,67,111,166,205,255,255,255,255,255,255,255,255,255,255,255,255
db 82,74,79,95,109,128,145,160,173,205,205,205,224,255,255,224,255,224
db 125,74,59,69,97,141,182,255,255,255,255,255,255,255,255,255,255,255
db 173,115,85,73,76,92,115,145,173,205,224,224,255,255,255,255,255,255
db 166,134,113,102,101,102,107,118,125,138,145,155,166,182,192,192,205,150
db 224,182,134,101,83,79,85,97,120,145,173,205,224,255,255,255,255,255
db 255,224,192,150,120,101,92,89,93,102,118,134,160,182,192,224,224,224
db 255,224,224,182,155,134,118,109,104,102,106,111,118,131,145,160,173,131
align 32
sn_silk_pulses_per_block_iCDF:
db 125,51,26,18,15,12,11,10,9,8,7,6,5,4,3,2,1,0
db 198,105,45,22,15,12,11,10,9,8,7,6,5,4,3,2,1,0
db 213,162,116,83,59,43,32,24,18,15,12,9,7,6,5,3,2,0
db 239,187,116,59,28,16,11,10,9,8,7,6,5,4,3,2,1,0
db 250,229,188,135,86,51,30,19,13,10,8,6,5,4,3,2,1,0
db 249,235,213,185,156,128,103,83,66,53,42,33,26,21,17,13,10,0
db 254,249,235,206,164,118,77,46,27,16,10,7,5,4,3,2,1,0
db 255,253,249,239,220,191,156,119,85,57,37,23,15,10,6,4,2,0
db 255,253,251,246,237,223,203,179,152,124,98,75,55,40,29,21,15,0
db 255,254,253,247,220,162,106,67,42,28,18,12,9,6,4,3,2,0
sn_silk_max_pulses_table:
db 8,10,12,16

; ===== NLSF_unpack.c =====
section .text
align 16
sn_silk_NLSF_unpack:
movsx	eax, word [rdx+2]
mov	r8, rdx
mov	edx, eax
imul	eax, ecx
xor	ecx, ecx
mov	r9d, eax
shr	r9d, 31
add	r9d, eax
sar	r9d, 1
movsx	r9, r9d
add	r9, qword [r8+40]
test	dx, dx
jle	sn_NLSF_unpack_L1
align 16
align 8
sn_NLSF_unpack_L2:
movzx	eax, byte [r9]
add	r9, 1
mov	edx, eax
mov	r10d, eax
shr	dl, 1
and	r10d, 1
and	edx, 7
neg	r10d
lea	edx, [rdx+rdx*8]
mov	word [rdi+rcx*2], dx
movsx	edx, word [r8+2]
sub	edx, 1
and	edx, r10d
mov	r10, qword [r8+32]
add	edx, ecx
movsx	rdx, edx
movzx	edx, byte [r10+rdx]
mov	byte [rsi+rcx], dl
mov	edx, eax
shr	al, 4
shr	dl, 5
and	eax, 1
movzx	edx, dl
neg	eax
lea	edx, [rdx+rdx*8]
mov	word [rdi+rcx*2+2], dx
movsx	edx, word [r8+2]
sub	edx, 1
and	eax, edx
mov	rdx, qword [r8+32]
lea	eax, [rax+rcx+1]
cdqe
movzx	eax, byte [rdx+rax]
mov	byte [rsi+rcx+1], al
movsx	eax, word [r8+2]
add	rcx, 2
cmp	eax, ecx
jg	sn_NLSF_unpack_L2
sn_NLSF_unpack_L1:
ret

; ===== bwexpander_32.c =====
section .text
align 16
sn_silk_bwexpander_32:
lea	r10d, [rsi+-1]
mov	r9, rdi
lea	edi, [rdx+-65536]
mov	ecx, edx
test	r10d, r10d
jle	sn_bwexpander_32_L2
lea	eax, [rsi+-2]
mov	rdx, r9
lea	r8, [r9+rax*4+4]
align 16
align 8
sn_bwexpander_32_L3:
movsx	rax, dword [rdx]
movsx	rsi, ecx
add	rdx, 4
imul	rax, rsi
sar	rax, 16
mov	dword [rdx+-4], eax
mov	eax, edi
imul	eax, ecx
sar	eax, 15
add	eax, 1
sar	eax, 1
add	ecx, eax
cmp	r8, rdx
jne	sn_bwexpander_32_L3
sn_bwexpander_32_L2:
movsx	r10, r10d
movsx	rcx, ecx
lea	rdx, [r9+r10*4]
movsx	rax, dword [rdx]
imul	rax, rcx
sar	rax, 16
mov	dword [rdx], eax
ret

; ===== bwexpander.c =====
section .text
align 16
sn_silk_bwexpander:
lea	r9d, [rsi+-1]
mov	r8, rdi
lea	edi, [rdx+-65536]
mov	ecx, edx
test	r9d, r9d
jle	sn_bwexpander_L2
lea	eax, [rsi+-2]
mov	rdx, r8
lea	rsi, [r8+rax*2+2]
align 16
align 8
sn_bwexpander_L3:
movsx	eax, word [rdx]
add	rdx, 2
imul	eax, ecx
sar	eax, 15
add	eax, 1
sar	eax, 1
mov	word [rdx+-2], ax
mov	eax, edi
imul	eax, ecx
sar	eax, 15
add	eax, 1
sar	eax, 1
add	ecx, eax
cmp	rsi, rdx
jne	sn_bwexpander_L3
sn_bwexpander_L2:
movsx	r9, r9d
lea	rdx, [r8+r9*2]
movsx	eax, word [rdx]
imul	eax, ecx
sar	eax, 15
add	eax, 1
sar	eax, 1
mov	word [rdx], ax
ret

; ===== decode_pitch.c =====
section .text
align 16
sn_silk_decode_pitch:
push	rbp
mov	r11, rdx
movsx	edi, di
push	rbx
cmp	ecx, 8
je	sn_decode_pitch_L16
cmp	r8d, 4
je	sn_decode_pitch_L5
lea	rbp, [rel sn_silk_CB_lags_stage3_10_ms]
mov	ebx, 12
sn_decode_pitch_L3:
movsx	ecx, cx
lea	r10d, [rcx+rcx]
lea	r9d, [rcx+rcx*8]
add	r9d, r9d
add	edi, r10d
test	r8d, r8d
jle	sn_decode_pitch_L1
sn_decode_pitch_L4:
movsx	esi, sil
xor	edx, edx
jmp	sn_decode_pitch_L8
align 16
align 8
sn_decode_pitch_L17:
cmp	eax, r9d
mov	ecx, r9d
cmovge	ecx, eax
cmp	eax, r10d
mov	eax, ecx
cmovg	eax, r10d
add	esi, ebx
mov	dword [r11+rdx*4], eax
add	rdx, 1
cmp	r8d, edx
jle	sn_decode_pitch_L1
sn_decode_pitch_L8:
movsx	rax, esi
movsx	eax, byte [rbp+rax+0]
add	eax, edi
cmp	r10d, r9d
jg	sn_decode_pitch_L17
cmp	eax, r10d
mov	ecx, r10d
cmovge	ecx, eax
cmp	eax, r9d
mov	eax, ecx
cmovg	eax, r9d
add	esi, ebx
mov	dword [r11+rdx*4], eax
add	rdx, 1
cmp	r8d, edx
jg	sn_decode_pitch_L8
sn_decode_pitch_L1:
pop	rbx
pop	rbp
ret
align 16
align 8
sn_decode_pitch_L5:
movsx	ecx, cx
lea	rbp, [rel sn_silk_CB_lags_stage3]
mov	ebx, 34
lea	r10d, [rcx+rcx]
lea	r9d, [rcx+rcx*8]
add	r9d, r9d
add	edi, r10d
jmp	sn_decode_pitch_L4
align 16
align 8
sn_decode_pitch_L16:
lea	rbp, [rel sn_silk_CB_lags_stage2_10_ms]
mov	ebx, 3
cmp	r8d, 4
jne	sn_decode_pitch_L3
add	edi, 16
mov	r9d, 144
mov	r10d, 16
mov	ebx, 11
lea	rbp, [rel sn_silk_CB_lags_stage2]
jmp	sn_decode_pitch_L4

; ===== inner_prod_aligned.c =====
section .text
align 16
sn_silk_inner_prod_aligned_scale:
mov	r10, rdi
mov	r11, rsi
test	ecx, ecx
jle	sn_inner_prod_aligned_L4
movsx	r9, ecx
xor	esi, esi
xor	edi, edi
add	r9, r9
align 16
align 8
sn_inner_prod_aligned_L3:
movsx	eax, word [r10+rsi]
movsx	r8d, word [r11+rsi]
mov	ecx, edx
add	rsi, 2
imul	eax, r8d
sar	eax, cl
add	edi, eax
cmp	r9, rsi
jne	sn_inner_prod_aligned_L3
mov	eax, edi
ret
align 16
align 8
sn_inner_prod_aligned_L4:
xor	edi, edi
mov	eax, edi
ret

; ===== lin2log.c =====
section .text
align 16
sn_silk_lin2log:
mov	eax, -128
test	edi, edi
je	sn_lin2log_L1
bsr	eax, edi
mov	ecx, 24
xor	eax, 31
sub	ecx, eax
jne	sn_lin2log_L3
and	edi, 127
mov	eax, 128
sub	eax, edi
imul	eax, edi
cdqe
imul	rax, rax, 179
sar	rax, 16
lea	eax, [rdi+rax+896]
ret
align 16
align 8
sn_lin2log_L3:
mov	edx, 31
sub	edx, eax
shl	edx, 7
test	ecx, ecx
js	sn_lin2log_L10
ror	edi, cl
sn_lin2log_L8:
and	edi, 127
mov	eax, 128
sub	eax, edi
imul	eax, edi
add	edi, edx
cdqe
imul	rax, rax, 179
sar	rax, 16
add	eax, edi
sn_lin2log_L1:
ret
align 16
align 8
sn_lin2log_L10:
lea	ecx, [rax+-24]
rol	edi, cl
jmp	sn_lin2log_L8

; ===== log2lin.c =====
section .text
align 16
sn_silk_log2lin:
xor	eax, eax
test	edi, edi
js	sn_log2lin_L1
mov	eax, 2147483647
cmp	edi, 3966
jg	sn_log2lin_L1
mov	esi, edi
mov	edx, 128
mov	ecx, edi
mov	eax, 1
and	esi, 127
sar	ecx, 7
sub	edx, esi
shl	eax, cl
movsx	edx, dx
imul	edx, esi
movsx	rdx, edx
imul	rdx, rdx, -174
sar	rdx, 16
add	esi, edx
cmp	edi, 2047
jg	sn_log2lin_L3
shl	esi, cl
sar	esi, 7
add	eax, esi
ret
align 16
align 8
sn_log2lin_L3:
mov	edx, eax
sar	edx, 7
imul	edx, esi
add	eax, edx
sn_log2lin_L1:
ret

; ===== LPC_analysis_filter.c =====
section .text
align 16
sn_silk_LPC_analysis_filter:
push	r15
mov	r9, rdi
push	r14
push	r13
push	r12
mov	r12d, r8d
push	rbp
push	rbx
sub	rsp, 24
cmp	r8d, ecx
jge	sn_LPC_analysis_filter_L14
lea	r13d, [rcx+-1]
lea	eax, [r12+-7]
mov	r11, rdx
movsx	rdx, r12d
mov	dword [rsp+12], r13d
shr	eax, 1
mov	rbp, rsi
lea	r8d, [r8+-1]
lea	rbx, [rdi+rdx*2]
lea	r10, [r11+rax*4+16]
mov	rsi, rdi
mov	r15, rdx
mov	r14d, -32768
align 16
align 8
sn_LPC_analysis_filter_L6:
movsx	rax, r8d
movsx	edx, word [r11]
lea	r9, [rbp+rax*2+0]
movsx	eax, word [r11+2]
movsx	edi, word [r9+-2]
imul	edi, eax
movsx	eax, word [r9]
imul	eax, edx
movsx	edx, word [r11+4]
add	edi, eax
movsx	eax, word [r9+-4]
imul	eax, edx
movsx	edx, word [r11+6]
add	edi, eax
movsx	eax, word [r9+-6]
imul	eax, edx
movsx	edx, word [r11+8]
add	edi, eax
movsx	eax, word [r9+-8]
imul	eax, edx
movsx	edx, word [r11+10]
add	edi, eax
movsx	eax, word [r9+-10]
imul	eax, edx
add	edi, eax
cmp	r12d, 6
jle	sn_LPC_analysis_filter_L3
mov	qword [rsp], r9
lea	rdx, [r11+12]
lea	rcx, [r9+-12]
align 16
align 8
sn_LPC_analysis_filter_L4:
movsx	r9d, word [rdx]
movsx	eax, word [rcx]
add	rdx, 4
sub	rcx, 4
movsx	r13d, word [rdx+-2]
imul	eax, r9d
movsx	r9d, word [rcx+2]
imul	r9d, r13d
add	eax, r9d
add	edi, eax
cmp	r10, rdx
jne	sn_LPC_analysis_filter_L4
mov	r9, qword [rsp]
sn_LPC_analysis_filter_L3:
movsx	eax, word [r9+2]
mov	edx, 32767
shl	eax, 12
sub	eax, edi
sar	eax, 11
add	eax, 1
mov	ecx, eax
sar	ecx, 1
cmp	eax, 65535
jg	sn_LPC_analysis_filter_L5
cmp	ecx, -32768
mov	edx, ecx
cmovl	edx, r14d
sn_LPC_analysis_filter_L5:
mov	word [rbx], dx
add	r8d, 1
add	rbx, 2
cmp	dword [rsp+12], r8d
jne	sn_LPC_analysis_filter_L6
mov	r9, rsi
mov	rdx, r15
sn_LPC_analysis_filter_L7:
add	rsp, 24
add	rdx, rdx
xor	esi, esi
mov	rdi, r9
pop	rbx
pop	rbp
pop	r12
pop	r13
pop	r14
pop	r15
jmp	sn_set
sn_LPC_analysis_filter_L14:
movsx	rdx, r8d
jmp	sn_LPC_analysis_filter_L7

; ===== LPC_inv_pred_gain.c =====
section .text
align 16
sn_silk_LPC_inverse_pred_gain_c:
push	r15
push	r14
push	r13
push	r12
push	rbp
push	rbx
sub	rsp, 120
test	esi, esi
jle	sn_LPC_inv_pred_gain_L6
movsx	r8, esi
xor	eax, eax
lea	rbx, [rsp+24]
xor	ecx, ecx
align 16
align 8
sn_LPC_inv_pred_gain_L5:
movsx	edx, word [rdi+rax*2]
add	ecx, edx
shl	edx, 12
mov	dword [rbx+rax*4], edx
add	rax, 1
cmp	r8, rax
jne	sn_LPC_inv_pred_gain_L5
cmp	ecx, 4095
jle	sn_LPC_inv_pred_gain_L6
sn_LPC_inv_pred_gain_L8:
xor	eax, eax
sn_LPC_inv_pred_gain_L1:
add	rsp, 120
pop	rbx
pop	rbp
pop	r12
pop	r13
pop	r14
pop	r15
ret
align 16
align 8
sn_LPC_inv_pred_gain_L6:
sub	esi, 1
mov	edi, 1073741824
test	esi, esi
jle	sn_LPC_inv_pred_gain_L4
movsx	rax, esi
lea	rbx, [rsp+24]
mov	r14d, esi
mov	edi, 1073741824
lea	r11, [rbx+rax*4]
mov	r15, -2147483648
mov	r13d, 2147483648
mov	r12d, 4294967295
mov	rsi, r11
sn_LPC_inv_pred_gain_L10:
mov	r9d, dword [rsi]
lea	eax, [r9+16773022]
cmp	eax, 33546044
ja	sn_LPC_inv_pred_gain_L8
shl	r9d, 7
mov	eax, 1073741824
neg	r9d
movsx	r9, r9d
mov	rdx, r9
imul	rdx, r9
sar	rdx, 32
sub	eax, edx
movsx	rdx, edi
movsx	rcx, eax
imul	rdx, rcx
sar	rdx, 32
lea	edi, [0+rdx*4+0]
cmp	edi, 107373
jle	sn_LPC_inv_pred_gain_L8
bsr	r8d, eax
xor	edx, edx
xor	r8d, 31
lea	ecx, [r8+-1]
shl	eax, cl
movsx	rcx, eax
mov	eax, 536870911
mov	r10d, ecx
sar	r10d, 16
idiv	r10d
movsx	rdx, ax
mov	ebp, eax
cdqe
imul	rcx, rdx
mov	edx, 536870912
shl	ebp, 16
sar	rcx, 16
sub	edx, ecx
shl	edx, 3
movsx	rdx, edx
imul	rdx, rax
lea	eax, [r14+1]
sub	r14d, 1
sar	eax, 1
sar	rdx, 16
add	ebp, edx
test	eax, eax
jle	sn_LPC_inv_pred_gain_L16
cdqe
mov	ecx, 31
mov	dword [rsp+8], r14d
movsx	rbp, ebp
lea	rax, [rbx+rax*4]
sub	ecx, r8d
mov	dword [rsp+12], edi
mov	r8, rbx
mov	qword [rsp], rax
mov	r10d, r14d
mov	qword [rsp+16], rsi
jmp	sn_LPC_inv_pred_gain_L15
align 16
align 8
sn_LPC_inv_pred_gain_L27:
add	esi, -2147483648
movsx	rdx, edx
test	esi, eax
cmovs	rdx, r15
sn_LPC_inv_pred_gain_L12:
imul	rdx, rbp
sar	rdx, cl
add	rdx, 1
sar	rdx, 1
lea	rsi, [rdx+r13]
cmp	r12, rsi
jb	sn_LPC_inv_pred_gain_L8
imul	rax, r9
mov	dword [r8], edx
mov	edx, edi
sar	rax, 30
add	rax, 1
sar	rax, 1
sub	edx, eax
js	sn_LPC_inv_pred_gain_L13
add	eax, -2147483648
movsx	rdx, edx
test	eax, edi
cmovs	rdx, r15
sn_LPC_inv_pred_gain_L14:
imul	rdx, rbp
sar	rdx, cl
add	rdx, 1
sar	rdx, 1
lea	rax, [rdx+r13]
cmp	r12, rax
jb	sn_LPC_inv_pred_gain_L8
mov	rax, qword [rsp]
add	r8, 4
mov	dword [r11], edx
sub	r10d, 1
cmp	r8, rax
je	sn_LPC_inv_pred_gain_L26
sn_LPC_inv_pred_gain_L15:
movsx	rdx, r10d
movsx	rax, dword [r8]
lea	r11, [rbx+rdx*4]
movsx	rsi, dword [r11]
mov	edx, eax
mov	rdi, rsi
imul	rsi, r9
sar	rsi, 30
add	rsi, 1
sar	rsi, 1
sub	edx, esi
jns	sn_LPC_inv_pred_gain_L27
lea	r14d, [rax+-2147483648]
movsx	rdx, edx
test	r14d, esi
mov	esi, 2147483647
cmovs	rdx, rsi
jmp	sn_LPC_inv_pred_gain_L12
align 16
align 8
sn_LPC_inv_pred_gain_L13:
add	edi, -2147483648
movsx	rdx, edx
test	edi, eax
mov	eax, 2147483647
cmovs	rdx, rax
jmp	sn_LPC_inv_pred_gain_L14
align 16
align 8
sn_LPC_inv_pred_gain_L26:
mov	r14d, dword [rsp+8]
mov	edi, dword [rsp+12]
mov	rsi, qword [rsp+16]
sn_LPC_inv_pred_gain_L16:
sub	rsi, 4
test	r14d, r14d
jne	sn_LPC_inv_pred_gain_L10
mov	esi, r14d
sn_LPC_inv_pred_gain_L4:
movsx	rsi, esi
mov	eax, dword [rsp+rsi*4+24]
add	eax, 16773022
cmp	eax, 33546044
ja	sn_LPC_inv_pred_gain_L8
mov	eax, dword [rsp+24]
movsx	rdi, edi
shl	eax, 7
neg	eax
cdqe
imul	rax, rax
sar	rax, 32
mov	rdx, rax
mov	eax, 1073741824
sub	eax, edx
cdqe
imul	rax, rdi
sar	rax, 32
shl	eax, 2
cmp	eax, 107373
jg	sn_LPC_inv_pred_gain_L1
jmp	sn_LPC_inv_pred_gain_L8

; ===== table_LSF_cos.c =====
section .text
section .rodata
align 32
sn_silk_LSFCosTab_FIX_Q12:
dw 8192
dw 8190
dw 8182
dw 8170
dw 8152
dw 8130
dw 8104
dw 8072
dw 8034
dw 7994
dw 7946
dw 7896
dw 7840
dw 7778
dw 7714
dw 7644
dw 7568
dw 7490
dw 7406
dw 7318
dw 7226
dw 7128
dw 7026
dw 6922
dw 6812
dw 6698
dw 6580
dw 6458
dw 6332
dw 6204
dw 6070
dw 5934
dw 5792
dw 5648
dw 5502
dw 5352
dw 5198
dw 5040
dw 4880
dw 4718
dw 4552
dw 4382
dw 4212
dw 4038
dw 3862
dw 3684
dw 3502
dw 3320
dw 3136
dw 2948
dw 2760
dw 2570
dw 2378
dw 2186
dw 1990
dw 1794
dw 1598
dw 1400
dw 1202
dw 1002
dw 802
dw 602
dw 402
dw 202
dw 0
dw -202
dw -402
dw -602
dw -802
dw -1002
dw -1202
dw -1400
dw -1598
dw -1794
dw -1990
dw -2186
dw -2378
dw -2570
dw -2760
dw -2948
dw -3136
dw -3320
dw -3502
dw -3684
dw -3862
dw -4038
dw -4212
dw -4382
dw -4552
dw -4718
dw -4880
dw -5040
dw -5198
dw -5352
dw -5502
dw -5648
dw -5792
dw -5934
dw -6070
dw -6204
dw -6332
dw -6458
dw -6580
dw -6698
dw -6812
dw -6922
dw -7026
dw -7128
dw -7226
dw -7318
dw -7406
dw -7490
dw -7568
dw -7644
dw -7714
dw -7778
dw -7840
dw -7896
dw -7946
dw -7994
dw -8034
dw -8072
dw -8104
dw -8130
dw -8152
dw -8170
dw -8182
dw -8190
dw -8192

; ===== NLSF2A.c =====
section .text
align 16
sn_silk_NLSF2A:
push	r15
mov	r8, rsi
push	r14
push	r13
push	r12
mov	r12d, edx
push	rbp
push	rbx
mov	rbx, rdi
mov	edi, edx
sar	edi, 1
sub	rsp, 328
cmp	edx, 16
je	sn_NLSF2A_L25
lea	r9, [rel sn_NLSF2A_ordering10_0]
test	edx, edx
jle	sn_NLSF2A_L45
sn_NLSF2A_L2:
xor	ecx, ecx
lea	rsi, [rel sn_silk_LSFCosTab_FIX_Q12]
align 16
align 8
sn_NLSF2A_L4:
movsx	r10d, word [r8+rcx*2]
movzx	edx, byte [r9+rcx]
add	rcx, 1
mov	eax, r10d
sar	ax, 8
movsx	ebp, ax
movsx	rax, ax
movsx	r11d, word [rsi+rax*2]
lea	eax, [rbp+1]
shl	ebp, 8
cdqe
sub	r10d, ebp
movsx	eax, word [rsi+rax*2]
sub	eax, r11d
shl	r11d, 8
imul	eax, r10d
add	eax, r11d
sar	eax, 3
add	eax, 1
sar	eax, 1
mov	dword [rsp+rdx*4+128], eax
cmp	r12d, ecx
jg	sn_NLSF2A_L4
mov	edx, dword [rsp+128]
mov	dword [rsp+24], 65536
neg	edx
mov	dword [rsp+28], edx
cmp	edi, 1
jle	sn_NLSF2A_L7
mov	eax, edi
lea	rbp, [rsp+28]
mov	r14, -1
mov	edx, edi
mov	qword [rsp], rax
mov	r13d, 1
mov	r9, rbx
align 16
align 8
sn_NLSF2A_L9:
lea	ecx, [r13+r13]
movsx	rsi, dword [rbp+0]
mov	r8d, dword [rbp+-4]
movsx	r11, dword [rsp+rcx*4+128]
mov	rcx, rsi
lea	edi, [r8+r8]
imul	rsi, r11
mov	r15, r11
sar	rsi, 15
add	rsi, 1
sar	rsi, 1
sub	edi, esi
mov	dword [rbp+4], edi
cmp	r13, 1
je	sn_NLSF2A_L12
mov	esi, r14d
mov	dword [rsp+8], r11d
lea	r10, [rbp+-4]
mov	rbx, r14
shl	rsi, 2
mov	rdi, rbp
sub	rbx, r13
sub	r10, rsi
align 16
align 8
sn_NLSF2A_L11:
movsx	rax, r8d
mov	r8d, dword [rdi+rbx*4]
sub	rdi, 4
mov	r15, rax
imul	rax, r11
mov	esi, r8d
sar	rax, 15
add	rax, 1
sar	rax, 1
sub	esi, eax
add	esi, ecx
mov	ecx, r15d
mov	dword [rdi+4], esi
cmp	r10, rdi
jne	sn_NLSF2A_L11
mov	r15d, dword [rsp+8]
sn_NLSF2A_L12:
sub	dword [rsp+28], r15d
add	r13, 1
add	rbp, 4
add	r14, 1
cmp	qword [rsp], r13
jne	sn_NLSF2A_L9
mov	edi, edx
mov	dword [rsp+12], r12d
lea	r8, [rsp+80]
mov	edx, dword [rsp+132]
mov	dword [rsp+76], 65536
mov	r14, -1
mov	r13d, 1
lea	rcx, [rsp+128]
neg	edx
mov	dword [rsp+80], edx
mov	rdx, r9
align 16
align 8
sn_NLSF2A_L15:
movsx	rbp, dword [rcx+r13*8+4]
movsx	r9, dword [r8]
mov	r10d, dword [r8+-4]
mov	rsi, r9
imul	r9, rbp
mov	r15, rbp
lea	r11d, [r10+r10]
sar	r9, 15
add	r9, 1
sar	r9, 1
sub	r11d, r9d
mov	dword [r8+4], r11d
cmp	r13, 1
je	sn_NLSF2A_L17
mov	r9d, r14d
mov	dword [rsp+8], ebp
lea	rbx, [r8+-4]
mov	r12, r14
shl	r9, 2
sub	r12, r13
sub	rbx, r9
mov	r9, r8
align 16
align 8
sn_NLSF2A_L16:
movsx	rax, r10d
mov	r10d, dword [r9+r12*4]
sub	r9, 4
mov	r15, rax
imul	rax, rbp
mov	r11d, r10d
sar	rax, 15
add	rax, 1
sar	rax, 1
sub	r11d, eax
add	r11d, esi
mov	esi, r15d
mov	dword [r9+4], r11d
cmp	rbx, r9
jne	sn_NLSF2A_L16
mov	r15d, dword [rsp+8]
sn_NLSF2A_L17:
sub	dword [rsp+80], r15d
add	r13, 1
add	r8, 4
add	r14, 1
cmp	qword [rsp], r13
jne	sn_NLSF2A_L15
mov	r12d, dword [rsp+12]
mov	rbx, rdx
sn_NLSF2A_L13:
lea	eax, [rdi+1]
mov	ecx, dword [rsp+76]
mov	r8d, dword [rsp+24]
lea	r14, [rsp+224]
movsx	r9, eax
lea	r11, [rsp+24]
mov	eax, 1
lea	r10, [rsp+76]
align 16
align 8
sn_NLSF2A_L19:
mov	ebp, ecx
mov	edx, r8d
mov	ecx, dword [r10+rax*4]
mov	r8d, dword [r11+rax*4]
mov	esi, ebp
add	edx, r8d
sub	esi, ecx
mov	edi, ecx
sub	esi, edx
sub	edi, ebp
mov	dword [r14+rax*4+-4], esi
mov	esi, r12d
sub	edi, edx
sub	esi, eax
add	rax, 1
movsx	rsi, esi
mov	dword [rsp+rsi*4+224], edi
cmp	rax, r9
jne	sn_NLSF2A_L19
sn_NLSF2A_L6:
mov	rsi, r14
mov	rdi, rbx
mov	r8d, r12d
mov	ecx, 17
mov	edx, 12
xor	ebp, ebp
mov	r13d, 2
call	sn_silk_LPC_fit
mov	esi, r12d
mov	rdi, rbx
call	sn_silk_LPC_inverse_pred_gain_c
cmp	ebp, 16
je	sn_NLSF2A_L1
align 16
align 8
sn_NLSF2A_L46:
test	eax, eax
jne	sn_NLSF2A_L1
mov	ecx, ebp
mov	eax, r13d
mov	edx, 65536
mov	esi, r12d
shl	eax, cl
mov	rdi, r14
sub	edx, eax
call	sn_silk_bwexpander_32
movsx	rcx, r12d
xor	edx, edx
test	r12d, r12d
jle	sn_NLSF2A_L22
align 16
align 8
sn_NLSF2A_L21:
mov	eax, dword [r14+rdx*4]
sar	eax, 4
add	eax, 1
sar	eax, 1
mov	word [rbx+rdx*2], ax
add	rdx, 1
cmp	rdx, rcx
jne	sn_NLSF2A_L21
sn_NLSF2A_L22:
add	ebp, 1
mov	esi, r12d
mov	rdi, rbx
call	sn_silk_LPC_inverse_pred_gain_c
cmp	ebp, 16
jne	sn_NLSF2A_L46
sn_NLSF2A_L1:
add	rsp, 328
pop	rbx
pop	rbp
pop	r12
pop	r13
pop	r14
pop	r15
ret
sn_NLSF2A_L25:
lea	r9, [rel sn_NLSF2A_ordering16_1]
jmp	sn_NLSF2A_L2
sn_NLSF2A_L45:
mov	eax, dword [rsp+128]
mov	dword [rsp+24], 65536
lea	r14, [rsp+224]
mov	dword [rsp+76], 65536
neg	eax
mov	dword [rsp+28], eax
mov	eax, dword [rsp+132]
neg	eax
mov	dword [rsp+80], eax
jmp	sn_NLSF2A_L6
sn_NLSF2A_L7:
mov	edx, dword [rsp+132]
mov	dword [rsp+76], 65536
neg	edx
mov	dword [rsp+80], edx
cmp	edi, 1
je	sn_NLSF2A_L13
lea	r14, [rsp+224]
jmp	sn_NLSF2A_L6
section .rodata
align 8
sn_NLSF2A_ordering10_0:
db 0
db 9,6,3,4,5,8,1,2,7
align 16
sn_NLSF2A_ordering16_1:
db 0
db 15,8,7,4,11,12,3,2,13,10,5,6,9,14,1

; ===== NLSF_stabilize.c =====
section .text
align 16
sn_silk_NLSF_stabilize:
push	r15
movsx	rdx, edx
mov	r9d, 20
mov	r15d, 32768
push	r14
lea	r10d, [rdx+-1]
lea	r14, [rsi+rdx*2]
push	r13
movsx	r8, r10d
lea	rax, [r14+-2]
mov	r13, rdx
push	r12
lea	r12, [rdi+r8*2]
push	rbp
mov	rbp, rsi
push	rbx
mov	rbx, rdi
sub	rsp, 56
mov	qword [rsp+32], rax
mov	qword [rsp+40], r8
align 16
align 8
sn_NLSF_stabilize_L22:
movsx	esi, word [rbx]
movsx	eax, word [rbp+0]
xor	r11d, r11d
mov	r8d, esi
mov	edi, eax
sub	r8d, eax
test	r10d, r10d
jle	sn_NLSF_stabilize_L2
mov	word [rsp+8], ax
mov	edx, 1
jmp	sn_NLSF_stabilize_L4
align 16
align 8
sn_NLSF_stabilize_L49:
movsx	esi, word [rbx+rcx*2]
sn_NLSF_stabilize_L4:
movsx	rcx, edx
movsx	eax, word [rbx+rcx*2]
movsx	edi, word [rbp+rcx*2+0]
sub	eax, edi
sub	eax, esi
cmp	eax, r8d
jge	sn_NLSF_stabilize_L3
mov	r8d, eax
mov	r11d, edx
sn_NLSF_stabilize_L3:
add	edx, 1
cmp	edx, r10d
jle	sn_NLSF_stabilize_L49
movzx	edi, word [rsp+8]
sn_NLSF_stabilize_L2:
movsx	ecx, word [r14]
mov	eax, r15d
sub	eax, ecx
mov	edx, ecx
movsx	ecx, word [r12]
sub	eax, ecx
cmp	eax, r8d
jge	sn_NLSF_stabilize_L5
test	eax, eax
jns	sn_NLSF_stabilize_L1
test	r13d, r13d
je	sn_NLSF_stabilize_L7
sn_NLSF_stabilize_L8:
mov	eax, -32768
sub	eax, edx
mov	word [r12], ax
sn_NLSF_stabilize_L10:
sub	r9d, 1
jne	sn_NLSF_stabilize_L22
mov	r8, qword [rsp+40]
mov	esi, r13d
mov	rdi, rbx
mov	qword [rsp+8], r8
call	sn_silk_insertion_sort_increasing_all_values_int16
movsx	eax, word [rbx]
movsx	edx, word [rbp+0]
mov	r8, qword [rsp+8]
cmp	edx, eax
cmovl	edx, eax
cmp	r13d, 1
mov	word [rbx], dx
mov	eax, edx
jle	sn_NLSF_stabilize_L23
mov	esi, r13d
mov	ecx, 1
mov	edi, -32768
align 16
align 8
sn_NLSF_stabilize_L25:
movsx	r9d, word [rbp+rcx*2+0]
movsx	r10d, ax
mov	edx, r9d
add	r9d, r10d
mov	r10d, 32767
cmp	r9d, 32767
jg	sn_NLSF_stabilize_L24
add	edx, eax
cmp	r9d, -32769
movsx	edx, dx
cmovle	edx, edi
mov	r10d, edx
sn_NLSF_stabilize_L24:
movsx	edx, word [rbx+rcx*2]
cmp	edx, r10d
cmovl	edx, r10d
mov	word [rbx+rcx*2], dx
add	rcx, 1
mov	eax, edx
cmp	rsi, rcx
jne	sn_NLSF_stabilize_L25
movsx	eax, word [r14]
mov	edx, 32768
sub	edx, eax
movsx	eax, word [r12]
cmp	edx, eax
cmovg	edx, eax
mov	word [r12], dx
movsx	eax, dx
lea	edx, [r13+-2]
sn_NLSF_stabilize_L30:
movsx	esi, word [rbp+r8*2+0]
movsx	rcx, edx
lea	rcx, [rbx+rcx*2]
sub	eax, esi
movsx	esi, word [rcx]
cmp	eax, esi
cmovg	eax, esi
mov	word [rcx], ax
lea	eax, [r13+-3]
cmp	r13d, 2
je	sn_NLSF_stabilize_L1
cdqe
lea	rcx, [rbx+rax*2]
align 16
align 8
sn_NLSF_stabilize_L28:
mov	esi, edx
movsx	eax, word [rbx+rsi*2]
movsx	esi, word [rbp+rsi*2+0]
sub	eax, esi
movsx	esi, word [rcx]
cmp	eax, esi
cmovg	eax, esi
sub	rcx, 2
mov	word [rcx+2], ax
sub	edx, 1
jne	sn_NLSF_stabilize_L28
sn_NLSF_stabilize_L1:
add	rsp, 56
pop	rbx
pop	rbp
pop	r12
pop	r13
pop	r14
pop	r15
ret
align 16
align 8
sn_NLSF_stabilize_L5:
test	r8d, r8d
jns	sn_NLSF_stabilize_L1
test	r11d, r11d
je	sn_NLSF_stabilize_L7
cmp	r13d, r11d
je	sn_NLSF_stabilize_L8
xor	eax, eax
movsx	rdi, r11d
test	r11d, r11d
jle	sn_NLSF_stabilize_L12
movsx	rdi, r11d
mov	rdx, rbp
xor	eax, eax
lea	rsi, [rbp+rdi*2+0]
align 16
align 8
sn_NLSF_stabilize_L13:
movsx	ecx, word [rdx]
add	rdx, 2
add	eax, ecx
cmp	rsi, rdx
jne	sn_NLSF_stabilize_L13
sn_NLSF_stabilize_L12:
add	rdi, rdi
lea	rcx, [rbp+rdi+0]
movzx	esi, word [rcx]
sar	si, 1
movsx	r8d, si
mov	word [rsp+30], si
add	eax, r8d
mov	dword [rsp+8], eax
cmp	r13d, r11d
jle	sn_NLSF_stabilize_L33
mov	eax, r10d
mov	rsi, qword [rsp+32]
mov	qword [rsp+16], r12
mov	edx, 32768
sub	eax, r11d
add	rax, rax
sub	rsi, rax
mov	rax, r14
align 16
align 8
sn_NLSF_stabilize_L15:
movsx	r12d, word [rax]
sub	rax, 2
sub	edx, r12d
cmp	rax, rsi
jne	sn_NLSF_stabilize_L15
mov	r12, qword [rsp+16]
sn_NLSF_stabilize_L14:
sub	r11d, 1
sub	edx, r8d
add	rdi, rbx
movsx	r11, r11d
mov	dword [rsp+16], edx
lea	rsi, [rbx+r11*2]
movsx	r11d, word [rdi]
movsx	edx, word [rsi]
mov	eax, edx
add	edx, r11d
add	eax, r11d
sar	edx, 1
mov	r11d, dword [rsp+16]
mov	r8d, eax
and	eax, 1
and	r8d, 1
add	eax, edx
cmp	dword [rsp+8], r11d
jle	sn_NLSF_stabilize_L16
mov	r11d, dword [rsp+8]
cmp	r11d, eax
jge	sn_NLSF_stabilize_L17
sn_NLSF_stabilize_L47:
mov	edx, r11d
sn_NLSF_stabilize_L18:
sub	dx, word [rsp+30]
mov	word [rsi], dx
add	dx, word [rcx]
mov	word [rdi], dx
jmp	sn_NLSF_stabilize_L10
align 16
align 8
sn_NLSF_stabilize_L7:
mov	word [rbx], di
jmp	sn_NLSF_stabilize_L10
align 16
align 8
sn_NLSF_stabilize_L16:
mov	r11d, dword [rsp+16]
cmp	r11d, eax
jl	sn_NLSF_stabilize_L47
mov	r11d, dword [rsp+8]
add	edx, r8d
cmp	r11d, eax
cmovg	edx, r11d
jmp	sn_NLSF_stabilize_L18
sn_NLSF_stabilize_L17:
add	r8d, edx
mov	edx, dword [rsp+16]
cmp	edx, eax
cmovle	edx, r8d
jmp	sn_NLSF_stabilize_L18
sn_NLSF_stabilize_L33:
mov	edx, 32768
jmp	sn_NLSF_stabilize_L14
sn_NLSF_stabilize_L23:
movsx	eax, word [r14]
mov	edx, 32768
mov	edi, r13d
sub	edx, eax
movsx	eax, word [r12]
cmp	edx, eax
cmovg	edx, eax
sub	edi, 2
mov	word [r12], dx
movsx	eax, dx
js	sn_NLSF_stabilize_L1
mov	edx, 2147483647
jmp	sn_NLSF_stabilize_L30

; ===== NLSF_VQ_weights_laroia.c =====
section .text
align 16
sn_silk_NLSF_VQ_weights_laroia:
push	rbp
mov	r11, rdi
mov	r9, rsi
push	rbx
movsx	ecx, word [rsi]
mov	ebx, edx
mov	edx, 1
movsx	eax, word [rsi+2]
sub	eax, ecx
test	eax, eax
mov	edi, eax
mov	eax, 131072
cmovle	edi, edx
xor	edx, edx
idiv	edi
test	ecx, ecx
mov	esi, eax
mov	eax, 1
cmovle	ecx, eax
xor	edx, edx
mov	eax, 131072
idiv	ecx
mov	edx, 32767
add	eax, esi
cmp	eax, edx
cmovg	eax, edx
sub	ebx, 1
mov	word [r11], ax
cmp	ebx, 1
jle	sn_NLSF_VQ_weights_laroia_L2
mov	r8d, 1
align 16
align 8
sn_NLSF_VQ_weights_laroia_L3:
lea	r10d, [r8+1]
movsx	eax, word [r9+r8*2]
lea	rbp, [r9+r10*2]
movsx	ecx, word [rbp+0]
sub	ecx, eax
mov	eax, 1
test	ecx, ecx
cmovle	ecx, eax
xor	edx, edx
mov	eax, 131072
idiv	ecx
mov	edx, 32767
mov	edi, eax
lea	eax, [rax+rsi]
cmp	eax, edx
cmovg	eax, edx
mov	word [r11+r8*2], ax
lea	eax, [r8+2]
movsx	ecx, word [r9+rax*2]
movsx	eax, word [rbp+0]
sub	ecx, eax
mov	eax, 1
test	ecx, ecx
cmovle	ecx, eax
xor	edx, edx
mov	eax, 131072
idiv	ecx
mov	edx, 32767
mov	esi, eax
lea	eax, [rdi+rax]
cmp	eax, edx
cmovg	eax, edx
add	r8, 2
mov	word [r11+r10*2], ax
cmp	ebx, r8d
jg	sn_NLSF_VQ_weights_laroia_L3
sn_NLSF_VQ_weights_laroia_L2:
movsx	rbx, ebx
mov	ecx, 32768
xor	edx, edx
movsx	eax, word [r9+rbx*2]
sub	ecx, eax
mov	eax, 131072
idiv	ecx
mov	edx, 32767
add	eax, esi
cmp	eax, edx
cmovg	eax, edx
mov	word [r11+rbx*2], ax
pop	rbx
pop	rbp
ret

; ===== pitch_est_tables.c =====
section .text
section .rodata
sn_silk_nb_cbk_searchs_stage3:
db 16,24,34
align 16
sn_silk_Lag_range_stage3:
db 251,8
db 255,6
db 255,6
db 252,10
db 250,10
db 254,6
db 255,6
db 251,10
db 247,12
db 253,7
db 254,7
db 249,13
align 32
sn_silk_CB_lags_stage3:
db 0
db 0
db 1,255,0
db 1,255,0
db 255,1,254,2,254,254,2,253,2,3,253,252,3,252,4
db 4,251,5,250,251,6,249,6,5,8,247
db 0
db 0
db 1,0
db 0
db 0
db 0
db 0
db 0
db 0
db 255,1,0
db 0
db 1,255,0
db 1,255,255,1,255,2,1,255,2,254,254,2,254,2,2
db 3,253
db 0
db 1,0
db 0
db 0
db 0
db 0
db 0
db 1,0
db 1,0
db 0
db 1,255,1,0
db 0
db 2,1,255,2,255,255,2,255,2,2,255,3,254,254,254
db 3
db 0
db 1,0
db 0
db 1,0
db 1,255,2,255,2,255,2,3,254,3,254,254,4,4,253
db 5,253,252,6,252,6,5,251,8,250,251,249,9
align 32
sn_silk_CB_lags_stage2:
db 0
db 2,255,255,255,0
db 0
db 1,1,0
db 1
db 0
db 1,0
db 0
db 0
db 0
db 0
db 1,0
db 0
db 0
db 0
db 0
db 1,0
db 0
db 0
db 1,0
db 0
db 0
db 0
db 0
db 255,2,1,0
db 1,1,0
db 0
db 255,255
sn_silk_Lag_range_stage3_10_ms:
db 253,7
db 254,7
align 16
sn_silk_CB_lags_stage3_10_ms:
db 0
db 0
db 1,255,1,255,2,254,2,254,3,253
db 0
db 1,0
db 1,255,2,255,2,254,3,254,3
sn_silk_CB_lags_stage2_10_ms:
db 0
db 1,0
db 0
db 0
db 1

; ===== resampler.c =====
section .text
align 16
sn_silk_resampler_init:
push	r13
mov	r13d, ecx
push	r12
mov	r12, rdi
push	rbp
mov	ebp, edx
mov	edx, 304
push	rbx
mov	ebx, esi
xor	esi, esi
sub	rsp, 8
call	sn_set
cmp	ebx, 8000
setne	al
cmp	ebx, 12000
setne	dl
and	eax, edx
test	r13d, r13d
je	sn_resampler_L2
test	al, al
jne	sn_resampler_L54
sn_resampler_L3:
cmp	ebp, 8000
setne	dl
cmp	ebp, 12000
setne	al
test	dl, al
je	sn_resampler_L24
cmp	ebp, 16000
jne	sn_resampler_L5
sn_resampler_L24:
mov	edx, ebp
mov	eax, ebx
xor	ecx, ecx
sar	edx, 12
sar	eax, 12
sub	edx, 1
cmp	ebx, 16000
setg	cl
movsx	rdx, edx
sub	eax, ecx
cmp	ebx, 24000
setg	cl
sar	eax, cl
sub	eax, 1
cdqe
lea	rcx, [rax+rax*2]
lea	rax, [rel sn_delay_matrix_enc]
add	rax, rcx
movsx	eax, byte [rax+rdx]
sn_resampler_L7:
mov	dword [r12+292], eax
movsx	rax, ebx
mov	edx, ebx
movsx	rsi, ebp
imul	rax, rax, 274877907
sar	edx, 31
mov	ecx, ebp
sar	ecx, 31
sar	rax, 38
sub	eax, edx
imul	rdx, rsi, 274877907
mov	dword [r12+284], eax
lea	eax, [rax+rax*4]
add	eax, eax
sar	rdx, 38
mov	dword [r12+268], eax
sub	edx, ecx
mov	dword [r12+288], edx
cmp	ebx, ebp
jge	sn_resampler_L11
lea	eax, [rbx+rbx]
cmp	eax, ebp
je	sn_resampler_L55
mov	ecx, 15
mov	edi, 1
mov	dword [r12+264], 2
sn_resampler_L14:
mov	eax, ebx
shl	eax, cl
mov	ecx, edi
cdq
shl	ebx, cl
idiv	ebp
shl	eax, 2
movsx	rcx, eax
lea	edx, [rax+1]
imul	rcx, rsi
sar	rcx, 16
cmp	ebx, ecx
jle	sn_resampler_L56
align 16
align 8
sn_resampler_L23:
movsx	rax, edx
add	edx, 1
mov	rcx, rax
imul	rax, rsi
sar	rax, 16
cmp	ebx, eax
jg	sn_resampler_L23
mov	dword [r12+272], ecx
sn_resampler_L22:
xor	eax, eax
sn_resampler_L1:
add	rsp, 8
pop	rbx
pop	rbp
pop	r12
pop	r13
ret
align 16
align 8
sn_resampler_L2:
cmp	ebx, 16000
je	sn_resampler_L25
test	al, al
jne	sn_resampler_L5
sn_resampler_L25:
cmp	ebp, 8000
je	sn_resampler_L9
cmp	ebp, 12000
je	sn_resampler_L9
cmp	ebp, 16000
setne	dl
cmp	ebp, 24000
setne	al
test	dl, al
je	sn_resampler_L9
cmp	ebp, 48000
jne	sn_resampler_L5
sn_resampler_L9:
mov	eax, ebp
xor	edx, edx
sar	eax, 12
cmp	ebp, 16000
setg	dl
sub	eax, edx
cmp	ebp, 24000
mov	edx, ebx
setg	cl
sar	edx, 12
sub	edx, 1
sar	eax, cl
movsx	rdx, edx
sub	eax, 1
lea	rcx, [rdx+rdx*4]
lea	rdx, [rel sn_delay_matrix_dec]
cdqe
add	rdx, rcx
movsx	eax, byte [rdx+rax]
jmp	sn_resampler_L7
align 16
align 8
sn_resampler_L54:
cmp	ebx, 16000
setne	dl
cmp	ebx, 24000
setne	al
test	dl, al
je	sn_resampler_L3
cmp	ebx, 48000
je	sn_resampler_L3
sn_resampler_L5:
mov	eax, -1
jmp	sn_resampler_L1
align 16
align 8
sn_resampler_L11:
jle	sn_resampler_L15
lea	eax, [rbx+rbx]
lea	edx, [0+rbp*4+0]
mov	dword [r12+264], 3
lea	ecx, [rax+rbx]
cmp	edx, ecx
je	sn_resampler_L57
lea	edi, [rbp+rbp]
lea	ecx, [rdi+rbp]
cmp	ecx, eax
je	sn_resampler_L58
cmp	edi, ebx
je	sn_resampler_L59
cmp	ecx, ebx
je	sn_resampler_L60
cmp	edx, ebx
je	sn_resampler_L61
add	ecx, ecx
cmp	ecx, ebx
jne	sn_resampler_L5
mov	rax, 4294967332
mov	qword [r12+276], rax
lea	rax, [rel sn_silk_Resampler_1_6_COEFS]
mov	qword [r12+296], rax
jmp	sn_resampler_L13
align 16
align 8
sn_resampler_L15:
mov	dword [r12+264], 0
sn_resampler_L13:
mov	ecx, 14
xor	edi, edi
jmp	sn_resampler_L14
sn_resampler_L57:
mov	rax, 12884901906
mov	qword [r12+276], rax
lea	rax, [rel sn_silk_Resampler_3_4_COEFS]
mov	qword [r12+296], rax
jmp	sn_resampler_L13
align 16
align 8
sn_resampler_L55:
mov	dword [r12+264], 1
jmp	sn_resampler_L13
align 16
align 8
sn_resampler_L56:
mov	dword [r12+272], eax
jmp	sn_resampler_L22
sn_resampler_L58:
mov	rax, 8589934610
mov	qword [r12+276], rax
lea	rax, [rel sn_silk_Resampler_2_3_COEFS]
mov	qword [r12+296], rax
jmp	sn_resampler_L13
sn_resampler_L60:
mov	rax, 4294967332
mov	qword [r12+276], rax
lea	rax, [rel sn_silk_Resampler_1_3_COEFS]
mov	qword [r12+296], rax
jmp	sn_resampler_L13
sn_resampler_L59:
mov	rax, 4294967320
mov	qword [r12+276], rax
lea	rax, [rel sn_silk_Resampler_1_2_COEFS]
mov	qword [r12+296], rax
jmp	sn_resampler_L13
sn_resampler_L61:
mov	rax, 4294967332
mov	qword [r12+276], rax
lea	rax, [rel sn_silk_Resampler_1_4_COEFS]
mov	qword [r12+296], rax
jmp	sn_resampler_L13
align 16
sn_silk_resampler:
push	r15
push	r14
mov	r14, rsi
push	r13
mov	r13, rdx
push	r12
mov	rsi, r13
mov	r12d, ecx
push	rbp
push	rbx
mov	rbx, rdi
sub	rsp, 8
movsx	rax, dword [rdi+292]
mov	ebp, dword [rdi+284]
sub	ebp, eax
lea	rdi, [rdi+rax*2+168]
movsx	rbp, ebp
add	rbp, rbp
mov	rdx, rbp
add	rbp, r13
call	sn_copy
mov	eax, dword [rbx+264]
cmp	eax, 2
je	sn_resampler_L63
cmp	eax, 3
je	sn_resampler_L64
cmp	eax, 1
jne	sn_resampler_L65
mov	ecx, dword [rbx+284]
lea	r15, [rbx+168]
mov	rsi, r14
mov	rdi, rbx
mov	rdx, r15
call	sn_silk_resampler_private_up2_HQ_wrapper
mov	ecx, r12d
mov	rdx, rbp
mov	rdi, rbx
movsx	rax, dword [rbx+288]
sub	ecx, dword [rbx+284]
lea	rsi, [r14+rax*2]
call	sn_silk_resampler_private_up2_HQ_wrapper
sn_resampler_L66:
movsx	rdx, dword [rbx+292]
mov	rdi, r15
mov	rax, rdx
add	rdx, rdx
sub	r12d, eax
movsx	r12, r12d
lea	rsi, [r13+r12*2+0]
call	sn_copy
add	rsp, 8
xor	eax, eax
pop	rbx
pop	rbp
pop	r12
pop	r13
pop	r14
pop	r15
ret
align 16
align 8
sn_resampler_L64:
mov	ecx, dword [rbx+284]
lea	r15, [rbx+168]
mov	rsi, r14
mov	rdi, rbx
mov	rdx, r15
call	sn_silk_resampler_private_down_FIR
mov	ecx, r12d
mov	rdx, rbp
mov	rdi, rbx
movsx	rax, dword [rbx+288]
sub	ecx, dword [rbx+284]
lea	rsi, [r14+rax*2]
call	sn_silk_resampler_private_down_FIR
jmp	sn_resampler_L66
align 16
align 8
sn_resampler_L63:
mov	ecx, dword [rbx+284]
lea	r15, [rbx+168]
mov	rsi, r14
mov	rdi, rbx
mov	rdx, r15
call	sn_silk_resampler_private_IIR_FIR
mov	ecx, r12d
mov	rdx, rbp
mov	rdi, rbx
movsx	rax, dword [rbx+288]
sub	ecx, dword [rbx+284]
lea	rsi, [r14+rax*2]
call	sn_silk_resampler_private_IIR_FIR
jmp	sn_resampler_L66
align 16
align 8
sn_resampler_L65:
movsx	rdx, dword [rbx+284]
lea	r15, [rbx+168]
mov	rdi, r14
mov	rsi, r15
add	rdx, rdx
call	sn_copy
movsx	rax, dword [rbx+288]
mov	edx, r12d
mov	rsi, rbp
sub	edx, dword [rbx+284]
movsx	rdx, edx
lea	rdi, [r14+rax*2]
add	rdx, rdx
call	sn_copy
jmp	sn_resampler_L66
section .rodata
align 8
sn_delay_matrix_dec:
db 4,0
db 2,0
db 0
db 0
db 9,4,7,4
db 0
db 3,12,7,7
align 8
sn_delay_matrix_enc:
db 6,0
db 3
db 0
db 7,3
db 0
db 1,10
db 0
db 2,6
db 18,10,12

; ===== resampler_private_AR2.c =====
section .text
align 16
sn_silk_resampler_private_AR2:
test	r8d, r8d
jle	sn_resampler_private_AR2_L7
mov	r10, rdx
mov	edx, dword [rdi]
push	rbx
mov	r9, rsi
movsx	rbx, word [rcx]
movsx	r11, word [rcx+2]
movsx	rsi, r8d
xor	ecx, ecx
align 16
align 8
sn_resampler_private_AR2_L3:
movsx	eax, word [r10+rcx*2]
shl	eax, 8
add	eax, edx
mov	dword [r9+rcx*4], eax
shl	eax, 2
add	rcx, 1
cdqe
mov	rdx, rax
imul	rax, r11
imul	rdx, rbx
sar	rax, 16
sar	rdx, 16
add	edx, dword [rdi+4]
mov	dword [rdi+4], eax
cmp	rsi, rcx
jne	sn_resampler_private_AR2_L3
mov	dword [rdi], edx
pop	rbx
ret
align 16
align 8
sn_resampler_private_AR2_L7:
ret

; ===== resampler_private_down_FIR.c =====
section .text
align 16
sn_silk_resampler_private_down_FIR:
push	rbp
mov	rbp, rsp
push	r15
mov	r15, rdi
push	r14
push	r13
push	r12
mov	r12, rsi
push	rbx
sub	rsp, 72
mov	qword [rbp+-64], rdx
mov	eax, dword [rdi+268]
movsx	rdx, dword [rdi+276]
mov	dword [rbp+-52], ecx
mov	rsi, rsp
add	eax, edx
cdqe
lea	rax, [0+rax*4+15]
mov	rcx, rax
and	rax, -4096
sub	rsi, rax
and	rcx, -16
cmp	rsp, rsi
je	sn_resampler_private_down_FIR_L3
sn_resampler_private_down_FIR_L37:
sub	rsp, 4096
or	qword [rsp+4088], 0
cmp	rsp, rsi
jne	sn_resampler_private_down_FIR_L37
sn_resampler_private_down_FIR_L3:
and	ecx, 4095
sub	rsp, rcx
test	rcx, rcx
jne	sn_resampler_private_down_FIR_L38
sn_resampler_private_down_FIR_L4:
mov	r13, rsp
lea	rsi, [r15+24]
shl	rdx, 2
mov	rdi, r13
mov	qword [rbp+-104], rsi
call	sn_copy
mov	rbx, qword [r15+296]
mov	r14d, dword [r15+272]
lea	rax, [rbx+4]
mov	rcx, rbx
mov	qword [rbp+-96], rax
align 16
align 8
sn_resampler_private_down_FIR_L16:
mov	esi, dword [rbp+-52]
mov	eax, dword [r15+268]
mov	rdi, r15
mov	rdx, qword [rbp+-64]
cmp	esi, eax
cmovle	eax, esi
mov	r11d, eax
movsx	rax, dword [r15+276]
mov	r8d, r11d
mov	dword [rbp+-72], r11d
lea	rsi, [r13+rax*4+0]
call	sn_silk_resampler_private_AR2
mov	r11d, dword [rbp+-72]
movsx	rdi, dword [r15+276]
mov	r10d, dword [r15+280]
mov	r9d, r11d
shl	r9d, 16
cmp	edi, 24
je	sn_resampler_private_down_FIR_L5
cmp	edi, 36
je	sn_resampler_private_down_FIR_L6
cmp	edi, 18
jne	sn_resampler_private_down_FIR_L8
test	r9d, r9d
jle	sn_resampler_private_down_FIR_L8
mov	dword [rbp+-56], edi
lea	eax, [r10+-1]
xor	r8d, r8d
movsx	r10, r10w
mov	qword [rbp+-88], r15
mov	dword [rbp+-76], r11d
mov	r11, qword [rbp+-96]
mov	qword [rbp+-72], rbx
mov	ebx, eax
align 16
align 8
sn_resampler_private_down_FIR_L12:
movzx	esi, r8w
mov	eax, r8d
imul	rsi, r10
sar	eax, 16
cdqe
lea	rax, [r13+rax*4+0]
sar	rsi, 16
movsx	r15, dword [rax+4]
lea	edx, [rsi+rsi*8]
movsx	rdx, edx
lea	rcx, [r11+rdx*2]
movsx	rdx, dword [rax]
movsx	rdi, word [rcx]
imul	rdi, rdx
movsx	rdx, word [rcx+2]
imul	rdx, r15
movsx	r15, dword [rax+8]
sar	rdi, 16
sar	rdx, 16
add	edx, edi
movsx	rdi, word [rcx+4]
imul	rdi, r15
movsx	r15, dword [rax+12]
sar	rdi, 16
add	edi, edx
movsx	rdx, word [rcx+6]
imul	rdx, r15
movsx	r15, dword [rax+16]
sar	rdx, 16
add	edx, edi
movsx	rdi, word [rcx+8]
imul	rdi, r15
movsx	r15, dword [rax+20]
sar	rdi, 16
add	edi, edx
movsx	rdx, word [rcx+10]
imul	rdx, r15
movsx	r15, dword [rax+24]
sar	rdx, 16
add	edx, edi
movsx	rdi, word [rcx+12]
imul	rdi, r15
movsx	r15, dword [rax+28]
sar	rdi, 16
add	edi, edx
movsx	rdx, word [rcx+14]
movsx	rcx, word [rcx+16]
imul	rdx, r15
sar	rdx, 16
add	edx, edi
movsx	rdi, dword [rax+32]
imul	rcx, rdi
movsx	rdi, dword [rax+68]
sar	rcx, 16
add	edx, ecx
mov	ecx, ebx
sub	ecx, esi
lea	ecx, [rcx+rcx*8]
movsx	rcx, ecx
lea	rcx, [r11+rcx*2]
movsx	rsi, word [rcx]
imul	rsi, rdi
movsx	rdi, dword [rax+64]
sar	rsi, 16
add	esi, edx
movsx	rdx, word [rcx+2]
imul	rdx, rdi
movsx	rdi, dword [rax+60]
sar	rdx, 16
add	edx, esi
movsx	rsi, word [rcx+4]
imul	rsi, rdi
movsx	rdi, dword [rax+56]
sar	rsi, 16
add	esi, edx
movsx	rdx, word [rcx+6]
imul	rdx, rdi
movsx	rdi, dword [rax+52]
sar	rdx, 16
add	edx, esi
movsx	rsi, word [rcx+8]
imul	rsi, rdi
movsx	rdi, dword [rax+48]
sar	rsi, 16
add	esi, edx
movsx	rdx, word [rcx+10]
imul	rdx, rdi
movsx	rdi, dword [rax+44]
sar	rdx, 16
add	edx, esi
movsx	rsi, word [rcx+12]
imul	rsi, rdi
sar	rsi, 16
add	esi, edx
movsx	rdx, word [rcx+14]
movsx	rdi, dword [rax+40]
movsx	rcx, word [rcx+16]
movsx	rax, dword [rax+36]
imul	rdx, rdi
imul	rcx, rax
mov	eax, 32767
sar	rdx, 16
sar	rcx, 16
add	edx, esi
add	edx, ecx
sar	edx, 5
add	edx, 1
mov	ecx, edx
sar	ecx, 1
cmp	edx, 65535
jg	sn_resampler_private_down_FIR_L11
cmp	ecx, -32768
mov	eax, -32768
cmovge	eax, ecx
sn_resampler_private_down_FIR_L11:
add	r8d, r14d
add	r12, 2
mov	word [r12+-2], ax
cmp	r9d, r8d
jg	sn_resampler_private_down_FIR_L12
mov	rbx, qword [rbp+-72]
movsx	rdi, dword [rbp+-56]
mov	r11d, dword [rbp+-76]
mov	r15, qword [rbp+-88]
sn_resampler_private_down_FIR_L8:
mov	rsi, qword [rbp+-64]
movsx	rax, r11d
sub	dword [rbp+-52], r11d
lea	rdx, [0+rdi*4+0]
mov	ecx, dword [rbp+-52]
lea	rsi, [rsi+rax*2]
mov	qword [rbp+-64], rsi
lea	rsi, [r13+rax*4+0]
cmp	ecx, 1
jle	sn_resampler_private_down_FIR_L15
mov	rdi, r13
call	sn_copy
mov	rcx, qword [r15+296]
jmp	sn_resampler_private_down_FIR_L16
align 16
align 8
sn_resampler_private_down_FIR_L6:
xor	esi, esi
test	r9d, r9d
jle	sn_resampler_private_down_FIR_L8
align 16
align 8
sn_resampler_private_down_FIR_L9:
mov	eax, esi
movsx	rcx, word [rbx+4]
movsx	r8, word [rbx+6]
sar	eax, 16
cdqe
lea	rdx, [r13+rax*4+0]
mov	eax, dword [rdx]
add	eax, dword [rdx+140]
cdqe
imul	rax, rcx
mov	ecx, dword [rdx+4]
add	ecx, dword [rdx+136]
movsx	rcx, ecx
imul	rcx, r8
movsx	r8, word [rbx+8]
sar	rax, 16
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+8]
add	ecx, dword [rdx+132]
movsx	rcx, ecx
imul	rcx, r8
movsx	r8, word [rbx+10]
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+12]
add	ecx, dword [rdx+128]
movsx	rcx, ecx
imul	rcx, r8
movsx	r8, word [rbx+12]
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+16]
add	ecx, dword [rdx+124]
movsx	rcx, ecx
imul	rcx, r8
movsx	r8, word [rbx+14]
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+20]
add	ecx, dword [rdx+120]
movsx	rcx, ecx
imul	rcx, r8
movsx	r8, word [rbx+16]
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+24]
add	ecx, dword [rdx+116]
movsx	rcx, ecx
imul	rcx, r8
movsx	r8, word [rbx+18]
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+28]
add	ecx, dword [rdx+112]
movsx	rcx, ecx
imul	rcx, r8
movsx	r8, word [rbx+20]
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+32]
add	ecx, dword [rdx+108]
movsx	rcx, ecx
imul	rcx, r8
movsx	r8, word [rbx+22]
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+36]
add	ecx, dword [rdx+104]
movsx	rcx, ecx
imul	rcx, r8
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+40]
add	ecx, dword [rdx+100]
movsx	r8, word [rbx+24]
movsx	rcx, ecx
imul	rcx, r8
movsx	r8, word [rbx+26]
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+44]
add	ecx, dword [rdx+96]
movsx	rcx, ecx
imul	rcx, r8
movsx	r8, word [rbx+28]
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+48]
add	ecx, dword [rdx+92]
movsx	rcx, ecx
imul	rcx, r8
movsx	r8, word [rbx+30]
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+52]
add	ecx, dword [rdx+88]
movsx	rcx, ecx
imul	rcx, r8
movsx	r8, word [rbx+32]
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+56]
add	ecx, dword [rdx+84]
movsx	rcx, ecx
imul	rcx, r8
movsx	r8, word [rbx+34]
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+60]
add	ecx, dword [rdx+80]
movsx	rcx, ecx
imul	rcx, r8
movsx	r8, word [rbx+36]
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+64]
add	ecx, dword [rdx+76]
movsx	rcx, ecx
imul	rcx, r8
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+68]
add	ecx, dword [rdx+72]
movsx	rdx, ecx
movsx	rcx, word [rbx+38]
imul	rdx, rcx
sar	rdx, 16
add	eax, edx
mov	edx, 32767
sar	eax, 5
add	eax, 1
mov	ecx, eax
sar	ecx, 1
cmp	eax, 65535
jg	sn_resampler_private_down_FIR_L14
cmp	ecx, -32768
mov	edx, -32768
cmovge	edx, ecx
sn_resampler_private_down_FIR_L14:
add	esi, r14d
add	r12, 2
mov	word [r12+-2], dx
cmp	r9d, esi
jg	sn_resampler_private_down_FIR_L9
jmp	sn_resampler_private_down_FIR_L8
align 16
align 8
sn_resampler_private_down_FIR_L5:
xor	esi, esi
test	r9d, r9d
jle	sn_resampler_private_down_FIR_L8
align 16
align 8
sn_resampler_private_down_FIR_L10:
mov	eax, esi
movsx	rcx, word [rbx+4]
movsx	r8, word [rbx+6]
sar	eax, 16
cdqe
lea	rdx, [r13+rax*4+0]
mov	eax, dword [rdx]
add	eax, dword [rdx+92]
cdqe
imul	rax, rcx
mov	ecx, dword [rdx+4]
add	ecx, dword [rdx+88]
movsx	rcx, ecx
imul	rcx, r8
movsx	r8, word [rbx+8]
sar	rax, 16
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+8]
add	ecx, dword [rdx+84]
movsx	rcx, ecx
imul	rcx, r8
movsx	r8, word [rbx+10]
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+12]
add	ecx, dword [rdx+80]
movsx	rcx, ecx
imul	rcx, r8
movsx	r8, word [rbx+12]
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+16]
add	ecx, dword [rdx+76]
movsx	rcx, ecx
imul	rcx, r8
movsx	r8, word [rbx+14]
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+20]
add	ecx, dword [rdx+72]
movsx	rcx, ecx
imul	rcx, r8
movsx	r8, word [rbx+16]
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+24]
add	ecx, dword [rdx+68]
movsx	rcx, ecx
imul	rcx, r8
movsx	r8, word [rbx+18]
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+28]
add	ecx, dword [rdx+64]
movsx	rcx, ecx
imul	rcx, r8
movsx	r8, word [rbx+20]
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+32]
add	ecx, dword [rdx+60]
movsx	rcx, ecx
imul	rcx, r8
movsx	r8, word [rbx+22]
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+36]
add	ecx, dword [rdx+56]
movsx	rcx, ecx
imul	rcx, r8
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+40]
add	ecx, dword [rdx+52]
movsx	r8, word [rbx+24]
movsx	rcx, ecx
imul	rcx, r8
sar	rcx, 16
add	eax, ecx
mov	ecx, dword [rdx+44]
add	ecx, dword [rdx+48]
movsx	rdx, ecx
movsx	rcx, word [rbx+26]
imul	rdx, rcx
sar	rdx, 16
add	eax, edx
mov	edx, 32767
sar	eax, 5
add	eax, 1
mov	ecx, eax
sar	ecx, 1
cmp	eax, 65535
jg	sn_resampler_private_down_FIR_L13
cmp	ecx, -32768
mov	edx, -32768
cmovge	edx, ecx
sn_resampler_private_down_FIR_L13:
add	esi, r14d
add	r12, 2
mov	word [r12+-2], dx
cmp	r9d, esi
jg	sn_resampler_private_down_FIR_L10
jmp	sn_resampler_private_down_FIR_L8
align 16
align 8
sn_resampler_private_down_FIR_L15:
mov	rdi, qword [rbp+-104]
call	sn_copy
lea	rsp, [rbp+-40]
pop	rbx
pop	r12
pop	r13
pop	r14
pop	r15
pop	rbp
ret
sn_resampler_private_down_FIR_L38:
or	qword [rsp+rcx+-8], 0
jmp	sn_resampler_private_down_FIR_L4

; ===== resampler_private_IIR_FIR.c =====
section .text
align 16
sn_silk_resampler_private_IIR_FIR:
push	rbp
mov	r8d, ecx
mov	r11, rdi
mov	rbp, rsp
push	r15
push	r14
push	r13
push	r12
mov	r12, rsi
push	rbx
sub	rsp, 56
mov	eax, dword [rdi+268]
mov	qword [rbp+-56], rdx
mov	rcx, rsp
lea	eax, [rax+rax+8]
cdqe
lea	rax, [rax+rax+15]
mov	rdx, rax
and	rax, -4096
sub	rcx, rax
and	rdx, -16
cmp	rsp, rcx
je	sn_resampler_private_IIR_FIR_L3
sn_resampler_private_IIR_FIR_L18:
sub	rsp, 4096
or	qword [rsp+4088], 0
cmp	rsp, rcx
jne	sn_resampler_private_IIR_FIR_L18
sn_resampler_private_IIR_FIR_L3:
and	edx, 4095
sub	rsp, rdx
test	rdx, rdx
jne	sn_resampler_private_IIR_FIR_L19
sn_resampler_private_IIR_FIR_L4:
lea	rax, [r11+24]
mov	r13, rsp
mov	edx, 16
mov	qword [rbp+-64], r11
mov	rsi, rax
mov	rdi, r13
mov	dword [rbp+-92], r8d
lea	rbx, [rel sn_silk_resampler_frac_FIR_12]
mov	qword [rbp+-88], rax
call	sn_copy
mov	r11, qword [rbp+-64]
lea	rax, [r13+16]
mov	r15d, dword [rbp+-92]
mov	qword [rbp+-72], rax
mov	qword [rbp+-80], r11
mov	r14d, dword [r11+272]
align 16
align 8
sn_resampler_private_IIR_FIR_L9:
mov	rdi, qword [rbp+-80]
mov	rdx, qword [rbp+-56]
mov	rsi, qword [rbp+-72]
mov	r8d, dword [rdi+268]
cmp	r15d, r8d
mov	ecx, r8d
cmovle	ecx, r15d
mov	dword [rbp+-64], ecx
call	sn_silk_resampler_private_up2_HQ
mov	ecx, dword [rbp+-64]
mov	r10d, ecx
shl	r10d, 17
test	r10d, r10d
jle	sn_resampler_private_IIR_FIR_L5
xor	edi, edi
mov	r8d, -32768
align 16
align 8
sn_resampler_private_IIR_FIR_L7:
movzx	eax, di
lea	rdx, [rax+rax*2]
mov	eax, edi
sar	eax, 16
mov	r9, rdx
cdqe
shr	r9, 14
lea	rax, [r13+rax*2+0]
movsx	ecx, word [rbx+r9*8]
movsx	esi, word [rax]
movsx	r11d, word [rax+2]
movsx	edx, word [rax+6]
imul	ecx, esi
movsx	esi, word [rbx+r9*8+2]
imul	esi, r11d
movsx	r11d, word [rax+4]
add	esi, ecx
movsx	ecx, word [rbx+r9*8+4]
imul	ecx, r11d
add	ecx, esi
movsx	esi, word [rbx+r9*8+6]
imul	esi, edx
mov	edx, 11
sub	edx, r9d
movsx	r9d, word [rax+8]
movsx	rdx, edx
add	esi, ecx
movsx	ecx, word [rbx+rdx*8+6]
imul	ecx, r9d
movsx	r9d, word [rax+10]
add	ecx, esi
movsx	esi, word [rbx+rdx*8+4]
imul	esi, r9d
movsx	r9d, word [rax+12]
movsx	eax, word [rax+14]
add	esi, ecx
movsx	ecx, word [rbx+rdx*8+2]
movsx	edx, word [rbx+rdx*8]
imul	ecx, r9d
imul	eax, edx
mov	edx, 32767
add	ecx, esi
add	eax, ecx
sar	eax, 14
add	eax, 1
mov	ecx, eax
sar	ecx, 1
cmp	eax, 65535
jg	sn_resampler_private_IIR_FIR_L6
cmp	ecx, -32768
mov	edx, ecx
cmovl	edx, r8d
sn_resampler_private_IIR_FIR_L6:
add	edi, r14d
add	r12, 2
mov	word [r12+-2], dx
cmp	r10d, edi
jg	sn_resampler_private_IIR_FIR_L7
mov	ecx, dword [rbp+-64]
sn_resampler_private_IIR_FIR_L5:
mov	rdi, qword [rbp+-56]
movsx	rax, ecx
lea	r8d, [rcx+rcx]
sub	r15d, ecx
movsx	r8, r8d
mov	edx, 16
lea	rax, [rdi+rax*2]
lea	rsi, [r13+r8*2+0]
mov	qword [rbp+-56], rax
test	r15d, r15d
jle	sn_resampler_private_IIR_FIR_L8
mov	rdi, r13
call	sn_copy
jmp	sn_resampler_private_IIR_FIR_L9
align 16
align 8
sn_resampler_private_IIR_FIR_L8:
mov	rdi, qword [rbp+-88]
call	sn_copy
lea	rsp, [rbp+-40]
pop	rbx
pop	r12
pop	r13
pop	r14
pop	r15
pop	rbp
ret
sn_resampler_private_IIR_FIR_L19:
or	qword [rsp+rdx+-8], 0
jmp	sn_resampler_private_IIR_FIR_L4

; ===== resampler_private_up2_HQ.c =====
section .text
align 16
sn_silk_resampler_private_up2_HQ:
test	ecx, ecx
jle	sn_resampler_private_up2_HQ_L12
push	r15
movsx	rcx, ecx
push	r14
lea	rax, [rdx+rcx*2]
xor	ecx, ecx
push	r13
mov	r15, rax
push	r12
push	rbp
mov	rbp, rsi
push	rbx
mov	rbx, rdi
sub	rsp, 8
mov	r11d, dword [rdi]
mov	r10d, dword [rdi+4]
mov	r9d, dword [rdi+8]
mov	r8d, dword [rdi+12]
mov	qword [rsp], rbx
mov	edi, dword [rdi+16]
mov	esi, dword [rbx+20]
align 16
align 8
sn_resampler_private_up2_HQ_L5:
movsx	ebx, word [rdx]
shl	ebx, 10
mov	eax, ebx
sub	eax, r11d
cdqe
imul	rax, rax, 1746
sar	rax, 16
lea	r12d, [r11+rax]
lea	r11d, [rbx+rax]
mov	eax, r12d
sub	eax, r10d
cdqe
imul	rax, rax, 14986
sar	rax, 16
lea	r13d, [r10+rax]
lea	r10d, [r12+rax]
mov	r12d, r13d
sub	r12d, r9d
movsx	rax, r12d
imul	rax, rax, -26453
sar	rax, 16
add	r12d, eax
lea	eax, [r12+r9]
lea	r9d, [r12+r13]
mov	r12d, 32767
sar	eax, 9
add	eax, 1
mov	r13d, eax
sar	r13d, 1
cmp	eax, 65535
jg	sn_resampler_private_up2_HQ_L3
cmp	r13d, -32768
mov	r12d, -32768
cmovge	r12d, r13d
sn_resampler_private_up2_HQ_L3:
movsx	rax, ecx
lea	r13, [rbp+rax*2+0]
mov	eax, ebx
sub	eax, r8d
mov	word [r13+0], r12w
cdqe
imul	rax, rax, 6854
sar	rax, 16
lea	r14d, [r8+rax]
lea	r8d, [rbx+rax]
mov	eax, r14d
sub	eax, edi
cdqe
imul	rax, rax, 25769
sar	rax, 16
lea	ebx, [rdi+rax]
lea	edi, [r14+rax]
mov	r14d, ebx
sub	r14d, esi
movsx	rax, r14d
imul	rax, rax, -9994
sar	rax, 16
add	eax, r14d
lea	r14d, [rax+rsi]
lea	esi, [rax+rbx]
sar	r14d, 9
lea	eax, [r14+1]
mov	r14d, 32767
mov	ebx, eax
sar	ebx, 1
cmp	eax, 65535
jg	sn_resampler_private_up2_HQ_L4
cmp	ebx, -32768
mov	r14d, -32768
cmovge	r14d, ebx
sn_resampler_private_up2_HQ_L4:
lea	eax, [rcx+1]
add	rdx, 2
add	ecx, 2
cdqe
lea	rax, [rbp+rax*2+0]
mov	word [rax], r14w
cmp	r15, rdx
jne	sn_resampler_private_up2_HQ_L5
mov	rbx, qword [rsp]
mov	dword [rbx], r11d
mov	dword [rbx+4], r10d
mov	dword [rbx+8], r9d
mov	word [r13+0], r12w
mov	dword [rbx+12], r8d
mov	dword [rbx+16], edi
mov	dword [rbx+20], esi
mov	word [rax], r14w
add	rsp, 8
pop	rbx
pop	rbp
pop	r12
pop	r13
pop	r14
pop	r15
ret
align 16
align 8
sn_resampler_private_up2_HQ_L12:
ret
align 16
sn_silk_resampler_private_up2_HQ_wrapper:
jmp	sn_silk_resampler_private_up2_HQ

; ===== resampler_rom.c =====
section .text
section .rodata
align 32
sn_silk_resampler_frac_FIR_12:
dw 189
dw -600
dw 617
dw 30567
dw 117
dw -159
dw -1070
dw 29704
dw 52
dw 221
dw -2392
dw 28276
dw -4
dw 529
dw -3350
dw 26341
dw -48
dw 758
dw -3956
dw 23973
dw -80
dw 905
dw -4235
dw 21254
dw -99
dw 972
dw -4222
dw 18278
dw -107
dw 967
dw -3957
dw 15143
dw -103
dw 896
dw -3487
dw 11950
dw -91
dw 773
dw -2865
dw 8798
dw -71
dw 611
dw -2143
dw 5784
dw -46
dw 425
dw -1375
dw 2996
align 8
sn_silk_Resampler_2_3_COEFS_LQ:
dw -2797
dw -6507
dw 4697
dw 10739
dw 1567
dw 8276
align 32
sn_silk_Resampler_1_6_COEFS:
dw 27540
dw -15257
dw 17
dw 12
dw 8
dw 1
dw -10
dw -22
dw -30
dw -32
dw -22
dw 3
dw 44
dw 100
dw 168
dw 243
dw 317
dw 381
dw 429
dw 455
align 32
sn_silk_Resampler_1_4_COEFS:
dw 22500
dw -15099
dw 3
dw -14
dw -20
dw -15
dw 2
dw 25
dw 37
dw 25
dw -16
dw -71
dw -107
dw -79
dw 50
dw 292
dw 623
dw 982
dw 1288
dw 1464
align 32
sn_silk_Resampler_1_3_COEFS:
dw 16102
dw -15162
dw -13
dw 0
dw 20
dw 26
dw 5
dw -31
dw -43
dw -4
dw 65
dw 90
dw 7
dw -157
dw -248
dw -44
dw 593
dw 1583
dw 2612
dw 3271
align 16
sn_silk_Resampler_1_2_COEFS:
dw 616
dw -14323
dw -10
dw 39
dw 58
dw -46
dw -84
dw 120
dw 184
dw -315
dw -541
dw 1284
dw 5380
dw 9024
align 32
sn_silk_Resampler_2_3_COEFS:
dw -14457
dw -14019
dw 64
dw 128
dw -122
dw 36
dw 310
dw -768
dw 584
dw 9267
dw 17733
dw 12
dw 128
dw 18
dw -142
dw 288
dw -117
dw -865
dw 4123
dw 14459
align 32
sn_silk_Resampler_3_4_COEFS:
dw -20694
dw -13867
dw -49
dw 64
dw 17
dw -157
dw 353
dw -496
dw 163
dw 11047
dw 22205
dw -39
dw 6
dw 91
dw -170
dw 186
dw 23
dw -896
dw 6336
dw 19928
dw -19
dw -36
dw 102
dw -89
dw -24
dw 328
dw -951
dw 2568
dw 15909

; ===== sort.c =====
section .text
align 16
sn_silk_insertion_sort_increasing:
push	r15
mov	rax, rdi
movsx	rdi, ecx
push	r14
push	r13
mov	r13d, edx
push	r12
push	rbp
push	rbx
mov	rbx, rdi
sub	rsp, 32
test	edi, edi
jle	sn_sort_L6
xor	edx, edx
test	dil, 1
je	sn_sort_L5
mov	edx, 1
mov	dword [rsi], 0
cmp	rdx, rdi
je	sn_sort_L33
align 16
align 8
sn_sort_L5:
mov	dword [rsi+rdx*4], edx
lea	rcx, [rdx+1]
add	rdx, 2
mov	dword [rsi+rcx*4], ecx
cmp	rdx, rdi
jne	sn_sort_L5
sn_sort_L33:
cmp	ebx, 1
je	sn_sort_L6
lea	ebp, [rbx+-1]
xor	r10d, r10d
align 16
align 8
sn_sort_L10:
mov	r9d, dword [rax+r10*4+4]
lea	r11d, [r10+1]
mov	rcx, r10
jmp	sn_sort_L7
align 16
align 8
sn_sort_L9:
mov	dword [r8], edi
mov	edi, dword [rsi+rcx*4]
sub	rcx, 1
mov	dword [rdx], edi
cmp	ecx, -1
je	sn_sort_L17
sn_sort_L7:
lea	edx, [rcx+1]
mov	edi, dword [rax+rcx*4]
movsx	rdx, edx
shl	rdx, 2
lea	r8, [rax+rdx]
add	rdx, rsi
cmp	edi, r9d
jg	sn_sort_L9
add	r10, 1
mov	dword [r8], r9d
mov	dword [rdx], r11d
cmp	r10, rbp
jne	sn_sort_L10
sn_sort_L6:
cmp	ebx, r13d
jge	sn_sort_L1
lea	edi, [rbx+-1]
lea	r15d, [rbx+-2]
movsx	rdx, edi
mov	dword [rsp+4], edi
lea	rdi, [0+rdx*4+0]
movsx	rdx, ebx
lea	rbp, [rax+rdx*4]
movsx	rdx, r15d
mov	qword [rsp+24], rdi
lea	r14, [rax+rdi]
shl	rdx, 2
lea	rdi, [rax+rdx]
mov	qword [rsp+16], rdi
lea	rdi, [rsi+rdx]
mov	qword [rsp+8], rdi
jmp	sn_sort_L16
align 16
align 8
sn_sort_L11:
add	ebx, 1
add	rbp, 4
cmp	r13d, ebx
je	sn_sort_L1
sn_sort_L16:
mov	r11d, dword [rbp+0]
cmp	dword [r14], r11d
jle	sn_sort_L11
mov	edi, dword [rsp+4]
mov	r8, qword [rsp+8]
mov	rcx, qword [rsp+16]
test	r15d, r15d
jns	sn_sort_L14
jmp	sn_sort_L39
align 16
align 8
sn_sort_L15:
mov	dword [r10], r9d
mov	r9d, dword [r8]
mov	r10, r8
sub	rcx, 4
sub	r8, 4
mov	dword [rdx], r9d
sub	edi, 1
je	sn_sort_L18
sn_sort_L14:
movsx	rdx, edi
mov	r9d, dword [rcx]
mov	r12, rcx
shl	rdx, 2
lea	r10, [rax+rdx]
add	rdx, rsi
cmp	r9d, r11d
jg	sn_sort_L15
mov	dword [r10], r11d
mov	dword [rdx], ebx
sn_sort_L40:
add	ebx, 1
add	rbp, 4
cmp	r13d, ebx
jne	sn_sort_L16
sn_sort_L1:
add	rsp, 32
pop	rbx
pop	rbp
pop	r12
pop	r13
pop	r14
pop	r15
ret
align 16
align 8
sn_sort_L17:
mov	rdx, rsi
mov	r8, rax
add	r10, 1
mov	dword [r8], r9d
mov	dword [rdx], r11d
cmp	r10, rbp
jne	sn_sort_L10
jmp	sn_sort_L6
align 16
align 8
sn_sort_L18:
mov	rdx, r10
mov	r10, r12
mov	dword [r10], r11d
mov	dword [rdx], ebx
jmp	sn_sort_L40
sn_sort_L39:
mov	rdi, qword [rsp+24]
mov	r10, r14
mov	dword [r10], r11d
lea	rdx, [rsi+rdi]
mov	dword [rdx], ebx
jmp	sn_sort_L40
align 16
sn_silk_insertion_sort_decreasing_int16:
push	r15
mov	rax, rdi
movsx	rdi, ecx
push	r14
mov	r8, rdi
push	r13
push	r12
mov	r12d, edx
push	rbp
push	rbx
sub	rsp, 32
test	edi, edi
jle	sn_sort_L46
xor	edx, edx
test	dil, 1
je	sn_sort_L45
mov	dword [rsi], 0
mov	edx, 1
cmp	rdi, 1
je	sn_sort_L73
align 16
align 8
sn_sort_L45:
mov	dword [rsi+rdx*4], edx
lea	rcx, [rdx+1]
add	rdx, 2
mov	dword [rsi+rcx*4], ecx
cmp	rdi, rdx
jne	sn_sort_L45
sn_sort_L73:
cmp	r8d, 1
je	sn_sort_L46
lea	ebp, [r8+-1]
xor	r11d, r11d
align 16
align 8
sn_sort_L50:
movzx	r10d, word [rax+r11*2+2]
lea	ebx, [r11+1]
mov	rdx, r11
jmp	sn_sort_L47
align 16
align 8
sn_sort_L49:
mov	word [r9], di
mov	edi, dword [rsi+rdx*4]
sub	rdx, 1
mov	dword [rcx], edi
cmp	edx, -1
je	sn_sort_L57
sn_sort_L47:
lea	ecx, [rdx+1]
movzx	edi, word [rax+rdx*2]
movsx	rcx, ecx
lea	r9, [rax+rcx*2]
lea	rcx, [rsi+rcx*4]
cmp	r10w, di
jg	sn_sort_L49
add	r11, 1
mov	word [r9], r10w
mov	dword [rcx], ebx
cmp	r11, rbp
jne	sn_sort_L50
sn_sort_L46:
cmp	r8d, r12d
jge	sn_sort_L41
lea	ebx, [r8+-1]
movsx	rdx, r8d
lea	r14d, [r8+-2]
mov	dword [rsp+4], ebx
movsx	rbx, ebx
mov	qword [rsp+24], rbx
lea	r13, [rax+rbx*2]
lea	rbx, [rax+rdx*2]
movsx	rdx, r14d
lea	rdi, [rax+rdx*2]
mov	qword [rsp+16], rdi
lea	rdi, [rsi+rdx*4]
mov	qword [rsp+8], rdi
jmp	sn_sort_L56
align 16
align 8
sn_sort_L51:
add	r8d, 1
add	rbx, 2
cmp	r12d, r8d
je	sn_sort_L41
sn_sort_L56:
movzx	ebp, word [rbx]
cmp	bp, word [r13+0]
jle	sn_sort_L51
mov	ecx, dword [rsp+4]
mov	rdi, qword [rsp+8]
mov	rdx, qword [rsp+16]
test	r14d, r14d
jns	sn_sort_L54
jmp	sn_sort_L78
align 16
align 8
sn_sort_L55:
mov	word [r11], r10w
mov	r10d, dword [rdi]
mov	r11, rdi
sub	rdx, 2
sub	rdi, 4
mov	dword [r9], r10d
sub	ecx, 1
je	sn_sort_L58
sn_sort_L54:
movzx	r10d, word [rdx]
movsx	r9, ecx
mov	r15, rdx
lea	r11, [rax+r9*2]
lea	r9, [rsi+r9*4]
cmp	bp, r10w
jg	sn_sort_L55
mov	word [r11], bp
mov	dword [r9], r8d
sn_sort_L79:
add	r8d, 1
add	rbx, 2
cmp	r12d, r8d
jne	sn_sort_L56
sn_sort_L41:
add	rsp, 32
pop	rbx
pop	rbp
pop	r12
pop	r13
pop	r14
pop	r15
ret
align 16
align 8
sn_sort_L57:
mov	rcx, rsi
mov	r9, rax
add	r11, 1
mov	word [r9], r10w
mov	dword [rcx], ebx
cmp	r11, rbp
jne	sn_sort_L50
jmp	sn_sort_L46
align 16
align 8
sn_sort_L58:
mov	r9, r11
mov	r11, r15
mov	word [r11], bp
mov	dword [r9], r8d
jmp	sn_sort_L79
sn_sort_L78:
mov	rdi, qword [rsp+24]
mov	r11, r13
mov	word [r11], bp
lea	r9, [rsi+rdi*4]
mov	dword [r9], r8d
jmp	sn_sort_L79
align 16
sn_silk_insertion_sort_increasing_all_values_int16:
lea	r9d, [rsi+-1]
xor	r8d, r8d
cmp	esi, 1
jle	sn_sort_L80
align 16
align 8
sn_sort_L85:
movzx	esi, word [rdi+r8*2+2]
mov	rax, r8
jmp	sn_sort_L82
align 16
align 8
sn_sort_L84:
sub	rax, 1
mov	word [rdx], cx
cmp	eax, -1
je	sn_sort_L87
sn_sort_L82:
lea	edx, [rax+1]
movzx	ecx, word [rdi+rax*2]
movsx	rdx, edx
lea	rdx, [rdi+rdx*2]
cmp	si, cx
jl	sn_sort_L84
add	r8, 1
mov	word [rdx], si
cmp	r9, r8
jne	sn_sort_L85
sn_sort_L80:
ret
align 16
align 8
sn_sort_L87:
mov	rdx, rdi
add	r8, 1
mov	word [rdx], si
cmp	r9, r8
jne	sn_sort_L85
ret

; ===== sum_sqr_shift.c =====
section .text
align 16
sn_silk_sum_sqr_shift:
push	rbp
mov	r8, rsi
push	rbx
test	ecx, ecx
je	sn_sum_sqr_shift_L13
bsr	ebx, ecx
mov	r10d, ecx
mov	ecx, 31
mov	rsi, rdx
xor	ebx, 31
lea	r9d, [r10+-1]
sub	ecx, ebx
test	r9d, r9d
jle	sn_sum_sqr_shift_L3
mov	r11d, r10d
xor	edx, edx
align 16
align 8
sn_sum_sqr_shift_L4:
movsx	rax, edx
movsx	eax, word [rsi+rax*2]
imul	eax, eax
mov	ebp, eax
lea	eax, [rdx+1]
add	edx, 2
cdqe
movsx	eax, word [rsi+rax*2]
imul	eax, eax
add	eax, ebp
shr	eax, cl
add	r11d, eax
cmp	r9d, edx
jg	sn_sum_sqr_shift_L4
mov	ebp, 34
sub	ebp, ebx
cmp	r10d, edx
jle	sn_sum_sqr_shift_L24
sn_sum_sqr_shift_L6:
movsx	rdx, edx
movsx	eax, word [rsi+rdx*2]
mov	edx, 32
imul	eax, eax
shr	eax, cl
add	eax, r11d
je	sn_sum_sqr_shift_L9
bsr	edx, eax
xor	edx, 31
sn_sum_sqr_shift_L9:
sub	ebp, edx
mov	ecx, 0
cmovns	ecx, ebp
test	r9d, r9d
je	sn_sum_sqr_shift_L16
sn_sum_sqr_shift_L11:
xor	ebx, ebx
xor	edx, edx
align 16
align 8
sn_sum_sqr_shift_L10:
movsx	rax, edx
movsx	eax, word [rsi+rax*2]
imul	eax, eax
mov	r11d, eax
lea	eax, [rdx+1]
add	edx, 2
cdqe
movsx	eax, word [rsi+rax*2]
imul	eax, eax
add	eax, r11d
shr	eax, cl
add	ebx, eax
cmp	r9d, edx
jg	sn_sum_sqr_shift_L10
sn_sum_sqr_shift_L7:
cmp	r10d, edx
jle	sn_sum_sqr_shift_L2
movsx	rdx, edx
movsx	eax, word [rsi+rdx*2]
imul	eax, eax
shr	eax, cl
add	ebx, eax
sn_sum_sqr_shift_L2:
mov	dword [r8], ecx
mov	dword [rdi], ebx
pop	rbx
pop	rbp
ret
align 16
align 8
sn_sum_sqr_shift_L13:
xor	ebx, ebx
xor	ecx, ecx
mov	dword [r8], ecx
mov	dword [rdi], ebx
pop	rbx
pop	rbp
ret
align 16
align 8
sn_sum_sqr_shift_L24:
test	r11d, r11d
je	sn_sum_sqr_shift_L12
bsr	r11d, r11d
mov	ecx, 0
xor	r11d, 31
sub	ebp, r11d
cmovns	ecx, ebp
jmp	sn_sum_sqr_shift_L11
sn_sum_sqr_shift_L12:
mov	ecx, 2
mov	eax, 0
sub	ecx, ebx
cmovs	ecx, eax
jmp	sn_sum_sqr_shift_L11
sn_sum_sqr_shift_L16:
xor	ebx, ebx
xor	edx, edx
jmp	sn_sum_sqr_shift_L7
sn_sum_sqr_shift_L3:
cmp	r10d, 1
jne	sn_sum_sqr_shift_L25
mov	r11d, 1
mov	ebp, 3
xor	edx, edx
jmp	sn_sum_sqr_shift_L6
sn_sum_sqr_shift_L25:
mov	ecx, 34
xor	ebx, ebx
xor	edx, edx
jmp	sn_sum_sqr_shift_L7

; ===== LPC_fit.c =====
section .text
align 16
sn_silk_LPC_fit:
push	r15
sub	ecx, edx
xor	r15d, r15d
push	r14
mov	r14d, ecx
push	r13
movsx	r13, r8d
push	r12
mov	r12, rsi
push	rbp
mov	rbp, r13
push	rbx
xor	ebx, ebx
sub	rsp, 24
mov	qword [rsp+8], rdi
align 16
align 8
sn_LPC_fit_L2:
test	ebp, ebp
jle	sn_LPC_fit_L36
xor	eax, eax
xor	esi, esi
align 16
align 8
sn_LPC_fit_L4:
mov	ecx, dword [r12+rax*4]
mov	edx, ecx
neg	edx
cmovs	edx, ecx
cmp	esi, edx
cmovl	ebx, eax
cmovl	esi, edx
add	rax, 1
cmp	r13, rax
jne	sn_LPC_fit_L4
cmp	r14d, 1
je	sn_LPC_fit_L37
lea	ecx, [r14+-1]
sar	esi, cl
add	esi, 1
sar	esi, 1
sn_LPC_fit_L9:
cmp	esi, 32767
jle	sn_LPC_fit_L7
mov	eax, 163838
lea	ecx, [rbx+1]
mov	rdi, r12
cmp	esi, eax
cmovg	esi, eax
add	r15d, 1
imul	ecx, esi
lea	eax, [rsi+-32767]
mov	esi, ebp
shl	eax, 14
cdq
sar	ecx, 2
idiv	ecx
mov	edx, 65470
sub	edx, eax
call	sn_silk_bwexpander_32
cmp	r15d, 10
jne	sn_LPC_fit_L2
xor	edx, edx
lea	edi, [r14+-1]
mov	r9d, -32768
mov	r8d, -32768
jmp	sn_LPC_fit_L19
align 16
align 8
sn_LPC_fit_L13:
mov	ecx, edi
sar	eax, cl
add	eax, 1
mov	ecx, eax
sar	ecx, 1
cmp	eax, 65535
jg	sn_LPC_fit_L33
cmp	ecx, -32769
mov	esi, r9d
mov	eax, ecx
cmovg	esi, ecx
cmovle	eax, r8d
sn_LPC_fit_L15:
mov	rbx, qword [rsp+8]
mov	ecx, r14d
shl	esi, cl
mov	word [rbx+rdx*2], ax
mov	dword [r12+rdx*4], esi
add	rdx, 1
cmp	rdx, r13
je	sn_LPC_fit_L1
sn_LPC_fit_L19:
mov	eax, dword [r12+rdx*4]
cmp	r14d, 1
jne	sn_LPC_fit_L13
mov	esi, eax
and	eax, 1
sar	esi, 1
lea	ecx, [rax+rsi]
cmp	ecx, 32767
jg	sn_LPC_fit_L33
cmp	ecx, -32768
jge	sn_LPC_fit_L17
mov	esi, -32768
mov	eax, -32768
jmp	sn_LPC_fit_L15
align 16
align 8
sn_LPC_fit_L37:
mov	eax, esi
and	esi, 1
sar	eax, 1
add	esi, eax
jmp	sn_LPC_fit_L9
align 16
align 8
sn_LPC_fit_L36:
cmp	r14d, 1
je	sn_LPC_fit_L1
sn_LPC_fit_L7:
test	ebp, ebp
jle	sn_LPC_fit_L1
mov	eax, dword [r12]
movsx	r8, ebp
xor	edx, edx
lea	ecx, [r14+-1]
cmp	r14d, 1
jne	sn_LPC_fit_L20
jmp	sn_LPC_fit_L21
align 16
align 8
sn_LPC_fit_L38:
mov	eax, dword [r12+rdx*4]
sn_LPC_fit_L20:
sar	eax, cl
mov	rdi, qword [rsp+8]
add	eax, 1
sar	eax, 1
mov	word [rdi+rdx*2], ax
add	rdx, 1
cmp	rdx, r8
jne	sn_LPC_fit_L38
sn_LPC_fit_L1:
add	rsp, 24
pop	rbx
pop	rbp
pop	r12
pop	r13
pop	r14
pop	r15
ret
align 16
align 8
sn_LPC_fit_L39:
mov	eax, dword [r12+rdx*4]
sn_LPC_fit_L21:
mov	ecx, eax
mov	rdi, qword [rsp+8]
sar	eax, 1
and	ecx, 1
add	eax, ecx
mov	word [rdi+rdx*2], ax
add	rdx, 1
cmp	rdx, r8
jne	sn_LPC_fit_L39
add	rsp, 24
pop	rbx
pop	rbp
pop	r12
pop	r13
pop	r14
pop	r15
ret
align 16
align 8
sn_LPC_fit_L33:
mov	esi, 32767
mov	eax, 32767
jmp	sn_LPC_fit_L15
sn_LPC_fit_L17:
add	eax, esi
movsx	esi, ax
jmp	sn_LPC_fit_L15

; ===== dec_API.c =====
section .text
align 16
sn_silk_LoadOSCEModels:
xor	eax, eax
ret
align 16
sn_silk_Get_Decoder_Size:
mov	dword [rdi], 8616
xor	eax, eax
ret
align 16
sn_silk_ResetDecoder:
push	rbp
push	rbx
mov	rbx, rdi
sub	rsp, 8
call	sn_silk_reset_decoder
lea	rdi, [rbx+4296]
call	sn_silk_reset_decoder
lea	rdi, [rbx+8592]
mov	edx, 12
xor	esi, esi
mov	ebp, eax
call	sn_set
mov	eax, ebp
mov	dword [rbx+8612], 0
add	rsp, 8
pop	rbx
pop	rbp
ret
align 16
sn_silk_InitDecoder:
push	rbp
push	rbx
mov	rbx, rdi
sub	rsp, 8
call	sn_silk_init_decoder
lea	rdi, [rbx+4296]
call	sn_silk_init_decoder
lea	rdi, [rbx+8592]
mov	edx, 12
xor	esi, esi
mov	ebp, eax
call	sn_set
mov	eax, ebp
mov	dword [rbx+8612], 0
add	rsp, 8
pop	rbx
pop	rbp
ret
align 16
sn_silk_Decode:
push	rbp
mov	rbp, rsp
push	r15
push	r14
push	r13
mov	r13, rdi
push	r12
mov	r12, rsi
push	rbx
sub	rsp, 760
mov	dword [rbp+-724], edx
mov	eax, dword [rsi+4]
mov	qword [rbp+-736], r8
mov	qword [rbp+-744], r9
mov	dword [rbp+-720], 0
mov	qword [rbp+-712], 0
test	ecx, ecx
je	sn_dec_API_L12
test	eax, eax
jle	sn_dec_API_L10
movsx	rcx, eax
lea	rdx, [rdi+2400]
imul	rcx, rcx, 4296
lea	rcx, [rdi+rcx+2400]
mov	rsi, rcx
sub	rsi, rdx
and	esi, 8
je	sn_dec_API_L11
mov	dword [rdx], 0
lea	rdx, [rdi+6696]
cmp	rcx, rdx
je	sn_dec_API_L12
align 16
align 8
sn_dec_API_L11:
mov	dword [rdx], 0
add	rdx, 8592
mov	dword [rdx+-4296], 0
cmp	rcx, rdx
jne	sn_dec_API_L11
sn_dec_API_L12:
xor	ebx, ebx
cmp	dword [r13+8608], eax
jl	sn_dec_API_L120
sn_dec_API_L13:
cmp	eax, 1
je	sn_dec_API_L227
mov	edi, dword [r13+2400]
mov	dword [rbp+-728], edi
test	edi, edi
je	sn_dec_API_L228
sn_dec_API_L123:
mov	dword [rbp+-728], 0
sn_dec_API_L223:
mov	eax, dword [r12+4]
sn_dec_API_L17:
mov	edx, eax
sn_dec_API_L18:
mov	esi, dword [r12]
mov	r8d, esi
cmp	esi, 2
je	sn_dec_API_L229
sn_dec_API_L27:
mov	edi, dword [r12+8]
mov	dword [r13+8604], esi
mov	dword [r13+8608], eax
lea	r9d, [rdi+-8000]
mov	ecx, edi
cmp	r9d, 40000
ja	sn_dec_API_L29
cmp	dword [rbp+-724], 1
je	sn_dec_API_L30
mov	r14d, dword [r13+2400]
test	r14d, r14d
jne	sn_dec_API_L31
test	eax, eax
jle	sn_dec_API_L32
mov	qword [rbp+-760], r13
xor	eax, eax
mov	r15, qword [rbp+-736]
mov	dword [rbp+-752], ebx
mov	r14d, eax
mov	rbx, r13
align 16
align 8
sn_dec_API_L33:
mov	r11d, dword [rbx+2404]
xor	r13d, r13d
test	r11d, r11d
jle	sn_dec_API_L36
sn_dec_API_L34:
mov	esi, 1
mov	rdi, r15
call	sn_ec_dec_bit_logp
mov	dword [rbx+r13*4+2416], eax
add	r13, 1
cmp	dword [rbx+2404], r13d
jg	sn_dec_API_L34
sn_dec_API_L36:
mov	esi, 1
mov	rdi, r15
add	r14d, 1
add	rbx, 4296
call	sn_ec_dec_bit_logp
mov	dword [rbx+-1868], eax
mov	edx, dword [r12+4]
mov	eax, edx
cmp	edx, r14d
jg	sn_dec_API_L33
mov	ebx, dword [rbp+-752]
mov	r13, qword [rbp+-760]
test	edx, edx
jle	sn_dec_API_L37
lea	r15, [r13+2432]
xor	r14d, r14d
jmp	sn_dec_API_L44
align 16
align 8
sn_dec_API_L231:
mov	dword [r15], 1
sn_dec_API_L39:
mov	edx, dword [r12+4]
add	r14d, 1
add	r15, 4296
mov	eax, edx
cmp	edx, r14d
jle	sn_dec_API_L230
sn_dec_API_L44:
mov	edx, 12
xor	esi, esi
mov	rdi, r15
call	sn_set
mov	r10d, dword [r15+-4]
test	r10d, r10d
je	sn_dec_API_L39
mov	eax, dword [r15+-28]
cmp	eax, 1
je	sn_dec_API_L231
cmp	eax, 2
lea	rsi, [rel sn_silk_LBRR_flags_2_iCDF]
mov	edx, 8
mov	rdi, qword [rbp+-736]
lea	rax, [rel sn_silk_LBRR_flags_3_iCDF]
cmovne	rsi, rax
call	sn_ec_dec_icdf
movsx	rsi, dword [r15+-28]
add	eax, 1
test	esi, esi
jle	sn_dec_API_L39
lea	rdi, [r15+-2432]
xor	ecx, ecx
sn_dec_API_L43:
mov	edx, eax
sar	edx, cl
and	edx, 1
mov	dword [rdi+rcx*4+2432], edx
add	rcx, 1
cmp	rsi, rcx
jne	sn_dec_API_L43
jmp	sn_dec_API_L39
align 16
align 8
sn_dec_API_L228:
test	eax, eax
jle	sn_dec_API_L232
sn_dec_API_L16:
mov	r15, r13
xor	r14d, r14d
jmp	sn_dec_API_L26
align 16
align 8
sn_dec_API_L19:
cmp	eax, 10
je	sn_dec_API_L222
cmp	eax, 20
je	sn_dec_API_L233
cmp	eax, 40
je	sn_dec_API_L234
cmp	eax, 60
jne	sn_dec_API_L124
mov	dword [r15+2404], 3
mov	dword [r15+2324], 4
align 16
align 8
sn_dec_API_L20:
mov	esi, dword [r12+12]
sar	esi, 10
add	esi, 1
mov	eax, esi
and	eax, -5
cmp	eax, 8
je	sn_dec_API_L25
cmp	esi, 16
jne	sn_dec_API_L29
sn_dec_API_L25:
mov	edx, dword [r12+8]
mov	rdi, r15
add	r14d, 1
add	r15, 4296
call	sn_silk_decoder_set_fs
add	ebx, eax
mov	eax, dword [r12+4]
mov	edx, eax
cmp	eax, r14d
jle	sn_dec_API_L18
sn_dec_API_L26:
mov	eax, dword [r12+16]
test	eax, eax
jne	sn_dec_API_L19
sn_dec_API_L222:
mov	dword [r15+2404], 1
mov	dword [r15+2324], 2
jmp	sn_dec_API_L20
align 16
align 8
sn_dec_API_L233:
mov	dword [r15+2404], 1
mov	dword [r15+2324], 4
jmp	sn_dec_API_L20
align 16
align 8
sn_dec_API_L234:
mov	dword [r15+2404], 2
mov	dword [r15+2324], 4
jmp	sn_dec_API_L20
align 16
align 8
sn_dec_API_L230:
mov	esi, dword [rbp+-724]
test	esi, esi
jne	sn_dec_API_L49
mov	ecx, dword [r13+2404]
test	ecx, ecx
jle	sn_dec_API_L50
sn_dec_API_L47:
mov	qword [rbp+-752], r12
xor	r9d, r9d
mov	r10, r13
mov	dword [rbp+-772], ebx
mov	rbx, qword [rbp+-736]
mov	r13, r9
sn_dec_API_L51:
mov	edi, r13d
mov	r12d, r13d
mov	r14, r10
xor	r15d, r15d
test	eax, eax
jle	sn_dec_API_L61
mov	qword [rbp+-768], r10
mov	dword [rbp+-760], edi
mov	rdi, r14
mov	r14, r13
mov	r13d, r15d
mov	r15, rdi
align 16
align 8
sn_dec_API_L59:
mov	edx, dword [r15+r14*4+2432]
test	edx, edx
je	sn_dec_API_L53
cmp	eax, 2
jne	sn_dec_API_L56
test	r13d, r13d
je	sn_dec_API_L235
sn_dec_API_L56:
xor	r8d, r8d
test	r14d, r14d
jle	sn_dec_API_L58
mov	eax, dword [rbp+-760]
xor	r8d, r8d
sub	eax, 1
mov	eax, dword [r15+rax*4+2432]
test	eax, eax
setne	r8b
add	r8d, r8d
sn_dec_API_L58:
mov	ecx, 1
mov	edx, r12d
mov	rsi, rbx
mov	rdi, r15
call	sn_silk_decode_indices
movsx	ecx, byte [r15+2790]
mov	rdi, rbx
movsx	edx, byte [r15+2789]
mov	r8d, dword [r15+2328]
lea	rsi, [rbp+-688]
call	sn_silk_decode_pulses
mov	rax, qword [rbp+-752]
mov	eax, dword [rax+4]
sn_dec_API_L53:
add	r13d, 1
mov	edx, eax
add	r15, 4296
cmp	eax, r13d
jg	sn_dec_API_L59
mov	r10, qword [rbp+-768]
mov	r13, r14
sn_dec_API_L61:
add	r13, 1
cmp	dword [r10+2404], r13d
jg	sn_dec_API_L51
mov	ebx, dword [rbp+-772]
mov	r12, qword [rbp+-752]
mov	r13, r10
sn_dec_API_L31:
cmp	eax, 2
je	sn_dec_API_L66
sn_dec_API_L225:
mov	ecx, dword [r12+8]
mov	r8d, dword [r12]
sn_dec_API_L74:
imul	ecx, r8d
mov	edi, dword [r12+12]
imul	edi, edx
mov	dword [rbp+-768], ecx
mov	r11d, ecx
movsx	rcx, dword [r13+2328]
mov	dword [rbp+-760], edi
mov	rax, rcx
lea	rsi, [rcx+rcx+4]
cmp	edi, r11d
jge	sn_dec_API_L76
mov	rdi, qword [rbp+-744]
add	rsi, rdi
sn_dec_API_L77:
mov	r10d, dword [rbp+-724]
mov	qword [rbp+-688], rdi
mov	qword [rbp+-680], rsi
test	r10d, r10d
jne	sn_dec_API_L81
mov	r9d, dword [rbp+-720]
xor	ecx, ecx
test	r9d, r9d
sete	cl
sn_dec_API_L82:
mov	eax, dword [r12+24]
mov	dword [r13+4288], eax
test	edx, edx
jle	sn_dec_API_L84
sn_dec_API_L83:
mov	eax, ecx
mov	qword [rbp+-784], rsi
mov	r15, r13
xor	r14d, r14d
and	eax, 1
mov	qword [rbp+-792], rdi
mov	byte [rbp+-772], al
lea	rax, [rbp+-716]
mov	qword [rbp+-752], rax
sn_dec_API_L90:
test	r14d, r14d
je	sn_dec_API_L135
cmp	byte [rbp+-772], 0
jne	sn_dec_API_L135
movsx	rax, r14d
movsx	rdx, dword [rbp+-716]
xor	esi, esi
mov	rdi, qword [rbp+rax*8+-688]
add	rdx, rdx
add	rdi, 4
call	sn_set
sn_dec_API_L89:
add	dword [r13+2400], 1
mov	eax, dword [r12+4]
add	r14d, 1
add	r13, 4296
cmp	eax, r14d
jg	sn_dec_API_L90
cmp	dword [r12], 2
mov	rsi, qword [rbp+-784]
mov	r13, r15
mov	rdi, qword [rbp+-792]
jne	sn_dec_API_L84
cmp	eax, 2
je	sn_dec_API_L236
sn_dec_API_L84:
lea	r14, [r13+8596]
mov	edx, 4
mov	qword [rbp+-736], rdi
mov	rsi, r14
call	sn_copy
mov	rdi, qword [rbp+-736]
mov	edx, 4
movsx	rax, dword [rbp+-716]
lea	rsi, [rdi+rax*2]
mov	rdi, r14
call	sn_copy
sn_dec_API_L91:
movsx	ecx, word [r13+2316]
mov	eax, dword [r12+8]
imul	eax, dword [rbp+-716]
mov	rdi, qword [rbp+-744]
imul	ecx, ecx, 1000
mov	qword [rbp+-736], rdi
cdq
idiv	ecx
mov	rcx, qword [rbp+16]
mov	dword [rcx], eax
mov	edx, dword [r12]
cmp	edx, 2
je	sn_dec_API_L237
sn_dec_API_L92:
mov	ecx, dword [rbp+-768]
cmp	dword [rbp+-760], ecx
jge	sn_dec_API_L96
mov	eax, dword [r13+2328]
mov	rsi, rsp
lea	edx, [rax+2]
imul	edx, dword [r12+4]
movsx	rdx, edx
add	rdx, rdx
lea	rax, [rdx+15]
mov	rcx, rax
and	rax, -4096
sub	rsi, rax
and	rcx, -16
cmp	rsp, rsi
je	sn_dec_API_L98
sn_dec_API_L238:
sub	rsp, 4096
or	qword [rsp+4088], 0
cmp	rsp, rsi
jne	sn_dec_API_L238
sn_dec_API_L98:
and	ecx, 4095
sub	rsp, rcx
test	rcx, rcx
je	sn_dec_API_L99
or	qword [rsp+rcx+-8], 0
sn_dec_API_L99:
mov	r14, rsp
mov	rsi, qword [rbp+-744]
mov	rdi, r14
call	sn_copy
movsx	rax, dword [r13+2328]
mov	qword [rbp+-688], r14
mov	edx, dword [r12]
lea	rax, [r14+rax*2+4]
mov	qword [rbp+-680], rax
sn_dec_API_L96:
mov	eax, dword [r12+4]
mov	ecx, edx
cmp	eax, edx
cmovle	ecx, eax
test	ecx, ecx
jle	sn_dec_API_L102
lea	rdi, [r13+2448]
xor	r14d, r14d
lea	r15, [rbp+-688]
mov	qword [rbp+-752], r13
mov	r13, r15
mov	r15, r12
mov	r12d, ebx
mov	rbx, r14
mov	r14, rdi
sn_dec_API_L101:
mov	rax, qword [r13+rbx*8+0]
mov	ecx, dword [rbp+-716]
mov	rdi, r14
mov	rsi, qword [rbp+-736]
lea	rdx, [rax+2]
call	sn_silk_resampler
mov	edx, dword [r15]
add	r12d, eax
cmp	edx, 2
je	sn_dec_API_L100
sn_dec_API_L103:
mov	eax, dword [r15+4]
add	rbx, 1
add	r14, 4296
mov	ecx, eax
cmp	edx, eax
cmovle	ecx, edx
cmp	ecx, ebx
jg	sn_dec_API_L101
mov	r13, qword [rbp+-752]
mov	ebx, r12d
mov	r12, r15
sn_dec_API_L102:
cmp	eax, 1
jne	sn_dec_API_L109
cmp	edx, 2
je	sn_dec_API_L239
sn_dec_API_L109:
cmp	dword [r13+4188], 2
je	sn_dec_API_L240
mov	dword [r12+20], 0
sn_dec_API_L114:
cmp	dword [rbp+-724], 1
je	sn_dec_API_L241
mov	eax, dword [rbp+-720]
mov	dword [r13+8612], eax
sn_dec_API_L8:
lea	rsp, [rbp+-40]
mov	eax, ebx
pop	rbx
pop	r12
pop	r13
pop	r14
pop	r15
pop	rbp
ret
align 16
align 8
sn_dec_API_L135:
mov	eax, dword [r15+2400]
xor	r9d, r9d
sub	eax, r14d
test	eax, eax
jle	sn_dec_API_L87
cmp	dword [rbp+-724], 2
je	sn_dec_API_L242
mov	r9d, 2
test	r14d, r14d
jle	sn_dec_API_L87
mov	eax, dword [r15+8612]
neg	eax
sbb	r9d, r9d
add	r9d, 2
sn_dec_API_L87:
movsx	rax, r14d
sub	rsp, 8
mov	rcx, qword [rbp+-752]
mov	r8d, dword [rbp+-724]
mov	rdx, qword [rbp+rax*8+-688]
mov	eax, dword [rbp+24]
mov	rdi, r13
mov	rsi, qword [rbp+-736]
push	rax
add	rdx, 4
call	sn_silk_decode_frame
pop	rdx
pop	rcx
add	ebx, eax
jmp	sn_dec_API_L89
align 16
align 8
sn_dec_API_L81:
mov	r8d, dword [r13+8612]
test	r8d, r8d
je	sn_dec_API_L129
cmp	edx, 2
jne	sn_dec_API_L130
cmp	dword [rbp+-724], 2
je	sn_dec_API_L243
sn_dec_API_L130:
xor	ecx, ecx
jmp	sn_dec_API_L82
align 16
align 8
sn_dec_API_L76:
add	eax, 2
mov	rdi, rsp
imul	eax, edx
cdqe
lea	rax, [rax+rax+15]
mov	rcx, rax
and	rax, -4096
sub	rdi, rax
and	rcx, -16
cmp	rsp, rdi
je	sn_dec_API_L79
sn_dec_API_L244:
sub	rsp, 4096
or	qword [rsp+4088], 0
cmp	rsp, rdi
jne	sn_dec_API_L244
sn_dec_API_L79:
and	ecx, 4095
sub	rsp, rcx
test	rcx, rcx
je	sn_dec_API_L80
or	qword [rsp+rcx+-8], 0
sn_dec_API_L80:
mov	rdi, rsp
add	rsi, rdi
jmp	sn_dec_API_L77
align 16
align 8
sn_dec_API_L227:
cmp	dword [r13+8608], 2
je	sn_dec_API_L245
mov	eax, dword [r13+2400]
mov	dword [rbp+-728], eax
test	eax, eax
jne	sn_dec_API_L123
jmp	sn_dec_API_L16
sn_dec_API_L10:
cmp	dword [rdi+8608], eax
jge	sn_dec_API_L246
align 16
align 8
sn_dec_API_L120:
lea	rdi, [r13+4296]
call	sn_silk_init_decoder
mov	ebx, eax
mov	eax, dword [r12+4]
jmp	sn_dec_API_L13
align 16
align 8
sn_dec_API_L229:
cmp	eax, 2
jne	sn_dec_API_L27
cmp	dword [r13+8604], 1
je	sn_dec_API_L28
cmp	dword [r13+8608], 1
jne	sn_dec_API_L27
sn_dec_API_L28:
lea	rdi, [r13+8592]
mov	edx, 4
xor	esi, esi
call	sn_set
lea	rdi, [r13+8600]
mov	edx, 4
xor	esi, esi
call	sn_set
lea	rsi, [r13+2448]
mov	edx, 304
lea	rdi, [r13+6744]
call	sn_copy
mov	esi, dword [r12]
mov	eax, dword [r12+4]
mov	r8d, esi
mov	edx, eax
jmp	sn_dec_API_L27
align 16
align 8
sn_dec_API_L30:
cmp	eax, 2
jne	sn_dec_API_L74
sn_dec_API_L62:
movsx	eax, word [r13+8592]
mov	dword [rbp+-712], eax
movsx	eax, word [r13+8594]
mov	dword [rbp+-708], eax
sn_dec_API_L70:
mov	r11d, dword [rbp+-720]
test	r11d, r11d
je	sn_dec_API_L73
mov	ecx, dword [r12+8]
mov	r8d, dword [r12]
mov	edx, 2
jmp	sn_dec_API_L74
align 16
align 8
sn_dec_API_L237:
cdqe
mov	rsi, rsp
lea	rax, [rax+rax+15]
mov	rcx, rax
and	rax, -4096
and	rcx, -16
sub	rsi, rax
sn_dec_API_L93:
cmp	rsp, rsi
je	sn_dec_API_L94
sub	rsp, 4096
or	qword [rsp+4088], 0
jmp	sn_dec_API_L93
align 16
align 8
sn_dec_API_L241:
mov	eax, dword [r13+8608]
test	eax, eax
jle	sn_dec_API_L8
mov	byte [r13+2312], 10
cmp	eax, 1
je	sn_dec_API_L8
mov	byte [r13+6608], 10
jmp	sn_dec_API_L8
align 16
align 8
sn_dec_API_L240:
mov	rax, 17179869190
mov	dword [rbp+-696], 3
mov	qword [rbp+-704], rax
mov	eax, dword [r13+2316]
sub	eax, 8
sar	eax, 2
cdqe
mov	eax, dword [rbp+rax*4+-704]
imul	eax, dword [r13+2308]
mov	dword [r12+20], eax
jmp	sn_dec_API_L114
align 16
align 8
sn_dec_API_L100:
mov	rax, qword [rbp+16]
movsx	rax, dword [rax]
test	eax, eax
jle	sn_dec_API_L103
mov	rcx, qword [rbp+-736]
mov	r10d, ebx
mov	rdi, qword [rbp+-744]
lea	r11, [rcx+rax*2]
sub	r10d, ecx
mov	rax, rcx
align 16
align 8
sn_dec_API_L104:
movzx	esi, word [rax]
lea	ecx, [r10+rax]
add	rax, 2
movsx	rcx, ecx
mov	word [rdi+rcx*2], si
cmp	r11, rax
jne	sn_dec_API_L104
jmp	sn_dec_API_L103
align 16
align 8
sn_dec_API_L242:
sub	eax, 1
xor	r9d, r9d
cdqe
mov	esi, dword [r13+rax*4+2432]
test	esi, esi
setne	r9b
add	r9d, r9d
jmp	sn_dec_API_L87
align 16
align 8
sn_dec_API_L129:
mov	ecx, 1
jmp	sn_dec_API_L82
align 16
align 8
sn_dec_API_L49:
cmp	edx, 2
je	sn_dec_API_L67
sn_dec_API_L224:
mov	edi, dword [r12+8]
mov	esi, dword [r12]
sn_dec_API_L48:
mov	ecx, edi
mov	r8d, esi
jmp	sn_dec_API_L74
sn_dec_API_L94:
and	ecx, 4095
sub	rsp, rcx
test	rcx, rcx
jne	sn_dec_API_L247
sn_dec_API_L95:
mov	qword [rbp+-736], rsp
jmp	sn_dec_API_L92
align 16
align 8
sn_dec_API_L29:
mov	ebx, -200
jmp	sn_dec_API_L8
align 16
align 8
sn_dec_API_L235:
mov	rdi, rbx
lea	rsi, [rbp+-712]
call	sn_silk_stereo_decode_pred
mov	rdi, qword [rbp+-768]
movsx	rax, r12d
mov	eax, dword [rdi+rax*4+6728]
test	eax, eax
jne	sn_dec_API_L56
lea	rsi, [rbp+-720]
mov	rdi, rbx
call	sn_silk_stereo_decode_mid_only
jmp	sn_dec_API_L56
sn_dec_API_L67:
cmp	dword [rbp+-724], 2
jne	sn_dec_API_L62
movsx	rax, dword [r13+2400]
cmp	dword [r13+rax*4+2432], 1
jne	sn_dec_API_L62
mov	rdi, qword [rbp+-736]
lea	rsi, [rbp+-712]
call	sn_silk_stereo_decode_pred
movsx	rax, dword [r13+2400]
mov	r15d, dword [r13+rax*4+6728]
test	r15d, r15d
je	sn_dec_API_L72
sn_dec_API_L71:
mov	dword [rbp+-720], 0
mov	edx, dword [r12+4]
cmp	edx, 2
jne	sn_dec_API_L225
sn_dec_API_L73:
cmp	dword [r13+8612], 1
je	sn_dec_API_L75
mov	ecx, dword [r12+8]
mov	r8d, dword [r12]
mov	edx, 2
jmp	sn_dec_API_L74
align 16
align 8
sn_dec_API_L66:
mov	eax, dword [rbp+-724]
test	eax, eax
jne	sn_dec_API_L67
sn_dec_API_L52:
mov	rdi, qword [rbp+-736]
lea	rsi, [rbp+-712]
call	sn_silk_stereo_decode_pred
movsx	rax, dword [r13+2400]
mov	r14d, dword [r13+rax*4+6712]
test	r14d, r14d
jne	sn_dec_API_L71
sn_dec_API_L72:
mov	rdi, qword [rbp+-736]
lea	rsi, [rbp+-720]
call	sn_silk_stereo_decode_mid_only
mov	edx, dword [r12+4]
cmp	edx, 2
je	sn_dec_API_L70
jmp	sn_dec_API_L225
align 16
align 8
sn_dec_API_L245:
imul	eax, dword [r13+2316], 1000
cmp	eax, dword [r12+12]
sete	al
mov	r15d, dword [r13+2400]
movzx	eax, al
mov	dword [rbp+-728], eax
test	r15d, r15d
je	sn_dec_API_L16
jmp	sn_dec_API_L223
align 16
align 8
sn_dec_API_L239:
mov	eax, dword [rbp+-728]
test	eax, eax
jne	sn_dec_API_L107
mov	rax, qword [rbp+16]
mov	rcx, qword [rbp+-744]
mov	edx, dword [rax]
xor	eax, eax
lea	esi, [rdx+rdx]
test	edx, edx
jle	sn_dec_API_L109
align 16
align 8
sn_dec_API_L112:
movsx	rdx, eax
movzx	edi, word [rcx+rdx*2]
lea	edx, [rax+1]
add	eax, 2
movsx	rdx, edx
mov	word [rcx+rdx*2], di
cmp	esi, eax
jne	sn_dec_API_L112
jmp	sn_dec_API_L109
align 16
align 8
sn_dec_API_L236:
lea	rax, [r15+8592]
mov	r9d, dword [rbp+-716]
mov	rdx, rsi
mov	rsi, rdi
mov	r8d, dword [r15+2316]
lea	rcx, [rbp+-712]
mov	rdi, rax
call	sn_silk_stereo_MS_to_LR
jmp	sn_dec_API_L91
sn_dec_API_L247:
or	qword [rsp+rcx+-8], 0
jmp	sn_dec_API_L95
sn_dec_API_L246:
mov	ebx, dword [rdi+2400]
test	ebx, ebx
je	sn_dec_API_L121
mov	dword [rbp+-728], 0
xor	ebx, ebx
jmp	sn_dec_API_L17
sn_dec_API_L243:
movsx	rax, dword [r13+6696]
xor	ecx, ecx
cmp	dword [r13+rax*4+6728], 1
mov	eax, dword [r12+24]
sete	cl
mov	dword [r13+4288], eax
jmp	sn_dec_API_L83
sn_dec_API_L124:
mov	ebx, -203
jmp	sn_dec_API_L8
sn_dec_API_L107:
mov	rax, qword [rbp+-688]
mov	r14, qword [rbp+-736]
lea	rdi, [r13+6744]
mov	ecx, dword [rbp+-716]
lea	rdx, [rax+2]
mov	rsi, r14
call	sn_silk_resampler
add	ebx, eax
mov	rax, qword [rbp+16]
movsx	rax, dword [rax]
test	eax, eax
jle	sn_dec_API_L109
mov	ecx, 1
mov	r8, qword [rbp+-744]
mov	rdx, r14
lea	rsi, [r14+rax*2]
sub	ecx, r14d
align 16
align 8
sn_dec_API_L111:
movzx	edi, word [rdx]
lea	eax, [rcx+rdx]
add	rdx, 2
cdqe
mov	word [r8+rax*2], di
cmp	rdx, rsi
jne	sn_dec_API_L111
jmp	sn_dec_API_L109
sn_dec_API_L32:
mov	r9d, dword [rbp+-724]
test	r9d, r9d
jne	sn_dec_API_L48
mov	r8d, dword [r13+2404]
test	r8d, r8d
jg	sn_dec_API_L47
jmp	sn_dec_API_L48
sn_dec_API_L50:
cmp	edx, 2
jne	sn_dec_API_L224
jmp	sn_dec_API_L52
sn_dec_API_L75:
lea	rdi, [r13+5644]
mov	edx, 960
xor	esi, esi
call	sn_set
mov	edx, 64
lea	rdi, [r13+5580]
xor	esi, esi
call	sn_set
mov	byte [r13+6608], 10
mov	edx, dword [r12+4]
mov	dword [r13+6604], 100
mov	dword [r13+8484], 0
mov	dword [r13+6672], 1
jmp	sn_dec_API_L225
sn_dec_API_L232:
mov	eax, dword [r12+4]
sn_dec_API_L121:
mov	dword [rbp+-728], 0
mov	edx, eax
jmp	sn_dec_API_L18
sn_dec_API_L37:
cmp	dword [rbp+-724], 0
jne	sn_dec_API_L224
cmp	dword [r13+2404], 0
jg	sn_dec_API_L47
jmp	sn_dec_API_L224

; ===== stereo_decode_pred.c =====
section .text
align 16
sn_silk_stereo_decode_pred:
push	r13
mov	edx, 8
lea	r13, [rel sn_silk_uniform3_iCDF]
push	r12
lea	r12, [rel sn_silk_uniform5_iCDF]
push	rbp
mov	rbp, rdi
push	rbx
mov	rbx, rsi
lea	rsi, [rel sn_silk_stereo_pred_joint_iCDF]
sub	rsp, 40
call	sn_ec_dec_icdf
mov	rsi, r13
mov	rdi, rbp
movsx	rdx, eax
mov	ecx, eax
imul	rdx, rdx, 1717986919
sar	ecx, 31
sar	rdx, 33
sub	edx, ecx
mov	dword [rsp+16], edx
lea	edx, [rdx+rdx*4]
sub	eax, edx
mov	edx, 8
mov	dword [rsp+28], eax
call	sn_ec_dec_icdf
mov	edx, 8
mov	rsi, r12
mov	rdi, rbp
mov	dword [rsp+8], eax
call	sn_ec_dec_icdf
mov	edx, 8
mov	rsi, r13
mov	rdi, rbp
mov	dword [rsp+12], eax
call	sn_ec_dec_icdf
mov	rsi, r12
mov	rdi, rbp
mov	edx, 8
mov	dword [rsp+20], eax
call	sn_ec_dec_icdf
lea	rcx, [rsp+8]
xor	esi, esi
lea	rdi, [rel sn_silk_stereo_pred_quant_Q13]
mov	dword [rsp+24], eax
sn_stereo_decode_pred_L2:
mov	eax, dword [rcx+8]
add	rcx, 12
lea	eax, [rax+rax*2]
add	eax, dword [rcx+-12]
movsx	rdx, eax
mov	dword [rcx+-12], eax
add	eax, 1
cdqe
movsx	r8d, word [rdi+rdx*2]
movsx	edx, word [rdi+rax*2]
mov	eax, dword [rcx+-8]
sub	edx, r8d
lea	eax, [rax+rax+1]
movsx	rdx, edx
cwde
imul	rdx, rdx, 6554
sar	rdx, 16
imul	eax, edx
add	eax, r8d
mov	dword [rbx+rsi*4], eax
test	rsi, rsi
jne	sn_stereo_decode_pred_L6
mov	esi, 1
jmp	sn_stereo_decode_pred_L2
align 16
align 8
sn_stereo_decode_pred_L6:
mov	eax, dword [rbx+4]
sub	dword [rbx], eax
add	rsp, 40
pop	rbx
pop	rbp
pop	r12
pop	r13
ret
align 16
sn_silk_stereo_decode_mid_only:
push	rbx
mov	edx, 8
mov	rbx, rsi
lea	rsi, [rel sn_silk_stereo_only_code_mid_iCDF]
call	sn_ec_dec_icdf
mov	dword [rbx], eax
pop	rbx
ret

; ===== stereo_MS_to_LR.c =====
section .text
align 16
sn_silk_stereo_MS_to_LR:
push	r15
mov	r15d, r9d
push	r14
mov	r14, rcx
push	r13
push	r12
mov	r12, rdi
push	rbp
lea	r13, [r12+8]
mov	rbp, rdx
mov	edx, 4
push	rbx
mov	rbx, rsi
sub	rsp, 40
mov	dword [rsp+12], r8d
lea	r8, [rdi+4]
mov	rdi, rbx
mov	rsi, r8
mov	qword [rsp+16], r8
mov	dword [rsp+8], r9d
call	sn_copy
mov	rsi, r13
mov	edx, 4
mov	rdi, rbp
call	sn_copy
movsx	rax, r15d
mov	rdi, qword [rsp+16]
mov	edx, 4
lea	r15, [rax+rax]
mov	qword [rsp+24], rax
lea	rsi, [rbx+r15]
call	sn_copy
mov	rdi, r13
lea	rsi, [rbp+r15+0]
mov	edx, 4
call	sn_copy
mov	r8d, dword [rsp+12]
xor	edx, edx
mov	r11d, dword [r14]
mov	eax, 65536
movsx	edi, word [r12]
movsx	esi, word [r12+2]
xor	ecx, ecx
shl	r8d, 3
mov	dword [rsp+12], r11d
mov	r13d, -32768
idiv	r8d
mov	edx, dword [r14+4]
mov	dword [rsp+16], edx
mov	r10d, edx
sub	r11d, edi
xor	edx, edx
sub	r10d, esi
movsx	r11d, r11w
movsx	r10d, r10w
cwde
imul	r11d, eax
imul	r10d, eax
sar	r11d, 15
sar	r10d, 15
add	r11d, 1
add	r10d, 1
sar	r11d, 1
sar	r10d, 1
test	r8d, r8d
jle	sn_stereo_MS_to_LR_L6
align 16
align 8
sn_stereo_MS_to_LR_L2:
lea	eax, [rdx+2]
movsx	ecx, word [rbx+rcx*2]
add	edx, 1
add	edi, r11d
cdqe
movsx	r15, di
add	esi, r10d
movsx	eax, word [rbx+rax*2]
add	eax, ecx
movsx	rcx, edx
movsx	r14d, word [rbx+rcx*2]
lea	r9, [rbp+rcx*2+0]
lea	eax, [rax+r14*2]
shl	r14d, 11
shl	eax, 9
movsx	r14, r14d
cdqe
imul	rax, r15
movsx	r15, si
imul	r14, r15
sar	rax, 16
sar	r14, 16
add	r14d, eax
movsx	eax, word [r9]
shl	eax, 8
add	eax, r14d
mov	r14d, 32767
sar	eax, 7
add	eax, 1
mov	r15d, eax
sar	r15d, 1
cmp	eax, 65535
jg	sn_stereo_MS_to_LR_L5
cmp	r15d, -32768
mov	r14d, r15d
cmovl	r14d, r13d
sn_stereo_MS_to_LR_L5:
mov	word [r9], r14w
cmp	r8d, edx
jg	sn_stereo_MS_to_LR_L2
sn_stereo_MS_to_LR_L6:
mov	eax, dword [rsp+8]
cmp	r8d, eax
jge	sn_stereo_MS_to_LR_L4
lea	edi, [r8+1]
mov	r11d, dword [rsp+8]
movsx	rax, r8d
xor	esi, esi
movsx	rdi, edi
movsx	r14, word [rsp+12]
movsx	r13, word [rsp+16]
lea	r10, [rbx+rax*2]
add	rdi, rdi
sub	r11d, r8d
mov	r15d, -32768
add	r8d, 2
lea	r9, [rbx+rdi]
add	rdi, rbp
align 16
align 8
sn_stereo_MS_to_LR_L10:
lea	eax, [r8+rsi]
movsx	ecx, word [r9+rsi*2]
cdqe
movsx	edx, word [rbx+rax*2]
movsx	eax, word [r10+rsi*2]
lea	eax, [rax+rcx*2]
shl	ecx, 11
add	edx, eax
movsx	rcx, ecx
movsx	eax, word [rdi+rsi*2]
shl	edx, 9
imul	rcx, r13
movsx	rdx, edx
shl	eax, 8
imul	rdx, r14
sar	rcx, 16
add	eax, ecx
sar	rdx, 16
add	eax, edx
mov	edx, 32767
sar	eax, 7
add	eax, 1
mov	ecx, eax
sar	ecx, 1
cmp	eax, 65535
jg	sn_stereo_MS_to_LR_L9
cmp	ecx, -32768
mov	edx, ecx
cmovl	edx, r15d
sn_stereo_MS_to_LR_L9:
mov	word [rdi+rsi*2], dx
add	rsi, 1
cmp	r11, rsi
jne	sn_stereo_MS_to_LR_L10
sn_stereo_MS_to_LR_L4:
movzx	eax, word [rsp+12]
mov	edx, dword [rsp+8]
mov	r8d, -32768
mov	word [r12], ax
movzx	eax, word [rsp+16]
mov	word [r12+2], ax
mov	rax, qword [rsp+24]
lea	r9, [rax+rax+2]
mov	eax, 2
test	edx, edx
jle	sn_stereo_MS_to_LR_L1
align 16
align 8
sn_stereo_MS_to_LR_L13:
movsx	esi, word [rbp+rax+0]
movsx	edx, word [rbx+rax]
lea	r10d, [rsi+rdx]
mov	ecx, edx
mov	edi, esi
sub	edx, esi
mov	esi, 32767
cmp	r10d, 32767
jg	sn_stereo_MS_to_LR_L11
lea	esi, [rdi+rcx]
cmp	r10d, -32769
cmovle	esi, r8d
sn_stereo_MS_to_LR_L11:
mov	word [rbx+rax], si
mov	esi, 32767
cmp	edx, 32767
jg	sn_stereo_MS_to_LR_L12
sub	ecx, edi
cmp	edx, -32769
mov	esi, ecx
cmovle	esi, r8d
sn_stereo_MS_to_LR_L12:
mov	word [rbp+rax+0], si
add	rax, 2
cmp	r9, rax
jne	sn_stereo_MS_to_LR_L13
sn_stereo_MS_to_LR_L1:
add	rsp, 40
pop	rbx
pop	rbp
pop	r12
pop	r13
pop	r14
pop	r15
ret

; ===== profile.c =====
section .text
align 16
sn_valid:
mov	rax, rdi
mov	edi, esi
xor	esi, esi
mov	r8d, dword [rax]
test	r8d, r8d
jle	sn_profile_L1
mov	r8d, dword [rax+2308]
test	r8d, r8d
js	sn_profile_L1
lea	r9d, [rdi+rdi*8]
add	r9d, r9d
cmp	r8d, r9d
jg	sn_profile_L1
cmp	byte [rax+2312], 63
ja	sn_profile_L1
cmp	dword [rax+2316], edi
je	sn_profile_L27
sn_profile_L1:
mov	eax, esi
ret
align 16
align 8
sn_profile_L27:
cmp	dword [rax+2320], 48000
jne	sn_profile_L1
mov	r8d, edx
mov	r9d, 3435973837
imul	r8, r9
shr	r8, 34
cmp	dword [rax+2324], r8d
jne	sn_profile_L1
imul	edx, edi
cmp	dword [rax+2328], edx
jne	sn_profile_L1
lea	r9d, [rdi+rdi*4]
cmp	dword [rax+2332], r9d
jne	sn_profile_L1
imul	edx, edi, 20
cmp	dword [rax+2336], edx
jne	sn_profile_L1
cmp	edi, 16
mov	esi, 16
mov	edx, 10
cmove	edx, esi
xor	esi, esi
cmp	dword [rax+2340], edx
jne	sn_profile_L1
mov	esi, dword [rax+2376]
test	esi, esi
jne	sn_profile_L23
cmp	qword [rax+2384], 0
jne	sn_profile_L1
cmp	qword [rax+2392], 0
jne	sn_profile_L1
cmp	qword [rax+2752], 0
jne	sn_profile_L1
cmp	dword [rax+2400], ecx
jne	sn_profile_L1
cmp	dword [rax+2404], ecx
jne	sn_profile_L1
cmp	dword [rax+2408], 2
ja	sn_profile_L1
cmp	dword [rax+4184], 0
jne	sn_profile_L1
cmp	dword [rax+4188], 2
ja	sn_profile_L1
mov	esi, dword [rax+4192]
test	esi, esi
jne	sn_profile_L23
cmp	dword [rax+2712], 2
jne	sn_profile_L1
imul	edx, edi, 10
cmp	dword [rax+2716], edx
jne	sn_profile_L1
mov	ecx, dword [rax+2720]
cmp	edi, 16
je	sn_profile_L21
cmp	edi, 12
mov	edx, 21846
mov	r10d, 32768
cmove	edx, r10d
sn_profile_L4:
cmp	ecx, edx
jne	sn_profile_L1
cmp	dword [rax+2724], 0
jne	sn_profile_L1
mov	esi, dword [rax+2728]
test	esi, esi
jne	sn_profile_L23
cmp	dword [rax+2732], edi
jne	sn_profile_L1
cmp	dword [rax+2736], 48
jne	sn_profile_L1
mov	ecx, dword [rax+2740]
cmp	edi, 16
je	sn_profile_L24
xor	edx, edx
cmp	edi, 12
sete	dl
shl	edx, 2
sn_profile_L5:
cmp	ecx, edx
jne	sn_profile_L1
cmp	qword [rax+2744], 0
jne	sn_profile_L1
cmp	dword [rax+4180], edi
jne	sn_profile_L1
cmp	dword [rax+4276], edi
jne	sn_profile_L1
cmp	dword [rax+4244], 0
jne	sn_profile_L1
xor	esi, esi
cmp	r8d, dword [rax+4280]
jne	sn_profile_L1
xor	esi, esi
cmp	dword [rax+4284], r9d
sete	sil
jmp	sn_profile_L1
sn_profile_L23:
xor	esi, esi
jmp	sn_profile_L1
sn_profile_L24:
mov	edx, 7
jmp	sn_profile_L5
sn_profile_L21:
mov	edx, 43691
jmp	sn_profile_L4
align 16
sn_bind_book:
sub	rsp, 152
mov	edx, esi
mov	rax, 100255755143872544
mov	qword [rsp], rax
lea	rax, [rel sn_silk_NLSF_CB1_NB_MB_Q8]
cmp	edx, 16
mov	rsi, rsp
mov	qword [rsp+8], rax
lea	rax, [rel sn_silk_NLSF_CB1_Wght_Q9]
mov	edx, 72
mov	qword [rsp+16], rax
lea	rax, [rel sn_silk_NLSF_CB1_iCDF_NB_MB]
mov	qword [rsp+24], rax
lea	rax, [rel sn_silk_NLSF_PRED_NB_MB_Q8]
mov	qword [rsp+32], rax
lea	rax, [rel sn_silk_NLSF_CB2_SELECT_NB_MB]
mov	qword [rsp+40], rax
lea	rax, [rel sn_silk_NLSF_CB2_iCDF_NB_MB]
mov	qword [rsp+48], rax
lea	rax, [rel sn_silk_NLSF_CB2_BITS_NB_MB_Q5]
mov	qword [rsp+56], rax
lea	rax, [rel sn_silk_NLSF_DELTA_MIN_NB_MB_Q15]
mov	qword [rsp+64], rax
mov	rax, 120232034585018400
mov	qword [rsp+72], rax
lea	rax, [rel sn_silk_NLSF_CB1_WB_Q8]
mov	qword [rsp+80], rax
lea	rax, [rel sn_silk_NLSF_CB1_WB_Wght_Q9]
mov	qword [rsp+88], rax
lea	rax, [rel sn_silk_NLSF_CB1_iCDF_WB]
mov	qword [rsp+96], rax
lea	rax, [rel sn_silk_NLSF_PRED_WB_Q8]
mov	qword [rsp+104], rax
lea	rax, [rel sn_silk_NLSF_CB2_SELECT_WB]
mov	qword [rsp+112], rax
lea	rax, [rel sn_silk_NLSF_CB2_iCDF_WB]
mov	qword [rsp+120], rax
lea	rax, [rel sn_silk_NLSF_CB2_BITS_WB_Q5]
mov	qword [rsp+128], rax
lea	rax, [rel sn_silk_NLSF_DELTA_MIN_WB_Q15]
mov	qword [rsp+136], rax
lea	rax, [rsp+72]
cmove	rsi, rax
call	sn_copy
add	rsp, 152
ret
align 16
sn_ec_dec_icdf:
push	rbx
mov	ecx, edx
mov	rbx, rdi
mov	edx, 1
sub	rsp, 64
jmp	sn_profile_L33
align 16
align 8
sn_profile_L35:
add	rdx, 1
cmp	rdx, 256
je	sn_profile_L34
sn_profile_L33:
cmp	byte [rsi+rdx+-1], 0
jne	sn_profile_L35
sn_profile_L34:
mov	rax, qword [rbx]
mov	edi, dword [rbx+24]
mov	dword [rsp+52], 827478095
mov	r8d, dword [rbx+44]
mov	r9d, dword [rbx+12]
mov	qword [rsp+56], 0
mov	qword [rsp], rax
mov	eax, dword [rbx+8]
shl	r8, 32
mov	r10, qword [rbx+16]
shl	r9, 32
mov	qword [rsp+8], rax
mov	eax, dword [rbx+32]
mov	qword [rsp+24], r10
shl	rax, 32
or	rdi, rax
mov	eax, dword [rbx+36]
mov	qword [rsp+32], rdi
mov	rdi, rsp
or	rax, r8
mov	r8d, dword [rbx+28]
mov	qword [rsp+40], rax
mov	eax, dword [rbx+48]
or	r8, r9
mov	qword [rsp+16], r8
mov	dword [rsp+48], eax
call	media_opus_range_icdf
mov	rdx, qword [rsp]
mov	ecx, dword [rsp+20]
mov	dword [rbx+40], 0
mov	qword [rbx], rdx
mov	edx, dword [rsp+16]
shl	rcx, 32
mov	dword [rbx+28], edx
mov	edx, dword [rsp+8]
or	rdx, rcx
mov	qword [rbx+8], rdx
mov	rdx, qword [rsp+24]
mov	qword [rbx+16], rdx
mov	edx, dword [rsp+32]
mov	dword [rbx+24], edx
mov	rdx, qword [rsp+36]
mov	qword [rbx+32], rdx
mov	rdx, qword [rsp+44]
mov	qword [rbx+44], rdx
mov	edx, eax
test	rax, rax
js	sn_profile_L42
add	rsp, 64
mov	eax, edx
pop	rbx
ret
align 16
align 8
sn_profile_L42:
mov	dword [rbx+48], 1
xor	edx, edx
add	rsp, 64
mov	eax, edx
pop	rbx
ret
align 16
sn_ec_dec_bit_logp:
push	rbx
mov	rbx, rdi
mov	esi, esi
sub	rsp, 64
mov	rax, qword [rdi]
mov	edx, dword [rdi+24]
mov	ecx, dword [rdi+44]
mov	r8, qword [rdi+16]
mov	dword [rsp+52], 827478095
mov	qword [rsp], rax
mov	eax, dword [rdi+8]
shl	rcx, 32
mov	qword [rsp+24], r8
mov	qword [rsp+8], rax
mov	eax, dword [rdi+32]
mov	qword [rsp+56], 0
shl	rax, 32
or	rdx, rax
mov	eax, dword [rdi+36]
mov	edi, dword [rdi+12]
mov	qword [rsp+32], rdx
or	rax, rcx
mov	ecx, dword [rbx+28]
shl	rdi, 32
mov	qword [rsp+40], rax
mov	eax, dword [rbx+48]
or	rcx, rdi
mov	rdi, rsp
mov	qword [rsp+16], rcx
mov	dword [rsp+48], eax
call	media_opus_range_bit
mov	rdx, qword [rsp]
mov	ecx, dword [rsp+20]
mov	dword [rbx+40], 0
mov	qword [rbx], rdx
mov	edx, dword [rsp+16]
shl	rcx, 32
mov	dword [rbx+28], edx
mov	edx, dword [rsp+8]
or	rdx, rcx
mov	qword [rbx+8], rdx
mov	rdx, qword [rsp+24]
mov	qword [rbx+16], rdx
mov	edx, dword [rsp+32]
mov	dword [rbx+24], edx
mov	rdx, qword [rsp+36]
mov	qword [rbx+32], rdx
mov	rdx, qword [rsp+44]
mov	qword [rbx+44], rdx
mov	edx, eax
test	rax, rax
js	sn_profile_L48
add	rsp, 64
mov	eax, edx
pop	rbx
ret
align 16
align 8
sn_profile_L48:
mov	dword [rbx+48], 1
xor	edx, edx
add	rsp, 64
mov	eax, edx
pop	rbx
ret
align 16
sn_paos_ltp_icdf:
lea	rax, [rel sn_silk_LTP_gain_iCDF_0]
test	edi, edi
je	sn_profile_L49
cmp	edi, 1
lea	rax, [rel sn_silk_LTP_gain_iCDF_2]
lea	rdx, [rel sn_silk_LTP_gain_iCDF_1]
cmove	rax, rdx
sn_profile_L49:
ret
align 16
sn_paos_ltp_vq:
lea	rax, [rel sn_silk_LTP_gain_vq_0]
test	edi, edi
je	sn_profile_L54
cmp	edi, 1
lea	rax, [rel sn_silk_LTP_gain_vq_2]
lea	rdx, [rel sn_silk_LTP_gain_vq_1]
cmove	rax, rdx
sn_profile_L54:
ret
align 16
sn_paos_silk_transaction:
cld
test	rdi, rdi
jne	sn_profile_L268
mov	rax, -1
ret
align 16
align 8
sn_profile_L268:
push	r15
push	r14
push	r13
push	r12
push	rbp
push	rbx
lea	r11, [rsp+-20480]
sn_profile_LPSRL0:
sub	rsp, 4096
or	dword [rsp], 0
cmp	rsp, r11
jne	sn_profile_LPSRL0
sub	rsp, 1608
mov	rbx, rdi
test	dil, 7
jne	sn_profile_L61
mov	rax, rdi
shr	rax, 47
jne	sn_profile_L61
mov	rax, 140737488355328
sub	rax, rdi
cmp	rax, 79
ja	sn_profile_L269
align 16
align 8
sn_profile_L61:
mov	rax, -1
sn_profile_L59:
add	rsp, 22088
pop	rbx
pop	rbp
pop	r12
pop	r13
pop	r14
pop	r15
ret
sn_profile_L269:
mov	rax, qword [rdi+16]
mov	rcx, qword [rdi+8]
mov	qword [rsp+120], rdi
mov	r13, qword [rdi]
mov	rdx, qword [rdi+40]
mov	qword [rsp+152], 80
mov	qword [rsp+136], rax
mov	rax, qword [rdi+32]
lea	rsi, [rcx+-3]
mov	qword [rsp+128], r13
mov	qword [rsp+144], rax
mov	rax, qword [rdi+24]
mov	qword [rsp+160], rcx
mov	qword [rsp+168], rax
sub	rax, 9120
cmp	rax, 56416
mov	qword [rsp+176], rdx
seta	al
cmp	rsi, 65533
seta	sil
or	al, sil
jne	sn_profile_L61
lea	rax, [rdx+-960]
cmp	rax, 261184
ja	sn_profile_L61
mov	rdi, qword [rdi+48]
lea	rax, [rdi+-1]
cmp	rax, 1
ja	sn_profile_L61
cmp	qword [rbx+56], 1
jne	sn_profile_L61
mov	r14, qword [rbx+64]
test	r14, r14
jne	sn_profile_L61
mov	qword [rsp], r13
xor	esi, esi
lea	r8, [rsp+120]
mov	ebp, 8
lea	r9, [rsp+152]
mov	r12d, 2
mov	r11, 140737488355326
sn_profile_L70:
cmp	rsi, 1
jbe	sn_profile_L63
mov	r13, qword [r8+rsi*8]
cmp	rsi, 2
mov	rax, rbp
mov	r15, qword [r9+rsi*8]
cmovne	rax, r12
lea	r10, [r13+-1]
cmp	r11, r10
jb	sn_profile_L61
test	r15, r15
je	sn_profile_L61
sub	rax, 1
test	rax, r13
jne	sn_profile_L61
mov	eax, 1
shl	rax, 47
sub	rax, r13
cmp	rax, r15
jnb	sn_profile_L65
jmp	sn_profile_L61
align 16
align 8
sn_profile_L174:
mov	esi, 1
align 16
align 8
sn_profile_L63:
mov	r13, qword [r8+rsi*8]
mov	r15, qword [r9+rsi*8]
mov	r10, 140737488355326
lea	rax, [r13+-1]
cmp	r10, rax
jb	sn_profile_L61
test	r15, r15
je	sn_profile_L61
mov	rax, 140737488355328
sub	rax, r13
cmp	rax, r15
jb	sn_profile_L61
cmp	esi, 1
jne	sn_profile_L174
sn_profile_L65:
mov	qword [rsp+8], rcx
xor	eax, eax
add	r15, r13
align 16
align 8
sn_profile_L68:
mov	rcx, qword [r8+rax*8]
mov	r10, qword [r9+rax*8]
add	r10, rcx
cmp	r13, r10
jnb	sn_profile_L67
cmp	rcx, r15
jb	sn_profile_L61
sn_profile_L67:
add	rax, 1
cmp	rax, rsi
jne	sn_profile_L68
mov	rcx, qword [rsp+8]
lea	rsi, [rax+1]
cmp	rax, 3
jne	sn_profile_L70
mov	r13, qword [rsp]
movzx	esi, byte [r13+0]
mov	eax, esi
and	eax, 252
cmp	rdi, 2
je	sn_profile_L270
mov	esi, eax
and	esi, -25
test	al, -60
je	sn_profile_L184
cmp	esi, 64
jne	sn_profile_L61
sn_profile_L184:
shr	eax, 3
and	eax, 3
je	sn_profile_L123
cmp	eax, 1
je	sn_profile_L271
cmp	eax, 2
je	sn_profile_L272
cmp	esi, 64
je	sn_profile_L133
cmp	esi, 32
je	sn_profile_L273
cmp	rdx, 5759
jbe	sn_profile_L61
mov	dword [rsp+68], 2880
mov	r12d, 8
mov	ebp, 827018323
mov	dword [rsp+48], 160
mov	dword [rsp], 3
mov	qword [rsp+56], 5760
sn_profile_L139:
lea	rax, [rbp+150994944]
mov	dword [rsp+16], 20
mov	qword [rsp+8], rax
mov	dword [rsp+64], 60
jmp	sn_profile_L126
sn_profile_L123:
cmp	esi, 64
je	sn_profile_L176
cmp	esi, 32
mov	edx, 120
mov	eax, 80
mov	ebp, 860572755
cmove	eax, edx
sete	r12b
movzx	r12d, r12b
mov	dword [rsp+48], eax
mov	eax, 827018323
lea	r12d, [0+r12*4+8]
cmovne	rbp, rax
lea	rax, [rbp+50331648]
mov	qword [rsp+8], rax
sn_profile_L136:
mov	dword [rsp+68], 480
mov	dword [rsp+16], 10
mov	dword [rsp], 1
mov	dword [rsp+64], 10
mov	qword [rsp+56], 960
sn_profile_L126:
lea	rdx, [rsp+376]
mov	rsi, rcx
mov	rdi, r13
call	media_opus_packet_parse
test	rax, rax
jne	sn_profile_L61
mov	rax, qword [rbx+72]
mov	edx, dword [rsp+384]
cmp	rax, rdx
jnb	sn_profile_L61
lea	rax, [rax+rax+8]
mov	edi, dword [rsp+rax*4+376]
mov	eax, dword [rsp+rax*4+380]
mov	dword [rsp+40], eax
sub	eax, 2
mov	dword [rsp+24], edi
cmp	eax, 1273
ja	sn_profile_L61
mov	rsi, qword [rbx+16]
lea	r15, [rsp+10560]
mov	edx, 9120
mov	rdi, r15
call	sn_copy
mov	rax, qword [rsp+10560]
test	rax, rax
jne	sn_profile_L140
mov	rax, r15
lea	rbp, [rsp+19680]
align 16
align 8
sn_profile_L141:
cmp	byte [rax], 0
jne	sn_profile_L61
add	rax, 1
cmp	rbp, rax
jne	sn_profile_L141
lea	rax, [rsp+10592]
mov	rdi, rax
mov	qword [rsp+32], rax
call	sn_silk_init_decoder
mov	eax, dword [rsp+16]
mov	edx, 3435973837
mov	esi, r12d
mov	rdi, qword [rsp+32]
imul	rax, rdx
mov	edx, 48000
shr	rax, 34
mov	dword [rsp+12916], eax
call	sn_silk_decoder_set_fs
jmp	sn_profile_L142
sn_profile_L140:
mov	rdi, qword [rsp+8]
cmp	rax, rdi
je	sn_profile_L178
cmp	dword [rsp+64], 20
jg	sn_profile_L61
cmp	rax, rbp
je	sn_profile_L179
add	rbp, 50331648
cmp	rax, rbp
jne	sn_profile_L61
mov	r11d, 1
mov	r8d, 10
sn_profile_L143:
mov	rax, qword [rsp+10568]
mov	edx, 4294967293
sub	rax, 1
cmp	rdx, rax
jb	sn_profile_L61
mov	eax, 4294967295
cmp	rax, qword [rsp+10576]
jb	sn_profile_L61
mov	ecx, -24
mov	rdi, qword [rsp+10584]
lea	rbp, [rsp+19680]
mov	rax, r15
mov	rsi, -3750763034362895579
sub	ecx, r15d
align 16
align 8
sn_profile_L145:
lea	edx, [rcx+rax]
cmp	edx, 7
ja	sn_profile_L274
sn_profile_L144:
add	rax, 1
cmp	rax, rbp
jne	sn_profile_L145
cmp	rdi, rsi
jne	sn_profile_L61
lea	rax, [rsp+10592]
mov	ecx, r11d
mov	edx, r8d
mov	esi, r12d
mov	rdi, rax
mov	qword [rsp+32], rax
mov	r11, rax
call	sn_valid
test	eax, eax
je	sn_profile_L61
mov	eax, dword [rsp+16]
mov	edx, 3435973837
mov	esi, r12d
mov	rdi, r11
imul	rax, rdx
mov	edx, 48000
shr	rax, 34
mov	dword [rsp+12916], eax
call	sn_silk_decoder_set_fs
test	eax, eax
jne	sn_profile_L61
sn_profile_L142:
mov	eax, dword [rsp]
mov	dword [rsp+12996], eax
lea	rax, [rsp+14892]
align 16
align 8
sn_profile_L146:
cmp	byte [rax], 0
jne	sn_profile_L61
add	rax, 1
cmp	rax, rbp
jne	sn_profile_L146
lea	rax, [rsp+304]
mov	esi, r12d
mov	rdi, rax
mov	qword [rsp+72], rax
call	sn_bind_book
mov	rax, qword [rsp+72]
mov	qword [rsp+13344], rax
cmp	r12d, 16
je	sn_profile_L275
cmp	r12d, 12
je	sn_profile_L276
lea	rax, [rel sn_silk_uniform4_iCDF]
cmp	dword [rsp+64], 10
lea	rdx, [rel sn_silk_pitch_contour_NB_iCDF]
mov	qword [rsp+12976], rax
lea	rax, [rel sn_silk_pitch_contour_10_ms_NB_iCDF]
cmovne	rax, rdx
sn_profile_L149:
mov	esi, dword [rsp+24]
mov	edx, dword [rsp+40]
lea	rdi, [rsp+240]
mov	qword [rsp+12984], rax
mov	dword [rsp+12992], 0
add	rsi, r13
call	media_opus_range_init
test	rax, rax
jne	sn_profile_L61
mov	rax, qword [rsp+240]
mov	edx, dword [rsp+260]
mov	dword [rsp+224], 0
mov	qword [rsp+184], rax
mov	eax, dword [rsp+256]
shl	rdx, 32
mov	dword [rsp+212], eax
mov	eax, dword [rsp+248]
or	rax, rdx
mov	qword [rsp+192], rax
mov	rax, qword [rsp+264]
mov	qword [rsp+200], rax
mov	eax, dword [rsp+272]
mov	dword [rsp+208], eax
mov	rax, qword [rsp+276]
mov	qword [rsp+216], rax
mov	rax, qword [rsp+284]
mov	qword [rsp+228], rax
movsx	rax, dword [rsp]
mov	qword [rsp+80], rax
lea	rax, [r15+rax*4]
mov	qword [rsp+72], rax
lea	rax, [rsp+184]
mov	qword [rsp+24], rax
mov	rax, rbp
mov	rbp, rbx
mov	rbx, r15
mov	r13, rax
sn_profile_L152:
mov	rdi, qword [rsp+24]
mov	esi, 1
add	rbx, 4
call	sn_ec_dec_bit_logp
mov	dword [rbx+2444], eax
mov	rax, qword [rsp+72]
cmp	rbx, rax
jne	sn_profile_L152
mov	rdi, qword [rsp+24]
mov	esi, 1
mov	rbx, rbp
mov	rbp, r13
call	sn_ec_dec_bit_logp
lea	rdi, [rsp+13024]
mov	edx, 12
xor	esi, esi
mov	dword [rsp+13020], eax
call	sn_set
mov	r8d, dword [rsp+13020]
test	r8d, r8d
je	sn_profile_L257
cmp	dword [rsp], 1
je	sn_profile_L277
cmp	dword [rsp], 2
mov	edx, 8
je	sn_profile_L156
mov	rdi, qword [rsp+24]
lea	rsi, [rel sn_silk_LBRR_flags_3_iCDF]
call	sn_ec_dec_icdf
add	eax, 1
sn_profile_L157:
xor	ecx, ecx
sn_profile_L158:
mov	edx, eax
mov	rdi, qword [rsp+80]
sar	edx, cl
and	edx, 1
mov	dword [r15+rcx*4+2464], edx
add	rcx, 1
cmp	rcx, rdi
jne	sn_profile_L158
mov	rax, rbp
mov	r13, rdi
mov	rbp, rbx
mov	rbx, r15
mov	r15, rax
sn_profile_L161:
mov	edi, dword [rbx+r14*4+2464]
test	edi, edi
je	sn_profile_L159
xor	r8d, r8d
test	r14, r14
je	sn_profile_L160
mov	esi, dword [rbx+r14*4+2460]
xor	r8d, r8d
test	esi, esi
setne	r8b
add	r8d, r8d
sn_profile_L160:
mov	rsi, qword [rsp+24]
mov	rdi, qword [rsp+32]
mov	ecx, 1
mov	edx, r14d
call	sn_silk_decode_indices
movsx	ecx, byte [rsp+13382]
mov	rdi, qword [rsp+24]
lea	rsi, [rsp+1440]
movsx	edx, byte [rsp+13381]
mov	r8d, dword [rsp+12920]
call	sn_silk_decode_pulses
sn_profile_L159:
add	r14, 1
cmp	r14, r13
jne	sn_profile_L161
mov	r14d, dword [rsp+232]
mov	rax, r15
mov	r15, rbx
mov	rbx, rbp
mov	rbp, rax
test	r14d, r14d
jne	sn_profile_L61
mov	eax, dword [rsp+16]
movsx	rsi, dword [rsp+48]
xor	r13d, r13d
mov	qword [rsp+104], rbp
lea	rdi, [rsp+796]
mov	dword [rsp+48], r12d
lea	edx, [rax+rax*2]
lea	rax, [rsp+116]
mov	qword [rsp+88], rbx
mov	r12, rdi
mov	qword [rsp+16], rax
shl	edx, 4
lea	rax, [rsp+800]
mov	ebx, esi
mov	dword [rsp+80], edx
mov	qword [rsp+72], rax
mov	qword [rsp+96], r15
mov	r15, rsi
align 16
align 8
sn_profile_L163:
xor	eax, eax
test	r14d, r14d
mov	dword [rsp+116], 0
setne	al
sub	rsp, 8
xor	r8d, r8d
push	0
mov	rcx, qword [rsp+32]
lea	r9d, [rax+rax]
mov	rdx, qword [rsp+88]
mov	rsi, qword [rsp+40]
mov	rdi, qword [rsp+48]
call	sn_silk_decode_frame
pop	rdx
pop	rcx
cmp	dword [rsp+116], ebx
jne	sn_profile_L61
mov	eax, dword [rsp+232]
test	eax, eax
jne	sn_profile_L61
mov	eax, dword [rsp+14888]
lea	rbp, [rsp+1440]
mov	ecx, ebx
lea	rdx, [rsp+798]
lea	rdi, [rsp+13040]
add	dword [rsp+12992], 1
mov	dword [rsp+796], eax
mov	eax, dword [r12+r15*2]
mov	dword [rsp+14888], eax
movsx	rax, r13d
lea	rsi, [rbp+rax*2+0]
call	sn_silk_resampler
test	eax, eax
jne	sn_profile_L61
mov	eax, dword [rsp+80]
add	r14d, 1
add	r13d, eax
mov	eax, dword [rsp]
cmp	r14d, eax
jne	sn_profile_L163
mov	ecx, dword [rsp+216]
mov	esi, dword [rsp+40]
mov	r12d, dword [rsp+48]
mov	rbx, qword [rsp+88]
mov	qword [rsp+48], rbp
bsr	eax, ecx
shl	esi, 3
mov	r15, qword [rsp+96]
mov	rbp, qword [rsp+104]
xor	eax, 31
add	eax, dword [rsp+208]
cmp	dword [rsp+64], 20
lea	edi, [rax+-32]
jne	sn_profile_L185
mov	edx, 8
cmp	r12d, 8
jne	sn_profile_L185
sn_profile_L165:
add	edx, esi
cmp	edx, edi
jl	sn_profile_L61
sub	eax, 15
cmp	eax, esi
jle	sn_profile_L61
add	qword [rsp+10568], 1
mov	rax, qword [rsp+8]
mov	rsi, -3750763034362895579
mov	qword [rsp+12976], 0
mov	qword [rsp+12984], 0
mov	qword [rsp+13344], 0
mov	qword [rsp+13336], 0
mov	qword [rsp+10560], rax
mov	eax, ecx
mov	ecx, -24
mov	qword [rsp+10576], rax
sub	ecx, r15d
mov	rax, r15
align 16
align 8
sn_profile_L168:
lea	edx, [rcx+rax]
cmp	edx, 7
ja	sn_profile_L278
sn_profile_L167:
add	rax, 1
cmp	rax, rbp
jne	sn_profile_L168
mov	rdi, qword [rbx+16]
mov	qword [rsp+10584], rsi
mov	edx, 9120
mov	rsi, r15
call	sn_copy
mov	rdi, qword [rbx+32]
mov	rdx, qword [rsp+56]
mov	rsi, qword [rsp+48]
call	sn_copy
movsx	rax, dword [rsp+68]
jmp	sn_profile_L59
sn_profile_L176:
mov	qword [rsp+8], 894127187
mov	r12d, 16
mov	ebp, 843795539
mov	dword [rsp+48], 160
jmp	sn_profile_L136
sn_profile_L271:
cmp	esi, 64
je	sn_profile_L279
cmp	esi, 32
je	sn_profile_L280
cmp	rdx, 1919
jbe	sn_profile_L61
mov	dword [rsp+68], 960
mov	r12d, 8
mov	ebp, 827018323
mov	dword [rsp+48], 160
mov	dword [rsp], 1
mov	qword [rsp+56], 1920
sn_profile_L244:
mov	qword [rsp+8], rbp
mov	dword [rsp+16], 20
mov	dword [rsp+64], 20
jmp	sn_profile_L126
sn_profile_L178:
mov	r11d, dword [rsp]
mov	r8d, dword [rsp+16]
jmp	sn_profile_L143
sn_profile_L133:
cmp	rdx, 5759
jbe	sn_profile_L61
mov	dword [rsp+68], 2880
mov	ebp, 843795539
mov	r12d, 16
mov	qword [rsp+56], 5760
mov	dword [rsp], 3
mov	dword [rsp+48], 320
jmp	sn_profile_L139
sn_profile_L279:
cmp	rdx, 1919
jbe	sn_profile_L61
mov	qword [rsp+8], 843795539
mov	r12d, 16
mov	ebp, 843795539
mov	dword [rsp+68], 960
mov	dword [rsp+48], 320
mov	dword [rsp+16], 20
mov	dword [rsp], 1
mov	dword [rsp+64], 20
mov	qword [rsp+56], 1920
jmp	sn_profile_L126
sn_profile_L270:
mov	edi, eax
and	edi, -29
and	esi, 4
je	sn_profile_L61
test	al, -64
je	sn_profile_L183
cmp	edi, 64
jne	sn_profile_L61
sn_profile_L183:
shr	eax, 3
and	eax, 3
je	sn_profile_L76
cmp	eax, 1
je	sn_profile_L77
cmp	eax, 2
je	sn_profile_L78
cmp	edi, 64
je	sn_profile_L79
cmp	edi, 32
je	sn_profile_L281
cmp	rdx, 11519
jbe	sn_profile_L61
mov	dword [rsp+16], 60
mov	ebp, 8
mov	r14d, 3
mov	qword [rsp+32], 11520
mov	dword [rsp+8], 2880
mov	qword [rsp], 1095453779
sn_profile_L169:
add	qword [rsp], 150994944
mov	r12d, 20
sn_profile_L83:
lea	rdx, [rsp+796]
mov	rsi, rcx
mov	rdi, r13
call	media_opus_packet_parse
test	rax, rax
jne	sn_profile_L61
mov	rax, qword [rbx+72]
mov	edx, dword [rsp+804]
cmp	rax, rdx
jnb	sn_profile_L61
lea	rax, [rax+rax+8]
mov	edi, dword [rsp+rax*4+796]
mov	eax, dword [rsp+rax*4+800]
mov	dword [rsp+64], eax
sub	eax, 2
mov	dword [rsp+24], edi
cmp	eax, 1273
ja	sn_profile_L61
lea	r15, [rsp+1440]
mov	rsi, qword [rbx+16]
mov	edx, 9120
mov	rdi, r15
mov	qword [rsp+48], r15
call	sn_copy
mov	rax, qword [rsp+1440]
test	rax, rax
jne	sn_profile_L94
mov	rax, r15
lea	r15, [rsp+10560]
align 16
align 8
sn_profile_L95:
cmp	byte [rax], 0
jne	sn_profile_L61
add	rax, 1
cmp	r15, rax
jne	sn_profile_L95
lea	rax, [rsp+1472]
mov	rdi, rax
mov	qword [rsp+40], rax
call	sn_silk_InitDecoder
mov	eax, 3435973837
mov	ecx, r12d
mov	rdi, qword [rsp+40]
imul	rcx, rax
mov	edx, 48000
mov	rsi, 8589934594
mov	qword [rsp+10076], rsi
mov	esi, ebp
shr	rcx, 34
mov	dword [rsp+3796], ecx
mov	dword [rsp+56], ecx
call	sn_silk_decoder_set_fs
mov	ecx, dword [rsp+56]
mov	edx, 48000
mov	esi, ebp
lea	rdi, [rsp+5768]
mov	dword [rsp+3876], r14d
mov	dword [rsp+8092], ecx
call	sn_silk_decoder_set_fs
mov	dword [rsp+8172], r14d
sn_profile_L96:
lea	rax, [rsp+10088]
align 16
align 8
sn_profile_L104:
cmp	byte [rax], 0
jne	sn_profile_L61
add	rax, 1
cmp	rax, r15
jne	sn_profile_L104
lea	rcx, [rsp+376]
mov	esi, ebp
mov	rdi, rcx
mov	qword [rsp+56], rcx
call	sn_bind_book
mov	rdx, qword [rsp+48]
mov	rcx, qword [rsp+56]
lea	rdi, [rel sn_silk_uniform4_iCDF]
mov	qword [rsp+4224], rcx
mov	rax, rdx
lea	rsi, [rdx+8592]
cmp	ebp, 16
je	sn_profile_L282
cmp	ebp, 12
je	sn_profile_L107
sn_profile_L284:
mov	qword [rdx+2416], rdi
cmp	r12d, 10
je	sn_profile_L283
lea	r11, [rel sn_silk_pitch_contour_NB_iCDF]
add	rax, 4296
mov	qword [rdx+2424], r11
cmp	rsi, rax
je	sn_profile_L111
sn_profile_L265:
mov	qword [rax+2784], rcx
mov	rdx, rax
cmp	ebp, 12
jne	sn_profile_L284
sn_profile_L107:
lea	rdi, [rel sn_silk_uniform6_iCDF]
mov	qword [rdx+2416], rdi
cmp	r12d, 10
je	sn_profile_L285
lea	rdi, [rel sn_silk_pitch_contour_iCDF]
add	rax, 4296
mov	qword [rdx+2424], rdi
cmp	rsi, rax
je	sn_profile_L111
sn_profile_L266:
mov	qword [rax+2784], rcx
mov	rdx, rax
jmp	sn_profile_L107
align 16
align 8
sn_profile_L272:
cmp	esi, 64
je	sn_profile_L130
cmp	esi, 32
je	sn_profile_L286
cmp	rdx, 3839
jbe	sn_profile_L61
mov	dword [rsp+48], 160
mov	r12d, 8
mov	ebp, 827018323
sn_profile_L138:
lea	rax, [rbp+100663296]
mov	dword [rsp+68], 1920
mov	qword [rsp+8], rax
mov	dword [rsp+16], 20
mov	dword [rsp], 2
mov	dword [rsp+64], 40
mov	qword [rsp+56], 3840
jmp	sn_profile_L126
sn_profile_L179:
mov	r11d, 1
mov	r8d, 20
jmp	sn_profile_L143
sn_profile_L76:
cmp	edi, 64
je	sn_profile_L287
cmp	edi, 32
je	sn_profile_L288
cmp	rdx, 1919
jbe	sn_profile_L61
mov	ebp, 8
mov	eax, 1095453779
sn_profile_L91:
add	rax, 50331648
mov	qword [rsp], rax
sn_profile_L89:
mov	dword [rsp+16], 10
mov	r14d, 1
mov	r12d, 10
mov	qword [rsp+32], 1920
mov	dword [rsp+8], 480
jmp	sn_profile_L83
sn_profile_L94:
mov	rdi, qword [rsp]
cmp	rax, rdi
jne	sn_profile_L61
mov	rax, qword [rsp+1448]
mov	edx, 4294967293
sub	rax, 1
cmp	rdx, rax
jb	sn_profile_L61
mov	eax, 4294967295
cmp	rax, qword [rsp+1456]
jb	sn_profile_L61
mov	rdx, qword [rsp+48]
mov	ecx, -24
mov	rdi, qword [rsp+1464]
lea	r15, [rsp+10560]
mov	rsi, -3750763034362895579
mov	rax, rdx
sub	ecx, edx
align 16
align 8
sn_profile_L98:
lea	edx, [rcx+rax]
cmp	edx, 7
ja	sn_profile_L289
sn_profile_L97:
add	rax, 1
cmp	rax, r15
jne	sn_profile_L98
cmp	rdi, rsi
jne	sn_profile_L61
cmp	dword [rsp+10076], 2
jne	sn_profile_L61
cmp	dword [rsp+10080], 2
jne	sn_profile_L61
mov	r11d, dword [rsp+10084]
cmp	r11d, 1
ja	sn_profile_L61
lea	rax, [rsp+1472]
mov	ecx, r14d
mov	edx, r12d
mov	esi, ebp
mov	rdi, rax
mov	qword [rsp+40], rax
call	sn_valid
test	eax, eax
je	sn_profile_L61
mov	eax, dword [rsp+8144]
test	eax, eax
je	sn_profile_L290
cmp	eax, 1
jne	sn_profile_L61
test	r11d, r11d
je	sn_profile_L61
cmp	dword [rsp+5768], 65536
jne	sn_profile_L61
cmp	dword [rsp+8076], 100
jne	sn_profile_L61
cmp	byte [rsp+8080], 10
jne	sn_profile_L61
mov	eax, dword [rsp+9956]
or	eax, dword [rsp+9948]
or	eax, dword [rsp+10044]
jne	sn_profile_L61
mov	rax, 85899345922
cmp	qword [rsp+10048], rax
jne	sn_profile_L61
mov	rdi, r15
mov	eax, r12d
lea	rsi, [rsp+5768]
mov	ecx, 537
rep movsq
xor	ecx, ecx
cdq
lea	r15, [rsp+10560]
mov	dword [rsp+12936], ecx
mov	ecx, 5
mov	esi, ebp
mov	rdi, r15
idiv	ecx
mov	dword [rsp+14740], ebp
mov	dword [rsp+14836], ebp
mov	ecx, r14d
mov	edx, r12d
mov	dword [rsp+14840], eax
lea	eax, [rbp+rbp*4+0]
mov	dword [rsp+14844], eax
call	sn_valid
sn_profile_L100:
test	eax, eax
jne	sn_profile_L96
jmp	sn_profile_L61
align 16
align 8
sn_profile_L277:
mov	dword [rsp+13024], 1
sn_profile_L257:
mov	rax, rbp
mov	r13, qword [rsp+80]
mov	rbp, rbx
mov	rbx, r15
mov	r15, rax
jmp	sn_profile_L161
sn_profile_L273:
cmp	rdx, 5759
jbe	sn_profile_L61
mov	dword [rsp+68], 2880
mov	r12d, 12
mov	ebp, 860572755
mov	dword [rsp+48], 240
mov	dword [rsp], 3
mov	qword [rsp+56], 5760
jmp	sn_profile_L139
sn_profile_L280:
cmp	rdx, 1919
jbe	sn_profile_L61
mov	dword [rsp+68], 960
mov	r12d, 12
mov	ebp, 860572755
mov	dword [rsp+48], 240
mov	dword [rsp], 1
mov	qword [rsp+56], 1920
jmp	sn_profile_L244
sn_profile_L130:
cmp	rdx, 3839
jbe	sn_profile_L61
mov	dword [rsp+48], 320
mov	r12d, 16
mov	ebp, 843795539
jmp	sn_profile_L138
sn_profile_L286:
cmp	rdx, 3839
jbe	sn_profile_L61
mov	dword [rsp+48], 240
mov	r12d, 12
mov	ebp, 860572755
jmp	sn_profile_L138
sn_profile_L275:
lea	rax, [rel sn_silk_uniform8_iCDF]
cmp	dword [rsp+64], 10
mov	qword [rsp+12976], rax
je	sn_profile_L151
sn_profile_L148:
lea	rax, [rel sn_silk_pitch_contour_iCDF]
jmp	sn_profile_L149
sn_profile_L77:
cmp	edi, 64
je	sn_profile_L291
cmp	edi, 32
je	sn_profile_L84
cmp	rdx, 3839
jbe	sn_profile_L61
mov	qword [rsp], 1095453779
mov	ebp, 8
sn_profile_L264:
mov	dword [rsp+16], 20
mov	r14d, 1
mov	r12d, 20
mov	qword [rsp+32], 3840
mov	dword [rsp+8], 960
jmp	sn_profile_L83
sn_profile_L287:
cmp	rdx, 1919
jbe	sn_profile_L61
mov	qword [rsp], 1162562643
mov	ebp, 16
jmp	sn_profile_L89
sn_profile_L288:
cmp	rdx, 1919
jbe	sn_profile_L61
mov	ebp, 12
mov	eax, 1129008211
jmp	sn_profile_L91
sn_profile_L276:
lea	rax, [rel sn_silk_uniform6_iCDF]
cmp	dword [rsp+64], 10
mov	qword [rsp+12976], rax
jne	sn_profile_L148
sn_profile_L151:
lea	rax, [rel sn_silk_pitch_contour_10_ms_iCDF]
jmp	sn_profile_L149
sn_profile_L290:
lea	rdi, [rsp+5768]
mov	ecx, r14d
mov	edx, r12d
mov	esi, ebp
call	sn_valid
jmp	sn_profile_L100
sn_profile_L78:
cmp	edi, 64
je	sn_profile_L85
cmp	edi, 32
je	sn_profile_L292
cmp	rdx, 7679
jbe	sn_profile_L61
mov	ebp, 8
mov	eax, 1095453779
sn_profile_L93:
add	rax, 100663296
mov	dword [rsp+16], 40
mov	r14d, 2
mov	r12d, 20
mov	qword [rsp], rax
mov	qword [rsp+32], 7680
mov	dword [rsp+8], 1920
jmp	sn_profile_L83
sn_profile_L79:
cmp	rdx, 11519
jbe	sn_profile_L61
mov	dword [rsp+16], 60
mov	ebp, 16
mov	r14d, 3
mov	qword [rsp+32], 11520
mov	dword [rsp+8], 2880
mov	qword [rsp], 1112230995
jmp	sn_profile_L169
sn_profile_L283:
lea	r11, [rel sn_silk_pitch_contour_10_ms_NB_iCDF]
add	rax, 4296
mov	qword [rdx+2424], r11
cmp	rsi, rax
jne	sn_profile_L265
sn_profile_L111:
mov	esi, dword [rsp+24]
mov	edx, dword [rsp+64]
lea	rdi, [rsp+304]
add	rsi, r13
call	media_opus_range_init
test	rax, rax
jne	sn_profile_L61
mov	rax, qword [rsp+304]
mov	edx, dword [rsp+324]
imul	ebp, ebp, 1000
mov	dword [rsp+280], 0
mov	qword [rsp+204], 0
lea	r8, [rsp+240]
mov	qword [rsp+240], rax
shl	rdx, 32
mov	eax, dword [rsp+320]
mov	dword [rsp+192], 48000
mov	dword [rsp+268], eax
mov	eax, dword [rsp+312]
mov	dword [rsp+196], ebp
xor	ebp, ebp
or	rax, rdx
mov	qword [rsp+248], rax
mov	rax, qword [rsp+328]
mov	qword [rsp+256], rax
mov	eax, dword [rsp+336]
mov	dword [rsp+264], eax
mov	rax, qword [rsp+340]
mov	qword [rsp+272], rax
mov	rax, qword [rsp+348]
mov	qword [rsp+284], rax
mov	rax, 8589934594
mov	qword [rsp+184], rax
mov	eax, dword [rsp+16]
mov	dword [rsp+200], eax
lea	eax, [r12+r12*2]
xor	r12d, r12d
shl	eax, 4
mov	r13d, eax
lea	rax, [rsp+184]
mov	qword [rsp+24], rax
lea	rax, [rsp+116]
mov	qword [rsp+16], rax
sn_profile_L118:
mov	dword [rsp+116], 0
lea	eax, [r12+r12]
xor	ecx, ecx
test	ebp, ebp
push	0
cdqe
sete	cl
xor	edx, edx
push	qword [rsp+24]
mov	rsi, qword [rsp+40]
lea	r9, [r15+rax*2]
mov	rdi, qword [rsp+56]
mov	qword [rsp+72], r8
call	sn_silk_Decode
pop	r11
pop	rdx
test	eax, eax
jne	sn_profile_L61
cmp	r13d, dword [rsp+116]
jne	sn_profile_L61
mov	r10d, dword [rsp+288]
test	r10d, r10d
jne	sn_profile_L61
add	ebp, 1
add	r12d, r13d
mov	r8, qword [rsp+56]
cmp	ebp, r14d
jne	sn_profile_L118
mov	eax, dword [rsp+8]
cmp	r12d, eax
jne	sn_profile_L61
mov	ecx, dword [rsp+272]
mov	edi, dword [rsp+64]
bsr	eax, ecx
lea	edx, [0+rdi*8+16]
xor	eax, 31
add	eax, dword [rsp+264]
lea	esi, [rax+-32]
cmp	esi, edx
jg	sn_profile_L61
sub	eax, 15
sub	edx, 16
cmp	eax, edx
jle	sn_profile_L61
xor	r9d, r9d
mov	rax, qword [rsp]
mov	rdi, qword [rsp+48]
add	qword [rsp+1448], 1
mov	qword [rsp+4224], r9
mov	rbp, rdi
mov	qword [rsp+3856], r9
mov	qword [rsp+3864], r9
mov	qword [rsp+4216], r9
mov	qword [rsp+8520], r9
mov	qword [rsp+8152], r9
mov	qword [rsp+8160], r9
mov	qword [rsp+8512], r9
mov	qword [rsp+1440], rax
mov	eax, ecx
mov	ecx, -24
mov	qword [rsp+1456], rax
sub	ecx, edi
mov	rax, -3750763034362895579
sn_profile_L120:
lea	edx, [rcx+rbp]
cmp	edx, 7
ja	sn_profile_L293
sn_profile_L119:
add	rbp, 1
cmp	rbp, r15
jne	sn_profile_L120
mov	rdi, qword [rbx+16]
mov	rsi, qword [rsp+48]
mov	edx, 9120
mov	qword [rsp+1464], rax
call	sn_copy
mov	rdi, qword [rbx+32]
mov	rdx, qword [rsp+32]
mov	rsi, rbp
call	sn_copy
movsx	rax, dword [rsp+8]
jmp	sn_profile_L59
sn_profile_L185:
mov	edx, 16
jmp	sn_profile_L165
sn_profile_L156:
mov	rdi, qword [rsp+24]
lea	rsi, [rel sn_silk_LBRR_flags_2_iCDF]
call	sn_ec_dec_icdf
add	eax, 1
jmp	sn_profile_L157
sn_profile_L292:
cmp	rdx, 7679
jbe	sn_profile_L61
mov	ebp, 12
mov	eax, 1129008211
jmp	sn_profile_L93
sn_profile_L85:
cmp	rdx, 7679
jbe	sn_profile_L61
mov	ebp, 16
mov	eax, 1112230995
jmp	sn_profile_L93
sn_profile_L84:
cmp	rdx, 3839
jbe	sn_profile_L61
mov	qword [rsp+32], 3840
mov	ebp, 12
mov	r14d, 1
mov	r12d, 20
mov	dword [rsp+8], 960
mov	qword [rsp], 1129008211
mov	dword [rsp+16], 20
jmp	sn_profile_L83
sn_profile_L291:
cmp	rdx, 3839
jbe	sn_profile_L61
mov	qword [rsp], 1112230995
mov	ebp, 16
jmp	sn_profile_L264
sn_profile_L282:
lea	r8, [rel sn_silk_uniform8_iCDF]
lea	rdi, [rel sn_silk_pitch_contour_iCDF]
mov	qword [rdx+2416], r8
cmp	r12d, 10
je	sn_profile_L294
sn_profile_L243:
add	rax, 4296
mov	qword [rdx+2424], rdi
cmp	rsi, rax
je	sn_profile_L111
sn_profile_L267:
mov	rdx, rax
mov	qword [rax+2784], rcx
mov	qword [rdx+2416], r8
cmp	r12d, 10
jne	sn_profile_L243
sn_profile_L294:
lea	r11, [rel sn_silk_pitch_contour_10_ms_iCDF]
add	rax, 4296
mov	qword [rdx+2424], r11
cmp	rsi, rax
jne	sn_profile_L267
jmp	sn_profile_L111
sn_profile_L281:
cmp	rdx, 11519
jbe	sn_profile_L61
mov	dword [rsp+16], 60
mov	ebp, 12
mov	r14d, 3
mov	qword [rsp+32], 11520
mov	dword [rsp+8], 2880
mov	qword [rsp], 1129008211
jmp	sn_profile_L169
sn_profile_L274:
movzx	edx, byte [rax]
xor	rsi, rdx
mov	rdx, 1099511628211
imul	rsi, rdx
jmp	sn_profile_L144
sn_profile_L289:
movzx	edx, byte [rax]
xor	rsi, rdx
mov	rdx, 1099511628211
imul	rsi, rdx
jmp	sn_profile_L97
sn_profile_L285:
lea	rdi, [rel sn_silk_pitch_contour_10_ms_iCDF]
add	rax, 4296
mov	qword [rdx+2424], rdi
cmp	rsi, rax
jne	sn_profile_L266
jmp	sn_profile_L111
sn_profile_L278:
movzx	edx, byte [rax]
xor	rsi, rdx
mov	rdx, 1099511628211
imul	rsi, rdx
jmp	sn_profile_L167
sn_profile_L293:
movzx	edx, byte [rbp+0]
xor	rax, rdx
mov	rdx, 1099511628211
imul	rax, rdx
jmp	sn_profile_L119

section .text
media_opus_silk_decode:
 cld
 jmp sn_paos_silk_transaction

sn_copy:
 jmp memcpy
sn_move:
 mov rax,rdi
 mov rcx,rdx
 cmp rdi,rsi
 jbe .forward
 test rcx,rcx
 jz .done
 lea rdi,[rdi+rcx-1]
 lea rsi,[rsi+rcx-1]
 std
 rep movsb
 cld
 ret
.forward:
 rep movsb
.done:
 ret
sn_set:
 jmp memset
