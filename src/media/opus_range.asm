;; MODULE media/opus_range
;; LAYER 4
;; EXPORTS media_opus_range_init, media_opus_range_bit, media_opus_range_icdf, media_opus_range_uint, media_opus_range_bits, media_opus_range_tell, media_opus_range_tell_frac, media_opus_range_decode, media_opus_range_update
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
;
; Private UNWIRED native Opus entropy primitives, ported from Xiph Opus1.5.2
; celt/entdec.c and entcode.c (RFC6716 section4.1). No SILK/CELT synthesis,
; PCM, packet admission, allocation, globals, device or floating-point use.
; The retained upstream license below covers the port and threshold table.
;
; Stable caller-owned state64* is RDI throughout; mapped lower-canonical,
; 8-byte aligned, disjoint from the immutable frame span and ICDF table.
; init(RDI=state,RSI=frame,RDX=truthful frame bytes0..1275) -> 0/-1.
; Zero bytes permits a null frame and performs no input read.
; bit(RDI,RSI=logp1..15) -> bit0/1/-1.
; icdf(RDI,RSI=u8 table,RDX=count1..256,RCX=precision1..8) -> index/-1.
; uint(RDI,RSI=exclusive bound2..0xffffffff) -> unsigned symbol/-1.
; bits(RDI,RSI=raw count1..25) -> unsigned symbol/-1.
; tell(RDI) -> rounded consumed bits/-1; tell_frac -> eighth-bits/-1.
; decode(RDI,RSI=total2..65536) -> cumulative symbol/-1, no mutation.
; update(RDI,RSI=low,RDX=high,RCX=total2..65536) -> 0/-1.
; update recomputes the split factor and checks the CURRENT decoded symbol is
; in [low,high). No hidden pending factor or change to state64's reserved bytes.
; Caller serializes the pair; any intervening entropy operation requires decoding
; again. General division equals ec_decode_bin exactly for power-of-two totals.
; Full-width argument/span checks; -1 leaves state and all inputs unchanged.
; State64 layout: u64 frame,length; u32 offs,end_offs,window,available,total,
; rng,val,rem,error,magic,reserved0,reserved1. No hidden borrowed table pointer.
; State is serialized and not a security boundary against arbitrary writes.
; SysV nonvolatile GPR/RSP preserved; DF0 on every exit; FP state untouched.
;
; Opus deliberately pads exhausted entropy/raw input with zeros and permits
; head/tail byte overlap. Physical exhaustion is NOT itself an error. Codec
; consumers must enforce their own symbol/bit budget with tell/tell_frac.
; An out-of-range uint clamps to bound-1 and latches error1 exactly as Xiph;
; later operations retain that sticky error. No primitive implies decodable PCM.
; Counter guard refuses before signed/fractional accounting can overflow.
;
; /* Copyright (c) 2001-2011 Timothy B. Terriberry
;    Copyright (c) 2008-2009 Xiph.Org Foundation */
; /*
;    Redistribution and use in source and binary forms, with or without
;    modification, are permitted provided that the following conditions
;    are met:
;
;    - Redistributions of source code must retain the above copyright
;    notice, this list of conditions and the following disclaimer.
;
;    - Redistributions in binary form must reproduce the above copyright
;    notice, this list of conditions and the following disclaimer in the
;    documentation and/or other materials provided with the distribution.
;
;    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;    ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
;    OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
;    EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
;    PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
;    PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
;    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;    NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
; */
;

MOPR_BYTES equ 64
MOPR_MAGIC equ 0x3152504f
MOPR_BOT equ 0x00800000
MOPR_TOP equ 0x80000000

; State pointer only. Preserve public arguments; R8 becomes state span end.
mopr_state_span:
 test rdi,rdi
 jz .bad
 test dil,7
 jnz .bad
 mov r8,rdi
 add r8,MOPR_BYTES
 jc .bad
 mov rax,r8
 dec rax
 shr rax,47
 jnz .bad
 xor eax,eax
 ret
.bad:
 mov rax,-1
 ret

; Current initialized state invariants. No writes, including on refusal.
; Preserve RSI/RDX/RCX, use only volatile scratch R8..R11/RAX.
mopr_validate:
 push rcx
 call mopr_state_span
 test rax,rax
 jnz .bad
 cmp dword [rdi+52],MOPR_MAGIC
 jne .bad
 cmp qword [rdi+56],0
 jne .bad
 mov r9,[rdi+8]
 cmp r9,1275
 ja .bad
 mov eax,[rdi+16]
 cmp rax,r9
 ja .bad
 mov eax,[rdi+20]
 cmp rax,r9
 ja .bad
 mov ecx,[rdi+28]
 cmp ecx,31
 ja .bad
 mov eax,[rdi+24]
 shr eax,cl
 test eax,eax
 jnz .bad
 cmp dword [rdi+32],33
 jb .bad
 cmp dword [rdi+32],0x0fffff00
 ja .bad
 mov eax,[rdi+36]
 cmp eax,MOPR_BOT
 jbe .bad
 cmp eax,MOPR_TOP
 ja .bad
 cmp [rdi+40],eax
 jae .bad
 cmp dword [rdi+44],255
 ja .bad
 cmp dword [rdi+48],1
 ja .bad
 mov r10,[rdi]
 mov rax,r10
 shr rax,47
 jnz .bad
 test r9,r9
 jz .ok
 test r10,r10
 jz .bad
 mov r11,r10
 add r11,r9
 jc .bad
 mov rax,r11
 dec rax
 shr rax,47
 jnz .bad
 cmp rdi,r11
 jae .ok
 cmp r10,r8
 jb .bad
.ok:
 xor eax,eax
 pop rcx
 ret
.bad:
 mov rax,-1
 pop rcx
 ret

; Read forward with implicit zero padding, advancing only inside true storage.
mopr_read:
 mov eax,[rdi+16]
 cmp rax,[rdi+8]
 jae .zero
 mov r8,[rdi]
 movzx eax,byte [r8+rax]
 inc dword [rdi+16]
 ret
.zero:
 xor eax,eax
 ret

; Normalize after a nonempty interval operation. Preserves RSI/RDX/RCX/R11.
mopr_normalize:
 push rdx
.again:
 cmp dword [rdi+36],MOPR_BOT
 ja .done
 add dword [rdi+32],8
 shl dword [rdi+36],8
 mov r9d,[rdi+44]
 shl r9d,8
 call mopr_read
 mov [rdi+44],eax
 or r9d,eax
 shr r9d,1
 not r9d
 and r9d,255
 mov eax,[rdi+40]
 shl eax,8
 add eax,r9d
 and eax,0x7fffffff
 mov [rdi+40],eax
 jmp .again
.done:
 pop rdx
 ret

media_opus_range_init:
 cld
 call mopr_state_span
 test rax,rax
 jnz mopr_bad
 cmp rdx,1275
 ja mopr_bad
 mov rax,rsi
 shr rax,47
 jnz mopr_bad
 test rdx,rdx
 jz .valid
 test rsi,rsi
 jz mopr_bad
 mov r9,rsi
 add r9,rdx
 jc mopr_bad
 mov rax,r9
 dec rax
 shr rax,47
 jnz mopr_bad
 cmp rdi,r9
 jae .valid
 cmp rsi,r8
 jb mopr_bad
.valid:
 mov [rdi],rsi
 mov [rdi+8],rdx
 mov qword [rdi+16],0
 mov qword [rdi+24],0
 mov dword [rdi+32],9
 mov dword [rdi+36],128
 mov qword [rdi+40],0
 mov dword [rdi+48],0
 mov dword [rdi+52],MOPR_MAGIC
 mov qword [rdi+56],0
 call mopr_read
 mov [rdi+44],eax
 shr eax,1
 mov r9d,127
 sub r9d,eax
 mov [rdi+40],r9d
 call mopr_normalize
 xor eax,eax
 ret

media_opus_range_bit:
 cld
 cmp rsi,1
 jb mopr_bad
 cmp rsi,15
 ja mopr_bad
 call mopr_validate
 test rax,rax
 jnz mopr_bad
 mov ecx,esi
 mov eax,[rdi+36]
 mov edx,eax
 shr edx,cl
 mov r11d,1
 cmp [rdi+40],edx
 jb .one
 xor r11d,r11d
 sub [rdi+40],edx
 sub eax,edx
 mov edx,eax
.one:
 mov [rdi+36],edx
 call mopr_normalize
 mov eax,r11d
 ret

media_opus_range_icdf:
 cld
 cmp rdx,1
 jb mopr_bad
 cmp rdx,256
 ja mopr_bad
 cmp rcx,1
 jb mopr_bad
 cmp rcx,8
 ja mopr_bad
 call mopr_validate
 test rax,rax
 jnz mopr_bad
 test rsi,rsi
 jz mopr_bad
 mov r9,rsi
 add r9,rdx
 jc mopr_bad
 mov rax,r9
 dec rax
 shr rax,47
 jnz mopr_bad
 cmp rdi,r9
 jae .span_ok
 cmp rsi,r8
 jb mopr_bad
.span_ok:
 mov r10d,1
 shl r10d,cl
 xor r11d,r11d
.check_table:
 movzx eax,byte [rsi+r11]
 cmp eax,r10d
 ja .table_bad
 mov r10d,eax
 inc r11d
 cmp r11,rdx
 jb .check_table
 test eax,eax
 jnz .table_bad
 ; All table bytes validated before any mutation. Last0 guarantees termination.
 mov r8d,[rdi+36]
 mov r9d,r8d
 shr r9d,cl
 xor r11d,r11d
.decode:
 mov r10d,r8d
 movzx r8d,byte [rsi+r11]
 imul r8d,r9d
 cmp [rdi+40],r8d
 jae .found
 inc r11d
 jmp .decode
.found:
 sub [rdi+40],r8d
 sub r10d,r8d
 mov [rdi+36],r10d
 call mopr_normalize
 mov eax,r11d
 ret
.table_bad:
 mov rax,-1
 ret

; Raw bits from the back, little-endian bit order, matching ec_dec_bits.
; Internal use assumes checked state/count; returns EAX, clobbers volatile regs.
mopr_bits:
 mov ecx,[rdi+28]
 mov r9d,[rdi+24]
 cmp rcx,rsi
 jae .extract
.refill:
 mov eax,[rdi+20]
 xor r10d,r10d
 cmp rax,[rdi+8]
 jae .pad
 inc eax
 mov [rdi+20],eax
 mov r8,[rdi+8]
 sub r8,rax
 add r8,[rdi]
 movzx r10d,byte [r8]
.pad:
 shl r10d,cl
 or r9d,r10d
 add ecx,8
 cmp ecx,24
 jbe .refill
.extract:
 sub ecx,esi
 mov [rdi+28],ecx
 mov ecx,esi
 mov eax,1
 shl eax,cl
 dec eax
 and eax,r9d
 shr r9d,cl
 mov [rdi+24],r9d
 add [rdi+32],esi
 ret

media_opus_range_bits:
 cld
 cmp rsi,1
 jb mopr_bad
 cmp rsi,25
 ja mopr_bad
 call mopr_validate
 test rax,rax
 jnz mopr_bad
 jmp mopr_bits

media_opus_range_uint:
 cld
 cmp rsi,2
 jb mopr_bad
 mov eax,0xffffffff
 cmp rsi,rax
 ja mopr_bad
 call mopr_validate
 test rax,rax
 jnz mopr_bad
 push r12
 push r13
 push r14
 mov r12d,esi
 dec r12d                         ; max symbol
 bsr ecx,r12d
 inc ecx
 xor r13d,r13d
 cmp ecx,8
 jbe .direct
 lea r13d,[rcx-8]                  ; raw low bits
 mov ecx,r13d
 mov esi,r12d
 shr esi,cl
 inc esi                          ; range-coded high alphabet
.direct:
 ; ec_decode(ft): ext=rng/ft, s=ft-min(val/ext+1,ft).
 mov r14d,esi
 mov eax,[rdi+36]
 xor edx,edx
 div r14d
 mov r8d,eax                       ; ext
 mov eax,[rdi+40]
 xor edx,edx
 div r8d
 inc eax
 cmp eax,r14d
 cmova eax,r14d
 mov r11d,r14d
 sub r11d,eax                      ; symbol s
 ; ec_dec_update(s,s+1,ft), retaining initial-interval remainder.
 dec eax                          ; ft-s-1
 imul eax,r8d
 sub [rdi+40],eax
 test r11d,r11d
 jz .first
 mov [rdi+36],r8d
 jmp .normalize
.first:
 sub [rdi+36],eax
.normalize:
 call mopr_normalize
 mov r14d,r11d
 test r13d,r13d
 jz .result
 mov esi,r13d
 call mopr_bits
 mov ecx,r13d
 shl r14d,cl
 or r14d,eax
 cmp r14d,r12d
 jbe .result
 mov dword [rdi+48],1
 mov r14d,r12d
.result:
 mov eax,r14d
 pop r14
 pop r13
 pop r12
 ret

; Split interval primitives for the codec's Laplace consumer. General total
; bound keeps ext nonzero for every validated normalized range.
media_opus_range_decode:
 cld
 cmp rsi,2
 jb mopr_bad
 cmp rsi,65536
 ja mopr_bad
 call mopr_validate
 test rax,rax
 jnz mopr_bad
 mov eax,[rdi+36]
 xor edx,edx
 div esi
 mov r8d,eax
 mov eax,[rdi+40]
 xor edx,edx
 div r8d
 inc eax
 cmp eax,esi
 cmova eax,esi
 mov edx,esi
 sub edx,eax
 mov eax,edx
 ret

media_opus_range_update:
 cld
 cmp rcx,2
 jb mopr_bad
 cmp rcx,65536
 ja mopr_bad
 cmp rsi,rdx
 jae mopr_bad
 cmp rdx,rcx
 ja mopr_bad
 call mopr_validate
 test rax,rax
 jnz mopr_bad
 mov r11d,edx                     ; high
 mov r10d,esi                     ; low
 mov r9d,ecx                      ; total
 mov eax,[rdi+36]
 xor edx,edx
 div r9d
 mov r8d,eax                      ; ext
 mov eax,[rdi+40]
 xor edx,edx
 div r8d
 inc eax
 cmp eax,r9d
 cmova eax,r9d
 mov ecx,r9d
 sub ecx,eax                      ; current cumulative symbol
 cmp ecx,r10d
 jb mopr_bad
 cmp ecx,r11d
 jae mopr_bad
 mov eax,r9d
 sub eax,r11d
 imul eax,r8d
 sub [rdi+40],eax
 test r10d,r10d
 jz .first
 sub r11d,r10d
 imul r11d,r8d
 mov [rdi+36],r11d
 jmp .normalize
.first:
 sub [rdi+36],eax                  ; preserve division remainder in first interval
.normalize:
 call mopr_normalize
 xor eax,eax
 ret

media_opus_range_tell:
 cld
 call mopr_validate
 test rax,rax
 jnz mopr_bad
 bsr ecx,[rdi+36]
 inc ecx
 mov eax,[rdi+32]
 sub eax,ecx
 ret

media_opus_range_tell_frac:
 cld
 call mopr_validate
 test rax,rax
 jnz mopr_bad
 mov edx,[rdi+36]
 bsr ecx,edx
 inc ecx
 mov r9d,ecx
 sub ecx,16
 shr edx,cl
 mov r10d,edx
 shr r10d,12
 sub r10d,8
 lea r8,[rel mopr_correction]
 cmp edx,[r8+r10*4]
 seta al
 movzx eax,al
 add r10d,eax
 mov eax,[rdi+32]
 sub eax,r9d
 shl eax,3
 sub eax,r10d
 ret

mopr_bad:
 mov rax,-1
 ret

align 4
mopr_correction:
 dd 35733,38967,42495,46340,50535,55109,60097,65535
