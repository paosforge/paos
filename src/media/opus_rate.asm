;; MODULE media/opus_rate
;; LAYER 4
;; EXPORTS media_opus_rate_get_pulses, media_opus_rate_bits_to_pulses, media_opus_rate_pulses_to_bits, media_opus_rate_cap
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
;
; UNWIRED exact Opus1.5.2 standard48k rate.h/cache/init_caps scalar helpers.
; get_pulses(RDI=pseudo0..40) ->K0..128/-1.
; bits_to_pulses(RDI=band0..20,RSI=signed LM-1..3,RDX=eighthbits0..81600)
; ->pseudo0..rowmax/-1. pulses_to_bits(same band/LM,RDX=pseudo0..rowmax)
; ->eighthbits/-1. LM-1/bands0..7 have no cache and refuse.
; cap(RDI=band0..20,RSI=LM0..3,RDX=channels1/2) ->eighthbit cap/-1.
; Immutable exact tables; no caller pointers/state/FP/alloc/device/runtime.
; Full64 admission; SysV nonvolatiles/RSP preserved,DF0,FP untouched.
; Fixed standard-mode tables only. See OPUS_NATIVE_RATE.md.
; Scalar mapping alone does not prove a decodable frame.
;
; Additional celt.c/modes.c attribution:
; Copyright (c) 2007-2010 Xiph.Org Foundation
; Copyright (c) 2008 Gregory Maxwell
; Written by Jean-Marc Valin and Gregory Maxwell.
;
; /* Copyright (c) 2007-2008 CSIRO
;    Copyright (c) 2007-2009 Xiph.Org Foundation
;    Written by Jean-Marc Valin */
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

media_opus_rate_get_pulses:
 cld
 cmp rdi,40
 ja motrate_bad
 mov eax,edi
 cmp eax,8
 jb .done
 mov ecx,eax
 shr ecx,3
 dec ecx
 and eax,7
 add eax,8
 shl eax,cl
.done:
 ret

media_opus_rate_bits_to_pulses:
 cld
 cmp rdx,81600
 ja motrate_bad
 xor r11d,r11d
 jmp motrate_cache
media_opus_rate_pulses_to_bits:
 cld
 cmp rdx,40
 ja motrate_bad
 mov r11d,1
motrate_cache:
 cmp rdi,20
 ja motrate_bad
 lea rax,[rsi+1]                ; signed LM=-1 represented as UINT64_MAX
 cmp rax,4
 ja motrate_bad
 imul rax,21
 add rax,rdi
 lea r8,[rel motrate_index]
 movsx eax,word [r8+rax*2]
 test eax,eax
 js motrate_bad
 lea r8,[rel motrate_bits]
 add r8,rax
 movzx r9d,byte [r8]           ; maximum pseudo index in this cache row
 test r11d,r11d
 jz .search
 cmp rdx,r9
 ja motrate_bad
 xor eax,eax
 test rdx,rdx
 jz .done
 movzx eax,byte [r8+rdx]
 inc eax
.done:
 ret
.search:
 dec edx                       ; bits--, preserves signed -1 for zero input
 xor eax,eax                   ; lo
 mov ecx,6                     ; LOG_MAX_PSEUDO, fixed iteration count
.loop:
 lea r10d,[rax+r9+1]
 shr r10d,1
 movzx esi,byte [r8+r10]
 cmp esi,edx
 jl .lower
 mov r9d,r10d
 jmp .next
.lower:
 mov eax,r10d
.next:
 dec ecx
 jnz .loop
 mov r10d,-1                   ; conceptual cache[0] cost is -1
 test eax,eax
 jz .zero_cost
 movzx r10d,byte [r8+rax]
.zero_cost:
 mov ecx,edx
 sub ecx,r10d                  ; bits - lower cost
 movzx esi,byte [r8+r9]
 sub esi,edx                   ; upper cost - bits
 cmp ecx,esi
 jle .done                     ; exact midpoint chooses lower index
 mov eax,r9d
 ret

media_opus_rate_cap:
 cld
 cmp rdi,20
 ja motrate_bad
 cmp rsi,3
 ja motrate_bad
 lea rax,[rdx-1]
 cmp rax,1
 ja motrate_bad
 lea rax,[rsi*2]
 add rax,rdx
 dec rax
 imul rax,21
 add rax,rdi
 lea r8,[rel motrate_caps]
 movzx r9d,byte [r8+rax]
 add r9d,64
 imul r9d,edx
 lea r8,[rel motrate_ebands]
 movzx eax,word [r8+rdi*2+2]
 movzx ecx,word [r8+rdi*2]
 sub eax,ecx
 mov ecx,esi
 shl eax,cl                    ; N=(eBands[b+1]-eBands[b])<<LM
 imul eax,r9d
 shr eax,2
 ret
motrate_bad:
 mov rax,-1
 ret

motrate_index:
 dw -1,-1,-1,-1,-1,-1,-1,-1,0,0,0,0,41,41,41,82
 dw 82,123,164,200,222,0,0,0,0,0,0,0,0,41,41,41
 dw 41,123,123,123,164,164,240,266,283,295,41,41,41,41,41,41
 dw 41,41,123,123,123,123,240,240,240,266,266,305,318,328,336,123
 dw 123,123,123,123,123,123,123,240,240,240,240,305,305,305,318,318
 dw 343,351,358,364,240,240,240,240,240,240,240,240,305,305,305,305
 dw 343,343,343,351,351,370,376,382,387
motrate_bits:
 db 40,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7
 db 7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7
 db 7,7,7,7,7,7,7,7,7,40,15,23,28,31,34,36
 db 38,39,41,42,43,44,45,46,47,47,49,50,51,52,53,54
 db 55,55,57,58,59,60,61,62,63,63,65,66,67,68,69,70
 db 71,71,40,20,33,41,48,53,57,61,64,66,69,71,73,75
 db 76,78,80,82,85,87,89,91,92,94,96,98,101,103,105,107
 db 108,110,112,114,117,119,121,123,124,126,128,40,23,39,51,60
 db 67,73,79,83,87,91,94,97,100,102,105,107,111,115,118,121
 db 124,126,129,131,135,139,142,145,148,150,153,155,159,163,166,169
 db 172,174,177,179,35,28,49,65,78,89,99,107,114,120,126,132
 db 136,141,145,149,153,159,165,171,176,180,185,189,192,199,205,211
 db 216,220,225,229,232,239,245,251,21,33,58,79,97,112,125,137
 db 148,157,166,174,182,189,195,201,207,217,227,235,243,251,17,35
 db 63,86,106,123,139,152,165,177,187,197,206,214,222,230,237,250
 db 25,31,55,75,91,105,117,128,138,146,154,161,168,174,180,185
 db 190,200,208,215,222,229,235,240,245,255,16,36,65,89,110,128
 db 144,159,173,185,196,207,217,226,234,242,250,11,41,74,103,128
 db 151,172,191,209,225,241,255,9,43,79,110,138,163,186,207,227
 db 246,12,39,71,99,123,144,164,182,198,214,228,241,253,9,44
 db 81,113,142,168,192,214,235,255,7,49,90,127,160,191,220,247
 db 6,51,95,134,170,203,234,7,47,87,123,155,184,212,237,6
 db 52,97,137,174,208,240,5,57,106,151,192,231,5,59,111,158
 db 202,243,5,55,103,147,187,224,5,60,113,161,206,248,4,65
 db 122,175,224,4,67,127,182,234
motrate_caps:
 db 224,224,224,224,224,224,224,224,160,160,160,160,185,185,185,178
 db 178,168,134,61,37,224,224,224,224,224,224,224,224,240,240,240
 db 240,207,207,207,198,198,183,144,66,40,160,160,160,160,160,160
 db 160,160,185,185,185,185,193,193,193,183,183,172,138,64,38,240
 db 240,240,240,240,240,240,240,207,207,207,207,204,204,204,193,193
 db 180,143,66,40,185,185,185,185,185,185,185,185,193,193,193,193
 db 193,193,193,183,183,172,138,65,39,207,207,207,207,207,207,207
 db 207,204,204,204,204,201,201,201,188,188,176,141,66,40,193,193
 db 193,193,193,193,193,193,193,193,193,193,194,194,194,184,184,173
 db 139,65,39,204,204,204,204,204,204,204,204,201,201,201,201,198
 db 198,198,187,187,175,140,66,40
motrate_ebands:
 dw 0,1,2,3,4,5,6,7,8,10,12,14,16,20,24,28
 dw 34,40,48,60,78,100
