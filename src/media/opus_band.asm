;; MODULE media/opus_band
;; LAYER 4
;; EXPORTS media_opus_band_decode
;; IMPORTS media_opus_partition_recursive_decode, media_opus_tf_shape, media_opus_range_tell, media_opus_range_tell_frac
;; CAPS
;; OWNER rc-codex-av
; UNWIRED bounded Opus1.5.2 quant_band decoder. See OPUS_NATIVE_BAND.md.
; RDI=range64*,RSI=readonly config160*; returns0/-1, full staged transaction.
; /* Copyright (c) 2007-2008 CSIRO
;    Copyright (c) 2007-2009 Xiph.Org Foundation
;    Copyright (c) 2008-2009 Gregory Maxwell
;    Written by Jean-Marc Valin and Gregory Maxwell */
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
; vq.c
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
;
; mathops.c
; /* Copyright (c) 2002-2008 Jean-Marc Valin
;    Copyright (c) 2007-2008 CSIRO
;    Copyright (c) 2007-2009 Xiph.Org Foundation
;    Written by Jean-Marc Valin */
; /**
;    @file mathops.h
;    @brief Various math functions
; */
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
; mathops.h
; /* Copyright (c) 2002-2008 Jean-Marc Valin
;    Copyright (c) 2007-2008 CSIRO
;    Copyright (c) 2007-2009 Xiph.Org Foundation
;    Written by Jean-Marc Valin */
; /**
;    @file mathops.h
;    @brief Various math functions
; */
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
; modes.c
; /* Copyright (c) 2007-2008 CSIRO
;    Copyright (c) 2007-2009 Xiph.Org Foundation
;    Copyright (c) 2008 Gregory Maxwell
;    Written by Jean-Marc Valin and Gregory Maxwell */
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
moband_span:
 test rdi,rdi
 jz moband_bad
 test rdi,rdx
 jnz moband_bad
 mov rax,rdi
 add rax,rsi
 jc moband_bad
 mov r9,rax
 dec r9
 shr r9,47
 jnz moband_bad
 mov [r8],rdi
 mov [r8+8],rax
 xor eax,eax
 ret

media_opus_band_decode:
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,4328
 mov r12,rsp
 mov r13,rsi
 mov r14,rdi
 mov rdi,r13
 mov esi,160
 mov edx,7
 lea r8,[r12+2848]
 call moband_span
 test rax,rax
 jnz .bad
 mov rsi,r13
 lea rdi,[r12+3200]
 mov ecx,20
 rep movsq
 cmp qword [r12+3200],20
 ja .bad
 mov rax,[r12+3208]
 cmp rax,-1
 jl .bad
 cmp rax,3
 jg .bad
 cmp qword [r12+3216],81600
 ja .bad
 mov rax,[r12+3224]
 test rax,rax
 jz .bad
 cmp rax,8
 ja .bad
 lea rcx,[rax-1]
 test rax,rcx
 jnz .bad
 cmp qword [r12+3232],3
 ja .bad
 cmp qword [r12+3240],32767
 ja .bad
 cmp qword [r12+3248],81600
 ja .bad
 mov eax,0xffffffff
 cmp [r12+3256],rax
 ja .bad
 cmp qword [r12+3264],65535
 ja .bad
 lea rsi,[rel moband_ebands]
 mov rax,[r12+3200]
 movzx edx,word [rsi+rax*2+2]
 movzx eax,word [rsi+rax*2]
 sub edx,eax
 mov rcx,[r12+3208]
 cmp rcx,-1
 jne .scale_N
 shr edx,1
 jmp .N_ready
.scale_N:
 shl edx,cl
.N_ready:
 cmp edx,2
 jb .bad
 cmp edx,176
 ja .bad
 mov [r12+3360],rdx
 mov eax,edx
 xor edx,edx
 div dword [r12+3224]
 test edx,edx
 jnz .bad
 mov rdi,r14
 mov esi,64
 mov edx,7
 lea r8,[r12+2864]
 call moband_span
 test rax,rax
 jnz .bad
 call media_opus_range_tell_frac
 test rax,rax
 js .bad
 cmp rax,[r12+3272]
 ja .bad
 cmp dword [r14+48],0
 jne .bad
 mov rax,[r14+8]
 shl rax,6
 cmp [r12+3272],rax
 ja .bad
 mov rdi,[r12+3280]
 mov rsi,[r12+3288]
 mov rax,[r12+3360]
 add rax,rax
 cmp rsi,rax
 jb .bad
 mov edx,1
 lea r8,[r12+2880]
 call moband_span
 test rax,rax
 jnz .bad
 mov rdi,[r12+3312]
 mov rsi,[r12+3320]
 cmp rsi,24
 jb .bad
 mov edx,3
 lea r8,[r12+2896]
 call moband_span
 test rax,rax
 jnz .bad
 mov qword [r12+3400],4
 mov rsi,[r14+8]
 test rsi,rsi
 jz .lowband_span
 mov rdi,[r14]
 xor edx,edx
 lea r8,[r12+2912]
 call moband_span
 test rax,rax
 jnz .bad
 inc qword [r12+3400]
.lowband_span:
 mov rdi,[r12+3296]
 mov rsi,[r12+3304]
 test rdi,rdi
 jnz .lowband_present
 test rsi,rsi
 jnz .bad
 jmp .foldout_span
.lowband_present:
 mov rax,[r12+3360]
 add rax,rax
 cmp rsi,rax
 jb .bad
 mov edx,1
 mov rax,[r12+3400]
 shl rax,4
 lea r8,[r12+2848+rax]
 call moband_span
 test rax,rax
 jnz .bad
 inc qword [r12+3400]
.foldout_span:
 cmp qword [r12+3352],0
 jne .bad
 mov rax,[r12+3328]
 cmp rax,-3
 jl .bad
 cmp rax,3
 jg .bad
 mov rdi,[r12+3336]
 mov rsi,[r12+3344]
 test rdi,rdi
 jnz .foldout_present
 test rsi,rsi
 jnz .bad
 jmp .aliases
.foldout_present:
 mov rax,[r12+3360]
 add rax,rax
 cmp rsi,rax
 jb .bad
 mov edx,1
 mov rax,[r12+3400]
 shl rax,4
 lea r8,[r12+2848+rax]
 call moband_span
 test rax,rax
 jnz .bad
 inc qword [r12+3400]
.aliases:
 xor ebx,ebx
.outer:
 lea r8,[rbx+1]
 mov rax,rbx
 shl rax,4
 lea r9,[r12+2848+rax]
.inner:
 cmp r8,[r12+3400]
 jae .next_outer
 mov rax,r8
 shl rax,4
 lea r10,[r12+2848+rax]
 mov rax,[r9]
 cmp rax,[r10+8]
 jae .next_pair
 mov rax,[r10]
 cmp rax,[r9+8]
 jb .bad
.next_pair:
 inc r8
 jmp .inner
.next_outer:
 inc rbx
 cmp rbx,[r12+3400]
 jb .outer

 ; Private state and copied folding source. All declared spans validated first.
 mov rsi,r14
 mov rdi,r12
 mov ecx,8
 rep movsq
 mov rsi,[r12+3296]
 test rsi,rsi
 jz .no_low
 lea rdi,[r12+544]
 mov rcx,[r12+3360]
 rep movsw
 lea rax,[r12+544]
 mov [r12+3296],rax
 mov rax,[r12+3360]
 add rax,rax
 mov [r12+3304],rax
.no_low:
 mov rax,[r12+3224]             ; initial B
 mov [r12+3600],rax             ; working B
 cmp rax,1
 sete al
 movzx eax,al
 mov [r12+3632],rax             ; longBlocks
 mov rcx,[r12+3224]
 mov eax,1
 shl eax,cl
 dec eax
 cmp [r12+3264],rax             ; active fill only (upstream precondition)
 ja .bad
 mov rax,[r12+3360]
 xor edx,edx
 div qword [r12+3224]
 mov [r12+3608],rax             ; N_B
 mov qword [r12+3616],0         ; recombine
 mov qword [r12+3624],0         ; time_divide
 mov qword [r12+3640],0         ; k
 mov rax,[r12+3328]
 test rax,rax
 jle .recombined
 mov [r12+3616],rax
 mov rcx,rax
 mov rax,[r12+3600]
 shr rax,cl
 test rax,rax
 jz .bad
.recombine_loop:
 mov rcx,[r12+3640]
 mov rdi,[r12+3360]
 shr rdi,cl
 mov esi,1
 shl rsi,cl
 xor edx,edx
 call moband_low_tf
 test rax,rax
 js .bad
 mov eax,[r12+3264]
 mov ecx,eax
 and eax,15
 shr ecx,4
 lea rdx,[rel moband_interleave]
 movzx eax,byte [rdx+rax]
 movzx ecx,byte [rdx+rcx]
 shl ecx,2
 or eax,ecx
 mov [r12+3264],rax
 inc qword [r12+3640]
 mov rax,[r12+3640]
 cmp rax,[r12+3616]
 jb .recombine_loop
 mov rcx,[r12+3616]
 shr qword [r12+3600],cl
 shl qword [r12+3608],cl
.recombined:
 cmp qword [r12+3328],0
 jge .divided
 test qword [r12+3608],1
 jnz .divided
 mov rdi,[r12+3608]
 mov rsi,[r12+3600]
 xor edx,edx
 call moband_low_tf
 test rax,rax
 js .bad
 mov rcx,[r12+3600]
 mov rax,[r12+3264]
 shl rax,cl
 or [r12+3264],rax
 shl qword [r12+3600],1
 shr qword [r12+3608],1
 inc qword [r12+3624]
 inc qword [r12+3328]
 jmp .recombined
.divided:
 cmp qword [r12+3600],16        ; recursive helper domain
 ja .bad
 mov rcx,[r12+3616]
 mov rax,[r12+3600]
 shl rax,cl
 cmp rax,16                    ; TF primitive stride domain
 ja .bad
 cmp qword [r12+3600],1
 je .partition
 mov rdi,[r12+3608]
 shr rdi,cl
 mov rsi,rax
 mov edx,1
 call moband_low_tf
 test rax,rax
 js .bad
.partition:
 mov rax,[r12+3600]
 mov [r12+3224],rax
 lea rax,[r12+192]
 mov [r12+3280],rax
 mov rax,[r12+3360]
 add rax,rax
 mov [r12+3288],rax
 lea rax,[r12+64]
 mov [r12+3312],rax
 mov qword [r12+3320],24
 mov rdi,r12
 lea rsi,[r12+3200]
 call media_opus_partition_recursive_decode
 test rax,rax
 js .bad
 cmp qword [r12+3600],1
 je .undo_time
 mov rcx,[r12+3616]
 mov rdi,[r12+3608]
 shr rdi,cl
 mov rsi,[r12+3600]
 shl rsi,cl
 mov edx,2
 lea rax,[r12+192]
 call moband_tf
 test rax,rax
 js .bad
.undo_time:
 cmp qword [r12+3624],0
 je .undo_recombine
 shr qword [r12+3600],1
 shl qword [r12+3608],1
 mov rcx,[r12+3600]
 mov eax,[r12+84]
 shr eax,cl
 or [r12+84],eax
 mov rdi,[r12+3608]
 mov rsi,[r12+3600]
 xor edx,edx
 lea rax,[r12+192]
 call moband_tf
 test rax,rax
 js .bad
 dec qword [r12+3624]
 jmp .undo_time
.undo_recombine:
 mov qword [r12+3640],0
.uncombine_loop:
 mov rcx,[r12+3640]
 cmp rcx,[r12+3616]
 jae .fold_output
 mov eax,[r12+84]
 cmp eax,15
 ja .bad
 lea rdx,[rel moband_deinterleave]
 movzx eax,byte [rdx+rax]
 mov [r12+84],eax
 mov rdi,[r12+3360]
 shr rdi,cl
 mov esi,1
 shl rsi,cl
 xor edx,edx
 lea rax,[r12+192]
 call moband_tf
 test rax,rax
 js .bad
 inc qword [r12+3640]
 jmp .uncombine_loop
.fold_output:
 mov rcx,[r13+24]              ; restore original active block mask
 mov eax,1
 shl eax,cl
 dec eax
 and [r12+84],eax
 cmp qword [r13+136],0
 je .publish
 ; Exact celt_sqrt(N<<22), all intermediates bounded for N2..176.
 mov eax,[r12+3360]
 shl eax,22
 bsr ecx,eax
 shr ecx,1
 sub ecx,7
 mov ebx,ecx
 add ecx,ecx
 sar eax,cl
 sub eax,32768
 movsx edx,ax
 mov eax,-664
 imul eax,edx
 sar eax,15
 add eax,1699
 movsx eax,ax
 imul eax,edx
 sar eax,15
 sub eax,3011
 movsx eax,ax
 imul eax,edx
 sar eax,15
 add eax,11561
 movsx eax,ax
 imul eax,edx
 sar eax,15
 add eax,23175
 movsx eax,ax
 mov ecx,7
 sub ecx,ebx
 sar eax,cl
 xor ecx,ecx
.scale_fold:
 movsx edx,word [r12+192+rcx*2]
 imul edx,eax
 sar edx,15
 mov [r12+1248+rcx*2],dx
 inc rcx
 cmp rcx,[r12+3360]
 jb .scale_fold
.publish:
 ; Recursive helper validated entropy/caps; transformations consume no entropy.
 lea rsi,[r12+192]
 mov rdi,[r13+80]
 mov rcx,[r12+3360]
 rep movsw
 cmp qword [r13+136],0
 je .publish_meta
 lea rsi,[r12+1248]
 mov rdi,[r13+136]
 mov rcx,[r12+3360]
 rep movsw
.publish_meta:
 lea rsi,[r12+64]
 mov rdi,[r13+112]
 mov ecx,6
 rep movsd
 mov rsi,r12
 mov rdi,r14
 mov ecx,8
 rep movsq
 xor eax,eax
 jmp .done
.bad:
 mov rax,-1
.done:
 add rsp,4328
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; Internal TF adapter uses only private arrays. N0=RDI,stride=RSI,op=EDX.
moband_low_tf:
 mov rax,[r12+3296]
 test rax,rax
 jnz moband_tf
 xor eax,eax
 ret
moband_tf:
 mov [r12+3504],rdi
 mov [r12+3512],rsi
 mov [r12+3520],rdx
 xor ecx,ecx
 test edx,edx
 jz .ordering
 mov rcx,[r12+3632]
.ordering:
 mov [r12+3528],rcx
 mov [r12+3536],rax
 mov [r12+3544],rax
 mov rax,[r12+3360]
 add rax,rax
 mov [r12+3552],rax
 lea rcx,[r12+896]
 mov [r12+3560],rcx
 mov [r12+3568],rax
 mov qword [r12+3576],0
 lea rdi,[r12+3504]
 sub rsp,8
 call media_opus_tf_shape
 add rsp,8
 ret
moband_bad:
 mov rax,-1
 ret
moband_ebands:
 dw 0,1,2,3,4,5,6,7,8,10,12,14,16,20,24,28,34,40,48,60,78,100
moband_interleave:
 db 0,1,1,1,2,3,3,3,2,3,3,3,2,3,3,3
moband_deinterleave:
 db 0,3,12,15,48,51,60,63,192,195,204,207,240,243,252,255
