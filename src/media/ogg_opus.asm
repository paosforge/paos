;; MODULE media/ogg_opus
;; LAYER 4
;; EXPORTS media_ogg_opus_parse
;; IMPORTS media_opus_packet_parse
;; CAPS
;; OWNER rc-codex-av
;
; Private UNWIRED RFC3533/RFC7845 finite single-stream CELT Opus admission.
; RDI=readonly config64: source,bytes,result,result_capacity,scratch,capacity,0,0.
; Result16512 and scratch323712 minimum; full declared spans mutually disjoint,
; mapped/stable/serialized/lower canonical. Config/result/scratch align8.
; 0 success,-1 malformed/span,-2 unsupported,-3 capacity,-4 work quota.
; Every refusal preserves source/config/result; scratch may be dirty and must
; be discarded. No allocation/FP/device/global state. SysV preserved,DF0.
; Source<=307200, pages<=1024,audio packets<=512,packet<=65536,
; decoded samples/channel<=131072. CRC is the Ogg MSB polynomial0x04c11db7.
; Result header128, then512 rows32 {scratch_offset,bytes,samples,frames}.
; Header qwords: magic,channels,preskip,input_rate,gain_signed,serial,pages,
; packets,decoded,initial_granule,final_granule,output_frames,packed_bytes,0,0,0.
; Packet bytes remain original, contiguous in scratch at offsets>=16512.
; Complete EOS required; no resync, holes, chaining,multiplexing,SILK/hybrid/PLC.

OGOP_RESULT_BYTES equ 16512
OGOP_SCRATCH_BYTES equ 323712
ogop_span:                         ; rdi,bytes rsi,alignment mask rdx,row r8
 test rdi,rdi
 jz .bad
 test rsi,rsi
 jz .bad
 test rdi,rdx
 jnz .bad
 mov rax,rdi
 add rax,rsi
 jc .bad
 mov rcx,rax
 dec rcx
 shr rcx,47
 jnz .bad
 mov [r8],rdi
 mov [r8+8],rax
 xor eax,eax
 ret
.bad:
 mov rax,-1
 ret
media_ogg_opus_parse:
 cld
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,728
 mov rbp,rsp
 mov esi,64
 mov edx,7
 lea r8,[rbp+64]
 call ogop_span
 test rax,rax
 jnz .bad
 mov rsi,rdi
 mov rdi,rbp
 mov ecx,8
 rep movsq
 mov rax,[rbp+48]
 or rax,[rbp+56]
 jnz .bad
 mov rsi,[rbp+8]
 cmp rsi,27
 jb .bad
 cmp rsi,307200
 ja .quota
 mov rdi,[rbp]
 xor edx,edx
 lea r8,[rbp+80]
 call ogop_span
 test rax,rax
 jnz .bad
 mov rdi,[rbp+16]
 mov rsi,[rbp+24]
 cmp rsi,OGOP_RESULT_BYTES
 jb .capacity
 cmp rsi,1048576
 ja .quota
 mov edx,7
 lea r8,[rbp+96]
 call ogop_span
 test rax,rax
 jnz .bad
 mov rdi,[rbp+32]
 mov rsi,[rbp+40]
 cmp rsi,OGOP_SCRATCH_BYTES
 jb .capacity
 cmp rsi,1048576
 ja .quota
 lea r8,[rbp+112]
 mov edx,7
 call ogop_span
 test rax,rax
 jnz .bad
 xor ecx,ecx
.pair_a:
 lea edx,[ecx+16]
.pair_b:
 mov rax,[rbp+64+rcx]
 cmp rax,[rbp+72+rdx]
 jae .pair_next
 mov rax,[rbp+64+rdx]
 cmp rax,[rbp+72+rcx]
 jb .bad
.pair_next:
 add edx,16
 cmp edx,64
 jb .pair_b
 add ecx,16
 cmp ecx,48
 jb .pair_a
 mov r12,[rbp]
 mov r13,r12
 add r13,[rbp+8]
 mov r14,[rbp+16]
 mov r15,[rbp+32]
 mov rdi,r15
 xor eax,eax
 mov ecx,OGOP_RESULT_BYTES/8
 rep stosq
 lea rdi,[rbp+128]
 mov ecx,(296-128)/8
 rep stosq
 mov qword [rbp+208],OGOP_RESULT_BYTES ; packet start
 mov qword [rbp+224],OGOP_RESULT_BYTES ; packed cursor
 mov [rbp+128],r12
.page:
 mov rbx,[rbp+128]
 mov rax,r13
 sub rax,rbx
 cmp rax,27
 jb .bad
 cmp dword [rbx],0x5367674f
 jne .bad
 cmp byte [rbx+4],0
 jne .unsupported
 movzx eax,byte [rbx+5]
 cmp eax,7
 ja .bad
 mov [rbp+280],rax
 mov rax,[rbx+6]
 mov [rbp+272],rax
 movzx eax,byte [rbx+26]
 mov [rbp+168],rax
 lea rdi,[rbx+27+rax]
 cmp rdi,r13
 ja .bad
 mov [rbp+152],rdi
 xor ecx,ecx
 xor edx,edx
.sum:
 cmp rcx,[rbp+168]
 jae .sum_done
 movzx eax,byte [rbx+27+rcx]
 add edx,eax
 inc ecx
 jmp .sum
.sum_done:
 add rdi,rdx
 cmp rdi,r13
 ja .bad
 mov [rbp+144],rdi
 ; Compute the actual page CRC with its four stored CRC bytes treated as0.
 xor r8d,r8d
 xor ecx,ecx
.crc_byte:
 lea rax,[rbx+rcx]
 cmp rax,rdi
 jae .crc_done
 xor eax,eax
 cmp ecx,22
 jb .crc_read
 cmp ecx,26
 jb .crc_zero
.crc_read:
 movzx eax,byte [rbx+rcx]
.crc_zero:
 shl eax,24
 xor r8d,eax
 mov edx,8
.crc_bit:
 shl r8d,1
 jnc .crc_next
 xor r8d,0x04c11db7
.crc_next:
 dec edx
 jnz .crc_bit
 inc ecx
 jmp .crc_byte
.crc_done:
 cmp r8d,[rbx+22]
 jne .bad
 cmp qword [rbp+192],0
 jne .later
 cmp qword [rbp+280],2
 jne .bad
 cmp dword [rbx+18],0
 jne .bad
 mov eax,[rbx+14]
 mov [rbp+184],rax
 mov [r15+40],rax
 jmp .seq
.later:
 test byte [rbx+5],2
 jnz .bad
 mov eax,[rbx+14]
 cmp rax,[rbp+184]
 jne .unsupported
 mov eax,[rbx+5]
 and eax,1
 cmp qword [rbp+216],0
 setne dl
 movzx edx,dl
 cmp eax,edx
 jne .bad
.seq:
 mov eax,[rbx+18]
 cmp rax,[rbp+176]
 jne .bad
 inc qword [rbp+176]
 inc qword [rbp+192]
 cmp qword [rbp+192],1024
 ja .quota
 mov qword [rbp+160],0
 mov rax,[rbp+232]
 mov [rbp+288],rax
 ; bit8 marks a completed header on this page (not an on-wire flag).
.segment:
 mov rcx,[rbp+160]
 cmp rcx,[rbp+168]
 jae .page_done
 movzx ecx,byte [rbx+27+rcx]
 mov rax,[rbp+216]
 add rax,rcx
 cmp rax,65536
 ja .quota
 mov [rbp+216],rax
 mov rax,[rbp+224]
 add rax,rcx
 cmp rax,OGOP_SCRATCH_BYTES
 ja .quota
 mov [rbp+224],rax
 lea rdi,[r15+rax]
 sub rdi,rcx
 mov rsi,[rbp+152]
 add [rbp+152],rcx
 rep movsb
 mov rcx,[rbp+160]
 inc qword [rbp+160]
 cmp byte [rbx+27+rcx],255
 je .segment
 call .packet
 mov qword [rbp+216],0
 mov rax,[rbp+224]
 mov [rbp+208],rax
 jmp .segment
.page_done:
 mov rax,[rbp+232]
 cmp rax,[rbp+288]
 jne .audio_gp
 test qword [rbp+280],256
 jnz .header_gp
 test qword [rbp+280],4
 jnz .nil_eos
 cmp qword [rbp+272],-1
 jne .bad
 jmp .page_next
.header_gp:
 cmp qword [rbp+272],0
 jne .bad
 jmp .page_next
.nil_eos:
 cmp qword [rbp+168],0
 jne .bad
 cmp qword [rbp+264],1
 jne .bad
 mov rax,[rbp+272]
 cmp rax,[rbp+256]
 jne .bad
 jmp .page_next
.audio_gp:
 mov rax,[rbp+272]
 test rax,rax
 js .bad
 cmp qword [rbp+264],0
 jne .known_gp
 mov qword [rbp+264],1
 xor edx,edx
 cmp rax,[rbp+240]
 jae .gp_base
 test qword [rbp+280],4
 jz .bad
 jmp .base_ready
.gp_base:
 mov rdx,rax
 sub rdx,[rbp+240]
.base_ready:
 mov [rbp+248],rdx
.known_gp:
 mov rdx,[rbp+248]
 add rdx,[rbp+240]
 jo .bad
 cmp rax,rdx
 ja .bad
 test qword [rbp+280],4
 jnz .eos_gp
 cmp rax,rdx
 jne .bad
.eos_gp:
 cmp rax,[rbp+256]
 jb .bad
 mov [rbp+256],rax
.page_next:
 mov rax,[rbp+144]
 test qword [rbp+280],4
 jnz .finish
 mov [rbp+128],rax
 jmp .page
.finish:
 cmp rax,r13
 jne .unsupported
 cmp qword [rbp+216],0
 jne .bad
 cmp qword [rbp+232],0
 je .bad
 cmp qword [rbp+200],2
 jne .bad
 mov rax,[rbp+256]
 mov [r15+80],rax
 sub rax,[rbp+248]
 jc .bad
 sub rax,[r15+16]
 jc .bad
 mov [r15+88],rax
 mov rax,[rbp+248]
 mov [r15+72],rax
 mov rax,[rbp+240]
 mov [r15+64],rax
 mov rax,[rbp+232]
 mov [r15+56],rax
 mov rax,[rbp+192]
 mov [r15+48],rax
 mov rax,[rbp+224]
 sub rax,OGOP_RESULT_BYTES
 mov [r15+96],rax
 mov qword [r15],0x314f4747
 mov rdi,r14
 mov rsi,r15
 mov ecx,OGOP_RESULT_BYTES/8
 rep movsq
 xor eax,eax
 jmp .done
.packet:
 mov rax,[rbp+200]
 cmp eax,0
 je .head
 cmp eax,1
 je .tags
 mov rcx,[rbp+232]
 cmp rcx,512
 jae .quota
 cmp qword [rbp+216],0
 je .bad
 mov rdi,[rbp+208]
 add rdi,r15
 movzx eax,byte [rdi]
 xor edx,edx                 ; CELT0;20ms1/2/3;10ms4/5/6;40ms7/8/9;60ms10/11/12
 test eax,128
 jnz .codec
 and eax,252
 mov edx,eax
 shr edx,3
 and edx,3
 cmp edx,1
 je .twenty_kind
 test edx,edx
 jz .ten_kind
 imul edx,3                  ;40ms6,60ms9 plus NB/WB/MB1/2/3
 jmp .duration_kind
.ten_kind:
 mov edx,3
 jmp .duration_kind
.twenty_kind:
 xor edx,edx
.duration_kind:
 mov ecx,eax
 shr ecx,2
 and ecx,1
 inc ecx
 cmp [r15+8],rcx
 jne .unsupported           ; exact original/coded channels, no mode switch
 test eax,4
 jz .mono_kind
 add edx,12                 ; stereo kinds13..24 bind both histories
.mono_kind:
 and eax,~28
 cmp eax,0                   ; NB mono10/20/40/60ms
 je .silk_kind
 cmp eax,64                  ; WB mono10/20/40/60ms
 je .wide_kind
 cmp eax,32                  ; MB mono10/20/40/60ms
 jne .unsupported
 inc edx
.wide_kind:
 inc edx
.silk_kind:
 inc edx
.codec:
 cmp qword [rbp+232],0
 je .first_codec
 cmp [r15+104],rdx
 je .first_codec
 ; Only mono10/20ms within one band can change history. Preserve existing
 ; homogeneous kinds; mixed NB/WB/MB files use25/26/27 respectively.
 mov rax,[r15+104]
 cmp edx,1
 jb .unsupported
 cmp edx,6
 ja .unsupported
 cmp rax,25
 jb .old_short_kind
 cmp rax,27
 ja .unsupported
 sub eax,24                 ; mixed kind -> same band's20ms kind
 jmp .short_band
.old_short_kind:
 cmp rax,1
 jb .unsupported
 cmp rax,6
 ja .unsupported
 cmp eax,3
 jbe .short_band
 sub eax,3
.short_band:
 cmp edx,3
 jbe .new_short_band
 sub edx,3
.new_short_band:
 cmp eax,edx
 jne .unsupported
 add edx,24
.first_codec:
 mov [r15+104],rdx
 mov rsi,[rbp+216]
 lea rdx,[rbp+296]
 sub rsp,8
 call media_opus_packet_parse
 add rsp,8
 test rax,rax
 jnz .bad
 mov ecx,[rbp+296+8]
 xor edx,edx
.frames:
 cmp edx,ecx
 jae .frames_ok
 cmp dword [rbp+296+36+rdx*8],2
 jb .unsupported
 inc edx
 jmp .frames
.frames_ok:
 mov eax,[rbp+296+16]
 add [rbp+240],rax
 cmp qword [rbp+240],131072
 ja .quota
 mov rcx,[rbp+232]
 shl rcx,5
 lea rdi,[r15+128+rcx]
 mov rax,[rbp+208]
 stosq
 mov rax,[rbp+216]
 stosq
 mov eax,[rbp+296+16]
 stosq
 mov eax,[rbp+296+8]
 stosq
 inc qword [rbp+232]
 ret
.head:
 cmp qword [rbp+192],1
 jne .bad
 cmp qword [rbp+168],1
 jne .bad
 cmp qword [rbp+216],19
 jne .unsupported
 mov rdi,[rbp+208]
 add rdi,r15
 mov rax,0x646165487375704f
 cmp [rdi],rax
 jne .bad
 cmp byte [rdi+8],1
 jne .unsupported
 movzx eax,byte [rdi+9]
 dec eax
 cmp eax,1
 ja .unsupported
 inc eax
 mov [r15+8],rax
 cmp byte [rdi+18],0
 jne .unsupported
 movzx eax,word [rdi+10]
 mov [r15+16],rax
 mov eax,[rdi+12]
 mov [r15+24],rax
 movsx rax,word [rdi+16]
 mov [r15+32],rax
 mov qword [rbp+200],1
 or qword [rbp+280],256
 ret
.tags:
 mov rsi,[rbp+208]
 add rsi,r15
 mov rdx,[rbp+216]
 cmp rdx,16
 jb .bad
 add rdx,rsi
 mov rax,0x736761547375704f
 cmp [rsi],rax
 jne .bad
 mov eax,[rsi+8]
 lea rsi,[rsi+12+rax]
 lea rax,[rsi+4]
 cmp rax,rdx
 ja .bad
 mov ecx,[rsi]
 add rsi,4
 mov rax,rdx
 sub rax,rsi
 shr rax,2
 cmp rcx,rax
 ja .bad
.tag_loop:
 test ecx,ecx
 jz .tag_done
 lea rax,[rsi+4]
 cmp rax,rdx
 ja .bad
 mov eax,[rsi]
 lea rsi,[rsi+4+rax]
 cmp rsi,rdx
 ja .bad
 dec ecx
 jmp .tag_loop
.tag_done:
 mov rax,[rbp+160]
 cmp rax,[rbp+168]
 jne .bad
 mov qword [rbp+200],2
 or qword [rbp+280],256
 ret
.bad:
 mov rax,-1
 jmp .done
.unsupported:
 mov rax,-2
 jmp .done
.capacity:
 mov rax,-3
 jmp .done
.quota:
 mov rax,-4
.done:
 mov rsp,rbp
 add rsp,728
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 cld
 ret
