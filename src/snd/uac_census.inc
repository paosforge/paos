; Pure retained UAC owner observation. RDI=distinct mapped40B output.
; Ten u32s: owner phase,mode,activation-success(UAC1)/prepare-state(UAC2),
; AC interface,AS interface,AS alternate,raw AC class24,raw AS class24,
; owner generation,flags (1=no accepted metadata,2=record custody mismatch,
; 4=unknown owner mode,8=owner phase/mode/generation changed while copying).
; No controller/time/owner callback, probe, admission or selection change.
%ifndef PAOS_UAC_CENSUS_INC
%define PAOS_UAC_CENSUS_INC 1
%macro UAC_CENSUS 1
    mov eax,[rel %1_phase]
    mov [rdi],eax
    mov eax,[rel %1_mode]
    mov [rdi+4],eax
    mov r9d,eax
    mov eax,[rel %1_generation]
    mov [rdi+32],eax
    xor r8d,r8d
    cmp r9d,1
    je %%uac2
    cmp r9d,2
    jbe %%uac1
    mov r8d,4
    mov qword [rdi+8],0
    mov qword [rdi+16],0
    mov qword [rdi+24],0
    jmp %%done
%%uac1:
    lea rsi,[rel %1_activation]
    mov eax,[rsi+136]
    mov [rdi+8],eax
    mov eax,[rsi+68]
    mov [rdi+12],eax
    mov eax,[rsi]
    mov [rdi+16],eax
    mov eax,[rsi+4]
    mov [rdi+20],eax
    mov eax,[rsi+120]
    mov [rdi+24],eax
    mov eax,[rsi+124]
    mov [rdi+28],eax
    mov eax,[rel %1_address]
    cmp eax,[rsi+140]
    jne %%mismatch
    mov rax,[rel %1_hc]
    cmp rax,[rsi+144]
    jne %%mismatch
    mov eax,[rdi+32]
    cmp eax,[rsi+152]
    jne %%mismatch
    jmp %%metadata
%%uac2:
    lea rsi,[rel %1_uac2_context]
    mov eax,[rsi+88]
    mov [rdi+8],eax
    mov eax,[rsi+144+168]
    mov [rdi+12],eax
    mov eax,[rsi+144+172]
    mov [rdi+16],eax
    mov eax,[rsi+144+176]
    mov [rdi+20],eax
    mov eax,[rsi+408]
    mov [rdi+24],eax
    mov eax,[rsi+412]
    mov [rdi+28],eax
    cmp dword [rsi],512
    jne %%mismatch
    cmp dword [rsi+4],1
    jne %%mismatch
    cmp dword [rsi+144+160],1
    jne %%mismatch
    mov eax,[rel %1_address]
    cmp rax,[rsi+16]
    jne %%mismatch
    mov rax,[rel %1_hc]
    cmp rax,[rsi+8]
    jne %%mismatch
    mov eax,[rdi+32]
    cmp rax,[rsi+56]
    je %%metadata
%%mismatch:
    or r8d,2
%%metadata:
    cmp dword [rdi+24],0
    je %%missing
    cmp dword [rdi+28],0
    jne %%done
%%missing:
    or r8d,1
%%done:
    mov eax,[rel %1_phase]
    cmp eax,[rdi]
    jne %%changed
    mov eax,[rel %1_mode]
    cmp eax,[rdi+4]
    jne %%changed
    mov eax,[rel %1_generation]
    cmp eax,[rdi+32]
    je %%store
%%changed:
    or r8d,8
%%store:
    mov [rdi+36],r8d
    ret
%endmacro
%endif
