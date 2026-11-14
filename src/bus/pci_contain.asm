;; MODULE bus/pci_contain
;; LAYER 2
;; EXPORTS pci_contain_root_port, pci_contain_lookup
;; IMPORTS bus/pci, bus/pci_bdf
;; CAPS
;; OWNER saga:bus
; Uncorrected root-port AER: fence the segment-0 subtree, clear IO/MEM/BME and
; disable INTx on every present function, with independent Command readbacks.
; No reset, AER status acknowledgement or recovery. This stops native PCI
; configuration re-arm; it does not by itself prove DMA cessation or drain
; transactions already accepted by a device. That requires the H3 DMA witness.
;
; BSP serialized service context only. One attempt per root-port BDF per boot;
; every outcome is retained. Invalid topology is refused before any write.
; The complete downstream bus interval is fenced, including absent functions,
; so a later enumeration/driver restore cannot arm an unobserved function.
; Bound: <=255 buses *256 functions + the root; never touches another subtree.
;
; Read-only retained row: 16 dwords (64B), status at0:
; 0 unattempted (lookup returns0),1 verified config stop,2 invalid root/header,
; 3 invalid bus interval,4 identity changed,5 readback failed,6 busy/incomplete.
; +4 root identity; +8/+12 secondary/subordinate; +16 present downstream;
; +20 verified downstream; +24 first failed BDF(-1 none);
; +28/+32 root command before/after; +36 root verified (0/1).
PCI_CONTAIN_STRIDE equ 64

; RDI=bus0 packed BDF0..255 -> RAX=read-only row or0. No I/O/mutation.
pci_contain_lookup:
    cmp rdi,255
    ja .none
    lea rax,[rel pci_contain_rows]
    shl rdi,6
    add rax,rdi
    cmp dword [rax],0
    jne .out
.none:
    xor eax,eax
.out:
    ret

; RDI=bus0 root-port BDF. EAX=status1..6. Preserves callee-saved registers.
pci_contain_root_port:
    cmp rdi,255
    ja .invalid
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    mov r12d,edi
    mov rbx,rdi
    shl rbx,6
    lea rax,[rel pci_contain_rows]
    add rbx,rax
    mov eax,[rbx]
    test eax,eax
    jnz .out
    mov dword [rbx],6                     ; publish attempt before I/O
    mov dword [rbx+24],-1
    xor esi,esi
    call pci_bdf_read
    cmp ax,0xffff
    je .bad_port
    test ax,ax
    jz .bad_port
    mov [rbx+4],eax
    mov edi,r12d
    mov esi,8
    call pci_bdf_read
    shr eax,16
    cmp eax,0x0604                       ; bridge class/subclass
    jne .bad_port
    mov edi,r12d
    mov esi,12
    call pci_bdf_read
    shr eax,16
    and eax,0x7f
    cmp eax,1                            ; type1 header, not a spoofed endpoint
    jne .bad_port
    mov edi,r12d
    mov esi,0x10
    call pci_find_cap
    cmp eax,0x40
    jb .bad_port
    cmp eax,0xfc
    ja .bad_port
    mov esi,eax
    mov edi,r12d
    call pci_bdf_read
    shr eax,20
    and eax,15
    cmp eax,4                            ; PCI Express Root Port
    jne .bad_port
    mov edi,r12d
    mov esi,24
    call pci_bdf_read
    test al,al                           ; root primary bus must be0
    jnz .bad_range
    mov ecx,eax
    shr ecx,8
    and ecx,255
    mov [rbx+8],ecx
    shr eax,16
    and eax,255
    mov [rbx+12],eax
    test ecx,ecx                         ; never fence bus0 control/storage
    jz .bad_range
    cmp ecx,eax
    ja .bad_range
    mov r13d,ecx
    shl r13d,8                           ; first downstream BDF
    mov r14d,eax
    inc r14d
    shl r14d,8                           ; exclusive last, can be65536
    ; A malformed overlapping bus0 bridge must not let this port's error
    ; quarantine a sibling's NIC/storage. Check all present type1 bridges.
    xor r15d,r15d
.topology:
    cmp r15d,r12d
    je .topology_next
    mov edi,r15d
    xor esi,esi
    call pci_bdf_read
    cmp ax,0xffff
    je .topology_next
    mov edi,r15d
    mov esi,8
    call pci_bdf_read
    shr eax,16
    cmp eax,0x0604
    jne .topology_next
    mov edi,r15d
    mov esi,12
    call pci_bdf_read
    shr eax,16
    and eax,0x7f
    cmp eax,1
    jne .topology_next
    mov edi,r15d
    mov esi,24
    call pci_bdf_read
    mov ecx,eax
    shr ecx,8
    and ecx,255
    shr eax,16
    and eax,255
    test ecx,ecx
    jz .topology_next
    cmp ecx,eax
    ja .topology_next
    cmp ecx,[rbx+12]
    ja .topology_next
    cmp eax,[rbx+8]
    jae .bad_range                       ; nonempty intersection
.topology_next:
    inc r15d
    cmp r15d,256
    jb .topology
    mov edi,r12d
    xor esi,esi
    call pci_bdf_read
    cmp eax,[rbx+4]
    jne .changed
    ; Fence both before the first stop write. No broad bus0 fence.
    mov edi,r12d
    mov esi,r12d
    call pci_cfg_quarantine
    ; Freeze routing before trusting the interval. A driver changing bridge
    ; buses during discovery must not make us stop the stale child subtree.
    mov edi,r12d
    xor esi,esi
    call pci_bdf_read
    cmp eax,[rbx+4]
    jne .changed
    mov edi,r12d
    mov esi,24
    call pci_bdf_read
    and eax,0xffffff
    mov ecx,[rbx+12]
    shl ecx,16
    mov edx,[rbx+8]
    shl edx,8
    or ecx,edx
    cmp eax,ecx
    jne .changed
    mov edi,r13d
    lea esi,[r14-1]
    call pci_cfg_quarantine
    mov edi,r12d
    mov esi,4
    call pci_bdf_read
    mov [rbx+28],eax
    mov edx,eax
    and edx,0xfff8
    or edx,0x400
    mov edi,r12d
    mov esi,4
    call pci_bdf_write
    mov edi,r12d
    mov esi,4
    call pci_bdf_read
    mov [rbx+32],eax
    test eax,7
    jnz .root_failed
    cmp ax,0xffff
    je .root_failed
    test eax,0x400
    jz .root_failed
    mov dword [rbx+36],1
    jmp .scan
.root_failed:
    mov [rbx+24],r12d
.scan:
    mov edi,r13d
    xor esi,esi
    call pci_bdf_read
    cmp ax,0xffff
    je .next
    inc dword [rbx+16]
    mov r15d,eax                          ; function identity before stop
    mov edi,r13d
    mov esi,4
    call pci_bdf_read
    mov edx,eax
    and edx,0xfff8                        ; do not replay Status W1C bits
    or edx,0x400
    mov edi,r13d
    mov esi,4
    call pci_bdf_write
    mov edi,r13d
    mov esi,4
    call pci_bdf_read
    mov ebp,eax
    mov edi,r13d
    xor esi,esi
    call pci_bdf_read
    cmp eax,r15d                         ; no credit for absent/replaced function
    jne .failed
    test ebp,7
    jnz .failed
    test ebp,0x400
    jz .failed
    inc dword [rbx+20]
    jmp .next
.failed:
    cmp dword [rbx+24],-1
    jne .next
    mov [rbx+24],r13d
.next:
    inc r13d
    cmp r13d,r14d
    jb .scan
    ; Recheck root identity after all downstream readbacks as well.
    mov edi,r12d
    xor esi,esi
    call pci_bdf_read
    cmp eax,[rbx+4]
    jne .changed
    cmp dword [rbx+24],-1
    jne .readback
    mov eax,1
    jmp .publish
.bad_port:
    mov eax,2
    jmp .publish
.bad_range:
    mov eax,3
    jmp .publish
.changed:
    mov eax,4
    jmp .publish
.readback:
    mov eax,5
.publish:
    mov [rbx],eax
.out:
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.invalid:
    mov eax,2
    ret

%include "core/abi/wdata.inc"
%macro WDATA_pci_contain 0
alignb 8
pci_contain_rows: resb 256 * PCI_CONTAIN_STRIDE
%endmacro
WDATA_BSS_DEFER WDATA_pci_contain
