; Shared native read-only group predicates. Included by either hardware backend.
; OWNER rc-codex-av
%ifndef IOMMU_GUEST_GROUP_INC
%define IOMMU_GUEST_GROUP_INC
%include "hv/pcia_grp.inc"

%include "hv/iommu_guest_group_member.inc"

; RDI frozen record, RAX metadata start, RDX length -> EAX1 disjoint.
iommu_guest_group_disjoint:
 test rax,rax
 jz .no
 test rdx,rdx
 jz .no
 add rdx,rax
 jc .no
 mov rcx,[rdi+PG_RAM]
 cmp rdx,rcx
 jbe .yes
 add rcx,[rdi+PG_BYTES]
 jc .no
 cmp rax,rcx
 jb .no
.yes: mov eax,1
 ret
.no: xor eax,eax
 ret

; Both native backends' globals, A/C custody, claim/alias censuses and retained
; observations live in the complete writable regions. Exclude those regions,
; including their BSS tails, rather than an incomplete list of scalar fields.
iommu_guest_group_wdata_ok:
 lea rax,[rel wdata_region]
 lea rdx,[rel wdata_region_end]
 sub rdx,rax
 call iommu_guest_group_disjoint
 test eax,eax
 jz .out
 lea rax,[rel wdata_bss]
 lea rdx,[rel wdata_bss_end]
 sub rdx,rax
 call iommu_guest_group_disjoint
.out: ret

; RDI/RSI candidate range, RAX/RDX B-owned captured RAM/bytes -> EAX overlap.
; Held resources with an invalid captured span pin all candidates. RDI/RSI and
; RCX are preserved; the backend wrapper also preserves its incoming RDX.
iommu_guest_group_overlap:
 push rcx
 test rax,rax
 jz .yes
 test rdx,rdx
 jz .yes
 add rdx,rax
 jc .yes
 mov rcx,rdi
 add rcx,rsi
 jc .yes
 cmp rdi,rdx
 jae .no
 cmp rcx,rax
 jbe .no
.yes: mov eax,1
 jmp .out
.no: xor eax,eax
.out:
 pop rcx
 ret

%endif
