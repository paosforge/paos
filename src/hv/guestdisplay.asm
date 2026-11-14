;; MODULE hv/guestdisplay
%include "hv/guest_power.inc"

;; LAYER 5
;; EXPORTS guestdisplay_hva, guestdisplay_capture_span, guestdisplay_clear, guestdisplay_map, guestdisplay_screen_info, guestdisplay_sum, guestdisplay_render_stat, guestdisplay_reset, guestdisplay_ready, hv_linux_fb_bytes
;; IMPORTS hv/guest_power, hv/vmx, hv/hv_ops, hv/vm_profile, hv/vcpu_ap_run, hv/vcpu_bsp
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; ============================================================================
; RCQ-23 S1: the DISPLAY device of the desktop-linux guest.
;
; There is no emulated display hardware. PaOS reserves a private framebuffer
; right after guest RAM in the same 2 MiB-aligned host region (VP_FB_BYTES,
; counted in the profile plan's reserve), clears it on every START, maps it at
; guest-physical VP_FB_GPA as one 2 MiB EPT leaf, and describes it to Linux in
; boot_params.screen_info as a VLFB x8r8g8b8 surface. Linux's sysfb turns that
; into a simple-framebuffer device (simplefb -> /dev/fb0). Guest stores never
; exit; PaOS reads the pixels from its side (the desktop window, STAT fb_sum).
;
; EPT leaf: R+W, no execute, WB with IPAT. IPAT pins the guest's accesses to
; write-back whatever its PAT says (simplefb maps write-combining), so the
; guest's stores and PaOS's cached reads of the same bytes stay coherent.
; The framebuffer lies outside every e820 RAM entry the guest is given.
; ============================================================================

GD_EPT_LEAF      equ 0xF3               ; R W !X, memtype WB (6<<3), IPAT, 2 MiB page
GD_VIDEO_VLFB    equ 0x23               ; VIDEO_TYPE_VLFB

; The BSP owns this lifecycle; there is no yield from validation through clear,
; map or a live read. START revokes the old record before preparing and on every
; return (including failure). Only clear may create a prepared reservation;
; only an accepted SLAT leaf may promote it to mapped. No cached HVA is exported
; across STARTs. All record storage lives in the existing zero-fill tail.
GD_CAPTURE_LEN    equ VP_FB_STRIDE * VP_FB_HEIGHT
GD_IDENT_SHIFT    equ 34
GD_IDENT_CEILING  equ 1 << GD_IDENT_SHIFT
%if GD_CAPTURE_LEN > VP_FB_BYTES
    %error "the capture span must fit the reserved DISPLAY leaf"
%endif

; All concrete owner fields must still match the fully checked clear snapshot.
; Uses only RAX/RCX/RDX; a live capture remains a read-only, stackless leaf with
; its original RAX/RDX/ECX results and all other registers/DF untouched.
%macro GD_OWNER_CURRENT 1
    mov  ecx, [rel hv_linux_start_consumed]
    test ecx, ecx
    jz   %1
    cmp  ecx, [rel gd_generation]
    jne  %1
    cmp  ecx, [rel vm_profile_gen]
    jne  %1
    mov  eax, [rel vm_profile_dev_mask]
    cmp  eax, [rel gd_devices]
    jne  %1
    test eax, VP_DEV_DISPLAY
    jz   %1
    mov  rax, [rel vm_profile_active]
    cmp  rax, [rel gd_profile]
    jne  %1
    mov  rax, [rel hv_ops_active]
    cmp  rax, [rel gd_backend]
    jne  %1
    mov  rax, [rel hv_linux_region]
    cmp  rax, [rel gd_region]
    jne  %1
    mov  rdx, [rel hv_linux_region_capacity]
    cmp  rdx, [rel gd_capacity]
    jne  %1
    mov  rax, [rel hv_linux_ram]
    cmp  rax, [rel gd_ram]
    jne  %1
    mov  rdx, [rel hv_linux_ram_bytes]
    cmp  rdx, [rel gd_ram_bytes]
    jne  %1
    cmp  qword [rel hv_linux_fb_bytes], VP_FB_BYTES
    jne  %1
    mov  rax, [rel gd_frame]
%endmacro

guestdisplay_reset:
    HV_POWER_WORK guestdisplay_reset, 0, hv_guest_power_admit
    mov  byte [rel gd_state], 0
    ret

; guestdisplay_hva -> RAX = current running frame or zero. Same live authority
; as capture and checksum, never the selected/future reservation. Retains the
; original HVA clobber contract: only RAX and flags.
guestdisplay_hva:
    push rcx
    push rdx
    call guestdisplay_capture_span
    pop  rdx
    pop  rcx
    ret

; guestdisplay_capture_span -> RAX = live frame, RDX = visible byte length,
; ECX = START generation (upper RCX zero), all three zero on refusal. No calls,
; stack or writes. BSP callers must not yield while reading; call again before
; publishing and require equal RAX/ECX (guest_desktop's existing protocol).
guestdisplay_capture_span:
    cmp byte [rel hv_guest_power_fenced], 0
    jne .none
    cmp  byte [rel gd_state], 2
    jne  .none
    cmp  byte [rel hv_linux_running], 1
    jne  .none
    GD_OWNER_CURRENT .none
    mov  edx, [rel vm_profile_live_devices]
    cmp  edx, [rel gd_devices]
    jne  .none
    mov  rdx, [rel gd_region]
    mov  rax, [rdx + 0x3000 + 3*8]
    cmp  rax, [rel gd_link]
    jne  .none
    mov  rax, [rdx + HV_VCON_EPT_PD + ((VP_FB_GPA - 0xC0000000) >> 21) * 8]
    cmp  rax, [rel gd_leaf]
    jne  .none
    mov  rax, [rel gd_frame]
    mov  edx, GD_CAPTURE_LEN
    ret
.none:
    xor  eax, eax
    xor  ecx, ecx
    xor  edx, edx
    ret

; Selected/prepared validation. Same owner as live capture, but no live reads
; before START runs. Only states 1 (cleared) and 2 (mapped) are prepared.
gd_prepared:
    cmp  byte [rel hv_linux_running], 0
    jne  .none
    cmp  byte [rel gd_state], 1
    jb   .none
    cmp  byte [rel gd_state], 2
    ja   .none
    GD_OWNER_CURRENT .none
    ret
.none:
    xor  eax, eax
    ret

; guestdisplay_clear -> EAX=1 for valid prepared state or an omitted DISPLAY
; with no reserve, 0 on refusal. Validate the full future leaf and consumed
; control/RAM spans BEFORE any pixel write; clear exactly VP_FB_BYTES. Preserve
; caller DF (as do all other display entries), no FP/SIMD state is touched.
guestdisplay_clear:
    HV_POWER_WORK guestdisplay_clear, 0, hv_guest_power_admit
    cmp  byte [rel hv_linux_running], 0
    jne  .bad
    call guestdisplay_reset
    test dword [rel vm_profile_dev_mask], VP_DEV_DISPLAY
    jnz  .selected
    cmp  qword [rel hv_linux_fb_bytes], 0
    jne  .bad
    mov  eax, 1
    ret
.selected:
    mov  ecx, [rel hv_linux_start_consumed]
    test ecx, ecx
    jz   .bad
    cmp  ecx, [rel vm_profile_gen]
    jne  .bad
    mov  rax, [rel vm_profile_active]
    test rax, rax
    jz   .bad
    mov  rdx, [rel hv_ops_active]
    test rdx, rdx
    jz   .bad
    cmp  qword [rel hv_linux_fb_bytes], VP_FB_BYTES
    jne  .bad
    mov  rax, [rel hv_linux_region]
    test rax, rax
    jz   .bad
    test rax, 0x1FFFFF
    jnz  .bad
    mov  rdx, rax
    add  rdx, [rel hv_linux_region_capacity]
    jc   .bad                               ; allocation endpoint, full 64 bits
    add  rax, HV_LINUX_CTRL_BYTES
    jc   .bad
    cmp  rax, [rel hv_linux_ram]
    jne  .bad                               ; RAM follows this exact control span
    mov  rcx, [rel hv_linux_ram_bytes]
    test rcx, rcx
    jz   .bad
    test rcx, 0x1FFFFF
    jnz  .bad
    cmp  rcx, HV_LINUX_BROWSER_RAM_BYTES
    ja   .bad                               ; one RAM PD; e820 excludes DISPLAY GPA
    add  rax, rcx
    jc   .bad
    mov  [rel gd_frame], rax
    add  rax, VP_FB_BYTES
    jc   .bad
    cmp  rax, rdx
    ja   .bad                               ; full reservation, not visible pixels
    mov  rdx, GD_IDENT_CEILING
    cmp  rax, rdx
    ja   .bad                               ; end equal to ceiling is valid
    mov  rax, [rel hv_linux_region]
    mov  [rel gd_region], rax
    mov  rax, [rel hv_linux_region_capacity]
    mov  [rel gd_capacity], rax
    mov  rax, [rel hv_linux_ram]
    mov  [rel gd_ram], rax
    mov  rax, [rel hv_linux_ram_bytes]
    mov  [rel gd_ram_bytes], rax
    mov  rax, [rel vm_profile_active]
    mov  [rel gd_profile], rax
    mov  rax, [rel hv_ops_active]
    mov  [rel gd_backend], rax
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rel gd_generation], eax
    mov  eax, [rel vm_profile_dev_mask]
    mov  [rel gd_devices], eax
    push rdi
    pushfq
    mov  rdi, [rel gd_frame]
    mov  ecx, VP_FB_BYTES / 8
    xor  eax, eax
    cld
    rep  stosq
    popfq
    pop  rdi
    mov  byte [rel gd_state], 1              ; publish only after complete scrub
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; guestdisplay_map(RDI=control base) -> EAX=1 only for the exact cleared
; reservation. The caller has installed PDPT[3] -> this control's display PD.
; Revalidate after the backend seam; keep no pointer from another owner.
guestdisplay_map:
    ; S7: table lifetime is frozen until both vCPUs are retired.
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    HV_POWER_WORK guestdisplay_map, 0, hv_guest_power_admit
    call gd_prepared
    test rax, rax
    jz   .bad
    cmp  byte [rel gd_state], 1
    jne  .bad
    cmp  rdi, [rel gd_region]
    jne  .bad
    push rdi
    mov  edi, HV_SLAT_FB_2M
    call hv_slat_bits
    pop  rdi
    test rax, rax
    jz   .bad
    push rax
    call gd_prepared
    test rax, rax
    pop  rdx
    jz   .bad
    cmp  rdi, [rel gd_region]
    jne  .bad
    or   rdx, rax
    mov  rax, [rdi + 0x3000 + 3*8]
    mov  rcx, rax
    and  rcx, -0x1000
    sub  rcx, HV_VCON_EPT_PD
    cmp  rcx, rdi
    jne  .bad
    test al, 1
    jz   .bad
    mov  [rel gd_link], rax
    mov  [rdi + HV_VCON_EPT_PD + ((VP_FB_GPA - 0xC0000000) >> 21) * 8], rdx
    mov  [rel gd_leaf], rdx
    mov  byte [rel gd_state], 2
    mov  eax, 1
    ret
.bad:
    ; An attempted remap/failure cannot leave an old prepared proof usable.
    cmp  byte [rel hv_linux_running], 0
    jne  .out
    call guestdisplay_reset
.out:
    xor  eax, eax
    ret

; Loader's final acceptance, after map_devices. A selected DISPLAY must have
; been mapped; omission must have no hidden reservation or old prepared state.
guestdisplay_ready:
    test dword [rel vm_profile_dev_mask], VP_DEV_DISPLAY
    jz   .omitted
    call gd_prepared
    test rax, rax
    jz   .bad
    cmp  byte [rel gd_state], 2
    jne  .bad
    test dword [rel vm_profile_live_devices], VP_DEV_DISPLAY
    jz   .bad
    mov  eax, 1
    ret
.omitted:
    cmp  byte [rel gd_state], 0
    jne  .bad
    cmp  qword [rel hv_linux_fb_bytes], 0
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; guestdisplay_screen_info(RDI=boot_params) -> EAX=1 on a validated write or
; a no-reservation omission, 0 on refusal. The fixed VLFB ABI is unchanged.
guestdisplay_screen_info:
    HV_POWER_WORK guestdisplay_screen_info, 0, hv_guest_power_admit
    test dword [rel vm_profile_dev_mask], VP_DEV_DISPLAY
    jz   .omitted
    call gd_prepared
    test rax, rax
    jz   .bad
    mov  rax, [rel gd_ram]
    add  rax, HV_LINUX_BP_GPA
    jc   .bad
    cmp  rax, rdi
    jne  .bad
    add  rax, 0x1000                         ; full boot_params zero page
    jc   .bad
    cmp  rax, [rel gd_frame]
    ja   .bad
    mov  byte [rdi + 0x0F], GD_VIDEO_VLFB   ; orig_video_isVGA
    mov  word [rdi + 0x12], VP_FB_WIDTH     ; lfb_width
    mov  word [rdi + 0x14], VP_FB_HEIGHT    ; lfb_height
    mov  word [rdi + 0x16], 32              ; lfb_depth
    mov  dword [rdi + 0x18], VP_FB_GPA      ; lfb_base
    mov  dword [rdi + 0x1C], VP_FB_BYTES >> 16 ; lfb_size, 64 KiB units for VLFB
    mov  word [rdi + 0x24], VP_FB_STRIDE    ; lfb_linelength
    mov  byte [rdi + 0x26], 8               ; red size/pos
    mov  byte [rdi + 0x27], 16
    mov  byte [rdi + 0x28], 8               ; green
    mov  byte [rdi + 0x29], 8
    mov  byte [rdi + 0x2A], 8               ; blue
    mov  byte [rdi + 0x2B], 0
    mov  byte [rdi + 0x2C], 8               ; reserved (X)
    mov  byte [rdi + 0x2D], 24
    mov  dword [rdi + 0x36], 0              ; capabilities: base below 4 GiB
    mov  dword [rdi + 0x3A], 0              ; ext_lfb_base
    mov  eax, 1
    ret
.omitted:
    jmp  guestdisplay_ready
.bad:
    xor  eax, eax
    ret

; guestdisplay_sum -> EAX = FNV-1a 32 over the visible pixels (row-major,
; colour bytes only: the X byte is masked), or 0 without a display.
guestdisplay_sum:
    call guestdisplay_hva
    test rax, rax
    jz   .out
    mov  rsi, rax
    mov  eax, 0x811C9DC5
    mov  r8d, 16777619
    xor  ecx, ecx                           ; row
.row:
    cmp  ecx, VP_FB_HEIGHT
    jae  .out
    xor  edx, edx                           ; column
.px:
    mov  edi, [rsi + rdx*4]
    and  edi, 0x00FFFFFF
    xor  eax, edi
    imul eax, r8d
    inc  edx
    cmp  edx, VP_FB_WIDTH
    jb   .px
    add  rsi, VP_FB_STRIDE
    inc  ecx
    jmp  .row
.out:
    ret

; guestdisplay_render_stat — appended to GUESTVM STAT when a display is live.
guestdisplay_render_stat:
    call guestdisplay_hva
    test rax, rax
    jz   .ret
    lea  rdi, [rel str_gd_mode]
    call hv_out_str
    call guestdisplay_sum
    push rax
    lea  rdi, [rel str_gd_k_sum]
    call hv_out_str
    pop  rax
    jmp  hv_out_dec
.ret:
    ret

str_gd_mode:   db " fb=800x600x32 fb_gpa=0xC0000000", 0
str_gd_k_sum:  db " fb_sum=", 0
%if VP_FB_WIDTH != 800 || VP_FB_HEIGHT != 600 || VP_FB_GPA != 0xC0000000
    %error "str_gd_mode must name the DISPLAY mode"
%endif

%include "core/abi/wdata.inc"
%macro WDATA_hv_guestdisplay_0 0
alignb 8
hv_linux_fb_bytes: resq 1               ; reserved after guest RAM for this selection
gd_region:        resq 1
gd_capacity:      resq 1
gd_ram:           resq 1
gd_ram_bytes:     resq 1
gd_frame:         resq 1
gd_profile:       resq 1
gd_backend:       resq 1
gd_link:          resq 1
gd_leaf:          resq 1
gd_generation:    resd 1
gd_devices:       resd 1
gd_state:         resb 1                ; 0 revoked, 1 fully cleared, 2 mapped
%endmacro
WDATA_BSS_DEFER WDATA_hv_guestdisplay_0
