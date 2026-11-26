;; MODULE gui/img/img_jpeg
;; LAYER 6
;; EXPORTS img_jpeg_probe, img_jpeg_probe_exact, img_jpeg_decode
;; IMPORTS core/heap, core/lib/sha256
;; CAPS
;; OWNER saga:gui_image_pipeline

%include "gui/img/img_cold_hooks.inc"

; Baseline/extended-sequential/progressive Huffman8 JPEG: gray or YCbCr444/420/422/440/411.
; SOF1 keeps 8-bit samples/quantizers and permits four DC/AC destinations.
; Every SOF1 scan uses the SHA-owned complete coefficient frame, sequential
; coverage and full-spectrum syntax; no RGBA publishes before exact EOI.
; Three-component color: Y=1x1,2x2,2x1,1x2,4x1; Cb/Cr=1x1.
; Explicit Adobe transform0 requires R,G,B IDs and 1x1 all planes. It uses
; the owned complete coefficient frame for both SOF0 and SOF2, with exact EOI
; and no RGBA writes until all scans validate. This is device RGB, not ICC.
; New asymmetric profiles use the SHA-owned/exact-file path. Their maximum
; six blocks/MCU fits the existing ten-block CMYK/YCCK sample buffer.
; T.81 A.2: interleaved MCU=selected H*V blocks, noninterleaved MCU=one
; block. Generic padded-frame and actual scan geometry handles both unchanged.
; Grayscale uses noninterleaved one-block MCUs (T.81 A.2.1), independent
; of declared H/V factors. Its sole allocation holds RGBA plus a SHA-bound
; private source; metadata/entropy are reparsed from that owned snapshot.
; DRI-bearing color scans use that same owned/exact-file path. Restart intervals
; count MCUs (not component blocks), validate one-bit alignment and cyclic RST,
; and reset all component DC predictors. No recovery or partial result publishes.
; Existing color IDCT/conversion and native color-without-DRI suffix policy stay.
; Progressive Huffman8 and component-separated baseline scans use a capped
; private whole-frame coefficient tail. Baseline components transmit DC+AC once,
; with scan-local tables/predictors and complete component coverage before RGBA.
; Single-component scans use actual block dimensions; interleaved subsets use
; padded MCU geometry in frame order. Quantization snapshots belong to each
; component, so sequential scans may reuse/redefine tables for later components.
; Adobe APP14 transform0 CMYK (1x1) and transform2 YCCK (1x1 or 2x2 Y/K)
; share baseline/progressive entropy, capped coefficients and SHA-owned decoding.
; Four-channel metadata is explicit: one version100/101, zero-flags Adobe marker
; before scans; absent/conflicting/late metadata, JFIF, non-Exif APP1, ICC and
; Photoshop profiles are refused. No profile guessing. Bounded Exif IFD0
; Orientation1..8 uses a SHA-owned snapshot and exact complete-file span for
; every component profile. Coding geometry stays stored; public dimensions and
; the shared pixel store describe the oriented raster. No extra allocation.
; Lossless/arithmetic remain unsupported.

JPG_HT_COUNT equ 8
JPG_FRAME_CAP equ 67108864             ; <=64MiB, derived padded 4Mpixel frame bound
JPG_QT_COUNT equ 4

img_jpeg_probe:
    IMG_COLD_PUBLIC_GUARD
    cld
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    call img_jpeg_parse
    test eax, eax
    jnz  .out
    mov  ebx, IMG_FMT_JPEG
    call img_jpeg_dimensions
    mov  r8d, [rel img_jpg_ncomp]
    shl  r8d, 3
.out:
    pop  r13
    pop  r12
    ret

; Exact-span adapter entry: the parser's actual scan EOI, not a suffix search.
img_jpeg_probe_exact:
    IMG_COLD_PUBLIC_GUARD
    cld
    mov  rax, rdi
    add  rax, rsi
    jc   .bounds
    push rdi
    push rsi
    call img_jpeg_probe
    pop  rsi
    pop  rdi
    test eax, eax
    jnz  .out
    lea  r9, [rdi + rsi]
    mov  r10, [rel img_jpg_file_end]    ; includes legal FF fill before EOI
    cmp  r9, r10
    je   .out
    mov  eax, IMG_E_CORRUPT
.out:
    ret
.bounds:
    mov  eax, IMG_E_BOUNDS
    ret

; Parse complete marker structure without allocation. EAX=status.
img_jpeg_parse:
    xor  edx, edx                     ; probe/header-only: no coefficient writes
    jmp  img_jpeg_parse_coeff

; RDX=private buffered coefficient tail, or zero for structural probe. Never caller bytes.
img_jpeg_parse_coeff:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  r12, rdi
    mov  r13, rdi
    add  r13, rsi
    jc   .bounds
    cmp  rsi, 33554432                 ; bounded complete source, before any read
    ja   .bounds
    cmp  rsi, 4
    jb   .truncated
    cmp  word [r12], 0xD8FF
    jne  .bad_magic
    push rdx
    push rcx
    call img_jpeg_clear
    pop  rcx
    pop  rdx
    mov  byte [rel img_jpg_orientation], 1
    mov  [rel img_jpg_frame], rdx
    mov  [rel img_jpg_frame_capacity], rcx
    lea  rdi, [rel img_jpg_progress_bits]
    mov  ecx, 4 * 64
    mov  al, 255
    IMG_COLD_MEMORY stosb
    add  r12, 2
.marker:
    cmp  r12, r13
    jae  .truncated
    cmp  byte [r12], 0xFF
    jne  .corrupt
.ff:
    inc  r12
    cmp  r12, r13
    jae  .truncated
    cmp  byte [r12], 0xFF
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    je   .ff
    movzx ebp, byte [r12]
    inc  r12
    cmp  ebp, 0xD9
    je   .eoi
    cmp  ebp, 0xD8
    je   .corrupt                     ; one SOI/frame; no inherited interval state
    cmp  ebp, 0x01
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    je   .marker
    cmp  ebp, 0xD0
    jb   .has_len
    cmp  ebp, 0xD7
    jbe  .corrupt                     ; RST is legal only inside the scan
.has_len:
    lea  rax, [r12 + 2]
    cmp  rax, r13
    ja   .truncated
    movzx ebx, word [r12]
    xchg bl, bh
    cmp  ebx, 2
    jb   .corrupt
    lea  r14, [r12 + rbx]             ; segment end
    cmp  r14, r13
    ja   .truncated
    lea  r15, [r12 + 2]               ; payload
    cmp  ebp, 0xEE
    je   .adobe
    cmp  ebp, 0xE1
    je   .app1
    cmp  ebp, 0xE2
    je   .profile
    cmp  ebp, 0xED
    je   .profile
    cmp  ebp, 0xE0
    je   .app0
    cmp  ebp, 0xC0
    je   .sof0
    cmp  ebp, 0xC1
    je   .sof1                        ; extended sequential, 8-bit subset
    cmp  ebp, 0xC2
    je   .sof2                        ; progressive Huffman8
    cmp  ebp, 0xC3
    je   .unsupported                 ; lossless sequential
    cmp  ebp, 0xC4
    je   .dht
    cmp  ebp, 0xDB
    je   .dqt
    cmp  ebp, 0xDA
    je   .sos
    cmp  ebp, 0xDD
    je   .dri
    ; Only APPn and COM are ignorable length-bearing segments. Reserved codes,
    ; JPG extensions, DHP/DNL and unsupported coding processes are not metadata.
    cmp  ebp, 0xE0
    jb   .unsupported
    cmp  ebp, 0xEF
    jbe  .skip_unknown
    cmp  ebp, 0xFE
    jne  .unsupported
.skip_unknown:
    mov  r12, r14
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .marker

.app1:
    ; Only the complete six-byte Exif identifier admits TIFF interpretation.
    ; Non-Exif APP1 keeps the existing color-profile policy (notably CMYK).
    cmp  ebx, 8
    jb   .profile
    cmp  dword [r15], 0x66697845       ; Exif
    jne  .profile
    cmp  word [r15 + 4], 0
    jne  .profile
    cmp  byte [rel img_jpg_exif_seen], 0
    jne  .corrupt                     ; one Exif APP1, even without Orientation
    cmp  qword [rel img_jpg_scan_ptr], 0
    jne  .corrupt                     ; dimensions are fixed before first SOS
    mov  byte [rel img_jpg_exif_seen], 1
    lea  rdi, [r15 + 6]
    lea  rsi, [rbx - 8]               ; TIFF extent, strictly inside APP1
    call img_jpeg_exif
    test eax, eax
    jnz  .out
    jmp  .seg_done

.app0:
    cmp  ebx, 7
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .skip_unknown
    cmp  dword [r15], 0x4649464A       ; JFIF implies YCbCr, conflicts with device RGB/CMYK
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jne  .skip_unknown
    cmp  byte [r15 + 4], 0
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jne  .skip_unknown
    mov  byte [rel img_jpg_jfif_seen], 1
    jmp  .seg_done
.profile:
    mov  byte [rel img_jpg_color_bad], 1
    jmp  .seg_done
.adobe:
    ; Record invalid/unknown/duplicate/late APP14, including before SOF.
    ; Three/four-component explicit color must fail shut on malformed metadata.
    mov  byte [rel img_jpg_adobe_attempt], 1
    cmp  byte [rel img_jpg_adobe_seen], 0
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jne  .profile
    cmp  qword [rel img_jpg_scan_ptr], 0
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jne  .profile
    cmp  ebx, 14                      ; 12-byte Adobe payload
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jne  .profile
    cmp  dword [r15], 0x626F6441       ; Adobe
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jne  .profile
    cmp  byte [r15 + 4], 'e'
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jne  .profile
    cmp  word [r15 + 5], 0x6400       ; version100 BE
    je   .adobe_version
    cmp  word [r15 + 5], 0x6500       ; version101 BE
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jne  .profile
.adobe_version:
    cmp  dword [r15 + 7], 0           ; unsupported flags are not a profile
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jne  .profile
    mov  al, [r15 + 11]
    mov  [rel img_jpg_adobe_transform], al
    mov  byte [rel img_jpg_adobe_seen], 1
    jmp  .seg_done
.dri:
    cmp  ebx, 4                       ; T.81 B.2.4.4: exactly one BE16 interval
    jne  .corrupt
    movzx eax, word [r15]
    rol  ax, 8
    mov  [rel img_jpg_restart_interval], eax
    mov  byte [rel img_jpg_restart_seen], 1
    jmp  .seg_done                    ; last definition wins; zero disables RST
.sof1:
    mov  byte [rel img_jpg_extended], 1
    mov  byte [rel img_jpg_sequential], 1
    mov  byte [rel img_jpg_buffered], 1
    jmp  .sof0
.sof2:
    mov  byte [rel img_jpg_buffered], 1
    mov  byte [rel img_jpg_progressive], 1
.sof0:
    cmp  byte [rel img_jpg_sof_seen], 0
    jne  .corrupt
    cmp  rbx, 11
    jb   .truncated
    cmp  byte [r15], 8
    jne  .unsupported
    movzx eax, word [r15 + 1]
    xchg al, ah
    mov  [rel img_jpg_height], eax
    movzx eax, word [r15 + 3]
    xchg al, ah
    mov  [rel img_jpg_width], eax
    movzx ecx, byte [r15 + 5]
    cmp  ecx, 1
    je   .sof_components
    cmp  ecx, 3
    je   .sof_components
    cmp  ecx, 4
    jne  .unsupported
.sof_components:
    mov  [rel img_jpg_ncomp], ecx
    lea  eax, [rcx + rcx * 2 + 8]
    cmp  ebx, eax
    jb   .truncated
    jne  .corrupt                      ; exact SOF component extent
    mov  eax, [rel img_jpg_width]
    test eax, eax
    jz   .bounds
    cmp  eax, IMG_MAX_DIM
    ja   .bounds
    mov  edx, [rel img_jpg_height]
    test edx, edx
    jz   .bounds
    cmp  edx, IMG_MAX_DIM
    ja   .bounds
    imul rax, rdx
    cmp  rax, IMG_MAX_PIXELS
    ja   .bounds
    xor  edx, edx
    mov  byte [rel img_jpg_max_h], 0
    mov  byte [rel img_jpg_max_v], 0
.sof_comp_loop:
    cmp  edx, ecx
    jae  .sof_sampling
    lea  rsi, [r15 + 6 + rdx * 2]
    add  rsi, rdx
    lea  rdi, [rel img_jpg_comp_id]
    mov  al, [rsi]
    mov  [rdi + rdx], al
    movzx eax, byte [rsi + 1]
    mov  edi, eax
    shr  edi, 4
    and  eax, 0x0F
    test edi, edi
    jz   .unsupported
    test eax, eax
    jz   .unsupported
    mov  r8d, 2
    cmp  ecx, 4
    je   .sampling_limit
    mov  r8d, 4                       ; T.81 B.2; finite color profiles checked below
.sampling_limit:
    cmp  edi, r8d
    ja   .unsupported
    cmp  eax, r8d
    ja   .unsupported
    lea  rsi, [rel img_jpg_comp_h]
    mov  [rsi + rdx], dil
    lea  rsi, [rel img_jpg_comp_v]
    mov  [rsi + rdx], al
    cmp  dil, [rel img_jpg_max_h]
    jbe  .h_ok
    mov  [rel img_jpg_max_h], dil
.h_ok:
    cmp  al, [rel img_jpg_max_v]
    jbe  .v_ok
    mov  [rel img_jpg_max_v], al
.v_ok:
    lea  rsi, [r15 + 8 + rdx * 2]
    add  rsi, rdx
    movzx eax, byte [rsi]
    cmp  eax, JPG_QT_COUNT
    jae  .unsupported
    lea  rsi, [rel img_jpg_comp_qt]
    mov  [rsi + rdx], al
    inc  edx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .sof_comp_loop
.sof_sampling:
    cmp  ecx, 1
    jne  .color_sampling
    mov  byte [rel img_jpg_comp_h], 1
    mov  byte [rel img_jpg_comp_v], 1
    mov  byte [rel img_jpg_max_h], 1
    mov  byte [rel img_jpg_max_v], 1
    jmp  .sof_accept
.color_sampling:
    cmp  ecx, 3
    je   .sof_three
    ; Four-component color retains 1x1 or Y/K=2x2, Cb/Cr=1x1.
    cmp  byte [rel img_jpg_comp_h], 1
    jne  .sof_420
    cmp  byte [rel img_jpg_comp_v], 1
    jne  .unsupported
    cmp  byte [rel img_jpg_comp_h + 1], 1
    jne  .unsupported
    cmp  byte [rel img_jpg_comp_v + 1], 1
    jne  .unsupported
    cmp  byte [rel img_jpg_comp_h + 2], 1
    jne  .unsupported
    cmp  byte [rel img_jpg_comp_v + 2], 1
    jne  .unsupported
    jmp  .sof_accept
.sof_420:
    cmp  byte [rel img_jpg_comp_h], 2
    jne  .unsupported
    cmp  byte [rel img_jpg_comp_v], 2
    jne  .unsupported
    cmp  byte [rel img_jpg_comp_h + 1], 1
    jne  .unsupported
    cmp  byte [rel img_jpg_comp_v + 1], 1
    jne  .unsupported
    cmp  byte [rel img_jpg_comp_h + 2], 1
    jne  .unsupported
    cmp  byte [rel img_jpg_comp_v + 2], 1
    jne  .unsupported
    jmp  .sof_accept
.sof_three:
    cmp  byte [rel img_jpg_comp_h + 1], 1
    jne  .unsupported
    cmp  byte [rel img_jpg_comp_v + 1], 1
    jne  .unsupported
    cmp  byte [rel img_jpg_comp_h + 2], 1
    jne  .unsupported
    cmp  byte [rel img_jpg_comp_v + 2], 1
    jne  .unsupported
    movzx eax, byte [rel img_jpg_comp_h]
    movzx edx, byte [rel img_jpg_comp_v]
    cmp  eax, 4
    je   .sof_411
    cmp  eax, 2
    ja   .unsupported                 ; H=1/2 (zero already refused)
    cmp  edx, 2
    ja   .unsupported                 ; V=1/2: 444/440/422/420
    jmp  .sof_three_owned
.sof_411:
    cmp  edx, 1
    jne  .unsupported                 ; finite 4x1 only, not arbitrary factors
.sof_three_owned:
    cmp  eax, edx
    setne byte [rel img_jpg_asymmetric] ; new profiles all have unequal H/V
    jmp  .sof_accept
.sof_accept:
    cmp  dword [rel img_jpg_ncomp], 4
    jne  .sof_geometry
    ; Only 1x1 all channels, or Y/K=2x2,Cb/Cr=1x1 (10 blocks/MCU).
    mov  al, [rel img_jpg_comp_h]
    cmp  al, [rel img_jpg_comp_h + 3]
    jne  .unsupported
    mov  al, [rel img_jpg_comp_v]
    cmp  al, [rel img_jpg_comp_v + 3]
    jne  .unsupported
.sof_geometry:
    call img_jpeg_frame_geometry
    test eax, eax
    jnz  .bounds
    mov  byte [rel img_jpg_sof_seen], 1
    mov  r12, r14
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .marker

.dqt:
    mov  rsi, r15
.dqt_loop:
    cmp  rsi, r14
    jae  .seg_done
    movzx eax, byte [rsi]
    mov  ecx, eax
    shr  ecx, 4
    and  eax, 0x0F
    test ecx, ecx
    jnz  .unsupported                 ; 16-bit quantization not in v1
    cmp  eax, JPG_QT_COUNT
    jae  .unsupported
    mov  r8d, eax
    lea  rdx, [rsi + 65]
    cmp  rdx, r14
    ja   .truncated
    lea  rdi, [rel img_jpg_qtables]
    shl  eax, 6
    add  rdi, rax
    inc  rsi
    call img_jpeg_quant_change
    test eax, eax
    jnz  .corrupt
    mov  ecx, 64
.quant_copy:
    lodsb
    test al, al
    jz   .corrupt                      ; T.81 quantizer values are 1..255
    stosb
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    loop .quant_copy
    lea  rax, [rel img_jpg_qpresent]
    mov  byte [rax + r8], 1
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .dqt_loop

.dht:
    mov  rsi, r15
.dht_loop:
    cmp  rsi, r14
    jae  .seg_done
    lea  rax, [rsi + 17]
    cmp  rax, r14
    ja   .truncated
    movzx eax, byte [rsi]
    mov  ecx, eax
    shr  ecx, 4
    and  eax, 0x0F
    cmp  ecx, 1
    ja   .corrupt
    cmp  eax, 3
    ja   .unsupported
    mov  edx, eax
    and  eax, 1
    and  edx, 2
    shl  edx, 1
    add  eax, edx
    shl  ecx, 1
    add  ecx, eax                       ; old DC0/1,AC0/1 indices retained;2/3 in4..7
    mov  r8d, ecx
    xor  ebp, ebp
    xor  edx, edx
    mov  r9d, 1
.dht_sum:
    movzx eax, byte [rsi + 1 + rdx]
    add  ebp, eax
    shl  r9d, 1
    sub  r9d, eax
    jle  .corrupt                      ; oversubscribed or reserved all-ones code
    inc  edx
    cmp  edx, 16
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .dht_sum
    test ebp, ebp
    jz   .corrupt
    cmp  ebp, 256
    ja   .corrupt                       ; bad_huff fixture lands here
    lea  rax, [rsi + 17 + rbp]
    cmp  rax, r14
    ja   .truncated
    lea  rdi, [rel img_jpg_hcounts]
    mov  eax, r8d
    shl  eax, 4
    add  rdi, rax
    push rsi
    inc  rsi
    mov  ecx, 16
    IMG_COLD_MEMORY movsb
    pop  rsi
    lea  rdi, [rel img_jpg_hsymbols]
    mov  eax, r8d
    shl  eax, 8
    add  rdi, rax
    lea  rsi, [rsi + 17]
    mov  ecx, ebp
.symbol_copy:
    lodsb
    test r8d, 2
    jnz  .ac_symbol
    cmp  al, 11
    ja   .corrupt
    jmp  .symbol_ok
.ac_symbol:
    test al, al
    jz   .symbol_ok
    cmp  al, 0xF0
    je   .symbol_ok
    mov  dl, al
    and  dl, 15
    jz   .symbol_ok                    ; progressive EOBr; baseline validates at SOS
    cmp  dl, 10
    ja   .corrupt
.symbol_ok:
    stosb
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    loop .symbol_copy
    lea  rax, [rel img_jpg_hpresent]
    mov  byte [rax + r8], 1
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .dht_loop

.sos:
    call img_jpeg_four_metadata
    test eax, eax
    jnz  .unsupported
.sos_header:
    cmp  byte [rel img_jpg_rgb], 1
    jne  .sos_mode
    cmp  byte [rel img_jpg_progressive], 1
    je   .sos_mode
    ; Even full interleaved baseline RGB is decoded into private coefficients.
    mov  byte [rel img_jpg_sequential], 1
    mov  byte [rel img_jpg_buffered], 1
.sos_mode:
    cmp  byte [rel img_jpg_sof_seen], 1
    jne  .corrupt
    cmp  byte [rel img_jpg_progressive], 1
    je   .progressive_sos
    cmp  ebx, 3
    jb   .truncated
    movzx ecx, byte [r15]
    cmp  byte [rel img_jpg_sequential], 1
    je   .progressive_sos              ; same private frame traversal, sequential syntax
    cmp  qword [rel img_jpg_scan_ptr], 0
    jne  .unsupported                 ; legacy complete interleaved scan stays single
    cmp  ecx, [rel img_jpg_ncomp]
    je   .baseline_full
    test ecx, ecx
    jz   .corrupt
    cmp  ecx, [rel img_jpg_ncomp]
    ja   .corrupt
    cmp  dword [rel img_jpg_ncomp], 1
    je   .unsupported
    mov  byte [rel img_jpg_sequential], 1
    mov  byte [rel img_jpg_buffered], 1
    jmp  .progressive_sos
.baseline_full:
    lea  eax, [rcx + rcx + 6]
    cmp  ebx, eax
    jb   .truncated
    jne  .corrupt                      ; exact SOS selector/tail extent
    xor  edx, edx
.sos_comp:
    cmp  edx, ecx
    jae  .sos_tail
    mov  al, [r15 + 1 + rdx * 2]
    xor  edi, edi
.find_comp:
    cmp  edi, [rel img_jpg_ncomp]
    jae  .corrupt
    lea  rsi, [rel img_jpg_comp_id]
    cmp  al, [rsi + rdi]
    je   .found_comp
    inc  edi
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .find_comp
.found_comp:
    ; Complete interleaved scans follow SOF order. Since SOF IDs are unique,
    ; exact ordinal equality also excludes repeated/missing SOS components.
    cmp  edi, edx                     ; baseline entropy follows frame order
    jne  .unsupported
    movzx eax, byte [r15 + 2 + rdx * 2]
    mov  esi, eax
    shr  esi, 4
    and  eax, 0x0F
    cmp  esi, 1
    ja   .unsupported
    cmp  eax, 1
    ja   .unsupported
    movzx esi, byte [r15 + 2 + rdx * 2]
    mov  eax, esi
    shr  esi, 4
    and  eax, 0x0F
    lea  r8, [rel img_jpg_comp_dc]
    mov  [r8 + rdi], sil
    lea  r8, [rel img_jpg_comp_ac]
    mov  [r8 + rdi], al
    inc  edx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .sos_comp
.sos_tail:
    lea  rsi, [r15 + 1 + rcx * 2]
    cmp  byte [rsi], 0
    jne  .unsupported
    cmp  byte [rsi + 1], 63
    jne  .unsupported
    cmp  byte [rsi + 2], 0
    jne  .unsupported
    call img_jpeg_validate_tables
    test eax, eax
    jnz  .corrupt
    mov  [rel img_jpg_scan_ptr], r14
    ; Scan geometry determines the exact number of RSTs: none after the last
    ; MCU, including an exact multiple of Ri. All geometry was capped at SOF.
    movzx ecx, byte [rel img_jpg_max_h]
    shl  ecx, 3
    mov  eax, [rel img_jpg_width]
    lea  eax, [rax + rcx - 1]
    xor  edx, edx
    div  ecx
    mov  r8d, eax
    movzx ecx, byte [rel img_jpg_max_v]
    shl  ecx, 3
    mov  eax, [rel img_jpg_height]
    lea  eax, [rax + rcx - 1]
    xor  edx, edx
    div  ecx
    imul eax, r8d
    dec  eax
    mov  ecx, [rel img_jpg_restart_interval]
    test ecx, ecx
    jz   .no_restarts
    xor  edx, edx
    div  ecx
    mov  [rel img_jpg_restart_count], eax
.no_restarts:
    mov  r12, r14
.scan:
    lea  rax, [r12 + 1]
    cmp  rax, r13
    jae  .truncated
    cmp  byte [r12], 0xFF
    jne  .scan_next
    cmp  byte [r12 + 1], 0x00
    je   .scan_stuffed
    lea  rcx, [r12 + 1]
.scan_fill:
    cmp  rcx, r13
    jae  .truncated
    movzx eax, byte [rcx]
    inc  rcx
    cmp  eax, 0xFF
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    je   .scan_fill                    ; marker fill bytes are not coded data
    cmp  eax, 0xD9
    je   .scan_eoi
    cmp  eax, 0xD0
    jb   .scan_other
    cmp  eax, 0xD7
    ja   .scan_other
    cmp  dword [rel img_jpg_restart_count], 0
    je   .corrupt                     ; disabled, extra, or final-MCU RST
    sub  eax, 0xD0
    cmp  eax, [rel img_jpg_restart_next]
    jne  .corrupt
    inc  eax
    and  eax, 7
    mov  [rel img_jpg_restart_next], eax
    dec  dword [rel img_jpg_restart_count]
    mov  r12, rcx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .scan
.scan_other:
    test eax, eax
    jz   .corrupt                     ; FF fill cannot precede stuffed00
    cmp  byte [rel img_jpg_buffered], 1
    je   .scan_eoi
    jmp  .unsupported                 ; legacy complete baseline stays single-scan
.scan_eoi:
    cmp  dword [rel img_jpg_restart_count], 0
    jne  .corrupt                     ; missing restart(s), even if pixels fit
    mov  [rel img_jpg_scan_end], r12
    cmp  byte [rel img_jpg_buffered], 1
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jne  .marker
    cmp  qword [rel img_jpg_frame], 0
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    je   .marker
    call img_jpeg_progressive_scan
    test eax, eax
    jnz  .corrupt
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .marker
.scan_stuffed:
    add  r12, 2
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .scan
.scan_next:
    inc  r12
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .scan
.progressive_sos:
    call img_jpeg_progressive_header
    test eax, eax
    jnz  .corrupt
    mov  [rel img_jpg_scan_ptr], r14
    mov  r12, r14
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .scan
.seg_done:
    mov  r12, r14
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .marker
.eoi:
    call img_jpeg_four_metadata
    test eax, eax
    jnz  .unsupported
    cmp  byte [rel img_jpg_sof_seen], 1
    jne  .corrupt
    cmp  qword [rel img_jpg_scan_ptr], 0
    je   .truncated
    mov  [rel img_jpg_file_end], r12
    cmp  byte [rel img_jpg_sequential], 1
    je   .sequential_eoi
    cmp  byte [rel img_jpg_progressive], 1
    je   .progressive_eoi
    cmp  byte [rel img_jpg_asymmetric], 1
    je   .eoi_exact
    cmp  byte [rel img_jpg_exif_seen], 1
    je   .eoi_exact
    cmp  dword [rel img_jpg_ncomp], 4
    je   .eoi_exact
    cmp  dword [rel img_jpg_ncomp], 1
    je   .eoi_exact
    cmp  byte [rel img_jpg_restart_seen], 0
    je   .eoi_tables
.eoi_exact:
    cmp  r12, r13                     ; gray/DRI admit one exact complete file
    jne  .corrupt
    jmp  .eoi_tables
.sequential_eoi:
    cmp  r12, r13                     ; no suffix, forged EOI or second file
    jne  .corrupt
    mov  ecx, [rel img_jpg_ncomp]
    mov  eax, 1
    shl  eax, cl
    dec  eax
    cmp  eax, [rel img_jpg_sequential_mask]
    jne  .corrupt                     ; every component transmitted exactly once
    xor  eax, eax
    jmp  .out
.progressive_eoi:
    cmp  r12, r13
    jne  .corrupt
    call img_jpeg_progressive_complete
    test eax, eax
    jnz  .corrupt
    xor  eax, eax
    jmp  .out
.eoi_tables:
    call img_jpeg_validate_tables      ; full header lint precedes allocation
    test eax, eax
    jnz  .corrupt
    xor  eax, eax
    jmp  .out
.bad_magic:
    mov  eax, IMG_E_BAD_MAGIC
    jmp  .out
.bounds:
    mov  eax, IMG_E_BOUNDS
    jmp  .out
.truncated:
    mov  eax, IMG_E_TRUNCATED
    jmp  .out
.unsupported:
    mov  eax, IMG_E_UNSUPPORTED
    jmp  .out
.corrupt:
    mov  eax, IMG_E_CORRUPT
.out:
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Explicit color admission is checked before each SOS and again at EOI.
; Three-channel APP14 transform0: only exact R,G,B/444, valid single pre-scan
; Adobe marker, no JFIF or profile interpretation. No absent-marker RGB guess.
; Transform1 retains YCbCr (JFIF is consistent). Four channels retain CMYK/YCCK.
img_jpeg_four_metadata:
    xor  eax, eax
    cmp  dword [rel img_jpg_ncomp], 3
    je   .three
    cmp  dword [rel img_jpg_ncomp], 4
    jne  .out
    cmp  byte [rel img_jpg_jfif_seen], 0
    jne  .bad
    cmp  byte [rel img_jpg_color_bad], 0
    jne  .bad
    cmp  byte [rel img_jpg_adobe_seen], 1
    jne  .bad
    cmp  byte [rel img_jpg_adobe_transform], 2
    je   .out
    cmp  byte [rel img_jpg_adobe_transform], 0
    jne  .bad
    cmp  byte [rel img_jpg_max_h], 1   ; subsampled CMYK is outside this slice
    jne  .bad
    cmp  byte [rel img_jpg_max_v], 1
    jne  .bad
    jmp  .out
.three:
    cmp  byte [rel img_jpg_adobe_attempt], 0
    jne  .three_adobe
    ; Any RGB channel ID without the exact admitted declaration is ambiguous.
.three_ycc:
    xor  ecx, ecx
.unmarked_id:
    lea  rdx, [rel img_jpg_comp_id]
    mov  dl, [rdx + rcx]
    cmp  dl, 'R'
    je   .bad
    cmp  dl, 'G'
    je   .bad
    cmp  dl, 'B'
    je   .bad
    inc  ecx
    cmp  ecx, 3
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .unmarked_id
    jmp  .out
.three_adobe:
    cmp  byte [rel img_jpg_color_bad], 0
    jne  .bad
    cmp  byte [rel img_jpg_adobe_seen], 1
    jne  .bad
    cmp  byte [rel img_jpg_adobe_transform], 1
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    je   .three_ycc
    cmp  byte [rel img_jpg_adobe_transform], 0
    jne  .bad
    cmp  byte [rel img_jpg_jfif_seen], 0
    jne  .bad
    cmp  byte [rel img_jpg_comp_id], 'R'
    jne  .bad
    cmp  byte [rel img_jpg_comp_id + 1], 'G'
    jne  .bad
    cmp  byte [rel img_jpg_comp_id + 2], 'B'
    jne  .bad
    cmp  byte [rel img_jpg_max_h], 1
    jne  .bad
    cmp  byte [rel img_jpg_max_v], 1
    jne  .bad
    mov  byte [rel img_jpg_rgb], 1
    jmp  .out
.out:
    ret
.bad:
    mov  eax, IMG_E_UNSUPPORTED
    ret

; Public dimensions describe the final raster; coding geometry stays stored.
; Only ECX/EDX and flags change, including on the decode publication path.
img_jpeg_dimensions:
    mov  ecx, [rel img_jpg_width]
    mov  edx, [rel img_jpg_height]
    cmp  byte [rel img_jpg_orientation], 5
    jb   .out
    xchg ecx, edx
.out:
    ret

; CIPA DC-008 4.6.2/4.6.4: a bounded TIFF IFD0 only. Never chase its next-IFD
; or unknown field pointers. A single inline SHORT/count1 Orientation is read;
; absent means1, duplicate/malformed means corrupt, unsupported means refused.
; RDI=TIFF header, RSI=APP1 TIFF bytes. Only volatile registers are changed.
img_jpeg_exif:
    mov  r9, rdi
    mov  r10, rsi
    cmp  r10, 8
    jb   .truncated
    xor  r8d, r8d                     ; II
    cmp  word [rdi], 0x4949
    je   .header
    inc  r8d                          ; MM
    cmp  word [rdi], 0x4D4D
    jne  .corrupt
.header:
    add  rdi, 2
    call .u16
    cmp  eax, 42
    jne  .corrupt
    lea  rdi, [r9 + 4]
    call .u32
    cmp  eax, 8
    jb   .corrupt                     ; no overlap with TIFF header
    test al, 1
    jnz  .corrupt                     ; TIFF word-aligned IFD
    mov  edx, eax
    add  rdx, 2
    cmp  rdx, r10
    ja   .truncated
    lea  rdi, [r9 + rax]
    call .u16
    mov  r11d, eax
    imul eax, 12                      ; <=65535*12, wide span arithmetic
    add  rdx, rax
    add  rdx, 4                       ; include next-IFD field, never follow it
    cmp  rdx, r10
    ja   .truncated
    lea  rsi, [rdi + 2]
    xor  ecx, ecx                     ; Orientation occurrence count
.entry:
    test r11d, r11d
    jz   .ok
    mov  rdi, rsi
    call .u16
    cmp  eax, 274
    jne  .next
    test ecx, ecx
    jnz  .corrupt
    inc  ecx
    lea  rdi, [rsi + 2]
    call .u16
    cmp  eax, 3                       ; SHORT
    jne  .unsupported
    lea  rdi, [rsi + 4]
    call .u32
    cmp  eax, 1
    jne  .unsupported
    lea  rdi, [rsi + 8]
    call .u16                         ; left-justified in both endian forms
    cmp  eax, 1
    jb   .unsupported
    cmp  eax, 8
    ja   .unsupported
    mov  [rel img_jpg_orientation], al
.next:
    add  rsi, 12
    dec  r11d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .entry
.ok:
    xor  eax, eax
    ret
.u16:
    movzx eax, word [rdi]
    test r8d, r8d
    jz   .read
    rol  ax, 8
.read:
    ret
.u32:
    mov  eax, [rdi]
    test r8d, r8d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jz   .read
    bswap eax
    ret
.truncated:
    mov  eax, IMG_E_TRUNCATED
    ret
.corrupt:
    mov  eax, IMG_E_CORRUPT
    ret
.unsupported:
    mov  eax, IMG_E_UNSUPPORTED
    ret

img_jpeg_clear:
    IMG_COLD_OWNER_ONLY
    lea  rdi, [rel img_jpg_state_begin]
    lea  rcx, [rel img_jpg_state_end]
    sub  rcx, rdi
    xor  eax, eax
    IMG_COLD_MEMORY stosb
    ret

img_jpeg_decode:
    IMG_COLD_PUBLIC_GUARD
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub  rsp, 112                     ; digests, geometry, source/coeff tail offsets
    cld
    mov  r12, rdi
    mov  r13, rsi
    mov  dword [rsp + 72], 0
    mov  qword [rsp + 104], 0
    mov  [rel img_active_src], rdi
    mov  [rel img_active_len], rsi
    call img_jpeg_parse
    test eax, eax
    jnz  .out
    mov  eax, [rel img_jpg_width]
    imul eax, dword [rel img_jpg_height]
    shl  rax, 2
    mov  ecx, [rel img_jpg_ncomp]
    mov  [rsp + 88], ecx
    cmp  byte [rel img_jpg_asymmetric], 1
    je   .snapshot
    cmp  byte [rel img_jpg_exif_seen], 1
    je   .snapshot
    cmp  byte [rel img_jpg_buffered], 1
    je   .snapshot
    cmp  ecx, 4
    je   .snapshot
    cmp  ecx, 1
    je   .snapshot
    cmp  byte [rel img_jpg_restart_seen], 0
    je   .color_alloc
.snapshot:
    mov  dword [rsp + 72], 1
    movzx ecx, byte [rel img_jpg_buffered]
    mov  [rsp + 92], ecx
    movzx ecx, byte [rel img_jpg_orientation]
    mov  [rsp + 76], ecx
    mov  ecx, [rel img_jpg_width]
    mov  [rsp + 64], ecx
    mov  ecx, [rel img_jpg_height]
    mov  [rsp + 68], ecx
    add  rax, 15
    and  rax, -16
    mov  [rsp + 80], rax
    cmp  byte [rel img_jpg_buffered], 1
    jne  .snapshot_hash
    mov  rcx, [rel img_jpg_frame_bytes]
    mov  [rsp + 104], rcx
.snapshot_hash:
    lea  rdi, [rsp]
    mov  rsi, r12
    mov  rdx, r13
    IMG_COLD_DIGEST
    mov  rdi, [rsp + 80]
    add  rdi, r13                     ; RGBA <=16MiB, source <=32MiB
    add  rdi, 15
    and  rdi, -16
    mov  [rsp + 96], rdi              ; coefficient tail after aligned private file
    cmp  byte [rel img_jpg_buffered], 1
    jne  .snapshot_alloc
    add  rdi, [rel img_jpg_frame_bytes]
.snapshot_alloc:
    call img_output_alloc
    test rax, rax
    jz   .oom
    mov  r14, rax
    add  r14, [rsp + 80]
    mov  rdi, r14
    mov  rsi, r12
    mov  rcx, r13
    IMG_COLD_MEMORY movsb
    lea  rdi, [rsp + 32]
    mov  rsi, r14
    mov  rdx, r13
    IMG_COLD_DIGEST
    lea  rdi, [rsp]
    lea  rsi, [rsp + 32]
    mov  ecx, 32
    repe cmpsb
    jne  .corrupt_release
    xor  edx, edx
    cmp  byte [rel img_jpg_buffered], 1
    jne  .snapshot_parse
    mov  rdi, [rel img_active_out]
    add  rdi, [rsp + 96]
    mov  rdx, rdi
    mov  rcx, [rel img_jpg_frame_bytes]
    shr  rcx, 2
    xor  eax, eax
    IMG_COLD_MEMORY stosd                        ; untransmitted coefficients are zero
.snapshot_parse:
    mov  rdi, r14
    mov  rsi, r13
    mov  rcx, [rsp + 104]
    call img_jpeg_parse_coeff          ; private tables/entropy and buffered scan writes
    test eax, eax
    jnz  .corrupt_release
    movzx ecx, byte [rel img_jpg_buffered]
    cmp  ecx, [rsp + 92]
    jne  .corrupt_release              ; no private frame writes/render without its allocation
    mov  ecx, [rsp + 88]
    cmp  ecx, [rel img_jpg_ncomp]
    jne  .corrupt_release
    mov  eax, [rsp + 64]
    cmp  eax, [rel img_jpg_width]
    jne  .corrupt_release
    mov  eax, [rsp + 68]
    cmp  eax, [rel img_jpg_height]
    jne  .corrupt_release
    movzx eax, byte [rel img_jpg_orientation]
    cmp  eax, [rsp + 76]
    jne  .corrupt_release              ; bind preflight to private metadata too
    mov  [rel img_active_src], r14
    mov  rax, [rel img_active_out]
    jmp  .owned_ready
.color_alloc:
    mov  rdi, rax
    call img_output_alloc
    test rax, rax
    jz   .oom
.owned_ready:
    mov  [rel img_jpg_out], rax
    cmp  byte [rel img_jpg_buffered], 1
    je   .progressive_render
    call img_jpeg_validate_tables
    test eax, eax
    jnz  .corrupt_release
    mov  rdi, [rel img_jpg_scan_ptr]
    mov  rsi, [rel img_jpg_scan_end]
    sub  rsi, rdi
    call img_jpeg_bs_init
    mov  dword [rel img_jpg_dc_pred], 0
    mov  dword [rel img_jpg_dc_pred + 4], 0
    mov  dword [rel img_jpg_dc_pred + 8], 0
    mov  dword [rel img_jpg_dc_pred + 12], 0
    mov  eax, [rel img_jpg_restart_interval]
    mov  [rel img_jpg_restart_left], eax
    mov  dword [rel img_jpg_restart_next], 0

    movzx eax, byte [rel img_jpg_max_h]
    shl  eax, 3
    mov  [rel img_jpg_mcu_w], eax
    mov  ecx, [rel img_jpg_width]
    add  ecx, eax
    dec  ecx
    mov  eax, ecx
    xor  edx, edx
    div  dword [rel img_jpg_mcu_w]
    mov  [rel img_jpg_mcu_cols], eax
    movzx eax, byte [rel img_jpg_max_v]
    shl  eax, 3
    mov  [rel img_jpg_mcu_h], eax
    mov  ecx, [rel img_jpg_height]
    add  ecx, eax
    dec  ecx
    mov  eax, ecx
    xor  edx, edx
    div  dword [rel img_jpg_mcu_h]
    mov  [rel img_jpg_mcu_rows], eax
    xor  ebp, ebp                       ; mcu y
.mcu_y:
    cmp  ebp, [rel img_jpg_mcu_rows]
    jae  .success
    xor  r15d, r15d                     ; mcu x
.mcu_x:
    cmp  r15d, [rel img_jpg_mcu_cols]
    jae  .next_mcu_y
    cmp  dword [rel img_jpg_restart_interval], 0
    je   .decode_mcu
    cmp  dword [rel img_jpg_restart_left], 0
    jne  .decode_mcu
    call img_jpeg_restart
    test eax, eax
    jnz  .corrupt_release
.decode_mcu:
    call img_jpeg_decode_mcu
    test eax, eax
    jnz  .corrupt_release
    mov  edi, r15d
    mov  esi, ebp
    call img_jpeg_write_mcu
    cmp  dword [rel img_jpg_restart_interval], 0
    je   .advance_mcu
    dec  dword [rel img_jpg_restart_left]
.advance_mcu:
    inc  r15d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .mcu_x
.next_mcu_y:
    inc  ebp
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .mcu_y
.progressive_render:
    call img_jpeg_progressive_render
    test eax, eax
    jnz  .corrupt_release
    jmp  .publish
.success:
    cmp  dword [rsp + 72], 1
    jne  .publish
    mov  rax, [rel img_jpg_bs_ptr]
    cmp  rax, [rel img_jpg_bs_end]
    jne  .corrupt_release              ; no extra entropy or additional coded blocks
    mov  ecx, [rel img_jpg_bs_n]
    mov  eax, 1
    shl  eax, cl
    dec  eax
    mov  edx, [rel img_jpg_bs_buf]
    and  edx, eax
    cmp  edx, eax                      ; T.81 B.1.1.5/F.1.2.3 final fill bits are ones
    jne  .corrupt_release
.publish:
    mov  rbx, [rel img_jpg_out]
    call img_jpeg_dimensions
    mov  r8d, IMG_FMT_JPEG
    cmp  dword [rsp + 72], 1
    jne  .published
    call img_codec_state_clear
    mov  qword [rel img_active_src], 0
    mov  qword [rel img_active_len], 0
.published:
    xor  eax, eax
    jmp  .out
.corrupt_release:
    call img_output_release
    mov  eax, IMG_E_CORRUPT
    jmp  .out
.oom:
    mov  eax, IMG_E_OOM
.out:
    test eax, eax
    jz   .return
    call img_refusal_clear
.return:
    add  rsp, 112
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    ret

img_jpeg_validate_tables:
    xor  ecx, ecx
.comp:
    cmp  ecx, [rel img_jpg_ncomp]
    jae  .ok
    lea  rdi, [rel img_jpg_comp_qt]
    movzx eax, byte [rdi + rcx]
    lea  rdi, [rel img_jpg_qpresent]
    cmp  byte [rdi + rax], 1
    jne  .bad
    lea  rdi, [rel img_jpg_comp_dc]
    movzx eax, byte [rdi + rcx]
    lea  rdi, [rel img_jpg_hpresent]
    cmp  byte [rdi + rax], 1
    jne  .bad
    lea  rdi, [rel img_jpg_comp_ac]
    movzx eax, byte [rdi + rcx]
    add  eax, 2
    lea  rdi, [rel img_jpg_hpresent]
    cmp  byte [rdi + rax], 1
    jne  .bad
    push rcx
    mov  edi, eax
    call img_jpeg_baseline_ac_table
    pop  rcx
    test eax, eax
    jnz  .bad
    inc  ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .comp
.ok:
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; Decode every component block for one MCU into img_jpg_samples.
img_jpeg_decode_mcu:
    push rbx
    push r12
    push r13
    xor  r12d, r12d                    ; component
    xor  r13d, r13d                    ; sample-block offset
.comp:
    cmp  r12d, [rel img_jpg_ncomp]
    jae  .ok
    lea  rdi, [rel img_jpg_comp_h]
    movzx ebx, byte [rdi + r12]
    lea  rdi, [rel img_jpg_comp_v]
    movzx eax, byte [rdi + r12]
    imul ebx, eax
.block:
    test ebx, ebx
    jz   .next_comp
    mov  edi, r12d
    call img_jpeg_decode_block
    test eax, eax
    jnz  .bad
    lea  rdi, [rel img_jpg_coeff]
    lea  rsi, [rel img_jpg_samples]
    mov  eax, r13d
    shl  eax, 6
    add  rsi, rax
    call img_jpeg_idct
    inc  r13d
    dec  ebx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .block
.next_comp:
    inc  r12d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .comp
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=component. Decode/dequantize one 8x8 block.
img_jpeg_decode_block:
    push rbx
    push r12
    push r13
    push r14
    mov  r14d, edi
    lea  rdi, [rel img_jpg_coeff]
    xor  eax, eax
    mov  ecx, 64
    IMG_COLD_MEMORY stosd
    lea  rdi, [rel img_jpg_comp_dc]
    movzx edi, byte [rdi + r14]
    call img_jpeg_huff
    jc   .bad
    cmp  eax, 11
    ja   .bad
    mov  ebx, eax
    mov  edi, eax
    call img_jpeg_receive
    jc   .bad
    lea  rdi, [rel img_jpg_dc_pred]
    add  eax, [rdi + r14 * 4]
    cmp  dword [rel img_jpg_ncomp], 1
    je   .dc_range_check
    cmp  byte [rel img_jpg_restart_seen], 0
    je   .dc_range_ok
.dc_range_check:
    cmp  eax, -1024                    ; bounded 8-bit quantized DC coefficient
    jl   .bad
    cmp  eax, 1023
    jg   .bad
.dc_range_ok:
    mov  [rdi + r14 * 4], eax
    lea  rdi, [rel img_jpg_comp_qt]
    movzx edx, byte [rdi + r14]
    shl  edx, 6
    lea  rdi, [rel img_jpg_qtables]
    movzx ecx, byte [rdi + rdx]
    imul eax, ecx
    mov  [rel img_jpg_coeff], eax
    mov  r12d, 1
.ac:
    cmp  r12d, 64
    jae  .ok
    lea  rdi, [rel img_jpg_comp_ac]
    movzx edi, byte [rdi + r14]
    add  edi, 2
    call img_jpeg_huff
    jc   .bad
    test eax, eax
    jz   .ok
    cmp  eax, 0xF0
    je   .zrl
    mov  ebx, eax
    shr  ebx, 4
    add  r12d, ebx
    cmp  r12d, 64
    jae  .bad
    and  eax, 0x0F
    cmp  eax, 10
    ja   .bad
    mov  edi, eax
    call img_jpeg_receive
    jc   .bad
    lea  rdi, [rel img_jpg_comp_qt]
    movzx edx, byte [rdi + r14]
    shl  edx, 6
    lea  rdi, [rel img_jpg_qtables]
    add  rdx, r12
    movzx ecx, byte [rdi + rdx]
    imul eax, ecx
    lea  rdi, [rel img_jpg_zigzag]
    movzx edx, byte [rdi + r12]
    lea  rdi, [rel img_jpg_coeff]
    mov  [rdi + rdx * 4], eax
    inc  r12d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .ac
.zrl:
    add  r12d, 16
    cmp  r12d, 64
    ja   .bad
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .ac
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

img_jpeg_bs_init:
    mov  [rel img_jpg_bs_ptr], rdi
    lea  rax, [rdi + rsi]
    mov  [rel img_jpg_bs_end], rax
    mov  dword [rel img_jpg_bs_buf], 0
    mov  dword [rel img_jpg_bs_n], 0
    ret

; Called before the next MCU, never after the final MCU. No speculative byte
; reads: the one-byte bit reader leaves exactly0..7 unused bits in its buffer.
img_jpeg_restart:
    mov  ecx, [rel img_jpg_bs_n]
    mov  eax, 1
    shl  eax, cl
    dec  eax
    mov  edx, [rel img_jpg_bs_buf]
    and  edx, eax
    cmp  edx, eax                     ; T.81 F.1.2.3 all remaining bits are1
    jne  .bad
    mov  rdx, [rel img_jpg_bs_ptr]
    cmp  rdx, [rel img_jpg_bs_end]
    jae  .bad
    cmp  byte [rdx], 0xFF
    jne  .bad                         ; no entropy bytes may be skipped
.fill:
    inc  rdx
    cmp  rdx, [rel img_jpg_bs_end]
    jae  .bad
    cmp  byte [rdx], 0xFF
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    je   .fill
    movzx eax, byte [rdx]
    sub  eax, 0xD0
    cmp  eax, [rel img_jpg_restart_next]
    jne  .bad
    inc  rdx
    mov  [rel img_jpg_bs_ptr], rdx
    inc  eax
    and  eax, 7
    mov  [rel img_jpg_restart_next], eax
    mov  dword [rel img_jpg_bs_n], 0
    mov  dword [rel img_jpg_bs_buf], 0
    mov  dword [rel img_jpg_dc_pred], 0
    mov  dword [rel img_jpg_dc_pred + 4], 0
    mov  dword [rel img_jpg_dc_pred + 8], 0
    mov  dword [rel img_jpg_dc_pred + 12], 0
    mov  eax, [rel img_jpg_restart_interval]
    mov  [rel img_jpg_restart_left], eax
    xor  eax, eax
    ret
.bad:
    mov  eax, IMG_E_CORRUPT
    ret

img_jpeg_bit:
    cmp  dword [rel img_jpg_bs_n], 0
    jne  .have
    mov  rdx, [rel img_jpg_bs_ptr]
    cmp  rdx, [rel img_jpg_bs_end]
    jae  .bad
    movzx eax, byte [rdx]
    inc  rdx
    cmp  al, 0xFF
    jne  .store
    cmp  rdx, [rel img_jpg_bs_end]
    jae  .bad
    cmp  byte [rdx], 0
    jne  .bad
    inc  rdx
.store:
    mov  [rel img_jpg_bs_ptr], rdx
    mov  [rel img_jpg_bs_buf], eax
    mov  dword [rel img_jpg_bs_n], 8
.have:
    dec  dword [rel img_jpg_bs_n]
    mov  ecx, [rel img_jpg_bs_n]
    mov  eax, [rel img_jpg_bs_buf]
    shr  eax, cl
    and  eax, 1
    clc
    ret
.bad:
    xor  eax, eax
    stc
    ret

img_jpeg_bits:
    push rbx
    mov  ecx, edi
    xor  ebx, ebx
.loop:
    test ecx, ecx
    jz   .ok
    shl  ebx, 1
    push rcx
    call img_jpeg_bit
    pop  rcx
    jc   .bad
    or   ebx, eax
    dec  ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .loop
.ok:
    mov  eax, ebx
    clc
    pop  rbx
    ret
.bad:
    xor  eax, eax
    stc
    pop  rbx
    ret

; EDI=table index -> EAX symbol, CF invalid/EOF.
img_jpeg_huff:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    xor  ebx, ebx                       ; code
    xor  r13d, r13d                     ; symbol base
    xor  esi, esi                       ; first code
    xor  ecx, ecx                       ; length index
.len:
    cmp  ecx, 16
    jae  .bad
    push rcx
    call img_jpeg_bit
    pop  rcx
    jc   .bad
    shl  ebx, 1
    or   ebx, eax
    lea  rdi, [rel img_jpg_hcounts]
    mov  edx, r12d
    shl  edx, 4
    add  rdx, rcx
    movzx eax, byte [rdi + rdx]
    mov  edx, ebx
    sub  edx, esi
    cmp  edx, eax
    jb   .found
    add  r13d, eax
    add  esi, eax
    shl  esi, 1
    inc  ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .len
.found:
    add  r13d, edx
    lea  rdi, [rel img_jpg_hsymbols]
    mov  eax, r12d
    shl  eax, 8
    add  rax, r13
    movzx eax, byte [rdi + rax]
    clc
    jmp  .out
.bad:
    xor  eax, eax
    stc
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=category -> signed value.
img_jpeg_receive:
    test edi, edi
    jz   .zero
    push rdi
    call img_jpeg_bits
    pop  rdi
    jc   .bad
    mov  ecx, edi
    dec  ecx
    mov  edx, 1
    shl  edx, cl
    cmp  eax, edx
    jae  .ok
    inc  ecx
    mov  edx, 1
    shl  edx, cl
    dec  edx
    sub  eax, edx
.ok:
    clc
    ret
.zero:
    xor  eax, eax
    clc
    ret
.bad:
    xor  eax, eax
    stc
    ret

; Direct fixed-point IDCT. RDI=64 dwords, RSI=64 output bytes.
img_jpeg_idct:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  r12, rdi
    mov  r13, rsi
    xor  r14d, r14d                     ; y
.y:
    xor  r15d, r15d                     ; x
.x:
    xor  rbp, rbp                       ; signed 64-bit sum
    xor  ebx, ebx                       ; v
.v:
    xor  ecx, ecx                       ; u
.u:
    mov  eax, ebx
    shl  eax, 3
    add  eax, ecx
    movsxd rax, dword [r12 + rax * 4]
    lea  rdi, [rel img_jpg_idct_matrix]
    mov  edx, r15d
    shl  edx, 3
    add  edx, ecx
    movsx rdx, word [rdi + rdx * 2]
    imul rax, rdx
    mov  edx, r14d
    shl  edx, 3
    add  edx, ebx
    movsx rdx, word [rdi + rdx * 2]
    imul rax, rdx
    add  rbp, rax
    inc  ecx
    cmp  ecx, 8
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .u
    inc  ebx
    cmp  ebx, 8
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .v
    sar  rbp, 26                       ; / (4 * 4096 * 4096)
    add  ebp, 128
    cmp  ebp, 0
    jge  .not_low
    xor  ebp, ebp
.not_low:
    cmp  ebp, 255
    jle  .store
    mov  ebp, 255
.store:
    mov  eax, r14d
    shl  eax, 3
    add  eax, r15d
    mov  [r13 + rax], bpl
    inc  r15d
    cmp  r15d, 8
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .x
    inc  r14d
    cmp  r14d, 8
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .y
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=mcu x, ESI=mcu y. Sample each component at its declared ratio.
img_jpeg_write_mcu:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  r14d, edi
    mov  r15d, esi
    xor  ebp, ebp                       ; dy
.dy:
    cmp  ebp, [rel img_jpg_mcu_h]
    jae  .out
    mov  eax, r15d
    imul eax, [rel img_jpg_mcu_h]
    add  eax, ebp
    cmp  eax, [rel img_jpg_height]
    jae  .out
    mov  r13d, eax                      ; absolute y
    xor  r12d, r12d                     ; dx
.dx:
    cmp  r12d, [rel img_jpg_mcu_w]
    jae  .next_y
    mov  eax, r14d
    imul eax, [rel img_jpg_mcu_w]
    add  eax, r12d
    cmp  eax, [rel img_jpg_width]
    jae  .next_y
    mov  ebx, eax                       ; absolute x
    mov  edi, 0
    mov  esi, r12d
    mov  edx, ebp
    call img_jpeg_sample
    mov  r8d, eax                       ; Y
    cmp  dword [rel img_jpg_ncomp], 1
    jne  .color
    mov  eax, r8d
    mov  edx, r8d
    mov  ecx, r8d
    jmp  .write
.color:
    push rax                            ; preserve Y across component sampling
    mov  edi, 1
    mov  esi, r12d
    mov  edx, ebp
    call img_jpeg_sample
    push rax                            ; preserve Cb
    mov  edi, 2
    mov  esi, r12d
    mov  edx, ebp
    call img_jpeg_sample
    mov  r10d, eax                      ; Cr
    pop  r9                             ; Cb
    pop  r8                             ; Y/C
    cmp  byte [rel img_jpg_rgb], 1
    je   .rgb
    cmp  dword [rel img_jpg_ncomp], 4
    jne  .ycc
    cmp  byte [rel img_jpg_adobe_transform], 0
    jne  .ycc
    mov  eax, r8d                      ; inverted Adobe C/M/Y samples
    mov  ecx, r9d
    mov  edx, r10d
    jmp  .black
.ycc:
    ; Fixed-point YCbCr -> RGB (coefficients scaled by 256).
    sub  r9d, 128
    sub  r10d, 128
    mov  eax, r10d
    imul eax, 359
    sar  eax, 8
    add  eax, r8d                       ; R
    mov  edx, r9d
    imul edx, 88
    mov  ecx, r10d
    imul ecx, 183
    add  edx, ecx
    sar  edx, 8
    mov  ecx, r8d
    sub  ecx, edx                       ; G
    mov  edx, r9d
    imul edx, 454
    sar  edx, 8
    add  edx, r8d                       ; B
    call img_jpeg_clamp_rgb
    cmp  dword [rel img_jpg_ncomp], 4
    jne  .write
    xor  eax, 255                      ; YCCK -> inverted CMY (libjpeg jdcolor)
    xor  ecx, 255
    xor  edx, 255
.black:
    push rax
    push rcx
    push rdx
    mov  edi, 3
    mov  esi, r12d
    mov  edx, ebp
    call img_jpeg_sample
    mov  r11d, eax                     ; Adobe inverted K, unchanged by YCCK
    pop  r10
    pop  r9
    pop  r8
    ; Device CMYK fallback: round(C*K/255), no ICC conversion. Products <=65025.
    imul r8d, r11d
    lea  eax, [r8 + 127]
    xor  edx, edx
    mov  edi, 255
    div  edi
    mov  r8d, eax
    imul r9d, r11d
    lea  eax, [r9 + 127]
    xor  edx, edx
    div  edi
    mov  ecx, eax
    imul r10d, r11d
    lea  eax, [r10 + 127]
    xor  edx, edx
    div  edi
    mov  edx, eax
    mov  eax, r8d
    jmp  .write
.rgb:
    mov  eax, r8d                      ; decoded R/G/B planes: no color transform
    mov  ecx, r9d
    mov  edx, r10d
.write:
    ; Source (EBX,R13D) is clipped in stored geometry. Apply Exif once at
    ; the shared baseline/progressive store, before any cache resampling.
    ; Preserve RGB in EAX/ECX/EDX. The permutation uses the same pixel count.
    mov  edi, ebx                     ; output x
    mov  esi, r13d                    ; output y
    mov  r9d, [rel img_jpg_width]      ; output stride
    movzx r11d, byte [rel img_jpg_orientation]
    cmp  r11d, 1
    jbe  .pixel_index
    cmp  r11d, 5
    jae  .transpose
    cmp  r11d, 4
    je   .flip_y
    mov  edi, r9d
    dec  edi
    sub  edi, ebx                     ; 2/3: reflect x
    cmp  r11d, 2
    je   .pixel_index
.flip_y:
    mov  esi, [rel img_jpg_height]
    dec  esi
    sub  esi, r13d                    ; 3/4: reflect y
    jmp  .pixel_index
.transpose:
    mov  edi, r13d
    mov  esi, ebx
    mov  r9d, [rel img_jpg_height]     ; 5..8: swapped axes and stride
    cmp  r11d, 6
    jb   .pixel_index                 ; 5: transpose
    cmp  r11d, 8
    je   .transpose_y
    mov  edi, r9d
    dec  edi
    sub  edi, r13d                    ; 6/7: reflect transposed x
    cmp  r11d, 6
    je   .pixel_index
.transpose_y:
    mov  esi, [rel img_jpg_width]
    dec  esi
    sub  esi, ebx                     ; 7/8: reflect transposed y
.pixel_index:
    imul esi, r9d
    add  edi, esi
    shl  edi, 2
    mov  rsi, [rel img_jpg_out]
    mov  [rsi + rdi], al
    mov  [rsi + rdi + 1], cl
    mov  [rsi + rdi + 2], dl
    mov  byte [rsi + rdi + 3], 0xFF
    inc  r12d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .dx
.next_y:
    inc  ebp
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .dy
.out:
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=component, ESI=dx, EDX=dy -> EAX sample.
img_jpeg_sample:
    push rbx
    push r12
    mov  r12d, edi
    mov  r8d, edx                       ; preserve dy across DIV remainder writes
    lea  rdi, [rel img_jpg_comp_h]
    movzx ecx, byte [rdi + r12]
    imul esi, ecx
    movzx ecx, byte [rel img_jpg_max_h]
    mov  eax, esi
    xor  edx, edx
    div  ecx
    mov  esi, eax                       ; component x
    mov  eax, r8d
    lea  rdi, [rel img_jpg_comp_v]
    movzx ecx, byte [rdi + r12]
    imul eax, ecx
    movzx ecx, byte [rel img_jpg_max_v]
    xor  edx, edx
    div  ecx
    mov  ebx, eax                       ; component y
    xor  edi, edi                       ; prior component block base
    xor  ecx, ecx
.base:
    cmp  ecx, r12d
    jae  .base_done
    lea  rdx, [rel img_jpg_comp_h]
    movzx eax, byte [rdx + rcx]
    lea  rdx, [rel img_jpg_comp_v]
    movzx edx, byte [rdx + rcx]
    imul eax, edx
    add  edi, eax
    inc  ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .base
.base_done:
    mov  eax, ebx
    shr  eax, 3
    lea  rdx, [rel img_jpg_comp_h]
    movzx edx, byte [rdx + r12]
    imul eax, edx
    mov  ecx, esi
    shr  ecx, 3
    add  eax, ecx
    add  edi, eax                       ; block index
    and  ebx, 7
    and  esi, 7
    shl  ebx, 3
    add  ebx, esi
    shl  edi, 6
    add  edi, ebx
    lea  rdx, [rel img_jpg_samples]
    movzx eax, byte [rdx + rdi]
    pop  r12
    pop  rbx
    ret

img_jpeg_clamp_rgb:
    test eax, eax
    jns  .r_hi
    xor  eax, eax
.r_hi:
    cmp  eax, 255
    jle  .g_lo
    mov  eax, 255
.g_lo:
    test ecx, ecx
    jns  .g_hi
    xor  ecx, ecx
.g_hi:
    cmp  ecx, 255
    jle  .b_lo
    mov  ecx, 255
.b_lo:
    test edx, edx
    jns  .b_hi
    xor  edx, edx
.b_hi:
    cmp  edx, 255
    jle  .done
    mov  edx, 255
.done:
    ret

; Retain the baseline symbol restrictions after admitting progressive EOBr tables.
; EDI=active AC table index. Progressive never calls this baseline validator.
img_jpeg_baseline_ac_table:
    lea  r8, [rel img_jpg_hcounts]
    mov  eax, edi
    shl  eax, 4
    add  r8, rax
    xor  ecx, ecx
    xor  edx, edx
.count:
    movzx eax, byte [r8 + rcx]
    add  edx, eax
    inc  ecx
    cmp  ecx, 16
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .count
    lea  r8, [rel img_jpg_hsymbols]
    shl  edi, 8
    add  r8, rdi
    xor  ecx, ecx
.symbol:
    cmp  ecx, edx
    jae  .ok
    movzx eax, byte [r8 + rcx]
    test al, al
    jz   .next
    cmp  al, 0xF0
    je   .next
    and  eax, 15
    jz   .bad
.next:
    inc  ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .symbol
.ok:
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; Derive padded frame coefficients and noninterleaved scan geometry under the
; existing dimension/pixel limits. Every offset is64-bit and <=JPG_FRAME_CAP.
img_jpeg_frame_geometry:
    push rbx
    push r12
    push r13
    push r14
    xor  ebx, ebx
.ids:
    cmp  ebx, [rel img_jpg_ncomp]
    jae  .geometry
    xor  ecx, ecx
    lea  rdi, [rel img_jpg_comp_id]
.unique:
    cmp  ecx, ebx
    jae  .next_id
    mov  al, [rdi + rbx]
    cmp  al, [rdi + rcx]
    je   .bad
    inc  ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .unique
.next_id:
    inc  ebx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .ids
.geometry:
    movzx ecx, byte [rel img_jpg_max_h]
    shl  ecx, 3
    mov  [rel img_jpg_mcu_w], ecx
    mov  eax, [rel img_jpg_width]
    lea  eax, [rax + rcx - 1]
    xor  edx, edx
    div  ecx
    mov  [rel img_jpg_mcu_cols], eax
    mov  r12d, eax
    movzx ecx, byte [rel img_jpg_max_v]
    shl  ecx, 3
    mov  [rel img_jpg_mcu_h], ecx
    mov  eax, [rel img_jpg_height]
    lea  eax, [rax + rcx - 1]
    xor  edx, edx
    div  ecx
    mov  [rel img_jpg_mcu_rows], eax
    mov  r13d, eax
    xor  r14d, r14d
    xor  ebx, ebx
.comp:
    cmp  ebx, [rel img_jpg_ncomp]
    jae  .done
    lea  rdi, [rel img_jpg_comp_offset]
    mov  [rdi + rbx * 8], r14
    lea  rdi, [rel img_jpg_comp_h]
    movzx eax, byte [rdi + rbx]
    imul eax, r12d
    lea  rdi, [rel img_jpg_padded_cols]
    mov  [rdi + rbx * 4], eax
    lea  rdi, [rel img_jpg_comp_v]
    movzx edx, byte [rdi + rbx]
    imul edx, r13d
    imul rax, rdx
    shl  rax, 8                       ; 64 signed32 coefficients per block
    add  r14, rax
    jc   .bad
    cmp  r14, JPG_FRAME_CAP
    ja   .bad
    lea  rdi, [rel img_jpg_comp_h]
    movzx eax, byte [rdi + rbx]
    imul eax, [rel img_jpg_width]
    mov  ecx, [rel img_jpg_mcu_w]
    lea  eax, [rax + rcx - 1]
    xor  edx, edx
    div  ecx
    lea  rdi, [rel img_jpg_block_cols]
    mov  [rdi + rbx * 4], eax
    lea  rdi, [rel img_jpg_comp_v]
    movzx eax, byte [rdi + rbx]
    imul eax, [rel img_jpg_height]
    mov  ecx, [rel img_jpg_mcu_h]
    lea  eax, [rax + rcx - 1]
    xor  edx, edx
    div  ecx
    lea  rdi, [rel img_jpg_block_rows]
    mov  [rdi + rbx * 4], eax
    inc  ebx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .comp
.done:
    cmp  qword [rel img_jpg_frame], 0
    je   .capacity_ok
    cmp  r14, [rel img_jpg_frame_capacity]
    jne  .bad                         ; bind private parse before any coefficient write
.capacity_ok:
    mov  [rel img_jpg_frame_bytes], r14
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RSI=new64 values,R8D=table destination. T.81 B.2.4: a quantization table
; cannot change between progressive scans of any component that uses it.
; Preserve the copy's RSI/RDI/R8. A redefinition with identical values is valid.
img_jpeg_quant_change:
    push rsi
    push rdi
    cmp  byte [rel img_jpg_progressive], 1
    jne  .ok
    xor  ecx, ecx
.comp:
    cmp  ecx, [rel img_jpg_ncomp]
    jae  .ok
    lea  rax, [rel img_jpg_quant_locked]
    cmp  byte [rax + rcx], 0
    je   .next
    lea  rax, [rel img_jpg_comp_qt]
    cmp  [rax + rcx], r8b
    jne  .next
    mov  eax, ecx
    shl  eax, 6
    lea  rdi, [rel img_jpg_component_quant]
    add  rdi, rax
    xor  edx, edx
.compare:
    mov  al, [rdi + rdx]
    cmp  al, [rsi + rdx]
    jne  .bad
    inc  edx
    cmp  edx, 64
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .compare
.next:
    inc  ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .comp
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  rdi
    pop  rsi
    ret

; Parser registers R15=payload,RBX=length,R14=segmentend. Validate scan syntax,
; sequential coverage or progressive coefficient history, tables and exact RST count. No alloc.
img_jpeg_progressive_header:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, r15
    cmp  ebx, 8
    jb   .bad
    movzx r13d, byte [r12]
    test r13d, r13d
    jz   .bad
    cmp  r13d, [rel img_jpg_ncomp]
    ja   .bad
    lea  eax, [r13 + r13 + 6]
    cmp  ebx, eax
    jne  .bad
    mov  [rel img_jpg_scan_ncomp], r13d
    lea  rdi, [r12 + r13 * 2 + 1]
    movzx eax, byte [rdi]
    mov  [rel img_jpg_ss], eax
    movzx edx, byte [rdi + 1]
    mov  [rel img_jpg_se], edx
    cmp  byte [rel img_jpg_sequential], 1
    jne  .progressive_band
    test eax, eax
    jnz  .bad
    cmp  edx, 63
    jne  .bad
    cmp  byte [rdi + 2], 0
    jne  .bad                         ; baseline is full spectrum, no approximation
    jmp  .select
.progressive_band:
    cmp  edx, 63
    ja   .bad
    cmp  eax, edx
    ja   .bad
    test eax, eax
    jnz  .ac_band
    test edx, edx
    jnz  .bad
    jmp  .approx
.ac_band:
    cmp  r13d, 1
    jne  .bad
.approx:
    movzx eax, byte [rdi + 2]
    mov  edx, eax
    shr  edx, 4
    and  eax, 15
    cmp  eax, 13
    ja   .bad
    mov  [rel img_jpg_al], eax
    mov  [rel img_jpg_ah], edx
    test edx, edx
    jz   .select
    dec  edx
    cmp  edx, eax
    jne  .bad
.select:
    xor  r14d, r14d                    ; selected component ordinal
    xor  r15d, r15d                    ; uniqueness mask
.comp:
    cmp  r14d, r13d
    jae  .scan_geometry
    mov  al, [r12 + r14 * 2 + 1]
    xor  ebx, ebx
.find:
    cmp  ebx, [rel img_jpg_ncomp]
    jae  .bad
    lea  rdi, [rel img_jpg_comp_id]
    cmp  al, [rdi + rbx]
    je   .found
    inc  ebx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .find
.found:
    bts  r15d, ebx
    jc   .bad
    test r14d, r14d
    jz   .component_ordered
    lea  rdi, [rel img_jpg_scan_components]
    cmp  [rdi + r14 - 1], bl
    jae  .bad                         ; T.81 B.2.3: every scan follows frame order
.component_ordered:
    cmp  byte [rel img_jpg_sequential], 1
    jne  .component_selected
    bts  dword [rel img_jpg_sequential_mask], ebx
    jc   .bad                         ; no duplicate within/across sequential scans
.component_selected:
    lea  rdi, [rel img_jpg_scan_components]
    mov  [rdi + r14], bl
    movzx eax, byte [r12 + r14 * 2 + 2]
    mov  edx, eax
    shr  edx, 4
    and  eax, 15
    cmp  byte [rel img_jpg_sequential], 1
    jne  .progressive_selectors
    mov  ecx, 1                       ; SOF0 permits two DC/AC destinations
    cmp  byte [rel img_jpg_extended], 1
    jne  .sequential_selectors
    mov  ecx, 3                       ; SOF1 permits four, same Huffman8 bounds
.sequential_selectors:
    cmp  eax, ecx
    ja   .bad
    cmp  edx, ecx
    ja   .bad
    jmp  .map_selectors
.progressive_selectors:
    cmp  eax, 3
    ja   .bad
    cmp  edx, 3
    ja   .bad
    ; T.81 B.2.3 table B.3 permits0..3 for both selectors in
    ; progressive scans. Only the active DC/AC selector is consumed.
    ; Common stock JPEGs carry Ta=1 in a DC-only chroma scan.
    jmp  .map_selectors
.map_selectors:
    mov  ecx, eax
    and  ecx, 2
    and  eax, 1
    lea  eax, [rax + rcx * 2]
    lea  rdi, [rel img_jpg_comp_ac]
    mov  [rdi + rbx], al
    mov  ecx, edx
    and  ecx, 2
    and  edx, 1
    lea  edx, [rdx + rcx * 2]
    lea  rdi, [rel img_jpg_comp_dc]
    mov  [rdi + rbx], dl
    cmp  byte [rel img_jpg_sequential], 1
    jne  .progressive_table
    lea  rdi, [rel img_jpg_hpresent]
    cmp  byte [rdi + rdx], 1
    jne  .bad
    add  eax, 2
    cmp  byte [rdi + rax], 1
    jne  .bad
    mov  edi, eax
    call img_jpeg_baseline_ac_table    ; no progressive EOB-run alphabet in SOF0
    test eax, eax
    jnz  .bad
    jmp  .quant
.progressive_table:
    cmp  dword [rel img_jpg_ss], 0
    jne  .ac_table
    cmp  dword [rel img_jpg_ah], 0
    jne  .quant                       ; DC refinement has no Huffman symbols
    mov  eax, edx
    jmp  .table
.ac_table:
    add  eax, 2
.table:
    lea  rdi, [rel img_jpg_hpresent]
    cmp  byte [rdi + rax], 1
    jne  .bad
.quant:
    lea  rdi, [rel img_jpg_comp_qt]
    movzx eax, byte [rdi + rbx]
    lea  rdi, [rel img_jpg_qpresent]
    cmp  byte [rdi + rax], 1
    jne  .bad
    lea  rdi, [rel img_jpg_quant_locked]
    cmp  byte [rdi + rbx], 1
    je   .history
    mov  byte [rdi + rbx], 1
    shl  eax, 6
    lea  rsi, [rel img_jpg_qtables]
    add  rsi, rax
    mov  eax, ebx
    shl  eax, 6
    lea  rdi, [rel img_jpg_component_quant]
    add  rdi, rax
    mov  ecx, 64
    IMG_COLD_MEMORY movsb
.history:
    cmp  byte [rel img_jpg_sequential], 1
    je   .component_done              ; sequential uses whole-component coverage
    mov  eax, ebx
    shl  eax, 6
    lea  rdi, [rel img_jpg_progress_bits]
    add  rdi, rax
    cmp  dword [rel img_jpg_ss], 0
    je   .history_start
    cmp  byte [rdi], 255               ; AC requires preceding DC for this component
    je   .bad
.history_start:
    mov  ecx, [rel img_jpg_ss]
.coefficient:
    mov  eax, [rel img_jpg_ah]
    test eax, eax
    jnz  .refine_history
    cmp  byte [rdi + rcx], 255         ; one initial transmission only
    jne  .bad
    jmp  .history_store
.refine_history:
    cmp  [rdi + rcx], al               ; previous Al must equal this Ah
    jne  .bad
.history_store:
    mov  eax, [rel img_jpg_al]
    mov  [rdi + rcx], al
    inc  ecx
    cmp  ecx, [rel img_jpg_se]
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jbe  .coefficient
.component_done:
    inc  r14d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .comp
.scan_geometry:
    mov  eax, [rel img_jpg_mcu_cols]
    mov  edx, [rel img_jpg_mcu_rows]
    cmp  r13d, 1
    jne  .geometry_store
    lea  rdi, [rel img_jpg_scan_components]
    movzx ecx, byte [rdi]
    lea  rdi, [rel img_jpg_block_cols]
    mov  eax, [rdi + rcx * 4]
    lea  rdi, [rel img_jpg_block_rows]
    mov  edx, [rdi + rcx * 4]
.geometry_store:
    mov  [rel img_jpg_scan_cols], eax
    mov  [rel img_jpg_scan_rows], edx
    imul eax, edx
    dec  eax
    mov  dword [rel img_jpg_restart_count], 0
    mov  dword [rel img_jpg_restart_next], 0
    mov  ecx, [rel img_jpg_restart_interval]
    test ecx, ecx
    jz   .ok
    xor  edx, edx
    div  ecx
    mov  [rel img_jpg_restart_count], eax
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

img_jpeg_progressive_complete:
    xor  ecx, ecx
    lea  rdi, [rel img_jpg_progress_bits]
.comp:
    cmp  ecx, [rel img_jpg_ncomp]
    jae  .ok
    mov  eax, ecx
    shl  eax, 6
    cmp  byte [rdi + rax], 255          ; every component requires initial DC
    je   .bad
    inc  ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .comp
.ok:
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; EDI=component,ESI=physical blockx,EDX=blocky -> private zigzag coefficient ptr.
; Every caller traverses the SOF-derived padded/actual scan dimensions.
img_jpeg_frame_block:
    mov  eax, edx
    lea  r8, [rel img_jpg_padded_cols]
    imul eax, [r8 + rdi * 4]
    add  eax, esi
    shl  rax, 8
    lea  r8, [rel img_jpg_comp_offset]
    add  rax, [r8 + rdi * 8]
    add  rax, [rel img_jpg_frame]
    ret

; EDI=component,ESI=MCUx,EDX=MCUy,ECX=block ordinal in component MCU.
img_jpeg_frame_mcu_block:
    mov  r9d, edx
    mov  r10d, esi
    lea  r8, [rel img_jpg_comp_h]
    movzx r11d, byte [r8 + rdi]
    mov  eax, ecx
    xor  edx, edx
    div  r11d
    imul r10d, r11d
    add  r10d, edx
    lea  r8, [rel img_jpg_comp_v]
    movzx edx, byte [r8 + rdi]
    imul edx, r9d
    add  edx, eax
    mov  esi, r10d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  img_jpeg_frame_block

; Decode one scan immediately when the private parser reaches its terminal marker.
; Probe performs identical header/marker validation without decoding or allocating.
img_jpeg_progressive_scan:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  rdi, [rel img_jpg_scan_ptr]
    mov  rsi, [rel img_jpg_scan_end]
    sub  rsi, rdi
    call img_jpeg_bs_init
    mov  dword [rel img_jpg_dc_pred], 0
    mov  dword [rel img_jpg_dc_pred + 4], 0
    mov  dword [rel img_jpg_dc_pred + 8], 0
    mov  dword [rel img_jpg_dc_pred + 12], 0
    mov  dword [rel img_jpg_eobrun], 0
    mov  dword [rel img_jpg_restart_next], 0
    mov  eax, [rel img_jpg_restart_interval]
    mov  [rel img_jpg_restart_left], eax
    xor  ebp, ebp
.row:
    cmp  ebp, [rel img_jpg_scan_rows]
    jae  .finish
    xor  r15d, r15d
.col:
    cmp  r15d, [rel img_jpg_scan_cols]
    jae  .next_row
    cmp  dword [rel img_jpg_restart_interval], 0
    je   .mcu
    cmp  dword [rel img_jpg_restart_left], 0
    jne  .mcu
    cmp  dword [rel img_jpg_eobrun], 0
    jne  .bad                         ; EOB run cannot cross restart boundary
    call img_jpeg_restart
    test eax, eax
    jnz  .bad
    mov  dword [rel img_jpg_eobrun], 0
.mcu:
    xor  r14d, r14d
.comp:
    cmp  r14d, [rel img_jpg_scan_ncomp]
    jae  .advance
    lea  rdi, [rel img_jpg_scan_components]
    movzx r12d, byte [rdi + r14]
    mov  ebx, 1
    cmp  dword [rel img_jpg_scan_ncomp], 1
    je   .blocks
    lea  rdi, [rel img_jpg_comp_h]
    movzx ebx, byte [rdi + r12]
    lea  rdi, [rel img_jpg_comp_v]
    movzx eax, byte [rdi + r12]
    imul ebx, eax
.blocks:
    xor  r13d, r13d
.block:
    cmp  r13d, ebx
    jae  .next_comp
    mov  edi, r12d
    mov  esi, r15d
    mov  edx, ebp
    cmp  dword [rel img_jpg_scan_ncomp], 1
    je   .single
    mov  ecx, r13d
    call img_jpeg_frame_mcu_block
    jmp  .decode
.single:
    call img_jpeg_frame_block
.decode:
    mov  rdi, rax
    mov  esi, r12d
    cmp  byte [rel img_jpg_sequential], 1
    jne  .progressive_block
    call img_jpeg_sequential_block
    jmp  .block_status
.progressive_block:
    call img_jpeg_progressive_block
.block_status:
    test eax, eax
    jnz  .bad
    inc  r13d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .block
.next_comp:
    inc  r14d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .comp
.advance:
    cmp  dword [rel img_jpg_restart_interval], 0
    je   .next_col
    dec  dword [rel img_jpg_restart_left]
.next_col:
    inc  r15d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .col
.next_row:
    inc  ebp
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .row
.finish:
    cmp  dword [rel img_jpg_eobrun], 0
    jne  .bad                         ; no run may extend beyond final MCU
    mov  rax, [rel img_jpg_bs_ptr]
    cmp  rax, [rel img_jpg_bs_end]
    jne  .bad
    mov  ecx, [rel img_jpg_bs_n]
    mov  eax, 1
    shl  eax, cl
    dec  eax
    mov  edx, [rel img_jpg_bs_buf]
    and  edx, eax
    cmp  edx, eax
    jne  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; RDI=owned zeroed zigzag block,ESI=component. Sequential Huffman8 DC+AC.
; Per-component quantization was pinned by this scan header before entropy.
img_jpeg_sequential_block:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13d, esi
    lea  rdi, [rel img_jpg_comp_dc]
    movzx edi, byte [rdi + r13]
    call img_jpeg_huff
    jc   .bad
    cmp  eax, 11
    ja   .bad
    mov  edi, eax
    call img_jpeg_receive
    jc   .bad
    lea  rdi, [rel img_jpg_dc_pred]
    add  eax, [rdi + r13 * 4]
    jo   .bad
    cmp  eax, -1024
    jl   .bad
    cmp  eax, 1023
    jg   .bad
    mov  [rdi + r13 * 4], eax
    mov  [r12], eax
    mov  r14d, 1
.ac:
    cmp  r14d, 64
    jae  .ok
    lea  rdi, [rel img_jpg_comp_ac]
    movzx edi, byte [rdi + r13]
    add  edi, 2
    call img_jpeg_huff
    jc   .bad
    test eax, eax
    jz   .ok
    cmp  eax, 0xF0
    je   .zrl
    mov  ebx, eax
    shr  ebx, 4
    add  r14d, ebx
    cmp  r14d, 64
    jae  .bad
    and  eax, 15
    test eax, eax
    jz   .bad
    cmp  eax, 10
    ja   .bad
    mov  edi, eax
    call img_jpeg_receive
    jc   .bad
    mov  [r12 + r14 * 4], eax
    inc  r14d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .ac
.zrl:
    add  r14d, 16
    cmp  r14d, 64
    ja   .bad
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .ac
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=private zigzag block,ESI=component. Four progressive Huffman scan modes.
img_jpeg_progressive_block:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13d, esi
    mov  ecx, [rel img_jpg_al]
    mov  ebp, 1
    shl  ebp, cl
    cmp  dword [rel img_jpg_ss], 0
    jne  .ac
    cmp  dword [rel img_jpg_ah], 0
    jne  .dc_refine
    lea  rdi, [rel img_jpg_comp_dc]
    movzx edi, byte [rdi + r13]
    call img_jpeg_huff
    jc   .bad
    cmp  eax, 11
    ja   .bad
    mov  edi, eax
    call img_jpeg_receive
    jc   .bad
    lea  rdi, [rel img_jpg_dc_pred]
    add  eax, [rdi + r13 * 4]
    jo   .bad
    mov  [rdi + r13 * 4], eax
    movsxd rax, eax
    mov  ecx, [rel img_jpg_al]
    shl  rax, cl
    cmp  rax, -1024
    jl   .bad
    cmp  rax, 1023
    jg   .bad
    mov  [r12], eax
    jmp  .ok
.dc_refine:
    call img_jpeg_bit
    jc   .bad
    test eax, eax
    jz   .ok
    or   [r12], ebp                   ; next bit of two's-complement DC, also negative
    cmp  dword [r12], -1024
    jl   .bad
    cmp  dword [r12], 1023
    jg   .bad
    jmp  .ok
.ac:
    mov  r14d, [rel img_jpg_ss]
    cmp  dword [rel img_jpg_ah], 0
    jne  .ac_refine
    cmp  dword [rel img_jpg_eobrun], 0
    jne  .eob_done
.ac_initial:
    cmp  r14d, [rel img_jpg_se]
    ja   .ok
    call .ac_symbol
    jc   .bad
    mov  ebx, eax
    shr  ebx, 4
    and  eax, 15
    test eax, eax
    jz   .initial_zero
    cmp  eax, 10
    ja   .bad
    add  r14d, ebx
    cmp  r14d, [rel img_jpg_se]
    ja   .bad
    mov  edi, eax
    call img_jpeg_receive
    jc   .bad
    movsxd rax, eax
    mov  ecx, [rel img_jpg_al]
    shl  rax, cl
    cmp  rax, -1023
    jl   .bad
    cmp  rax, 1023
    jg   .bad
    mov  [r12 + r14 * 4], eax
    inc  r14d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .ac_initial
.initial_zero:
    cmp  ebx, 15
    jne  .initial_eob
    add  r14d, 16
    mov  eax, [rel img_jpg_se]
    inc  eax
    cmp  r14d, eax
    ja   .bad
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .ac_initial
.initial_eob:
    call .read_eob
    jc   .bad
.eob_done:
    dec  dword [rel img_jpg_eobrun]
    jmp  .ok
.ac_refine:
    cmp  dword [rel img_jpg_eobrun], 0
    jne  .eob_refine
.refine_symbol:
    cmp  r14d, [rel img_jpg_se]
    ja   .ok
    call .ac_symbol
    jc   .bad
    mov  ebx, eax
    shr  ebx, 4
    and  eax, 15
    xor  r15d, r15d                    ; new signed coefficient, zero for ZRL
    test eax, eax
    jz   .refine_zero
    cmp  eax, 1
    jne  .bad
    call img_jpeg_bit
    jc   .bad
    mov  r15d, ebp
    test eax, eax
    jnz  .walk
    neg  r15d
    jmp  .walk
.refine_zero:
    cmp  ebx, 15
    je   .walk
    call .read_eob
    jc   .bad
    jmp  .eob_refine
.walk:
    cmp  r14d, [rel img_jpg_se]
    ja   .bad
    cmp  dword [r12 + r14 * 4], 0
    je   .zero_coefficient
    lea  rdi, [r12 + r14 * 4]
    mov  esi, ebp
    call img_jpeg_progressive_correct
    test eax, eax
    jnz  .bad
    jmp  .walk_next
.zero_coefficient:
    dec  ebx
    js   .target
.walk_next:
    inc  r14d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .walk
.target:
    test r15d, r15d
    jz   .target_next
    cmp  r15d, -1023
    jl   .bad
    cmp  r15d, 1023
    jg   .bad
    mov  [r12 + r14 * 4], r15d
.target_next:
    inc  r14d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .refine_symbol
.eob_refine:
    cmp  r14d, [rel img_jpg_se]
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    ja   .eob_done
    cmp  dword [r12 + r14 * 4], 0
    je   .eob_next
    lea  rdi, [r12 + r14 * 4]
    mov  esi, ebp
    call img_jpeg_progressive_correct
    test eax, eax
    jnz  .bad
.eob_next:
    inc  r14d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .eob_refine
.ac_symbol:
    lea  rdi, [rel img_jpg_comp_ac]
    movzx edi, byte [rdi + r13]
    add  edi, 2
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  img_jpeg_huff
.read_eob:
    mov  edi, ebx
    call img_jpeg_bits
    jc   .eob_bad
    mov  ecx, ebx
    mov  edx, 1
    shl  edx, cl
    add  eax, edx
    mov  [rel img_jpg_eobrun], eax
    clc
    ret
.eob_bad:
    stc
    ret
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; RDI=nonzero coefficient address,ESI=1<<Al. One sign/magnitude correction bit.
img_jpeg_progressive_correct:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12d, esi
    call img_jpeg_bit
    jc   .bad
    test eax, eax
    jz   .ok
    mov  eax, [rbx]
    test eax, r12d
    jnz  .ok
    test eax, eax
    js   .negative
    add  eax, r12d
    cmp  eax, 1023
    jg   .bad
    jmp  .store
.negative:
    sub  eax, r12d
    cmp  eax, -1023
    jl   .bad
.store:
    mov  [rbx], eax
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

; Reuse the exact baseline IDCT, component sampler and RGBA writer after all
; scans/EOI validate. Padded edge blocks are allocated but never sampled outside.
img_jpeg_progressive_render:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    cmp  qword [rel img_jpg_frame], 0
    je   .bad
    xor  ebp, ebp
.row:
    cmp  ebp, [rel img_jpg_mcu_rows]
    jae  .ok
    xor  r15d, r15d
.col:
    cmp  r15d, [rel img_jpg_mcu_cols]
    jae  .next_row
    xor  ebx, ebx                     ; sample block offset
    xor  r12d, r12d
.comp:
    cmp  r12d, [rel img_jpg_ncomp]
    jae  .write
    xor  r13d, r13d
.block:
    lea  rdi, [rel img_jpg_comp_h]
    movzx eax, byte [rdi + r12]
    lea  rdi, [rel img_jpg_comp_v]
    movzx edx, byte [rdi + r12]
    imul eax, edx
    cmp  r13d, eax
    jae  .next_comp
    mov  edi, r12d
    mov  esi, r15d
    mov  edx, ebp
    mov  ecx, r13d
    call img_jpeg_frame_mcu_block
    mov  r14, rax
    xor  ecx, ecx
.dequant:
    mov  eax, r12d
    shl  eax, 6
    add  eax, ecx
    lea  rdi, [rel img_jpg_component_quant]
    movzx edx, byte [rdi + rax]
    mov  eax, [r14 + rcx * 4]
    imul eax, edx
    lea  rdi, [rel img_jpg_zigzag]
    movzx edx, byte [rdi + rcx]
    lea  rdi, [rel img_jpg_coeff]
    mov  [rdi + rdx * 4], eax
    inc  ecx
    cmp  ecx, 64
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .dequant
    lea  rdi, [rel img_jpg_coeff]
    lea  rsi, [rel img_jpg_samples]
    mov  eax, ebx
    shl  eax, 6
    add  rsi, rax
    call img_jpeg_idct
    inc  ebx
    inc  r13d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .block
.next_comp:
    inc  r12d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .comp
.write:
    mov  edi, r15d
    mov  esi, ebp
    call img_jpeg_write_mcu
    inc  r15d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .col
.next_row:
    inc  ebp
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .row
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_gui_img_img_jpeg_0 0
img_jpg_zigzag:
    db 0,1,8,16,9,2,3,10,17,24,32,25,18,11,4,5
    db 12,19,26,33,40,48,41,34,27,20,13,6,7,14,21,28
    db 35,42,49,56,57,50,43,36,29,22,15,23,30,37,44,51
    db 58,59,52,45,38,31,39,46,53,60,61,54,47,55,62,63

; A[x,u] = C(u)*cos((2x+1)u*pi/16), scaled by 4096.
img_jpg_idct_matrix:
    dw 2896,4017,3784,3406,2896,2276,1567,799
    dw 2896,3406,1567,-799,-2896,-4017,-3784,-2276
    dw 2896,2276,-1567,-4017,-2896,799,3784,3406
    dw 2896,799,-3784,-2276,2896,3406,-1567,-4017
    dw 2896,-799,-3784,2276,2896,-3406,-1567,4017
    dw 2896,-2276,-1567,4017,-2896,-799,3784,-3406
    dw 2896,-3406,1567,799,-2896,4017,-3784,2276
    dw 2896,-4017,3784,-3406,2896,-2276,1567,-799

align 8
; img_jpg_state_begin..img_jpg_state_end moved to WDATA_gui_img_img_jpeg_0_bss1 (zero-fill tail)
%endmacro
WDATA_DEFER WDATA_gui_img_img_jpeg_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_gui_img_img_jpeg_0_bss1 0
alignb 8
img_jpg_state_begin:
img_jpg_width:       resd 1
img_jpg_height:      resd 1
img_jpg_ncomp:       resd 1
img_jpg_orientation: resb 1
img_jpg_exif_seen: resb 1
img_jpg_asymmetric: resb 1
img_jpg_adobe_seen: resb 1
img_jpg_adobe_transform: resb 1
img_jpg_color_bad: resb 1
img_jpg_jfif_seen: resb 1
img_jpg_adobe_attempt: resb 1
img_jpg_rgb: resb 1
img_jpg_sof_seen:    resb 1
img_jpg_restart_seen: resb 1
img_jpg_max_h:       resb 1
img_jpg_max_v:       resb 1
img_jpg_comp_id:     resb 4
img_jpg_comp_h:      resb 4
img_jpg_comp_v:      resb 4
img_jpg_comp_qt:     resb 4
img_jpg_comp_dc:     resb 4
img_jpg_comp_ac:     resb 4
alignb 8
img_jpg_scan_ptr:    resq 1
img_jpg_scan_end:    resq 1
img_jpg_file_end:    resq 1
img_jpg_qpresent:    resb 4
img_jpg_hpresent:    resb JPG_HT_COUNT
img_jpg_qtables:     resb (4 * 64)
img_jpg_hcounts:     resb (JPG_HT_COUNT * 16)
img_jpg_hsymbols:    resb (JPG_HT_COUNT * 256)

alignb 8
img_jpg_bs_ptr:      resq 1
img_jpg_bs_end:      resq 1
img_jpg_bs_buf:      resd 1
img_jpg_bs_n:        resd 1
img_jpg_restart_interval: resd 1
img_jpg_restart_count: resd 1
img_jpg_restart_next: resd 1
img_jpg_restart_left: resd 1
img_jpg_dc_pred:     resd 4
img_jpg_out:         resq 1
img_jpg_mcu_w:       resd 1
img_jpg_mcu_h:       resd 1
img_jpg_mcu_cols:    resd 1
img_jpg_mcu_rows:    resd 1
img_jpg_coeff:       resd 64
img_jpg_samples:     resb (10 * 64)
; All buffered pointers/workspaces live inside ordinary codec retirement.
img_jpg_progressive: resb 1
img_jpg_buffered: resb 1
img_jpg_sequential: resb 1
img_jpg_extended: resb 1
alignb 4
img_jpg_sequential_mask: resd 1
img_jpg_quant_locked: resb 4
img_jpg_scan_components: resb 4
img_jpg_progress_bits: resb (4 * 64)
img_jpg_component_quant: resb (4 * 64)
alignb 8
img_jpg_frame: resq 1
img_jpg_frame_capacity: resq 1
img_jpg_frame_bytes: resq 1
img_jpg_comp_offset: resq 4
img_jpg_padded_cols: resd 4
img_jpg_block_cols: resd 4
img_jpg_block_rows: resd 4
img_jpg_scan_ncomp: resd 1
img_jpg_ss: resd 1
img_jpg_se: resd 1
img_jpg_ah: resd 1
img_jpg_al: resd 1
img_jpg_scan_cols: resd 1
img_jpg_scan_rows: resd 1
img_jpg_eobrun: resd 1
img_jpg_state_end:
%endmacro
WDATA_BSS_DEFER WDATA_gui_img_img_jpeg_0_bss1
