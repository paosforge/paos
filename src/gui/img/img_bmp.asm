;; MODULE gui/img/img_bmp
;; LAYER 6
;; EXPORTS img_bmp_probe, img_bmp_decode
;; IMPORTS core/heap, core/lib/sha256, gui/img/img_png, gui/img/img_jpeg
;; CAPS
;; OWNER saga:gui_image_pipeline

%include "gui/img/img_cold_hooks.inc"

; Pure bounded BMP parser/decoder. Existing 24/32 BI_RGB plus a finite subset:
; 40-byte DIB: 1/2/4/8 BI_RGB indexed (2bpp Windows CE), 16 BI_RGB default RGB555,
; 16 BI_BITFIELDS RGB555/RGB565,
; 32 BI_BITFIELDS RGB888 (unused high byte is opaque, not alpha).
; Also exactly 108-byte V4 or 124-byte V5 BI_BITFIELDS with the same masks,
; zero/canonical32 alpha, sRGB and zero endpoints/gamma. V5 permits rendering intent 1/2/4/8 and
; zero profile data/size/reserved. No other extended bitfield/indexed
; DIBs, custom color management or arbitrary masks. Exactly 108-byte V4 or
; 124-byte V5 BI_RGB indexed 1/4/8 accepts zero masks and the same opaque
; sRGB metadata (including the V5 intent/profile restrictions above).
; Exact V4/V5 BI_RGB16 also uses that zero-mask opaque metadata and default
; RGB555 decoding; bit 15 is ignored. No other RGB16 DIBs are admitted.
; BI_RLE8/4 are exact40/52/56/108/124-byte8/4bpp bottom-up: bounded encoded/absolute
; runs. V2/V3 require zero inline masks; V4/V5 also require sRGB/no-profile metadata.
; New extended
; RLE decode uses one owned allocation for RGBA and a SHA-bound private source,
; capped at32MiB; palette/stream reads never return to the caller after copying.
; Both permit forward right/up delta, short/empty EOL and early
; exact EOB; unwritten pixels use opaque palette0 (local deterministic policy).
; RLE4 retains run-local high/low nibble parity. Both Windows and OS2 pad each
; literal run to an even byte length, independent of the pixel-array offset.
; Exact12-byte BITMAPCOREHEADER1/4/8/24 is opaque bottom-up with DWORD stride;
; unsigned16 dimensions, planes1, complete26-byte header. Indexed CORE requires
; the full2^bpp BGR triple table. No other CORE formats are supported.
; Exact52-byte V2 BI_BITFIELDS admits only canonical16/32 RGB masks; no alpha
; or color metadata. New V2 decode requalifies and binds its selected span.
; Exact56/108/124 BI_BITFIELDS32 also admits canonicalRGB888 + ff000000 alpha,
; copied verbatim to straight RGBA8888. Zero alpha mask remains opaque255.
; V4/V5 retain all sRGB/zero color data and intent/profile restrictions.
; Exact56-byte V3 BI_RGB16 is default555 only when all four inline masks are0.
; Exact52-byte V2 BI_RGB16 reuses default555 with three zero inline masks.
; Exact52-byte V2 BI_RGB24/32 also requires three zero inline RGB masks;
; retained raw conversion gives24 opaque alpha and32 verbatim byte alpha.
; Exact52/56-byte BI_RGB indexed1/4/8 uses RGBQUADs after the actual DIB,
; zero RGB masks (and zero V3 alpha), opaque palette colors, either row order.
; Historical BI_RGB24/32 dispatch remains independent of this finite subset.
; RCQ-34 general masks: 16/32 BI_BITFIELDS (40 external, 52/56 inline, 108/124
; internal) admit ANY red/green/blue masks that are nonzero, contiguous, inside
; the depth and pairwise disjoint, plus an optional alpha mask of the same kind
; (56/108/124 only; zero = opaque255). The canonical 555/565/888 masks above are
; members of this set and decode byte-identically. BI_ALPHABITFIELDS (6) is the
; 40-byte DIB with four external masks (R G B A at 54..70), 16/32 bpp only.
; Each channel is (pixel & mask) >> shift scaled as v*255/max (floor), the rule
; the canonical 5/6-bit channels always used; a full 8-bit channel is verbatim.
; Decode reads each mask once into a private table, validated again before
; allocation, so pixels never depend on a later read of the source masks.
; Exact40/52/56/108/124-byte BI_JPEG/BI_PNG: planes1/bpp0, positive bounded dimensions,
; no palette, reserved0, exact file/encoded extents. Native codec subsets only.
; Legacy52/56 compatibility uses zero inline RGB masks (and V3 alpha).
; V4/V5 require zero masks, sRGB and zero endpoints/gamma; V5 also requires
; rendering intent1/2/4/8 and zero profile data/size/reserved. Offset follows actual DIB.
; An owned SHA-bound snapshot isolates decode from changed caller bytes.
; OS/2 BITMAPINFOHEADER2 full64 or unambiguous complete-field short lengths
; 16/20/24/28/32/36/42/44/46/48/60: indexed1/4/8 and RGB24 uncompressed,
; or RLE4/8, Huffman1D and BCA_RLE24 (4, never Windows JPEG). Compressed
; short headers require present compression and cbImage (cbFix >=24).
; Omitted palette counts default to the full depth table at actual cbFix.
; Unsigned positive dimensions,
; BA arrays return first member after bounded complete-chain validation;
; every member must be a supported BM.
; bottom-up, RGB2 palettes, DWORD raw stride, exact file/pixel spans <=32MiB.
; RGB24 optional device RGB2 tables use present used/important counts and actual
; cbFix; they never index/recolor pixels. The table span is checked in 64 bits.
; RLE4/8 share the Windows bounded cursor/index grammar and opaque palette0
; sparse policy. OS2 uses literal-length word padding (zero), independent of
; the file offset, and permits finite zero deltas. Windows policy is retained.
; RLE24 literal counts are BYTES divisible by3, with zero pad for odd counts;
; encoded counts are pixels. Shared validation/write grammar supports EOL/EOB
; and unsigned right/up delta; sparse pixels are opaque black. A bounded stream
; permits zero delta. SHA before/after allocation binds all source bytes.
; Compatibility: BMP Suite2.8 counts literal pixels instead. Full IBM grammar
; is tried first, then full pixel-count grammar only if IBM validation refuses.
; The chosen mode is pinned across allocation; no mixed grammar within a stream.
; OS2 codec3/1bpp uses bounded MSB-first T.4 Huffman1D with initial/row EOL,
; term/makeup runs and six-EOL RTC, RGB2 colors and bottom-up rows.
; Outside this decoder (refused): BI_CMYK* (11-13),
; OS2 RGB24 advisory palettes,
; short indexed compressed profiles,
; 2bpp outside 40-byte BI_RGB, 64bpp, 24-bpp bitfields, Windows RLE on other-size or top-down DIBs,
; V4/V5 colour spaces other than sRGB or
; with endpoints/gamma/profiles, nonzero masks in52/56 indexed DIBs.
; Single-size IC/PT/CI/CP use the independent bounded OS2 mask/pair grammar
; in img_bmp_icon.inc. CORE/full64 raw profiles only; screen inversion refuses.
; The shared ABI is declared by img_core.asm:
; probe -> EAX status, EBX format, ECX width, EDX height, R8D source bpp.
; decode -> EAX status, RBX output, ECX width, EDX height, R8D format.

img_bmp_probe:
    IMG_COLD_PUBLIC_GUARD
    cld
    xor  ebx, ebx
    xor  ecx, ecx
    xor  edx, edx
    xor  r8d, r8d
    mov  rax, rdi
    add  rax, rsi
    jc   .bounds                     ; every caller source span before any field read
    cmp  rsi, 26
    jb   .truncated
    mov  rax, rdi
    add  rax, 26
    jc   .bounds                     ; fixed header pointer before any field read
    cmp  word [rdi], 'BA'
    je   img_bmp_array_probe
    cmp  word [rdi], 'IC'
    je   img_bmp_icon_probe
    cmp  word [rdi], 'PT'
    je   img_bmp_icon_probe
    cmp  word [rdi], 'CI'
    je   img_bmp_icon_probe
    cmp  word [rdi], 'CP'
    je   img_bmp_icon_probe
    cmp  word [rdi], 'BM'
    jne  .bad_magic
    mov  eax, [rdi + 14]
    cmp  eax, 12
    je   .core24
    call img_bmp_os2_header
    jnc  .os2                       ; qualify declared short header before any optional field
    ; Preserve historical Windows RGB24/32 fallback for other DIB lengths.
    ; Such inputs receive no OS2 semantics; indexed/masked/codecs retain exact
    ; Windows namespaces. cbFix alone cannot distinguish legacy raw headers.
    cmp  rsi, 54
    jb   .truncated
    cmp  eax, 40
    jb   .unsupported
    add  rax, 14                         ; complete DIB header before pixels
    jc   .bounds
    cmp  rax, rsi
    ja   .truncated
    mov  r11, rax
    cmp  dword [rdi + 14], 52
    je   .inline_pointer
    cmp  dword [rdi + 14], 56
    je   .v3_pointer
    cmp  dword [rdi + 14], 108
    je   .extended_pointer
    cmp  dword [rdi + 14], 124
    jne  .header_ready
.extended_pointer:
    mov  r9, rdi
    add  r9, r11
    jc   .bounds                     ; full extended header before codec/masks
    cmp  dword [rdi + 30], 3
    jne  .header_ready
    cmp  word [rdi + 28], 32
    jne  .header_ready
    jmp  .inline_pointer             ; entire alpha-family caller pointer span
.v3_pointer:
    mov  r9, rdi
    add  r9, r11
    jc   .bounds                     ; full70-byte pointer before V3 codec read
    cmp  dword [rdi + 30], 3
    je   .inline_pointer
    cmp  dword [rdi + 30], 0
    jne  .header_ready
    cmp  word [rdi + 28], 8
    jbe  .inline_pointer             ; indexed V3 also proves full caller pointer
    cmp  word [rdi + 28], 16
    jne  .header_ready               ; preserve historical RGB24/32
.inline_pointer:
    mov  r9, rdi
    add  r9, r11
    jc   .bounds                     ; full V2 header pointer before fields/masks
    mov  r9, rdi
    add  r9, rsi
    jc   .bounds                     ; V2 entire caller source pointer span
    cmp  dword [rdi + 14], 52
    jne  .header_ready               ; selected V3 inline entrance above
    cmp  dword [rdi + 30], 4
    je   .header_ready               ; exact native embedded profile checked below
    cmp  dword [rdi + 30], 5
    je   .header_ready
    cmp  dword [rdi + 30], 3
    je   .header_ready
    cmp  dword [rdi + 30], 1
    je   .header_ready               ; RLE8 depth/masks qualified below
    cmp  dword [rdi + 30], 2
    je   .header_ready               ; RLE4 depth/masks qualified below
    cmp  dword [rdi + 30], 0
    jne  .unsupported                ; V2 RGB, bitfields or qualified RLE only
    cmp  word [rdi + 28], 1
    je   .header_ready
    cmp  word [rdi + 28], 4
    je   .header_ready
    cmp  word [rdi + 28], 8
    je   .header_ready
    cmp  word [rdi + 28], 16
    je   .header_ready
    cmp  word [rdi + 28], 24
    je   .header_ready
    cmp  word [rdi + 28], 32
    jne  .unsupported                ; unsupported BI_RGB depth
.header_ready:
    cmp  dword [rdi + 30], 4
    je   .embedded
    cmp  dword [rdi + 30], 5
    je   .embedded
    cmp  word [rdi + 26], 1
    jne  .unsupported
    movzx r8d, word [rdi + 28]
    cmp  dword [rdi + 30], 2          ; finite BI_RLE4 entrance
    je   .rle4_format
    cmp  dword [rdi + 30], 1          ; finite BI_RLE8 entrance
    jne  .uncompressed_format
    cmp  r8d, 8
    jne  .unsupported
    jmp  .rle_format
.rle4_format:
    cmp  r8d, 4
    jne  .unsupported
.rle_format:
    cmp  dword [rdi + 22], 0
    jle  .unsupported                 ; RLE cannot be top-down
    cmp  dword [rdi + 14], 40
    je   .palette
    cmp  dword [rdi + 14], 52
    je   .rle_inline
    cmp  dword [rdi + 14], 56
    je   .rle_inline
    cmp  dword [rdi + 14], 108
    je   .rle_extended
    cmp  dword [rdi + 14], 124
    jne  .unsupported
.rle_extended:
    cmp  rsi, BMP_EMBED_MAX
    ja   .bounds
    jmp  .indexed_masks              ; actual R11 DIB extent; shared zero-mask metadata
.rle_inline:
    cmp  rsi, BMP_EMBED_MAX
    ja   .bounds
    mov  r9, rdi
    add  r9, rsi
    jc   .bounds                     ; full source span before private snapshot hashing
    jmp  .indexed_inline_masks       ; retain actual52/56 palette start; zero masks
.uncompressed_format:
    cmp  dword [rdi + 30], 3          ; BI_BITFIELDS, external or qualified V4/V5 masks
    je   .bitfields
    cmp  dword [rdi + 30], 6          ; BI_ALPHABITFIELDS: 40-byte DIB, four external masks
    je   .alpha_bitfields
    cmp  dword [rdi + 30], 0
    jne  .unsupported
    cmp  r8d, 24
    je   .rgb_truecolor
    cmp  r8d, 32
    je   .rgb_truecolor
    cmp  r8d, 16
    jne  .indexed_depth
    cmp  dword [rdi + 14], 40
    je   .format_ok                   ; implicit 5:5:5, no external masks
    cmp  dword [rdi + 14], 52
    je   .rgb16_v2_masks
    cmp  dword [rdi + 14], 56
    je   .rgb16_v3_masks
    cmp  dword [rdi + 14], 108
    je   .rgb16_extended
    cmp  dword [rdi + 14], 124
    jne  .unsupported
    jmp  .rgb16_extended
.rgb_truecolor:
    cmp  dword [rdi + 14], 52
    je   .rgb16_v2_masks             ; same three zero masks, no V2 alpha field
    jmp  .format_ok                   ; historical other-header RGB24/32 path
.rgb16_v2_masks:
    cmp  qword [rdi + 54], 0          ; RGB16 V2 red/green must be zero
    jne  .unsupported
    cmp  dword [rdi + 62], 0          ; RGB16 V2 blue must be zero, no alpha field
    jne  .unsupported
    jmp  .format_ok                   ; retained opaque default555 decoder
.rgb16_v3_masks:
    cmp  qword [rdi + 54], 0          ; RGB16 V3 red/green must be zero
    jne  .unsupported
    cmp  qword [rdi + 62], 0          ; RGB16 V3 blue/alpha must be zero
    jne  .unsupported
    jmp  .format_ok                   ; existing opaque default555 decoder
.rgb16_extended:
    ; Complete header already proved. Bound pixels before reading extended
    ; masks/color metadata, including for V4; retain the full R11 extent.
    mov  r9d, [rdi + 10]
    cmp  r9, r11
    jb   .truncated
    cmp  r9, rsi
    ja   .truncated
    jmp  .indexed_masks              ; same zero masks and opaque sRGB subset
.indexed_depth:
    cmp  r8d, 2
    jne  .standard_indexed_depth
    cmp  dword [rdi + 14], 40
    jne  .unsupported                ; CE BI_RGB2 is the 40-byte DIB only
    jmp  .palette                    ; four MSB-first indexes per byte, RGBQUADs
.standard_indexed_depth:
    cmp  r8d, 1
    je   .indexed_header
    cmp  r8d, 4
    je   .indexed_header
    cmp  r8d, 8
    jne  .unsupported
.indexed_header:
    cmp  dword [rdi + 14], 40
    je   .palette
    cmp  dword [rdi + 14], 52
    je   .indexed_inline_masks
    cmp  dword [rdi + 14], 56
    je   .indexed_inline_masks
    cmp  dword [rdi + 14], 108
    je   .indexed_masks
    cmp  dword [rdi + 14], 124
    jne  .unsupported
    jmp  .indexed_masks              ; retain V5 color/profile validation
.indexed_inline_masks:
    cmp  qword [rdi + 54], 0          ; complete52/56 header proved before masks
    jne  .unsupported
    cmp  dword [rdi + 62], 0
    jne  .unsupported
    cmp  dword [rdi + 14], 52
    je   .palette                    ; V2 has no alpha field at offset66
    cmp  dword [rdi + 66], 0          ; V3 indexed has no alpha semantics
    jne  .unsupported
    jmp  .palette                    ; R11 retains actual DIB/palette start
.indexed_masks:
    cmp  qword [rdi + 54], 0          ; V4/V5 indexed red + green masks must be zero
    jne  .unsupported
    cmp  dword [rdi + 62], 0          ; blue; alpha checked by shared V4 metadata
    jne  .unsupported
    cmp  dword [rdi + 14], 124
    je   .v5_metadata
    jmp  .v4_color
.palette:
    mov  ecx, r8d
    mov  eax, 1
    shl  eax, cl                      ; maximum colors = 2^bpp
    mov  r9d, [rdi + 46]             ; biClrUsed, zero means the full table
    test r9d, r9d
    jnz  .palette_count
    mov  r9d, eax
.palette_count:
    cmp  r9d, eax
    ja   .corrupt
    lea  r11, [r11 + r9 * 4]         ; all RGBQUADs must precede pixels
    jmp  .format_ok
.alpha_bitfields:
    cmp  dword [rdi + 14], 40
    jne  .unsupported
    jmp  .bitfield_depth
.bitfields:
    cmp  dword [rdi + 14], 40
    je   .bitfield_depth
    cmp  dword [rdi + 14], 52
    je   .bitfield_depth             ; V2 inline masks end at66; no V4 metadata
    cmp  dword [rdi + 14], 56
    jne  .extended_bitfields
    call img_bmp_alpha_mask          ; bounded zero/canonical32 inline alpha
    test eax, eax
    jnz  .unsupported
    jmp  .bitfield_depth             ; no V4 color fields on70-byte header
.extended_bitfields:
    cmp  dword [rdi + 14], 108
    je   .v4_color
    cmp  dword [rdi + 14], 124
    jne  .unsupported
.v5_metadata:
    ; Complete 138-byte file+DIB extent proved above. Prove the V5 pixel
    ; offset before reading its metadata; R11 remains the full header extent.
    mov  r9d, [rdi + 10]
    cmp  r9, r11
    jb   .truncated
    cmp  r9, rsi
    ja   .truncated
    mov  eax, [rdi + 122]
    call img_bmp_v5_intent           ; one documented enum, not a bitmask
    jne  .unsupported
    cmp  qword [rdi + 126], 0         ; bV5ProfileData + bV5ProfileSize
    jne  .unsupported
    cmp  dword [rdi + 134], 0         ; bV5Reserved
    jne  .unsupported
.v4_color:
    ; The complete 122/138-byte file+DIB extent was proved above, including the
    ; internal masks, color-space and all endpoint/gamma bytes read here.
    call img_bmp_alpha_mask          ; shared V4/V5 zero/canonical32 alpha
    test eax, eax
    jnz  .unsupported
    cmp  dword [rdi + 70], 0x73524742 ; LCS_sRGB
    jne  .unsupported
    lea  r9, [rdi + 74]
    mov  ecx, 6                      ; 36 endpoint + 12 gamma bytes
.v4_zero:
    cmp  qword [r9], 0
    jne  .unsupported
    add  r9, 8
    dec  ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jnz  .v4_zero
    cmp  dword [rdi + 30], 3
    je   .bitfield_depth             ; retain R11 = 122/138, masks are internal
    cmp  r8d, 16
    je   .format_ok                  ; default555 has no palette
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .palette                    ; exact V4/V5 BI_RGB/RLE indexed entrance
.bitfield_depth:
    cmp  r8d, 16
    je   .masks_present
    cmp  r8d, 32
    jne  .unsupported
.masks_present:
    cmp  dword [rdi + 14], 40
    jne  .masks_ready                 ; complete internal V4/V5 masks already proved
    mov  r11d, 66                     ; three external RGB masks
    cmp  dword [rdi + 30], 6
    jne  .external_masks
    mov  r11d, 70                     ; BI_ALPHABITFIELDS adds the external alpha mask
.external_masks:
    cmp  rsi, r11
    jb   .truncated                   ; never read a partial external mask
.masks_ready:
    xor  r9d, r9d                     ; validate only; R9 is reset below
    push rcx
    xor  ecx, ecx
    cmp  dword [rdi + 30], 6
    je   .probe_alpha
    cmp  dword [rdi + 14], 56
    jb   .probe_alpha_known           ; 40/52: no alpha field
.probe_alpha:
    mov  ecx, 1
.probe_alpha_known:
    call img_bmp_mask_table           ; contiguous, disjoint, in-depth masks
    pop  rcx
    test eax, eax
    jnz  .unsupported
.format_ok:
    movsxd rcx, dword [rdi + 18]
    test rcx, rcx
    jle  .bounds
    movsxd rdx, dword [rdi + 22]
    test rdx, rdx
    jz   .bounds
    cmp  dword [rdi + 22], 0x80000000
    je   .bounds
    test rdx, rdx
    jns  .height_abs
    neg  rdx
.height_abs:
    cmp  rcx, IMG_MAX_DIM
    ja   .bounds
    cmp  rdx, IMG_MAX_DIM
    ja   .bounds
    mov  rax, rcx
    imul rax, rdx
    jo   .bounds
    cmp  rax, IMG_MAX_PIXELS
    ja   .bounds
    cmp  dword [rdi + 30], 1
    je   .rle8_span
    cmp  dword [rdi + 30], 2
    je   .rle8_span

    ; row_bytes = ((width*bpp + 31) >> 5) << 2; validate complete pixels.
    mov  rax, rcx
    imul rax, r8
    jo   .bounds
    add  rax, 31
    jc   .bounds
    shr  rax, 5
    shl  rax, 2
    mov  r9, rax
    imul rax, rdx
    jo   .bounds
    mov  r10d, [rdi + 10]
    cmp  r10, r11
    jb   .truncated                      ; pixel array overlaps the header
    cmp  r10, rsi
    ja   .truncated
    add  rax, r10
    jc   .bounds
    cmp  rax, rsi
    ja   .truncated
    cmp  dword [rdi + 14], 52
    je   .inline_pixel_pointer
    cmp  dword [rdi + 14], 56
    jne  .pointer_ready
    cmp  dword [rdi + 30], 3
    je   .inline_pixel_pointer
    cmp  r8d, 8
    jbe  .inline_pixel_pointer        ; complete indexed V3 pixel pointer
    cmp  r8d, 16
    jne  .pointer_ready              ; RGB24/32 historical span unchanged
.inline_pixel_pointer:
    mov  r11, rdi
    add  r11, rax
    jc   .bounds                     ; V2 complete pixel pointer before decode
.pointer_ready:
    ; New subsets also bind the advertised file/image lengths. Keep historical
    ; RGB24/32 parsing unchanged; uncompressed biSizeImage may legitimately be 0.
    cmp  dword [rdi + 14], 52
    je   .declared_lengths           ; new V2 RGB24/32 shares strict V2 extents
    cmp  r8d, 8
    jbe  .declared_lengths
    cmp  r8d, 16
    je   .declared_lengths
    cmp  dword [rdi + 30], 3
    je   .declared_lengths
    cmp  dword [rdi + 30], 6
    jne  .valid
.declared_lengths:
    mov  r11d, [rdi + 2]             ; bfSize covers the complete pixel span
    cmp  r11, rsi
    ja   .truncated
    cmp  rax, r11
    ja   .truncated
    mov  eax, [rdi + 34]
    test rax, rax
    jz   .indexes
    mov  r11, r9
    imul r11, rdx
    cmp  rax, r11
    jb   .corrupt
    add  rax, r10
    mov  r11d, [rdi + 2]
    cmp  rax, r11
    ja   .truncated
.indexes:
    cmp  r8d, 8
    ja   .valid
    call img_bmp_palette_check       ; visible indexes linted before allocation
    test eax, eax
    jnz  .corrupt
.valid:
    mov  ebx, IMG_FMT_BMP
    xor  eax, eax
    ret
.core24:
    call img_bmp_core24_span          ; no Windows fields on this branch
    test eax, eax
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jz   .valid
    ret
.os2:
    call img_bmp_os2_span
    test eax, eax
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jz   .valid
    ret
.rle8_span:
    ; Complete palette before the exact compressed stream. Worst-case grammar
    ; is two bytes/pixel + one EOL/row + EOB, bounded by the same pixel cap.
    mov  r10d, [rdi + 10]
    cmp  r10, r11
    jb   .truncated
    mov  r11d, [rdi + 34]
    test r11d, r11d
    jz   .corrupt
    lea  r9, [rax + rdx]
    lea  r9, [r9*2 + 2]
    cmp  r11, r9
    ja   .corrupt
    add  r11, r10
    cmp  r11, rsi
    ja   .truncated
    mov  r9d, [rdi + 2]
    cmp  r11, r9                     ; bfSize exactly covers declared stream
    jne  .truncated
    mov  r9, rdi
    add  r9, r11
    jc   .bounds                     ; complete pointer extent before token reads
    xor  r9d, r9d                    ; pure validation, no output
    call img_bmp_rle8
    test eax, eax
    jnz  .unsupported                ; outside this finite complete-row grammar
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .valid
.bad_magic:
    mov  eax, IMG_E_BAD_MAGIC
    ret
.bounds:
    mov  eax, IMG_E_BOUNDS
    ret
.truncated:
    mov  eax, IMG_E_TRUNCATED
    ret
.unsupported:
    mov  eax, IMG_E_UNSUPPORTED
    ret
.corrupt:
    mov  eax, IMG_E_CORRUPT
    ret

.embedded:
    cmp  word [rdi + 26], 1
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jne  .unsupported
    jmp  img_bmp_embedded_probe

; IBM OS/2 Warp PM Reference Vol II (Oct1994), BITMAPINFOHEADER2 A-16..19.
; Complete-field short/full64: never consult Windows masks/embedded codecs.
; Omitted trailing fields use defaults; no read crosses the declared cbFix.
; R11 is preserved
; because the second probe runs with an owned output there. Raw returns stride
; R9 and offset R10; both forms lint all data before the first allocation.
; EAX=cbFix preserved; CF clear for unambiguous OS2 complete-field boundaries.
; 40/52/56 retain their established Windows personalities even though IBM can
; truncate there too. No partial ULONG/USHORT or invented header length.
img_bmp_os2_header:
    cmp  eax, 64
    je   .yes
    cmp  eax, 16
    jb   .no
    cmp  eax, 36
    jbe  .dword
    cmp  eax, 42
    jb   .no
    cmp  eax, 48
    jbe  .word
    cmp  eax, 60
    jne  .no
.yes:
    clc
    ret
.dword:
    test al, 3
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jz   .yes
    jmp  .no
.word:
    test al, 1
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jz   .yes
.no:
    stc
    ret

img_bmp_os2_span:
    xor  eax, eax
; Private BA entry: RAX is the embedded BM's absolute file offset. The
; on-disk offBits remains absolute; all other span logic uses BM-relative bytes.
img_bmp_os2_span_bias:
    push r11
    push r12
    push rax                         ; immutable absolute-to-member offset bias
    mov  r12d, [rdi + 14]            ; caller selected a complete OS2 cbFix boundary
    lea  r11d, [r12d + 14]
    cmp  rsi, r11
    jb   .truncated
    cmp  rsi, BMP_EMBED_MAX
    ja   .bounds
    cmp  word [rdi + 26], 1
    jne  .unsupported
    cmp  r12d, 42
    jb   .metadata_done
    cmp  word [rdi + 54], 0           ; BRU_METRIC
    jne  .unsupported
    cmp  r12d, 44
    jb   .metadata_done
    cmp  word [rdi + 56], 0           ; reserved, required zero
    jne  .unsupported
    cmp  r12d, 46
    jb   .metadata_done
    cmp  word [rdi + 58], 0           ; BRA_BOTTOMUP, no signed-height convention
    jne  .unsupported
    cmp  r12d, 48
    jb   .metadata_done
    cmp  word [rdi + 60], 3           ; known halftoning metadata, pixels already encoded
    ja   .unsupported
    cmp  r12d, 60
    jb   .metadata_done
    cmp  dword [rdi + 70], 0          ; BCE_RGB, RGB2 entries
    jne  .unsupported
.metadata_done:
    mov  ecx, [rdi + 18]
    mov  edx, [rdi + 22]
    test ecx, ecx
    jz   .bounds
    test edx, edx
    jz   .bounds
    cmp  ecx, IMG_MAX_DIM
    ja   .bounds
    cmp  edx, IMG_MAX_DIM
    ja   .bounds
    mov  eax, ecx
    imul rax, rdx
    cmp  rax, IMG_MAX_PIXELS
    ja   .bounds
    movzx r8d, word [rdi + 28]
    cmp  r8d, 24
    je   .truecolor
    cmp  r12d, 64
    je   .indexed
    cmp  r12d, 20
    jb   .short_indexed_raw
    cmp  dword [rdi + 30], 0
    je   .short_indexed_raw
    cmp  r12d, 24
    jb   .unsupported                ; compressed streams require present cbImage
    jmp  .indexed
.short_indexed_raw:
    cmp  r8d, 1
    je   .palette
    cmp  r8d, 4
    je   .palette
    cmp  r8d, 8
    je   .palette
    jmp  .unsupported
.indexed:
    cmp  r8d, 1
    je   .indexed1
    cmp  r8d, 4
    je   .indexed4
    cmp  r8d, 8
    jne  .unsupported
    cmp  dword [rdi + 30], 1          ; BCA_RLE8 only at eight bits
    je   .palette
    jmp  .indexed_raw
.indexed1:
    cmp  dword [rdi + 30], 3          ; IBM BCA_HUFFMAN1D at one bit only
    je   .palette
    jmp  .indexed_raw
.indexed4:
    cmp  dword [rdi + 30], 2          ; BCA_RLE4 only at four bits
    je   .palette
.indexed_raw:
    cmp  dword [rdi + 30], 0
    jne  .unsupported                ; codecs are specific to the OS2 depth
.palette:
    push rcx
    mov  ecx, r8d
    mov  r9d, 1
    shl  r9d, cl
    pop  rcx
    xor  r10d, r10d                  ; omitted cclrUsed defaults to full table
    cmp  r12d, 36
    jb   .default_count
    mov  r10d, [rdi + 46]
.default_count:
    test r10d, r10d
    jnz  .palette_count
    mov  r10d, r9d
.palette_count:
    cmp  r10d, r9d
    ja   .corrupt
    cmp  r12d, 40
    jb   .important_done
    cmp  [rdi + 50], r10d
    ja   .corrupt
.important_done:
    lea  r11, [r11 + r10*4]          ; actual RGB2 count, reserved byte ignored
    jmp  .extent
.truecolor:
    ; RGB24 pixels are direct RGB. Optional RGB2 entries are device hints,
    ; starting after the actual cbFix, never an indexed pixel palette.
    xor  r9d, r9d
    cmp  r12d, 36
    jb   .truecolor_codec
    mov  r9d, [rdi + 46]             ; complete cclrUsed field, else absent
    cmp  r12d, 40
    jb   .advisory_span
    mov  r10d, [rdi + 50]            ; complete cclrImportant field
    test r9d, r9d
    jnz  .advisory_used
    mov  r9d, r10d                   ; IBM: RGB24 important colors also listed
    jmp  .advisory_span
.advisory_used:
    cmp  r10d, r9d
    ja   .corrupt                    ; explicit total bounds important entries
.advisory_span:
    lea  r11, [r11 + r9*4]           ; ULONG count * RGB2 width, no 32-bit wrap
.truecolor_codec:
    cmp  r12d, 20
    jb   .extent                    ; omitted compression is BCA_UNCOMP
    cmp  dword [rdi + 30], 0
    je   .extent
    cmp  dword [rdi + 30], 4          ; BCA_RLE24, not BI_JPEG
    jne  .unsupported
    cmp  r12d, 24
    jb   .unsupported               ; compressed data requires explicit cbImage
.extent:
    mov  r10d, [rdi + 10]
    sub  r10, [rsp]
    jc   .truncated
    cmp  r10, r11
    jb   .truncated
    mov  r11d, [rdi + 2]
    cmp  r11, rsi
    je   .file_extent
    cmp  r11d, 78                    ; IBM cbSize = sizeof(BITMAPFILEHEADER2)
    jne  .truncated                  ; also accept widespread total-file convention
.file_extent:                         ; actual pixels must still end exactly at caller len
    cmp  r12d, 20
    jb   .raw
    cmp  dword [rdi + 30], 0
    je   .raw
    cmp  dword [rdi + 30], 4
    je   .rle
    cmp  dword [rdi + 30], 3
    je   .huffman
    xor  r9d, r9d
    mov  rax, [rsp]
    call img_bmp_rle8_bias           ; shared bounded RLE4/8, OS2 header personality
    jmp  .out
.huffman:
    mov  r11d, [rdi + 34]
    cmp  r11d, 2
    jb   .corrupt
    mov  eax, ecx
    imul rax, rdx
    add  rax, rdx
    lea  rax, [rax*4 + 128]          ; bounded profile, including zero fill and RTC
    cmp  r11, rax
    ja   .corrupt                    ; Huffman compressed-work cap
    mov  rax, r10
    add  rax, r11
    cmp  rax, rsi
    jne  .truncated
    xor  r9d, r9d
    mov  rax, [rsp]
    call img_bmp_os2_huffman_bias
    jmp  .out
.raw:
    mov  eax, ecx
    imul eax, r8d
    add  eax, 31
    shr  eax, 5
    shl  eax, 2
    mov  r9d, eax                    ; DWORD raw stride, even for indexed rows
    imul rax, rdx
    cmp  r12d, 24
    jb   .raw_extent                ; omitted cbImage defaults to computed raw size
    cmp  dword [rdi + 34], 0
    je   .raw_extent
    mov  r11d, [rdi + 34]
    cmp  rax, r11
    jne  .corrupt
.raw_extent:
    add  rax, r10
    cmp  rax, rsi
    jne  .truncated
    cmp  r8d, 8
    ja   .good
    call img_bmp_palette_check
    test eax, eax
    jnz  .corrupt
.good:
    xor  eax, eax
    jmp  .out
.rle:
    mov  r11d, [rdi + 34]
    cmp  r11d, 2
    jb   .corrupt
    add  rax, rdx
    lea  rax, [rax*4 + 2]            ; finite bytes/work budget, includes sparse commands
    cmp  r11, rax
    ja   .corrupt
    mov  rax, r10
    add  rax, r11
    cmp  rax, rsi
    jne  .truncated
    xor  r9d, r9d
    xor  r10d, r10d                  ; IBM literal byte-count grammar first
    mov  rax, [rsp]
    call img_bmp_os2_rle24_bias
    test eax, eax
    jz   .out
    mov  r10d, 1                     ; bounded BMP Suite literal pixel-count grammar
    mov  rax, [rsp]
    call img_bmp_os2_rle24_bias
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
    add  rsp, 8
    pop  r12
    pop  r11
    ret

; Qualified short/full64 OS2 codec3/1bpp. R9=0 dry; otherwise owned RGBA.
; ITU-T T.4 (07/1996) 4.1, Tables2/3: MSB-first alternating white/black
; term/makeup codes; initial EOL, per-row EOL, six-EOL RTC (last row EOL
; is its first). Zero fill before EOL; only 0..7 zero bits after RTC.
; This bounded profile excludes T.4 uncompressed extensions and missing RTC.
; Palette0 is white, palette1 black in code space; actual RGB2 colors retained.
; Every used register except EAX preserved. No allocation or source writes.
img_bmp_os2_huffman:
    xor  eax, eax
img_bmp_os2_huffman_bias:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    push rdi
    push rsi
    sub  rsp, 16
    cld
    mov  ebp, ecx
    mov  ebx, edx
    mov  r12d, [rdi + 10]
    sub  r12, rax                 ; BA absolute offBits, zero for ordinary BM
    add  r12, rdi
    xor  r13d, r13d                  ; absolute bit cursor; .bit bounds its byte offset
    mov  r14d, [rdi + 34]
    shl  r14, 3
    xor  eax, eax
    cmp  dword [rdi + 14], 36
    jb   .default_count              ; omitted cclrUsed is not palette data
    mov  eax, [rdi + 46]
.default_count:
    test eax, eax
    jnz  .count
    mov  eax, 2
.count:
    mov  [rsp + 8], eax
    mov  edx, [rdi + 14]
    lea  rdx, [rdi + rdx + 14]       ; RGB2 starts at actual cbFix, including short
    mov  eax, [rdx]
    bswap eax
    shr  eax, 8
    or   eax, 0xff000000
    mov  [rsp], eax
    xor  eax, eax
    cmp  dword [rsp + 8], 2
    jb   .second_color
    mov  eax, [rdx + 4]
    bswap eax
    shr  eax, 8
    or   eax, 0xff000000
.second_color:
    mov  [rsp + 4], eax
    mov  r15, r9
    test r15, r15
    jz   .initial_eol
    mov  eax, ebx
    dec  eax
    imul eax, ebp
    lea  r15, [r15 + rax*4]          ; encoded rows run bottom to top
.initial_eol:
    call .read_eol
    jc   .bad
.row:
    xor  r8d, r8d
    xor  r9d, r9d                    ; every row starts with a white run
.run:
    xor  r10d, r10d
.code:
    lea  r11, [rel .white_tree]
    test r9d, r9d
    jz   .tree
    lea  r11, [rel .black_tree]
.tree:
    xor  edx, edx
.edge:
    call .bit
    jc   .bad
    lea  rcx, [r11 + rdx*4]
    movzx edx, word [rcx + rax*2]
    cmp  edx, 0xffff
    je   .bad
    test edx, 0x8000
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jz   .edge
    and  edx, 0x7fff
    add  r10d, edx
    mov  eax, r8d
    add  eax, r10d
    cmp  eax, ebp
    ja   .bad                       ; makeup and terminating runs cannot cross a row
    cmp  edx, 64
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jae  .code                      ; makeup MUST be followed by a terminator
    test r10d, r10d
    jnz  .visible
    test r8d, r8d
    jnz  .bad
    test r9d, r9d
    jnz  .bad                       ; only initial white zero, or makeup+zero term
.visible:
    test r9d, r9d
    jz   .write
    test r10d, r10d
    jz   .write
    cmp  dword [rsp + 8], 2
    jb   .bad                       ; dry pass proves every visible palette index
.write:
    test r15, r15
    jz   .advance
    mov  eax, [rsp + r9*4]
    lea  rdi, [r15 + r8*4]
    mov  ecx, r10d
    IMG_COLD_MEMORY stosd
.advance:
    add  r8d, r10d
    xor  r9d, 1
    cmp  r8d, ebp
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .run
    call .read_eol
    jc   .bad
    dec  ebx
    jz   .rtc
    test r15, r15
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jz   .row
    mov  eax, ebp
    shl  eax, 2
    sub  r15, rax
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .row
.rtc:
    mov  ebx, 5                     ; final row EOL is first of six RTC EOLs
.rtc_eol:
    call .read_eol
    jc   .bad
    dec  ebx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jnz  .rtc_eol
    mov  rax, r14
    sub  rax, r13
    cmp  rax, 7
    ja   .bad                       ; only final byte alignment, no trailing bytes
.padding:
    cmp  r13, r14
    je   .good
    call .bit
    jc   .bad
    test eax, eax
    jnz  .bad
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .padding
.good:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, IMG_E_CORRUPT
.out:
    add  rsp, 16
    pop  rsi
    pop  rdi
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret
; Private bit reader clobbers EAX/ECX, CF=1 on exhausted exact extent.
; Qualified streams are nonempty. Select byte zero on an exhausted cursor
; before the refusal branch; neither CMOV nor JAE changes the comparison flags.
.bit:
    mov  rax, r13
    shr  rax, 3
    xor  ecx, ecx
    cmp  r13, r14
    cmovae rax, rcx
    jae  .bit_bad
    movzx eax, byte [r12 + rax]
    mov  ecx, r13d
    not  ecx
    and  ecx, 7
    shr  eax, cl
    and  eax, 1
    inc  r13
    clc
    ret
.bit_bad:
    stc
    ret
; Zero fill occurs only immediately before EOL, never inside a run code.
.read_eol:
    xor  edx, edx
.eol_bit:
    call .bit
    jc   .eol_bad
    test eax, eax
    jnz  .eol_one
    inc  edx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .eol_bit
.eol_one:
    cmp  edx, 11
    jb   .eol_bad
    clc
    ret
.eol_bad:
    stc
    ret
; Factual T.4 prefix trees: node={zero,one}, internal indexes; leaf=0x8000|run.
; 0xffff is invalid. No EOL/extension symbols: framing has its own reader.
.white_tree:
    dw   0x0001, 0x000d ; node0
    dw   0x0002, 0x000b ; node1
    dw   0x0008, 0x0003 ; node2
    dw   0x0018, 0x0004 ; node3
    dw   0x0005, 0x800a ; node4
    dw   0x002f, 0x0006 ; node5
    dw   0x0007, 0x0049 ; node6
    dw   0x803f, 0x8000 ; node7
    dw   0x001a, 0x0009 ; node8
    dw   0x0022, 0x000a ; node9
    dw   0x0021, 0x8001 ; node10
    dw   0x0016, 0x000c ; node11
    dw   0x0046, 0x8002 ; node12
    dw   0x000e, 0x0011 ; node13
    dw   0x000f, 0x0010 ; node14
    dw   0x8003, 0x0014 ; node15
    dw   0x0015, 0x8004 ; node16
    dw   0x0012, 0x0013 ; node17
    dw   0x8005, 0x001c ; node18
    dw   0x8006, 0x8007 ; node19
    dw   0x8080, 0x8008 ; node20
    dw   0x8009, 0x001e ; node21
    dw   0x0017, 0x0029 ; node22
    dw   0x800b, 0x001f ; node23
    dw   0x0019, 0x0024 ; node24
    dw   0x800c, 0x002d ; node25
    dw   0x0026, 0x001b ; node26
    dw   0x0028, 0x800d ; node27
    dw   0x001d, 0x8040 ; node28
    dw   0x800e, 0x800f ; node29
    dw   0x8010, 0x8011 ; node30
    dw   0x002e, 0x0020 ; node31
    dw   0x0058, 0x8012 ; node32
    dw   0x8013, 0x0032 ; node33
    dw   0x0023, 0x0034 ; node34
    dw   0x8014, 0x0033 ; node35
    dw   0x0037, 0x0025 ; node36
    dw   0x003a, 0x8015 ; node37
    dw   0x0030, 0x0027 ; node38
    dw   0x003b, 0x8016 ; node39
    dw   0x8017, 0x003c ; node40
    dw   0x002a, 0x0040 ; node41
    dw   0x002b, 0x002c ; node42
    dw   0x8018, 0x003d ; node43
    dw   0x003e, 0x8019 ; node44
    dw   0x003f, 0x801a ; node45
    dw   0x801b, 0x0044 ; node46
    dw   0x801c, 0x0045 ; node47
    dw   0x005b, 0x0031 ; node48
    dw   0x801d, 0x801e ; node49
    dw   0x801f, 0x8020 ; node50
    dw   0x8021, 0x8022 ; node51
    dw   0x0035, 0x0036 ; node52
    dw   0x8023, 0x8024 ; node53
    dw   0x8025, 0x8026 ; node54
    dw   0x0038, 0x0039 ; node55
    dw   0x8027, 0x8028 ; node56
    dw   0x8029, 0x802a ; node57
    dw   0x802b, 0x802c ; node58
    dw   0x802d, 0x802e ; node59
    dw   0x802f, 0x8030 ; node60
    dw   0x8031, 0x8032 ; node61
    dw   0x8033, 0x8034 ; node62
    dw   0x8035, 0x8036 ; node63
    dw   0x0041, 0x80c0 ; node64
    dw   0x0042, 0x0043 ; node65
    dw   0x8037, 0x8038 ; node66
    dw   0x8039, 0x803a ; node67
    dw   0x803b, 0x803c ; node68
    dw   0x803d, 0x803e ; node69
    dw   0x004a, 0x0047 ; node70
    dw   0x004d, 0x0048 ; node71
    dw   0x0055, 0x8100 ; node72
    dw   0x8140, 0x8180 ; node73
    dw   0x8680, 0x004b ; node74
    dw   0x004c, 0x004f ; node75
    dw   0x81c0, 0x8200 ; node76
    dw   0x004e, 0x0052 ; node77
    dw   0x8240, 0x0051 ; node78
    dw   0x0050, 0x8280 ; node79
    dw   0x82c0, 0x8300 ; node80
    dw   0x8340, 0x8380 ; node81
    dw   0x0053, 0x0054 ; node82
    dw   0x83c0, 0x8400 ; node83
    dw   0x8440, 0x8480 ; node84
    dw   0x0056, 0x0057 ; node85
    dw   0x84c0, 0x8500 ; node86
    dw   0x8540, 0x8580 ; node87
    dw   0x0059, 0x005a ; node88
    dw   0x85c0, 0x8600 ; node89
    dw   0x8640, 0x86c0 ; node90
    dw   0xffff, 0x005c ; node91
    dw   0x005d, 0x005f ; node92
    dw   0x005e, 0x0062 ; node93
    dw   0x8700, 0x0061 ; node94
    dw   0x0060, 0x0065 ; node95
    dw   0x8740, 0x8780 ; node96
    dw   0x87c0, 0x8800 ; node97
    dw   0x0063, 0x0064 ; node98
    dw   0x8840, 0x8880 ; node99
    dw   0x88c0, 0x8900 ; node100
    dw   0x0066, 0x0067 ; node101
    dw   0x8940, 0x8980 ; node102
    dw   0x89c0, 0x8a00 ; node103
.black_tree:
    dw   0x0001, 0x000b ; node0
    dw   0x0002, 0x000a ; node1
    dw   0x0003, 0x000c ; node2
    dw   0x0004, 0x000d ; node3
    dw   0x0010, 0x0005 ; node4
    dw   0x000f, 0x0006 ; node5
    dw   0x0007, 0x800c ; node6
    dw   0x0014, 0x0008 ; node7
    dw   0x001f, 0x0009 ; node8
    dw   0x0021, 0x8000 ; node9
    dw   0x8001, 0x8004 ; node10
    dw   0x8003, 0x8002 ; node11
    dw   0x8006, 0x8005 ; node12
    dw   0x000e, 0x8007 ; node13
    dw   0x8009, 0x8008 ; node14
    dw   0x800a, 0x800b ; node15
    dw   0x0019, 0x0011 ; node16
    dw   0x0012, 0x0013 ; node17
    dw   0x800d, 0x0015 ; node18
    dw   0x0017, 0x800e ; node19
    dw   0x800f, 0x001d ; node20
    dw   0x0024, 0x0016 ; node21
    dw   0x0047, 0x8010 ; node22
    dw   0x0018, 0x0022 ; node23
    dw   0x8011, 0x003a ; node24
    dw   0x005b, 0x001a ; node25
    dw   0x001b, 0x0028 ; node26
    dw   0x001c, 0x0026 ; node27
    dw   0x8012, 0x003d ; node28
    dw   0x002b, 0x001e ; node29
    dw   0x002d, 0x8013 ; node30
    dw   0x0020, 0x0032 ; node31
    dw   0x8014, 0x0031 ; node32
    dw   0x8015, 0x0036 ; node33
    dw   0x002e, 0x0023 ; node34
    dw   0x0035, 0x8016 ; node35
    dw   0x0025, 0x0037 ; node36
    dw   0x8017, 0x003c ; node37
    dw   0x0045, 0x0027 ; node38
    dw   0x004a, 0x8018 ; node39
    dw   0x0029, 0x0041 ; node40
    dw   0x002a, 0x003f ; node41
    dw   0x8019, 0x004e ; node42
    dw   0x004d, 0x002c ; node43
    dw   0x801a, 0x801b ; node44
    dw   0x801c, 0x801d ; node45
    dw   0x002f, 0x0030 ; node46
    dw   0x801e, 0x801f ; node47
    dw   0x8020, 0x8021 ; node48
    dw   0x8022, 0x8023 ; node49
    dw   0x0033, 0x0034 ; node50
    dw   0x8024, 0x8025 ; node51
    dw   0x8026, 0x8027 ; node52
    dw   0x8028, 0x8029 ; node53
    dw   0x802a, 0x802b ; node54
    dw   0x0038, 0x0039 ; node55
    dw   0x802c, 0x802d ; node56
    dw   0x802e, 0x802f ; node57
    dw   0x003b, 0x004c ; node58
    dw   0x8030, 0x8031 ; node59
    dw   0x8032, 0x8033 ; node60
    dw   0x003e, 0x0044 ; node61
    dw   0x8034, 0x0051 ; node62
    dw   0x004f, 0x0040 ; node63
    dw   0x0050, 0x8035 ; node64
    dw   0x0042, 0x8040 ; node65
    dw   0x0043, 0x0054 ; node66
    dw   0x8036, 0x0053 ; node67
    dw   0x0052, 0x8037 ; node68
    dw   0x0046, 0x0049 ; node69
    dw   0x8038, 0x0057 ; node70
    dw   0x0048, 0x004b ; node71
    dw   0x8039, 0x803a ; node72
    dw   0x0058, 0x803b ; node73
    dw   0x803c, 0x0059 ; node74
    dw   0x803d, 0x8100 ; node75
    dw   0x803e, 0x803f ; node76
    dw   0x8080, 0x80c0 ; node77
    dw   0x005a, 0x8140 ; node78
    dw   0x8180, 0x81c0 ; node79
    dw   0x8200, 0x8240 ; node80
    dw   0x8280, 0x82c0 ; node81
    dw   0x8300, 0x8340 ; node82
    dw   0x8380, 0x83c0 ; node83
    dw   0x0055, 0x0056 ; node84
    dw   0x8400, 0x8440 ; node85
    dw   0x8480, 0x84c0 ; node86
    dw   0x8500, 0x8540 ; node87
    dw   0x8580, 0x85c0 ; node88
    dw   0x8600, 0x8640 ; node89
    dw   0x8680, 0x86c0 ; node90
    dw   0xffff, 0x005c ; node91
    dw   0x005d, 0x005f ; node92
    dw   0x005e, 0x0062 ; node93
    dw   0x8700, 0x0061 ; node94
    dw   0x0060, 0x0065 ; node95
    dw   0x8740, 0x8780 ; node96
    dw   0x87c0, 0x8800 ; node97
    dw   0x0063, 0x0064 ; node98
    dw   0x8840, 0x8880 ; node99
    dw   0x88c0, 0x8900 ; node100
    dw   0x0066, 0x0067 ; node101
    dw   0x8940, 0x8980 ; node102
    dw   0x89c0, 0x8a00 ; node103

; Qualified OS2 source/geometry; R9=0 validates, nonzero writes owned RGBA.
; R10D=0 IBM literal byte counts, 1 BMP Suite literal pixel counts.
; All used registers except EAX preserved, so probe and decode share grammar.
img_bmp_os2_rle24:
    xor  eax, eax
img_bmp_os2_rle24_bias:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    push rdi
    push rsi
    mov  r12d, r10d                  ; immutable selected grammar
    mov  ebp, ecx                    ; width
    mov  ebx, edx                    ; remaining rows, bottom to top
    mov  r13d, [rdi + 10]
    sub  r13, rax                 ; BA absolute offBits, zero for ordinary BM
    add  r13, rdi
    mov  r14d, [rdi + 34]
    add  r14, r13                    ; probe proved exact source extent
    xor  r8d, r8d                    ; x in current row
    test r9, r9
    jz   .token
    mov  rdx, r9
    mov  ecx, ebp
    imul ecx, ebx
    mov  eax, 0xff000000             ; deterministic opaque black for skipped pixels
.background:
    mov  [rdx], eax
    add  rdx, 4
    dec  ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jnz  .background
    mov  eax, ebx
    dec  eax
    imul eax, ebp
    lea  r9, [r9 + rax*4]
.token:
    mov  rax, r14
    sub  rax, r13
    cmp  rax, 2
    jb   .bad
    movzx ecx, byte [r13]
    test ecx, ecx
    jz   .escape
    cmp  rax, 4                     ; complete encoded count+BGR triple
    jb   .bad
    inc  r13
    xor  r11d, r11d                 ; encoded count is pixels
    jmp  .run
.escape:
    movzx esi, byte [r13 + 1]
    add  r13, 2
    test esi, esi
    jz   .eol
    cmp  esi, 1
    je   .eob
    cmp  esi, 2
    je   .delta
    mov  r15d, esi                   ; absolute count is BYTES, at most255
    test r12d, r12d
    jnz  .pixel_count
    mov  eax, esi
    xor  edx, edx
    mov  edi, 3
    div  edi
    test edx, edx
    jnz  .bad                       ; COUNT must be a multiple of3 (IBM A-17)
    mov  ecx, eax                    ; one through85 literal pixels
    jmp  .literal_extent
.pixel_count:
    mov  ecx, esi                    ; BMP Suite absolute count is pixels3..255
    lea  esi, [rsi + rsi*2]
    mov  r15d, esi                   ; <=765 literal bytes, still bounded
.literal_extent:
    mov  eax, esi
    and  eax, 1
    add  eax, esi
    mov  rdx, r14
    sub  rdx, r13
    cmp  rax, rdx
    ja   .bad                       ; qualify all bytes AND zero pad first
    test sil, 1
    jz   .literal_ready
    cmp  byte [r13 + rsi], 0
    jne  .bad
.literal_ready:
    mov  r11d, 1
.run:
    test ebx, ebx
    jz   .bad
    mov  eax, ebp
    sub  eax, r8d
    cmp  ecx, eax
    ja   .bad                       ; runs never cross a scan line
    mov  r10d, ecx
.pixel:
    movzx esi, byte [r13]            ; BGR, not RGB and no fourth source byte
    shl  esi, 16
    movzx eax, byte [r13 + 1]
    shl  eax, 8
    or   esi, eax
    movzx eax, byte [r13 + 2]
    or   esi, eax
    or   esi, 0xff000000
    test r9, r9
    jz   .advance
    mov  [r9], esi
    add  r9, 4
.advance:
    test r11d, r11d
    jz   .encoded_advance
    add  r13, 3
.encoded_advance:
    inc  r8d
    dec  r10d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jnz  .pixel
    test r11d, r11d
    jnz  .literal_end
    add  r13, 3
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .token
.literal_end:
    and  r15d, 1
    add  r13, r15                    ; count parity, independent of file offset
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .token
.delta:
    mov  rax, r14
    sub  rax, r13
    cmp  rax, 2
    jb   .bad
    movzx ecx, byte [r13]
    movzx eax, byte [r13 + 1]
    add  r13, 2
    test ebx, ebx
    jz   .bad
    add  ecx, r8d
    cmp  ecx, ebp
    ja   .bad
    cmp  eax, ebx
    jae  .bad
    test r9, r9
    jz   .delta_cursor
    mov  edx, eax
    imul rdx, rbp
    shl  rdx, 2
    sub  r9, rdx
    mov  edx, ecx
    sub  edx, r8d
    lea  r9, [r9 + rdx*4]
.delta_cursor:
    sub  ebx, eax
    mov  r8d, ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .token
.eol:
    test ebx, ebx
    jz   .bad
    dec  ebx
    test ebx, ebx
    jz   .eol_reset
    test r9, r9
    jz   .eol_reset
    mov  eax, ebp
    add  eax, r8d
    shl  eax, 2
    sub  r9, rax
.eol_reset:
    xor  r8d, r8d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .token
.eob:
    cmp  r13, r14
    jne  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, IMG_E_CORRUPT
.out:
    pop  rsi
    pop  rdi
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Packed MSB-first 1/2/4/8-bit index: RSI=file row, ECX=x, EBP=bpp.
; RAX alone is clobbered. Padding and invisible trailing bits are never read.
img_bmp_index:
    cmp  ebp, 8
    je   .byte
    mov  eax, ecx
    cmp  ebp, 4
    je   .nibble
    cmp  ebp, 2
    je   .pair
    shr  eax, 3
    movzx eax, byte [rsi + rax]
    push rcx
    xor  ecx, 7
    and  ecx, 7
    shr  eax, cl
    and  eax, 1
    pop  rcx
    ret
.pair:
    shr  eax, 2
    movzx eax, byte [rsi + rax]
    push rcx
    xor  ecx, 3
    and  ecx, 3
    shl  ecx, 1
    shr  eax, cl
    and  eax, 3
    pop  rcx
    ret
.nibble:
    shr  eax, 1
    movzx eax, byte [rsi + rax]
    test cl, 1
    jnz  .low
    shr  eax, 4
.low:
    and  eax, 15
    ret
.byte:
    movzx eax, byte [rsi + rcx]
    ret

; V5 rendering intent describes a subsequent destination gamut mapping. This
; decoder returns source sRGB samples and performs no color-space transform.
; EAX=enum; ZF=1 only for BUSINESS1/GRAPHICS2/IMAGES4/ABS_COLORIMETRIC8.
; Preserve all general registers; callers already proved the complete V5 tail.
img_bmp_v5_intent:
    cmp  eax, 1
    je   .out
    cmp  eax, 2
    je   .out
    cmp  eax, 4
    je   .out
    cmp  eax, 8
.out:
    ret

; Private metadata predicate, called only after complete56/108/124 extent.
img_bmp_alpha_mask:
    cmp  dword [rdi + 66], 0
    je   .valid                      ; retained opaque16/32 and zero-mask indexed
    cmp  dword [rdi + 30], 3
    jne  .unsupported                ; indexed/RGB16 metadata keeps a zero alpha mask
    ; BI_BITFIELDS alpha: img_bmp_mask_table qualifies it with the colour masks
.valid:
    xor  eax, eax
    ret
.unsupported:
    mov  eax, IMG_E_UNSUPPORTED
    ret

; RCQ-34 general masks. RDI=file whose DIB fields and masks (54..66, plus 66..70
; when an alpha field exists) are proven readable, R8D=16/32. ECX=1 when the
; caller's header has an alpha field (the 56/108/124-byte DIBs and
; BI_ALPHABITFIELDS), 0 for 40/52; the decoder passes its pinned codec and DIB
; size, so the alpha decision never rereads the source.
; Red, green and blue must be nonzero; every nonzero mask must be contiguous,
; inside the depth and disjoint from the others; a zero alpha mask is opaque.
; R9=0 validates only. Otherwise R9 receives four 16-byte entries (R G B A):
; mask, shift, max (= mask >> shift), 0, built from ONE read of each source
; mask, so a decoder that uses only the table cannot divide by a zero max.
; EAX=0 or IMG_E_UNSUPPORTED (the retained refusal for masks outside the set);
; every other register is preserved.
img_bmp_mask_table:
    push rbx
    push rcx
    push rdx
    push rsi
    push r10
    push r11
    sub  rsp, 16                      ; private copy: R G B A
    mov  eax, [rdi + 54]
    mov  [rsp], eax
    mov  eax, [rdi + 58]
    mov  [rsp + 4], eax
    mov  eax, [rdi + 62]
    mov  [rsp + 8], eax
    xor  eax, eax
    test ecx, ecx
    jz   .alpha_ready                 ; 40/52: no alpha field, opaque
    mov  eax, [rdi + 66]
.alpha_ready:
    mov  [rsp + 12], eax
    xor  r10d, r10d                   ; union of the masks already taken
    xor  esi, esi                     ; channel 0..3
.mask:
    mov  edx, [rsp + rsi*4]
    xor  ecx, ecx
    xor  ebx, ebx
    test edx, edx
    jnz  .present
    cmp  esi, 3
    jne  .bad                         ; red, green and blue are required
    jmp  .entry                       ; alpha absent: opaque
.present:
    cmp  r8d, 32
    je   .in_depth
    test edx, 0xffff0000
    jnz  .bad                         ; outside the 16-bit pixel
.in_depth:
    test edx, r10d
    jnz  .bad                         ; overlaps an earlier channel
    or   r10d, edx
    bsf  ecx, edx                     ; shift = lowest set bit
    mov  ebx, edx
    shr  ebx, cl                      ; max >= 1, zero-extended
    lea  r11, [rbx + 1]
    test r11, rbx
    jnz  .bad                         ; a gap inside the mask
.entry:
    test r9, r9
    jz   .next
    mov  rax, rsi
    shl  rax, 4
    mov  [r9 + rax], edx
    mov  [r9 + rax + 4], ecx
    mov  [r9 + rax + 8], ebx
    mov  dword [r9 + rax + 12], 0
.next:
    inc  esi
    cmp  esi, 4
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .mask
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, IMG_E_UNSUPPORTED
.out:
    add  rsp, 16
    pop  r11
    pop  r10
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    ret

; One general-mask channel. EDX=pixel, RBX=table entry. AL=(pixel & mask) >>
; shift scaled to 0..255 as v*255/max; a zero mask (alpha only) gives 255.
; RAX alone is clobbered.
img_bmp_mask_channel:
    mov  eax, [rbx]
    test eax, eax
    jz   .opaque
    and  eax, edx
    push rcx
    push rdx
    mov  ecx, [rbx + 4]
    shr  eax, cl                      ; v <= max, zero-extended
    imul rax, rax, 255                ; < 2^40, no overflow
    xor  edx, edx
    mov  ecx, [rbx + 8]               ; table max is never zero for a set mask
    div  rcx
    pop  rdx
    pop  rcx
    ret
.opaque:
    mov  eax, 255
    ret

; Uses already-bounded stride/span; preserves the probe's returned geometry.
; No allocation or persistent parser state. At most IMG_MAX_PIXELS indexes.
img_bmp_palette_check:
    push rbp
    push r12
    push r13
    push r14
    push rcx
    push rsi
    mov  ebp, r8d
    mov  r12d, ecx
    mov  r13d, edx
    xor  r14d, r14d
    cmp  dword [rdi + 14], 36
    jb   .default_count             ; shortened OS2 has no cclrUsed field
    mov  r14d, [rdi + 46]
.default_count:
    test r14d, r14d
    jnz  .rows
    mov  ecx, ebp
    mov  r14d, 1
    shl  r14d, cl
.rows:
    lea  rsi, [rdi + r10]
.row:
    xor  ecx, ecx
.pixel:
    call img_bmp_index
    cmp  eax, r14d
    jae  .bad
    inc  ecx
    cmp  ecx, r12d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .pixel
    add  rsi, r9
    dec  r13d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jnz  .row
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, IMG_E_CORRUPT
.out:
    pop  rsi
    pop  rcx
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    ret

; Windows BITMAPINFOHEADER BI_JPEG/BI_PNG adapter. Source cap includes header/gap.
; Positive dimensions describe the decompressed raster, not a BMP row reversal.
BMP_EMBED_MAX equ 33554432
; IBM PM Vol2 Appendix A/D bitmap arrays: cbSize is STRUCTURE size;
; offNext/offBits are absolute file offsets. The single-surface API returns
; member zero, independent of display hints, only if EVERY member qualifies.
; Supported BM members are CORE and this decoder's unambiguous OS2 profiles;
; icon/pointer masks, nested arrays and ambiguous Windows headers are refused.
; At most64 entries, 32MiB source and IMG_MAX_PIXELS aggregate work. Header,
; table and pixel intervals must be disjoint; forward headers may precede all
; pixels (native OS2 layout) or interleave with them. No allocation/source writes.
; Fixed2112-byte descriptor frame; R10 returns first member's absolute pixel end.
img_bmp_array_probe:
    cld
    push r12
    push r13
    push r14
    push r15
    push rbp
    push rdi
    push rsi
    push r11
    sub  rsp, 2112
    mov  r12, rdi
    mov  r13, rsi
    mov  rax, rdi
    add  rax, rsi
    jc   .bounds
    cmp  r13, BMP_EMBED_MAX
    ja   .bounds
    cmp  r13, 40
    jb   .truncated
    xor  r14d, r14d                 ; entry count
    xor  r15d, r15d                 ; current BA absolute offset
    xor  ebp, ebp                   ; total decoded pixels, across all members
    mov  qword [rsp + 2048], 0      ; maximum referenced pixel end
.chain:
    cmp  r14d, 64
    jae  .bounds
    lea  rax, [r15 + 40]
    cmp  rax, r13
    ja   .truncated
    lea  rdi, [r12 + r15]
    cmp  word [rdi], 'BA'
    jne  .corrupt
    cmp  word [rdi + 14], 'BM'
    jne  .unsupported
    mov  r11d, [rdi + 28]           ; cbFix, not a Windows BITMAPINFOHEADER
    mov  eax, r11d
    cmp  eax, 12
    je   .core_header
    call img_bmp_os2_header
    jc   .unsupported
    cmp  dword [rdi + 2], 92
    jne  .corrupt
    cmp  dword [rdi + 16], 78
    jne  .corrupt
    lea  rsi, [r15 + r11 + 28]
    cmp  rsi, r13
    ja   .truncated
    mov  ecx, [rdi + 32]
    mov  edx, [rdi + 36]
    movzx r8d, word [rdi + 42]
    jmp  .geometry
.core_header:
    cmp  dword [rdi + 2], 40
    jne  .corrupt
    cmp  dword [rdi + 16], 26
    jne  .corrupt
    lea  rsi, [r15 + 40]
    movzx ecx, word [rdi + 32]
    movzx edx, word [rdi + 34]
    movzx r8d, word [rdi + 38]
.geometry:
    test ecx, ecx
    jz   .bounds
    test edx, edx
    jz   .bounds
    cmp  ecx, IMG_MAX_DIM
    ja   .bounds
    cmp  edx, IMG_MAX_DIM
    ja   .bounds
    mov  eax, ecx
    imul rax, rdx
    add  rbp, rax
    cmp  rbp, IMG_MAX_PIXELS
    ja   .bounds
    cmp  r8d, 24
    je   .truecolor_table
    cmp  r8d, 1
    je   .indexed_table
    cmp  r8d, 4
    je   .indexed_table
    cmp  r8d, 8
    jne  .unsupported
.indexed_table:
    push rcx
    mov  ecx, r8d
    mov  r9d, 1
    shl  r9d, cl
    pop  rcx
    cmp  r11d, 12
    je   .core_table
    cmp  r11d, 36
    jb   .os2_table
    mov  eax, [rdi + 60]
    test eax, eax
    jz   .os2_table
    cmp  rax, r9
    ja   .corrupt
    mov  r9, rax
    jmp  .os2_table
.truecolor_table:
    xor  r9d, r9d
    cmp  r11d, 36
    jb   .table_done
    mov  r9d, [rdi + 60]
.os2_table:
    lea  rsi, [rsi + r9*4]
    jmp  .table_done
.core_table:
    lea  r9, [r9 + r9*2]
    add  rsi, r9
.table_done:
    cmp  rsi, r13
    ja   .truncated
    mov  r10d, [rdi + 24]           ; DWORD offBits, absolute from array file start
    cmp  r10, rsi
    jb   .truncated
    cmp  r11d, 20
    jb   .raw_extent
    cmp  dword [rdi + 44], 0        ; omitted compression is raw
    je   .raw_extent
    cmp  r11d, 24
    jb   .unsupported
    mov  eax, [rdi + 48]            ; cbImage required for every compressed member
    jmp  .pixel_extent
.raw_extent:
    mov  eax, ecx
    imul rax, r8
    add  rax, 31
    shr  rax, 5
    shl  rax, 2
    imul rax, rdx
.pixel_extent:
    add  rax, r10                   ; bounded DWORD fields plus bounded geometry
    cmp  rax, r13
    ja   .truncated
    mov  rbx, r14
    shl  rbx, 5
    add  rbx, rsp
    mov  [rbx], r15
    mov  [rbx + 8], rsi
    mov  [rbx + 16], r10
    mov  [rbx + 24], rax
    cmp  rax, [rsp + 2048]
    jbe  .max_done
    mov  [rsp + 2048], rax
.max_done:
    inc  r14d
    mov  eax, [rdi + 6]
    test eax, eax
    jz   .chain_done
    cmp  rax, rsi                   ; complete current header/table before next BA
    jb   .corrupt
    cmp  rax, r15
    jbe  .corrupt                   ; finite forward progress, no cycles/alias
    mov  r15, rax
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .chain
.chain_done:
    cmp  r13, [rsp + 2048]
    jne  .truncated                 ; no hidden trailing array or unreferenced tail
    shl  r14, 5                     ; descriptor byte length
    xor  r15d, r15d
.pairs:
    lea  rbx, [rsp + r15]
    lea  rbp, [r15 + 32]
.inner_pair:
    cmp  rbp, r14
    jae  .next_pair
    lea  rdi, [rsp + rbp]
    mov  rax, [rbx + 16]            ; A pixels versus B header/table
    cmp  rax, [rdi + 8]
    jae  .reverse_header
    mov  rax, [rdi]
    cmp  rax, [rbx + 24]
    jb   .corrupt
.reverse_header:
    mov  rax, [rdi + 16]
    cmp  rax, [rbx + 8]
    jae  .pixel_pair
    mov  rax, [rbx]
    cmp  rax, [rdi + 24]
    jb   .corrupt
.pixel_pair:
    mov  rax, [rbx + 16]
    cmp  rax, [rdi + 24]
    jae  .disjoint
    mov  rax, [rdi + 16]
    cmp  rax, [rbx + 24]
    jb   .corrupt
.disjoint:
    add  rbp, 32
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .inner_pair
.next_pair:
    add  r15, 32
    cmp  r15, r14
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .pairs
    xor  r15d, r15d
.qualify:
    lea  rbx, [rsp + r15]
    mov  rax, [rbx]
    add  rax, 14                    ; absolute BM offset, passed to biased span
    lea  rdi, [r12 + rax]
    mov  rsi, [rbx + 24]
    sub  rsi, rax                   ; exact BM-view extent through its pixels
    cmp  dword [rdi + 14], 12
    je   .qualify_core
    call img_bmp_os2_span_bias
    jmp  .qualified
.qualify_core:
    call img_bmp_core24_span_bias
.qualified:
    test eax, eax
    jnz  .out
    test r15, r15
    jnz  .saved
    mov  [rsp + 2056], ecx
    mov  [rsp + 2060], edx
    mov  [rsp + 2064], r8d
    mov  rax, [rsp + 24]
    mov  [rsp + 2072], rax
.saved:
    add  r15, 32
    cmp  r15, r14
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .qualify                   ; validate trailing members' actual pixel grammar
    mov  ecx, [rsp + 2056]
    mov  edx, [rsp + 2060]
    mov  r8d, [rsp + 2064]
    mov  r10, [rsp + 2072]
    mov  ebx, IMG_FMT_BMP
    xor  eax, eax
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
    test eax, eax
    jz   .restore
    xor  ebx, ebx
    xor  ecx, ecx
    xor  edx, edx
    xor  r8d, r8d
.restore:
    add  rsp, 2112
    pop  r11
    pop  rsi
    pop  rdi
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    ret

; Whole-array SHA before qualification; copy after full allocation-free chain
; validation, compare and requalify the private copy. Only that owned snapshot
; is normalized into a standalone BM view. Existing pixel grammars remain the
; sole decoders. Nested output is released before publishing outer owned RGBA.
img_bmp_array_decode:
    cld
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub  rsp, 128
    mov  r12, rdi
    mov  r13, rsi
    mov  rax, rdi
    add  rax, rsi
    jc   .bounds
    cmp  r13, BMP_EMBED_MAX
    ja   .bounds
    cmp  r13, 40
    jb   .truncated
    lea  rdi, [rsp + 64]
    mov  rsi, r12
    mov  rdx, r13
    IMG_COLD_DIGEST
    mov  rdi, r12
    mov  rsi, r13
    call img_bmp_array_probe
    test eax, eax
    jnz  .refused
    mov  [rsp], ecx
    mov  [rsp + 4], edx
    mov  [rsp + 8], r10             ; absolute selected pixel end
    mov  [rsp + 16], r8d
    mov  eax, ecx
    imul rax, rdx
    shl  rax, 2
    mov  [rsp + 24], rax
    cmp  rax, r13
    cmovb rax, r13
    mov  [rsp + 32], rax
    IMG_COLD_HEAP_NOW
    mov  [rsp + 40], rax
    mov  rdi, [rsp + 32]
    IMG_COLD_HEAP_ALLOC
    test rax, rax
    jz   .oom
    mov  r14, rax
    IMG_COLD_HEAP_NOW
    mov  [rsp + 48], rax
    mov  rdi, r14
    mov  rsi, r12
    mov  rcx, r13
    IMG_COLD_MEMORY movsb
    lea  rdi, [rsp + 96]
    mov  rsi, r14
    mov  rdx, r13
    IMG_COLD_DIGEST
    lea  rdi, [rsp + 64]
    lea  rsi, [rsp + 96]
    mov  ecx, 32
    repe cmpsb
    jne  .changed
    mov  rdi, r14
    mov  rsi, r13
    call img_bmp_array_probe
    test eax, eax
    jnz  .scratch_failure
    cmp  ecx, [rsp]
    jne  .changed
    cmp  edx, [rsp + 4]
    jne  .changed
    cmp  r8d, [rsp + 16]
    jne  .changed
    cmp  r10, [rsp + 8]
    jne  .changed
    sub  dword [r14 + 24], 14       ; private offBits relative to the BM at14
    mov  rax, r10
    sub  rax, 14
    mov  [r14 + 16], eax           ; private standalone bfSize, not BA cbSize
    lea  rdi, [r14 + 14]
    mov  rsi, rax
    call img_bmp_decode
    test eax, eax
    jnz  .scratch_failure
    cmp  r8d, IMG_FMT_BMP
    jne  .output_changed
    cmp  ecx, [rsp]
    jne  .output_changed
    cmp  edx, [rsp + 4]
    jne  .output_changed
    mov  rdi, r14
    mov  rsi, rbx
    mov  rcx, [rsp + 24]
    IMG_COLD_MEMORY movsb
    call img_output_release
    cmp  qword [rel img_active_out], 0
    jne  .retire_failed
    mov  [rel img_active_out], r14
    mov  rax, [rsp + 40]
    mov  [rel img_alloc_before], rax
    mov  rax, [rsp + 48]
    mov  [rel img_alloc_after], rax
    mov  rax, [rsp + 32]
    mov  [rel img_alloc_size], rax
    mov  qword [rel img_active_src], 0
    mov  qword [rel img_active_len], 0
    mov  rbx, r14
    mov  ecx, [rsp]
    mov  edx, [rsp + 4]
    mov  r8d, IMG_FMT_BMP
    xor  eax, eax
    jmp  .out
.output_changed:
    call img_output_release
.changed:
    mov  eax, IMG_E_CORRUPT
    jmp  .scratch_failure
.retire_failed:
    mov  eax, IMG_E_OOM
.scratch_failure:
    mov  ebp, eax
    mov  rdi, r14
%ifdef PAOS_IMG_COLD_WORK
    mov  rax, [rsp + 48]
    mov  rdx, [rsp + 40]
    call img_cold_heap_rewind
%else
    call kfree
    mov  rax, [rsp + 48]
    mov  rdx, [rsp + 40]
    lock cmpxchg [rel heap_next], rdx
%endif
    mov  eax, ebp
    jmp  .refused
.oom:
    mov  eax, IMG_E_OOM
    jmp  .refused
.bounds:
    mov  eax, IMG_E_BOUNDS
    jmp  .refused
.truncated:
    mov  eax, IMG_E_TRUNCATED
.refused:
    call img_refusal_clear
.out:
    add  rsp, 128
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    ret

img_bmp_embedded_probe:
    cld
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov  r12, rdi
    mov  r13, rsi
    cmp  dword [r12 + 14], 40
    je   .profile_ready
    cmp  dword [r12 + 14], 52
    je   .inline_metadata
    cmp  dword [r12 + 14], 56
    je   .inline_metadata
    cmp  dword [r12 + 14], 108
    je   .extended_metadata
    cmp  dword [r12 + 14], 124
    jne  .unsupported
    ; Parent proved the complete declared header and entire caller pointer span.
    mov  eax, [r12 + 122]
    call img_bmp_v5_intent           ; same source-sRGB metadata policy
    jne  .unsupported
    cmp  qword [r12 + 126], 0
    jne  .unsupported
    cmp  dword [r12 + 134], 0
    jne  .unsupported
.extended_metadata:
    cmp  qword [r12 + 54], 0          ; embedded codecs have no RGB/alpha masks
    jne  .unsupported
    cmp  qword [r12 + 62], 0
    jne  .unsupported
    cmp  dword [r12 + 70], 0x73524742 ; same finite sRGB policy as raw V4/V5
    jne  .unsupported
    lea  r9, [r12 + 74]
    mov  ecx, 6                      ; all 36 endpoint + 12 gamma bytes
.zero_color:
    cmp  qword [r9], 0
    jne  .unsupported
    add  r9, 8
    dec  ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jnz  .zero_color
    jmp  .profile_ready
.inline_metadata:
    cmp  qword [r12 + 54], 0          ; complete52/56 proved by parent
    jne  .unsupported
    cmp  dword [r12 + 62], 0
    jne  .unsupported
    cmp  dword [r12 + 14], 52
    je   .profile_ready             ; V2 has no alpha field at66
    cmp  dword [r12 + 66], 0
    jne  .unsupported
.profile_ready:
    cmp  word [r12 + 28], 0
    jne  .unsupported
    cmp  dword [r12 + 6], 0
    jne  .unsupported
    cmp  qword [r12 + 46], 0          ; no palette or important-color table
    jne  .unsupported
    cmp  r13, BMP_EMBED_MAX
    ja   .bounds
    mov  eax, [r12 + 2]
    cmp  rax, r13                     ; exact declared/caller file extent
    jne  .truncated
    mov  r14d, [r12 + 18]
    mov  r15d, [r12 + 22]
    test r14d, r14d
    jle  .bounds
    test r15d, r15d
    jle  .bounds
    cmp  r14d, IMG_MAX_DIM
    ja   .bounds
    cmp  r15d, IMG_MAX_DIM
    ja   .bounds
    mov  eax, r14d
    imul rax, r15
    cmp  rax, IMG_MAX_PIXELS
    ja   .bounds
    mov  edi, [r12 + 10]
    mov  eax, [r12 + 14]
    add  eax, 14                     ; complete selected DIB, not fixed54
    cmp  edi, eax
    jb   .bounds
    mov  esi, [r12 + 34]
    test esi, esi
    jz   .truncated
    mov  rax, rdi
    add  rax, rsi                     ; zero-extended fields, full64 sum
    cmp  rax, r13
    jne  .truncated
    add  rdi, r12                     ; full caller pointer checked by parent
    mov  ebp, [r12 + 30]
    cmp  ebp, 5
    je   .png
    call img_jpeg_probe_exact
    mov  r9d, IMG_FMT_JPEG
    jmp  .checked
.png:
    call img_png_probe_exact
    mov  r9d, IMG_FMT_PNG
.checked:
    test eax, eax
    jnz  .out
    cmp  ebx, r9d
    jne  .corrupt
    cmp  ecx, r14d
    jne  .corrupt
    cmp  edx, r15d
    jne  .corrupt
    mov  ebx, IMG_FMT_BMP
    xor  eax, eax
    jmp  .out
.unsupported:
    mov  eax, IMG_E_UNSUPPORTED
    jmp  .out
.bounds:
    mov  eax, IMG_E_BOUNDS
    jmp  .out
.truncated:
    mov  eax, IMG_E_TRUNCATED
    jmp  .out
.corrupt:
    mov  eax, IMG_E_CORRUPT
.out:
    call img_codec_state_clear       ; no borrowed source/parse tables escape probe
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    ret

; Two nested allocations, with a single published final allocation. A validated
; source is SHA-bound before allocation, copied, compared and requalified. The
; native decoder only sees owned bytes. After decode, copy RGBA into the first
; block, release the codec block, then adopt the first block via the unchanged
; img_output_release contract. No caller pointer is used after the copy.
; BSP-serialized image/heap workspace, same LIFO/contention semantics as core.
img_bmp_embedded_decode:
    cld
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub  rsp, 128
    mov  r12, rdi
    mov  r13, rsi
    mov  [rsp], ecx                  ; dimensions from allocation-free probe
    mov  [rsp + 4], edx
    mov  eax, [r12 + 30]
    mov  [rsp + 8], eax
    mov  eax, [r12 + 10]
    mov  [rsp + 12], eax
    mov  eax, [r12 + 34]
    mov  [rsp + 16], eax
    mov  eax, ecx
    imul rax, rdx
    shl  rax, 2
    mov  [rsp + 24], rax             ; canonical RGBA bytes
    cmp  rax, r13
    cmovb rax, r13
    mov  [rsp + 32], rax             ; first block fits both source and output
    lea  rdi, [rsp + 64]
    mov  rsi, r12
    mov  rdx, r13
    IMG_COLD_DIGEST
    IMG_COLD_HEAP_NOW
    mov  [rsp + 40], rax
    mov  rdi, [rsp + 32]
    IMG_COLD_HEAP_ALLOC
    test rax, rax
    jz   .oom
    mov  r14, rax
    IMG_COLD_HEAP_NOW
    mov  [rsp + 48], rax
    mov  rdi, r14
    mov  rsi, r12
    mov  rcx, r13
    IMG_COLD_MEMORY movsb
    lea  rdi, [rsp + 96]
    mov  rsi, r14
    mov  rdx, r13
    IMG_COLD_DIGEST
    lea  rdi, [rsp + 64]
    lea  rsi, [rsp + 96]
    mov  ecx, 32
    repe cmpsb
    jne  .changed
    mov  rdi, r14
    mov  rsi, r13
    call img_bmp_probe                ; qualify the private copy, not the caller
    test eax, eax
    jnz  .scratch_failure
    cmp  ecx, [rsp]
    jne  .changed
    cmp  edx, [rsp + 4]
    jne  .changed
    mov  eax, [r14 + 30]
    cmp  eax, [rsp + 8]
    jne  .changed
    mov  edi, [r14 + 10]
    cmp  edi, [rsp + 12]
    jne  .changed
    mov  esi, [r14 + 34]
    cmp  esi, [rsp + 16]
    jne  .changed
    add  rdi, r14
    mov  [rel img_active_src], rdi
    mov  [rel img_active_len], rsi
    cmp  dword [rsp + 8], 5
    je   .png
    call img_jpeg_decode
    mov  r9d, IMG_FMT_JPEG
    jmp  .decoded
.png:
    call img_png_decode
    mov  r9d, IMG_FMT_PNG
.decoded:
    test eax, eax
    jnz  .scratch_failure             ; native failure already releases its block
    cmp  r8d, r9d
    jne  .output_changed
    cmp  ecx, [rsp]
    jne  .output_changed
    cmp  edx, [rsp + 4]
    jne  .output_changed
    mov  rdi, r14
    mov  rsi, rbx
    mov  rcx, [rsp + 24]
    IMG_COLD_MEMORY movsb                       ; owned codec output -> first allocation
    call img_output_release          ; releases only the nested codec block
    cmp  qword [rel img_active_out], 0
    jne  .retire_failed               ; never publish over a contended release
    mov  [rel img_active_out], r14
    mov  rax, [rsp + 40]
    mov  [rel img_alloc_before], rax
    mov  rax, [rsp + 48]
    mov  [rel img_alloc_after], rax
    mov  rax, [rsp + 32]
    mov  [rel img_alloc_size], rax
    mov  rbx, r14
    mov  ecx, [rsp]
    mov  edx, [rsp + 4]
    mov  r8d, IMG_FMT_BMP
    xor  eax, eax
    jmp  .out
.retire_failed:
    mov  eax, IMG_E_OOM               ; canonical LIFO contention remains honest
    jmp  .scratch_failure
.output_changed:
    call img_output_release
.changed:
    mov  eax, IMG_E_CORRUPT
.scratch_failure:
    mov  ebp, eax
    mov  rdi, r14
%ifdef PAOS_IMG_COLD_WORK
    mov  rax, [rsp + 48]
    mov  rdx, [rsp + 40]
    call img_cold_heap_rewind
%else
    call kfree
    mov  rax, [rsp + 48]
    mov  rdx, [rsp + 40]
    lock cmpxchg [rel heap_next], rdx
%endif
    mov  eax, ebp
    call img_refusal_clear
    jmp  .out
.oom:
    mov  eax, IMG_E_OOM
    call img_refusal_clear
.out:
    add  rsp, 128
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    ret

; New extended Windows RLE profiles only. Public probe has bounded dimensions,
; source <=32MiB and its complete pointer span before entry. One allocation
; holds aligned RGBA followed by an immutable source copy. The original digest
; precedes allocation; compare the private digest before its full dry pass and
; write pass. All metadata, palette and stream reads after copying use R12.
img_bmp_extended_rle_decode:
    cld
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub  rsp, 80                     ; original/private SHA256 and RGBA aligned size
    mov  r12, rdi
    mov  r13, rsi
    mov  r14d, ecx
    mov  r15d, edx
    mov  ebp, r8d
    lea  rdi, [rsp]
    mov  rsi, r12
    mov  rdx, r13
    IMG_COLD_DIGEST
    mov  eax, r14d
    imul rax, r15
    shl  rax, 2
    add  rax, 15
    and  rax, -16
    mov  [rsp + 64], rax
    lea  rdi, [rax + r13]            ; <=16MiB aligned pixels +32MiB snapshot
    call img_output_alloc
    test rax, rax
    jz   .oom
    add  rax, [rsp + 64]
    mov  rdi, rax
    mov  rsi, r12
    mov  r12, rax                    ; from here only the private source is read
    mov  rcx, r13
    IMG_COLD_MEMORY movsb
    lea  rdi, [rsp + 32]
    mov  rsi, r12
    mov  rdx, r13
    IMG_COLD_DIGEST
    lea  rdi, [rsp]
    lea  rsi, [rsp + 32]
    mov  ecx, 32
    repe cmpsb
    jne  .changed
    mov  [rel img_active_src], r12
    mov  [rel img_active_len], r13
    mov  rdi, r12
    mov  rsi, r13
    call img_bmp_probe                ; full allocation-free private dry pass
    test eax, eax
    jnz  .changed
    cmp  ecx, r14d
    jne  .changed
    cmp  edx, r15d
    jne  .changed
    cmp  r8d, ebp
    jne  .changed
    mov  rdi, r12
    mov  rsi, r13
    mov  r9, [rel img_active_out]
    call img_bmp_rle8                 ; same private source and Windows grammar
    test eax, eax
    jnz  .changed
    mov  qword [rel img_active_src], 0
    mov  qword [rel img_active_len], 0
    call img_codec_state_clear
    mov  rbx, [rel img_active_out]
    mov  ecx, r14d
    mov  edx, r15d
    mov  r8d, IMG_FMT_BMP
    xor  eax, eax
    jmp  .out
.changed:
    call img_output_release          ; retire only the exact owned allocation
    mov  eax, IMG_E_CORRUPT
    jmp  .out
.oom:
    mov  eax, IMG_E_OOM
    call img_refusal_clear
.out:
    add  rsp, 80
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    ret

img_bmp_decode:
    IMG_COLD_PUBLIC_GUARD
    cld
    mov  rax, rdi
    add  rax, rsi
    jc   .ordinary
    cmp  rsi, 2
    jb   .ordinary
    cmp  word [rdi], 'BA'
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    je   img_bmp_array_decode
.ordinary:
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub  rsp, 128                    ; 32..95 masks; 96..120 Windows pins; 124 raw palette bound
    mov  r12, rdi                     ; source
    mov  r13, rsi                     ; source length
    call img_bmp_probe
    test eax, eax
    jnz  .out
    cmp  word [r12], 'BM'
    jne  .icon_decode
    cmp  dword [r12 + 14], 40
    je   .embedded_select
    cmp  dword [r12 + 14], 52
    je   .embedded_select
    cmp  dword [r12 + 14], 56
    je   .embedded_select
    cmp  dword [r12 + 14], 108
    je   .embedded_select
    cmp  dword [r12 + 14], 124
    jne  .legacy_decode
.embedded_select:
    cmp  dword [r12 + 30], 4
    je   .embedded_decode
    cmp  dword [r12 + 30], 5
    jne  .legacy_decode
.embedded_decode:
    mov  rdi, r12
    mov  rsi, r13
    call img_bmp_embedded_decode
    jmp  .out
.icon_decode:
    mov  rdi, r12
    mov  rsi, r13
    call img_bmp_icon_decode
    jmp  .out
.legacy_decode:
    cmp  dword [r12 + 14], 52
    je   .extended_rle_select
    cmp  dword [r12 + 14], 56
    je   .extended_rle_select
    cmp  dword [r12 + 14], 108
    je   .extended_rle_select
    cmp  dword [r12 + 14], 124
    jne  .legacy_pixels
.extended_rle_select:
    cmp  dword [r12 + 30], 1
    je   .extended_rle_decode
    cmp  dword [r12 + 30], 2
    jne  .legacy_pixels
.extended_rle_decode:
    mov  rdi, r12
    mov  rsi, r13
    call img_bmp_extended_rle_decode
    jmp  .out
.legacy_pixels:
    mov  r14d, ecx                    ; width
    mov  r15d, edx                    ; absolute height
    mov  ebp, r8d                     ; source bpp
    mov  eax, [r12 + 14]
    mov  [rsp + 4], eax              ; immutable CORE vs Windows row personality
    call img_bmp_os2_header
    jnc  .os2_pin
    cmp  eax, 40
    jne  .non_rle8_pins
    cmp  ebp, 8
    jne  .rle4_header_select
    cmp  dword [r12 + 30], 1
    je   .rle8_header_pins
    jmp  .header_pinned
.rle4_header_select:
    cmp  ebp, 4
    jne  .header_pinned
    cmp  dword [r12 + 30], 2
    je   .rle8_header_pins
    jmp  .header_pinned
.non_rle8_pins:
    cmp  eax, 52
    je   .inline_header_pins
    cmp  eax, 56
    je   .v3_header_pins
    cmp  eax, 108
    je   .extended_header_pins
    cmp  eax, 124
    jne  .header_pinned
.extended_header_pins:
    cmp  ebp, 32
    jne  .header_pinned
    cmp  dword [r12 + 30], 3
    jne  .header_pinned
    jmp  .inline_header_pins
.v3_header_pins:
    cmp  dword [r12 + 30], 3
    je   .inline_header_pins
    cmp  ebp, 16
    jne  .header_pinned
.inline_header_pins:
    mov  eax, [r12 + 54]
    mov  [rsp + 8], eax              ; selected canonical555/565/888 red mask
    mov  eax, [r12 + 22]
    mov  [rsp + 12], eax             ; signed orientation, not just absolute height
    mov  eax, [r12 + 10]
    mov  [rsp + 16], eax             ; exact selected pixel offset
    mov  eax, [r12 + 34]
    mov  [rsp + 20], eax             ; image length binds V2 span
    mov  eax, [r12 + 2]
    mov  [rsp + 24], eax             ; declared file bound
    mov  dword [rsp + 28], 0
    cmp  dword [rsp + 4], 52
    je   .inline_pins_done            ; V2 has NO alpha field
    mov  eax, [r12 + 66]
    mov  [rsp + 28], eax             ; selected opaque vs straight alpha mode
.inline_pins_done:
    mov  eax, [rsp + 4]              ; exact selected52/56 personality
    jmp  .header_pinned
.rle8_header_pins:
    mov  eax, [r12 + 46]
    mov  [rsp + 8], eax              ; exact selected palette count (including0)
    mov  eax, [r12 + 10]
    mov  [rsp + 12], eax             ; selected stream offset
    mov  eax, [r12 + 34]
    mov  [rsp + 16], eax             ; selected compressed length
    mov  eax, [r12 + 2]
    mov  [rsp + 20], eax             ; selected file extent
    mov  eax, [rsp + 4]
    jmp  .header_pinned
.os2_pin:
    mov  [rsp + 8], r10d             ; selected whole-stream literal grammar
    lea  rdi, [rsp + 32]
    mov  rsi, r12
    mov  rdx, r13
    IMG_COLD_DIGEST                 ; bounded original, before allocator callbacks
    test rax, rax
    jnz  .table_changed
    mov  eax, [rsp + 4]              ; retain actual short/full header personality
.header_pinned:
    mov  dword [rsp + 116], 0
    mov  eax, [rsp + 4]
    call img_bmp_os2_header
    jnc  .windows_pins_done          ; OS2 is already bound by its whole-source digest
    cmp  eax, 12
    je   .windows_pins_done          ; CORE uses its independent span helper
    cmp  ebp, 16
    jae  .windows_raw_pins
    cmp  dword [r12 + 30], 0
    jne  .windows_pins_done          ; indexed RLE retains its own stream grammar
.windows_raw_pins:
    mov  dword [rsp + 116], 1        ; every selected Windows raw personality
    mov  eax, [r12 + 10]
    mov  [rsp + 96], eax             ; selected pixel offset before allocator callbacks
    mov  eax, [r12 + 22]
    mov  [rsp + 100], eax            ; signed row orientation
    mov  eax, [r12 + 34]
    mov  [rsp + 104], eax            ; selected image/file bounds
    mov  eax, [r12 + 2]
    mov  [rsp + 108], eax
    mov  eax, [r12 + 26]
    mov  [rsp + 112], eax            ; planes and source depth
    cmp  ebp, 8
    ja   .windows_pins_done
    mov  eax, [r12 + 46]
    mov  [rsp + 120], eax            ; selected indexed palette count, including0
.windows_pins_done:
    mov  eax, [rsp + 4]
    cmp  eax, 12
    je   .core_codec
    cmp  eax, 20
    jb   .short_codec               ; do not read palette/pixels as compression
    mov  eax, [r12 + 30]
    jmp  .save_codec
.core_codec:
    mov  eax, -1                     ; CORE has no compression field
    jmp  .save_codec
.short_codec:
    xor  eax, eax
.save_codec:
    mov  [rsp], eax                   ; retain selected codec across allocation
    mov  eax, [rsp + 4]
    call img_bmp_os2_header
    mov  eax, [rsp]                  ; MOV retains the header predicate carry
    jnc  .table_ready                ; OS2 codec3 is Huffman, never Windows masks
    cmp  eax, 3
    je   .mask_table
    cmp  eax, 6
    jne  .table_ready
.mask_table:
    ; General masks: the pinned codec selects the private table, built from one
    ; read of the masks and validated again here, before allocation.
    cmp  ebp, 16
    je   .mask_depth
    cmp  ebp, 32
    jne  .table_changed               ; bitfields only at the probe's 16/32 depth
.mask_depth:
    cmp  r13, 70
    jb   .table_changed               ; every mask byte read below is in the source
    mov  rdi, r12
    mov  r8d, ebp
    push rcx                          ; [rsp + 8] = the pinned codec below
    xor  ecx, ecx
    cmp  dword [rsp + 8], 6
    je   .table_alpha
    cmp  dword [rsp + 12], 56
    jb   .table_alpha_known           ; the pinned 40/52 DIB has no alpha field
.table_alpha:
    mov  ecx, 1
.table_alpha_known:
    lea  r9, [rsp + 40]
    call img_bmp_mask_table
    pop  rcx
    test eax, eax
    jnz  .out                         ; nothing allocated yet
    jmp  .table_ready
.table_changed:
    mov  eax, IMG_E_CORRUPT
    jmp  .out
.table_ready:
    mov  eax, r14d
    imul rax, r15
    shl  rax, 2
    mov  rdi, rax
    call img_output_alloc
    mov  edx, [rsp]
    test rax, rax
    jz   .oom
    mov  r11, rax                     ; output base
    mov  eax, [rsp + 4]
    call img_bmp_os2_header
    jnc  .os2_recheck
    cmp  edx, -1
    je   .core_decode
    cmp  edx, 1
    je   .rle_decode
    cmp  edx, 2
    jne  .raw_rows
.rle_decode:
    cmp  dword [r12 + 14], 40
    jne  .v2_changed
    mov  eax, [rsp + 8]
    cmp  [r12 + 46], eax
    jne  .v2_changed                ; do not switch palette selection
    mov  eax, [rsp + 12]
    cmp  [r12 + 10], eax
    jne  .v2_changed
    mov  eax, [rsp + 16]
    cmp  [r12 + 34], eax
    jne  .v2_changed
    mov  eax, [rsp + 20]
    cmp  [r12 + 2], eax
    jne  .v2_changed                ; selected sparse stream span stays exact
.rle_current:
    mov  rdi, r12
    mov  rsi, r13
    mov  ecx, r14d
    mov  edx, r15d
    mov  r8d, ebp                    ; immutable selected depth binds RLE codec
    mov  r9, r11
    call img_bmp_rle8                 ; identical grammar, now writes pixels
    test eax, eax
    jz   .success
    sub  rsp, 16
    mov  [rsp], eax                   ; source changed since validation: refuse
    call img_output_release          ; existing exactly-one allocation seam
    mov  eax, [rsp]
    add  rsp, 16
    jmp  .out
.os2_recheck:
    push r11
    sub  rsp, 8
    lea  rdi, [rsp + 80]             ; original frame64..95, disjoint digest
    mov  rsi, r12
    mov  rdx, r13
    IMG_COLD_DIGEST
    add  rsp, 8
    pop  r11
    test rax, rax
    jnz  .v2_changed
    xor  ecx, ecx
.os2_digest:
    mov  rax, [rsp + rcx + 32]
    cmp  rax, [rsp + rcx + 64]
    jne  .v2_changed                 ; header, palette, gap AND pixels stay bound
    add  ecx, 8
    cmp  ecx, 32
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jb   .os2_digest
    push r11
    sub  rsp, 8
    mov  rdi, r12
    mov  rsi, r13
    call img_bmp_probe               ; no partial output before full current lint
    add  rsp, 8
    pop  r11
    test eax, eax
    jnz  .v2_refuse
    cmp  ecx, r14d
    jne  .v2_changed
    cmp  edx, r15d
    jne  .v2_changed
    cmp  r8d, ebp
    jne  .v2_changed
    cmp  dword [rsp], 0
    je   .raw_prepare
    cmp  dword [rsp], 3
    je   .os2_huffman
    cmp  dword [rsp], 4
    jne  .os2_rle48
    cmp  r10d, [rsp + 8]
    jne  .v2_changed
    mov  rdi, r12
    mov  rsi, r13
    mov  r9, r11
    call img_bmp_os2_rle24
    test eax, eax
    jnz  .v2_refuse
    jmp  .success
.os2_huffman:
    mov  rdi, r12
    mov  rsi, r13
    mov  r9, r11
    call img_bmp_os2_huffman          ; identical dry/write grammar after SHA + re-probe
    test eax, eax
    jnz  .v2_refuse
    jmp  .success
.os2_rle48:
    mov  rdi, r12
    mov  rsi, r13
    mov  r9, r11
    call img_bmp_rle8                ; same fully qualified OS2 stream as dry pass
    test eax, eax
    jnz  .v2_refuse
    jmp  .success
.core_decode:
    mov  rdi, r12
    mov  rsi, r13
    call img_bmp_core24_span          ; same complete span after allocation
    test eax, eax
    jnz  .core_refuse
    cmp  ecx, r14d
    jne  .core_changed
    cmp  edx, r15d
    jne  .core_changed
    cmp  r8d, ebp
    jne  .core_changed               ; original CORE depth cannot change
    ; CORE enters .row directly with its qualified stride/offset. Initialize
    ; the same complete-table bound used by the shared indexed pixel loop.
    mov  ecx, ebp
    mov  eax, 1
    shl  eax, cl
    mov  [rsp + 124], eax            ; CORE has no partial palette/count field
    mov  rax, r10                    ; qualified file pixel offset
    mov  r10, r9                     ; qualified DWORD stride
    mov  r9, rax
    add  r9, r12
    xor  r8d, r8d
    jmp  .row                        ; reuse bounded raw24 conversion
.core_changed:
    mov  eax, IMG_E_CORRUPT
.core_refuse:
    sub  rsp, 16
    mov  [rsp], eax
    call img_output_release          ; CORE second-pass owned refusal
    mov  eax, [rsp]
    add  rsp, 16
    jmp  .out
.raw_rows:
    cmp  dword [rsp + 116], 0
    je   .windows_bound
    ; The probe selected this exact Windows raw row span. A callback must not
    ; redirect it, even to another independently valid BMP selection. Refuse
    ; before any pixel write and release the one owned output allocation.
    cmp  word [r12], 'BM'
    jne  .v2_changed
    mov  eax, [rsp + 4]
    cmp  [r12 + 14], eax
    jne  .v2_changed
    mov  eax, [rsp]
    cmp  [r12 + 30], eax
    jne  .v2_changed
    cmp  [r12 + 18], r14d
    jne  .v2_changed
    mov  eax, [rsp + 96]
    cmp  [r12 + 10], eax
    jne  .v2_changed
    mov  eax, [rsp + 100]
    cmp  [r12 + 22], eax
    jne  .v2_changed
    mov  eax, [rsp + 104]
    cmp  [r12 + 34], eax
    jne  .v2_changed
    mov  eax, [rsp + 108]
    cmp  [r12 + 2], eax
    jne  .v2_changed
    mov  eax, [rsp + 112]
    cmp  [r12 + 26], eax
    jne  .v2_changed
    cmp  ebp, 8
    ja   .windows_bound
    mov  eax, [rsp + 120]
    cmp  [r12 + 46], eax
    jne  .v2_changed
    jmp  .inline_reprobe             ; qualify all current visible palette indexes
.windows_bound:
    mov  eax, [rsp]
    cmp  eax, 3
    je   .mask_recheck
    cmp  eax, 6
    jne  .raw_select
.mask_recheck:
    ; The private table decodes; a source codec, DIB size, depth or mask that
    ; changed since it was taken refuses and releases (R13 >= 70 proved).
    mov  eax, [rsp]
    cmp  [r12 + 30], eax
    jne  .v2_changed
    mov  eax, [rsp + 4]
    cmp  [r12 + 14], eax
    jne  .v2_changed
    cmp  word [r12 + 28], bp          ; the table's depth
    jne  .v2_changed
    mov  eax, [rsp + 32]
    cmp  [r12 + 54], eax
    jne  .v2_changed
    mov  eax, [rsp + 48]
    cmp  [r12 + 58], eax
    jne  .v2_changed
    mov  eax, [rsp + 64]
    cmp  [r12 + 62], eax
    jne  .v2_changed
    cmp  dword [rsp], 6
    je   .alpha_recheck
    cmp  dword [rsp + 4], 56
    jb   .raw_select                  ; 40/52: the table holds no alpha field
.alpha_recheck:
    mov  eax, [rsp + 80]
    cmp  [r12 + 66], eax
    jne  .v2_changed
.raw_select:
    cmp  dword [rsp + 4], 52
    je   .inline_recheck
    cmp  dword [rsp + 4], 56
    je   .v3_recheck
    cmp  dword [rsp + 4], 108
    je   .extended_recheck
    cmp  dword [rsp + 4], 124
    jne  .raw_prepare
.extended_recheck:
    cmp  ebp, 32
    jne  .raw_prepare
    cmp  dword [rsp], 3
    je   .inline_recheck
    jmp  .raw_prepare
.v3_recheck:
    cmp  dword [rsp], 3
    je   .inline_recheck
    cmp  ebp, 16
    jne  .raw_prepare               ; historical RGB24/32 retains old path
.inline_recheck:
    mov  eax, [rsp + 4]
    cmp  [r12 + 14], eax
    jne  .v2_changed                 ; do not switch header personality
    mov  eax, [rsp]
    cmp  [r12 + 30], eax             ; exact selected RGB or bitfield codec
    jne  .v2_changed
    cmp  word [r12 + 28], bp
    jne  .v2_changed
    mov  eax, [rsp + 8]
    cmp  [r12 + 54], eax
    jne  .v2_changed                 ; canonical mask kind remains selected
    cmp  dword [rsp + 4], 52
    je   .inline_alpha_bound          ; no out-of-header V2 alpha read
    mov  eax, [rsp + 28]
    cmp  [r12 + 66], eax
    jne  .v2_changed                 ; selected straight/opaque alpha cannot switch
.inline_alpha_bound:
    mov  eax, [rsp + 12]
    cmp  [r12 + 22], eax
    jne  .v2_changed
    mov  eax, [rsp + 16]
    cmp  [r12 + 10], eax
    jne  .v2_changed
    mov  eax, [rsp + 20]
    cmp  [r12 + 34], eax
    jne  .v2_changed
    mov  eax, [rsp + 24]
    cmp  [r12 + 2], eax
    jne  .v2_changed
.inline_reprobe:
    push r11
    sub  rsp, 8
    mov  rdi, r12
    mov  rsi, r13
    call img_bmp_probe               ; full current header/geometry/span/index recheck
    add  rsp, 8
    pop  r11                        ; original owned output, never probe scratch
    test eax, eax
    jnz  .v2_refuse
    cmp  ecx, r14d
    jne  .v2_changed
    cmp  edx, r15d
    jne  .v2_changed
    cmp  r8d, ebp
    jne  .v2_changed
    jmp  .raw_prepare
.raw_palette_refuse:
.v2_changed:
    mov  eax, IMG_E_CORRUPT
.v2_refuse:
    sub  rsp, 16
    mov  [rsp], eax
    call img_output_release          ; V2 second-pass exactly owned refusal
    mov  eax, [rsp]
    add  rsp, 16
    jmp  .out
.raw_prepare:
    ; Probe/reprobe has qualified the complete nonempty palette. Normalize its
    ; count once, without reading omitted CORE/short OS2 fields. Windows keeps
    ; its pre-allocation count pin; OS2 is bound by the whole-source digest.
    cmp  ebp, 8
    ja   .raw_palette_done
    mov  ecx, ebp
    mov  eax, 1
    shl  eax, cl
    mov  [rsp + 124], eax            ; full depth table when count is omitted/zero
    cmp  dword [rsp + 4], 36
    jb   .raw_palette_done          ; CORE12 and short OS2 have no clrUsed field
    cmp  dword [rsp + 116], 0
    je   .raw_palette_source
    mov  edx, [rsp + 120]            ; selected Windows count (including default0)
    jmp  .raw_palette_used
.raw_palette_source:
    mov  edx, [r12 + 46]             ; present OS2 count, source already requalified
.raw_palette_used:
    test edx, edx
    cmovz edx, eax
    mov  [rsp + 124], edx
.raw_palette_done:
    mov  eax, r14d
    imul eax, ebp
    add  eax, 31
    shr  eax, 5
    shl  eax, 2
    mov  r10d, eax                    ; source stride
    mov  r9d, [r12 + 10]              ; pixel offset
    cmp  dword [rsp + 116], 0
    je   .row_offset_ready
    mov  r9d, [rsp + 96]              ; Windows true-color uses the original qualified offset
.row_offset_ready:
    add  r9, r12                      ; first file row
    xor  r8d, r8d                     ; output y
.row:
    cmp  r8d, r15d
    jae  .success
    mov  eax, r8d
    cmp  dword [rsp + 4], 12
    je   .bottom_row                 ; CORE never reads Windows height
    cmp  dword [rsp + 116], 0
    je   .live_orientation
    cmp  dword [rsp + 100], 0         ; Windows true-color uses the original signed height
    jmp  .orientation_ready
.live_orientation:
    cmp  dword [r12 + 22], 0
.orientation_ready:
    jl   .row_index_ok                 ; negative height is already top-down
.bottom_row:
    mov  eax, r15d
    dec  eax
    sub  eax, r8d                     ; positive height is bottom-up
.row_index_ok:
    imul eax, r10d
    lea  rsi, [r9 + rax]
    mov  eax, r8d
    imul eax, r14d
    shl  eax, 2
    lea  rdi, [r11 + rax]
    xor  ecx, ecx
.pixel:
    cmp  ecx, r14d
    jae  .next_row
    cmp  ebp, 8
    jbe  .palette_pixel
    cmp  dword [rsp], 3
    je   .pixel_masked                ; pinned BI_BITFIELDS: private mask table
    cmp  dword [rsp], 6
    je   .pixel_masked                ; pinned BI_ALPHABITFIELDS likewise
    cmp  ebp, 16
    je   .pixel16
    movzx eax, byte [rsi + 2]
    mov  [rdi], al                    ; R
    movzx eax, byte [rsi + 1]
    mov  [rdi + 1], al                ; G
    movzx eax, byte [rsi]
    mov  [rdi + 2], al                ; B
    mov  byte [rdi + 3], 0xFF
    cmp  ebp, 32
    jne  .pixel_next
    movzx eax, byte [rsi + 3]
    mov  [rdi + 3], al                ; BI_RGB32 copies its alpha verbatim
    jmp  .pixel_next
.pixel_masked:
    lea  rbx, [rsp + 32]              ; R G B A entries, 16 bytes each
    movzx edx, word [rsi]             ; 16 bpp: two bytes (the last pixel may end the source)
    cmp  ebp, 32
    jne  .masked_channels             ; the table admitted only 16/32
    mov  edx, [rsi]                   ; 32 bpp: four pixel bytes in the row
.masked_channels:
    call img_bmp_mask_channel
    mov  [rdi], al
    add  rbx, 16
    call img_bmp_mask_channel
    mov  [rdi + 1], al
    add  rbx, 16
    call img_bmp_mask_channel
    mov  [rdi + 2], al
    add  rbx, 16
    call img_bmp_mask_channel         ; zero alpha mask -> 255
    mov  [rdi + 3], al
    jmp  .pixel_next
.palette_pixel:
    call img_bmp_index
    xor  edx, edx
    cmp  eax, [rsp + 124]
    cmovae eax, edx                  ; refused index selects validated palette[0]
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jae  .raw_palette_refuse         ; retain unsigned refusal and CMP flags
    cmp  dword [rsp + 4], 12
    je   .core_palette_pixel         ; no RGBQUAD or clrUsed field on CORE
    mov  edx, [r12 + 14]             ; qualified Windows/OS2 DIB, then RGBQUAD/RGB2
    cmp  dword [rsp + 116], 0
    je   .palette_base
    mov  edx, [rsp + 4]              ; retain selected Windows palette base
.palette_base:
    lea  rdx, [r12 + rdx + 14]
    mov  eax, [rdx + rax * 4]         ; bounded selected index within complete palette
    bswap eax
    shr  eax, 8                      ; BGR-reserved -> RGBA, ignore reserved
    or   eax, 0xff000000
    mov  [rdi], eax
    jmp  .output_next                  ; RSI remains the packed row base
.core_palette_pixel:
    lea  rdx, [rax + rax*2]
    lea  rdx, [r12 + rdx + 26]        ; exactly three palette bytes per index
    movzx eax, byte [rdx + 2]
    mov  [rdi], al
    movzx eax, byte [rdx + 1]
    mov  [rdi + 1], al
    movzx eax, byte [rdx]
    mov  [rdi + 2], al
    mov  byte [rdi + 3], 0xff
    jmp  .output_next
.pixel16:
    movzx edx, word [rsi]             ; BI_RGB16: default 5:5:5, bit 15 ignored
    mov  eax, edx
    shr  eax, 10
    and  eax, 31
    mov  ebx, 31
    call img_bmp_expand_channel
    mov  [rdi], al
    mov  eax, edx
    shr  eax, 5
    and  eax, 31
    call img_bmp_expand_channel
    mov  [rdi + 1], al
    mov  eax, edx
    and  eax, 31
    mov  ebx, 31
    call img_bmp_expand_channel
    mov  [rdi + 2], al
    mov  byte [rdi + 3], 0xff
.pixel_next:
    mov  eax, ebp
    shr  eax, 3
    add  rsi, rax
.output_next:
    add  rdi, 4
    inc  ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .pixel
.next_row:
    inc  r8d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .row
.success:
    mov  eax, [rsp + 4]
    call img_bmp_os2_header
    jc   .publish
    mov  qword [rel img_active_src], 0
    mov  qword [rel img_active_len], 0
.publish:
    mov  rbx, r11
    mov  ecx, r14d
    mov  edx, r15d
    mov  r8d, IMG_FMT_BMP
    xor  eax, eax
    jmp  .out
.oom:
    mov  eax, IMG_E_OOM
.out:
    add  rsp, 128
    pop  rbp
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    ret

; Pure private CORE span, also rechecked after allocation. Retain private symbol.
; EAX=status; ECX/EDX=unsigned width/height, R8D=depth, R9=stride, R10=file offset.
; R11 (owned output base in decode) and callee-saved registers are untouched.
img_bmp_core24_span:
    xor  eax, eax
img_bmp_core24_span_bias:
    push rbp
    mov  rbp, rax
    cmp  rsi, 26
    jb   .truncated                 ; complete file+CORE before any field read
    mov  rax, rdi
    add  rax, 26
    jc   .bounds
    cmp  word [rdi], 'BM'
    jne  .bad_magic
    cmp  dword [rdi + 14], 12
    jne  .unsupported
    cmp  word [rdi + 22], 1
    jne  .unsupported
    movzx r8d, word [rdi + 24]        ; exact CORE depth
    cmp  r8d, 24
    je   .depth_ok
    cmp  r8d, 1
    je   .depth_ok
    cmp  r8d, 4
    je   .depth_ok
    cmp  r8d, 8
    jne  .unsupported
.depth_ok:
    movzx ecx, word [rdi + 18]
    movzx edx, word [rdi + 20]
    test ecx, ecx
    jz   .bounds
    test edx, edx
    jz   .bounds
    cmp  rcx, IMG_MAX_DIM
    ja   .bounds
    cmp  rdx, IMG_MAX_DIM
    ja   .bounds
    mov  rax, rcx
    imul rax, rdx
    jo   .bounds
    cmp  rax, IMG_MAX_PIXELS
    ja   .bounds
    ; Full-width DWORD row stride and complete pixel extent, not CORE padding
    ; interpreted as a Windows biSizeImage/compression/height/bitdepth field.
    cmp  r8d, 24
    jne  .packed_stride
    imul r9, rcx, 3
    add  r9, 3
    jc   .bounds
    and  r9, -4
    jmp  .row_span
.packed_stride:
    mov  r9, rcx
    imul r9, r8
    add  r9, 31
    jc   .bounds
    shr  r9, 5
    shl  r9, 2                      ; CORE packed DWORD stride
.row_span:
    mov  rax, r9
    imul rax, rdx
    jo   .bounds
    mov  r10d, [rdi + 10]
    sub  r10, rbp
    jc   .truncated
    cmp  r10, 26
    jb   .truncated
    cmp  r8d, 24
    je   .palette_span
    push rax
    push rcx
    mov  ecx, r8d
    mov  eax, 1
    shl  eax, cl
    lea  rax, [rax + rax*2 + 26]     ; full2^bpp CORE triples before pixels
    cmp  r10, rax
    pop  rcx
    pop  rax
    jb   .unsupported               ; incomplete/overlapping CORE palette
.palette_span:
    add  rax, r10
    jc   .bounds
    cmp  rax, rsi
    ja   .truncated
    test rbp, rbp
    jz   .ordinary_extent
    cmp  dword [rdi + 2], 26         ; IBM CORE structure size in arrays
    jne  .truncated
    cmp  rax, rsi
    jne  .truncated
    jmp  .pointer_extent
.ordinary_extent:
    mov  r8d, [rdi + 2]              ; bfSize bounds, not exact stream equality
    cmp  r8, rsi
    ja   .truncated
    cmp  rax, r8
    ja   .truncated
.pointer_extent:
    add  rax, rdi
    jc   .bounds                     ; pointer extent before decode dereference
    movzx r8d, word [rdi + 24]
    xor  eax, eax
    pop  rbp
    ret
.bad_magic:
    mov  eax, IMG_E_BAD_MAGIC
    pop  rbp
    ret
.unsupported:
    mov  eax, IMG_E_UNSUPPORTED
    pop  rbp
    ret
.truncated:
    mov  eax, IMG_E_TRUNCATED
    pop  rbp
    ret
.bounds:
    mov  eax, IMG_E_BOUNDS
    pop  rbp
    ret

; EAX=5/6-bit channel, EBX=31/63 -> floor(channel*255/max), RAX clobbered.
img_bmp_expand_channel:
    push rdx
    imul eax, eax, 255
    xor  edx, edx
    div  ebx
    pop  rdx
    ret

; Private shared Windows40/52/56/108/124 and OS2 RLE pass: RDI=file, ECX=width, EDX=height,
; R8D=selected4/8bpp. OS2 caller also qualifies its extended metadata and cap.
; R9=output or0 for lint. The retained private symbol also handles RLE4.
; Caller has qualified complete header/palette and geometry. Recheck current
; type/geometry/palette/span before reads in each pass, including after alloc.
; Both passes use these same source/cursor/index/EOL/EOB checks. EAX=status;
; all other registers preserved. No persistent state, allocation or I/O.
img_bmp_rle8:
    xor  eax, eax
img_bmp_rle8_bias:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    push rdi
    push rsi
    sub  rsp, 24                    ; palette pointer, header personality, BA bias
    mov  [rsp + 16], rax
    mov  r12, rdi
    cmp  rsi, 38
    jb   .bad
    cmp  word [r12], 'BM'
    jne  .bad
    mov  eax, [r12 + 14]
    mov  [rsp + 8], eax
    cmp  eax, 40
    je   .header
    cmp  eax, 52
    je   .windows_header
    cmp  eax, 56
    je   .windows_header
    cmp  eax, 108
    je   .windows_header
    cmp  eax, 124
    je   .windows_header
    call img_bmp_os2_header
    jc   .bad
    cmp  eax, 24
    jb   .bad                       ; compression and cbImage must both be present
    jmp  .header
.windows_header:
    mov  dword [rsp + 8], 40         ; Windows grammar; RAX retains actual palette offset
.header:
    lea  r10, [rax + 14]
    cmp  rsi, r10
    jb   .bad
    lea  rax, [r12 + rax + 14]
    mov  [rsp], rax                 ; RGBQUAD/RGB2 base at the actual complete DIB size
    cmp  r8d, 4
    je   .codec
    cmp  r8d, 8
    jne  .bad
.codec:
    cmp  word [r12 + 28], r8w
    jne  .bad
    mov  edi, r8d                    ; selected4/8, separate from row cursor R8D
    cmp  word [r12 + 26], 1
    jne  .bad
    mov  eax, 1
    cmp  edi, 8
    je   .compression
    inc  eax                        ; RLE4 depth must still bind compression2
.compression:
    cmp  dword [r12 + 30], eax
    jne  .bad
    cmp  ecx, [r12 + 18]
    jne  .bad
    cmp  edx, [r12 + 22]
    jne  .bad
    mov  ebp, ecx                    ; qualified positive width
    mov  ebx, edx                    ; rows not yet terminated by EOL
    mov  r13d, [r12 + 10]
    sub  r13, [rsp + 16]
    jc   .bad
    mov  r14d, [r12 + 34]
    test r14d, r14d
    jz   .bad
    xor  r15d, r15d
    cmp  dword [rsp + 8], 36
    jb   .default_palette           ; omitted count defaults to full depth table
    mov  r15d, [r12 + 46]
.default_palette:
    mov  ecx, edi
    mov  eax, 1
    shl  eax, cl
    cmp  r15d, eax
    ja   .bad
    test r15d, r15d
    jnz  .palette_count
    mov  r15d, eax
.palette_count:
    mov  rax, [rsp]
    sub  rax, r12
    lea  rax, [rax + r15*4]
    cmp  r13, rax
    jb   .bad                       ; current complete palette before stream
    mov  rax, r13
    add  rax, r14
    cmp  rax, rsi
    ja   .bad
    cmp  dword [rsp + 8], 40
    je   .windows_extent
    cmp  rax, rsi
    jne  .bad                       ; exact caller span, including IBM cbSize78
    cmp  dword [r12 + 2], 78
    je   .extent_ready
.windows_extent:
    mov  r10d, [r12 + 2]
    cmp  rax, r10
    jne  .bad                       ; full-width declared extent, no32-bit wrap
.extent_ready:
    mov  eax, ebp
    imul rax, rbx
    add  rax, rbx
    lea  rax, [rax*2 + 2]
    cmp  r14, rax
    ja   .bad                       ; same finite stream/pixel bound in both passes
    add  r13, r12                    ; current compressed token
    jc   .bad
    add  r14, r13                    ; exact declared stream end
    jc   .bad
    xor  r8d, r8d                    ; pixels in current row
    test r9, r9
    jz   .token
    ; Only after current type/geometry/palette/span qualification above.
    ; Every owned pixel is initialized; palette0 need not be black.
    mov  rax, [rsp]
    mov  eax, [rax]
    bswap eax
    shr  eax, 8
    or   eax, 0xff000000
    mov  rdx, r9
    mov  ecx, ebp
    imul ecx, ebx                   ; caller's retained IMG_MAX_PIXELS bound
.background:
    mov  [rdx], eax
    add  rdx, 4
    dec  ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jnz  .background
.bottom_output:
    mov  eax, ebx
    dec  eax
    imul eax, ebp
    lea  r9, [r9 + rax*4]            ; first stream row is bottom output row
.token:
    mov  rax, r14
    sub  rax, r13
    cmp  rax, 2
    jb   .bad                       ; complete count/escape pair before read
    movzx ecx, byte [r13]
    movzx esi, byte [r13 + 1]
    add  r13, 2
    xor  r11d, r11d                 ; encoded run unless literal escape
    test ecx, ecx
    jnz  .run
    test esi, esi
    jz   .eol
    cmp  esi, 1
    je   .eob
    cmp  esi, 2
    je   .delta                     ; selected RLE4/8 share forward cursor grammar
    mov  ecx, esi                   ; absolute count3..255
    mov  r11d, 1
    mov  edx, ecx
    cmp  edi, 8
    je   .literal_bytes
    inc  edx
    shr  edx, 1                     ; RLE4 ceil(pixels/2), never floor
.literal_bytes:
    mov  eax, edx                   ; run byte length, never absolute file offset
    and  eax, 1
    add  eax, edx                   ; include odd word-alignment padding
    mov  r10, r14
    sub  r10, r13
    cmp  rax, r10
    ja   .bad                       ; all literals/pad before any literal read
    cmp  dword [rsp + 8], 40
    je   .run
    test dl, 1
    jz   .run
    cmp  byte [r13 + rdx], 0         ; IBM specifies zero padding for OS2
    jne  .bad
.run:
    test ebx, ebx
    jz   .bad
    mov  eax, ebp
    sub  eax, r8d
    cmp  ecx, eax
    ja   .bad                       ; no run may cross the complete row
    mov  r10d, ecx
.pixel:
    mov  edx, esi
    test r11d, r11d
    jz   .encoded_pixel
    movzx edx, byte [r13]
    cmp  edi, 4
    je   .literal_nibble
    inc  r13
    jmp  .index
.literal_nibble:
    mov  eax, ecx
    sub  eax, r10d                   ; nibble parity is within this run
    test al, 1
    jnz  .literal_low
    shr  edx, 4
    cmp  r10d, 1
    jne  .index
    inc  r13                        ; consume final odd byte, unused low ignored
    jmp  .index
.literal_low:
    and  edx, 15
    inc  r13
    jmp  .index
.encoded_pixel:
    cmp  edi, 4
    jne  .index
    mov  eax, ecx
    sub  eax, r10d
    test al, 1
    jnz  .encoded_low
    shr  edx, 4                     ; first/high, then low, alternating per run
    jmp  .index
.encoded_low:
    and  edx, 15
.index:
    xor  eax, eax
    cmp  edx, r15d
    cmovae edx, eax                  ; refused index selects validated palette[0]
    jae  .bad                       ; retain unsigned refusal and CMP flags
    test r9, r9
    jz   .advance
    mov  rax, [rsp]
    mov  eax, [rax + rdx*4]
    bswap eax
    shr  eax, 8
    or   eax, 0xff000000             ; RGBQUAD reserved byte is not alpha
    mov  [r9], eax
    add  r9, 4
.advance:
    inc  r8d
    dec  r10d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jnz  .pixel
    test r11d, r11d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jz   .token
    mov  eax, ecx
    cmp  edi, 8
    je   .literal_end_parity
    inc  eax
    shr  eax, 1                     ; RLE4 packed bytes, including odd last nibble
.literal_end_parity:
    test al, 1
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jz   .token
    inc  r13                        ; odd literal padding already qualified
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .token
.delta:
    mov  rax, r14
    sub  rax, r13
    cmp  rax, 2
    jb   .bad                       ; complete unsigned dx/dy before read
    movzx ecx, byte [r13]
    movzx eax, byte [r13 + 1]
    add  r13, 2
    mov  edx, ecx
    or   edx, eax
    jnz  .delta_progress
    cmp  dword [rsp + 8], 40
    je   .bad                       ; retain Windows finite cursor policy
    ; OS2 zero delta consumes four source bytes; the finite work cap still holds.
.delta_progress:
    test ebx, ebx
    jz   .bad
    add  ecx, r8d
    jc   .bad
    cmp  ecx, ebp
    ja   .bad                       ; target x may equal width, never exceed
    cmp  eax, ebx
    jae  .bad                       ; target row must remain inside image
    test r9, r9
    jz   .delta_cursor
    mov  edx, eax
    imul rdx, rbp
    shl  rdx, 2
    sub  r9, rdx                    ; positive dy moves up in top-down output
    mov  edx, ecx
    sub  edx, r8d
    lea  r9, [r9 + rdx*4]            ; positive dx moves right, no row wrap
.delta_cursor:
    sub  ebx, eax
    mov  r8d, ecx
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .token
.eol:
    test ebx, ebx
    jz   .bad
.eol_qualified:
    dec  ebx
    test ebx, ebx
    jz   .eol_reset                  ; optional final EOL, EOB must follow
    test r9, r9
    jz   .eol_reset
    mov  eax, ebp
    add  eax, r8d
    shl  eax, 2
    sub  r9, rax                    ; current x to start of preceding row
.eol_reset:
    xor  r8d, r8d
    IMG_COLD_STEP                    ; bounded loop backedge, flags preserved
    jmp  .token
.eob:
    cmp  r13, r14
    jne  .bad                       ; no unchecked compressed trailing bytes
    ; Both selected codecs may end early: every owned pixel was initialized.
.done:
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, IMG_E_CORRUPT
.out:
    add  rsp, 24
    pop  rsi
    pop  rdi
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

%include "gui/img/img_bmp_icon.inc"
