; Embedded fixture catalog. Runtime pointer population mirrors forms_table.inc:
; static dq-symbol initializers would be RVAs, not runtime VAs in this PE image.
IMG_ASSET_COUNT equ 11
IMG_ASSET_NAME  equ 0
IMG_ASSET_PTR   equ 8
IMG_ASSET_LEN   equ 16
IMG_ASSET_ENTSZ equ 24

%macro EMBED_IMG 2
img_blob_%1:
    incbin "gui/img/assets/%2"
img_blob_%1_end:
%endmacro

EMBED_IMG kat_quad16, kat_quad16.bmp
EMBED_IMG kat_grad12, kat_grad12.bmp
EMBED_IMG kat_grad48, kat_grad48.png
EMBED_IMG kat_alpha16, kat_alpha16.png
EMBED_IMG kat_photo444, kat_photo444.jpg
EMBED_IMG kat_photo420, kat_photo420.jpg
EMBED_IMG bad_magic, bad_magic.bin
EMBED_IMG bad_trunc, bad_trunc.png
EMBED_IMG bad_crc, bad_crc.png
EMBED_IMG bad_huff, bad_huff.jpg
EMBED_IMG bad_hugedim, bad_hugedim.bmp

img_assets_init:
%macro IMG_ROW 2
    lea  rax, [rel img_name_%1]
    mov  [rel img_assets + (%2 * IMG_ASSET_ENTSZ) + IMG_ASSET_NAME], rax
    lea  rax, [rel img_blob_%1]
    mov  [rel img_assets + (%2 * IMG_ASSET_ENTSZ) + IMG_ASSET_PTR], rax
    mov  qword [rel img_assets + (%2 * IMG_ASSET_ENTSZ) + IMG_ASSET_LEN], img_blob_%1_end - img_blob_%1
%endmacro
    IMG_ROW kat_quad16,    0
    IMG_ROW kat_grad12,    1
    IMG_ROW kat_grad48,    2
    IMG_ROW kat_alpha16,   3
    IMG_ROW kat_photo444,  4
    IMG_ROW kat_photo420,  5
    IMG_ROW bad_magic,     6
    IMG_ROW bad_trunc,     7
    IMG_ROW bad_crc,       8
    IMG_ROW bad_huff,      9
    IMG_ROW bad_hugedim,  10
    ret

img_name_kat_quad16:   db "kat_quad16.bmp",0
img_name_kat_grad12:   db "kat_grad12.bmp",0
img_name_kat_grad48:   db "kat_grad48.png",0
img_name_kat_alpha16:  db "kat_alpha16.png",0
img_name_kat_photo444: db "kat_photo444.jpg",0
img_name_kat_photo420: db "kat_photo420.jpg",0
img_name_bad_magic:    db "bad_magic.bin",0
img_name_bad_trunc:    db "bad_trunc.png",0
img_name_bad_crc:      db "bad_crc.png",0
img_name_bad_huff:     db "bad_huff.jpg",0
img_name_bad_hugedim:  db "bad_hugedim.bmp",0
align 8
img_assets: times (IMG_ASSET_COUNT * IMG_ASSET_ENTSZ) db 0

%undef IMG_ROW
%undef EMBED_IMG
