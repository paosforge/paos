; Runtime-populated table: static `dq symbol` would bake an RVA, not a runtime VA.
FORM_COUNT  equ 8
FORM_NAME   equ 0
FORM_BLOB_PTR equ 8
FORM_LEN    equ 16
FORM_ENT_SZ equ 24

%macro EMBED_FORM 1
form_blob_%1:
    incbin "gui/forms/%1.frm"
form_blob_%1_end:
    db 0
%endmacro

EMBED_FORM demo_a
EMBED_FORM demo_b
EMBED_FORM demo_c
EMBED_FORM sysprops
EMBED_FORM netmon
EMBED_FORM bad_rawcolor
EMBED_FORM bad_unknown_widget
EMBED_FORM bad_unknown_key

forms_table_init:
%macro FORM_ROW 2
    lea  rax, [rel form_name_%1]
    mov  [rel forms_table + (%2 * FORM_ENT_SZ) + FORM_NAME], rax
    lea  rax, [rel form_blob_%1]
    mov  [rel forms_table + (%2 * FORM_ENT_SZ) + FORM_BLOB_PTR], rax
    mov  qword [rel forms_table + (%2 * FORM_ENT_SZ) + FORM_LEN], form_blob_%1_end - form_blob_%1
%endmacro
    FORM_ROW demo_a, 0
    FORM_ROW demo_b, 1
    FORM_ROW demo_c, 2
    FORM_ROW sysprops, 3
    FORM_ROW netmon, 4
    FORM_ROW bad_rawcolor, 5
    FORM_ROW bad_unknown_widget, 6
    FORM_ROW bad_unknown_key, 7
    ret

form_name_demo_a: db "demo_a",0
form_name_demo_b: db "demo_b",0
form_name_demo_c: db "demo_c",0
form_name_sysprops: db "sysprops",0
form_name_netmon: db "netmon",0
form_name_bad_rawcolor: db "bad_rawcolor",0
form_name_bad_unknown_widget: db "bad_unknown_widget",0
form_name_bad_unknown_key: db "bad_unknown_key",0
forms_table: times (FORM_COUNT * FORM_ENT_SZ) db 0

%undef FORM_ROW
%undef EMBED_FORM
