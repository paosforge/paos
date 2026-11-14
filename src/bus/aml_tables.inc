%ifndef PAOS_AML_TABLES_INC
%define PAOS_AML_TABLES_INC 1
%include "bus/aml_namespace.inc"
AML_TABLE_MAX       equ 16
AML_TABLE_HEADER    equ 36
AML_TABLE_CHECKSUM  equ -9
AML_TABLE_ORDER     equ -10
AML_TABLE_OVERLAP   equ -11
; These are caller-owned, mapped immutable byte spans, NOT firmware addresses.
struc aml_table_span
 .start: resq 1
 .end: resq 1
endstruc
struc aml_table
 .header: resb AML_TABLE_HEADER       ; exact original header, including OEM bytes
 .source_id: resd 1                   ; one-based input order, never OEM sorting
 .start: resq 1
 .body: resq 1
 .end: resq 1                        ; logical header Length, not mapping padding
endstruc
struc aml_tables
 .count: resd 1
 .total_bytes: resd 1                 ; headers included in aggregate 1MiB budget
 .integer_bits: resd 1                ; GLOBAL width from DSDT Revision only
 .reserved: resd 1                    ; zero
 .entries: resb AML_TABLE_MAX * aml_table_size
endstruc
%endif
