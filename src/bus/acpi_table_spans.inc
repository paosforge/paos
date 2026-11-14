%ifndef PAOS_ACPI_TABLE_SPANS_INC
%define PAOS_ACPI_TABLE_SPANS_INC 1
ACPI_TABLE_SPANS_MAX_TABLES equ 16
ACPI_TABLE_SPANS_MAX_BYTES equ 1048576
; Layout-compatible with aml_table_span. These are admitted, retained immutable
; native firmware bytes, not addresses copied from an offline registry capture.
struc acpi_table_span
 .start: resq 1
 .end: resq 1
endstruc
struc acpi_table_spans
 .root_start: resq 1
 .root_end: resq 1
 .fadt_start: resq 1
 .fadt_end: resq 1
 .count: resd 1
 .total_bytes: resd 1                 ; AML headers+bodies, excluding XSDT/FADT
 .spans: resb ACPI_TABLE_SPANS_MAX_TABLES * acpi_table_span_size
endstruc
%endif
