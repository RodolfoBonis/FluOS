/* Higher-half kernel at the top 2 GiB, as required by the `kernel` code model. */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(kmain)

PHDRS
{
    limine_requests PT_LOAD;
    text    PT_LOAD;
    rodata  PT_LOAD;
    data    PT_LOAD;
}

SECTIONS
{
    . = 0xffffffff80000000;
    __kernel_start = .;

    /* Limine requests: written by the bootloader before entry, read-only after. */
    .limine_requests : {
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end))
    } :limine_requests
    . = ALIGN(4K);
    __requests_end = .;

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .text : {
        __text_start = .;
        *(.text .text.*)
    } :text
    . = ALIGN(4K);
    __text_end = .;

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .rodata : {
        __rodata_start = .;
        *(.rodata .rodata.*)
    } :rodata
    .eh_frame_hdr : { *(.eh_frame_hdr) } :rodata
    .eh_frame : { KEEP(*(.eh_frame)) } :rodata
    . = ALIGN(4K);
    __rodata_end = .;

    . = ALIGN(CONSTANT(MAXPAGESIZE));
    .data : {
        __data_start = .;
        *(.data .data.*)
    } :data
    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data
    . = ALIGN(4K);
    __kernel_end = .;

    /DISCARD/ : { *(.note .note.*) }
}
