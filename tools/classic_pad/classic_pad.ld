/* Places classic_pad.c into free space in Text 0 of the WBME main DOL.
 *
 * Text 0 (0x80004000-0x800064E0) holds the MetroTRK exception vector table,
 * which is only copied to low memory when a debugger is attached.  Between
 * its stubs are runs of zero padding that nothing executes or reads; appl.py
 * already uses two of them (EUR dialog payload 0x800044F0-0x8000455C, SDHC
 * 0x80004DF4-0x80004F7C).  No single run is big enough for this patch, so
 * each piece is pinned to one, and appl.py refuses to write over anything
 * that is not still zero.
 *
 * Gap names match the IN_GAP()/DATA_GAP()/RODATA_GAP() letters in the C. */

OUTPUT_ARCH(powerpc:common)
ENTRY(cp_kpad_read)

MEMORY
{
    gap_a : ORIGIN = 0x80005BF4, LENGTH = 0x4CC   /* up to 0x800060C0 */
    gap_b : ORIGIN = 0x800058F4, LENGTH = 0x1CC   /* up to 0x80005AC0 */
    gap_c : ORIGIN = 0x80004F80, LENGTH = 0x140   /* after the SDHC guard word */
    gap_d : ORIGIN = 0x800045C4, LENGTH = 0x0FC   /* up to 0x800046C0 */
    gap_e : ORIGIN = 0x8000470C, LENGTH = 0x0B4   /* up to 0x800047C0 */
    gap_f : ORIGIN = 0x800047F4, LENGTH = 0x0CC   /* up to 0x800048C0 */
    gap_g : ORIGIN = 0x800048F4, LENGTH = 0x0CC   /* up to 0x800049C0 */
}

SECTIONS
{
    .cp_a : { KEEP(*(.cp.a)) } > gap_a
    .cp_b : { *(.cp.b) } > gap_b
    .cp_c : { *(.cp.c) } > gap_c
    /* libgcc's out-of-line FPR save/restore (-Os) */
    .cp_d : { *(.cp.d) *libgcc.a:*(.text .text.*) } > gap_d
    .cp_e : { *(.cp.e) *(.cp.e.ro) *(.rodata .rodata.*) } > gap_e
    .cp_f : { *(.cp.f.ro) } > gap_f
    .cp_g : { *(.cp.g.rw) } > gap_g

    /* Anything not placed above would silently be dropped from the DOL. */
    .orphans : { *(.text .text.* .data .data.* .sdata .sdata.* .sdata2 .sdata2.*
                   .bss .bss.* .sbss .sbss.* COMMON) }
    /DISCARD/ : { *(.comment) *(.eh_frame) *(.gnu.attributes) *(.note*) *(.debug*) }
}

ASSERT(SIZEOF(.orphans) == 0, "classic_pad: code/data outside the .cp.* gap sections")
