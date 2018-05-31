#include "globals.h"
#include "errs.h"
#include "disinfo.h"

/* Thumb32 opcodes use the same table structure as the ARM opcodes.
   We adopt the convention that hw1 is the high 16 bits of .value and
   .mask, hw2 the low 16 bits.

   print_insn_thumb32 recognizes the following format control codes:

   %%		%

   %I		print a 12-bit immediate from hw1[10],hw2[14:12,7:0]
   %M		print a modified 12-bit immediate (same location)
   %J		print a 16-bit immediate from hw1[3:0,10],hw2[14:12,7:0]
   %K		print a 16-bit immediate from hw2[3:0],hw1[3:0],hw2[11:4]
   %H		print a 16-bit immediate from hw2[3:0],hw1[11:0]
   %S		print a possibly-shifted Rm

   %L		print address for a ldrd/strd instruction
   %a		print the address of a plain load/store
   %w		print the width and signedness of a core load/store
   %m		print register mask for ldm/stm

   %E		print the lsb and width fields of a bfc/bfi instruction
   %F		print the lsb and width fields of a sbfx/ubfx instruction
   %b		print a conditional branch offset
   %B		print an unconditional branch offset
   %s		print the shift field of an SSAT instruction
   %R		print the rotation field of an SXT instruction
   %U		print barrier type.
   %P		print address for pli instruction.
   %c		print the condition code
   %x		print warning if conditional an not at end of IT block"
   %X		print "\t; unpredictable <IT:code>" if conditional

   %<bitfield>d	print bitfield in decimal
   %<bitfield>W	print bitfield*4 in decimal
   %<bitfield>r	print bitfield as an ARM register
   %<bitfield>R	as %<>r but r15 is UNPREDICTABLE
   %<bitfield>S	as %<>R but r13 is UNPREDICTABLE
   %<bitfield>c	print bitfield as a condition code

   %<bitfield>'c	print specified char iff bitfield is all ones
   %<bitfield>`c	print specified char iff bitfield is all zeroes
   %<bitfield>?ab... select from array of values in big endian order

   With one exception at the bottom (done because BL and BLX(1) need
   to come dead last), this table was machine-sorted first in
   decreasing order of number of bits set in the mask, then in
   increasing numeric order of mask, then in increasing numeric order
   of opcode.  This order is not the clearest for a human reader, but
   is guaranteed never to catch a special-case bit pattern with a more
   general mask, which is important, because this instruction encoding
   makes heavy use of special-case bit patterns.  */
static const opcode32 thumb32_opcodes[] = {
	/* V8 instructions.  */
	{ARM_EXT_V8, 0xf3af8005, 0xffffffff, "sevl%c.w"},
	{ARM_EXT_V8, 0xf78f8000, 0xfffffffc, "dcps%0-1d"},
	{ARM_EXT_V8, 0xe8c00f8f, 0xfff00fff, "stlb%c\t%12-15r, [%16-19R]"},
	{ARM_EXT_V8, 0xe8c00f9f, 0xfff00fff, "stlh%c\t%12-15r, [%16-19R]"},
	{ARM_EXT_V8, 0xe8c00faf, 0xfff00fff, "stl%c\t%12-15r, [%16-19R]"},
	{ARM_EXT_V8, 0xe8c00fc0, 0xfff00ff0, "stlexb%c\t%0-3r, %12-15r, [%16-19R]"},
	{ARM_EXT_V8, 0xe8c00fd0, 0xfff00ff0, "stlexh%c\t%0-3r, %12-15r, [%16-19R]"},
	{ARM_EXT_V8, 0xe8c00fe0, 0xfff00ff0, "stlex%c\t%0-3r, %12-15r, [%16-19R]"},
	{ARM_EXT_V8, 0xe8c000f0, 0xfff000f0, "stlexd%c\t%0-3r, %12-15r, %8-11r, [%16-19R]"},
	{ARM_EXT_V8, 0xe8d00f8f, 0xfff00fff, "ldab%c\t%12-15r, [%16-19R]"},
	{ARM_EXT_V8, 0xe8d00f9f, 0xfff00fff, "ldah%c\t%12-15r, [%16-19R]"},
	{ARM_EXT_V8, 0xe8d00faf, 0xfff00fff, "lda%c\t%12-15r, [%16-19R]"},
	{ARM_EXT_V8, 0xe8d00fcf, 0xfff00fff, "ldaexb%c\t%12-15r, [%16-19R]"},
	{ARM_EXT_V8, 0xe8d00fdf, 0xfff00fff, "ldaexh%c\t%12-15r, [%16-19R]"},
	{ARM_EXT_V8, 0xe8d00fef, 0xfff00fff, "ldaex%c\t%12-15r, [%16-19R]"},
	{ARM_EXT_V8, 0xe8d000ff, 0xfff000ff, "ldaexd%c\t%12-15r, %8-11r, [%16-19R]"},

	/* CRC32 instructions.  */
	{CRC_EXT_ARMV8, 0xfac0f080, 0xfff0f0f0, "crc32b\t%8-11S, %16-19S, %0-3S"},
	{CRC_EXT_ARMV8, 0xfac0f090, 0xfff0f0f0, "crc32h\t%9-11S, %16-19S, %0-3S"},
	{CRC_EXT_ARMV8, 0xfac0f0a0, 0xfff0f0f0, "crc32w\t%8-11S, %16-19S, %0-3S"},
	{CRC_EXT_ARMV8, 0xfad0f080, 0xfff0f0f0, "crc32cb\t%8-11S, %16-19S, %0-3S"},
	{CRC_EXT_ARMV8, 0xfad0f090, 0xfff0f0f0, "crc32ch\t%8-11S, %16-19S, %0-3S"},
	{CRC_EXT_ARMV8, 0xfad0f0a0, 0xfff0f0f0, "crc32cw\t%8-11S, %16-19S, %0-3S"},

	/* V7 instructions.  */
	{ARM_EXT_V7, 0xf910f000, 0xff70f000, "pli%c\t%a"},
	{ARM_EXT_V7, 0xf3af80f0, 0xfffffff0, "dbg%c\t#%0-3d"},
	{ARM_EXT_V8, 0xf3bf8f51, 0xfffffff3, "dmb%c\t%U"},
	{ARM_EXT_V8, 0xf3bf8f41, 0xfffffff3, "dsb%c\t%U"},
	{ARM_EXT_V7, 0xf3bf8f50, 0xfffffff0, "dmb%c\t%U"},
	{ARM_EXT_V7, 0xf3bf8f40, 0xfffffff0, "dsb%c\t%U"},
	{ARM_EXT_V7, 0xf3bf8f60, 0xfffffff0, "isb%c\t%U"},
	{ARM_EXT_DIV, 0xfb90f0f0, 0xfff0f0f0, "sdiv%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_DIV, 0xfbb0f0f0, 0xfff0f0f0, "udiv%c\t%8-11r, %16-19r, %0-3r"},

	/* Virtualization Extension instructions.  */
	{ARM_EXT_VIRT, 0xf7e08000, 0xfff0f000, "hvc%c\t%V"},
	/* We skip ERET as that is SUBS pc, lr, #0.  */

	/* MP Extension instructions.  */
	{ARM_EXT_MP,   0xf830f000, 0xff70f000, "pldw%c\t%a"},

	/* Security extension instructions.  */
	{ARM_EXT_SEC,  0xf7f08000, 0xfff0f000, "smc%c\t%K"},

	/* Instructions defined in the basic V6T2 set.  */
	{ARM_EXT_V6T2, 0xf3af8000, 0xffffffff, "nop%c.w"},
	{ARM_EXT_V6T2, 0xf3af8001, 0xffffffff, "yield%c.w"},
	{ARM_EXT_V6T2, 0xf3af8002, 0xffffffff, "wfe%c.w"},
	{ARM_EXT_V6T2, 0xf3af8003, 0xffffffff, "wfi%c.w"},
	{ARM_EXT_V6T2, 0xf3af8004, 0xffffffff, "sev%c.w"},
	{ARM_EXT_V6T2, 0xf3af8000, 0xffffff00, "nop%c.w\t{%0-7d}"},
	{ARM_EXT_V6T2, 0xf7f0a000, 0xfff0f000, "udf%c.w\t%H"},

	{ARM_EXT_V6T2, 0xf3bf8f2f, 0xffffffff, "clrex%c"},
	{ARM_EXT_V6T2, 0xf3af8400, 0xffffff1f, "cpsie.w\t%7'a%6'i%5'f%X"},
	{ARM_EXT_V6T2, 0xf3af8600, 0xffffff1f, "cpsid.w\t%7'a%6'i%5'f%X"},
	{ARM_EXT_V6T2, 0xf3c08f00, 0xfff0ffff, "bxj%c\t%16-19r%x"},
	{ARM_EXT_V6T2, 0xe810c000, 0xffd0ffff, "rfedb%c\t%16-19r%21'!"},
	{ARM_EXT_V6T2, 0xe990c000, 0xffd0ffff, "rfeia%c\t%16-19r%21'!"},
	{ARM_EXT_V6T2, 0xf3e08000, 0xffe0f000, "mrs%c\t%8-11r, %D"},
	{ARM_EXT_V6T2, 0xf3af8100, 0xffffffe0, "cps\t#%0-4d%X"},
	{ARM_EXT_V6T2, 0xe8d0f000, 0xfff0fff0, "tbb%c\t[%16-19r, %0-3r]%x"},
	{ARM_EXT_V6T2, 0xe8d0f010, 0xfff0fff0, "tbh%c\t[%16-19r, %0-3r, lsl #1]%x"},
	{ARM_EXT_V6T2, 0xf3af8500, 0xffffff00, "cpsie\t%7'a%6'i%5'f, #%0-4d%X"},
	{ARM_EXT_V6T2, 0xf3af8700, 0xffffff00, "cpsid\t%7'a%6'i%5'f, #%0-4d%X"},
	{ARM_EXT_V6T2, 0xf3de8f00, 0xffffff00, "subs%c\tpc, lr, #%0-7d"},
	{ARM_EXT_V6T2, 0xf3808000, 0xffe0f000, "msr%c\t%C, %16-19r"},
	{ARM_EXT_V6T2, 0xe8500f00, 0xfff00fff, "ldrex%c\t%12-15r, [%16-19r]"},
	{ARM_EXT_V6T2, 0xe8d00f4f, 0xfff00fef, "ldrex%4?hb%c\t%12-15r, [%16-19r]"},
	{ARM_EXT_V6T2, 0xe800c000, 0xffd0ffe0, "srsdb%c\t%16-19r%21'!, #%0-4d"},
	{ARM_EXT_V6T2, 0xe980c000, 0xffd0ffe0, "srsia%c\t%16-19r%21'!, #%0-4d"},
	{ARM_EXT_V6T2, 0xfa0ff080, 0xfffff0c0, "sxth%c.w\t%8-11r, %0-3r%R"},
	{ARM_EXT_V6T2, 0xfa1ff080, 0xfffff0c0, "uxth%c.w\t%8-11r, %0-3r%R"},
	{ARM_EXT_V6T2, 0xfa2ff080, 0xfffff0c0, "sxtb16%c\t%8-11r, %0-3r%R"},
	{ARM_EXT_V6T2, 0xfa3ff080, 0xfffff0c0, "uxtb16%c\t%8-11r, %0-3r%R"},
	{ARM_EXT_V6T2, 0xfa4ff080, 0xfffff0c0, "sxtb%c.w\t%8-11r, %0-3r%R"},
	{ARM_EXT_V6T2, 0xfa5ff080, 0xfffff0c0, "uxtb%c.w\t%8-11r, %0-3r%R"},
	{ARM_EXT_V6T2, 0xe8400000, 0xfff000ff, "strex%c\t%8-11r, %12-15r, [%16-19r]"},
	{ARM_EXT_V6T2, 0xe8d0007f, 0xfff000ff, "ldrexd%c\t%12-15r, %8-11r, [%16-19r]"},
	{ARM_EXT_V6T2, 0xfa80f000, 0xfff0f0f0, "sadd8%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfa80f010, 0xfff0f0f0, "qadd8%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfa80f020, 0xfff0f0f0, "shadd8%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfa80f040, 0xfff0f0f0, "uadd8%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfa80f050, 0xfff0f0f0, "uqadd8%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfa80f060, 0xfff0f0f0, "uhadd8%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfa80f080, 0xfff0f0f0, "qadd%c\t%8-11r, %0-3r, %16-19r"},
	{ARM_EXT_V6T2, 0xfa80f090, 0xfff0f0f0, "qdadd%c\t%8-11r, %0-3r, %16-19r"},
	{ARM_EXT_V6T2, 0xfa80f0a0, 0xfff0f0f0, "qsub%c\t%8-11r, %0-3r, %16-19r"},
	{ARM_EXT_V6T2, 0xfa80f0b0, 0xfff0f0f0, "qdsub%c\t%8-11r, %0-3r, %16-19r"},
	{ARM_EXT_V6T2, 0xfa90f000, 0xfff0f0f0, "sadd16%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfa90f010, 0xfff0f0f0, "qadd16%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfa90f020, 0xfff0f0f0, "shadd16%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfa90f040, 0xfff0f0f0, "uadd16%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfa90f050, 0xfff0f0f0, "uqadd16%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfa90f060, 0xfff0f0f0, "uhadd16%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfa90f080, 0xfff0f0f0, "rev%c.w\t%8-11r, %16-19r"},
	{ARM_EXT_V6T2, 0xfa90f090, 0xfff0f0f0, "rev16%c.w\t%8-11r, %16-19r"},
	{ARM_EXT_V6T2, 0xfa90f0a0, 0xfff0f0f0, "rbit%c\t%8-11r, %16-19r"},
	{ARM_EXT_V6T2, 0xfa90f0b0, 0xfff0f0f0, "revsh%c.w\t%8-11r, %16-19r"},
	{ARM_EXT_V6T2, 0xfaa0f000, 0xfff0f0f0, "sasx%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfaa0f010, 0xfff0f0f0, "qasx%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfaa0f020, 0xfff0f0f0, "shasx%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfaa0f040, 0xfff0f0f0, "uasx%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfaa0f050, 0xfff0f0f0, "uqasx%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfaa0f060, 0xfff0f0f0, "uhasx%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfaa0f080, 0xfff0f0f0, "sel%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfab0f080, 0xfff0f0f0, "clz%c\t%8-11r, %16-19r"},
	{ARM_EXT_V6T2, 0xfac0f000, 0xfff0f0f0, "ssub8%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfac0f010, 0xfff0f0f0, "qsub8%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfac0f020, 0xfff0f0f0, "shsub8%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfac0f040, 0xfff0f0f0, "usub8%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfac0f050, 0xfff0f0f0, "uqsub8%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfac0f060, 0xfff0f0f0, "uhsub8%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfad0f000, 0xfff0f0f0, "ssub16%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfad0f010, 0xfff0f0f0, "qsub16%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfad0f020, 0xfff0f0f0, "shsub16%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfad0f040, 0xfff0f0f0, "usub16%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfad0f050, 0xfff0f0f0, "uqsub16%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfad0f060, 0xfff0f0f0, "uhsub16%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfae0f000, 0xfff0f0f0, "ssax%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfae0f010, 0xfff0f0f0, "qsax%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfae0f020, 0xfff0f0f0, "shsax%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfae0f040, 0xfff0f0f0, "usax%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfae0f050, 0xfff0f0f0, "uqsax%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfae0f060, 0xfff0f0f0, "uhsax%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfb00f000, 0xfff0f0f0, "mul%c.w\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfb70f000, 0xfff0f0f0, "usad8%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfa00f000, 0xffe0f0f0, "lsl%20's%c.w\t%8-11R, %16-19R, %0-3R"},
	{ARM_EXT_V6T2, 0xfa20f000, 0xffe0f0f0, "lsr%20's%c.w\t%8-11R, %16-19R, %0-3R"},
	{ARM_EXT_V6T2, 0xfa40f000, 0xffe0f0f0, "asr%20's%c.w\t%8-11R, %16-19R, %0-3R"},
	{ARM_EXT_V6T2, 0xfa60f000, 0xffe0f0f0, "ror%20's%c.w\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xe8c00f40, 0xfff00fe0, "strex%4?hb%c\t%0-3r, %12-15r, [%16-19r]"},
	{ARM_EXT_V6T2, 0xf3200000, 0xfff0f0e0, "ssat16%c\t%8-11r, #%0-4d, %16-19r"},
	{ARM_EXT_V6T2, 0xf3a00000, 0xfff0f0e0, "usat16%c\t%8-11r, #%0-4d, %16-19r"},
	{ARM_EXT_V6T2, 0xfb20f000, 0xfff0f0e0, "smuad%4'x%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfb30f000, 0xfff0f0e0, "smulw%4?tb%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfb40f000, 0xfff0f0e0, "smusd%4'x%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfb50f000, 0xfff0f0e0, "smmul%4'r%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xfa00f080, 0xfff0f0c0, "sxtah%c\t%8-11r, %16-19r, %0-3r%R"},
	{ARM_EXT_V6T2, 0xfa10f080, 0xfff0f0c0, "uxtah%c\t%8-11r, %16-19r, %0-3r%R"},
	{ARM_EXT_V6T2, 0xfa20f080, 0xfff0f0c0, "sxtab16%c\t%8-11r, %16-19r, %0-3r%R"},
	{ARM_EXT_V6T2, 0xfa30f080, 0xfff0f0c0, "uxtab16%c\t%8-11r, %16-19r, %0-3r%R"},
	{ARM_EXT_V6T2, 0xfa40f080, 0xfff0f0c0, "sxtab%c\t%8-11r, %16-19r, %0-3r%R"},
	{ARM_EXT_V6T2, 0xfa50f080, 0xfff0f0c0, "uxtab%c\t%8-11r, %16-19r, %0-3r%R"},
	{ARM_EXT_V6T2, 0xfb10f000, 0xfff0f0c0, "smul%5?tb%4?tb%c\t%8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xf36f0000, 0xffff8020, "bfc%c\t%8-11r, %E"},
	{ARM_EXT_V6T2, 0xea100f00, 0xfff08f00, "tst%c.w\t%16-19r, %S"},
	{ARM_EXT_V6T2, 0xea900f00, 0xfff08f00, "teq%c\t%16-19r, %S"},
	{ARM_EXT_V6T2, 0xeb100f00, 0xfff08f00, "cmn%c.w\t%16-19r, %S"},
	{ARM_EXT_V6T2, 0xebb00f00, 0xfff08f00, "cmp%c.w\t%16-19r, %S"},
	{ARM_EXT_V6T2, 0xf0100f00, 0xfbf08f00, "tst%c.w\t%16-19r, %M"},
	{ARM_EXT_V6T2, 0xf0900f00, 0xfbf08f00, "teq%c\t%16-19r, %M"},
	{ARM_EXT_V6T2, 0xf1100f00, 0xfbf08f00, "cmn%c.w\t%16-19r, %M"},
	{ARM_EXT_V6T2, 0xf1b00f00, 0xfbf08f00, "cmp%c.w\t%16-19r, %M"},
	{ARM_EXT_V6T2, 0xea4f0000, 0xffef8000, "mov%20's%c.w\t%8-11r, %S"},
	{ARM_EXT_V6T2, 0xea6f0000, 0xffef8000, "mvn%20's%c.w\t%8-11r, %S"},
	{ARM_EXT_V6T2, 0xe8c00070, 0xfff000f0, "strexd%c\t%0-3r, %12-15r, %8-11r, [%16-19r]"},
	{ARM_EXT_V6T2, 0xfb000000, 0xfff000f0, "mla%c\t%8-11r, %16-19r, %0-3r, %12-15r"},
	{ARM_EXT_V6T2, 0xfb000010, 0xfff000f0, "mls%c\t%8-11r, %16-19r, %0-3r, %12-15r"},
	{ARM_EXT_V6T2, 0xfb700000, 0xfff000f0, "usada8%c\t%8-11R, %16-19R, %0-3R, %12-15R"},
	{ARM_EXT_V6T2, 0xfb800000, 0xfff000f0, "smull%c\t%12-15R, %8-11R, %16-19R, %0-3R"},
	{ARM_EXT_V6T2, 0xfba00000, 0xfff000f0, "umull%c\t%12-15R, %8-11R, %16-19R, %0-3R"},
	{ARM_EXT_V6T2, 0xfbc00000, 0xfff000f0, "smlal%c\t%12-15R, %8-11R, %16-19R, %0-3R"},
	{ARM_EXT_V6T2, 0xfbe00000, 0xfff000f0, "umlal%c\t%12-15R, %8-11R, %16-19R, %0-3R"},
	{ARM_EXT_V6T2, 0xfbe00060, 0xfff000f0, "umaal%c\t%12-15R, %8-11R, %16-19R, %0-3R"},
	{ARM_EXT_V6T2, 0xe8500f00, 0xfff00f00, "ldrex%c\t%12-15r, [%16-19r, #%0-7W]"},
	{ARM_EXT_V6T2, 0xf04f0000, 0xfbef8000, "mov%20's%c.w\t%8-11r, %M"},
	{ARM_EXT_V6T2, 0xf06f0000, 0xfbef8000, "mvn%20's%c.w\t%8-11r, %M"},
	{ARM_EXT_V6T2, 0xf810f000, 0xff70f000, "pld%c\t%a"},
	{ARM_EXT_V6T2, 0xfb200000, 0xfff000e0, "smlad%4'x%c\t%8-11R, %16-19R, %0-3R, %12-15R"},
	{ARM_EXT_V6T2, 0xfb300000, 0xfff000e0, "smlaw%4?tb%c\t%8-11R, %16-19R, %0-3R, %12-15R"},
	{ARM_EXT_V6T2, 0xfb400000, 0xfff000e0, "smlsd%4'x%c\t%8-11R, %16-19R, %0-3R, %12-15R"},
	{ARM_EXT_V6T2, 0xfb500000, 0xfff000e0, "smmla%4'r%c\t%8-11R, %16-19R, %0-3R, %12-15R"},
	{ARM_EXT_V6T2, 0xfb600000, 0xfff000e0, "smmls%4'r%c\t%8-11R, %16-19R, %0-3R, %12-15R"},
	{ARM_EXT_V6T2, 0xfbc000c0, 0xfff000e0, "smlald%4'x%c\t%12-15R, %8-11R, %16-19R, %0-3R"},
	{ARM_EXT_V6T2, 0xfbd000c0, 0xfff000e0, "smlsld%4'x%c\t%12-15R, %8-11R, %16-19R, %0-3R"},
	{ARM_EXT_V6T2, 0xeac00000, 0xfff08030, "pkhbt%c\t%8-11r, %16-19r, %S"},
	{ARM_EXT_V6T2, 0xeac00020, 0xfff08030, "pkhtb%c\t%8-11r, %16-19r, %S"},
	{ARM_EXT_V6T2, 0xf3400000, 0xfff08020, "sbfx%c\t%8-11r, %16-19r, %F"},
	{ARM_EXT_V6T2, 0xf3c00000, 0xfff08020, "ubfx%c\t%8-11r, %16-19r, %F"},
	{ARM_EXT_V6T2, 0xf8000e00, 0xff900f00, "str%wt%c\t%12-15r, %a"},
	{ARM_EXT_V6T2, 0xfb100000, 0xfff000c0, "smla%5?tb%4?tb%c\t%8-11r, %16-19r, %0-3r, %12-15r"},
	{ARM_EXT_V6T2, 0xfbc00080, 0xfff000c0, "smlal%5?tb%4?tb%c\t%12-15r, %8-11r, %16-19r, %0-3r"},
	{ARM_EXT_V6T2, 0xf3600000, 0xfff08020, "bfi%c\t%8-11r, %16-19r, %E"},
	{ARM_EXT_V6T2, 0xf8100e00, 0xfe900f00, "ldr%wt%c\t%12-15r, %a"},
	{ARM_EXT_V6T2, 0xf3000000, 0xffd08020, "ssat%c\t%8-11r, #%0-4d, %16-19r%s"},
	{ARM_EXT_V6T2, 0xf3800000, 0xffd08020, "usat%c\t%8-11r, #%0-4d, %16-19r%s"},
	{ARM_EXT_V6T2, 0xf2000000, 0xfbf08000, "addw%c\t%8-11r, %16-19r, %I"},
	{ARM_EXT_V6T2, 0xf2400000, 0xfbf08000, "movw%c\t%8-11r, %J"},
	{ARM_EXT_V6T2, 0xf2a00000, 0xfbf08000, "subw%c\t%8-11r, %16-19r, %I"},
	{ARM_EXT_V6T2, 0xf2c00000, 0xfbf08000, "movt%c\t%8-11r, %J"},
	{ARM_EXT_V6T2, 0xea000000, 0xffe08000, "and%20's%c.w\t%8-11r, %16-19r, %S"},
	{ARM_EXT_V6T2, 0xea200000, 0xffe08000, "bic%20's%c.w\t%8-11r, %16-19r, %S"},
	{ARM_EXT_V6T2, 0xea400000, 0xffe08000, "orr%20's%c.w\t%8-11r, %16-19r, %S"},
	{ARM_EXT_V6T2, 0xea600000, 0xffe08000, "orn%20's%c\t%8-11r, %16-19r, %S"},
	{ARM_EXT_V6T2, 0xea800000, 0xffe08000, "eor%20's%c.w\t%8-11r, %16-19r, %S"},
	{ARM_EXT_V6T2, 0xeb000000, 0xffe08000, "add%20's%c.w\t%8-11r, %16-19r, %S"},
	{ARM_EXT_V6T2, 0xeb400000, 0xffe08000, "adc%20's%c.w\t%8-11r, %16-19r, %S"},
	{ARM_EXT_V6T2, 0xeb600000, 0xffe08000, "sbc%20's%c.w\t%8-11r, %16-19r, %S"},
	{ARM_EXT_V6T2, 0xeba00000, 0xffe08000, "sub%20's%c.w\t%8-11r, %16-19r, %S"},
	{ARM_EXT_V6T2, 0xebc00000, 0xffe08000, "rsb%20's%c\t%8-11r, %16-19r, %S"},
	{ARM_EXT_V6T2, 0xe8400000, 0xfff00000, "strex%c\t%8-11r, %12-15r, [%16-19r, #%0-7W]"},
	{ARM_EXT_V6T2, 0xf0000000, 0xfbe08000, "and%20's%c.w\t%8-11r, %16-19r, %M"},
	{ARM_EXT_V6T2, 0xf0200000, 0xfbe08000, "bic%20's%c.w\t%8-11r, %16-19r, %M"},
	{ARM_EXT_V6T2, 0xf0400000, 0xfbe08000, "orr%20's%c.w\t%8-11r, %16-19r, %M"},
	{ARM_EXT_V6T2, 0xf0600000, 0xfbe08000, "orn%20's%c\t%8-11r, %16-19r, %M"},
	{ARM_EXT_V6T2, 0xf0800000, 0xfbe08000, "eor%20's%c.w\t%8-11r, %16-19r, %M"},
	{ARM_EXT_V6T2, 0xf1000000, 0xfbe08000, "add%20's%c.w\t%8-11r, %16-19r, %M"},
	{ARM_EXT_V6T2, 0xf1400000, 0xfbe08000, "adc%20's%c.w\t%8-11r, %16-19r, %M"},
	{ARM_EXT_V6T2, 0xf1600000, 0xfbe08000, "sbc%20's%c.w\t%8-11r, %16-19r, %M"},
	{ARM_EXT_V6T2, 0xf1a00000, 0xfbe08000, "sub%20's%c.w\t%8-11r, %16-19r, %M"},
	{ARM_EXT_V6T2, 0xf1c00000, 0xfbe08000, "rsb%20's%c\t%8-11r, %16-19r, %M"},
	{ARM_EXT_V6T2, 0xe8800000, 0xffd00000, "stmia%c.w\t%16-19r%21'!, %m"},
	{ARM_EXT_V6T2, 0xe8900000, 0xffd00000, "ldmia%c.w\t%16-19r%21'!, %m"},
	{ARM_EXT_V6T2, 0xe9000000, 0xffd00000, "stmdb%c\t%16-19r%21'!, %m"},
	{ARM_EXT_V6T2, 0xe9100000, 0xffd00000, "ldmdb%c\t%16-19r%21'!, %m"},
	{ARM_EXT_V6T2, 0xe9c00000, 0xffd000ff, "strd%c\t%12-15r, %8-11r, [%16-19r]"},
	{ARM_EXT_V6T2, 0xe9d00000, 0xffd000ff, "ldrd%c\t%12-15r, %8-11r, [%16-19r]"},
	{ARM_EXT_V6T2, 0xe9400000, 0xff500000, "strd%c\t%12-15r, %8-11r, [%16-19r, #%23`-%0-7W]%21'!%L"},
	{ARM_EXT_V6T2, 0xe9500000, 0xff500000, "ldrd%c\t%12-15r, %8-11r, [%16-19r, #%23`-%0-7W]%21'!%L"},
	{ARM_EXT_V6T2, 0xe8600000, 0xff700000, "strd%c\t%12-15r, %8-11r, [%16-19r], #%23`-%0-7W%L"},
	{ARM_EXT_V6T2, 0xe8700000, 0xff700000, "ldrd%c\t%12-15r, %8-11r, [%16-19r], #%23`-%0-7W%L"},
	{ARM_EXT_V6T2, 0xf8000000, 0xff100000, "str%w%c.w\t%12-15r, %a"},
	{ARM_EXT_V6T2, 0xf8100000, 0xfe100000, "ldr%w%c.w\t%12-15r, %a"},

	/* Filter out Bcc with cond=E or F, which are used for other instructions.  */
	{ARM_EXT_V6T2, 0xf3c08000, 0xfbc0d000, "undefined (bcc, cond=0xF)"},
	{ARM_EXT_V6T2, 0xf3808000, 0xfbc0d000, "undefined (bcc, cond=0xE)"},
	{ARM_EXT_V6T2, 0xf0008000, 0xf800d000, "b%22-25c.w\t%b%X"},
	{ARM_EXT_V6T2, 0xf0009000, 0xf800d000, "b%c.w\t%B%x"},

	/* These have been 32-bit since the invention of Thumb.  */
	{ARM_EXT_V4T,  0xf000c000, 0xf800d001, "blx%c\t%B%x"},
	{ARM_EXT_V4T,  0xf000d000, 0xf800d000, "bl%c\t%B%x"},

	/* Fallback.  */
	{ARM_EXT_V1,   0x00000000, 0x00000000, UNDEFINED_INSTRUCTION},
	{0, 0, 0, 0}
};

/* opcode编码规则 */
#define W_BIT 21
#define I_BIT 22
#define U_BIT 23
#define P_BIT 24

#define WRITEBACK_BIT_SET   (given & (1 << W_BIT))
#define IMMEDIATE_BIT_SET   (given & (1 << I_BIT))
#define NEGATIVE_BIT_SET    ((given & (1 << U_BIT)) == 0)
#define PRE_BIT_SET         (given & (1 << P_BIT))

unsigned char print_insn_thumb32(unsigned pc, 
								 void *pinfo, 
								 long given, 
								 unsigned char thumb) {
    UNUSED(thumb);
	const opcode32 *insn;
	disassemble_info *info = (disassemble_info*)pinfo;
	void *stream = info->stream;
	fprintf_ftype func = info->fprintf_func;

	if (print_insn_coprocessor(pc, info, given, 1))
		return 1;

	if (print_insn_neon(pc, info, given, 1))
		return 1;

	for (insn = thumb32_opcodes; insn->assembler; insn++) {
		if ((given & insn->mask) == insn->value) {
				unsigned char is_unpredictable = 0;
				signed long value_in_comment = 0;
				const char *c = insn->assembler;

				for (; *c; c++) {
					if (*c != '%') {
						func (stream, "%c", *c);
						continue;
					}/* end if */

					switch (*++c) {
					case '%': {
						func (stream, "%%");
					} break;
					case 'c': {
						if (ifthen_state)
							func (stream, "%s", arm_conditional[IFTHEN_COND]);
					} break;
					case 'x': {
						if (ifthen_next_state)
							func (stream, "\t; unpredictable branch in IT block\n");
					} break;
					case 'X': {
						if (ifthen_state) {
							func (stream, "\t; unpredictable <IT:%s>",
								  arm_conditional[IFTHEN_COND]);
						}
					} break;
					case 'I': {
						unsigned int imm12 = 0;
						imm12 |= (given & 0x000000ffu);
						imm12 |= (given & 0x00007000u) >> 4;
						imm12 |= (given & 0x04000000u) >> 15;
						func (stream, "#%u", imm12);
						value_in_comment = imm12;
					} break;
					case 'M': {
						unsigned int bits = 0, imm, imm8, mod;
						
						bits |= (given & 0x000000ffu);
						bits |= (given & 0x00007000u) >> 4;
						bits |= (given & 0x04000000u) >> 15;
						imm8 = (bits & 0x0ff);
						mod = (bits & 0xf00) >> 8;
						switch (mod) {
						case 0: imm = imm8; break;
						case 1: imm = ((imm8 << 16) | imm8); break;
						case 2: imm = ((imm8 << 24) | (imm8 << 8)); break;
						case 3: imm = ((imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8); break;
						default: {
							mod  = (bits & 0xf80) >> 7;
							imm8 = (bits & 0x07f) | 0x80;
							imm  = (((imm8 << (32 - mod)) | (imm8 >> mod)) & 0xffffffff);
						}/* end default */
						}/* end switch */
						func (stream, "#%u", imm);
						value_in_comment = imm;
					} break;
					case 'J': {
						unsigned int imm = 0;
						imm |= (given & 0x000000ffu);
						imm |= (given & 0x00007000u) >> 4;
						imm |= (given & 0x04000000u) >> 15;
						imm |= (given & 0x000f0000u) >> 4;
						func (stream, "#%u", imm);
						value_in_comment = imm;
					} break;
					case 'K': {
						unsigned int imm = 0;
						imm |= (given & 0x000f0000u) >> 16;
						imm |= (given & 0x00000ff0u) >> 0;
						imm |= (given & 0x0000000fu) << 12;
						func (stream, "#%u", imm);
						value_in_comment = imm;
					} break;
					case 'H': {
						unsigned int imm = 0;
						imm |= (given & 0x000f0000u) >> 4;
						imm |= (given & 0x00000fffu) >> 0;
						func (stream, "#%u", imm);
						value_in_comment = imm;
					} break;
					case 'V': {
						unsigned int imm = 0;
						imm |= (given & 0x00000fffu);
						imm |= (given & 0x000f0000u) >> 4;
						func (stream, "#%u", imm);
						value_in_comment = imm;
					} break;
					case 'S': {
						unsigned int reg = (given & 0x0000000fu);
						unsigned int stp = (given & 0x00000030u) >> 4;
						unsigned int imm = 0;
						imm |= (given & 0x000000c0u) >> 6;
						imm |= (given & 0x00007000u) >> 10;
						func (stream, "%s", arm_regnames[reg]);
						switch (stp) {
						case 0: {
							if (imm > 0)
								func (stream, ", lsl #%u", imm);
						} break;
						case 1: {
							if (imm == 0)
								imm = 32;
							func (stream, ", lsr #%u", imm);
						} break;
						case 2: {
							if (imm == 0)
								imm = 32;
							func (stream, ", asr #%u", imm);
						} break;
						case 3: {
							if (imm == 0)
								func (stream, ", rrx");
							else
								func (stream, ", ror #%u", imm);
						}/* end case 3 */
						}/* end switch */
					} break;
					case 'a': {
						unsigned int Rn = (given & 0x000f0000) >> 16;
						unsigned int U = ! NEGATIVE_BIT_SET;
						unsigned int op = (given & 0x00000f00) >> 8;
						unsigned int i12 = (given & 0x00000fff);
						unsigned int i8 = (given & 0x000000ff);
						unsigned char writeback = 0, postind = 0;
						unsigned offset = 0;
						
						func (stream, "[%s", arm_regnames[Rn]);
						if (U) { /* 12-bit 正立即数偏移  */
							offset = i12;
							if (Rn != 15)
								value_in_comment = offset;
						} else if (Rn == 15) {/* 12-bit 负立即数偏移  */
							offset = - (int) i12;
						} else if (op == 0x0) { /* Shifted register offset.  */
							unsigned int Rm = (i8 & 0x0f);
							unsigned int sh = (i8 & 0x30) >> 4;
							
							func (stream, ", %s", arm_regnames[Rm]);
							if (sh)
								func (stream, ", lsl #%u", sh);
							func (stream, "]");
							break;
						} else switch (op) {
							case 0xE: { /* 8-bit positive immediate offset.  */
								offset = i8;
							} break;
							case 0xC: { /* 8-bit negative immediate offset.  */
								offset = -i8;
							} break;
							case 0xF: { /* 8-bit + preindex with wb.  */
								offset = i8;
								writeback = 1;
							} break;
							case 0xD: { /* 8-bit - preindex with wb.  */
								offset = -i8;
								writeback = 1;
							} break;
							case 0xB: { /* 8-bit + postindex.  */
								offset = i8;
								postind = 1;
							} break;
							case 0x9: { /* 8-bit - postindex.  */
								offset = -i8;
								postind = 1;
							} break;
							default:
								func (stream, ", <undefined>]");
								goto skip;
							}/* end else switch */

						if (postind)
							func (stream, "], #%d", (int) offset);
						else {
							if (offset)
								func (stream, ", #%d", (int) offset);
							func (stream, writeback ? "]!" : "]");
						}/* end else */

						if (Rn == 15) {
							func (stream, "\t; ");
							info->print_address_func(((pc + 4) & ~3) + offset, info);
						}/* end if */
					} skip: break;
					case 'A': {
						unsigned int U  = ! NEGATIVE_BIT_SET;
						unsigned int W  = WRITEBACK_BIT_SET;
						unsigned int Rn = (given & 0x000f0000) >> 16;
						unsigned int off = (given & 0x000000ff);

						func (stream, "[%s", arm_regnames[Rn]);
						if (PRE_BIT_SET) {
							if (off || !U) {
								func (stream, ", #%c%u", U ? '+' : '-', off * 4);
								value_in_comment = off * 4 * U ? 1 : -1;
							}
							func (stream, "]");
							if (W)
								func (stream, "!");
						} else {
							func (stream, "], ");
							if (W) {
								func (stream, "#%c%u", U ? '+' : '-', off * 4);
								value_in_comment = off * 4 * U ? 1 : -1;
							} else {
								func (stream, "{%u}", off);
								value_in_comment = off;
							}
						}/* end else */
					} break;
					case 'w': {
						unsigned int Sbit = (given & 0x01000000) >> 24;
						unsigned int type = (given & 0x00600000) >> 21;
						
						switch (type) {
						case 0: func (stream, Sbit ? "sb" : "b"); break;
						case 1: func (stream, Sbit ? "sh" : "h"); break;
						case 2: {
							if (Sbit)
								func (stream, "??");
						} break;
						case 3: {
							func (stream, "??");
						} break;
						}/* end switch */
					} break;
					case 'm': {
						int started = 0;
						int reg;
						
						func (stream, "{");
						for (reg = 0; reg < 16; reg++) {
							if ((given & (1 << reg)) != 0) {
								if (started)
									func (stream, ", ");
								started = 1;
								func (stream, "%s", arm_regnames[reg]);
							}
						}/* end for */
						func (stream, "}");
					} break;
					case 'E': {
						unsigned int msb = (given & 0x0000001f);
						unsigned int lsb = 0;
						
						lsb |= (given & 0x000000c0u) >> 6;
						lsb |= (given & 0x00007000u) >> 10;
						func (stream, "#%u, #%u", lsb, msb - lsb + 1);
					} break;
					case 'F': {
						unsigned int width = (given & 0x0000001f) + 1;
						unsigned int lsb = 0;
						
						lsb |= (given & 0x000000c0u) >> 6;
						lsb |= (given & 0x00007000u) >> 10;
						func (stream, "#%u, #%u", lsb, width);
					} break;
					case 'b': {
						unsigned int S = (given & 0x04000000u) >> 26;
						unsigned int J1 = (given & 0x00002000u) >> 13;
						unsigned int J2 = (given & 0x00000800u) >> 11;
						unsigned offset = 0;

						offset |= !S << 20;
						offset |= J2 << 19;
						offset |= J1 << 18;
						offset |= (given & 0x003f0000) >> 4;
						offset |= (given & 0x000007ff) << 1;
						offset -= (1 << 20);
						
						info->print_address_func (pc + 4 + offset, info);
					} break;
					case 'B': {
						unsigned int S = (given & 0x04000000u) >> 26;
						unsigned int I1 = (given & 0x00002000u) >> 13;
						unsigned int I2 = (given & 0x00000800u) >> 11;
						unsigned offset = 0;
						offset |= !S << 24;
						offset |= !(I1 ^ S) << 23;
						offset |= !(I2 ^ S) << 22;
						offset |= (given & 0x03ff0000u) >> 4;
						offset |= (given & 0x000007ffu) << 1;
						offset -= (1 << 24);
						offset += pc + 4;
						
						/* BLX target addresses are always word aligned.  */
						if ((given & 0x00001000u) == 0)
							offset &= ~2u;
						
						info->print_address_func (offset, info);
					} break;
					case 's': {
						unsigned int shift = 0;
						
						shift |= (given & 0x000000c0u) >> 6;
						shift |= (given & 0x00007000u) >> 10;
						if (WRITEBACK_BIT_SET)
							func (stream, ", asr #%u", shift);
						else if (shift)
							func (stream, ", lsl #%u", shift);
						/* else print nothing - lsl #0 */
					} break;
					case 'R': {
						unsigned int rot = (given & 0x00000030) >> 4;
						
						if (rot)
							func (stream, ", ror #%u", rot * 8);
					} break;
					case 'U': {
						if ((given & 0xf0) == 0x60) {
							switch (given & 0xf) {
							case 0xf: func (stream, "sy"); break;
							default:
								func (stream, "#%d", (int) given & 0xf);
								break;
							}/* end switch */
						} else {
							const char *opt = data_barrier_option(given & 0xf);
							if (opt != NULL)
								func (stream, "%s", opt);
							else
								func (stream, "#%d", (int) given & 0xf);
						}/* end else */
					} break;
					case 'C': {
						if ((given & 0xff) == 0) {
							func (stream, "%cPSR_", (given & 0x100000) ? 'S' : 'C');
							if (given & 0x800)
								func (stream, "f");
							if (given & 0x400)
								func (stream, "s");
							if (given & 0x200)
								func (stream, "x");
							if (given & 0x100)
								func (stream, "c");
						} else if ((given & 0x20) == 0x20) {
							char const* name;
							unsigned sysm = (given & 0xf00) >> 8;
							
							sysm |= (given & 0x30);
							sysm |= (given & 0x00100000) >> 14;
							name = banked_regname (sysm);
							
							if (name != NULL)
								func (stream, "%s", name);
							else
								func (stream, "(UNDEF: %lu)", (unsigned long) sysm);
						} else {
							func (stream, "%s", psr_name (given & 0xff));
						}/* end else */
					} break;
					case 'D': {
						if (((given & 0xff) == 0) || ((given & 0x20) == 0x20)) {
							char const* name;
							unsigned sm = (given & 0xf0000) >> 16;

							sm |= (given & 0x30);
							sm |= (given & 0x00100000) >> 14;
							name = banked_regname (sm);

							if (name != NULL)
								func (stream, "%s", name);
							else
								func (stream, "(UNDEF: %lu)", (unsigned long) sm);
						} else func (stream, "%s", psr_name (given & 0xff));
					} break;
					case '0': case '1': case '2': case '3': case '4':
					case '5': case '6': case '7': case '8': case '9': {
						int width;
						unsigned long val;

						c = arm_decode_bitfield (c, given, &val, &width);
						
						switch (*c) {
						case 'd': {
							func (stream, "%lu", val);
							value_in_comment = val;
						} break;
						case 'W': {
							func (stream, "%lu", val * 4);
							value_in_comment = val * 4;
						} break;
						case 'S': if (val == 13) is_unpredictable = 1;
						case 'R': if (val == 15) is_unpredictable = 1;
						case 'r': {
							func (stream, "%s", arm_regnames[val]);
						} break;
						case 'c': {
							func (stream, "%s", arm_conditional[val]);
						} break;
						case '\'': {
							c++;
							if (val == ((1ul << width) - 1))
								func (stream, "%c", *c);
						} break;		     
						case '`': {
							c++;
							if (val == 0)
								func (stream, "%c", *c);
						} break;
						case '?': {
							func (stream, "%c", c[(1 << width) - (int) val]);
							c += 1 << width;
						} break;
						case 'x': {
							func (stream, "0x%lx", val & 0xffffffffUL);
						} break;
						default: ERROR_INTERNAL_EXCEPT("disasm failed");
						}/* end switch */
					} break;
					case 'L': {
						/* PR binutils/12534
						   If we have a PC relative offset in an LDRD or STRD
						   instructions then display the decoded address.  */
						if (((given >> 16) & 0xf) == 0xf) {
							unsigned offset = (given & 0xff) * 4;
							
							if ((given & (1 << 23)) == 0)
								offset = - offset;
							func (stream, "\t; ");
							info->print_address_func ((pc & ~3) + 4 + offset, info);
						}/* end if */
					} break;
					default: ERROR_INTERNAL_EXCEPT("disasm failed");
					}/* end switch */
				}/* end for */

				/* 打印注释 */
				if (value_in_comment > 32 || value_in_comment < -16)
					func (stream, "\t; 0x%lx", value_in_comment);
				
				if (is_unpredictable)
					func (stream, UNPREDICTABLE_INSTRUCTION);
				
				return 1;
		}/* end if */
	}/* end for */

	return 0;
}

