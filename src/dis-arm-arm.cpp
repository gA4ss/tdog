#include "globals.h"
#include "errs.h"
#include "disinfo.h"


/* Opcode tables: ARM, 16-bit Thumb, 32-bit Thumb.  All three are partially
   ordered: they must be searched linearly from the top to obtain a correct
   match.  */

/* print_insn_arm recognizes the following format control codes:

   %%			%

   %a			print address for ldr/str instruction
   %s                   print address for ldr/str halfword/signextend instruction
   %S                   like %s but allow UNPREDICTABLE addressing
   %b			print branch destination
   %c			print condition code (always bits 28-31)
   %m			print register mask for ldm/stm instruction
   %o			print operand2 (immediate or register + shift)
   %p			print 'p' iff bits 12-15 are 15
   %t			print 't' iff bit 21 set and bit 24 clear
   %B			print arm BLX(1) destination
   %C			print the PSR sub type.
   %U			print barrier type.
   %P			print address for pli instruction.

   %<bitfield>r		print as an ARM register
   %<bitfield>T		print as an ARM register + 1
   %<bitfield>R		as %r but r15 is UNPREDICTABLE
   %<bitfield>{r|R}u    as %{r|R} but if matches the other %u field then is UNPREDICTABLE
   %<bitfield>{r|R}U    as %{r|R} but if matches the other %U field then is UNPREDICTABLE
   %<bitfield>d		print the bitfield in decimal
   %<bitfield>W         print the bitfield plus one in decimal 
   %<bitfield>x		print the bitfield in hex
   %<bitfield>X		print the bitfield as 1 hex digit without leading "0x"
   
   %<bitfield>'c	print specified char iff bitfield is all ones
   %<bitfield>`c	print specified char iff bitfield is all zeroes
   %<bitfield>?ab...    select from array of values in big endian order

   %e                   print arm SMI operand (bits 0..7,8..19).
   %E			print the LSB and WIDTH fields of a BFI or BFC instruction.
   %V                   print the 16-bit immediate field of a MOVT or MOVW instruction.
   %R			print the SPSR/CPSR or banked register of an MRS.  */

const opcode32 arm_opcodes[] = {
	/* ARM instructions.  */
	{ARM_EXT_V1, 0xe1a00000, 0xffffffff, "nop\t\t\t; (mov r0, r0)"},
	{ARM_EXT_V1, 0xe7f000f0, 0xfff000f0, "udf\t#%e"},

	{ARM_EXT_V4T | ARM_EXT_V5, 0x012FFF10, 0x0ffffff0, "bx%c\t%0-3r"},
	{ARM_EXT_V2, 0x00000090, 0x0fe000f0, "mul%20's%c\t%16-19R, %0-3R, %8-11R"},
	{ARM_EXT_V2, 0x00200090, 0x0fe000f0, "mla%20's%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
	{ARM_EXT_V2S, 0x01000090, 0x0fb00ff0, "swp%22'b%c\t%12-15RU, %0-3Ru, [%16-19RuU]"},
	{ARM_EXT_V3M, 0x00800090, 0x0fa000f0, "%22?sumull%20's%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},
	{ARM_EXT_V3M, 0x00a00090, 0x0fa000f0, "%22?sumlal%20's%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},

	/* V8 instructions.  */
	{ARM_EXT_V8,   0x0320f005, 0x0fffffff, "sevl"},
	{ARM_EXT_V8,   0xe1000070, 0xfff000f0, "hlt\t0x%16-19X%12-15X%8-11X%0-3X"},
	{ARM_EXT_V8,	 0x01800e90, 0x0ff00ff0, "stlex%c\t%12-15r, %0-3r, [%16-19R]"},
	{ARM_EXT_V8,	 0x01900e9f, 0x0ff00fff, "ldaex%c\t%12-15r, [%16-19R]"},
	{ARM_EXT_V8,	 0x01a00e90, 0x0ff00ff0, "stlexd%c\t%12-15r, %0-3r, %0-3T, [%16-19R]"},
	{ARM_EXT_V8,	 0x01b00e9f, 0x0ff00fff, "ldaexd%c\t%12-15r, %12-15T, [%16-19R]"},
	{ARM_EXT_V8,	 0x01c00e90, 0x0ff00ff0, "stlexb%c\t%12-15r, %0-3r, [%16-19R]"},
	{ARM_EXT_V8,	 0x01d00e9f, 0x0ff00fff, "ldaexb%c\t%12-15r, [%16-19R]"},
	{ARM_EXT_V8,	 0x01e00e90, 0x0ff00ff0, "stlexh%c\t%12-15r, %0-3r, [%16-19R]"},
	{ARM_EXT_V8,	 0x01f00e9f, 0x0ff00fff, "ldaexh%c\t%12-15r, [%16-19R]"},
	{ARM_EXT_V8,	 0x0180fc90, 0x0ff0fff0, "stl%c\t%0-3r, [%16-19R]"},
	{ARM_EXT_V8,	 0x01900c9f, 0x0ff00fff, "lda%c\t%12-15r, [%16-19R]"},
	{ARM_EXT_V8,	 0x01c0fc90, 0x0ff0fff0, "stlb%c\t%0-3r, [%16-19R]"},
	{ARM_EXT_V8,	 0x01d00c9f, 0x0ff00fff, "ldab%c\t%12-15r, [%16-19R]"},
	{ARM_EXT_V8,	 0x01e0fc90, 0x0ff0fff0, "stlh%c\t%0-3r, [%16-19R]"},
	{ARM_EXT_V8,	 0x01f00c9f, 0x0ff00fff, "ldaexh%c\t%12-15r, [%16-19R]"},
	/* CRC32 instructions.  */
	{CRC_EXT_ARMV8, 0xe1000040, 0xfff00ff0, "crc32b\t%12-15R, %16-19R, %0-3R"},
	{CRC_EXT_ARMV8, 0xe1200040, 0xfff00ff0, "crc32h\t%12-15R, %16-19R, %0-3R"},
	{CRC_EXT_ARMV8, 0xe1400040, 0xfff00ff0, "crc32w\t%12-15R, %16-19R, %0-3R"},
	{CRC_EXT_ARMV8, 0xe1000240, 0xfff00ff0, "crc32cb\t%12-15R, %16-19R, %0-3R"},
	{CRC_EXT_ARMV8, 0xe1200240, 0xfff00ff0, "crc32ch\t%12-15R, %16-19R, %0-3R"},
	{CRC_EXT_ARMV8, 0xe1400240, 0xfff00ff0, "crc32cw\t%12-15R, %16-19R, %0-3R"},

	/* Virtualization Extension instructions.  */
	{ARM_EXT_VIRT, 0x0160006e, 0x0fffffff, "eret%c"},
	{ARM_EXT_VIRT, 0x01400070, 0x0ff000f0, "hvc%c\t%e"},

	/* Integer Divide Extension instructions.  */
	{ARM_EXT_ADIV, 0x0710f010, 0x0ff0f0f0, "sdiv%c\t%16-19r, %0-3r, %8-11r"},
	{ARM_EXT_ADIV, 0x0730f010, 0x0ff0f0f0, "udiv%c\t%16-19r, %0-3r, %8-11r"},

	/* MP Extension instructions.  */
	{ARM_EXT_MP, 0xf410f000, 0xfc70f000, "pldw\t%a"},

	/* V7 instructions.  */
	{ARM_EXT_V7, 0xf450f000, 0xfd70f000, "pli\t%P"},
	{ARM_EXT_V7, 0x0320f0f0, 0x0ffffff0, "dbg%c\t#%0-3d"},
	{ARM_EXT_V8, 0xf57ff051, 0xfffffff3, "dmb\t%U"},
	{ARM_EXT_V8, 0xf57ff041, 0xfffffff3, "dsb\t%U"},
	{ARM_EXT_V7, 0xf57ff050, 0xfffffff0, "dmb\t%U"},
	{ARM_EXT_V7, 0xf57ff040, 0xfffffff0, "dsb\t%U"},
	{ARM_EXT_V7, 0xf57ff060, 0xfffffff0, "isb\t%U"},

	/* ARM V6T2 instructions.  */
	{ARM_EXT_V6T2, 0x07c0001f, 0x0fe0007f, "bfc%c\t%12-15R, %E"},
	{ARM_EXT_V6T2, 0x07c00010, 0x0fe00070, "bfi%c\t%12-15R, %0-3r, %E"},
	{ARM_EXT_V6T2, 0x00600090, 0x0ff000f0, "mls%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
	{ARM_EXT_V6T2, 0x002000b0, 0x0f3000f0, "strht%c\t%12-15R, %S"},

	{ARM_EXT_V6T2, 0x00300090, 0x0f3000f0, UNDEFINED_INSTRUCTION },
	{ARM_EXT_V6T2, 0x00300090, 0x0f300090, "ldr%6's%5?hbt%c\t%12-15R, %S"},
  
	{ARM_EXT_V6T2, 0x03000000, 0x0ff00000, "movw%c\t%12-15R, %V"},
	{ARM_EXT_V6T2, 0x03400000, 0x0ff00000, "movt%c\t%12-15R, %V"},
	{ARM_EXT_V6T2, 0x06ff0f30, 0x0fff0ff0, "rbit%c\t%12-15R, %0-3R"},
	{ARM_EXT_V6T2, 0x07a00050, 0x0fa00070, "%22?usbfx%c\t%12-15r, %0-3r, #%7-11d, #%16-20W"},

	/* ARM Security extension instructions.  */
	{ARM_EXT_SEC, 0x01600070, 0x0ff000f0, "smc%c\t%e"},

	/* ARM V6K instructions.  */
	{ARM_EXT_V6K, 0xf57ff01f, 0xffffffff, "clrex"},
	{ARM_EXT_V6K, 0x01d00f9f, 0x0ff00fff, "ldrexb%c\t%12-15R, [%16-19R]"},
	{ARM_EXT_V6K, 0x01b00f9f, 0x0ff00fff, "ldrexd%c\t%12-15r, [%16-19R]"},
	{ARM_EXT_V6K, 0x01f00f9f, 0x0ff00fff, "ldrexh%c\t%12-15R, [%16-19R]"},
	{ARM_EXT_V6K, 0x01c00f90, 0x0ff00ff0, "strexb%c\t%12-15R, %0-3R, [%16-19R]"},
	{ARM_EXT_V6K, 0x01a00f90, 0x0ff00ff0, "strexd%c\t%12-15R, %0-3r, [%16-19R]"},
	{ARM_EXT_V6K, 0x01e00f90, 0x0ff00ff0, "strexh%c\t%12-15R, %0-3R, [%16-19R]"},

	/* ARM V6K NOP hints.  */
	{ARM_EXT_V6K, 0x0320f001, 0x0fffffff, "yield%c"},
	{ARM_EXT_V6K, 0x0320f002, 0x0fffffff, "wfe%c"},
	{ARM_EXT_V6K, 0x0320f003, 0x0fffffff, "wfi%c"},
	{ARM_EXT_V6K, 0x0320f004, 0x0fffffff, "sev%c"},
	{ARM_EXT_V6K, 0x0320f000, 0x0fffff00, "nop%c\t{%0-7d}"},

	/* ARM V6 instructions.  */
	{ARM_EXT_V6, 0xf1080000, 0xfffffe3f, "cpsie\t%8'a%7'i%6'f"},
	{ARM_EXT_V6, 0xf10a0000, 0xfffffe20, "cpsie\t%8'a%7'i%6'f,#%0-4d"},
	{ARM_EXT_V6, 0xf10C0000, 0xfffffe3f, "cpsid\t%8'a%7'i%6'f"},
	{ARM_EXT_V6, 0xf10e0000, 0xfffffe20, "cpsid\t%8'a%7'i%6'f,#%0-4d"},
	{ARM_EXT_V6, 0xf1000000, 0xfff1fe20, "cps\t#%0-4d"},
	{ARM_EXT_V6, 0x06800010, 0x0ff00ff0, "pkhbt%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06800010, 0x0ff00070, "pkhbt%c\t%12-15R, %16-19R, %0-3R, lsl #%7-11d"},
	{ARM_EXT_V6, 0x06800050, 0x0ff00ff0, "pkhtb%c\t%12-15R, %16-19R, %0-3R, asr #32"},
	{ARM_EXT_V6, 0x06800050, 0x0ff00070, "pkhtb%c\t%12-15R, %16-19R, %0-3R, asr #%7-11d"},
	{ARM_EXT_V6, 0x01900f9f, 0x0ff00fff, "ldrex%c\tr%12-15d, [%16-19R]"},
	{ARM_EXT_V6, 0x06200f10, 0x0ff00ff0, "qadd16%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06200f90, 0x0ff00ff0, "qadd8%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06200f30, 0x0ff00ff0, "qasx%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06200f70, 0x0ff00ff0, "qsub16%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06200ff0, 0x0ff00ff0, "qsub8%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06200f50, 0x0ff00ff0, "qsax%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06100f10, 0x0ff00ff0, "sadd16%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06100f90, 0x0ff00ff0, "sadd8%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06100f30, 0x0ff00ff0, "sasx%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06300f10, 0x0ff00ff0, "shadd16%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06300f90, 0x0ff00ff0, "shadd8%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06300f30, 0x0ff00ff0, "shasx%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06300f70, 0x0ff00ff0, "shsub16%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06300ff0, 0x0ff00ff0, "shsub8%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06300f50, 0x0ff00ff0, "shsax%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06100f70, 0x0ff00ff0, "ssub16%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06100ff0, 0x0ff00ff0, "ssub8%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06100f50, 0x0ff00ff0, "ssax%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06500f10, 0x0ff00ff0, "uadd16%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06500f90, 0x0ff00ff0, "uadd8%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06500f30, 0x0ff00ff0, "uasx%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06700f10, 0x0ff00ff0, "uhadd16%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06700f90, 0x0ff00ff0, "uhadd8%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06700f30, 0x0ff00ff0, "uhasx%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06700f70, 0x0ff00ff0, "uhsub16%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06700ff0, 0x0ff00ff0, "uhsub8%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06700f50, 0x0ff00ff0, "uhsax%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06600f10, 0x0ff00ff0, "uqadd16%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06600f90, 0x0ff00ff0, "uqadd8%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06600f30, 0x0ff00ff0, "uqasx%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06600f70, 0x0ff00ff0, "uqsub16%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06600ff0, 0x0ff00ff0, "uqsub8%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06600f50, 0x0ff00ff0, "uqsax%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06500f70, 0x0ff00ff0, "usub16%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06500ff0, 0x0ff00ff0, "usub8%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06500f50, 0x0ff00ff0, "usax%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0x06bf0f30, 0x0fff0ff0, "rev%c\t%12-15R, %0-3R"},
	{ARM_EXT_V6, 0x06bf0fb0, 0x0fff0ff0, "rev16%c\t%12-15R, %0-3R"},
	{ARM_EXT_V6, 0x06ff0fb0, 0x0fff0ff0, "revsh%c\t%12-15R, %0-3R"},
	{ARM_EXT_V6, 0xf8100a00, 0xfe50ffff, "rfe%23?id%24?ba\t%16-19r%21'!"},
	{ARM_EXT_V6, 0x06bf0070, 0x0fff0ff0, "sxth%c\t%12-15R, %0-3R"},
	{ARM_EXT_V6, 0x06bf0470, 0x0fff0ff0, "sxth%c\t%12-15R, %0-3R, ror #8"},
	{ARM_EXT_V6, 0x06bf0870, 0x0fff0ff0, "sxth%c\t%12-15R, %0-3R, ror #16"},
	{ARM_EXT_V6, 0x06bf0c70, 0x0fff0ff0, "sxth%c\t%12-15R, %0-3R, ror #24"},
	{ARM_EXT_V6, 0x068f0070, 0x0fff0ff0, "sxtb16%c\t%12-15R, %0-3R"},
	{ARM_EXT_V6, 0x068f0470, 0x0fff0ff0, "sxtb16%c\t%12-15R, %0-3R, ror #8"},
	{ARM_EXT_V6, 0x068f0870, 0x0fff0ff0, "sxtb16%c\t%12-15R, %0-3R, ror #16"},
	{ARM_EXT_V6, 0x068f0c70, 0x0fff0ff0, "sxtb16%c\t%12-15R, %0-3R, ror #24"},
	{ARM_EXT_V6, 0x06af0070, 0x0fff0ff0, "sxtb%c\t%12-15R, %0-3R"},
	{ARM_EXT_V6, 0x06af0470, 0x0fff0ff0, "sxtb%c\t%12-15R, %0-3R, ror #8"},
	{ARM_EXT_V6, 0x06af0870, 0x0fff0ff0, "sxtb%c\t%12-15R, %0-3R, ror #16"},
	{ARM_EXT_V6, 0x06af0c70, 0x0fff0ff0, "sxtb%c\t%12-15R, %0-3R, ror #24"},
	{ARM_EXT_V6, 0x06ff0070, 0x0fff0ff0, "uxth%c\t%12-15R, %0-3R"},
	{ARM_EXT_V6, 0x06ff0470, 0x0fff0ff0, "uxth%c\t%12-15R, %0-3R, ror #8"},
	{ARM_EXT_V6, 0x06ff0870, 0x0fff0ff0, "uxth%c\t%12-15R, %0-3R, ror #16"},
	{ARM_EXT_V6, 0x06ff0c70, 0x0fff0ff0, "uxth%c\t%12-15R, %0-3R, ror #24"},
	{ARM_EXT_V6, 0x06cf0070, 0x0fff0ff0, "uxtb16%c\t%12-15R, %0-3R"},
	{ARM_EXT_V6, 0x06cf0470, 0x0fff0ff0, "uxtb16%c\t%12-15R, %0-3R, ror #8"},
	{ARM_EXT_V6, 0x06cf0870, 0x0fff0ff0, "uxtb16%c\t%12-15R, %0-3R, ror #16"},
	{ARM_EXT_V6, 0x06cf0c70, 0x0fff0ff0, "uxtb16%c\t%12-15R, %0-3R, ror #24"},
	{ARM_EXT_V6, 0x06ef0070, 0x0fff0ff0, "uxtb%c\t%12-15R, %0-3R"},
	{ARM_EXT_V6, 0x06ef0470, 0x0fff0ff0, "uxtb%c\t%12-15R, %0-3R, ror #8"},
	{ARM_EXT_V6, 0x06ef0870, 0x0fff0ff0, "uxtb%c\t%12-15R, %0-3R, ror #16"},
	{ARM_EXT_V6, 0x06ef0c70, 0x0fff0ff0, "uxtb%c\t%12-15R, %0-3R, ror #24"},
	{ARM_EXT_V6, 0x06b00070, 0x0ff00ff0, "sxtah%c\t%12-15R, %16-19r, %0-3R"},
	{ARM_EXT_V6, 0x06b00470, 0x0ff00ff0, "sxtah%c\t%12-15R, %16-19r, %0-3R, ror #8"},
	{ARM_EXT_V6, 0x06b00870, 0x0ff00ff0, "sxtah%c\t%12-15R, %16-19r, %0-3R, ror #16"},
	{ARM_EXT_V6, 0x06b00c70, 0x0ff00ff0, "sxtah%c\t%12-15R, %16-19r, %0-3R, ror #24"},
	{ARM_EXT_V6, 0x06800070, 0x0ff00ff0, "sxtab16%c\t%12-15R, %16-19r, %0-3R"},
	{ARM_EXT_V6, 0x06800470, 0x0ff00ff0, "sxtab16%c\t%12-15R, %16-19r, %0-3R, ror #8"},
	{ARM_EXT_V6, 0x06800870, 0x0ff00ff0, "sxtab16%c\t%12-15R, %16-19r, %0-3R, ror #16"},
	{ARM_EXT_V6, 0x06800c70, 0x0ff00ff0, "sxtab16%c\t%12-15R, %16-19r, %0-3R, ror #24"},
	{ARM_EXT_V6, 0x06a00070, 0x0ff00ff0, "sxtab%c\t%12-15R, %16-19r, %0-3R"},
	{ARM_EXT_V6, 0x06a00470, 0x0ff00ff0, "sxtab%c\t%12-15R, %16-19r, %0-3R, ror #8"},
	{ARM_EXT_V6, 0x06a00870, 0x0ff00ff0, "sxtab%c\t%12-15R, %16-19r, %0-3R, ror #16"},
	{ARM_EXT_V6, 0x06a00c70, 0x0ff00ff0, "sxtab%c\t%12-15R, %16-19r, %0-3R, ror #24"},
	{ARM_EXT_V6, 0x06f00070, 0x0ff00ff0, "uxtah%c\t%12-15R, %16-19r, %0-3R"},
	{ARM_EXT_V6, 0x06f00470, 0x0ff00ff0, "uxtah%c\t%12-15R, %16-19r, %0-3R, ror #8"},
	{ARM_EXT_V6, 0x06f00870, 0x0ff00ff0, "uxtah%c\t%12-15R, %16-19r, %0-3R, ror #16"},
	{ARM_EXT_V6, 0x06f00c70, 0x0ff00ff0, "uxtah%c\t%12-15R, %16-19r, %0-3R, ror #24"},
	{ARM_EXT_V6, 0x06c00070, 0x0ff00ff0, "uxtab16%c\t%12-15R, %16-19r, %0-3R"},
	{ARM_EXT_V6, 0x06c00470, 0x0ff00ff0, "uxtab16%c\t%12-15R, %16-19r, %0-3R, ror #8"},
	{ARM_EXT_V6, 0x06c00870, 0x0ff00ff0, "uxtab16%c\t%12-15R, %16-19r, %0-3R, ror #16"},
	{ARM_EXT_V6, 0x06c00c70, 0x0ff00ff0, "uxtab16%c\t%12-15R, %16-19r, %0-3R, ROR #24"},
	{ARM_EXT_V6, 0x06e00070, 0x0ff00ff0, "uxtab%c\t%12-15R, %16-19r, %0-3R"},
	{ARM_EXT_V6, 0x06e00470, 0x0ff00ff0, "uxtab%c\t%12-15R, %16-19r, %0-3R, ror #8"},
	{ARM_EXT_V6, 0x06e00870, 0x0ff00ff0, "uxtab%c\t%12-15R, %16-19r, %0-3R, ror #16"},
	{ARM_EXT_V6, 0x06e00c70, 0x0ff00ff0, "uxtab%c\t%12-15R, %16-19r, %0-3R, ror #24"},
	{ARM_EXT_V6, 0x06800fb0, 0x0ff00ff0, "sel%c\t%12-15R, %16-19R, %0-3R"},
	{ARM_EXT_V6, 0xf1010000, 0xfffffc00, "setend\t%9?ble"},
	{ARM_EXT_V6, 0x0700f010, 0x0ff0f0d0, "smuad%5'x%c\t%16-19R, %0-3R, %8-11R"},
	{ARM_EXT_V6, 0x0700f050, 0x0ff0f0d0, "smusd%5'x%c\t%16-19R, %0-3R, %8-11R"},
	{ARM_EXT_V6, 0x07000010, 0x0ff000d0, "smlad%5'x%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
	{ARM_EXT_V6, 0x07400010, 0x0ff000d0, "smlald%5'x%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},
	{ARM_EXT_V6, 0x07000050, 0x0ff000d0, "smlsd%5'x%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
	{ARM_EXT_V6, 0x07400050, 0x0ff000d0, "smlsld%5'x%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},
	{ARM_EXT_V6, 0x0750f010, 0x0ff0f0d0, "smmul%5'r%c\t%16-19R, %0-3R, %8-11R"},
	{ARM_EXT_V6, 0x07500010, 0x0ff000d0, "smmla%5'r%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
	{ARM_EXT_V6, 0x075000d0, 0x0ff000d0, "smmls%5'r%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
	{ARM_EXT_V6, 0xf84d0500, 0xfe5fffe0, "srs%23?id%24?ba\t%16-19r%21'!, #%0-4d"},
	{ARM_EXT_V6, 0x06a00010, 0x0fe00ff0, "ssat%c\t%12-15R, #%16-20W, %0-3R"},
	{ARM_EXT_V6, 0x06a00010, 0x0fe00070, "ssat%c\t%12-15R, #%16-20W, %0-3R, lsl #%7-11d"},
	{ARM_EXT_V6, 0x06a00050, 0x0fe00070, "ssat%c\t%12-15R, #%16-20W, %0-3R, asr #%7-11d"},
	{ARM_EXT_V6, 0x06a00f30, 0x0ff00ff0, "ssat16%c\t%12-15r, #%16-19W, %0-3r"},
	{ARM_EXT_V6, 0x01800f90, 0x0ff00ff0, "strex%c\t%12-15R, %0-3R, [%16-19R]"},
	{ARM_EXT_V6, 0x00400090, 0x0ff000f0, "umaal%c\t%12-15R, %16-19R, %0-3R, %8-11R"},
	{ARM_EXT_V6, 0x0780f010, 0x0ff0f0f0, "usad8%c\t%16-19R, %0-3R, %8-11R"},
	{ARM_EXT_V6, 0x07800010, 0x0ff000f0, "usada8%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
	{ARM_EXT_V6, 0x06e00010, 0x0fe00ff0, "usat%c\t%12-15R, #%16-20d, %0-3R"},
	{ARM_EXT_V6, 0x06e00010, 0x0fe00070, "usat%c\t%12-15R, #%16-20d, %0-3R, lsl #%7-11d"},
	{ARM_EXT_V6, 0x06e00050, 0x0fe00070, "usat%c\t%12-15R, #%16-20d, %0-3R, asr #%7-11d"},
	{ARM_EXT_V6, 0x06e00f30, 0x0ff00ff0, "usat16%c\t%12-15R, #%16-19d, %0-3R"},

	/* V5J instruction.  */
	{ARM_EXT_V5J, 0x012fff20, 0x0ffffff0, "bxj%c\t%0-3R"},

	/* V5 Instructions.  */
	{ARM_EXT_V5, 0xe1200070, 0xfff000f0, "bkpt\t0x%16-19X%12-15X%8-11X%0-3X"},
	{ARM_EXT_V5, 0xfa000000, 0xfe000000, "blx\t%B"},
	{ARM_EXT_V5, 0x012fff30, 0x0ffffff0, "blx%c\t%0-3R"},
	{ARM_EXT_V5, 0x016f0f10, 0x0fff0ff0, "clz%c\t%12-15R, %0-3R"},

	/* V5E "El Segundo" Instructions.  */    
	{ARM_EXT_V5E, 0x000000d0, 0x0e1000f0, "ldrd%c\t%12-15r, %s"},
	{ARM_EXT_V5E, 0x000000f0, 0x0e1000f0, "strd%c\t%12-15r, %s"},
	{ARM_EXT_V5E, 0xf450f000, 0xfc70f000, "pld\t%a"},
	{ARM_EXT_V5ExP, 0x01000080, 0x0ff000f0, "smlabb%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
	{ARM_EXT_V5ExP, 0x010000a0, 0x0ff000f0, "smlatb%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
	{ARM_EXT_V5ExP, 0x010000c0, 0x0ff000f0, "smlabt%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
	{ARM_EXT_V5ExP, 0x010000e0, 0x0ff000f0, "smlatt%c\t%16-19r, %0-3r, %8-11R, %12-15R"},

	{ARM_EXT_V5ExP, 0x01200080, 0x0ff000f0, "smlawb%c\t%16-19R, %0-3R, %8-11R, %12-15R"},
	{ARM_EXT_V5ExP, 0x012000c0, 0x0ff000f0, "smlawt%c\t%16-19R, %0-3r, %8-11R, %12-15R"},

	{ARM_EXT_V5ExP, 0x01400080, 0x0ff000f0, "smlalbb%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},
	{ARM_EXT_V5ExP, 0x014000a0, 0x0ff000f0, "smlaltb%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},
	{ARM_EXT_V5ExP, 0x014000c0, 0x0ff000f0, "smlalbt%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},
	{ARM_EXT_V5ExP, 0x014000e0, 0x0ff000f0, "smlaltt%c\t%12-15Ru, %16-19Ru, %0-3R, %8-11R"},

	{ARM_EXT_V5ExP, 0x01600080, 0x0ff0f0f0, "smulbb%c\t%16-19R, %0-3R, %8-11R"},
	{ARM_EXT_V5ExP, 0x016000a0, 0x0ff0f0f0, "smultb%c\t%16-19R, %0-3R, %8-11R"},
	{ARM_EXT_V5ExP, 0x016000c0, 0x0ff0f0f0, "smulbt%c\t%16-19R, %0-3R, %8-11R"},
	{ARM_EXT_V5ExP, 0x016000e0, 0x0ff0f0f0, "smultt%c\t%16-19R, %0-3R, %8-11R"},

	{ARM_EXT_V5ExP, 0x012000a0, 0x0ff0f0f0, "smulwb%c\t%16-19R, %0-3R, %8-11R"},
	{ARM_EXT_V5ExP, 0x012000e0, 0x0ff0f0f0, "smulwt%c\t%16-19R, %0-3R, %8-11R"},

	{ARM_EXT_V5ExP, 0x01000050, 0x0ff00ff0,  "qadd%c\t%12-15R, %0-3R, %16-19R"},
	{ARM_EXT_V5ExP, 0x01400050, 0x0ff00ff0, "qdadd%c\t%12-15R, %0-3R, %16-19R"},
	{ARM_EXT_V5ExP, 0x01200050, 0x0ff00ff0,  "qsub%c\t%12-15R, %0-3R, %16-19R"},
	{ARM_EXT_V5ExP, 0x01600050, 0x0ff00ff0, "qdsub%c\t%12-15R, %0-3R, %16-19R"},

	/* ARM Instructions.  */
	{ARM_EXT_V1, 0x052d0004, 0x0fff0fff, "push%c\t{%12-15r}\t\t; (str%c %12-15r, %a)"},
  
	{ARM_EXT_V1, 0x04400000, 0x0e500000, "strb%t%c\t%12-15R, %a"},
	{ARM_EXT_V1, 0x04000000, 0x0e500000, "str%t%c\t%12-15r, %a"},
	{ARM_EXT_V1, 0x06400000, 0x0e500ff0, "strb%t%c\t%12-15R, %a"},
	{ARM_EXT_V1, 0x06000000, 0x0e500ff0, "str%t%c\t%12-15r, %a"},
	{ARM_EXT_V1, 0x04400000, 0x0c500010, "strb%t%c\t%12-15R, %a"},
	{ARM_EXT_V1, 0x04000000, 0x0c500010, "str%t%c\t%12-15r, %a"},
  
	{ARM_EXT_V1, 0x04400000, 0x0e500000, "strb%c\t%12-15R, %a"},
	{ARM_EXT_V1, 0x06400000, 0x0e500010, "strb%c\t%12-15R, %a"},
	{ARM_EXT_V1, 0x004000b0, 0x0e5000f0, "strh%c\t%12-15R, %s"},
	{ARM_EXT_V1, 0x000000b0, 0x0e500ff0, "strh%c\t%12-15R, %s"},

	{ARM_EXT_V1, 0x00500090, 0x0e5000f0, UNDEFINED_INSTRUCTION},
	{ARM_EXT_V1, 0x00500090, 0x0e500090, "ldr%6's%5?hb%c\t%12-15R, %s"},
	{ARM_EXT_V1, 0x00100090, 0x0e500ff0, UNDEFINED_INSTRUCTION},
	{ARM_EXT_V1, 0x00100090, 0x0e500f90, "ldr%6's%5?hb%c\t%12-15R, %s"},

	{ARM_EXT_V1, 0x02000000, 0x0fe00000, "and%20's%c\t%12-15r, %16-19r, %o"},
	{ARM_EXT_V1, 0x00000000, 0x0fe00010, "and%20's%c\t%12-15r, %16-19r, %o"},
	{ARM_EXT_V1, 0x00000010, 0x0fe00090, "and%20's%c\t%12-15R, %16-19R, %o"},

	{ARM_EXT_V1, 0x02200000, 0x0fe00000, "eor%20's%c\t%12-15r, %16-19r, %o"},
	{ARM_EXT_V1, 0x00200000, 0x0fe00010, "eor%20's%c\t%12-15r, %16-19r, %o"},
	{ARM_EXT_V1, 0x00200010, 0x0fe00090, "eor%20's%c\t%12-15R, %16-19R, %o"},

	{ARM_EXT_V1, 0x02400000, 0x0fe00000, "sub%20's%c\t%12-15r, %16-19r, %o"},
	{ARM_EXT_V1, 0x00400000, 0x0fe00010, "sub%20's%c\t%12-15r, %16-19r, %o"},
	{ARM_EXT_V1, 0x00400010, 0x0fe00090, "sub%20's%c\t%12-15R, %16-19R, %o"},

	{ARM_EXT_V1, 0x02600000, 0x0fe00000, "rsb%20's%c\t%12-15r, %16-19r, %o"},
	{ARM_EXT_V1, 0x00600000, 0x0fe00010, "rsb%20's%c\t%12-15r, %16-19r, %o"},
	{ARM_EXT_V1, 0x00600010, 0x0fe00090, "rsb%20's%c\t%12-15R, %16-19R, %o"},

	{ARM_EXT_V1, 0x02800000, 0x0fe00000, "add%20's%c\t%12-15r, %16-19r, %o"},
	{ARM_EXT_V1, 0x00800000, 0x0fe00010, "add%20's%c\t%12-15r, %16-19r, %o"},
	{ARM_EXT_V1, 0x00800010, 0x0fe00090, "add%20's%c\t%12-15R, %16-19R, %o"},

	{ARM_EXT_V1, 0x02a00000, 0x0fe00000, "adc%20's%c\t%12-15r, %16-19r, %o"},
	{ARM_EXT_V1, 0x00a00000, 0x0fe00010, "adc%20's%c\t%12-15r, %16-19r, %o"},
	{ARM_EXT_V1, 0x00a00010, 0x0fe00090, "adc%20's%c\t%12-15R, %16-19R, %o"},

	{ARM_EXT_V1, 0x02c00000, 0x0fe00000, "sbc%20's%c\t%12-15r, %16-19r, %o"},
	{ARM_EXT_V1, 0x00c00000, 0x0fe00010, "sbc%20's%c\t%12-15r, %16-19r, %o"},
	{ARM_EXT_V1, 0x00c00010, 0x0fe00090, "sbc%20's%c\t%12-15R, %16-19R, %o"},

	{ARM_EXT_V1, 0x02e00000, 0x0fe00000, "rsc%20's%c\t%12-15r, %16-19r, %o"},
	{ARM_EXT_V1, 0x00e00000, 0x0fe00010, "rsc%20's%c\t%12-15r, %16-19r, %o"},
	{ARM_EXT_V1, 0x00e00010, 0x0fe00090, "rsc%20's%c\t%12-15R, %16-19R, %o"},

	{ARM_EXT_VIRT, 0x0120f200, 0x0fb0f200, "msr%c\t%C, %0-3r"},
	{ARM_EXT_V3, 0x0120f000, 0x0db0f000, "msr%c\t%C, %o"},
	{ARM_EXT_V3, 0x01000000, 0x0fb00cff, "mrs%c\t%12-15R, %R"},

	{ARM_EXT_V1, 0x03000000, 0x0fe00000, "tst%p%c\t%16-19r, %o"},
	{ARM_EXT_V1, 0x01000000, 0x0fe00010, "tst%p%c\t%16-19r, %o"},
	{ARM_EXT_V1, 0x01000010, 0x0fe00090, "tst%p%c\t%16-19R, %o"},

	{ARM_EXT_V1, 0x03200000, 0x0fe00000, "teq%p%c\t%16-19r, %o"},
	{ARM_EXT_V1, 0x01200000, 0x0fe00010, "teq%p%c\t%16-19r, %o"},
	{ARM_EXT_V1, 0x01200010, 0x0fe00090, "teq%p%c\t%16-19R, %o"},

	{ARM_EXT_V1, 0x03400000, 0x0fe00000, "cmp%p%c\t%16-19r, %o"},
	{ARM_EXT_V1, 0x01400000, 0x0fe00010, "cmp%p%c\t%16-19r, %o"},
	{ARM_EXT_V1, 0x01400010, 0x0fe00090, "cmp%p%c\t%16-19R, %o"},

	{ARM_EXT_V1, 0x03600000, 0x0fe00000, "cmn%p%c\t%16-19r, %o"},
	{ARM_EXT_V1, 0x01600000, 0x0fe00010, "cmn%p%c\t%16-19r, %o"},
	{ARM_EXT_V1, 0x01600010, 0x0fe00090, "cmn%p%c\t%16-19R, %o"},

	{ARM_EXT_V1, 0x03800000, 0x0fe00000, "orr%20's%c\t%12-15r, %16-19r, %o"},
	{ARM_EXT_V1, 0x01800000, 0x0fe00010, "orr%20's%c\t%12-15r, %16-19r, %o"},
	{ARM_EXT_V1, 0x01800010, 0x0fe00090, "orr%20's%c\t%12-15R, %16-19R, %o"},

	{ARM_EXT_V1, 0x03a00000, 0x0fef0000, "mov%20's%c\t%12-15r, %o"},
	{ARM_EXT_V1, 0x01a00000, 0x0def0ff0, "mov%20's%c\t%12-15r, %0-3r"},
	{ARM_EXT_V1, 0x01a00000, 0x0def0060, "lsl%20's%c\t%12-15R, %q"},
	{ARM_EXT_V1, 0x01a00020, 0x0def0060, "lsr%20's%c\t%12-15R, %q"},
	{ARM_EXT_V1, 0x01a00040, 0x0def0060, "asr%20's%c\t%12-15R, %q"},
	{ARM_EXT_V1, 0x01a00060, 0x0def0ff0, "rrx%20's%c\t%12-15r, %0-3r"},
	{ARM_EXT_V1, 0x01a00060, 0x0def0060, "ror%20's%c\t%12-15R, %q"},

	{ARM_EXT_V1, 0x03c00000, 0x0fe00000, "bic%20's%c\t%12-15r, %16-19r, %o"},
	{ARM_EXT_V1, 0x01c00000, 0x0fe00010, "bic%20's%c\t%12-15r, %16-19r, %o"},
	{ARM_EXT_V1, 0x01c00010, 0x0fe00090, "bic%20's%c\t%12-15R, %16-19R, %o"},

	{ARM_EXT_V1, 0x03e00000, 0x0fe00000, "mvn%20's%c\t%12-15r, %o"},
	{ARM_EXT_V1, 0x01e00000, 0x0fe00010, "mvn%20's%c\t%12-15r, %o"},
	{ARM_EXT_V1, 0x01e00010, 0x0fe00090, "mvn%20's%c\t%12-15R, %o"},

	{ARM_EXT_V1, 0x06000010, 0x0e000010, UNDEFINED_INSTRUCTION},
	{ARM_EXT_V1, 0x049d0004, 0x0fff0fff, "pop%c\t{%12-15r}\t\t; (ldr%c %12-15r, %a)"},
  
	{ARM_EXT_V1, 0x04500000, 0x0c500000, "ldrb%t%c\t%12-15R, %a"},

	{ARM_EXT_V1, 0x04300000, 0x0d700000, "ldrt%c\t%12-15R, %a"},
	{ARM_EXT_V1, 0x04100000, 0x0c500000, "ldr%c\t%12-15r, %a"},
  
	{ARM_EXT_V1, 0x092d0001, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x092d0002, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x092d0004, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x092d0008, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x092d0010, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x092d0020, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x092d0040, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x092d0080, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x092d0100, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x092d0200, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x092d0400, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x092d0800, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x092d1000, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x092d2000, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x092d4000, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x092d8000, 0x0fffffff, "stmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x092d0000, 0x0fff0000, "push%c\t%m"},
	{ARM_EXT_V1, 0x08800000, 0x0ff00000, "stm%c\t%16-19R%21'!, %m%22'^"},
	{ARM_EXT_V1, 0x08000000, 0x0e100000, "stm%23?id%24?ba%c\t%16-19R%21'!, %m%22'^"},

	{ARM_EXT_V1, 0x08bd0001, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x08bd0002, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x08bd0004, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x08bd0008, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x08bd0010, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x08bd0020, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x08bd0040, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x08bd0080, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x08bd0100, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x08bd0200, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x08bd0400, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x08bd0800, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x08bd1000, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x08bd2000, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x08bd4000, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x08bd8000, 0x0fffffff, "ldmfd%c\t%16-19R!, %m"},
	{ARM_EXT_V1, 0x08bd0000, 0x0fff0000, "pop%c\t%m"},
	{ARM_EXT_V1, 0x08900000, 0x0f900000, "ldm%c\t%16-19R%21'!, %m%22'^"},
	{ARM_EXT_V1, 0x08100000, 0x0e100000, "ldm%23?id%24?ba%c\t%16-19R%21'!, %m%22'^"},

	{ARM_EXT_V1, 0x0a000000, 0x0e000000, "b%24'l%c\t%b"},
	{ARM_EXT_V1, 0x0f000000, 0x0f000000, "svc%c\t%0-23x"},

	/* The rest.  */
	{ARM_EXT_V1, 0x00000000, 0x00000000, UNDEFINED_INSTRUCTION},
	{0, 0x00000000, 0x00000000, 0}
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

/* 解码然后打印ARM地址模式.返回在地址中使用的偏移 */
static signed long print_arm_address(unsigned pc, 
									 disassemble_info *info, 
									 long given) {
	void *stream = info->stream;
	fprintf_ftype func = info->fprintf_func;
	unsigned offset = 0;
	
	if (((given & 0x000f0000) == 0x000f0000)
		&& ((given & 0x02000000) == 0)) {
		offset = given & 0xfff;
		
		func (stream, "[pc");
			
		if (PRE_BIT_SET) {
			/* Pre-indexed.  Elide offset of positive zero when
			   non-writeback.  */
			if (WRITEBACK_BIT_SET || NEGATIVE_BIT_SET || offset)
				func (stream, ", #%s%d", NEGATIVE_BIT_SET ? "-" : "", (int) offset);
			
			if (NEGATIVE_BIT_SET)
				offset = -offset;
			
			offset += pc + 8;

			/* Cope with the possibility of write-back
			   being used.  Probably a very dangerous thing
			   for the programmer to do, but who are we to
			   argue ?  */
			func (stream, "]%s", WRITEBACK_BIT_SET ? "!" : "");
		} else {
			func (stream, "], #%s%d", NEGATIVE_BIT_SET ? "-" : "", (int) offset);
			
			/* Ie ignore the offset.  */
			offset = pc + 8;
		}
		
		func (stream, "\t; ");
		info->print_address_func (offset, info);
		offset = 0;
	} else {
		func (stream, "[%s",
			  arm_regnames[(given >> 16) & 0xf]);
		
		if (PRE_BIT_SET) {
			if ((given & 0x02000000) == 0) {
				/* Elide offset of positive zero when non-writeback.  */
				offset = given & 0xfff;
				if (WRITEBACK_BIT_SET || NEGATIVE_BIT_SET || offset)
					func (stream, ", #%s%d", NEGATIVE_BIT_SET ? "-" : "", (int) offset);
			} else {
				func (stream, ", %s", NEGATIVE_BIT_SET ? "-" : "");
				arm_decode_shift (given, func, stream, 1);
			}
			
			func (stream, "]%s", WRITEBACK_BIT_SET ? "!" : "");
		} else {
			if ((given & 0x02000000) == 0) {
				/* Always show offset.  */
				offset = given & 0xfff;
				func (stream, "], #%s%d",
					  NEGATIVE_BIT_SET ? "-" : "", (int) offset);
			} else {
				func (stream, "], %s",
					  NEGATIVE_BIT_SET ? "-" : "");
				arm_decode_shift (given, func, stream, 1);
			}
		}
		if (NEGATIVE_BIT_SET)
			offset = -offset;
	}
	
	return (signed long) offset;
}

/* 反汇编一条ARM指令 */
unsigned char print_insn_arm(unsigned pc, 
							 void *pinfo, 
							 long given, 
							 unsigned char thumb) {
	UNUSED(thumb);
	disassemble_info *info = (disassemble_info*)pinfo;
	const opcode32 *insn;
	void *stream = info->stream;
	fprintf_ftype func = info->fprintf_func;
	arm_private_data *private_data = (arm_private_data *)info->private_data;
	
	/* 打印协处理器指令 */
	if (print_insn_coprocessor(pc, pinfo, given, 0))
		return 1;
	
	if (print_insn_neon(pc, pinfo, given, 0))
		return 1;
	
	for (insn = arm_opcodes; insn->assembler; insn++) {
		/* 指令不匹配 */
		if ((given & insn->mask) != insn->value)
			continue;
		
		/* 架构不符合 */
		if ((insn->arch & private_data->features.core) == 0)
			continue;
	  
		/* Special case: an instruction with all bits set 
		   in the condition field(0xFnnn_nnnn) is only matched if all 
		   those bits are set in insn->mask,
		   or by the catchall at the end of the table.  */
		if ((given & 0xF0000000) != 0xF0000000
			|| (insn->mask & 0xF0000000) == 0xF0000000
			|| (insn->mask == 0 && insn->value == 0)) {
			unsigned long u_reg = 16;
			unsigned long U_reg = 16;
			unsigned char is_unpredictable = 0;
			signed long value_in_comment = 0;
			const char *c;
					
			for (c = insn->assembler; *c; c++) {
				if (*c == '%') {
					unsigned char allow_unpredictable = 0;
									
					switch (*++c) {
					case '%': {
						func (stream, "%%");
					} break;
					case 'a': {
						value_in_comment = 
							print_arm_address(pc, 
											  info, 
											  given);
					} break;
					case 'P': {
						/* Set P address bit and use normal address
						   printing routine.  */
						value_in_comment = print_arm_address (pc, info, given | (1 << P_BIT));
					} break;
					case 'S': allow_unpredictable = 1;
					case 's': {
						if ((given & 0x004f0000) == 0x004f0000) {
							/* PC相对立即数偏移 */
							unsigned offset = ((given & 0xf00) >> 4) | (given & 0xf);

							if (PRE_BIT_SET) {
								/* Elide positive zero offset.  */
								if (offset || NEGATIVE_BIT_SET)
									func (stream, "[pc, #%s%d]\t; ",
										  NEGATIVE_BIT_SET ? "-" : "", (int) offset);
								else
									func (stream, "[pc]\t; ");
								if (NEGATIVE_BIT_SET)
									offset = -offset;
								info->print_address_func (offset + pc + 8, info);
							} else {
								/* 总是显示偏移 */
								func (stream, "[pc], #%s%d",
									  NEGATIVE_BIT_SET ? "-" : "", (int) offset);
								if (! allow_unpredictable)
									is_unpredictable = 1;
							}/* end else */
						} else {
							int offset = ((given & 0xf00) >> 4) | (given & 0xf);
							func(stream, "[%s", arm_regnames[(given >> 16) & 0xf]);
							if (PRE_BIT_SET) {
								if (IMMEDIATE_BIT_SET) {
									/* Elide offset for non-writeback
									   positive zero.  */
									if (WRITEBACK_BIT_SET || NEGATIVE_BIT_SET || offset)
										func (stream, ", #%s%d",
											  NEGATIVE_BIT_SET ? "-" : "", offset);
									
									if (NEGATIVE_BIT_SET)
										offset = -offset;
									
									value_in_comment = offset;
								} else {
									/* Register Offset or Register Pre-Indexed.  */
									func (stream, ", %s%s",
										  NEGATIVE_BIT_SET ? "-" : "",
										  arm_regnames[given & 0xf]);
									
									/* Writing back to the register that is the source/
									   destination of the load/store is unpredictable.  */
									if (! allow_unpredictable
										&& WRITEBACK_BIT_SET
										&& ((given & 0xf) == ((given >> 12) & 0xf)))
										is_unpredictable = 1;
								}/* end else */
								
								func (stream, "]%s", WRITEBACK_BIT_SET ? "!" : "");
							} else {
								if (IMMEDIATE_BIT_SET) {
									/* Immediate Post-indexed.  */
									/* PR 10924: Offset must be printed, even if it is zero.  */
									func (stream, "], #%s%d", NEGATIVE_BIT_SET ? "-" : "", offset);
									if (NEGATIVE_BIT_SET)
										offset = -offset;
									value_in_comment = offset;
								} else {
									/* Register Post-indexed.  */
									func (stream, "], %s%s",
										  NEGATIVE_BIT_SET ? "-" : "",
										  arm_regnames[given & 0xf]);

									/* Writing back to the register that is the source/
									   destination of the load/store is unpredictable.  */
									if (! allow_unpredictable
										&& (given & 0xf) == ((given >> 12) & 0xf))
										is_unpredictable = 1;
								}/* end else */

								if (! allow_unpredictable) {
									/* Writeback is automatically implied by post- addressing.
									   Setting the W bit is unnecessary and ARM specify it as
									   being unpredictable.  */
									if (WRITEBACK_BIT_SET
										/* Specifying the PC register as the post-indexed
										   registers is also unpredictable.  */
										|| (! IMMEDIATE_BIT_SET && ((given & 0xf) == 0xf)))
										is_unpredictable = 1;
								}/* end if */
							}/* end else */
						}
					} break;
					case 'b': {
						unsigned disp = (((given & 0xffffff) ^ 0x800000) - 0x800000);
						info->print_address_func (disp * 4 + pc + 8, info);
					} break;
					case 'c': {
						if (((given >> 28) & 0xf) != 0xe)
							func (stream, "%s",
								  arm_conditional [(given >> 28) & 0xf]);
					} break;
					case 'm': {
						int started = 0;
						int reg;
							
						func (stream, "{");
						for (reg = 0; reg < 16; reg++)
							if ((given & (1 << reg)) != 0) {
								if (started)
									func (stream, ", ");
								started = 1;
								func (stream, "%s", arm_regnames[reg]);
							}
						func (stream, "}");
						if (! started)
							is_unpredictable = 1;
					} break;
					case 'q': {
						arm_decode_shift (given, func, stream, 0);
					} break;
					case 'o': {
						if ((given & 0x02000000) != 0) {
							unsigned int rotate = (given & 0xf00) >> 7;
							unsigned int immed = (given & 0xff);
							unsigned int a, i;
								
							a = (((immed << (32 - rotate)) | (immed >> rotate)) & 0xffffffff);
							/* If there is another encoding with smaller rotate,
							   the rotate should be specified directly.  */
							for (i = 0; i < 32; i += 2)
								if ((a << i | a >> (32 - i)) <= 0xff)
									break;

							if (i != rotate)
								func (stream, "#%d, %d", immed, rotate);
							else
								func (stream, "#%d", a);
							value_in_comment = a;
						} else {
							arm_decode_shift (given, func, stream, 1);
						}/* end else */
					} break;
					case 'p': {
						if ((given & 0x0000f000) == 0x0000f000) {
							/* The p-variants of tst/cmp/cmn/teq are the pre-V6
							   mechanism for setting PSR flag bits.  They are
							   obsolete in V6 onwards.  */
							if ((private_data->features.core & ARM_EXT_V6) == 0)
								func (stream, "p");
						}
					} break;
					case 't': {
						if ((given & 0x01200000) == 0x00200000)
							func (stream, "t");
					} break;
					case 'A': {
						int offset = given & 0xff;
						
						value_in_comment = offset * 4;
						if (NEGATIVE_BIT_SET)
							value_in_comment = - value_in_comment;
						
						func (stream, "[%s", arm_regnames [(given >> 16) & 0xf]);
						
						if (PRE_BIT_SET) {
							if (offset)
								func (stream, ", #%d]%s",
									  (int) value_in_comment,
									  WRITEBACK_BIT_SET ? "!" : "");
							else
								func (stream, "]");
						} else {
							func (stream, "]");
							
							if (WRITEBACK_BIT_SET) {
								if (offset)
									func (stream, ", #%d", (int) value_in_comment);
							} else {
								func (stream, ", {%d}", (int) offset);
								value_in_comment = offset;
							}/* end else */
						}/* end else */
					} break;
					case 'B': {
						/* Print ARM V5 BLX(1) address: pc+25 bits.  */
						unsigned address;
						unsigned offset = 0;

						if (! NEGATIVE_BIT_SET) {
							/* Is signed, hi bits should be ones.  */
							offset = (-1) ^ 0x00ffffff;
						}

						/* Offset is (SignExtend(offset field)<<2).  */
						offset += given & 0x00ffffff;
						offset <<= 2;
						address = offset + pc + 8;

						if (given & 0x01000000) {
							/* H bit allows addressing to 2-byte boundaries.  */
							address += 2;
						}

						info->print_address_func (address, info);
					} break;
					case 'C': {
						if ((given & 0x02000200) == 0x200) {
							const char * name;
							unsigned sysm = (given & 0x004f0000) >> 16;
							
							sysm |= (given & 0x300) >> 4;
							name = banked_regname (sysm);

							if (name != NULL)
								func (stream, "%s", name);
							else
								func (stream, "(UNDEF: %lu)", (unsigned long) sysm);
						} else {
							func (stream, "%cPSR_", 
								  (given & 0x00400000) ? 'S' : 'C');
							if (given & 0x80000)
								func (stream, "f");
							if (given & 0x40000)
								func (stream, "s");
							if (given & 0x20000)
								func (stream, "x");
							if (given & 0x10000)
								func (stream, "c");
						} 
					} break;
					case 'U': {
						if ((given & 0xf0) == 0x60) {
							switch (given & 0xf) {
							case 0xf: func (stream, "sy"); break;
							default:
								func (stream, "#%d", (int) given & 0xf);
								break;
							}
						} else {
							const char * opt = data_barrier_option (given & 0xf);
							if (opt != NULL)
								func (stream, "%s", opt);
							else
								func (stream, "#%d", (int) given & 0xf);
						}
					} break;
					case '0': case '1': case '2': case '3': case '4':
					case '5': case '6': case '7': case '8': case '9': {
						int width;
						unsigned long value;

						c = arm_decode_bitfield (c, given, &value, &width);
							
						switch (*c) {
						case 'R': if (value == 15) is_unpredictable = 1;
						case 'r':
						case 'T': {
							/* We want register + 1 when decoding T.  */
							if (*c == 'T')
								++value;

							if (c[1] == 'u') {
								/* Eat the 'u' character.  */
								++ c;
									
								if (u_reg == value)
									is_unpredictable = 1;
								u_reg = value;
							}
							if (c[1] == 'U') {
								/* Eat the 'U' character.  */
								++ c;
									
								if (U_reg == value)
									is_unpredictable = 1;
								U_reg = value;
							}
							func (stream, "%s", arm_regnames[value]);
						} break;
						case 'd': {
							func (stream, "%ld", value);
							value_in_comment = value;
						} break;
						case 'b': {
							func (stream, "%ld", value * 8);
							value_in_comment = value * 8;
						} break;
						case 'W': {
							func (stream, "%ld", value + 1);
							value_in_comment = value + 1;
						} break;
						case 'x': {
							func (stream, "0x%08lx", value);

							/* Some SWI instructions have special
							   meanings.  */
							if ((given & 0x0fffffff) == 0x0FF00000)
								func (stream, "\t; IMB");
							else if ((given & 0x0fffffff) == 0x0FF00001)
								func (stream, "\t; IMBRange");
						} break;
						case 'X': {
							func (stream, "%01lx", value & 0xf);
							value_in_comment = value;
						} break;
						case '`': {
							c++;
							if (value == 0)
								func (stream, "%c", *c);
						} break;
						case '\'': {
							c++;
							if (value == ((1ul << width) - 1))
								func (stream, "%c", *c);
						} break;
						case '?': {
							func (stream, "%c", c[(1 << width) - (int) value]);
							c += 1 << width;
						} break;
						default: ERROR_INTERNAL_EXCEPT("disasm failed");
						}/* end switch */
					} break;
					case 'e': {
						int imm;
							
						imm = (given & 0xf) | ((given & 0xfff00) >> 4);
						func (stream, "%d", imm);
						value_in_comment = imm;
					} break;
					case 'E': {
						/* LSB and WIDTH fields of BFI or BFC.  The machine-
						   language instruction encodes LSB and MSB.  */
						long msb = (given & 0x001f0000) >> 16;
						long lsb = (given & 0x00000f80) >> 7;
						long w = msb - lsb + 1;
							
						if (w > 0)
							func (stream, "#%lu, #%lu", lsb, w);
						else
							func (stream, "(invalid: %lu:%lu)", lsb, msb);
					} break;
					case 'R': {
						/* Get the PSR/banked register name.  */
						const char * name;
						unsigned sysm = (given & 0x004f0000) >> 16;
							
						sysm |= (given & 0x300) >> 4;
						name = banked_regname (sysm);

						if (name != NULL)
							func (stream, "%s", name);
						else
							func (stream, "(UNDEF: %lu)", (unsigned long) sysm);
					} break;
					case 'V': {
						/* 16-bit unsigned immediate from a MOVT or MOVW
						   instruction, encoded in bits 0:11 and 15:19.  */
						long hi = (given & 0x000f0000) >> 4;
						long lo = (given & 0x00000fff);
						long imm16 = hi | lo;
							
						func (stream, "#%lu", imm16);
						value_in_comment = imm16;
					} break;
					default: ERROR_INTERNAL_EXCEPT("disasm failed");
					}/* end switch */
				} else {
					func (stream, "%c", *c);
				}
			}/* end for */

			/* 打印注释 */
			if (value_in_comment > 32 || value_in_comment < -16)
				func (stream, "\t; 0x%lx", (value_in_comment & 0xffffffffUL));
			
			if (is_unpredictable)
				func (stream, UNPREDICTABLE_INSTRUCTION);

			return 1;
		}/* end if */
	}/* end for */
	ERROR_INTERNAL_EXCEPT("disasm failed");
	return 0;
}
