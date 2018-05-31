#include "globals.h"
#include "errs.h"
#include "disinfo.h"

/* print_insn_thumb16 recognizes the following format control codes:

   %S                   print Thumb register (bits 3..5 as high number if bit 6 set)
   %D                   print Thumb register (bits 0..2 as high number if bit 7 set)
   %<bitfield>I         print bitfield as a signed decimal
   (top bit of range being the sign bit)
   %N                   print Thumb register mask (with LR)
   %O                   print Thumb register mask (with PC)
   %M                   print Thumb register mask
   %b			print CZB's 6-bit unsigned branch destination
   %s			print Thumb right-shift immediate (6..10; 0 == 32).
   %c			print the condition code
   %C			print the condition code, or "s" if not conditional
   %x			print warning if conditional an not at end of IT block"
   %X			print "\t; unpredictable <IT:code>" if conditional
   %I			print IT instruction suffix and operands
   %W			print Thumb Writeback indicator for LDMIA
   %<bitfield>r		print bitfield as an ARM register
   %<bitfield>d		print bitfield as a decimal
   %<bitfield>H         print (bitfield * 2) as a decimal
   %<bitfield>W         print (bitfield * 4) as a decimal
   %<bitfield>a         print (bitfield * 4) as a pc-rel offset + decoded symbol
   %<bitfield>B         print Thumb branch destination (signed displacement)
   %<bitfield>c         print bitfield as a condition code
   %<bitnum>'c		print specified char iff bit is one
   %<bitnum>?ab		print a if bit is one else print b.  */

const opcode16 thumb_opcodes[] = {

	/* Thumb instructions.  */

	/* ARM V8 instructions.  */
	{ARM_EXT_V8,  0xbf50, 0xffff, "sevl%c"},
	{ARM_EXT_V8,  0xba80, 0xffc0, "hlt\t%0-5x"},

	/* ARM V6K no-argument instructions.  */
	{ARM_EXT_V6K, 0xbf00, 0xffff, "nop%c"},
	{ARM_EXT_V6K, 0xbf10, 0xffff, "yield%c"},
	{ARM_EXT_V6K, 0xbf20, 0xffff, "wfe%c"},
	{ARM_EXT_V6K, 0xbf30, 0xffff, "wfi%c"},
	{ARM_EXT_V6K, 0xbf40, 0xffff, "sev%c"},
	{ARM_EXT_V6K, 0xbf00, 0xff0f, "nop%c\t{%4-7d}"},

	/* ARM V6T2 instructions.  */
	{ARM_EXT_V6T2, 0xb900, 0xfd00, "cbnz\t%0-2r, %b%X"},
	{ARM_EXT_V6T2, 0xb100, 0xfd00, "cbz\t%0-2r, %b%X"},
	{ARM_EXT_V6T2, 0xbf00, 0xff00, "it%I%X"},

	/* ARM V6.  */
	{ARM_EXT_V6, 0xb660, 0xfff8, "cpsie\t%2'a%1'i%0'f%X"},
	{ARM_EXT_V6, 0xb670, 0xfff8, "cpsid\t%2'a%1'i%0'f%X"},
	{ARM_EXT_V6, 0x4600, 0xffc0, "mov%c\t%0-2r, %3-5r"},
	{ARM_EXT_V6, 0xba00, 0xffc0, "rev%c\t%0-2r, %3-5r"},
	{ARM_EXT_V6, 0xba40, 0xffc0, "rev16%c\t%0-2r, %3-5r"},
	{ARM_EXT_V6, 0xbac0, 0xffc0, "revsh%c\t%0-2r, %3-5r"},
	{ARM_EXT_V6, 0xb650, 0xfff7, "setend\t%3?ble%X"},
	{ARM_EXT_V6, 0xb200, 0xffc0, "sxth%c\t%0-2r, %3-5r"},
	{ARM_EXT_V6, 0xb240, 0xffc0, "sxtb%c\t%0-2r, %3-5r"},
	{ARM_EXT_V6, 0xb280, 0xffc0, "uxth%c\t%0-2r, %3-5r"},
	{ARM_EXT_V6, 0xb2c0, 0xffc0, "uxtb%c\t%0-2r, %3-5r"},

	/* ARM V5 ISA extends Thumb.  */
	{ARM_EXT_V5T, 0xbe00, 0xff00, "bkpt\t%0-7x"}, /* Is always unconditional.  */
	/* This is BLX(2).  BLX(1) is a 32-bit instruction.  */
	{ARM_EXT_V5T, 0x4780, 0xff87, "blx%c\t%3-6r%x"},	/* note: 4 bit register number.  */
	/* ARM V4T ISA (Thumb v1).  */
	{ARM_EXT_V4T, 0x46C0, 0xFFFF, "nop%c\t\t\t; (mov r8, r8)"},
	/* Format 4.  */
	{ARM_EXT_V4T, 0x4000, 0xFFC0, "and%C\t%0-2r, %3-5r"},
	{ARM_EXT_V4T, 0x4040, 0xFFC0, "eor%C\t%0-2r, %3-5r"},
	{ARM_EXT_V4T, 0x4080, 0xFFC0, "lsl%C\t%0-2r, %3-5r"},
	{ARM_EXT_V4T, 0x40C0, 0xFFC0, "lsr%C\t%0-2r, %3-5r"},
	{ARM_EXT_V4T, 0x4100, 0xFFC0, "asr%C\t%0-2r, %3-5r"},
	{ARM_EXT_V4T, 0x4140, 0xFFC0, "adc%C\t%0-2r, %3-5r"},
	{ARM_EXT_V4T, 0x4180, 0xFFC0, "sbc%C\t%0-2r, %3-5r"},
	{ARM_EXT_V4T, 0x41C0, 0xFFC0, "ror%C\t%0-2r, %3-5r"},
	{ARM_EXT_V4T, 0x4200, 0xFFC0, "tst%c\t%0-2r, %3-5r"},
	{ARM_EXT_V4T, 0x4240, 0xFFC0, "neg%C\t%0-2r, %3-5r"},
	{ARM_EXT_V4T, 0x4280, 0xFFC0, "cmp%c\t%0-2r, %3-5r"},
	{ARM_EXT_V4T, 0x42C0, 0xFFC0, "cmn%c\t%0-2r, %3-5r"},
	{ARM_EXT_V4T, 0x4300, 0xFFC0, "orr%C\t%0-2r, %3-5r"},
	{ARM_EXT_V4T, 0x4340, 0xFFC0, "mul%C\t%0-2r, %3-5r"},
	{ARM_EXT_V4T, 0x4380, 0xFFC0, "bic%C\t%0-2r, %3-5r"},
	{ARM_EXT_V4T, 0x43C0, 0xFFC0, "mvn%C\t%0-2r, %3-5r"},
	/* format 13 */
	{ARM_EXT_V4T, 0xB000, 0xFF80, "add%c\tsp, #%0-6W"},
	{ARM_EXT_V4T, 0xB080, 0xFF80, "sub%c\tsp, #%0-6W"},
	/* format 5 */
	{ARM_EXT_V4T, 0x4700, 0xFF80, "bx%c\t%S%x"},
	{ARM_EXT_V4T, 0x4400, 0xFF00, "add%c\t%D, %S"},
	{ARM_EXT_V4T, 0x4500, 0xFF00, "cmp%c\t%D, %S"},
	{ARM_EXT_V4T, 0x4600, 0xFF00, "mov%c\t%D, %S"},
	/* format 14 */
	{ARM_EXT_V4T, 0xB400, 0xFE00, "push%c\t%N"},
	{ARM_EXT_V4T, 0xBC00, 0xFE00, "pop%c\t%O"},
	/* format 2 */
	{ARM_EXT_V4T, 0x1800, 0xFE00, "add%C\t%0-2r, %3-5r, %6-8r"},
	{ARM_EXT_V4T, 0x1A00, 0xFE00, "sub%C\t%0-2r, %3-5r, %6-8r"},
	{ARM_EXT_V4T, 0x1C00, 0xFE00, "add%C\t%0-2r, %3-5r, #%6-8d"},
	{ARM_EXT_V4T, 0x1E00, 0xFE00, "sub%C\t%0-2r, %3-5r, #%6-8d"},
	/* format 8 */
	{ARM_EXT_V4T, 0x5200, 0xFE00, "strh%c\t%0-2r, [%3-5r, %6-8r]"},
	{ARM_EXT_V4T, 0x5A00, 0xFE00, "ldrh%c\t%0-2r, [%3-5r, %6-8r]"},
	{ARM_EXT_V4T, 0x5600, 0xF600, "ldrs%11?hb%c\t%0-2r, [%3-5r, %6-8r]"},
	/* format 7 */
	{ARM_EXT_V4T, 0x5000, 0xFA00, "str%10'b%c\t%0-2r, [%3-5r, %6-8r]"},
	{ARM_EXT_V4T, 0x5800, 0xFA00, "ldr%10'b%c\t%0-2r, [%3-5r, %6-8r]"},
	/* format 1 */
	{ARM_EXT_V4T, 0x0000, 0xFFC0, "mov%C\t%0-2r, %3-5r"},
	{ARM_EXT_V4T, 0x0000, 0xF800, "lsl%C\t%0-2r, %3-5r, #%6-10d"},
	{ARM_EXT_V4T, 0x0800, 0xF800, "lsr%C\t%0-2r, %3-5r, %s"},
	{ARM_EXT_V4T, 0x1000, 0xF800, "asr%C\t%0-2r, %3-5r, %s"},
	/* format 3 */
	{ARM_EXT_V4T, 0x2000, 0xF800, "mov%C\t%8-10r, #%0-7d"},
	{ARM_EXT_V4T, 0x2800, 0xF800, "cmp%c\t%8-10r, #%0-7d"},
	{ARM_EXT_V4T, 0x3000, 0xF800, "add%C\t%8-10r, #%0-7d"},
	{ARM_EXT_V4T, 0x3800, 0xF800, "sub%C\t%8-10r, #%0-7d"},
	/* format 6 */
	{ARM_EXT_V4T, 0x4800, 0xF800, "ldr%c\t%8-10r, [pc, #%0-7W]\t; (%0-7a)"},  /* TODO: Disassemble PC relative "LDR rD,=<symbolic>" */
	/* format 9 */
	{ARM_EXT_V4T, 0x6000, 0xF800, "str%c\t%0-2r, [%3-5r, #%6-10W]"},
	{ARM_EXT_V4T, 0x6800, 0xF800, "ldr%c\t%0-2r, [%3-5r, #%6-10W]"},
	{ARM_EXT_V4T, 0x7000, 0xF800, "strb%c\t%0-2r, [%3-5r, #%6-10d]"},
	{ARM_EXT_V4T, 0x7800, 0xF800, "ldrb%c\t%0-2r, [%3-5r, #%6-10d]"},
	/* format 10 */
	{ARM_EXT_V4T, 0x8000, 0xF800, "strh%c\t%0-2r, [%3-5r, #%6-10H]"},
	{ARM_EXT_V4T, 0x8800, 0xF800, "ldrh%c\t%0-2r, [%3-5r, #%6-10H]"},
	/* format 11 */
	{ARM_EXT_V4T, 0x9000, 0xF800, "str%c\t%8-10r, [sp, #%0-7W]"},
	{ARM_EXT_V4T, 0x9800, 0xF800, "ldr%c\t%8-10r, [sp, #%0-7W]"},
	/* format 12 */
	{ARM_EXT_V4T, 0xA000, 0xF800, "add%c\t%8-10r, pc, #%0-7W\t; (adr %8-10r, %0-7a)"},
	{ARM_EXT_V4T, 0xA800, 0xF800, "add%c\t%8-10r, sp, #%0-7W"},
	/* format 15 */
	{ARM_EXT_V4T, 0xC000, 0xF800, "stmia%c\t%8-10r!, %M"},
	{ARM_EXT_V4T, 0xC800, 0xF800, "ldmia%c\t%8-10r%W, %M"},
	/* format 17 */
	{ARM_EXT_V4T, 0xDF00, 0xFF00, "svc%c\t%0-7d"},
	/* format 16 */
	{ARM_EXT_V4T, 0xDE00, 0xFF00, "udf%c\t#%0-7d"},
	{ARM_EXT_V4T, 0xDE00, 0xFE00, UNDEFINED_INSTRUCTION},
	{ARM_EXT_V4T, 0xD000, 0xF000, "b%8-11c.n\t%0-7B%X"},
	/* format 18 */
	{ARM_EXT_V4T, 0xE000, 0xF800, "b%c.n\t%0-10B%x"},

	/* The E800 .. FFFF range is unconditionally redirected to the
	   32-bit table, because even in pre-V6T2 ISAs, BL and BLX(1) pairs
	   are processed via that table.  Thus, we can never encounter a
	   bare "second half of BL/BLX(1)" instruction here.  */
	{ARM_EXT_V1,  0x0000, 0x0000, UNDEFINED_INSTRUCTION},
	{0, 0, 0, 0}
};

unsigned char print_insn_thumb16(unsigned pc, 
								 void *pinfo, 
								 long given, 
								 unsigned char thumb) {
	UNUSED(thumb);
	disassemble_info *info = (disassemble_info*)pinfo;
	const opcode16 *insn;
	void *stream = info->stream;
	fprintf_ftype func = info->fprintf_func;

	for (insn = thumb_opcodes; insn->assembler; insn++)
		/* 匹配指令 */
		if ((given & insn->mask) == insn->value) {
			signed long value_in_comment = 0;
			const char *c = insn->assembler;

			for (; *c; c++) {
				int domaskpc = 0;
				int domasklr = 0;
				
				if (*c != '%') {
					func (stream, "%c", *c);
					continue;
				}

				/* 匹配字符 */
				switch (*++c) {
				case '%': {
					func (stream, "%%");
				} break;
				case 'c': {
					if (ifthen_state)
						func (stream, "%s", arm_conditional[IFTHEN_COND]);
				} break;
				case 'C': {
					if (ifthen_state)
						func (stream, "%s", arm_conditional[IFTHEN_COND]);
					else
						func (stream, "s");
				} break;
				case 'I': {
					unsigned int tmp;
					
					ifthen_next_state = given & 0xff;
					for (tmp = given << 1; tmp & 0xf; tmp <<= 1)
						func (stream, ((given ^ tmp) & 0x10) ? "e" : "t");
					func (stream, "\t%s", arm_conditional[(given >> 4) & 0xf]);
				} break;
				case 'x': {
					if (ifthen_next_state)
						func (stream, "\t; unpredictable branch in IT block\n");
				} break;
				case 'X': {
					if (ifthen_state)
						func (stream, "\t; unpredictable <IT:%s>",
							  arm_conditional[IFTHEN_COND]);
				} break;
				case 'S': {
					long reg;
					
					reg = (given >> 3) & 0x7;
					if (given & (1 << 6))
						reg += 8;
					
					func (stream, "%s", arm_regnames[reg]);
				} break;
				case 'D': {
					long reg;
					
					reg = given & 0x7;
					if (given & (1 << 7))
						reg += 8;
					
					func (stream, "%s", arm_regnames[reg]);
				} break;
				case 'N': if (given & (1 << 8)) domasklr = 1;
				case 'O': if (*c == 'O' && (given & (1 << 8))) domaskpc = 1;
				case 'M': {
					int started = 0;
					int reg;
					
					func (stream, "{");

					/* It would be nice if we could spot
					   ranges, and generate the rS-rE format: */
					for (reg = 0; (reg < 8); reg++) {
						if ((given & (1 << reg)) != 0) {
							if (started)
								func (stream, ", ");
							started = 1;
							func (stream, "%s", arm_regnames[reg]);
						}/* end if */
					}/* end for */

					if (domasklr) {
						if (started)
							func (stream, ", ");
						started = 1;
						func (stream, "%s", arm_regnames[14] /* "lr" */);
					}/* end if */
					if (domaskpc) {
						if (started)
							func (stream, ", ");
						func (stream, "%s", arm_regnames[15] /* "pc" */);
					}/* end if */

					func (stream, "}");
				} break;
				case 'W': {
					/* Print writeback indicator for a LDMIA.  We are doing a
					   writeback if the base register is not in the register
					   mask.  */
					if ((given & (1 << ((given & 0x0700) >> 8))) == 0)
						func (stream, "!");
				} break;
				case 'b': {
					/* Print ARM V6T2 CZB address: pc+4+6 bits.  */
					unsigned address = (pc + 4
										+ ((given & 0x00f8) >> 2)
										+ ((given & 0x0200) >> 3));
					info->print_address_func (address, info);
				} break;
				case 's': {
					/* Right shift immediate -- bits 6..10; 1-31 print
					   as themselves, 0 prints as 32.  */
					long imm = (given & 0x07c0) >> 6;
					if (imm == 0)
						imm = 32;
					func (stream, "#%ld", imm);
				} break;
				case '0': case '1': case '2': case '3': case '4':
				case '5': case '6': case '7': case '8': case '9': {
					int bitstart = *c++ - '0';
					int bitend = 0;

					while (*c >= '0' && *c <= '9')
						bitstart = (bitstart * 10) + *c++ - '0';
					
					switch (*c) {
					case '-': {
						unsigned reg;
						c++;
						while (*c >= '0' && *c <= '9')
							bitend = (bitend * 10) + *c++ - '0';
						if (!bitend)
							ERROR_INTERNAL_EXCEPT("disasm failed");
						reg = given >> bitstart;
						reg &= (2 << (bitend - bitstart)) - 1;
						
						switch (*c) {
						case 'r': {
							func (stream, "%s", arm_regnames[reg]);
						} break;
						case 'd': {
							func (stream, "%ld", (long) reg);
							value_in_comment = reg;
						} break;
						case 'H': {
							func (stream, "%ld", (long) (reg << 1));
							value_in_comment = reg << 1;
						} break;
						case 'W': {
							func (stream, "%ld", (long) (reg << 2));
							value_in_comment = reg << 2;
						} break;
						case 'a': {
							/* PC-relative address -- the bottom two
							   bits of the address are dropped
							   before the calculation.  */
							info->print_address_func
								(((pc + 4) & ~3) + (reg << 2), info);
							value_in_comment = 0;
						} break;
						case 'x': {
							func (stream, "0x%04lx", (long) reg);
						} break;
						case 'B': {
							reg = ((reg ^ (1 << bitend)) - (1 << bitend));
							info->print_address_func (reg * 2 + pc + 4, info);
							value_in_comment = 0;
						} break;
						case 'c': {
							func (stream, "%s", arm_conditional [reg]);
						} break;
						default: ERROR_INTERNAL_EXCEPT("disasm failed");
						}/* end switch */
					} break;
					case '\'': {
						c++;
						if ((given & (1 << bitstart)) != 0)
							func (stream, "%c", *c);
					} break;
					case '?': {
						++c;
						if ((given & (1 << bitstart)) != 0)
							func (stream, "%c", *c++);
						else
							func (stream, "%c", *++c);
					} break;
					default: ERROR_INTERNAL_EXCEPT("disasm failed");
					}/* end switch */
				} break;
				default: ERROR_INTERNAL_EXCEPT("disasm failed");
				}/* end switch */
			}/* end for */

			/* 注释 */
			if (value_in_comment > 32 || value_in_comment < -16)
				func (stream, "\t; 0x%lx", value_in_comment);
			return 1;
		}
	
	/* 不匹配 */
	ERROR_INTERNAL_EXCEPT("disasm failed");
	return 0;
}

