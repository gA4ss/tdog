#include "globals.h"
#include "errs.h"
#include "disinfo.h"

/* ARM条件 */
const char *const arm_conditional[] = {
	"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
	"hi", "ls", "ge", "lt", "gt", "le", "al", "<und>", ""
};

const char *const arm_fp_const[] = {
	"0.0", "1.0", "2.0", "3.0", "4.0", "5.0", "0.5", "10.0"
};

const char *const arm_shift[] = {
	"lsl", "lsr", "asr", "ror"
};

const arm_regname regnames[] = {
	{ "raw" , "Select raw register names",
	  { "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}},
	{ "gcc",  "Select register names used by GCC",
	  { "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "sl",  "fp",  "ip",  "sp",  "lr",  "pc" }},
	{ "std",  "Select register names used in ARM's ISA documentation",
	  { "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp",  "lr",  "pc" }},
	{ "apcs", "Select register names used in the APCS",
	  { "a1", "a2", "a3", "a4", "v1", "v2", "v3", "v4", "v5", "v6", "sl",  "fp",  "ip",  "sp",  "lr",  "pc" }},
	{ "atpcs", "Select register names used in the ATPCS",
	  { "a1", "a2", "a3", "a4", "v1", "v2", "v3", "v4", "v5", "v6", "v7",  "v8",  "IP",  "SP",  "LR",  "PC" }},
	{ "special-atpcs", "Select special register names used in the ATPCS",
	  { "a1", "a2", "a3", "a4", "v1", "v2", "v3", "WR", "v5", "SB", "SL",  "FP",  "IP",  "SP",  "LR",  "PC" }},
};

const char *const iwmmxt_wwnames[] = {
	"b", "h", "w", "d"
};

const char *const iwmmxt_wwssnames[] = {
	"b", "bus", "bc", "bss",
	"h", "hus", "hc", "hss",
	"w", "wus", "wc", "wss",
	"d", "dus", "dc", "dss"
};

const char *const iwmmxt_regnames[] = { 
	"wr0", "wr1", "wr2", "wr3", "wr4", "wr5", "wr6", "wr7",
	"wr8", "wr9", "wr10", "wr11", "wr12", "wr13", "wr14", "wr15"
};

const char *const iwmmxt_cregnames[] = { 
	"wcid", "wcon", "wcssf", "wcasf", "reserved", "reserved", "reserved", 
	"reserved", "wcgr0", "wcgr1", "wcgr2", "wcgr3", "reserved", "reserved", 
	"reserved", "reserved"
};

unsigned int regname_selected = 1;                           /* 默认的GCC
															  * 寄存器名称的
															  * 集合 */
unsigned char force_thumb = 0;                               /* 强行开启thumb */
unsigned int ifthen_state;                                   /* 当前的IT状态.
															  * 这个状态与CPSR
															  * 的IT位一样 */
unsigned int ifthen_next_state;                              /* 下一条指令的
															  * IT状态  */
unsigned ifthen_address;                                     /* 地址的IT状态有
															  * 效性 */
/* 寄存器数量 */
int get_arm_regname_num_options (void) {
	return NUM_ARM_REGNAMES;
}

/* 设置寄存器名称集合 */
int set_arm_regname_option (int option) {
	int old = regname_selected;
	regname_selected = option;
	return old;
}

/* 获取寄存器名称的组合 */
int get_arm_regnames(int option,
					 const char **setname,
					 const char **setdescription,
					 const char *const **register_names) {
	*setname = regnames[option].name;
	*setdescription = regnames[option].description;
	*register_names = regnames[option].reg_names;
	return 16;
}

/* 解码一个匹配正则表达式"(N(-N)?,)*N(-N)?"的bitfield
 * 返回一个指向格式化的字符串并且填充 valuep与widthp
 */
const char *arm_decode_bitfield(const char *ptr,
								unsigned long insn,
								unsigned long *valuep,
								int *widthp) {
	unsigned long value = 0;
	int width = 0;
	
	do {
		int start, end;
		int bits;

		/* 遍历转换为数字 */
		for (start = 0; *ptr >= '0' && *ptr <= '9'; ptr++)
			start = start * 10 + *ptr - '0';

		/* 转换结束字符 */
		if (*ptr == '-')
			for (end = 0, ptr++; *ptr >= '0' && *ptr <= '9'; ptr++)
				end = end * 10 + *ptr - '0';
		else
			end = start;/* 结束等于末尾 */
		bits = end - start;/* 计算多少位 */

		/* 如果数量小于0,则发生异常 */
		if (bits < 0)
			ERROR_INTERNAL_EXCEPT("disasm failed");

		/* 累计计算值 */
		value |= ((insn >> start) & ((2ul << bits) - 1)) << width;
		width += bits + 1;
	} while (*ptr++ == ',');     /* 以','隔开 */
	
	/* 输出值与宽度 */
	*valuep = value;
	if (widthp)
		*widthp = width;

	/* 输出字符串的末尾 */
	return ptr - 1;
}

/* 解码位移 指令的低0-11位(总共12位)
 * ARM指令中的第二操作数 
 * 灵活的使用第2个操作数“operand2”能够提高代码效率。它有如下的形式： 
 * #immed_8r——常数表达式； 
 * Rm——寄存器方式； 
 * Rm,shift——寄存器移位方式 
 *
 * ARM指令中的第二操作数 
 * 如果一个32位立即数直接用在32位指令编码中，就有可能完全占据32位指令编码空间。
 * 因此，ARM指令的32位立即数是通过循环右移偶数位得到的。 
 * 立即数是由一个8位的常数循环右移位偶数位得到的。 
 * <immediate>=immed_8循环右移（2×rotate_imm） 
 * 例如：下面的代码段： 
 * MOV R0, #0x0000F200 
 * MOV R1, #0x00110000 
 * MOV R4, #0x00012800 
 * 上面的指令经过汇编之后得到的二进制编码为： 
 * 8000：E3A00CF2 (0xF200是由0xF2循环右移24位得到的) 
 * 8004：E3A01811（0x110000是由0x11循环右移16位得到的） 
 * 8008: E3A04B4A（0x12800是由0下4A循环右移24位得到的） 
 * 非法的立即数：0x1010，0x00102，0xFF1000
 */
void arm_decode_shift(long given, fprintf_ftype func, 
					  void *stream, unsigned char print_shift) {
	func (stream, "%s", arm_regnames[given & 0xf]);

	/* op2不为0 */
	if ((given & 0xff0) != 0) {
		/* 第5位为0 */
		if ((given & 0x10) == 0) {
			int amount = (given & 0xf80) >> 7;
			int shift = (given & 0x60) >> 5;

			if (amount == 0) {
				if (shift == 3) {
					func (stream, ", rrx");
					return;
				}
				amount = 32;
			}/* end if */

			if (print_shift)
				func (stream, ", %s #%d", arm_shift[shift], amount);
			else
				func (stream, ", #%d", amount);
		} else if ((given & 0x80) == 0x80) {
			/* 非法的常数 */
			func (stream, "\t; <illegal shifter operand>");
		} else if (print_shift)
			func (stream, ", %s %s", arm_shift[(given & 0x60) >> 5],
				  arm_regnames[(given & 0xf00) >> 8]);
		else
			func (stream, ", %s", arm_regnames[(given & 0xf00) >> 8]);
	}
}

/* 返回一个 v7A 特定的寄存器名称 */
const char *banked_regname (unsigned reg) {
	switch (reg) {
	case 15: return "CPSR";
	case 32: return "R8_usr"; 
	case 33: return "R9_usr";
	case 34: return "R10_usr";
	case 35: return "R11_usr";
	case 36: return "R12_usr";
	case 37: return "SP_usr";
	case 38: return "LR_usr";
	case 40: return "R8_fiq"; 
	case 41: return "R9_fiq";
	case 42: return "R10_fiq";
	case 43: return "R11_fiq";
	case 44: return "R12_fiq";
	case 45: return "SP_fiq";
	case 46: return "LR_fiq";
	case 48: return "LR_irq";
	case 49: return "SP_irq";
	case 50: return "LR_svc";
	case 51: return "SP_svc";
	case 52: return "LR_abt";
	case 53: return "SP_abt";
	case 54: return "LR_und";
	case 55: return "SP_und";
	case 60: return "LR_mon";
	case 61: return "SP_mon";
	case 62: return "ELR_hyp";
	case 63: return "SP_hyp";
	case 79: return "SPSR";
	case 110: return "SPSR_fiq";
	case 112: return "SPSR_irq";
	case 114: return "SPSR_svc";
	case 116: return "SPSR_abt";
	case 118: return "SPSR_und";
	case 124: return "SPSR_mon";
	case 126: return "SPSR_hyp";
	default: return NULL;
	}
}

/* 返回DMB/DSB选项名称 */
const char *data_barrier_option (unsigned option) {
	switch (option & 0xf) {
	case 0xf: return "sy";
	case 0xe: return "st";
	case 0xd: return "ld";
	case 0xb: return "ish";
	case 0xa: return "ishst";
	case 0x9: return "ishld";
	case 0x7: return "un";
	case 0x6: return "unst";
	case 0x5: return "nshld";
	case 0x3: return "osh";
	case 0x2: return "oshst";
	case 0x1: return "oshld";
	default:  return NULL;
	}
}

/* 返回一个 v7M 特定的寄存器名称 */
const char *psr_name (int regno) {
	switch (regno) {
	case 0: return "APSR";
	case 1: return "IAPSR";
	case 2: return "EAPSR";
	case 3: return "PSR";
	case 5: return "IPSR";
	case 6: return "EPSR";
	case 7: return "IEPSR";
	case 8: return "MSP";
	case 9: return "PSP";
	case 16: return "PRIMASK";
	case 17: return "BASEPRI";
	case 18: return "BASEPRI_MAX";
	case 19: return "FAULTMASK";
	case 20: return "CONTROL";
	default: return "<unknown>";
	}
}
