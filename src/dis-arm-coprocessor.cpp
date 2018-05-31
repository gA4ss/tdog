#include "globals.h"
#include "errs.h"
#include "disinfo.h"
/* 协处理器的解码
 *
 * %%			%
 *
 * %c			条件代码(所有在28-31位在ARM模式, condition code)
 * %q			移动者参数(shifter argument)
 * %u			条件代码(无条件指令,在ARM模式,不可预料的,如果不是AL在Thumb模式)
 * %A			遇到ldc/stc/ldf/stf,打印地址
 * %B			打印vstm/vldm寄存器列表
 * %I           打印cirrus无符号移位 立即数: 7位 0..3|4..6
 * %F			打印一条LFM/SFM指令的COUNT区域
 * %P			打印浮点数精度在算数指令
 * %Q			打印浮点数在ldf/stf指令
 * %R			打印浮点数在rounding模式
 *
 * %<bitfield>c		打印作为条件代码(for vsel)
 * %<bitfield>r		打印一个ARM寄存器
 * %<bitfield>R		作为 %<>r 使用,但是r15无法预料的
 * %<bitfield>ru    作为 %<>r 使用,每个 u 寄存器必须是唯一的
 * %<bitfield>d		以10进制打印bitfield
 * %<bitfield>k		打印VFPv3指令的立即数
 * %<bitfield>x		以16进制打印bitfield
 * %<bitfield>X		以16进制打印bitfield,但是没有前缀"0x"
 * %<bitfield>f		如果>7打印浮点数常量或者打印一个浮点寄存器
 * %<bitfield>w     打印iWMMXt宽度域 - [bhwd]ss/us
 * %<bitfield>g     打印一个iWMMXt 64位寄存器
 * %<bitfield>G     打印一个iWMMXt通常的目的或者是作为控制寄存器
 * %<bitfield>D		打印一个NEON D寄存器
 * %<bitfield>Q		打印一个NEON Q寄存器
 *
 * %<bitfield>'c	打印指定的字符，如果bitfield全部是1
 * %<bitfield>`c	打印指定的字符，如果bitfield全部是0
 * %<bitfield>?ab... 在大端字序从值队列中选择
 *
 * %y<code>		    打印一个单精度VFP寄存器
 * Codes: 0=>Sm, 1=>Sd, 2=>Sn, 3=>multi-list, 4=>Sm pair
 * %z<code>		    打印一个双精度VFP寄存器
 * Codes: 0=>Dm, 1=>Dd, 2=>Dn, 3=>multi-list
 * 
 * %L			    打印作为一个iWMMXt N/M 宽度域
 * %Z			    打印WSHUFH指令的立即数
 * %l			    like 'A' except use byte offsets for 'B' & 'H' versions.
 * %i			    打印5位的立即数在位8,3..0(当是0时打印'32')
 * %r			    遇到wldr/wstr指令打印寄存器偏移地址
 */

/* Arm - Thumb-2之间共享的通常协处理器opcode */
static const opcode32 coprocessor_opcodes[] = {
	/* XScale instructions. */
	{ARM_CEXT_XSCALE, 0x0e200010, 0x0fff0ff0, "mia%c\tacc0, %0-3r, %12-15r"},
	{ARM_CEXT_XSCALE, 0x0e280010, 0x0fff0ff0, "miaph%c\tacc0, %0-3r, %12-15r"},
	{ARM_CEXT_XSCALE, 0x0e2c0010, 0x0ffc0ff0, "mia%17'T%17`B%16'T%16`B%c\tacc0, %0-3r, %12-15r"},
	{ARM_CEXT_XSCALE, 0x0c400000, 0x0ff00fff, "mar%c\tacc0, %12-15r, %16-19r"},
	{ARM_CEXT_XSCALE, 0x0c500000, 0x0ff00fff, "mra%c\t%12-15r, %16-19r, acc0"},

	/* Intel Wireless MMX technology instructions. */
	{ 0, SENTINEL_IWMMXT_START, 0, "" },
	{ARM_CEXT_IWMMXT, 0x0e130130, 0x0f3f0fff, "tandc%22-23w%c\t%12-15r"},
	{ARM_CEXT_XSCALE, 0x0e400010, 0x0ff00f3f, "tbcst%6-7w%c\t%16-19g, %12-15r"},
	{ARM_CEXT_XSCALE, 0x0e130170, 0x0f3f0ff8, "textrc%22-23w%c\t%12-15r, #%0-2d"},
	{ARM_CEXT_XSCALE, 0x0e100070, 0x0f300ff0, "textrm%3?su%22-23w%c\t%12-15r, %16-19g, #%0-2d"},
	{ARM_CEXT_XSCALE, 0x0e600010, 0x0ff00f38, "tinsr%6-7w%c\t%16-19g, %12-15r, #%0-2d"},
	{ARM_CEXT_XSCALE, 0x0e000110, 0x0ff00fff, "tmcr%c\t%16-19G, %12-15r"},
	{ARM_CEXT_XSCALE, 0x0c400000, 0x0ff00ff0, "tmcrr%c\t%0-3g, %12-15r, %16-19r"},
	{ARM_CEXT_XSCALE, 0x0e2c0010, 0x0ffc0e10, "tmia%17?tb%16?tb%c\t%5-8g, %0-3r, %12-15r"},
	{ARM_CEXT_XSCALE, 0x0e200010, 0x0fff0e10, "tmia%c\t%5-8g, %0-3r, %12-15r"},
	{ARM_CEXT_XSCALE, 0x0e280010, 0x0fff0e10, "tmiaph%c\t%5-8g, %0-3r, %12-15r"},
	{ARM_CEXT_XSCALE, 0x0e100030, 0x0f300fff, "tmovmsk%22-23w%c\t%12-15r, %16-19g"},
	{ARM_CEXT_XSCALE, 0x0e100110, 0x0ff00ff0, "tmrc%c\t%12-15r, %16-19G"},
	{ARM_CEXT_XSCALE, 0x0c500000, 0x0ff00ff0, "tmrrc%c\t%12-15r, %16-19r, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e130150, 0x0f3f0fff, "torc%22-23w%c\t%12-15r"},
	{ARM_CEXT_XSCALE, 0x0e120190, 0x0f3f0fff, "torvsc%22-23w%c\t%12-15r"},
	{ARM_CEXT_XSCALE, 0x0e2001c0, 0x0f300fff, "wabs%22-23w%c\t%12-15g, %16-19g"},
	{ARM_CEXT_XSCALE, 0x0e0001c0, 0x0f300fff, "wacc%22-23w%c\t%12-15g, %16-19g"},
	{ARM_CEXT_XSCALE, 0x0e000180, 0x0f000ff0, "wadd%20-23w%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e2001a0, 0x0fb00ff0, "waddbhus%22?ml%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0ea001a0, 0x0ff00ff0, "waddsubhx%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e000020, 0x0f800ff0, "waligni%c\t%12-15g, %16-19g, %0-3g, #%20-22d"},
	{ARM_CEXT_XSCALE, 0x0e800020, 0x0fc00ff0, "walignr%20-21d%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e200000, 0x0fe00ff0, "wand%20'n%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e800000, 0x0fa00ff0, "wavg2%22?hb%20'r%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e400000, 0x0fe00ff0, "wavg4%20'r%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e000060, 0x0f300ff0, "wcmpeq%22-23w%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e100060, 0x0f100ff0, "wcmpgt%21?su%22-23w%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0xfc500100, 0xfe500f00, "wldrd\t%12-15g, %r"},
	{ARM_CEXT_XSCALE, 0xfc100100, 0xfe500f00, "wldrw\t%12-15G, %A"},
	{ARM_CEXT_XSCALE, 0x0c100000, 0x0e100e00, "wldr%L%c\t%12-15g, %l"},
	{ARM_CEXT_XSCALE, 0x0e400100, 0x0fc00ff0, "wmac%21?su%20'z%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e800100, 0x0fc00ff0, "wmadd%21?su%20'x%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0ec00100, 0x0fd00ff0, "wmadd%21?sun%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e000160, 0x0f100ff0, "wmax%21?su%22-23w%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e000080, 0x0f100fe0, "wmerge%c\t%12-15g, %16-19g, %0-3g, #%21-23d"},
	{ARM_CEXT_XSCALE, 0x0e0000a0, 0x0f800ff0, "wmia%21?tb%20?tb%22'n%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e800120, 0x0f800ff0, "wmiaw%21?tb%20?tb%22'n%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e100160, 0x0f100ff0, "wmin%21?su%22-23w%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e000100, 0x0fc00ff0, "wmul%21?su%20?ml%23'r%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0ed00100, 0x0fd00ff0, "wmul%21?sumr%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0ee000c0, 0x0fe00ff0, "wmulwsm%20`r%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0ec000c0, 0x0fe00ff0, "wmulwum%20`r%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0eb000c0, 0x0ff00ff0, "wmulwl%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e8000a0, 0x0f800ff0, "wqmia%21?tb%20?tb%22'n%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e100080, 0x0fd00ff0, "wqmulm%21'r%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0ec000e0, 0x0fd00ff0, "wqmulwm%21'r%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e000000, 0x0ff00ff0, "wor%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e000080, 0x0f000ff0, "wpack%20-23w%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0xfe300040, 0xff300ef0, "wror%22-23w\t%12-15g, %16-19g, #%i"},
	{ARM_CEXT_XSCALE, 0x0e300040, 0x0f300ff0, "wror%22-23w%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e300140, 0x0f300ff0, "wror%22-23wg%c\t%12-15g, %16-19g, %0-3G"},
	{ARM_CEXT_XSCALE, 0x0e000120, 0x0fa00ff0, "wsad%22?hb%20'z%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e0001e0, 0x0f000ff0, "wshufh%c\t%12-15g, %16-19g, #%Z"},
	{ARM_CEXT_XSCALE, 0xfe100040, 0xff300ef0, "wsll%22-23w\t%12-15g, %16-19g, #%i"},
	{ARM_CEXT_XSCALE, 0x0e100040, 0x0f300ff0, "wsll%22-23w%8'g%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e100148, 0x0f300ffc, "wsll%22-23w%8'g%c\t%12-15g, %16-19g, %0-3G"},
	{ARM_CEXT_XSCALE, 0xfe000040, 0xff300ef0, "wsra%22-23w\t%12-15g, %16-19g, #%i"},
	{ARM_CEXT_XSCALE, 0x0e000040, 0x0f300ff0, "wsra%22-23w%8'g%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e000148, 0x0f300ffc, "wsra%22-23w%8'g%c\t%12-15g, %16-19g, %0-3G"},
	{ARM_CEXT_XSCALE, 0xfe200040, 0xff300ef0, "wsrl%22-23w\t%12-15g, %16-19g, #%i"},
	{ARM_CEXT_XSCALE, 0x0e200040, 0x0f300ff0, "wsrl%22-23w%8'g%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e200148, 0x0f300ffc, "wsrl%22-23w%8'g%c\t%12-15g, %16-19g, %0-3G"},
	{ARM_CEXT_XSCALE, 0xfc400100, 0xfe500f00, "wstrd\t%12-15g, %r"},
	{ARM_CEXT_XSCALE, 0xfc000100, 0xfe500f00, "wstrw\t%12-15G, %A"},
	{ARM_CEXT_XSCALE, 0x0c000000, 0x0e100e00, "wstr%L%c\t%12-15g, %l"},
	{ARM_CEXT_XSCALE, 0x0e0001a0, 0x0f000ff0, "wsub%20-23w%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0ed001c0, 0x0ff00ff0, "wsubaddhx%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e1001c0, 0x0f300ff0, "wabsdiff%22-23w%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e0000c0, 0x0fd00fff, "wunpckeh%21?sub%c\t%12-15g, %16-19g"},
	{ARM_CEXT_XSCALE, 0x0e4000c0, 0x0fd00fff, "wunpckeh%21?suh%c\t%12-15g, %16-19g"},
	{ARM_CEXT_XSCALE, 0x0e8000c0, 0x0fd00fff, "wunpckeh%21?suw%c\t%12-15g, %16-19g"},
	{ARM_CEXT_XSCALE, 0x0e0000e0, 0x0f100fff, "wunpckel%21?su%22-23w%c\t%12-15g, %16-19g"},
	{ARM_CEXT_XSCALE, 0x0e1000c0, 0x0f300ff0, "wunpckih%22-23w%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e1000e0, 0x0f300ff0, "wunpckil%22-23w%c\t%12-15g, %16-19g, %0-3g"},
	{ARM_CEXT_XSCALE, 0x0e100000, 0x0ff00ff0, "wxor%c\t%12-15g, %16-19g, %0-3g"},
	{ 0, SENTINEL_IWMMXT_END, 0, "" },

	/* Floating point coprocessor (FPA) instructions.  */
	{FPU_FPA_EXT_V1, 0x0e000100, 0x0ff08f10, "adf%c%P%R\t%12-14f, %16-18f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0e100100, 0x0ff08f10, "muf%c%P%R\t%12-14f, %16-18f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0e200100, 0x0ff08f10, "suf%c%P%R\t%12-14f, %16-18f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0e300100, 0x0ff08f10, "rsf%c%P%R\t%12-14f, %16-18f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0e400100, 0x0ff08f10, "dvf%c%P%R\t%12-14f, %16-18f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0e500100, 0x0ff08f10, "rdf%c%P%R\t%12-14f, %16-18f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0e600100, 0x0ff08f10, "pow%c%P%R\t%12-14f, %16-18f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0e700100, 0x0ff08f10, "rpw%c%P%R\t%12-14f, %16-18f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0e800100, 0x0ff08f10, "rmf%c%P%R\t%12-14f, %16-18f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0e900100, 0x0ff08f10, "fml%c%P%R\t%12-14f, %16-18f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0ea00100, 0x0ff08f10, "fdv%c%P%R\t%12-14f, %16-18f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0eb00100, 0x0ff08f10, "frd%c%P%R\t%12-14f, %16-18f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0ec00100, 0x0ff08f10, "pol%c%P%R\t%12-14f, %16-18f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0e008100, 0x0ff08f10, "mvf%c%P%R\t%12-14f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0e108100, 0x0ff08f10, "mnf%c%P%R\t%12-14f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0e208100, 0x0ff08f10, "abs%c%P%R\t%12-14f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0e308100, 0x0ff08f10, "rnd%c%P%R\t%12-14f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0e408100, 0x0ff08f10, "sqt%c%P%R\t%12-14f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0e508100, 0x0ff08f10, "log%c%P%R\t%12-14f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0e608100, 0x0ff08f10, "lgn%c%P%R\t%12-14f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0e708100, 0x0ff08f10, "exp%c%P%R\t%12-14f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0e808100, 0x0ff08f10, "sin%c%P%R\t%12-14f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0e908100, 0x0ff08f10, "cos%c%P%R\t%12-14f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0ea08100, 0x0ff08f10, "tan%c%P%R\t%12-14f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0eb08100, 0x0ff08f10, "asn%c%P%R\t%12-14f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0ec08100, 0x0ff08f10, "acs%c%P%R\t%12-14f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0ed08100, 0x0ff08f10, "atn%c%P%R\t%12-14f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0ee08100, 0x0ff08f10, "urd%c%P%R\t%12-14f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0ef08100, 0x0ff08f10, "nrm%c%P%R\t%12-14f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0e000110, 0x0ff00f1f, "flt%c%P%R\t%16-18f, %12-15r"},
	{FPU_FPA_EXT_V1, 0x0e100110, 0x0fff0f98, "fix%c%R\t%12-15r, %0-2f"},
	{FPU_FPA_EXT_V1, 0x0e200110, 0x0fff0fff, "wfs%c\t%12-15r"},
	{FPU_FPA_EXT_V1, 0x0e300110, 0x0fff0fff, "rfs%c\t%12-15r"},
	{FPU_FPA_EXT_V1, 0x0e400110, 0x0fff0fff, "wfc%c\t%12-15r"},
	{FPU_FPA_EXT_V1, 0x0e500110, 0x0fff0fff, "rfc%c\t%12-15r"},
	{FPU_FPA_EXT_V1, 0x0e90f110, 0x0ff8fff0, "cmf%c\t%16-18f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0eb0f110, 0x0ff8fff0, "cnf%c\t%16-18f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0ed0f110, 0x0ff8fff0, "cmfe%c\t%16-18f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0ef0f110, 0x0ff8fff0, "cnfe%c\t%16-18f, %0-3f"},
	{FPU_FPA_EXT_V1, 0x0c000100, 0x0e100f00, "stf%c%Q\t%12-14f, %A"},
	{FPU_FPA_EXT_V1, 0x0c100100, 0x0e100f00, "ldf%c%Q\t%12-14f, %A"},
	{FPU_FPA_EXT_V2, 0x0c000200, 0x0e100f00, "sfm%c\t%12-14f, %F, %A"},
	{FPU_FPA_EXT_V2, 0x0c100200, 0x0e100f00, "lfm%c\t%12-14f, %F, %A"},

	/* Register load/store.  */
	{FPU_VFP_EXT_V1xD | FPU_NEON_EXT_V1, 0x0d2d0b00, 0x0fbf0f01, "vpush%c\t%B"},
	{FPU_VFP_EXT_V1xD | FPU_NEON_EXT_V1, 0x0d200b00, 0x0fb00f01, "vstmdb%c\t%16-19r!, %B"},
	{FPU_VFP_EXT_V1xD | FPU_NEON_EXT_V1, 0x0d300b00, 0x0fb00f01, "vldmdb%c\t%16-19r!, %B"},
	{FPU_VFP_EXT_V1xD | FPU_NEON_EXT_V1, 0x0c800b00, 0x0f900f01, "vstmia%c\t%16-19r%21'!, %B"},
	{FPU_VFP_EXT_V1xD | FPU_NEON_EXT_V1, 0x0cbd0b00, 0x0fbf0f01, "vpop%c\t%B"},
	{FPU_VFP_EXT_V1xD | FPU_NEON_EXT_V1, 0x0c900b00, 0x0f900f01, "vldmia%c\t%16-19r%21'!, %B"},
	{FPU_VFP_EXT_V1xD | FPU_NEON_EXT_V1, 0x0d000b00, 0x0f300f00, "vstr%c\t%12-15,22D, %A"},
	{FPU_VFP_EXT_V1xD | FPU_NEON_EXT_V1, 0x0d100b00, 0x0f300f00, "vldr%c\t%12-15,22D, %A"},
	{FPU_VFP_EXT_V1xD, 0x0d2d0a00, 0x0fbf0f00, "vpush%c\t%y3"},
	{FPU_VFP_EXT_V1xD, 0x0d200a00, 0x0fb00f00, "vstmdb%c\t%16-19r!, %y3"},
	{FPU_VFP_EXT_V1xD, 0x0d300a00, 0x0fb00f00, "vldmdb%c\t%16-19r!, %y3"},
	{FPU_VFP_EXT_V1xD, 0x0c800a00, 0x0f900f00, "vstmia%c\t%16-19r%21'!, %y3"},
	{FPU_VFP_EXT_V1xD, 0x0cbd0a00, 0x0fbf0f00, "vpop%c\t%y3"},
	{FPU_VFP_EXT_V1xD, 0x0c900a00, 0x0f900f00, "vldmia%c\t%16-19r%21'!, %y3"},
	{FPU_VFP_EXT_V1xD, 0x0d000a00, 0x0f300f00, "vstr%c\t%y1, %A"},
	{FPU_VFP_EXT_V1xD, 0x0d100a00, 0x0f300f00, "vldr%c\t%y1, %A"},

	{FPU_VFP_EXT_V1xD, 0x0d200b01, 0x0fb00f01, "fstmdbx%c\t%16-19r!, %z3\t;@ Deprecated"},
	{FPU_VFP_EXT_V1xD, 0x0d300b01, 0x0fb00f01, "fldmdbx%c\t%16-19r!, %z3\t;@ Deprecated"},
	{FPU_VFP_EXT_V1xD, 0x0c800b01, 0x0f900f01, "fstmiax%c\t%16-19r%21'!, %z3\t;@ Deprecated"},
	{FPU_VFP_EXT_V1xD, 0x0c900b01, 0x0f900f01, "fldmiax%c\t%16-19r%21'!, %z3\t;@ Deprecated"},

	/* Data transfer between ARM and NEON registers.  */
	{FPU_NEON_EXT_V1, 0x0e800b10, 0x0ff00f70, "vdup%c.32\t%16-19,7D, %12-15r"},
	{FPU_NEON_EXT_V1, 0x0e800b30, 0x0ff00f70, "vdup%c.16\t%16-19,7D, %12-15r"},
	{FPU_NEON_EXT_V1, 0x0ea00b10, 0x0ff00f70, "vdup%c.32\t%16-19,7Q, %12-15r"},
	{FPU_NEON_EXT_V1, 0x0ea00b30, 0x0ff00f70, "vdup%c.16\t%16-19,7Q, %12-15r"},
	{FPU_NEON_EXT_V1, 0x0ec00b10, 0x0ff00f70, "vdup%c.8\t%16-19,7D, %12-15r"},
	{FPU_NEON_EXT_V1, 0x0ee00b10, 0x0ff00f70, "vdup%c.8\t%16-19,7Q, %12-15r"},
	{FPU_NEON_EXT_V1, 0x0c400b10, 0x0ff00fd0, "vmov%c\t%0-3,5D, %12-15r, %16-19r"},
	{FPU_NEON_EXT_V1, 0x0c500b10, 0x0ff00fd0, "vmov%c\t%12-15r, %16-19r, %0-3,5D"},
	{FPU_NEON_EXT_V1, 0x0e000b10, 0x0fd00f70, "vmov%c.32\t%16-19,7D[%21d], %12-15r"},
	{FPU_NEON_EXT_V1, 0x0e100b10, 0x0f500f70, "vmov%c.32\t%12-15r, %16-19,7D[%21d]"},
	{FPU_NEON_EXT_V1, 0x0e000b30, 0x0fd00f30, "vmov%c.16\t%16-19,7D[%6,21d], %12-15r"},
	{FPU_NEON_EXT_V1, 0x0e100b30, 0x0f500f30, "vmov%c.%23?us16\t%12-15r, %16-19,7D[%6,21d]"},
	{FPU_NEON_EXT_V1, 0x0e400b10, 0x0fd00f10, "vmov%c.8\t%16-19,7D[%5,6,21d], %12-15r"},
	{FPU_NEON_EXT_V1, 0x0e500b10, 0x0f500f10, "vmov%c.%23?us8\t%12-15r, %16-19,7D[%5,6,21d]"},
	/* Half-precision conversion instructions.  */
	{FPU_VFP_EXT_ARMV8, 0x0eb20b40, 0x0fbf0f50, "vcvt%7?tb%c.f64.f16\t%z1, %y0"},
	{FPU_VFP_EXT_ARMV8, 0x0eb30b40, 0x0fbf0f50, "vcvt%7?tb%c.f16.f64\t%y1, %z0"},
	{FPU_VFP_EXT_FP16, 0x0eb20a40, 0x0fbf0f50, "vcvt%7?tb%c.f32.f16\t%y1, %y0"},
	{FPU_VFP_EXT_FP16, 0x0eb30a40, 0x0fbf0f50, "vcvt%7?tb%c.f16.f32\t%y1, %y0"},

	/* Floating point coprocessor (VFP) instructions.  */
	{FPU_VFP_EXT_V1xD, 0x0ee00a10, 0x0fff0fff, "vmsr%c\tfpsid, %12-15r"},
	{FPU_VFP_EXT_V1xD, 0x0ee10a10, 0x0fff0fff, "vmsr%c\tfpscr, %12-15r"},
	{FPU_VFP_EXT_V1xD, 0x0ee60a10, 0x0fff0fff, "vmsr%c\tmvfr1, %12-15r"},
	{FPU_VFP_EXT_V1xD, 0x0ee70a10, 0x0fff0fff, "vmsr%c\tmvfr0, %12-15r"},
	{FPU_VFP_EXT_V1xD, 0x0ee80a10, 0x0fff0fff, "vmsr%c\tfpexc, %12-15r"},
	{FPU_VFP_EXT_V1xD, 0x0ee90a10, 0x0fff0fff, "vmsr%c\tfpinst, %12-15r\t@ Impl def"},
	{FPU_VFP_EXT_V1xD, 0x0eea0a10, 0x0fff0fff, "vmsr%c\tfpinst2, %12-15r\t@ Impl def"},
	{FPU_VFP_EXT_V1xD, 0x0ef00a10, 0x0fff0fff, "vmrs%c\t%12-15r, fpsid"},
	{FPU_VFP_EXT_V1xD, 0x0ef1fa10, 0x0fffffff, "vmrs%c\tAPSR_nzcv, fpscr"},
	{FPU_VFP_EXT_V1xD, 0x0ef10a10, 0x0fff0fff, "vmrs%c\t%12-15r, fpscr"},
	{FPU_VFP_EXT_V1xD, 0x0ef60a10, 0x0fff0fff, "vmrs%c\t%12-15r, mvfr1"},
	{FPU_VFP_EXT_V1xD, 0x0ef70a10, 0x0fff0fff, "vmrs%c\t%12-15r, mvfr0"},
	{FPU_VFP_EXT_V1xD, 0x0ef80a10, 0x0fff0fff, "vmrs%c\t%12-15r, fpexc"},
	{FPU_VFP_EXT_V1xD, 0x0ef90a10, 0x0fff0fff, "vmrs%c\t%12-15r, fpinst\t@ Impl def"},
	{FPU_VFP_EXT_V1xD, 0x0efa0a10, 0x0fff0fff, "vmrs%c\t%12-15r, fpinst2\t@ Impl def"},
	{FPU_VFP_EXT_V1, 0x0e000b10, 0x0fd00fff, "vmov%c.32\t%z2[%21d], %12-15r"},
	{FPU_VFP_EXT_V1, 0x0e100b10, 0x0fd00fff, "vmov%c.32\t%12-15r, %z2[%21d]"},
	{FPU_VFP_EXT_V1xD, 0x0ee00a10, 0x0ff00fff, "vmsr%c\t<impl def %16-19x>, %12-15r"},
	{FPU_VFP_EXT_V1xD, 0x0ef00a10, 0x0ff00fff, "vmrs%c\t%12-15r, <impl def %16-19x>"},
	{FPU_VFP_EXT_V1xD, 0x0e000a10, 0x0ff00f7f, "vmov%c\t%y2, %12-15r"},
	{FPU_VFP_EXT_V1xD, 0x0e100a10, 0x0ff00f7f, "vmov%c\t%12-15r, %y2"},
	{FPU_VFP_EXT_V1xD, 0x0eb50a40, 0x0fbf0f70, "vcmp%7'e%c.f32\t%y1, #0.0"},
	{FPU_VFP_EXT_V1, 0x0eb50b40, 0x0fbf0f70, "vcmp%7'e%c.f64\t%z1, #0.0"},
	{FPU_VFP_EXT_V1xD, 0x0eb00a40, 0x0fbf0fd0, "vmov%c.f32\t%y1, %y0"},
	{FPU_VFP_EXT_V1xD, 0x0eb00ac0, 0x0fbf0fd0, "vabs%c.f32\t%y1, %y0"},
	{FPU_VFP_EXT_V1, 0x0eb00b40, 0x0fbf0fd0, "vmov%c.f64\t%z1, %z0"},
	{FPU_VFP_EXT_V1, 0x0eb00bc0, 0x0fbf0fd0, "vabs%c.f64\t%z1, %z0"},
	{FPU_VFP_EXT_V1xD, 0x0eb10a40, 0x0fbf0fd0, "vneg%c.f32\t%y1, %y0"},
	{FPU_VFP_EXT_V1xD, 0x0eb10ac0, 0x0fbf0fd0, "vsqrt%c.f32\t%y1, %y0"},
	{FPU_VFP_EXT_V1, 0x0eb10b40, 0x0fbf0fd0, "vneg%c.f64\t%z1, %z0"},
	{FPU_VFP_EXT_V1, 0x0eb10bc0, 0x0fbf0fd0, "vsqrt%c.f64\t%z1, %z0"},
	{FPU_VFP_EXT_V1, 0x0eb70ac0, 0x0fbf0fd0, "vcvt%c.f64.f32\t%z1, %y0"},
	{FPU_VFP_EXT_V1, 0x0eb70bc0, 0x0fbf0fd0, "vcvt%c.f32.f64\t%y1, %z0"},
	{FPU_VFP_EXT_V1xD, 0x0eb80a40, 0x0fbf0f50, "vcvt%c.f32.%7?su32\t%y1, %y0"},
	{FPU_VFP_EXT_V1, 0x0eb80b40, 0x0fbf0f50, "vcvt%c.f64.%7?su32\t%z1, %y0"},
	{FPU_VFP_EXT_V1xD, 0x0eb40a40, 0x0fbf0f50, "vcmp%7'e%c.f32\t%y1, %y0"},
	{FPU_VFP_EXT_V1, 0x0eb40b40, 0x0fbf0f50, "vcmp%7'e%c.f64\t%z1, %z0"},
	{FPU_VFP_EXT_V3xD, 0x0eba0a40, 0x0fbe0f50, "vcvt%c.f32.%16?us%7?31%7?26\t%y1, %y1, #%5,0-3k"},
	{FPU_VFP_EXT_V3, 0x0eba0b40, 0x0fbe0f50, "vcvt%c.f64.%16?us%7?31%7?26\t%z1, %z1, #%5,0-3k"},
	{FPU_VFP_EXT_V1xD, 0x0ebc0a40, 0x0fbe0f50, "vcvt%7`r%c.%16?su32.f32\t%y1, %y0"},
	{FPU_VFP_EXT_V1, 0x0ebc0b40, 0x0fbe0f50, "vcvt%7`r%c.%16?su32.f64\t%y1, %z0"},
	{FPU_VFP_EXT_V3xD, 0x0ebe0a40, 0x0fbe0f50, "vcvt%c.%16?us%7?31%7?26.f32\t%y1, %y1, #%5,0-3k"},
	{FPU_VFP_EXT_V3, 0x0ebe0b40, 0x0fbe0f50, "vcvt%c.%16?us%7?31%7?26.f64\t%z1, %z1, #%5,0-3k"},
	{FPU_VFP_EXT_V1, 0x0c500b10, 0x0fb00ff0, "vmov%c\t%12-15r, %16-19r, %z0"},
	{FPU_VFP_EXT_V3xD, 0x0eb00a00, 0x0fb00ff0, "vmov%c.f32\t%y1, #%0-3,16-19d"},
	{FPU_VFP_EXT_V3, 0x0eb00b00, 0x0fb00ff0, "vmov%c.f64\t%z1, #%0-3,16-19d"},
	{FPU_VFP_EXT_V2, 0x0c400a10, 0x0ff00fd0, "vmov%c\t%y4, %12-15r, %16-19r"},
	{FPU_VFP_EXT_V2, 0x0c400b10, 0x0ff00fd0, "vmov%c\t%z0, %12-15r, %16-19r"},
	{FPU_VFP_EXT_V2, 0x0c500a10, 0x0ff00fd0, "vmov%c\t%12-15r, %16-19r, %y4"},
	{FPU_VFP_EXT_V1xD, 0x0e000a00, 0x0fb00f50, "vmla%c.f32\t%y1, %y2, %y0"},
	{FPU_VFP_EXT_V1xD, 0x0e000a40, 0x0fb00f50, "vmls%c.f32\t%y1, %y2, %y0"},
	{FPU_VFP_EXT_V1, 0x0e000b00, 0x0fb00f50, "vmla%c.f64\t%z1, %z2, %z0"},
	{FPU_VFP_EXT_V1, 0x0e000b40, 0x0fb00f50, "vmls%c.f64\t%z1, %z2, %z0"},
	{FPU_VFP_EXT_V1xD, 0x0e100a00, 0x0fb00f50, "vnmls%c.f32\t%y1, %y2, %y0"},
	{FPU_VFP_EXT_V1xD, 0x0e100a40, 0x0fb00f50, "vnmla%c.f32\t%y1, %y2, %y0"},
	{FPU_VFP_EXT_V1, 0x0e100b00, 0x0fb00f50, "vnmls%c.f64\t%z1, %z2, %z0"},
	{FPU_VFP_EXT_V1, 0x0e100b40, 0x0fb00f50, "vnmla%c.f64\t%z1, %z2, %z0"},
	{FPU_VFP_EXT_V1xD, 0x0e200a00, 0x0fb00f50, "vmul%c.f32\t%y1, %y2, %y0"},
	{FPU_VFP_EXT_V1xD, 0x0e200a40, 0x0fb00f50, "vnmul%c.f32\t%y1, %y2, %y0"},
	{FPU_VFP_EXT_V1, 0x0e200b00, 0x0fb00f50, "vmul%c.f64\t%z1, %z2, %z0"},
	{FPU_VFP_EXT_V1, 0x0e200b40, 0x0fb00f50, "vnmul%c.f64\t%z1, %z2, %z0"},
	{FPU_VFP_EXT_V1xD, 0x0e300a00, 0x0fb00f50, "vadd%c.f32\t%y1, %y2, %y0"},
	{FPU_VFP_EXT_V1xD, 0x0e300a40, 0x0fb00f50, "vsub%c.f32\t%y1, %y2, %y0"},
	{FPU_VFP_EXT_V1, 0x0e300b00, 0x0fb00f50, "vadd%c.f64\t%z1, %z2, %z0"},
	{FPU_VFP_EXT_V1, 0x0e300b40, 0x0fb00f50, "vsub%c.f64\t%z1, %z2, %z0"},
	{FPU_VFP_EXT_V1xD, 0x0e800a00, 0x0fb00f50, "vdiv%c.f32\t%y1, %y2, %y0"},
	{FPU_VFP_EXT_V1, 0x0e800b00, 0x0fb00f50, "vdiv%c.f64\t%z1, %z2, %z0"},

	/* Cirrus coprocessor instructions.  */
	{ARM_CEXT_MAVERICK, 0x0d100400, 0x0f500f00, "cfldrs%c\tmvf%12-15d, %A"},
	{ARM_CEXT_MAVERICK, 0x0c100400, 0x0f500f00, "cfldrs%c\tmvf%12-15d, %A"},
	{ARM_CEXT_MAVERICK, 0x0d500400, 0x0f500f00, "cfldrd%c\tmvd%12-15d, %A"},
	{ARM_CEXT_MAVERICK, 0x0c500400, 0x0f500f00, "cfldrd%c\tmvd%12-15d, %A"}, 
	{ARM_CEXT_MAVERICK, 0x0d100500, 0x0f500f00, "cfldr32%c\tmvfx%12-15d, %A"},
	{ARM_CEXT_MAVERICK, 0x0c100500, 0x0f500f00, "cfldr32%c\tmvfx%12-15d, %A"},
	{ARM_CEXT_MAVERICK, 0x0d500500, 0x0f500f00, "cfldr64%c\tmvdx%12-15d, %A"},
	{ARM_CEXT_MAVERICK, 0x0c500500, 0x0f500f00, "cfldr64%c\tmvdx%12-15d, %A"},
	{ARM_CEXT_MAVERICK, 0x0d000400, 0x0f500f00, "cfstrs%c\tmvf%12-15d, %A"},
	{ARM_CEXT_MAVERICK, 0x0c000400, 0x0f500f00, "cfstrs%c\tmvf%12-15d, %A"},
	{ARM_CEXT_MAVERICK, 0x0d400400, 0x0f500f00, "cfstrd%c\tmvd%12-15d, %A"},
	{ARM_CEXT_MAVERICK, 0x0c400400, 0x0f500f00, "cfstrd%c\tmvd%12-15d, %A"},
	{ARM_CEXT_MAVERICK, 0x0d000500, 0x0f500f00, "cfstr32%c\tmvfx%12-15d, %A"},
	{ARM_CEXT_MAVERICK, 0x0c000500, 0x0f500f00, "cfstr32%c\tmvfx%12-15d, %A"},
	{ARM_CEXT_MAVERICK, 0x0d400500, 0x0f500f00, "cfstr64%c\tmvdx%12-15d, %A"},
	{ARM_CEXT_MAVERICK, 0x0c400500, 0x0f500f00, "cfstr64%c\tmvdx%12-15d, %A"},
	{ARM_CEXT_MAVERICK, 0x0e000450, 0x0ff00ff0, "cfmvsr%c\tmvf%16-19d, %12-15r"},
	{ARM_CEXT_MAVERICK, 0x0e100450, 0x0ff00ff0, "cfmvrs%c\t%12-15r, mvf%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e000410, 0x0ff00ff0, "cfmvdlr%c\tmvd%16-19d, %12-15r"},
	{ARM_CEXT_MAVERICK, 0x0e100410, 0x0ff00ff0, "cfmvrdl%c\t%12-15r, mvd%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e000430, 0x0ff00ff0, "cfmvdhr%c\tmvd%16-19d, %12-15r"},
	{ARM_CEXT_MAVERICK, 0x0e100430, 0x0ff00fff, "cfmvrdh%c\t%12-15r, mvd%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e000510, 0x0ff00fff, "cfmv64lr%c\tmvdx%16-19d, %12-15r"},
	{ARM_CEXT_MAVERICK, 0x0e100510, 0x0ff00fff, "cfmvr64l%c\t%12-15r, mvdx%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e000530, 0x0ff00fff, "cfmv64hr%c\tmvdx%16-19d, %12-15r"},
	{ARM_CEXT_MAVERICK, 0x0e100530, 0x0ff00fff, "cfmvr64h%c\t%12-15r, mvdx%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e200440, 0x0ff00fff, "cfmval32%c\tmvax%12-15d, mvfx%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e100440, 0x0ff00fff, "cfmv32al%c\tmvfx%12-15d, mvax%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e200460, 0x0ff00fff, "cfmvam32%c\tmvax%12-15d, mvfx%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e100460, 0x0ff00fff, "cfmv32am%c\tmvfx%12-15d, mvax%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e200480, 0x0ff00fff, "cfmvah32%c\tmvax%12-15d, mvfx%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e100480, 0x0ff00fff, "cfmv32ah%c\tmvfx%12-15d, mvax%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e2004a0, 0x0ff00fff, "cfmva32%c\tmvax%12-15d, mvfx%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e1004a0, 0x0ff00fff, "cfmv32a%c\tmvfx%12-15d, mvax%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e2004c0, 0x0ff00fff, "cfmva64%c\tmvax%12-15d, mvdx%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e1004c0, 0x0ff00fff, "cfmv64a%c\tmvdx%12-15d, mvax%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e2004e0, 0x0fff0fff, "cfmvsc32%c\tdspsc, mvdx%12-15d"},
	{ARM_CEXT_MAVERICK, 0x0e1004e0, 0x0fff0fff, "cfmv32sc%c\tmvdx%12-15d, dspsc"},
	{ARM_CEXT_MAVERICK, 0x0e000400, 0x0ff00fff, "cfcpys%c\tmvf%12-15d, mvf%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e000420, 0x0ff00fff, "cfcpyd%c\tmvd%12-15d, mvd%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e000460, 0x0ff00fff, "cfcvtsd%c\tmvd%12-15d, mvf%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e000440, 0x0ff00fff, "cfcvtds%c\tmvf%12-15d, mvd%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e000480, 0x0ff00fff, "cfcvt32s%c\tmvf%12-15d, mvfx%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e0004a0, 0x0ff00fff, "cfcvt32d%c\tmvd%12-15d, mvfx%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e0004c0, 0x0ff00fff, "cfcvt64s%c\tmvf%12-15d, mvdx%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e0004e0, 0x0ff00fff, "cfcvt64d%c\tmvd%12-15d, mvdx%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e100580, 0x0ff00fff, "cfcvts32%c\tmvfx%12-15d, mvf%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e1005a0, 0x0ff00fff, "cfcvtd32%c\tmvfx%12-15d, mvd%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e1005c0, 0x0ff00fff, "cftruncs32%c\tmvfx%12-15d, mvf%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e1005e0, 0x0ff00fff, "cftruncd32%c\tmvfx%12-15d, mvd%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e000550, 0x0ff00ff0, "cfrshl32%c\tmvfx%16-19d, mvfx%0-3d, %12-15r"},
	{ARM_CEXT_MAVERICK, 0x0e000570, 0x0ff00ff0, "cfrshl64%c\tmvdx%16-19d, mvdx%0-3d, %12-15r"},
	{ARM_CEXT_MAVERICK, 0x0e000500, 0x0ff00f10, "cfsh32%c\tmvfx%12-15d, mvfx%16-19d, #%I"},
	{ARM_CEXT_MAVERICK, 0x0e200500, 0x0ff00f10, "cfsh64%c\tmvdx%12-15d, mvdx%16-19d, #%I"},
	{ARM_CEXT_MAVERICK, 0x0e100490, 0x0ff00ff0, "cfcmps%c\t%12-15r, mvf%16-19d, mvf%0-3d"},
	{ARM_CEXT_MAVERICK, 0x0e1004b0, 0x0ff00ff0, "cfcmpd%c\t%12-15r, mvd%16-19d, mvd%0-3d"},
	{ARM_CEXT_MAVERICK, 0x0e100590, 0x0ff00ff0, "cfcmp32%c\t%12-15r, mvfx%16-19d, mvfx%0-3d"},
	{ARM_CEXT_MAVERICK, 0x0e1005b0, 0x0ff00ff0, "cfcmp64%c\t%12-15r, mvdx%16-19d, mvdx%0-3d"},
	{ARM_CEXT_MAVERICK, 0x0e300400, 0x0ff00fff, "cfabss%c\tmvf%12-15d, mvf%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e300420, 0x0ff00fff, "cfabsd%c\tmvd%12-15d, mvd%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e300440, 0x0ff00fff, "cfnegs%c\tmvf%12-15d, mvf%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e300460, 0x0ff00fff, "cfnegd%c\tmvd%12-15d, mvd%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e300480, 0x0ff00ff0, "cfadds%c\tmvf%12-15d, mvf%16-19d, mvf%0-3d"},
	{ARM_CEXT_MAVERICK, 0x0e3004a0, 0x0ff00ff0, "cfaddd%c\tmvd%12-15d, mvd%16-19d, mvd%0-3d"},
	{ARM_CEXT_MAVERICK, 0x0e3004c0, 0x0ff00ff0, "cfsubs%c\tmvf%12-15d, mvf%16-19d, mvf%0-3d"},
	{ARM_CEXT_MAVERICK, 0x0e3004e0, 0x0ff00ff0, "cfsubd%c\tmvd%12-15d, mvd%16-19d, mvd%0-3d"},
	{ARM_CEXT_MAVERICK, 0x0e100400, 0x0ff00ff0, "cfmuls%c\tmvf%12-15d, mvf%16-19d, mvf%0-3d"},
	{ARM_CEXT_MAVERICK, 0x0e100420, 0x0ff00ff0, "cfmuld%c\tmvd%12-15d, mvd%16-19d, mvd%0-3d"},
	{ARM_CEXT_MAVERICK, 0x0e300500, 0x0ff00fff, "cfabs32%c\tmvfx%12-15d, mvfx%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e300520, 0x0ff00fff, "cfabs64%c\tmvdx%12-15d, mvdx%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e300540, 0x0ff00fff, "cfneg32%c\tmvfx%12-15d, mvfx%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e300560, 0x0ff00fff, "cfneg64%c\tmvdx%12-15d, mvdx%16-19d"},
	{ARM_CEXT_MAVERICK, 0x0e300580, 0x0ff00ff0, "cfadd32%c\tmvfx%12-15d, mvfx%16-19d, mvfx%0-3d"},
	{ARM_CEXT_MAVERICK, 0x0e3005a0, 0x0ff00ff0, "cfadd64%c\tmvdx%12-15d, mvdx%16-19d, mvdx%0-3d"},
	{ARM_CEXT_MAVERICK, 0x0e3005c0, 0x0ff00ff0, "cfsub32%c\tmvfx%12-15d, mvfx%16-19d, mvfx%0-3d"},
	{ARM_CEXT_MAVERICK, 0x0e3005e0, 0x0ff00ff0, "cfsub64%c\tmvdx%12-15d, mvdx%16-19d, mvdx%0-3d"},
	{ARM_CEXT_MAVERICK, 0x0e100500, 0x0ff00ff0, "cfmul32%c\tmvfx%12-15d, mvfx%16-19d, mvfx%0-3d"},
	{ARM_CEXT_MAVERICK, 0x0e100520, 0x0ff00ff0, "cfmul64%c\tmvdx%12-15d, mvdx%16-19d, mvdx%0-3d"},
	{ARM_CEXT_MAVERICK, 0x0e100540, 0x0ff00ff0, "cfmac32%c\tmvfx%12-15d, mvfx%16-19d, mvfx%0-3d"},
	{ARM_CEXT_MAVERICK, 0x0e100560, 0x0ff00ff0, "cfmsc32%c\tmvfx%12-15d, mvfx%16-19d, mvfx%0-3d"},
	{ARM_CEXT_MAVERICK, 0x0e000600, 0x0ff00f10, "cfmadd32%c\tmvax%5-7d, mvfx%12-15d, mvfx%16-19d, mvfx%0-3d"},
	{ARM_CEXT_MAVERICK, 0x0e100600, 0x0ff00f10, "cfmsub32%c\tmvax%5-7d, mvfx%12-15d, mvfx%16-19d, mvfx%0-3d"},
	{ARM_CEXT_MAVERICK, 0x0e200600, 0x0ff00f10, "cfmadda32%c\tmvax%5-7d, mvax%12-15d, mvfx%16-19d, mvfx%0-3d"},
	{ARM_CEXT_MAVERICK, 0x0e300600, 0x0ff00f10, "cfmsuba32%c\tmvax%5-7d, mvax%12-15d, mvfx%16-19d, mvfx%0-3d"},

	/* VFP Fused multiply add instructions.  */
	{FPU_VFP_EXT_FMA, 0x0ea00a00, 0x0fb00f50, "vfma%c.f32\t%y1, %y2, %y0"},
	{FPU_VFP_EXT_FMA, 0x0ea00b00, 0x0fb00f50, "vfma%c.f64\t%z1, %z2, %z0"},
	{FPU_VFP_EXT_FMA, 0x0ea00a40, 0x0fb00f50, "vfms%c.f32\t%y1, %y2, %y0"},
	{FPU_VFP_EXT_FMA, 0x0ea00b40, 0x0fb00f50, "vfms%c.f64\t%z1, %z2, %z0"},
	{FPU_VFP_EXT_FMA, 0x0e900a40, 0x0fb00f50, "vfnma%c.f32\t%y1, %y2, %y0"},
	{FPU_VFP_EXT_FMA, 0x0e900b40, 0x0fb00f50, "vfnma%c.f64\t%z1, %z2, %z0"},
	{FPU_VFP_EXT_FMA, 0x0e900a00, 0x0fb00f50, "vfnms%c.f32\t%y1, %y2, %y0"},
	{FPU_VFP_EXT_FMA, 0x0e900b00, 0x0fb00f50, "vfnms%c.f64\t%z1, %z2, %z0"},

	/* FP v5.  */
	{FPU_VFP_EXT_ARMV8, 0xfe000a00, 0xff800f00, "vsel%20-21c%u.f32\t%y1, %y2, %y0"},
	{FPU_VFP_EXT_ARMV8, 0xfe000b00, 0xff800f00, "vsel%20-21c%u.f64\t%z1, %z2, %z0"},
	{FPU_VFP_EXT_ARMV8, 0xfe800a00, 0xffb00f40, "vmaxnm%u.f32\t%y1, %y2, %y0"},
	{FPU_VFP_EXT_ARMV8, 0xfe800b00, 0xffb00f40, "vmaxnm%u.f64\t%z1, %z2, %z0"},
	{FPU_VFP_EXT_ARMV8, 0xfe800a40, 0xffb00f40, "vminnm%u.f32\t%y1, %y2, %y0"},
	{FPU_VFP_EXT_ARMV8, 0xfe800b40, 0xffb00f40, "vminnm%u.f64\t%z1, %z2, %z0"},
	{FPU_VFP_EXT_ARMV8, 0xfebc0a40, 0xffbc0f50, "vcvt%16-17?mpna%u.%7?su32.f32\t%y1, %y0"},
	{FPU_VFP_EXT_ARMV8, 0xfebc0b40, 0xffbc0f50, "vcvt%16-17?mpna%u.%7?su32.f64\t%y1, %z0"},
	{FPU_VFP_EXT_ARMV8, 0x0eb60a40, 0x0fbe0f50, "vrint%7,16??xzr%c.f32\t%y1, %y0"},
	{FPU_VFP_EXT_ARMV8, 0x0eb60b40, 0x0fbe0f50, "vrint%7,16??xzr%c.f64\t%z1, %z0"},
	{FPU_VFP_EXT_ARMV8, 0xfeb80a40, 0xffbc0f50, "vrint%16-17?mpna%u.f32\t%y1, %y0"},
	{FPU_VFP_EXT_ARMV8, 0xfeb80b40, 0xffbc0f50, "vrint%16-17?mpna%u.f64\t%z1, %z0"},

	/* Generic coprocessor instructions.  */
	{ 0, SENTINEL_GENERIC_START, 0, "" },
	{ARM_EXT_V5E, 0x0c400000, 0x0ff00000, "mcrr%c\t%8-11d, %4-7d, %12-15R, %16-19r, cr%0-3d"},
	{ARM_EXT_V5E, 0x0c500000, 0x0ff00000, "mrrc%c\t%8-11d, %4-7d, %12-15Ru, %16-19Ru, cr%0-3d"},
	{ARM_EXT_V2, 0x0e000000, 0x0f000010, "cdp%c\t%8-11d, %20-23d, cr%12-15d, cr%16-19d, cr%0-3d, {%5-7d}"},
	{ARM_EXT_V2, 0x0e10f010, 0x0f10f010, "mrc%c\t%8-11d, %21-23d, APSR_nzcv, cr%16-19d, cr%0-3d, {%5-7d}"},
	{ARM_EXT_V2, 0x0e100010, 0x0f100010, "mrc%c\t%8-11d, %21-23d, %12-15r, cr%16-19d, cr%0-3d, {%5-7d}"},
	{ARM_EXT_V2, 0x0e000010, 0x0f100010, "mcr%c\t%8-11d, %21-23d, %12-15R, cr%16-19d, cr%0-3d, {%5-7d}"},
	{ARM_EXT_V2, 0x0c000000, 0x0e100000, "stc%22'l%c\t%8-11d, cr%12-15d, %A"},
	{ARM_EXT_V2, 0x0c100000, 0x0e100000, "ldc%22'l%c\t%8-11d, cr%12-15d, %A"},

	/* V6 coprocessor instructions.  */
	{ARM_EXT_V6, 0xfc500000, 0xfff00000, "mrrc2%c\t%8-11d, %4-7d, %12-15Ru, %16-19Ru, cr%0-3d"},
	{ARM_EXT_V6, 0xfc400000, 0xfff00000, "mcrr2%c\t%8-11d, %4-7d, %12-15R, %16-19R, cr%0-3d"},

	/* V5 coprocessor instructions.  */
	{ARM_EXT_V5, 0xfc100000, 0xfe100000, "ldc2%22'l%c\t%8-11d, cr%12-15d, %A"},
	{ARM_EXT_V5, 0xfc000000, 0xfe100000, "stc2%22'l%c\t%8-11d, cr%12-15d, %A"},
	{ARM_EXT_V5, 0xfe000000, 0xff000010, "cdp2%c\t%8-11d, %20-23d, cr%12-15d, cr%16-19d, cr%0-3d, {%5-7d}"},
	{ARM_EXT_V5, 0xfe000010, 0xff100010, "mcr2%c\t%8-11d, %21-23d, %12-15R, cr%16-19d, cr%0-3d, {%5-7d}"},
	{ARM_EXT_V5, 0xfe100010, 0xff100010, "mrc2%c\t%8-11d, %21-23d, %12-15r, cr%16-19d, cr%0-3d, {%5-7d}"},

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

/* 1则成功,0则失败 */
unsigned char print_insn_coprocessor(unsigned pc,
									 void *pinfo,
									 long given,
									 unsigned char thumb) {
	const opcode32 *insn;
	disassemble_info *info = (disassemble_info*)pinfo;
	void *stream = info->stream;
	fprintf_ftype func = info->fprintf_func;
	unsigned long mask = 0;
	unsigned long value = 0;
	arm_private_data *private_data = (arm_private_data*)(info->private_data);
	unsigned long allowed_arches = private_data->features.coproc;
	int cond = 0;
	
	/* 遍历coprocessor opcode表 */
	for (insn = coprocessor_opcodes; insn->assembler; insn++) {
		unsigned long u_reg = 16;
		unsigned char is_unpredictable = 0;     /* 是无法可预料的 */
		signed long value_in_comment = 0;
		const char *c;

		/* 如果arch值为0
		 * 则value是一个哨兵标志
		 */
		if (insn->arch == 0) {
			/* 检查哨兵值
			 * 并且切换架构
			 */
			switch (insn->value) {
				/* 协处理器开始 */
			case SENTINEL_IWMMXT_START: {
				/* 如果不属于三个体系 
				 * 直到再找到arch为0,value不为SENTINEL_IWMMXT_END的
				 * 指令
				 */
				if (info->mach != MACH_ARM_XSCALE && \
					info->mach != MACH_ARM_IWMMXT && \
					info->mach != MACH_ARM_IWMMXT2)
					do
						insn++;
					while (insn->arch != 0 && insn->value != 
						   SENTINEL_IWMMXT_END);
				continue;
			} break;
				/* 协处理器完成 */
			case SENTINEL_IWMMXT_END: {
				continue;
			} break;
				/* 切换到正常架构 */
			case SENTINEL_GENERIC_START: {
				allowed_arches = private_data->features.core;
				continue;
			} break;
			default: {
				ERROR_INTERNAL_EXCEPT("disasm not currect sentinel");
			}/* end default */
			}/* end switch */
		}/* end if */
		/* 掩码与值 */
		mask = insn->mask;
		value = insn->value;
		/* 是否是thumb指令 */
		if (thumb) {
			/* 高4位是0xe表明是一个arm条件指令, 
			 * 0xe是一个arm无条件指令.编码是一样的 */
			mask |= 0xf0000000;     /* 最高4位必须取出,cond */
			value |= 0xe0000000;
			/* 如果ifthen_state开启表明是条件指令 */
			if (ifthen_state)
				cond = IFTHEN_COND;
			else
				cond = COND_UNCOND;
		} else {			/* 非thumb */
			/* 仅匹配无条件指令 */
			if ((given & 0xf0000000) == 0xf0000000) {
				mask |= 0xf0000000;
				cond = COND_UNCOND;
			} else {
				/* 取最高4位的条件码 */
				cond = (given >> 28) & 0xf;
				/* 如果条件位是0b1110 = 0xe,则表示无条件 */
				if (cond == 0xe)
					cond = COND_UNCOND;
			}
		}/* end else */
		
		/* 查看当前的读取的指令是否匹配当前的解码规则 
		 * 不匹配尝试下一条
		 */
		if ((given & mask) != value)
			continue;

		/* 架构不匹配,尝试下一条 */
		if ((insn->arch & allowed_arches) == 0)
			continue;

		/* 解析反汇编规则
		 * 读取规则的每一个字符并且进行解析 
		 */
		for (c = insn->assembler; *c; c++) {
			/* 找到匹配开始标记 */
			if (*c == '%') {
				switch (*++c) {
				case '%': {
					/* 输出 % */
					func (stream, "%%");
				} break;
					/* 遇到ldc/stc/ldf/stf,打印地址 */
				case 'A': {
					int rn = (given >> 16) & 0xf;   /* 获取源寄存器 */
					unsigned offset = given & 0xff; /* 获取偏移量末尾8位 */

					/* 打印源寄存器名称 */
					func (stream, "[%s", arm_regnames [(given >> 16) & 0xf]);

					/* 检测opcode位编码 */
					if (PRE_BIT_SET || WRITEBACK_BIT_SET) {
						/* 偏移是比例 */
						offset = offset * 4;

						/* 负数被设置 */
						if (NEGATIVE_BIT_SET)
							offset = - offset;
						if (rn != 15)
							value_in_comment = offset;
					}/* end if */

					/* 打印偏移立即数 */
					if (PRE_BIT_SET) {
						if (offset) {
							func (stream, ", #%d]%s",
								  (int) offset,
								  WRITEBACK_BIT_SET ? "!" : "");
						} else if (NEGATIVE_BIT_SET) {
							func (stream, ", #-0]");
						} else {
							func (stream, "]");
						}/* end else */
					} else {
						func (stream, "]");
						
						/* 打印偏移立即数 */
						if (WRITEBACK_BIT_SET) {
							if (offset)
								func (stream, ", #%d", (int) offset);
							else if (NEGATIVE_BIT_SET)
								func (stream, ", #-0");
						} else {
							func (stream, ", {%s%d}",
								  (NEGATIVE_BIT_SET && !offset) ? "-" : "",
								  (int) offset);
							value_in_comment = offset;
						}/* end else */
					}/* end else */
					if (rn == 15 && (PRE_BIT_SET || WRITEBACK_BIT_SET)) {
						func (stream, "\t; ");
						/* 对于没有对齐的PC值,应用对齐粒度 */
						info->print_address_func(offset + pc 
												 + info->bytes_per_chunk * 2
												 - (pc & 3),
												 info);
					}
				} break;
					/* 打印vstm/vldm寄存器列表 */
				case 'B': {
					int regno = ((given >> 12) & 0xf) | \
						((given >> (22 - 4)) & 0x10);
					int offset = (given >> 1) & 0x3f;
					
					if (offset == 1) {
						func (stream, "{d%d}", regno);
					} else if (regno + offset > 32) {
						func (stream, "{d%d-<overflow reg d%d>}", 
							  regno, regno + offset - 1);
					} else {
						func (stream, "{d%d-d%d}", regno, regno + offset - 1);
					}/* end else */
				} break;
					/* 条件代码(无条件指令,在ARM模式,不可预料的,
					 * 如果不是AL在Thumb模式) */
				case 'u' :
					if (cond != COND_UNCOND)
						is_unpredictable = 1;
					
					/* 向下传递 */
					/* 条件代码(所有在28-31位在ARM模式, condition code) */
				case 'c': {/* 打印条件 */
					func (stream, "%s", arm_conditional[cond]);
				} break;
					/* 打印cirrus无符号移位 立即数: 7位 0..3|4..6 */
				case 'I': {
					/* Print a Cirrus/DSP shift immediate.  */
					/* Immediates are 7bit signed ints with bits 0..3 in
					   bits 0..3 of opcode and bits 4..6 in bits 5..7
					   of opcode.  */
					int imm;
					imm = (given & 0xf) | ((given & 0xe0) >> 1);

					/* 立即数是否是负数 */
					if (imm & 0x40)
						imm |= (-1 << 7);

					func (stream, "%d", imm);
				} break;
					/* 打印一条LFM/SFM指令的COUNT区域 */
				case 'F': {
					switch (given & 0x00408000) {
					case 0:
						func (stream, "4");
						break;
					case 0x8000:
						func (stream, "1");
						break;
					case 0x00400000:
						func (stream, "2");
						break;
					default:
						func (stream, "3");
					}/* end switch */
				} break;
					/* 打印浮点数精度在算数指令 */
				case 'P': {
					switch (given & 0x00080080) {
					case 0:
						func (stream, "s");
						break;
					case 0x80:
						func (stream, "d");
						break;
					case 0x00080000:
						func (stream, "e");
						break;
					default:
						/* 非法的精度 */
						func (stream, ("<illegal precision>"));
						break;
					}/* end switch */
				} break;
					/* 打印浮点数在ldf/stf指令 */
				case 'Q': {
					switch (given & 0x00408000) {
					case 0:
						func (stream, "s");
						break;
					case 0x8000:
						func (stream, "d");
						break;
					case 0x00400000:
						func (stream, "e");
						break;
					default:
						func (stream, "p");
						break;
					}/* end switch */
				} break;
					/* 打印浮点数在rounding模式 */
				case 'R': {
					switch (given & 0x60) {
					case 0:
						break;
					case 0x20:
						func (stream, "p");
						break;
					case 0x40:
						func (stream, "m");
						break;
					default:
						func (stream, "z");
						break;
					}/* end switch */
				} break;
					/* 解析位域 */
				case '0': case '1': case '2': case '3': case '4':
				case '5': case '6': case '7': case '8': case '9': {
					int width;    /* 共有几位 */
					/* 解码bitfield区域 */
					c = arm_decode_bitfield(c, given, &value, &width);
					/* 位域解下来解析的字符 */
					switch (*c) {
						/* 作为 %<>r 使用,但是r15无法预料的 */
					case 'R':
						if (value == 15)
							is_unpredictable = 1;
						/* 传递 */
						/* 打印一个ARM寄存器 */
					case 'r': {
						/* 作为 %<>r 使用,每个 u 寄存器必须是唯一的 */
						if (c[1] == 'u') {
							++c;
							if (u_reg == value)
								is_unpredictable = 1;
							u_reg = value;
						}
						func (stream, "%s", arm_regnames[value]);
					} break;
						/* 打印一个NEON D寄存器 */
					case 'D': {
						func (stream, "d%ld", value);
					} break;
						/* 打印一个NEON Q寄存器 */
					case 'Q': {
						if (value & 1)
							func (stream, "<illegal reg q%ld.5>", value >> 1);
						else
							func (stream, "q%ld", value >> 1);
					} break;
						/* 以10进制打印bitfield */
					case 'd': {
						func (stream, "%ld", value);
						value_in_comment = value;
					} break;
						/* 打印VFPv3指令的立即数 */
					case 'k': {
						int from = (given & (1 << 7)) ? 32 : 16;
						func (stream, "%ld", from - value);
					} break;
						/* 如果>7打印浮点数常量或者打印一个浮点寄存器 */
					case 'f': {
						if (value > 7)
							func (stream, "#%s", arm_fp_const[value & 7]);
						else
							func (stream, "f%ld", value);
					} break;
						/* 打印iWMMXt宽度域 - [bhwd]ss/us */
					case 'w': {
						if (width == 2)
							func (stream, "%s", iwmmxt_wwnames[value]);
						else
							func (stream, "%s", iwmmxt_wwssnames[value]);
					} break;
						/* 打印一个iWMMXt 64位寄存器 */
					case 'g': {
						func (stream, "%s", iwmmxt_regnames[value]);
					} break;
						/* 打印一个iWMMXt通常的目的或者是作为控制寄存器 */
					case 'G': {
						func (stream, "%s", iwmmxt_cregnames[value]);
					} break;
						/* 以16进制打印bitfield */
					case 'x': {
						func (stream, "0x%lx", (value & 0xffffffffUL));
					} break;
						/* 打印作为条件代码(for vsel) */
					case 'c': {
						switch (value) {
						case 0:
							func (stream, "eq");
							break;
						case 1:
							func (stream, "vs");
							break;
						case 2:
							func (stream, "ge");
							break;
						case 3:
							func (stream, "gt");
							break;
						default:
							func (stream, "??");
							break;
						}/* end switch */
					} break;
						/* 打印指定的字符，如果bitfield全部是0 */
					case '`': {
						c++;
						if (value == 0)
							func (stream, "%c", *c);
					} break;
						/* 打印指定的字符，如果bitfield全部是1 */
					case '\'': {
						c++;
						if (value == ((1ul << width) - 1))
							func (stream, "%c", *c);
					} break;
						/* 在大端字序从值队列中选择 */
					case '?': {
						func (stream, "%c", c[(1 << width) - (int) value]);
						c += 1 << width;
					} break;
					default: {
						ERROR_INTERNAL_EXCEPT("disasm coprocessor bitfield failed");
					}
					}/* 位域解析完毕 */
				} break;
					/* 打印一个VFP寄存器 */
				case 'y':
				case 'z': {
					int single = *c++ == 'y';  /* 判断精度 */
					int regno;
						
					switch (*c) {
					case '4': /* Sm pair */
					case '0': { /* Sm, Dm */
						regno = given & 0x0000000f;
						if (single) {
							regno <<= 1;
							regno += (given >> 5) & 1;
						} else
							regno += ((given >> 5) & 1) << 4;
					} break;
					case '1': {/* Sd, Dd */
						regno = (given >> 12) & 0x0000000f;
						if (single) {
							regno <<= 1;
							regno += (given >> 22) & 1;
						} else
							regno += ((given >> 22) & 1) << 4;
					} break;
					case '2': {/* Sn, Dn */
						regno = (given >> 16) & 0x0000000f;
						if (single) {
							regno <<= 1;
							regno += (given >> 7) & 1;
						} else
							regno += ((given >> 7) & 1) << 4;
					} break;
					case '3': {/* List */
						func (stream, "{");
						regno = (given >> 12) & 0x0000000f;
						if (single) {
							regno <<= 1;
							regno += (given >> 22) & 1;
						} else
							regno += ((given >> 22) & 1) << 4;
					} break;
					default:{
						ERROR_INTERNAL_EXCEPT("disasm coprocessor VFP failed");
					}/* end default */
					}/* end switch */
					/* 打印VFP寄存器 */
					func (stream, "%c%d", single ? 's' : 'd', regno);
					if (*c == '3') {
						int count = given & 0xff;
							
						if (single == 0)
							count >>= 1;
							
						if (--count) {
							func (stream, "-%c%d",
								  single ? 's' : 'd',
								  regno + count);
						}
						func (stream, "}");
					} else if (*c == '4') {
						func (stream, ", %c%d", single ? 's' : 'd', 
							  regno + 1);
					}/* end else if */
				} break;
					/* 打印作为一个iWMMXt N/M 宽度域 */
				case 'L':{
					switch (given & 0x00400100) {
					case 0x00000000: func (stream, "b"); break;
					case 0x00400000: func (stream, "h"); break;
					case 0x00000100: func (stream, "w"); break;
					case 0x00400100: func (stream, "d"); break;
					default: break;
					}/* end switch */
				} break;
					/* 打印WSHUFH指令的立即数 */
				case 'Z': {
					/* given (20, 23) | given (0, 3) */
					value = ((given >> 16) & 0xf0) | (given & 0xf);
					func (stream, "%d", (int) value);
				} break;
					/* like 'A' except use byte offsets for 
					   'B' & 'H' versions. */
				case 'l': {
					/* This is like the 'A' operator, except that if
					   the width field "M" is zero, then the offset is
					   *not* multiplied by four.  */
					int offset = given & 0xff;
					int multiplier = (given & 0x00000100) ? 4 : 1;
					
					func (stream, "[%s", arm_regnames [(given >> 16) & 0xf]);
					
					if (multiplier > 1) {
						value_in_comment = offset * multiplier;
						if (NEGATIVE_BIT_SET)
							value_in_comment = - value_in_comment;
					}
					if (offset) {
						if (PRE_BIT_SET) {
							func (stream, ", #%s%d]%s",
								  NEGATIVE_BIT_SET ? "-" : "",
								  offset * multiplier,
								  WRITEBACK_BIT_SET ? "!" : "");
						} else {
							func (stream, "], #%s%d",
								  NEGATIVE_BIT_SET ? "-" : "",
								  offset * multiplier);
						}/* end else */
					} else {
						func (stream, "]");
					}/* end else */
				} break;
					/* 遇到wldr/wstr指令打印寄存器偏移地址 */
				case 'r': {
					int imm4 = (given >> 4) & 0xf;
					int puw_bits = ((given >> 22) & 6) | ((given >> W_BIT) & 1);
					int ubit = ! NEGATIVE_BIT_SET;
					const char *rm = arm_regnames [given & 0xf];
					const char *rn = arm_regnames [(given >> 16) & 0xf];
					
					switch (puw_bits) {
					case 1:
					case 3:
						func (stream, "[%s], %c%s", rn, ubit ? '+' : '-', 
							  rm);
						if (imm4)
							func (stream, ", lsl #%d", imm4);
						break;
					case 4:
					case 5:
					case 6:
					case 7: {
						func (stream, "[%s, %c%s", rn, ubit ? '+' : '-', 
							  rm);
						if (imm4 > 0)
							func (stream, ", lsl #%d", imm4);
						func (stream, "]");
						if (puw_bits == 5 || puw_bits == 7)
							func (stream, "!");
					} break;
					default: func (stream, "INVALID");
					}/* end switch */
				} break;
					/* 打印5位的立即数在位8,3..0(当是0时打印'32') */
				case 'i': {
					long imm5;
					imm5 = ((given & 0x100) >> 4) | (given & 0xf);
					func (stream, "%ld", (imm5 == 0) ? 32 : imm5);
				} break;
				default: {
					ERROR_INTERNAL_EXCEPT("disasm coprocessor %i");
				}/* end default */
				}/* end switch(++*c) */
			} else {
				/* 非%开头的转意字符直接打印 */
				func (stream, "%c", *c);
			}/* end else */
			
			/* 打印注释 */
			if (value_in_comment > 32 || value_in_comment < -16)
				func (stream, "\t; 0x%lx", (value_in_comment & 0xffffffffUL));
			
			/* 如果是不可预料的指令则打印说明 */
			if (is_unpredictable)
				func (stream, UNPREDICTABLE_INSTRUCTION);
			return 1;
		}/* end for 结束循环编码规则 */
	}/* end for 结束取出每一条解码退则 */
	return 0;
}
