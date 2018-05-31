#include "globals.h"
#include "errs.h"
#include "disinfo.h"

/* Neon opcode table:  This does not encode the top byte -- that is
   checked by the print_insn_neon routine, as it depends on whether we are
   doing thumb32 or arm32 disassembly.  */

/* print_insn_neon recognizes the following format control codes:

   %%			%

   %c			print condition code
   %u			print condition code (unconditional in ARM mode,
   UNPREDICTABLE if not AL in Thumb)
   %A			print v{st,ld}[1234] operands
   %B			print v{st,ld}[1234] any one operands
   %C			print v{st,ld}[1234] single->all operands
   %D			print scalar
   %E			print vmov, vmvn, vorr, vbic encoded constant
   %F			print vtbl,vtbx register list

   %<bitfield>r		print as an ARM register
   %<bitfield>d		print the bitfield in decimal
   %<bitfield>e     print the 2^N - bitfield in decimal
   %<bitfield>D		print as a NEON D register
   %<bitfield>Q		print as a NEON Q register
   %<bitfield>R		print as a NEON D or Q register
   %<bitfield>Sn	print byte scaled width limited by n
   %<bitfield>Tn	print short scaled width limited by n
   %<bitfield>Un	print long scaled width limited by n
   
   %<bitfield>'c	print specified char iff bitfield is all ones
   %<bitfield>`c	print specified char iff bitfield is all zeroes
   %<bitfield>?ab...    select from array of values in big endian order.  */

static const opcode32 neon_opcodes[] = {
	/* Extract.  */
	{FPU_NEON_EXT_V1, 0xf2b00840, 0xffb00850, "vext%c.8\t%12-15,22R, %16-19,7R, %0-3,5R, #%8-11d"},
	{FPU_NEON_EXT_V1, 0xf2b00000, 0xffb00810, "vext%c.8\t%12-15,22R, %16-19,7R, %0-3,5R, #%8-11d"},

	/* Move data element to all lanes.  */
	{FPU_NEON_EXT_V1, 0xf3b40c00, 0xffb70f90, "vdup%c.32\t%12-15,22R, %0-3,5D[%19d]"},
	{FPU_NEON_EXT_V1, 0xf3b20c00, 0xffb30f90, "vdup%c.16\t%12-15,22R, %0-3,5D[%18-19d]"},
	{FPU_NEON_EXT_V1, 0xf3b10c00, 0xffb10f90, "vdup%c.8\t%12-15,22R, %0-3,5D[%17-19d]"},

	/* Table lookup.  */
	{FPU_NEON_EXT_V1, 0xf3b00800, 0xffb00c50, "vtbl%c.8\t%12-15,22D, %F, %0-3,5D"},
	{FPU_NEON_EXT_V1, 0xf3b00840, 0xffb00c50, "vtbx%c.8\t%12-15,22D, %F, %0-3,5D"},
  
	/* Half-precision conversions.  */
	{FPU_VFP_EXT_FP16, 0xf3b60600, 0xffbf0fd0, "vcvt%c.f16.f32\t%12-15,22D, %0-3,5Q"},
	{FPU_VFP_EXT_FP16, 0xf3b60700, 0xffbf0fd0, "vcvt%c.f32.f16\t%12-15,22Q, %0-3,5D"},

	/* NEON fused multiply add instructions.  */
	{FPU_NEON_EXT_FMA, 0xf2000c10, 0xffa00f10, "vfma%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_FMA, 0xf2200c10, 0xffa00f10, "vfms%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},

	/* Two registers, miscellaneous.  */
	{FPU_NEON_EXT_ARMV8, 0xf3ba0400, 0xffbf0c10, "vrint%7-9?p?m?zaxn%u.f32\t%12-15,22R, %0-3,5R"},
	{FPU_NEON_EXT_ARMV8, 0xf3bb0000, 0xffbf0c10, "vcvt%8-9?mpna%u.%7?us32.f32\t%12-15,22R, %0-3,5R"},
	{FPU_CRYPTO_EXT_ARMV8, 0xf3b00300, 0xffbf0fd0, "aese%u.8\t%12-15,22Q, %0-3,5Q"},
	{FPU_CRYPTO_EXT_ARMV8, 0xf3b00340, 0xffbf0fd0, "aesd%u.8\t%12-15,22Q, %0-3,5Q"},
	{FPU_CRYPTO_EXT_ARMV8, 0xf3b00380, 0xffbf0fd0, "aesmc%u.8\t%12-15,22Q, %0-3,5Q"},
	{FPU_CRYPTO_EXT_ARMV8, 0xf3b003c0, 0xffbf0fd0, "aesimc%u.8\t%12-15,22Q, %0-3,5Q"},
	{FPU_CRYPTO_EXT_ARMV8, 0xf3b902c0, 0xffbf0fd0, "sha1h%u.32\t%12-15,22Q, %0-3,5Q"},
	{FPU_CRYPTO_EXT_ARMV8, 0xf3ba0380, 0xffbf0fd0, "sha1su1%u.32\t%12-15,22Q, %0-3,5Q"},
	{FPU_CRYPTO_EXT_ARMV8, 0xf3ba03c0, 0xffbf0fd0, "sha256su0%u.32\t%12-15,22Q, %0-3,5Q"},
	{FPU_NEON_EXT_V1, 0xf2880a10, 0xfebf0fd0, "vmovl%c.%24?us8\t%12-15,22Q, %0-3,5D"},
	{FPU_NEON_EXT_V1, 0xf2900a10, 0xfebf0fd0, "vmovl%c.%24?us16\t%12-15,22Q, %0-3,5D"},
	{FPU_NEON_EXT_V1, 0xf2a00a10, 0xfebf0fd0, "vmovl%c.%24?us32\t%12-15,22Q, %0-3,5D"},
	{FPU_NEON_EXT_V1, 0xf3b00500, 0xffbf0f90, "vcnt%c.8\t%12-15,22R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3b00580, 0xffbf0f90, "vmvn%c\t%12-15,22R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3b20000, 0xffbf0f90, "vswp%c\t%12-15,22R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3b20200, 0xffb30fd0, "vmovn%c.i%18-19T2\t%12-15,22D, %0-3,5Q"},
	{FPU_NEON_EXT_V1, 0xf3b20240, 0xffb30fd0, "vqmovun%c.s%18-19T2\t%12-15,22D, %0-3,5Q"},
	{FPU_NEON_EXT_V1, 0xf3b20280, 0xffb30fd0, "vqmovn%c.s%18-19T2\t%12-15,22D, %0-3,5Q"},
	{FPU_NEON_EXT_V1, 0xf3b202c0, 0xffb30fd0, "vqmovn%c.u%18-19T2\t%12-15,22D, %0-3,5Q"},
	{FPU_NEON_EXT_V1, 0xf3b20300, 0xffb30fd0, "vshll%c.i%18-19S2\t%12-15,22Q, %0-3,5D, #%18-19S2"},
	{FPU_NEON_EXT_V1, 0xf3bb0400, 0xffbf0e90, "vrecpe%c.%8?fu%18-19S2\t%12-15,22R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3bb0480, 0xffbf0e90, "vrsqrte%c.%8?fu%18-19S2\t%12-15,22R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3b00000, 0xffb30f90, "vrev64%c.%18-19S2\t%12-15,22R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3b00080, 0xffb30f90, "vrev32%c.%18-19S2\t%12-15,22R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3b00100, 0xffb30f90, "vrev16%c.%18-19S2\t%12-15,22R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3b00400, 0xffb30f90, "vcls%c.s%18-19S2\t%12-15,22R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3b00480, 0xffb30f90, "vclz%c.i%18-19S2\t%12-15,22R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3b00700, 0xffb30f90, "vqabs%c.s%18-19S2\t%12-15,22R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3b00780, 0xffb30f90, "vqneg%c.s%18-19S2\t%12-15,22R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3b20080, 0xffb30f90, "vtrn%c.%18-19S2\t%12-15,22R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3b20100, 0xffb30f90, "vuzp%c.%18-19S2\t%12-15,22R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3b20180, 0xffb30f90, "vzip%c.%18-19S2\t%12-15,22R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3b10000, 0xffb30b90, "vcgt%c.%10?fs%18-19S2\t%12-15,22R, %0-3,5R, #0"},
	{FPU_NEON_EXT_V1, 0xf3b10080, 0xffb30b90, "vcge%c.%10?fs%18-19S2\t%12-15,22R, %0-3,5R, #0"},
	{FPU_NEON_EXT_V1, 0xf3b10100, 0xffb30b90, "vceq%c.%10?fi%18-19S2\t%12-15,22R, %0-3,5R, #0"},
	{FPU_NEON_EXT_V1, 0xf3b10180, 0xffb30b90, "vcle%c.%10?fs%18-19S2\t%12-15,22R, %0-3,5R, #0"},
	{FPU_NEON_EXT_V1, 0xf3b10200, 0xffb30b90, "vclt%c.%10?fs%18-19S2\t%12-15,22R, %0-3,5R, #0"},
	{FPU_NEON_EXT_V1, 0xf3b10300, 0xffb30b90, "vabs%c.%10?fs%18-19S2\t%12-15,22R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3b10380, 0xffb30b90, "vneg%c.%10?fs%18-19S2\t%12-15,22R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3b00200, 0xffb30f10, "vpaddl%c.%7?us%18-19S2\t%12-15,22R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3b00600, 0xffb30f10, "vpadal%c.%7?us%18-19S2\t%12-15,22R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3b30600, 0xffb30e10, "vcvt%c.%7-8?usff%18-19Sa.%7-8?ffus%18-19Sa\t%12-15,22R, %0-3,5R"},

	/* Three registers of the same length.  */
	{FPU_CRYPTO_EXT_ARMV8, 0xf2000c40, 0xffb00f50, "sha1c%u.32\t%12-15,22Q, %16-19,7Q, %0-3,5Q"},
	{FPU_CRYPTO_EXT_ARMV8, 0xf2100c40, 0xffb00f50, "sha1p%u.32\t%12-15,22Q, %16-19,7Q, %0-3,5Q"},
	{FPU_CRYPTO_EXT_ARMV8, 0xf2200c40, 0xffb00f50, "sha1m%u.32\t%12-15,22Q, %16-19,7Q, %0-3,5Q"},
	{FPU_CRYPTO_EXT_ARMV8, 0xf2300c40, 0xffb00f50, "sha1su0%u.32\t%12-15,22Q, %16-19,7Q, %0-3,5Q"},
	{FPU_CRYPTO_EXT_ARMV8, 0xf3000c40, 0xffb00f50, "sha256h%u.32\t%12-15,22Q, %16-19,7Q, %0-3,5Q"},
	{FPU_CRYPTO_EXT_ARMV8, 0xf3100c40, 0xffb00f50, "sha256h2%u.32\t%12-15,22Q, %16-19,7Q, %0-3,5Q"},
	{FPU_CRYPTO_EXT_ARMV8, 0xf3200c40, 0xffb00f50, "sha256su1%u.32\t%12-15,22Q, %16-19,7Q, %0-3,5Q"},
	{FPU_NEON_EXT_ARMV8, 0xf3000f10, 0xffa00f10, "vmaxnm%u.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_ARMV8, 0xf3200f10, 0xffa00f10, "vminnm%u.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000110, 0xffb00f10, "vand%c\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2100110, 0xffb00f10, "vbic%c\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2200110, 0xffb00f10, "vorr%c\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2300110, 0xffb00f10, "vorn%c\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3000110, 0xffb00f10, "veor%c\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3100110, 0xffb00f10, "vbsl%c\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3200110, 0xffb00f10, "vbit%c\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3300110, 0xffb00f10, "vbif%c\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000d00, 0xffa00f10, "vadd%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000d10, 0xffa00f10, "vmla%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000e00, 0xffa00f10, "vceq%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000f00, 0xffa00f10, "vmax%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000f10, 0xffa00f10, "vrecps%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2200d00, 0xffa00f10, "vsub%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2200d10, 0xffa00f10, "vmls%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2200f00, 0xffa00f10, "vmin%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2200f10, 0xffa00f10, "vrsqrts%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3000d00, 0xffa00f10, "vpadd%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3000d10, 0xffa00f10, "vmul%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3000e00, 0xffa00f10, "vcge%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3000e10, 0xffa00f10, "vacge%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3000f00, 0xffa00f10, "vpmax%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3200d00, 0xffa00f10, "vabd%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3200e00, 0xffa00f10, "vcgt%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3200e10, 0xffa00f10, "vacgt%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3200f00, 0xffa00f10, "vpmin%c.f%20U0\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000800, 0xff800f10, "vadd%c.i%20-21S3\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000810, 0xff800f10, "vtst%c.%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000900, 0xff800f10, "vmla%c.i%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000b00, 0xff800f10, "vqdmulh%c.s%20-21S6\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000b10, 0xff800f10, "vpadd%c.i%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3000800, 0xff800f10, "vsub%c.i%20-21S3\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3000810, 0xff800f10, "vceq%c.i%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3000900, 0xff800f10, "vmls%c.i%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf3000b00, 0xff800f10, "vqrdmulh%c.s%20-21S6\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000000, 0xfe800f10, "vhadd%c.%24?us%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000010, 0xfe800f10, "vqadd%c.%24?us%20-21S3\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000100, 0xfe800f10, "vrhadd%c.%24?us%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000200, 0xfe800f10, "vhsub%c.%24?us%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000210, 0xfe800f10, "vqsub%c.%24?us%20-21S3\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000300, 0xfe800f10, "vcgt%c.%24?us%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000310, 0xfe800f10, "vcge%c.%24?us%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000400, 0xfe800f10, "vshl%c.%24?us%20-21S3\t%12-15,22R, %0-3,5R, %16-19,7R"},
	{FPU_NEON_EXT_V1, 0xf2000410, 0xfe800f10, "vqshl%c.%24?us%20-21S3\t%12-15,22R, %0-3,5R, %16-19,7R"},
	{FPU_NEON_EXT_V1, 0xf2000500, 0xfe800f10, "vrshl%c.%24?us%20-21S3\t%12-15,22R, %0-3,5R, %16-19,7R"},
	{FPU_NEON_EXT_V1, 0xf2000510, 0xfe800f10, "vqrshl%c.%24?us%20-21S3\t%12-15,22R, %0-3,5R, %16-19,7R"},
	{FPU_NEON_EXT_V1, 0xf2000600, 0xfe800f10, "vmax%c.%24?us%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000610, 0xfe800f10, "vmin%c.%24?us%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000700, 0xfe800f10, "vabd%c.%24?us%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000710, 0xfe800f10, "vaba%c.%24?us%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000910, 0xfe800f10, "vmul%c.%24?pi%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000a00, 0xfe800f10, "vpmax%c.%24?us%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},
	{FPU_NEON_EXT_V1, 0xf2000a10, 0xfe800f10, "vpmin%c.%24?us%20-21S2\t%12-15,22R, %16-19,7R, %0-3,5R"},

	/* One register and an immediate value.  */
	{FPU_NEON_EXT_V1, 0xf2800e10, 0xfeb80fb0, "vmov%c.i8\t%12-15,22R, %E"},
	{FPU_NEON_EXT_V1, 0xf2800e30, 0xfeb80fb0, "vmov%c.i64\t%12-15,22R, %E"},
	{FPU_NEON_EXT_V1, 0xf2800f10, 0xfeb80fb0, "vmov%c.f32\t%12-15,22R, %E"},
	{FPU_NEON_EXT_V1, 0xf2800810, 0xfeb80db0, "vmov%c.i16\t%12-15,22R, %E"},
	{FPU_NEON_EXT_V1, 0xf2800830, 0xfeb80db0, "vmvn%c.i16\t%12-15,22R, %E"},
	{FPU_NEON_EXT_V1, 0xf2800910, 0xfeb80db0, "vorr%c.i16\t%12-15,22R, %E"},
	{FPU_NEON_EXT_V1, 0xf2800930, 0xfeb80db0, "vbic%c.i16\t%12-15,22R, %E"},
	{FPU_NEON_EXT_V1, 0xf2800c10, 0xfeb80eb0, "vmov%c.i32\t%12-15,22R, %E"},
	{FPU_NEON_EXT_V1, 0xf2800c30, 0xfeb80eb0, "vmvn%c.i32\t%12-15,22R, %E"},
	{FPU_NEON_EXT_V1, 0xf2800110, 0xfeb809b0, "vorr%c.i32\t%12-15,22R, %E"},
	{FPU_NEON_EXT_V1, 0xf2800130, 0xfeb809b0, "vbic%c.i32\t%12-15,22R, %E"},
	{FPU_NEON_EXT_V1, 0xf2800010, 0xfeb808b0, "vmov%c.i32\t%12-15,22R, %E"},
	{FPU_NEON_EXT_V1, 0xf2800030, 0xfeb808b0, "vmvn%c.i32\t%12-15,22R, %E"},

	/* Two registers and a shift amount.  */
	{FPU_NEON_EXT_V1, 0xf2880810, 0xffb80fd0, "vshrn%c.i16\t%12-15,22D, %0-3,5Q, #%16-18e"},
	{FPU_NEON_EXT_V1, 0xf2880850, 0xffb80fd0, "vrshrn%c.i16\t%12-15,22D, %0-3,5Q, #%16-18e"},
	{FPU_NEON_EXT_V1, 0xf2880810, 0xfeb80fd0, "vqshrun%c.s16\t%12-15,22D, %0-3,5Q, #%16-18e"},
	{FPU_NEON_EXT_V1, 0xf2880850, 0xfeb80fd0, "vqrshrun%c.s16\t%12-15,22D, %0-3,5Q, #%16-18e"},
	{FPU_NEON_EXT_V1, 0xf2880910, 0xfeb80fd0, "vqshrn%c.%24?us16\t%12-15,22D, %0-3,5Q, #%16-18e"},
	{FPU_NEON_EXT_V1, 0xf2880950, 0xfeb80fd0, "vqrshrn%c.%24?us16\t%12-15,22D, %0-3,5Q, #%16-18e"},
	{FPU_NEON_EXT_V1, 0xf2880a10, 0xfeb80fd0, "vshll%c.%24?us8\t%12-15,22Q, %0-3,5D, #%16-18d"},
	{FPU_NEON_EXT_V1, 0xf2900810, 0xffb00fd0, "vshrn%c.i32\t%12-15,22D, %0-3,5Q, #%16-19e"},
	{FPU_NEON_EXT_V1, 0xf2900850, 0xffb00fd0, "vrshrn%c.i32\t%12-15,22D, %0-3,5Q, #%16-19e"},
	{FPU_NEON_EXT_V1, 0xf2880510, 0xffb80f90, "vshl%c.%24?us8\t%12-15,22R, %0-3,5R, #%16-18d"},
	{FPU_NEON_EXT_V1, 0xf3880410, 0xffb80f90, "vsri%c.8\t%12-15,22R, %0-3,5R, #%16-18e"},
	{FPU_NEON_EXT_V1, 0xf3880510, 0xffb80f90, "vsli%c.8\t%12-15,22R, %0-3,5R, #%16-18d"},
	{FPU_NEON_EXT_V1, 0xf3880610, 0xffb80f90, "vqshlu%c.s8\t%12-15,22R, %0-3,5R, #%16-18d"},
	{FPU_NEON_EXT_V1, 0xf2900810, 0xfeb00fd0, "vqshrun%c.s32\t%12-15,22D, %0-3,5Q, #%16-19e"},
	{FPU_NEON_EXT_V1, 0xf2900850, 0xfeb00fd0, "vqrshrun%c.s32\t%12-15,22D, %0-3,5Q, #%16-19e"},
	{FPU_NEON_EXT_V1, 0xf2900910, 0xfeb00fd0, "vqshrn%c.%24?us32\t%12-15,22D, %0-3,5Q, #%16-19e"},
	{FPU_NEON_EXT_V1, 0xf2900950, 0xfeb00fd0, "vqrshrn%c.%24?us32\t%12-15,22D, %0-3,5Q, #%16-19e"},
	{FPU_NEON_EXT_V1, 0xf2900a10, 0xfeb00fd0, "vshll%c.%24?us16\t%12-15,22Q, %0-3,5D, #%16-19d"},
	{FPU_NEON_EXT_V1, 0xf2880010, 0xfeb80f90, "vshr%c.%24?us8\t%12-15,22R, %0-3,5R, #%16-18e"},
	{FPU_NEON_EXT_V1, 0xf2880110, 0xfeb80f90, "vsra%c.%24?us8\t%12-15,22R, %0-3,5R, #%16-18e"},
	{FPU_NEON_EXT_V1, 0xf2880210, 0xfeb80f90, "vrshr%c.%24?us8\t%12-15,22R, %0-3,5R, #%16-18e"},
	{FPU_NEON_EXT_V1, 0xf2880310, 0xfeb80f90, "vrsra%c.%24?us8\t%12-15,22R, %0-3,5R, #%16-18e"},
	{FPU_NEON_EXT_V1, 0xf2880710, 0xfeb80f90, "vqshl%c.%24?us8\t%12-15,22R, %0-3,5R, #%16-18d"},
	{FPU_NEON_EXT_V1, 0xf2a00810, 0xffa00fd0, "vshrn%c.i64\t%12-15,22D, %0-3,5Q, #%16-20e"},
	{FPU_NEON_EXT_V1, 0xf2a00850, 0xffa00fd0, "vrshrn%c.i64\t%12-15,22D, %0-3,5Q, #%16-20e"},
	{FPU_NEON_EXT_V1, 0xf2900510, 0xffb00f90, "vshl%c.%24?us16\t%12-15,22R, %0-3,5R, #%16-19d"},
	{FPU_NEON_EXT_V1, 0xf3900410, 0xffb00f90, "vsri%c.16\t%12-15,22R, %0-3,5R, #%16-19e"},
	{FPU_NEON_EXT_V1, 0xf3900510, 0xffb00f90, "vsli%c.16\t%12-15,22R, %0-3,5R, #%16-19d"},
	{FPU_NEON_EXT_V1, 0xf3900610, 0xffb00f90, "vqshlu%c.s16\t%12-15,22R, %0-3,5R, #%16-19d"},
	{FPU_NEON_EXT_V1, 0xf2a00a10, 0xfea00fd0, "vshll%c.%24?us32\t%12-15,22Q, %0-3,5D, #%16-20d"},
	{FPU_NEON_EXT_V1, 0xf2900010, 0xfeb00f90, "vshr%c.%24?us16\t%12-15,22R, %0-3,5R, #%16-19e"},
	{FPU_NEON_EXT_V1, 0xf2900110, 0xfeb00f90, "vsra%c.%24?us16\t%12-15,22R, %0-3,5R, #%16-19e"},
	{FPU_NEON_EXT_V1, 0xf2900210, 0xfeb00f90, "vrshr%c.%24?us16\t%12-15,22R, %0-3,5R, #%16-19e"},
	{FPU_NEON_EXT_V1, 0xf2900310, 0xfeb00f90, "vrsra%c.%24?us16\t%12-15,22R, %0-3,5R, #%16-19e"},
	{FPU_NEON_EXT_V1, 0xf2900710, 0xfeb00f90, "vqshl%c.%24?us16\t%12-15,22R, %0-3,5R, #%16-19d"},
	{FPU_NEON_EXT_V1, 0xf2a00810, 0xfea00fd0, "vqshrun%c.s64\t%12-15,22D, %0-3,5Q, #%16-20e"},
	{FPU_NEON_EXT_V1, 0xf2a00850, 0xfea00fd0, "vqrshrun%c.s64\t%12-15,22D, %0-3,5Q, #%16-20e"},
	{FPU_NEON_EXT_V1, 0xf2a00910, 0xfea00fd0, "vqshrn%c.%24?us64\t%12-15,22D, %0-3,5Q, #%16-20e"},
	{FPU_NEON_EXT_V1, 0xf2a00950, 0xfea00fd0, "vqrshrn%c.%24?us64\t%12-15,22D, %0-3,5Q, #%16-20e"},
	{FPU_NEON_EXT_V1, 0xf2a00510, 0xffa00f90, "vshl%c.%24?us32\t%12-15,22R, %0-3,5R, #%16-20d"},
	{FPU_NEON_EXT_V1, 0xf3a00410, 0xffa00f90, "vsri%c.32\t%12-15,22R, %0-3,5R, #%16-20e"},
	{FPU_NEON_EXT_V1, 0xf3a00510, 0xffa00f90, "vsli%c.32\t%12-15,22R, %0-3,5R, #%16-20d"},
	{FPU_NEON_EXT_V1, 0xf3a00610, 0xffa00f90, "vqshlu%c.s32\t%12-15,22R, %0-3,5R, #%16-20d"},
	{FPU_NEON_EXT_V1, 0xf2a00010, 0xfea00f90, "vshr%c.%24?us32\t%12-15,22R, %0-3,5R, #%16-20e"},
	{FPU_NEON_EXT_V1, 0xf2a00110, 0xfea00f90, "vsra%c.%24?us32\t%12-15,22R, %0-3,5R, #%16-20e"},
	{FPU_NEON_EXT_V1, 0xf2a00210, 0xfea00f90, "vrshr%c.%24?us32\t%12-15,22R, %0-3,5R, #%16-20e"},
	{FPU_NEON_EXT_V1, 0xf2a00310, 0xfea00f90, "vrsra%c.%24?us32\t%12-15,22R, %0-3,5R, #%16-20e"},
	{FPU_NEON_EXT_V1, 0xf2a00710, 0xfea00f90, "vqshl%c.%24?us32\t%12-15,22R, %0-3,5R, #%16-20d"},
	{FPU_NEON_EXT_V1, 0xf2800590, 0xff800f90, "vshl%c.%24?us64\t%12-15,22R, %0-3,5R, #%16-21d"},
	{FPU_NEON_EXT_V1, 0xf3800490, 0xff800f90, "vsri%c.64\t%12-15,22R, %0-3,5R, #%16-21e"},
	{FPU_NEON_EXT_V1, 0xf3800590, 0xff800f90, "vsli%c.64\t%12-15,22R, %0-3,5R, #%16-21d"},
	{FPU_NEON_EXT_V1, 0xf3800690, 0xff800f90, "vqshlu%c.s64\t%12-15,22R, %0-3,5R, #%16-21d"},
	{FPU_NEON_EXT_V1, 0xf2800090, 0xfe800f90, "vshr%c.%24?us64\t%12-15,22R, %0-3,5R, #%16-21e"},
	{FPU_NEON_EXT_V1, 0xf2800190, 0xfe800f90, "vsra%c.%24?us64\t%12-15,22R, %0-3,5R, #%16-21e"},
	{FPU_NEON_EXT_V1, 0xf2800290, 0xfe800f90, "vrshr%c.%24?us64\t%12-15,22R, %0-3,5R, #%16-21e"},
	{FPU_NEON_EXT_V1, 0xf2800390, 0xfe800f90, "vrsra%c.%24?us64\t%12-15,22R, %0-3,5R, #%16-21e"},
	{FPU_NEON_EXT_V1, 0xf2800790, 0xfe800f90, "vqshl%c.%24?us64\t%12-15,22R, %0-3,5R, #%16-21d"},
	{FPU_NEON_EXT_V1, 0xf2a00e10, 0xfea00e90, "vcvt%c.%24,8?usff32.%24,8?ffus32\t%12-15,22R, %0-3,5R, #%16-20e"},

	/* Three registers of different lengths.  */
	{FPU_CRYPTO_EXT_ARMV8, 0xf2a00e00, 0xfeb00f50, "vmull%c.p64\t%12-15,22Q, %16-19,7D, %0-3,5D"},
	{FPU_NEON_EXT_V1, 0xf2800e00, 0xfea00f50, "vmull%c.p%20S0\t%12-15,22Q, %16-19,7D, %0-3,5D"},
	{FPU_NEON_EXT_V1, 0xf2800400, 0xff800f50, "vaddhn%c.i%20-21T2\t%12-15,22D, %16-19,7Q, %0-3,5Q"},
	{FPU_NEON_EXT_V1, 0xf2800600, 0xff800f50, "vsubhn%c.i%20-21T2\t%12-15,22D, %16-19,7Q, %0-3,5Q"},
	{FPU_NEON_EXT_V1, 0xf2800900, 0xff800f50, "vqdmlal%c.s%20-21S6\t%12-15,22Q, %16-19,7D, %0-3,5D"},
	{FPU_NEON_EXT_V1, 0xf2800b00, 0xff800f50, "vqdmlsl%c.s%20-21S6\t%12-15,22Q, %16-19,7D, %0-3,5D"},
	{FPU_NEON_EXT_V1, 0xf2800d00, 0xff800f50, "vqdmull%c.s%20-21S6\t%12-15,22Q, %16-19,7D, %0-3,5D"},
	{FPU_NEON_EXT_V1, 0xf3800400, 0xff800f50, "vraddhn%c.i%20-21T2\t%12-15,22D, %16-19,7Q, %0-3,5Q"},
	{FPU_NEON_EXT_V1, 0xf3800600, 0xff800f50, "vrsubhn%c.i%20-21T2\t%12-15,22D, %16-19,7Q, %0-3,5Q"},
	{FPU_NEON_EXT_V1, 0xf2800000, 0xfe800f50, "vaddl%c.%24?us%20-21S2\t%12-15,22Q, %16-19,7D, %0-3,5D"},
	{FPU_NEON_EXT_V1, 0xf2800100, 0xfe800f50, "vaddw%c.%24?us%20-21S2\t%12-15,22Q, %16-19,7Q, %0-3,5D"},
	{FPU_NEON_EXT_V1, 0xf2800200, 0xfe800f50, "vsubl%c.%24?us%20-21S2\t%12-15,22Q, %16-19,7D, %0-3,5D"},
	{FPU_NEON_EXT_V1, 0xf2800300, 0xfe800f50, "vsubw%c.%24?us%20-21S2\t%12-15,22Q, %16-19,7Q, %0-3,5D"},
	{FPU_NEON_EXT_V1, 0xf2800500, 0xfe800f50, "vabal%c.%24?us%20-21S2\t%12-15,22Q, %16-19,7D, %0-3,5D"},
	{FPU_NEON_EXT_V1, 0xf2800700, 0xfe800f50, "vabdl%c.%24?us%20-21S2\t%12-15,22Q, %16-19,7D, %0-3,5D"},
	{FPU_NEON_EXT_V1, 0xf2800800, 0xfe800f50, "vmlal%c.%24?us%20-21S2\t%12-15,22Q, %16-19,7D, %0-3,5D"},
	{FPU_NEON_EXT_V1, 0xf2800a00, 0xfe800f50, "vmlsl%c.%24?us%20-21S2\t%12-15,22Q, %16-19,7D, %0-3,5D"},
	{FPU_NEON_EXT_V1, 0xf2800c00, 0xfe800f50, "vmull%c.%24?us%20-21S2\t%12-15,22Q, %16-19,7D, %0-3,5D"},

	/* Two registers and a scalar.  */
	{FPU_NEON_EXT_V1, 0xf2800040, 0xff800f50, "vmla%c.i%20-21S6\t%12-15,22D, %16-19,7D, %D"},
	{FPU_NEON_EXT_V1, 0xf2800140, 0xff800f50, "vmla%c.f%20-21Sa\t%12-15,22D, %16-19,7D, %D"},
	{FPU_NEON_EXT_V1, 0xf2800340, 0xff800f50, "vqdmlal%c.s%20-21S6\t%12-15,22Q, %16-19,7D, %D"},
	{FPU_NEON_EXT_V1, 0xf2800440, 0xff800f50, "vmls%c.i%20-21S6\t%12-15,22D, %16-19,7D, %D"},
	{FPU_NEON_EXT_V1, 0xf2800540, 0xff800f50, "vmls%c.f%20-21S6\t%12-15,22D, %16-19,7D, %D"},
	{FPU_NEON_EXT_V1, 0xf2800740, 0xff800f50, "vqdmlsl%c.s%20-21S6\t%12-15,22Q, %16-19,7D, %D"},
	{FPU_NEON_EXT_V1, 0xf2800840, 0xff800f50, "vmul%c.i%20-21S6\t%12-15,22D, %16-19,7D, %D"},
	{FPU_NEON_EXT_V1, 0xf2800940, 0xff800f50, "vmul%c.f%20-21Sa\t%12-15,22D, %16-19,7D, %D"},
	{FPU_NEON_EXT_V1, 0xf2800b40, 0xff800f50, "vqdmull%c.s%20-21S6\t%12-15,22Q, %16-19,7D, %D"},
	{FPU_NEON_EXT_V1, 0xf2800c40, 0xff800f50, "vqdmulh%c.s%20-21S6\t%12-15,22D, %16-19,7D, %D"},
	{FPU_NEON_EXT_V1, 0xf2800d40, 0xff800f50, "vqrdmulh%c.s%20-21S6\t%12-15,22D, %16-19,7D, %D"},
	{FPU_NEON_EXT_V1, 0xf3800040, 0xff800f50, "vmla%c.i%20-21S6\t%12-15,22Q, %16-19,7Q, %D"},
	{FPU_NEON_EXT_V1, 0xf3800140, 0xff800f50, "vmla%c.f%20-21Sa\t%12-15,22Q, %16-19,7Q, %D"},
	{FPU_NEON_EXT_V1, 0xf3800440, 0xff800f50, "vmls%c.i%20-21S6\t%12-15,22Q, %16-19,7Q, %D"},
	{FPU_NEON_EXT_V1, 0xf3800540, 0xff800f50, "vmls%c.f%20-21Sa\t%12-15,22Q, %16-19,7Q, %D"},
	{FPU_NEON_EXT_V1, 0xf3800840, 0xff800f50, "vmul%c.i%20-21S6\t%12-15,22Q, %16-19,7Q, %D"},
	{FPU_NEON_EXT_V1, 0xf3800940, 0xff800f50, "vmul%c.f%20-21Sa\t%12-15,22Q, %16-19,7Q, %D"},
	{FPU_NEON_EXT_V1, 0xf3800c40, 0xff800f50, "vqdmulh%c.s%20-21S6\t%12-15,22Q, %16-19,7Q, %D"},
	{FPU_NEON_EXT_V1, 0xf3800d40, 0xff800f50, "vqrdmulh%c.s%20-21S6\t%12-15,22Q, %16-19,7Q, %D"},
	{FPU_NEON_EXT_V1, 0xf2800240, 0xfe800f50, "vmlal%c.%24?us%20-21S6\t%12-15,22Q, %16-19,7D, %D"},
	{FPU_NEON_EXT_V1, 0xf2800640, 0xfe800f50, "vmlsl%c.%24?us%20-21S6\t%12-15,22Q, %16-19,7D, %D"},
	{FPU_NEON_EXT_V1, 0xf2800a40, 0xfe800f50, "vmull%c.%24?us%20-21S6\t%12-15,22Q, %16-19,7D, %D"},

	/* Element and structure load/store. */
	{FPU_NEON_EXT_V1, 0xf4a00fc0, 0xffb00fc0, "vld4%c.32\t%C"},
	{FPU_NEON_EXT_V1, 0xf4a00c00, 0xffb00f00, "vld1%c.%6-7S2\t%C"},
	{FPU_NEON_EXT_V1, 0xf4a00d00, 0xffb00f00, "vld2%c.%6-7S2\t%C"},
	{FPU_NEON_EXT_V1, 0xf4a00e00, 0xffb00f00, "vld3%c.%6-7S2\t%C"},
	{FPU_NEON_EXT_V1, 0xf4a00f00, 0xffb00f00, "vld4%c.%6-7S2\t%C"},
	{FPU_NEON_EXT_V1, 0xf4000200, 0xff900f00, "v%21?ls%21?dt1%c.%6-7S3\t%A"},
	{FPU_NEON_EXT_V1, 0xf4000300, 0xff900f00, "v%21?ls%21?dt2%c.%6-7S2\t%A"},
	{FPU_NEON_EXT_V1, 0xf4000400, 0xff900f00, "v%21?ls%21?dt3%c.%6-7S2\t%A"},
	{FPU_NEON_EXT_V1, 0xf4000500, 0xff900f00, "v%21?ls%21?dt3%c.%6-7S2\t%A"},
	{FPU_NEON_EXT_V1, 0xf4000600, 0xff900f00, "v%21?ls%21?dt1%c.%6-7S3\t%A"},
	{FPU_NEON_EXT_V1, 0xf4000700, 0xff900f00, "v%21?ls%21?dt1%c.%6-7S3\t%A"},
	{FPU_NEON_EXT_V1, 0xf4000800, 0xff900f00, "v%21?ls%21?dt2%c.%6-7S2\t%A"},
	{FPU_NEON_EXT_V1, 0xf4000900, 0xff900f00, "v%21?ls%21?dt2%c.%6-7S2\t%A"},
	{FPU_NEON_EXT_V1, 0xf4000a00, 0xff900f00, "v%21?ls%21?dt1%c.%6-7S3\t%A"},
	{FPU_NEON_EXT_V1, 0xf4000000, 0xff900e00, "v%21?ls%21?dt4%c.%6-7S2\t%A"},
	{FPU_NEON_EXT_V1, 0xf4800000, 0xff900300, "v%21?ls%21?dt1%c.%10-11S2\t%B"},
	{FPU_NEON_EXT_V1, 0xf4800100, 0xff900300, "v%21?ls%21?dt2%c.%10-11S2\t%B"},
	{FPU_NEON_EXT_V1, 0xf4800200, 0xff900300, "v%21?ls%21?dt3%c.%10-11S2\t%B"},
	{FPU_NEON_EXT_V1, 0xf4800300, 0xff900300, "v%21?ls%21?dt4%c.%10-11S2\t%B"},

	{0,0 ,0, 0}
};

unsigned char print_insn_neon(unsigned pc, 
							  void *pinfo, 
							  long given, 
							  unsigned char thumb) {
	UNUSED(pc);

	const opcode32 *insn;
	disassemble_info *info = (disassemble_info*)pinfo;
	void *stream = info->stream;
	fprintf_ftype func = info->fprintf_func;

	/* 如果是thumb */
	if (thumb) {
		if ((given & 0xef000000) == 0xef000000) {
			unsigned long bit28 = given & (1 << 28);
			
			given &= 0x00ffffff;
			if (bit28)
				given |= 0xf3000000;
			else
				given |= 0xf2000000;
		}
		else if ((given & 0xff000000) == 0xf9000000)
			given ^= 0xf9000000 ^ 0xf4000000;
		else
			return 0;
	}/* end else */
	
	for (insn = neon_opcodes; insn->assembler; insn++) {
		/* 匹配指令 */
		if ((given & insn->mask) == insn->value) {
			signed long value_in_comment = 0;
			unsigned char is_unpredictable = 0;
			const char *c;

			for (c = insn->assembler; *c; c++) {
				if (*c == '%') {
					switch (*++c) {
					case '%': {
						func (stream, "%%");
					} break;
					case 'u':
						if (thumb && ifthen_state)
							is_unpredictable = 1;
					case 'c': {
						if (thumb && ifthen_state)
							func (stream, "%s", arm_conditional[IFTHEN_COND]);
					} break;
					case 'A': {
						static const unsigned char enc[16] = {
							0x4, 0x14, /* st4 0,1 */
							0x4, /* st1 2 */
							0x4, /* st2 3 */
							0x3, /* st3 4 */
							0x13, /* st3 5 */
							0x3, /* st1 6 */
							0x1, /* st1 7 */
							0x2, /* st2 8 */
							0x12, /* st2 9 */
							0x2, /* st1 10 */
							0, 0, 0, 0, 0
						};
						int rd = ((given >> 12) & 0xf) | (((given >> 22) & 1) << 4);
						int rn = ((given >> 16) & 0xf);
						int rm = ((given >> 0) & 0xf);
						int align = ((given >> 4) & 0x3);
						int type = ((given >> 8) & 0xf);
						int n = enc[type] & 0xf;
						int stride = (enc[type] >> 4) + 1;
						int ix;
					
						func (stream, "{");
						if (stride > 1) {
							for (ix = 0; ix != n; ix++) {
								func (stream, "%sd%d", ix ? "," : "", rd + ix * stride);
							}/* end for */
						} else if (n == 1) {
							func (stream, "d%d", rd);
						} else {
							func (stream, "d%d-d%d", rd, rd + n - 1);
							func (stream, "}, [%s", arm_regnames[rn]);
							if (align)
								func (stream, " :%d", 32 << align);
							func (stream, "]");
							if (rm == 0xd)
								func (stream, "!");
							else if (rm != 0xf)
								func (stream, ", %s", arm_regnames[rm]);
						}/* end else  */
					} break;
					case 'B': {
						int rd = ((given >> 12) & 0xf) | (((given >> 22) & 1) << 4);
						int rn = ((given >> 16) & 0xf);
						int rm = ((given >> 0) & 0xf);
						int idx_align = ((given >> 4) & 0xf);
						int align = 0;
						int size = ((given >> 10) & 0x3);
						int idx = idx_align >> (size + 1);
						int length = ((given >> 8) & 3) + 1;
						int stride = 1;
						int i;

						if (length > 1 && size > 0)
							stride = (idx_align & (1 << size)) ? 2 : 1;
					
						switch (length) {
						case 1: {
							int amask = (1 << size) - 1;
							if ((idx_align & (1 << size)) != 0)
								return 0;
							if (size > 0) {
								if ((idx_align & amask) == amask)
									align = 8 << size;
								else if ((idx_align & amask) != 0)
									return 0;
							}
						} break;
						case 2: {
							if (size == 2 && (idx_align & 2) != 0)
								return 0;
							align = (idx_align & 1) ? 16 << size : 0;
						} break;
						case 3: {
							if ((size == 2 && (idx_align & 3) != 0) || (idx_align & 1) != 0)
								return 0;
						} break;
						case 4: {
							if (size == 2) {
								if ((idx_align & 3) == 3)
									return 0;
								align = (idx_align & 3) * 64;
							} else
								align = (idx_align & 1) ? 32 << size : 0;
						} break;
						default: ERROR_INTERNAL_EXCEPT("disasm neon failed");
						}/* end switch */
                                
						func (stream, "{");
						for (i = 0; i < length; i++) {
							func (stream, "%sd%d[%d]", (i == 0) ? "" : ",",
								  rd + i * stride, idx);
						}/* end for */
						func (stream, "}, [%s", arm_regnames[rn]);
						if (align)
							func (stream, " :%d", align);
						func (stream, "]");
						if (rm == 0xd)
							func (stream, "!");
						else if (rm != 0xf)
							func (stream, ", %s", arm_regnames[rm]);
					} break;
					case 'C': {
						int rd = ((given >> 12) & 0xf) | (((given >> 22) & 1) << 4);
						int rn = ((given >> 16) & 0xf);
						int rm = ((given >> 0) & 0xf);
						int align = ((given >> 4) & 0x1);
						int size = ((given >> 6) & 0x3);
						int type = ((given >> 8) & 0x3);
						int n = type + 1;
						int stride = ((given >> 5) & 0x1);
						int ix;
						if (stride && (n == 1))
							n++;
						else
							stride++;
						func (stream, "{");
						if (stride > 1)
							for (ix = 0; ix != n; ix++)
								func (stream, "%sd%d[]", ix ? "," : "", rd + ix * stride);
						else if (n == 1)
							func (stream, "d%d[]", rd);
						else
							func (stream, "d%d[]-d%d[]", rd, rd + n - 1);
						func (stream, "}, [%s", arm_regnames[rn]);
						if (align) {
							align = (8 * (type + 1)) << size;
							if (type == 3)
								align = (size > 1) ? align >> 1 : align;
							if (type == 2 || (type == 0 && !size))
								func (stream, " :<bad align %d>", align);
							else
								func (stream, " :%d", align);
						}
						func (stream, "]");
						if (rm == 0xd)
							func (stream, "!");
						else if (rm != 0xf)
							func (stream, ", %s", arm_regnames[rm]);
					} break;
					case 'D': {
						int raw_reg = (given & 0xf) | ((given >> 1) & 0x10);
						int size = (given >> 20) & 3;
						int reg = raw_reg & ((4 << size) - 1);
						int ix = raw_reg >> size >> 2;
					
						func (stream, "d%d[%d]", reg, ix);
					} break;
					case 'E': {
						/* Neon encoded constant for mov, mvn, vorr, vbic.  */
						int bits = 0;
						int cmode = (given >> 8) & 0xf;
						int op = (given >> 5) & 0x1;
						unsigned long value = 0, hival = 0;
						unsigned shift;
						int size = 0;
						int isfloat = 0;
			
						bits |= ((given >> 24) & 1) << 7;
						bits |= ((given >> 16) & 7) << 4;
						bits |= ((given >> 0) & 15) << 0;
					
						if (cmode < 8) {
							shift = (cmode >> 1) & 3;
							value = (unsigned long) bits << (8 * shift);
							size = 32;
						} else if (cmode < 12) {
							shift = (cmode >> 1) & 1;
							value = (unsigned long) bits << (8 * shift);
							size = 16;
						} else if (cmode < 14) {
							shift = (cmode & 1) + 1;
							value = (unsigned long) bits << (8 * shift);
							value |= (1ul << (8 * shift)) - 1;
							size = 32;
						} else if (cmode == 14) {
							if (op) {
								/* Bit replication into bytes.  */
								int ix;
								unsigned long mask;
							
								value = 0;
								hival = 0;
								for (ix = 7; ix >= 0; ix--) {
									mask = ((bits >> ix) & 1) ? 0xff : 0;
									if (ix <= 3)
										value = (value << 8) | mask;
									else
										hival = (hival << 8) | mask;
								}/* end for */
								size = 64;
							} else {
								/* Byte replication.  */
								value = (unsigned long) bits;
								size = 8;
							}/* end else */
						} else if (!op) {
							/* 浮点解码 */
							int tmp;
						
							value = (unsigned long)  (bits & 0x7f) << 19;
							value |= (unsigned long) (bits & 0x80) << 24;
							tmp = bits & 0x40 ? 0x3c : 0x40;
							value |= (unsigned long) tmp << 24;
							size = 32;
							isfloat = 1;
						} else {
							func (stream, "<illegal constant %.8x:%x:%x>",
								  bits, cmode, op);
							size = 32;
							break;
						}/* end else */
						switch (size) {
						case 8: {
							func (stream, "#%ld\t; 0x%.2lx", value, value);
						} break;
						case 16 : {
							func (stream, "#%ld\t; 0x%.4lx", value, value);
						} break;
						case 32: {
							if (isfloat) {
								unsigned char valbytes[4];
								double fvalue = 0;
								/* Do this a byte at a time so we don't have to
								   worry about the host's endianness.  */
								valbytes[0] = value & 0xff;
								valbytes[1] = (value >> 8) & 0xff;
								valbytes[2] = (value >> 16) & 0xff;
								valbytes[3] = (value >> 24) & 0xff;
                            
								/* 进行格式转换 */
								// floatformat_to_double 
								// 	(&floatformat_ieee_single_little, valbytes,
								// 	 &fvalue);
                                                                
								func (stream, "#%.7g\t; 0x%.8lx", fvalue,
									  value);
							} else {
								func (stream, "#%ld\t; 0x%.8lx",
									  (long) (((value & 0x80000000L) != 0) 
											  ? value | ~0xffffffffL : value),
									  value);
							}/* end else */
						} break;
						case 64: {
							func (stream, "#0x%.8lx%.8lx", hival, value);
						} break;
						default: ERROR_INTERNAL_EXCEPT("disasm failed");
						}/* end switch */
					} break;
					case 'F': {
						int regno = ((given >> 16) & 0xf) | ((given >> (7 - 4)) & 0x10);
						int num = (given >> 8) & 0x3;
			
						if (!num)
							func (stream, "{d%d}", regno);
						else if (num + regno >= 32)
							func (stream, "{d%d-<overflow reg d%d}", regno, regno + num);
						else
							func (stream, "{d%d-d%d}", regno, regno + num);
					} break;
					case '0': case '1': case '2': case '3': case '4':
					case '5': case '6': case '7': case '8': case '9': {
						int width;
						unsigned long value;
						c = arm_decode_bitfield(c, given, &value, &width);
					
						switch (*c) {
						case 'r': {
							func (stream, "%s", arm_regnames[value]);
						} break;
						case 'd': {
							func (stream, "%ld", value);
							value_in_comment = value;
						} break;
						case 'e': {
							func (stream, "%ld", (1ul << width) - value);
						} break;
						case 'S':
						case 'T':
						case 'U': {
							/* 变量宽度解码 */
							int base = 8 << (*c - 'S'); /* 8,16 or 32 */
							int limit;
							unsigned low, high;

							c++;
							if (*c >= '0' && *c <= '9')
								limit = *c - '0';
							else if (*c >= 'a' && *c <= 'f')
								limit = *c - 'a' + 10;
							else
								ERROR_INTERNAL_EXCEPT("disasm failed");
							low = limit >> 2;
							high = limit & 3;

							if (value < low || value > high)
								func (stream, "<illegal width %d>", base << value);
							else
								func (stream, "%d", base << value);
						} break;
						case 'R': if (given & (1 << 6)) goto Q;
						case 'D': {
							func (stream, "d%ld", value);
						} break;
						case 'Q': {
							Q:
							if (value & 1)
								func (stream, "<illegal reg q%ld.5>", value >> 1);
							else
								func (stream, "q%ld", value >> 1);
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
					default: ERROR_INTERNAL_EXCEPT("disasm failed");
					}/* end switch */
				}/* c == '%' */
				else {
					/* 不在转移字符的直接打印 */
					func (stream, "%c", *c);
				}

				/* 打印注释 */
				
				if (value_in_comment > 32 || value_in_comment < -16)
					func (stream, "\t; 0x%lx", value_in_comment);
				
				if (is_unpredictable)
					func (stream, UNPREDICTABLE_INSTRUCTION);
				
				return 1;
			}/* end for */
		}/* 指令匹配 */
	}/* end for */
	return 0;
}
