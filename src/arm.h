/* 针对不同的体系的特性 */
typedef struct _arm_feature_set {
	unsigned long core;       /* 微处理器类型 */
	unsigned long coproc;     /* 协处理器类型 */
} arm_feature_set;

/* 是否拥有这个特性 */
#define ARM_CPU_HAS_FEATURE(CPU,FEAT)									\
	(((CPU).core & (FEAT).core) != 0 || ((CPU).coproc & (FEAT).coproc) != 0)

/* 任何特性 */
#define ARM_CPU_IS_ANY(CPU)	((CPU).core == ((arm_feature_set)ARM_ANY).core)

/* 合并特性集合 */
#define ARM_MERGE_FEATURE_SETS(TARG,F1,F2)		\
	do {										\
		(TARG).core = (F1).core | (F2).core;	\
		(TARG).coproc = (F1).coproc | (F2).coproc;	\
  } while (0)

/* 清除特性 */
#define ARM_CLEAR_FEATURE(TARG,F1,F2)			\
	do {										\
		(TARG).core = (F1).core &~ (F2).core;	\
		(TARG).coproc = (F1).coproc &~ (F2).coproc;	\
	} while (0)

/* 取某个特性 */
#define ARM_FEATURE(core, coproc) {(core), (coproc)}

/************************************************************/
// 宏工具
/************************************************************/
#ifndef strneq
#define strneq(a,b,n)	(strncmp ((a), (b), (n)) == 0)
#endif

#ifndef NUM_ELEM
#define NUM_ELEM(a)     (sizeof (a) / sizeof (a)[0])
#endif

/************************************************************/
// 体系结构
/************************************************************/
#define MACH_ARM              0
#define MACH_ARM_XSCALE       1
#define MACH_ARM_IWMMXT       2
#define MACH_ARM_IWMMXT2      4
#define MACH_X86              0x10
#define MACH_MIPS             0x20

/************************************************************/
// 字节序
/************************************************************/
#define ENDIAN_LITTLE         0
#define ENDIAN_BIG            1

/* 指令类型 */
enum dis_insn_type {
	dis_noninsn,		/* 不是一个有效的指令 */
	dis_nonbranch,		/* 不是一个分支指令 */
	dis_branch,			/* 无条件分支指令 */
	dis_condbranch,		/* 条件分支 */
	dis_jsr,			/* 跳转到子函数 */
	dis_condjsr,		/* 条件跳转到子函数 */
	dis_dref,			/* 数据引用指令 */
	dis_dref2			/* 两个数据在一条指令中引用 */
};

/************************************************************/
// 函数原型
/************************************************************/
typedef int (*fprintf_ftype) (void *, const char*, ...);
typedef unsigned char (*fdisasm_ftype)(unsigned pc,
									   void *info,
									   long given,
									   unsigned char thumb);

/* opcode的哨兵值 */
enum opcode_sentinel {
	SENTINEL_IWMMXT_START = 1,
	SENTINEL_IWMMXT_END,
	SENTINEL_GENERIC_START
};

/* 映射状态 */
enum map_type {
	MAP_ARM,/* ARM指令 */
	MAP_THUMB,/* THUMB指令 */
	MAP_DATA/* 数据 */
};

/* arm私有数据 */
typedef struct _arm_private_data {
	arm_feature_set features;
	int has_mapping_symbols;
	enum map_type last_type;
	int last_mapping_sym;
	unsigned last_mapping_addr;
} arm_private_data;

typedef struct _opcode32 {
	unsigned long arch;      /* 体系结构 */
	/* 如果arch等于0则value是一个哨兵值 */
	unsigned long value;
	/* 如果(op & mask) == value 
	 * 则认可这是一条指令 Recognise insn 
	 * if (op & mask) == value. 
	 */
	unsigned long mask;
	/* 如何反汇编这条指令 */
	const char *assembler;
} opcode32;

/* 与opcode32相同 */
typedef struct _opcode16 {
	unsigned long arch;
	unsigned short value;
	unsigned short mask;
	const char *assembler;
} opcode16;

/* 寄存器名称 */
typedef struct _arm_regname {
	const char *name;
	const char *description;
	const char *reg_names[16];
} arm_regname;


/************************************************************/
// 寄存器常量
/************************************************************/
extern const char *const arm_conditional[];
extern const char *const arm_fp_const[];
extern const char *const arm_shift[];
extern const arm_regname regnames[];
extern const char *const iwmmxt_wwnames[];
extern const char *const iwmmxt_wwssnames[];
extern const char *const iwmmxt_regnames[];
extern const char *const iwmmxt_cregnames[];
extern unsigned int regname_selected;

#define NUM_ARM_REGNAMES  NUM_ELEM (regnames)                /* 寄存器数量 */
#define arm_regnames regnames[regname_selected].reg_names    /* 寄存器的名称 */

/************************************************************/
// 全局选项
/************************************************************/
extern unsigned char force_thumb;
/* 在开始之前跳过0字符的数量,<可选属性> */
#define DEFAULT_SKIP_ZEROES   8

/* 在一个节末尾跳过0字符的数量.如果在末尾的0字符的数量是
 * SKIP_ZEROES_AT_END 与 SKIP_ZEROES,它们将被反汇编.如果仅比
 * SKIP_ZEROES_AT_END大一点,则它们会被跳过.尝试反汇编0替代节对齐
 */
#define DEFAULT_SKIP_ZEROES_AT_END 3

/************************************************************/
// ifthen状态
/************************************************************/
extern unsigned int ifthen_state;
extern unsigned int ifthen_next_state;
extern unsigned ifthen_address;
#define IFTHEN_COND ((ifthen_state >> 4) & 0xf)              /* IT条件检测 */
#define COND_UNCOND 16                                       /* 标记当前的
															  * 条件状态是无
															  * 条件的或者在
															  * 外部的IT块
															  */

/************************************************************/
// 辅助函数
/************************************************************/
int get_arm_regname_num_options (void);
int set_arm_regname_option (int option);
int get_arm_regnames (int option,
					  const char **setname,
					  const char **setdescription,
					  const char *const **register_names);
const char *banked_regname (unsigned reg);
const char *data_barrier_option (unsigned option);
const char *psr_name (int regno);

/************************************************************/
// 编码规则
/************************************************************/
//extern const opcode32 coprocessor_opcodes[];   /* dis-arm-coprocessor.cpp */
//extern const opcode32 neon_opcodes[];          /* dis-arm-neon.cpp */
//extern const opcode32 arm_opcodes[];           /* dis-arm-arm.cpp */
//extern const opcode16 thumb_opcodes[];         /* dis-arm-thumb16.cpp */
//extern const opcode32 thumb32_opcodes[];       /* dis-arm-thumb32.cpp */

const char *arm_decode_bitfield(const char *ptr,
								unsigned long insn,
								unsigned long *valuep,
								int *widthp);
void arm_decode_shift(long given, fprintf_ftype func, 
					  void *stream, unsigned char print_shift);


/* 反汇编协处理器 dis-arm-coprocessor.cpp */
unsigned char print_insn_coprocessor(unsigned pc,
									 void *pinfo,
									 long given,
									 unsigned char thumb);
/* 反汇编neon指令 dis-arm-neon.cpp */
unsigned char print_insn_neon(unsigned pc, 
							  void *pinfo, 
							  long given, 
							  unsigned char thumb);
/* 反汇编thumb16指令 dis-arm-thumb16.cpp */
unsigned char print_insn_thumb16(unsigned pc, 
								 void *pinfo, 
								 long given, 
								 unsigned char thumb);
/* 反汇编thumb32指令 dis-arm-thumb32.cpp */
unsigned char print_insn_thumb32(unsigned pc, 
								 void *pinfo, 
								 long given, 
								 unsigned char thumb);
/* 反汇编thumb32指令 dis-arm-arm.cpp */
unsigned char print_insn_arm(unsigned pc, 
							 void *pinfo, 
							 long given, 
							 unsigned char thumb);


/************************************************************/
// CPU扩展掩码
/************************************************************/
#define ARM_EXT_V1	 0x00000001	/* 所有的处理器(core集合) */
#define ARM_EXT_V2	 0x00000002	/* Multiply指令  */
#define ARM_EXT_V2S	 0x00000004	/* SWP指令 */
#define ARM_EXT_V3	 0x00000008	/* MSR MRS */
#define ARM_EXT_V3M	 0x00000010	/* 允许long multiplies */
#define ARM_EXT_V4	 0x00000020	/* 允许半字加载 */
#define ARM_EXT_V4T	 0x00000040	/* Thumb */
#define ARM_EXT_V5	 0x00000080	/* 允许CLZ等 */
#define ARM_EXT_V5T	 0x00000100	/* Improved interworking. */
#define ARM_EXT_V5ExP	 0x00000200	/* DSP core set. */
#define ARM_EXT_V5E	 0x00000400	/* DSP Double transfers. */
#define ARM_EXT_V5J	 0x00000800	/* Jazelle extension. */
#define ARM_EXT_V6       0x00001000     /* ARM V6. */
#define ARM_EXT_V6K      0x00002000     /* ARM V6K. */
/* 
 * 0x00004000 Was ARM V6Z.
 */
#define ARM_EXT_V8	 0x00004000     /* is now ARMv8.*/
#define ARM_EXT_V6T2	 0x00008000	/* Thumb-2. */
#define ARM_EXT_DIV	 0x00010000	/* Integer division. */
/* 
 * The 'M' in Arm V7M stands for Microcontroller.
 * On earlier architecture variants it stands for Multiply.
 */
#define ARM_EXT_V5E_NOTM 0x00020000	/* Arm V5E but not Arm V7M. */
#define ARM_EXT_V6_NOTM	 0x00040000	/* Arm V6 but not Arm V7M. */
#define ARM_EXT_V7	 0x00080000	/* Arm V7. */
#define ARM_EXT_V7A	 0x00100000	/* Arm V7A. */
#define ARM_EXT_V7R	 0x00200000	/* Arm V7R. */
#define ARM_EXT_V7M	 0x00400000	/* Arm V7M. */
#define ARM_EXT_V6M	 0x00800000	/* ARM V6M. */
#define ARM_EXT_BARRIER	 0x01000000	/* DSB/DMB/ISB.	*/
#define ARM_EXT_THUMB_MSR 0x02000000	/* Thumb MSR/MRS. */
#define ARM_EXT_V6_DSP 0x04000000	/* ARM v6 (DSP-related),not in v7-M.  */
#define ARM_EXT_MP   0x08000000     /* Multiprocessing Extensions.  */
#define ARM_EXT_SEC	 0x10000000	/* Security extensions.  */
#define ARM_EXT_OS	 0x20000000	/* OS Extensions.  */
#define ARM_EXT_ADIV 0x40000000	/* Integer divide extensions in ARM state.  */
#define ARM_EXT_VIRT 0x80000000	/* Virtualization extensions.  */

/************************************************************/
// Co-processor space 扩展
/************************************************************/
#define ARM_CEXT_XSCALE   0x00000001	/* Allow MIA etc.          */
#define ARM_CEXT_MAVERICK 0x00000002	/* Use Cirrus/DSP coprocessor.  */
#define ARM_CEXT_IWMMXT   0x00000004    /* Intel Wireless MMX technology coprocessor.   */
#define ARM_CEXT_IWMMXT2  0x00000008    /* Intel Wireless MMX technology coprocessor version 2.   */

#define FPU_ENDIAN_PURE	 0x80000000	/* Pure-endian doubles.	      */
#define FPU_ENDIAN_BIG	 0		/* Double words-big-endian.   */
#define FPU_FPA_EXT_V1	 0x40000000	/* Base FPA instruction set.  */
#define FPU_FPA_EXT_V2	 0x20000000	/* LFM/SFM.		      */
#define FPU_MAVERICK	 0x10000000	/* Cirrus Maverick.	      */
#define FPU_VFP_EXT_V1xD 0x08000000	/* Base VFP instruction set.  */
#define FPU_VFP_EXT_V1	 0x04000000	/* Double-precision insns.    */
#define FPU_VFP_EXT_V2	 0x02000000	/* ARM10E VFPr1.	      */
#define FPU_VFP_EXT_V3xD 0x01000000	/* VFPv3 single-precision.    */
#define FPU_VFP_EXT_V3	 0x00800000	/* VFPv3 double-precision.    */
#define FPU_NEON_EXT_V1	 0x00400000	/* Neon (SIMD) insns.	      */
#define FPU_VFP_EXT_D32  0x00200000	/* Registers D16-D31.	      */
#define FPU_VFP_EXT_FP16 0x00100000	/* Half-precision extensions. */
#define FPU_NEON_EXT_FMA 0x00080000	/* Neon fused multiply-add    */
#define FPU_VFP_EXT_FMA	 0x00040000	/* VFP fused multiply-add     */
#define FPU_VFP_EXT_ARMV8 0x00020000	/* FP for ARMv8.  */
#define FPU_NEON_EXT_ARMV8 0x00010000	/* Neon for ARMv8.  */
#define FPU_CRYPTO_EXT_ARMV8 0x00008000	/* Crypto for ARMv8.  */
#define CRC_EXT_ARMV8	 0x00004000	/* CRC32 for ARMv8.  */

/************************************************************/
// 基础架构与扩展架构的总和.ARM(rev E)定义允许: ARMv3,ARMv3M,ARMv4xM
// ARMv4,ARMv4TxM,ARMv4T,ARMv5xM,ARMv5,ARMv5TxM,ARMv5T,ARMv5TExP,ARMv5TE,
// 以上这些我们添加到三个或以上的特性到ARM6.最终这些特性继承特性扩展在
// 协处理器空间
/************************************************************/
#define ARM_AEXT_V1	    ARM_EXT_V1
#define ARM_AEXT_V2	    (ARM_AEXT_V1 | ARM_EXT_V2)
#define ARM_AEXT_V2S    (ARM_AEXT_V2 | ARM_EXT_V2S)
#define ARM_AEXT_V3	    (ARM_AEXT_V2S | ARM_EXT_V3)
#define ARM_AEXT_V3M	(ARM_AEXT_V3 | ARM_EXT_V3M)
#define ARM_AEXT_V4xM	(ARM_AEXT_V3 | ARM_EXT_V4)
#define ARM_AEXT_V4	    (ARM_AEXT_V3M | ARM_EXT_V4)
#define ARM_AEXT_V4TxM	(ARM_AEXT_V4xM | ARM_EXT_V4T)
#define ARM_AEXT_V4T	(ARM_AEXT_V4 | ARM_EXT_V4T)
#define ARM_AEXT_V5xM	(ARM_AEXT_V4xM | ARM_EXT_V5)
#define ARM_AEXT_V5	    (ARM_AEXT_V4 | ARM_EXT_V5)
#define ARM_AEXT_V5TxM	(ARM_AEXT_V5xM | ARM_EXT_V4T | ARM_EXT_V5T)
#define ARM_AEXT_V5T	(ARM_AEXT_V5 | ARM_EXT_V4T | ARM_EXT_V5T)
#define ARM_AEXT_V5TExP	(ARM_AEXT_V5T | ARM_EXT_V5ExP)
#define ARM_AEXT_V5TE	(ARM_AEXT_V5TExP | ARM_EXT_V5E)
#define ARM_AEXT_V5TEJ	(ARM_AEXT_V5TE	| ARM_EXT_V5J)
#define ARM_AEXT_V6     (ARM_AEXT_V5TEJ | ARM_EXT_V6)
#define ARM_AEXT_V6K    (ARM_AEXT_V6 | ARM_EXT_V6K)
#define ARM_AEXT_V6Z    (ARM_AEXT_V6K | ARM_EXT_SEC)
#define ARM_AEXT_V6ZK   (ARM_AEXT_V6K | ARM_EXT_SEC)
#define ARM_AEXT_V6T2   (ARM_AEXT_V6 | ARM_EXT_V6T2 | ARM_EXT_V6_NOTM | \
						 ARM_EXT_THUMB_MSR | ARM_EXT_V6_DSP)
#define ARM_AEXT_V6KT2  (ARM_AEXT_V6T2 | ARM_EXT_V6K)
#define ARM_AEXT_V6ZT2  (ARM_AEXT_V6T2 | ARM_EXT_SEC)
#define ARM_AEXT_V6ZKT2 (ARM_AEXT_V6T2 | ARM_EXT_V6K | ARM_EXT_SEC)
#define ARM_AEXT_V7_ARM	(ARM_AEXT_V6KT2 | ARM_EXT_V7 | ARM_EXT_BARRIER)
#define ARM_AEXT_V7A	(ARM_AEXT_V7_ARM | ARM_EXT_V7A)
#define ARM_AEXT_V7VE	(ARM_AEXT_V7A  | ARM_EXT_DIV | ARM_EXT_ADIV \
						 | ARM_EXT_VIRT | ARM_EXT_SEC | ARM_EXT_MP)
#define ARM_AEXT_V7R	(ARM_AEXT_V7_ARM | ARM_EXT_V7R | ARM_EXT_DIV)
#define ARM_AEXT_NOTM   (ARM_AEXT_V4 | ARM_EXT_V5ExP | ARM_EXT_V5J |	\
						 ARM_EXT_V6_NOTM | ARM_EXT_V6_DSP )
#define ARM_AEXT_V6M_ONLY ((ARM_EXT_BARRIER | ARM_EXT_V6M | ARM_EXT_THUMB_MSR) \
						   & ~(ARM_AEXT_NOTM))
#define ARM_AEXT_V6M     ((ARM_AEXT_V6K | ARM_AEXT_V6M_ONLY) & ~(ARM_AEXT_NOTM))
#define ARM_AEXT_V6SM    (ARM_AEXT_V6M | ARM_EXT_OS)
#define ARM_AEXT_V7M     ((ARM_AEXT_V7_ARM | ARM_EXT_V6M | ARM_EXT_V7M	\
						   | ARM_EXT_DIV) & ~(ARM_AEXT_NOTM))
#define ARM_AEXT_V7      (ARM_AEXT_V7A & ARM_AEXT_V7R & ARM_AEXT_V7M)
#define ARM_AEXT_V7EM    (ARM_AEXT_V7M | ARM_EXT_V5ExP | ARM_EXT_V6_DSP)
#define ARM_AEXT_V8A     (ARM_AEXT_V7A | ARM_EXT_MP | ARM_EXT_SEC | \
						  ARM_EXT_DIV | ARM_EXT_ADIV |				\
						  ARM_EXT_VIRT | ARM_EXT_V8)

/************************************************************/
// 协处理器特殊的扩展特性
/************************************************************/
#define ARM_ARCH_XSCALE	ARM_FEATURE(ARM_AEXT_V5TE, ARM_CEXT_XSCALE)
#define ARM_ARCH_IWMMXT	ARM_FEATURE(ARM_AEXT_V5TE, ARM_CEXT_XSCALE | \
									ARM_CEXT_IWMMXT)
#define ARM_ARCH_IWMMXT2 ARM_FEATURE(ARM_AEXT_V5TE, ARM_CEXT_XSCALE |	\
									 ARM_CEXT_IWMMXT | ARM_CEXT_IWMMXT2)

#define FPU_VFP_V1xD	(FPU_VFP_EXT_V1xD | FPU_ENDIAN_PURE)
#define FPU_VFP_V1	    (FPU_VFP_V1xD | FPU_VFP_EXT_V1)
#define FPU_VFP_V2	    (FPU_VFP_V1 | FPU_VFP_EXT_V2)
#define FPU_VFP_V3D16	(FPU_VFP_V2 | FPU_VFP_EXT_V3xD | FPU_VFP_EXT_V3)
#define FPU_VFP_V3	    (FPU_VFP_V3D16 | FPU_VFP_EXT_D32)
#define FPU_VFP_V3xD	(FPU_VFP_V1xD | FPU_VFP_EXT_V2 | FPU_VFP_EXT_V3xD)
#define FPU_VFP_V4D16	(FPU_VFP_V3D16 | FPU_VFP_EXT_FP16 | FPU_VFP_EXT_FMA)
#define FPU_VFP_V4	    (FPU_VFP_V3 | FPU_VFP_EXT_FP16 | FPU_VFP_EXT_FMA)
#define FPU_VFP_V4_SP_D16 (FPU_VFP_V3xD | FPU_VFP_EXT_FP16 | FPU_VFP_EXT_FMA)
#define FPU_VFP_ARMV8	(FPU_VFP_V4 | FPU_VFP_EXT_ARMV8)
#define FPU_NEON_ARMV8	(FPU_NEON_EXT_V1 | FPU_NEON_EXT_FMA | FPU_NEON_EXT_ARMV8)
#define FPU_CRYPTO_ARMV8 (FPU_CRYPTO_EXT_ARMV8)
#define FPU_VFP_HARD	(FPU_VFP_EXT_V1xD | FPU_VFP_EXT_V1 | FPU_VFP_EXT_V2 \
						 | FPU_VFP_EXT_V3xD | FPU_VFP_EXT_FMA | FPU_NEON_EXT_FMA \
                         | FPU_VFP_EXT_V3 | FPU_NEON_EXT_V1 | FPU_VFP_EXT_D32)
#define FPU_FPA		    (FPU_FPA_EXT_V1 | FPU_FPA_EXT_V2)

/************************************************************/
// 弃用
/************************************************************/
#define FPU_ARCH_VFP	ARM_FEATURE (0, FPU_ENDIAN_PURE)
#define FPU_ARCH_FPE	ARM_FEATURE (0, FPU_FPA_EXT_V1)
#define FPU_ARCH_FPA	ARM_FEATURE (0, FPU_FPA)
#define FPU_ARCH_VFP_V1xD ARM_FEATURE (0, FPU_VFP_V1xD)
#define FPU_ARCH_VFP_V1	  ARM_FEATURE (0, FPU_VFP_V1)
#define FPU_ARCH_VFP_V2	  ARM_FEATURE (0, FPU_VFP_V2)
#define FPU_ARCH_VFP_V3D16	ARM_FEATURE (0, FPU_VFP_V3D16)
#define FPU_ARCH_VFP_V3D16_FP16 ARM_FEATURE (0, FPU_VFP_V3D16 | FPU_VFP_EXT_FP16)
#define FPU_ARCH_VFP_V3	  ARM_FEATURE (0, FPU_VFP_V3)
#define FPU_ARCH_VFP_V3_FP16	ARM_FEATURE (0, FPU_VFP_V3 | FPU_VFP_EXT_FP16)
#define FPU_ARCH_VFP_V3xD	ARM_FEATURE (0, FPU_VFP_V3xD)
#define FPU_ARCH_VFP_V3xD_FP16	ARM_FEATURE (0, FPU_VFP_V3xD | FPU_VFP_EXT_FP16)
#define FPU_ARCH_NEON_V1  ARM_FEATURE (0, FPU_NEON_EXT_V1)
#define FPU_ARCH_VFP_V3_PLUS_NEON_V1 ARM_FEATURE (0, FPU_VFP_V3 | FPU_NEON_EXT_V1)
#define FPU_ARCH_NEON_FP16 ARM_FEATURE (0, FPU_VFP_V3 | FPU_NEON_EXT_V1 \
										| FPU_VFP_EXT_FP16)
#define FPU_ARCH_VFP_HARD ARM_FEATURE (0, FPU_VFP_HARD)
#define FPU_ARCH_VFP_V4 ARM_FEATURE(0, FPU_VFP_V4)
#define FPU_ARCH_VFP_V4D16 ARM_FEATURE(0, FPU_VFP_V4D16)
#define FPU_ARCH_VFP_V4_SP_D16 ARM_FEATURE(0, FPU_VFP_V4_SP_D16)
#define FPU_ARCH_NEON_VFP_V4 ARM_FEATURE(0, FPU_VFP_V4 | FPU_NEON_EXT_V1 \
										 | FPU_NEON_EXT_FMA)
#define FPU_ARCH_VFP_ARMV8 ARM_FEATURE(0, FPU_VFP_ARMV8)
#define FPU_ARCH_NEON_VFP_ARMV8 ARM_FEATURE(0, FPU_NEON_ARMV8 | FPU_VFP_ARMV8)
#define FPU_ARCH_CRYPTO_NEON_VFP_ARMV8 ARM_FEATURE(0, FPU_CRYPTO_ARMV8 | \
												   FPU_NEON_ARMV8 | FPU_VFP_ARMV8)
#define ARCH_CRC_ARMV8 ARM_FEATURE(0, CRC_EXT_ARMV8)
#define FPU_ARCH_ENDIAN_PURE ARM_FEATURE (0, FPU_ENDIAN_PURE)
#define FPU_ARCH_MAVERICK ARM_FEATURE (0, FPU_MAVERICK)

#define ARM_ARCH_V1	    ARM_FEATURE (ARM_AEXT_V1, 0)
#define ARM_ARCH_V2	    ARM_FEATURE (ARM_AEXT_V2, 0)
#define ARM_ARCH_V2S	ARM_FEATURE (ARM_AEXT_V2S, 0)
#define ARM_ARCH_V3	    ARM_FEATURE (ARM_AEXT_V3, 0)
#define ARM_ARCH_V3M	ARM_FEATURE (ARM_AEXT_V3M, 0)
#define ARM_ARCH_V4xM	ARM_FEATURE (ARM_AEXT_V4xM, 0)
#define ARM_ARCH_V4	    ARM_FEATURE (ARM_AEXT_V4, 0)
#define ARM_ARCH_V4TxM	ARM_FEATURE (ARM_AEXT_V4TxM, 0)
#define ARM_ARCH_V4T	ARM_FEATURE (ARM_AEXT_V4T, 0)
#define ARM_ARCH_V5xM	ARM_FEATURE (ARM_AEXT_V5xM, 0)
#define ARM_ARCH_V5	    ARM_FEATURE (ARM_AEXT_V5, 0)
#define ARM_ARCH_V5TxM	ARM_FEATURE (ARM_AEXT_V5TxM, 0)
#define ARM_ARCH_V5T	ARM_FEATURE (ARM_AEXT_V5T, 0)
#define ARM_ARCH_V5TExP	ARM_FEATURE (ARM_AEXT_V5TExP, 0)
#define ARM_ARCH_V5TE	ARM_FEATURE (ARM_AEXT_V5TE, 0)
#define ARM_ARCH_V5TEJ	ARM_FEATURE (ARM_AEXT_V5TEJ, 0)
#define ARM_ARCH_V6	    ARM_FEATURE (ARM_AEXT_V6, 0)
#define ARM_ARCH_V6K	ARM_FEATURE (ARM_AEXT_V6K, 0)
#define ARM_ARCH_V6Z	ARM_FEATURE (ARM_AEXT_V6Z, 0)
#define ARM_ARCH_V6ZK	ARM_FEATURE (ARM_AEXT_V6ZK, 0)
#define ARM_ARCH_V6T2	ARM_FEATURE (ARM_AEXT_V6T2, 0)
#define ARM_ARCH_V6KT2	ARM_FEATURE (ARM_AEXT_V6KT2, 0)
#define ARM_ARCH_V6ZT2	ARM_FEATURE (ARM_AEXT_V6ZT2, 0)
#define ARM_ARCH_V6ZKT2	ARM_FEATURE (ARM_AEXT_V6ZKT2, 0)
#define ARM_ARCH_V6M	ARM_FEATURE (ARM_AEXT_V6M, 0)
#define ARM_ARCH_V6SM	ARM_FEATURE (ARM_AEXT_V6SM, 0)
#define ARM_ARCH_V7	    ARM_FEATURE (ARM_AEXT_V7, 0)
#define ARM_ARCH_V7A	ARM_FEATURE (ARM_AEXT_V7A, 0)
#define ARM_ARCH_V7VE	ARM_FEATURE (ARM_AEXT_V7VE, 0)
#define ARM_ARCH_V7R	ARM_FEATURE (ARM_AEXT_V7R, 0)
#define ARM_ARCH_V7M	ARM_FEATURE (ARM_AEXT_V7M, 0)
#define ARM_ARCH_V7EM	ARM_FEATURE (ARM_AEXT_V7EM, 0)
#define ARM_ARCH_V8A	ARM_FEATURE (ARM_AEXT_V8A, 0)

/************************************************************/
// 一些有用的组合
/************************************************************/
#define ARM_ARCH_NONE	ARM_FEATURE (0, 0)
#define FPU_NONE	    ARM_FEATURE (0, 0)
#define ARM_ANY		    ARM_FEATURE (-1, 0)	/* 任何基础特性 */
#define FPU_ANY_HARD	ARM_FEATURE (0, FPU_FPA | FPU_VFP_HARD | \
									 FPU_MAVERICK)
#define ARM_ARCH_THUMB2 ARM_FEATURE (ARM_EXT_V6T2 | ARM_EXT_V7 | \
									 ARM_EXT_V7A | ARM_EXT_V7R | \
									 ARM_EXT_V7M | ARM_EXT_DIV, 0)
/* v7-a+sec.  */
#define ARM_ARCH_V7A_SEC ARM_FEATURE (ARM_AEXT_V7A | ARM_EXT_SEC, 0)
/* v7-a+mp+sec.  */
#define ARM_ARCH_V7A_MP_SEC ARM_FEATURE (ARM_AEXT_V7A | ARM_EXT_MP \
										 | ARM_EXT_SEC, 0)
/* v7-r+idiv.  */
#define ARM_ARCH_V7R_IDIV ARM_FEATURE (ARM_AEXT_V7R | ARM_EXT_ADIV, 0)
/* Features that are present in v6M and v6S-M but not other v6 cores.  */
#define ARM_ARCH_V6M_ONLY ARM_FEATURE (ARM_AEXT_V6M_ONLY, 0)
/* v8-a+fp.  */
#define ARM_ARCH_V8A_FP	ARM_FEATURE (ARM_AEXT_V8A, FPU_ARCH_VFP_ARMV8)
/* v8-a+simd (implies fp).  */
#define ARM_ARCH_V8A_SIMD ARM_FEATURE (ARM_AEXT_V8A, FPU_ARCH_NEON_VFP_ARMV8)
/* v8-a+crypto (implies simd+fp). */
#define ARM_ARCH_V8A_CRYPTOV1 ARM_FEATURE (ARM_AEXT_V8A,				\
										   FPU_ARCH_CRYPTO_NEON_VFP_ARMV8)

/************************************************************/
// 指令说明
/************************************************************/
/* 没有定义的指令 */
#define UNDEFINED_INSTRUCTION      "\t\t; <UNDEFINED> instruction: %0-31x"
/* 未预料到的指令 */
#define UNPREDICTABLE_INSTRUCTION  "\t; <UNPREDICTABLE>"
