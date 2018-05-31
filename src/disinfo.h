#ifndef __DISINFO_H__
#define __DISINFO_H__

#include "arm.h"

typedef struct _disassemble_info {
	void *stream;                         /* 输出流 */
	fprintf_ftype fprintf_func;           /* 打印函数指针 */

	void *application_data;               /* 用户私有数据 */
	void *elf_file;                       /* elf_file结构 */
	unsigned flavour;                     /* unknow */
	unsigned long mach;                   /* 体系结构 */
	unsigned endian;                      /* 字序 */
	unsigned endian_code;                 /* 字序编码 */

	void *function;                       /* 所属函数 */
	void *section;                        /* 所属节 */

	void *insn_sets;	                  /* 指令集合 */
	unsigned flags;                       /* 高16位保留,低16位反汇编内部使用 */

#define INSN_HAS_RELOC	 (1 << 31)              /* 当前指令存在重定位项 */
#define DISASSEMBLE_DATA (1 << 30)	            /* 将数据视为代码 */
#define USER_SPECIFIED_MACHINE_TYPE (1 << 29) 	/* 用户指定反汇编机器类型 */

	void *private_data;                  /* 内部使用的私有数据  */

	/* 读入数据的缓存 */
	unsigned char *buffer;
	unsigned buffer_vma;
	unsigned buffer_length;

	int bytes_per_line;                  /* 屏幕显示一行有多少字节 */
	int bytes_per_chunk;                 /* 每个负载的字节数 */
	unsigned display_endian;
	unsigned octets_per_byte;

	unsigned skip_zeroes;                /* 跳过0字节 */
	unsigned skip_zeroes_at_end;         /* 末尾跳过0字节 */
	unsigned disassembler_needs_relocs;  /* 总是需要重定位 */


	char insn_info_valid;		         /* 分支指令已经被设置 */
	char branch_delay_insns;	         /* (0 = normal) */
	char data_size;
	unsigned insn_type;                  /* 指令类型 */
	unsigned target;
	unsigned target2;
	
	char * disassembler_options;         /* 反汇编选项 */

	/******************************/
	// 函数集合
	/******************************/
	/* 打印地址 */
	void (*print_address_func)(unsigned addr, 
							   struct _disassemble_info *dinfo);
	/* 读取内存 */
	int (*read_memory_func)(unsigned memaddr, 
							unsigned char *myaddr, 
							unsigned int length,
							struct _disassemble_info *dinfo);
	/* 读取内存错误 */
	void (*memory_error_func)(int status, 
							  unsigned memaddr, 
							  struct _disassemble_info *dinfo);
	/* 如果一个符号在给定的地址(addr)函数返回1，否则返回0 */
	int (*symbol_at_address_func)(unsigned addr,
								  struct _disassemble_info *dinfo);

	/* 确定一个符号是否有效 */
	unsigned char (*symbol_is_valid)(void *sym, 
									 struct _disassemble_info *dinfo);
	

} disassemble_info;

#endif
