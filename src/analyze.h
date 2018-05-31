#ifndef __TDOG_ANALYZE_H__
#define __TDOG_ANALYZE_H__

#include <vector>
#include <algorithm>
using namespace std;

class MemBuffer;

/* 节结构 */
typedef struct _elf_section {
	char *name;
	unsigned offset;
	unsigned address;
	unsigned size;

	unsigned type;
	unsigned es;
	unsigned flag;
	unsigned link;
	unsigned info;
	unsigned align;

	unsigned segment;
} elf_section;

/* 段结构 */
typedef struct _elf_segment {
	unsigned type;
	unsigned offset;
	unsigned address;
	unsigned phys_address;
	unsigned filesize;
	unsigned memsize;
	unsigned flag;
	unsigned align;
} elf_segment;

/* 重定位项目 */
typedef struct _elf_reloc_item {
	unsigned offset;
	unsigned address;
	unsigned info;
	unsigned type;
	unsigned sym_value;
	char *sym_name;
	unsigned in_got;
} elf_reloc_item;

/* 动态段 */
typedef struct _elf_dynamic_item {
	unsigned type;

	union {
		unsigned value;
		char *libname;
		//vector<elf_reloc_item> *reloc_table;
	};
} elf_dynamic_item;

struct _elf_symbol;
typedef struct _elf_symbol elf_function;

/* 交叉引用表 */
typedef vector<elf_function> elf_func_ref_table;

/* 函数的符号属性 */
typedef struct _elf_function_attribute {
	/* 函数地址 */
	unsigned address;
	unsigned offset;

	/* 是外部引用函数 */
	unsigned is_import;

	/* 函数反汇编源代码 */
	char *asm_source;
	unsigned asm_source_size;

	/* 函数代码 */
	unsigned char *asm_code;
	unsigned asm_code_size;

	/* 交叉引用表 */
	elf_func_ref_table ref_table;
} elf_function_attribute;

/* 符号结构 */
typedef struct _elf_symbol {
	char *name;
	union{
		unsigned offset;
		unsigned address;
		unsigned value;
	};
	unsigned size;

	/* 属性 */
	unsigned bind;
	unsigned type;
	unsigned visibly;
	unsigned ndx;

	/* 映射符号 */
	unsigned is_mapping_symbol;
	unsigned mapping_type;

	/* 关联的重定位表 */
	unsigned has_reloc;
	unsigned reloc_address;

	/* 如果是一个函数 */
	elf_function_attribute func_attribute;
} elf_symbol;

/* 反汇编选项 */
typedef struct _elf_disassemble_options {
	int dis_all;/* 忽略是否是代码 */
	int insn_length;/* 一条指令的长度 */
	int need_reloc;/* 需要进行重定位 */
} elf_disassemble_options;

/* 分析选项 */
typedef struct _elf_analyze_options {
	unsigned disasm;                        /* 进行反汇编 */
	elf_disassemble_options dis_opt;      	/* 反汇编选项 */
	struct argument *opt;                   /* 全局选项的副本 */
} elf_analyze_options;

/* 一个完整的文件 */
typedef struct _elf_file {
	MemBuffer file_buffer;
	unsigned size_file_buffer;

	MemBuffer mem_buffer;
	unsigned size_mem_buffer;

	vector<elf_section> sections;   	/* 节 */
	vector<elf_segment> segments;      /* 段 */
	vector<elf_reloc_item> relocs;     /* 重定位项 */
	vector<elf_dynamic_item> dynamics; /* 动态段 */
	vector<elf_symbol> symbols;        /* 符号表 */
	vector<elf_function> functions;    /* 函数表 */
	
	/* pltgot表 */
	unsigned *plt_got;
	unsigned plt_got_address;
	unsigned plt_got_size;

	/* 需要进行代码重定位 */
	unsigned textrel;

	/* 分析选项 */
	elf_analyze_options analyze_opt;
} elf_file;

/* 反汇编引擎 */
unsigned disasm(elf_file *ef);

/* 确定节属于哪个段 */
unsigned make_sure_section_to_segment(elf_file *ef, unsigned sec_addr);
/* 确定符号是否属于映射符号 */
unsigned make_sure_symbol_is_mapping(char *name);
/* 确定映射符号类型 */
unsigned make_sure_symbol_mapping_type(char *name);
/* 排序 */
bool sort_sections(const elf_section &v1, const elf_section &v2);
bool sort_segments(const elf_segment &v1, const elf_segment &v2);
bool sort_reloc_table(const elf_reloc_item &v1, const elf_reloc_item &v2);
bool sort_symbols(const elf_symbol &v1, const elf_symbol &v2);
bool sort_functions(const elf_function &v1, const elf_function &v2);

/* 输出报告 */
void analyze_report(elf_file *ef);

#endif
