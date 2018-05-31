#include "globals.h"
#include "mem.h"
#include "file.h"
#include "analyze.h"
#include "disinfo.h"

//#define DISASM_DEBUG    1

#if 0
static void disassemble_bytes(elf_file *ef,
							  unsigned char *pfunc,
							  unsigned func_size,
							  disassemble_info *pinfo) {
	elf_section *curr_sec = (elf_section*)(pinfo->section);
	elf_function *curr_func = (elf_function)(pinfo->function);
	unsigned char *func_end = pfunc + func_size;
	unsigned char *pcurr = pfunc;
	int octets = 0;
	
	while (pcurr < func_end) {
	}
}
#endif

static void disassemble_function(elf_file *ef,
								 elf_function &curr_func,
								 disassemble_info *pinfo) {
	unsigned datasize = curr_func.size;
	unsigned start_address = curr_func.func_attribute.address;
	unsigned stop_address = start_address + datasize;
	unsigned start_offset = curr_func.func_attribute.offset;
	unsigned stop_offset = start_offset + datasize;
	unsigned char *fptr = pinfo->buffer + start_offset;
	
#ifdef DISASM_DEBUG
	if (curr_func.name)
		printf("function name = %s\n", curr_func.name);
	printf("function address = 0x%4X\n", start_address);
	printf("function size = %d\n", datasize);
#endif

	/* 开始反汇编 */
	//disassemble_bytes(ef, fptr, datasize, pinfo);
}

static void disassemble_section(elf_file *ef, 
								elf_section &currsec,
								disassemble_info *pinfo) {
	unsigned datasize = currsec.size;
	unsigned start_offset = currsec.offset;
	unsigned stop_offset = start_offset + datasize;
	unsigned start_address = currsec.address;
	unsigned stop_address = start_address + datasize;
	unsigned char *ptr = (unsigned char*)(ef->file_buffer) + start_offset;
	vector<elf_reloc_item> my_relocs;
	vector<elf_function> my_functions;

#ifdef DISASM_DEBUG
	printf("sec name = %s\n", currsec.name);
	printf("sec start address = 0x%4X\n", start_address);
	printf("sec stop address = 0x%4X\n", stop_address);
#endif

	/****************************************/
	// 获取当节对应的重定位表
	/****************************************/
	if (ef->textrel) {
		vector<elf_reloc_item>::iterator iter_rel = 
			ef->relocs.begin();
		vector<elf_reloc_item>::iterator iter_rel_end = 
			ef->relocs.end();
		
		/* 遍历重定位表 */
		for (; iter_rel != iter_rel_end; iter_rel++) {
			if (((*iter_rel).address >= start_address) &&
				((*iter_rel).address < stop_address)) {
				/* 在范围内 */
#ifdef DISASM_DEBUG
				printf("offset = 0x%4X\n", (*iter_rel).address);
#endif
				my_relocs.push_back((*iter_rel));
			}
		}/* end for */
	}/* end if */

	pinfo->buffer = ptr;
	pinfo->buffer_length = datasize;
	pinfo->buffer_vma = start_address;
	pinfo->section = (void*)&currsec;
	
	/****************************************/
	// 获取当前节的所有函数符号
	/****************************************/
	vector<elf_function>::iterator iter_func = 
		ef->functions.begin();
	vector<elf_function>::iterator iter_func_end = 
		ef->functions.end();
	
	/* 遍历重定位表 */
	for (; iter_func != iter_func_end; iter_func++) {
		if (((*iter_func).address >= start_address) &&
			((*iter_func).address < stop_address) &&
			((*iter_func).size != 0) &&
			((*iter_func).type == STT_FUNC)) {
			/* 在范围内 */
			my_functions.push_back((*iter_func));
		}
	}/* end for */

	/* 开始进行遍历符号 */
	iter_func = my_functions.begin();
	iter_func_end = my_functions.end();
	for (; iter_func != iter_func_end; iter_func++) {
		pinfo->function = (void*)&(*iter_func);
		disassemble_function(ef, *iter_func, pinfo);
	}/* end for */
	
}

static void disassemble_sections(elf_file *ef, disassemble_info *pinfo) {
	vector<elf_section>::iterator iter = 
		ef->sections.begin();
	vector<elf_section>::iterator iter_end = 
		ef->sections.end();

	/* 遍历所有节 */
	for (; iter != iter_end; iter++) {
		/* 判断是代码节 */
		if (((*iter).type == SHT_PROGBITS) && 
			((*iter).flag & SHF_EXECINSTR)) {
			disassemble_section(ef, *iter, pinfo);
		}
	}
}

unsigned disasm(elf_file *ef) {
	disassemble_info disinfo;
	disinfo.elf_file = ef;

	disinfo.mach = MACH_ARM;
	disinfo.endian = ENDIAN_LITTLE;
	disinfo.skip_zeroes = DEFAULT_SKIP_ZEROES;
	disinfo.skip_zeroes_at_end = DEFAULT_SKIP_ZEROES_AT_END;
	disinfo.disassembler_needs_relocs = 0;

	/* 遍历反汇编每个节 */
	disassemble_sections(ef, &disinfo);

	return 0;
}
