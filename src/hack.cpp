#include "globals.h"
#include "file.h"
#include "mem.h"
#include "x_elf_tools.h"
#include "loader.h"
#include "mapper.h"
#include "make_ld.h"
#include "dog.h"

#include <stdio.h>
#include <stdlib.h>

static void handle_analyze_options(arguments *opts, 
								   elf_analyze_options *analyze_opt) {
	XASSERT(opts);
	XASSERT(analyze_opt);

	//analyze_opt->dis_opt
	analyze_opt->disasm = opts->disasm;
}

void hackme(InputFile* fi, OutputFile* fo, 
			void* user_data, void* result) {
    XASSERT(fi);
	XASSERT(user_data);
	UNUSED(fo);
    UNUSED(result);

	elf_analyze_options analyze_opt;
	ElfAndroidDynamicTools *tool = new ElfAndroidDynamicTools(fi);
	if (tool == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new ElfAndroidDynamicTools");
		return;
	}
	if (tool->init()) {
		ERROR_INTERNAL_EXCEPT("elf tools init failed");
		return;
	}

	/* 主要负责分析目标程序 */
	struct arguments *opts = (struct arguments *)user_data;
	handle_analyze_options(opts, &analyze_opt);

	/* 打开文件进行初始化分析 */
	if (tool->analyze(&analyze_opt) != 0) {
		ERROR_INTERNAL_EXCEPT("analyze failed");
		return;
	}

	return;
}
