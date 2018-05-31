#include "globals.h"
#include "mem.h"
#include "file.h"
#include "x_elf_tools.h"

ElfAndroidDynamicTools::ElfAndroidDynamicTools() : ElfDynamicTools() {
	init_datas();
}

ElfAndroidDynamicTools::ElfAndroidDynamicTools(InputFile* fi) : ElfDynamicTools(fi) {
	init_datas();
}

ElfAndroidDynamicTools::~ElfAndroidDynamicTools() {
}

int ElfAndroidDynamicTools::init(bool custom_support, bool elfrel) {
	return super::init(custom_support, elfrel);
}

int ElfAndroidDynamicTools::init_merge_ptr(unsigned char* ptr, 
										   unsigned mem_size) {
	return super::init_merge_ptr(ptr, mem_size);
}

int ElfAndroidDynamicTools::update_merge_mem(unsigned add_size) {
	return super::update_merge_mem(add_size);
}

int ElfAndroidDynamicTools::init_datas() {
	_jni_onload_sym = NULL;
	_jni_onload_va = 0;
	return 0;
}

unsigned ElfAndroidDynamicTools::get_android_jni_onload() {
	_jni_onload_sym = (Elf32_Sym*)elf_lookup("JNI_OnLoad");
	if (_jni_onload_sym) {
		_jni_onload_va = get_te32(&_jni_onload_sym->st_value);
		return _jni_onload_va;
	}
	return 1;
}

bool ElfAndroidDynamicTools::find_entry_symbols_in_so() {
	Elf32_Sym* symtab = (Elf32_Sym*)_dt_symtab.context;
	if (ET_DYN == get_te16(&_ehdri->e_type)) {
		/* find plt rel */
		Elf32_Rel const * jmprel = 
			(Elf32_Rel const *) _dt_jmprel.context;
		for (int sz = _dt_pltrelsz.value; 0 < sz;
			 (sz -= sizeof(Elf32_Rel)), ++jmprel) {
			unsigned const symnum = get_te32(&jmprel->r_info) >> 8;
			char const * const symnam = 
				get_te32(&(symtab[symnum].st_name)) + 
				(char*)_dt_strtab.context;
			if (0 == strcmp(symnam, "__libc_start_main")
				|| 0 == strcmp(symnam, "__uClibc_main")
				|| 0 == strcmp(symnam, "__uClibc_start_main"))
				return true;
		}
	}
	return false;
}

int ElfAndroidDynamicTools::analyze(elf_analyze_options* opts/*=NULL*/) {
	int ret = ElfDynamicTools::analyze(opts);
	if (ret) {
		ERROR_INTERNAL_EXCEPT("ElfDynamicTools analyze failed");
		return -1;
	}
	
	analyze_report(_xfile);

	return ret;
}
