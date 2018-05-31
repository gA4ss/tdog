#include "globals.h"
#include "except.h"
#include "mem.h"
#include "file.h"
#include "x_elf_tools.h"
#include "mapper.h"
#include "make_ld.h"
#include "loader.h"
#include "Markup.h"

const unsigned g_inside_name_count = 67;
const char* g_inside_name[] = {
	"LOADER_OFFSET",
	"LOADER_CODE_OFFSET",
	"LOADER_CODE_SIZE",
	"ORIG_ENTRY",
	"CURR_ENTRY",
	"ENTRY_SIZE",
	"CURR_EXIT",
	"XCT_OFFSET",
	"ELF_EHDR_OFFSET",
	"ELF_PHDR_OFFSET",
	"ENCRYPT_INSIDE_DATA_NAME",
	"ENCRYPT_INSIDE_DATA_NAME_KEY",
	"STRTAB_OFFSET",
	"SYMTAB_OFFSET",
	"SYMNUM",
	"REL_CLEAN_ELF_EHDR",
	"REL_ENCRYPT_LOADER",
	"REL_ENCRYPT_CODES",
	"TARGET_OLD_SIZE",
	"TARGET_NEW_SIZE",
	"TARGET_OLD_OFFSET",
	"TARGET_NEW_OFFSET",
	"TARGET_KEY",
	"ELF_EHDR",
	"ELF_PHDR",
	"LOADER_SIZE",
	"PT_DYNAMIC_OFFSET",
	"PT_DYNAMIC_SIZE",
	"CODE_KEY",
	"CODE_KEY_BY_FILE",
	"CODE_CRC32_SIGN",
	"CODE_EN_CRC32_SIGN",
	"SKIP_ENCRYPT_RELOC_STRING",
	"ARCH",
	"TARGET_PLTJMP_RELOC_TABLE_OFFSET",
	"TARGET_PLTJMP_RELOC_TABLE_SIZE",
	"TARGET_REL_RELOC_TABLE_OFFSET",
	"TARGET_REL_RELOC_TABLE_SIZE",
	"ENCRYPT_ABS_EXPORT_FUNCTION",
	"ABS_EXPORT_FUNCTION_BLOCK_OFFSET",
	"ABS_EXPORT_FUNCTION_BLOCK_SIZE",
	"ABS_EXPORT_FUNCTION_KEY",
	"ABS_EXPORT_FUNCTION_BLOCK_COUNT",
	"ENCRYPT_FUNCTION",
	"ENCRYPT_FUNCTION_BLOCK_OFFSET",
	"ENCRYPT_FUNCTION_BLOCK_SIZE",
	"ENCRYPT_FUNCTION_KEY",
	"ENCRYPT_FUNCTION_BLOCK_COUNT",
	"HAS_DT_TEXTREL",
	"TEXTREL_OFFSET_TABLE",
	"TEXTREL_OFFSET_TABLE_SIZE",
	"EXSPACE_OFFSET",
	"EXSPACE_SIZE",
	"CODE_SIGN_OFFSET",
	"CODE_SIGN_LENGTH",
	"CODE_EN_SIGN_OFFSET",
	"CODE_EN_SIGN_LENGTH",
	"CODE_KEY_OFFSET",
	"CODE_KEY_LENGTH",
	"ENCRYPT_CODES",
	"CIPHER_TYPE",
	"KEEP_CODE_LOCAL",
	"ECT_OFFSET",
	"ECT_LENGTH",
	"DCT_OFFSET",
	"DCT_LENGTH",
	"ORIG_FINIT_OFFSET",
	NULL
};

Loader::Loader() : _loader(NULL), _lsize(0), _loader_code_size(0),
				   _loader_code_offset(0), _loader_entry(0), 
				   _loader_entry_size(0), _loader_exit(0),
				   _loader_control(0), _elftools(NULL), 
				   _loader_to(NULL), _target(NULL) {
	memset(&_linfo, 0, sizeof(_linfo));
}

Loader::~Loader() {
	
	loader_inside_var_node_t iter_i = _loader_inside_globals.begin();
	for (; iter_i != _loader_inside_globals.end(); iter_i++) {
		loader_inside_var_t* v = &((*iter_i).second);
		if (v->is_ptr) {
			if (v->ptr) {
				// delete [] v->ptr;
				// v->ptr = NULL;
			}
		}
	}/* end for */
	_loader_inside_globals.clear();

	loader_outside_var_node_t iter_o = _loader_outside_globals.begin();
	for (; iter_o != _loader_outside_globals.end(); iter_o++) {
		loader_outside_var_t* v = &((*iter_o).second);
		if (v->is_buf) {
			if (v->ptr) {
				delete [] v->ptr;
				v->ptr = NULL;
			}
		}
	}/* end for */
	_loader_outside_globals.clear();
}

int Loader::init(void* elftools) {
	XASSERT(elftools);

	_elftools = (ElfDynamicTools*)elftools;

	/* 填充系统变量表 */
	for (unsigned i = 0; i < g_inside_name_count; i++) {
		loader_inside_var_t t;
		memset(&t, 0, sizeof(loader_inside_var_t));
		char* varname = const_cast<char*>(g_inside_name[i]);
		_loader_inside_globals.insert(loader_inside_var_node_t::value_type(varname, t));
	}
	return 0;
}

void Loader::set_options(struct arguments* opts) {
	XASSERT(opts);
	memcpy(&_opts, opts, sizeof(struct arguments));
}

void Loader::write_loader(unsigned char* mem, unsigned offset) {
	XASSERT(mem);

    unsigned char* p = get_loader(true);
    _lsize = get_loader_size();
	//patch_loader_checksum();
	writeTarget(mem, (void*)p, _lsize, TDOG_DEBUG, "Loader", offset, true);
}

void Loader::write_loader(MemBuffer *mem, unsigned offset) {
	XASSERT(mem);

    unsigned char* p = get_loader(true);
    _lsize = get_loader_size();
	//patch_loader_checksum();
	writeTarget(NULL, (void*)p, _lsize, TDOG_DEBUG, 
				"Loader", offset, true,
				(void*)mem);
}

void Loader::write_loader(OutputFile* fo) {
	XASSERT(fo);

    unsigned char* p = get_loader(true);
    _lsize = get_loader_size();
	//patch_loader_checksum();
	writeTarget(fo, (void*)p, _lsize, TDOG_DEBUG, "Loader");
}

unsigned char* Loader::get_loader(bool clear_elf) {
	if (clear_elf == true) {
		memset(_loader, 0, sizeof(Elf32_Ehdr));
	}
	return _loader;
}

unsigned Loader::get_loader_size() {
	return _lsize;
}

unsigned Loader::get_loader_code_offset() {
	return _loader_code_offset;
}

unsigned Loader::get_loader_code_size() {
	return _loader_code_size;
}

unsigned Loader::get_loader_entry_offset() {
	return _loader_entry;
}

unsigned Loader::get_loader_entry_size() {
	return _loader_entry_size;
}

unsigned Loader::get_loader_exit_offset() {
	return _loader_exit;
}

unsigned Loader::get_loader_control_offset() {
	return _loader_control;
}

void Loader::build_loader(unsigned char* target, unsigned char* loader_to) {
	UNUSED(target);
	UNUSED(loader_to);
	return;
}

unsigned Loader::get_xml_int_value(char* v) {
	unsigned ret = 0;
	if (!v) return 0;
	if (*v != '@') return 0;
	if (*(v+1) == 'x') {
		ret = strtoul(v+2, NULL, 16);
	} else {
		ret = strtoul(v+1, NULL, 10);
	}
	return ret;
}

char* Loader::get_xml_string_value(char* v) {
	if ((!v) || (*v != '%')) return NULL;
	return v+1;
}

int Loader::get_xml_file_buf(char* filename, 
								  unsigned char** buf,
								  unsigned* size) {
	XASSERT(buf);
	XASSERT(size);

	FILE* fp = NULL;
	unsigned fsize = 0, ret = 0;
	fp = fopen(filename, "rb");
	if (fp == NULL) {
		return -1;
	}

	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	
	*buf = new unsigned char [fsize];
	if (*buf == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new unsigned char");
		return -1;
	}

	ret = fread(*buf, fsize, 1, fp);
	if (ret != fsize) {
		ERROR_READ_FILE_FAILED_EXCEPT("read extern file:%s failed", filename);
		return -1;
	}

	if (size)
		*size = fsize;

	fclose(fp);
	return 0;
}

int Loader::fill_globals() {
	return 0;
}

int Loader::fill_node(const char* name, 
					  const char* value,
					  unsigned offset,
					  unsigned size) {
	XASSERT(value);
	XASSERT(name);

	if (*value == '$') {
		/* 填充系统变量 */
		char* sys_name = (char*)(value + 1);
		set_var_offset(name, offset);
		set_var_size(name, size);
		set_var_sys_value(name, sys_name);
	} else if (*value == '@') {
		unsigned v = get_xml_int_value(const_cast<char*>(value));
		set_var_offset(name, offset);
		set_var_size(name, size);
		set_var_value(name, v);
	} else if (*value  == '%') {
		char* vs = get_xml_string_value(const_cast<char*>(value));
		set_var_offset(name, offset);
		/* 字符串的长度小于缓存大小，则设定为字符串的长度 */
		if (strlen(vs)+1 > (unsigned)size) {
			ERROR_INTERNAL_EXCEPT("string variable size invalid");
			return -1;
		}
		set_var_size(name, size);
		set_var_str_value(name, vs);
	} else if (*value  == '&') {
		unsigned char* fbuf = NULL;
		unsigned fbuf_size = 0;
		if (get_xml_file_buf((char*)(value + 1), &fbuf, &fbuf_size)) {
			ERROR_INTERNAL_EXCEPT("get file variable error");
			return -1;
		}
		set_var_offset(name, offset);
		set_var_size(name, fbuf_size);
		set_var_buf_value(name, fbuf);
	} else {
		ERROR_INTERNAL_EXCEPT("read value invalid");
		return -1;
	}
	return 0;
}

// void Loader::patch_loader_checksum() {
//     unsigned char *const ptr = get_loader();
//     l_info *const lp = &_linfo;
//     lp->l_magic = TDOG_MAGIC_LE32;
//     set_te16(&lp->l_lsize, (unsigned short) _lsize);
//     lp->l_version = (unsigned char) 0;
// 	lp->l_format  = (unsigned char) 0;
// }

loader_inside_var_t* Loader::get_sys_var(const char* varname) {
	XASSERT(varname);
	loader_inside_var_node_t node;
	node = _loader_inside_globals.find(varname);
	if (node != _loader_inside_globals.end()) {
		return &((*node).second);
	}
	return NULL;
}

loader_inside_var_t* Loader::set_sys_var_value(const char* varname, 
											   unsigned value) {
	loader_inside_var_t* var = get_sys_var(varname);
	if (var) {
		var->value = value;
		return var;
	} else {
		loader_inside_var_t v;
		memset(&v, 0, sizeof(loader_inside_var_t));
		v.value = value;
		_loader_inside_globals.insert(loader_inside_var_node_t::value_type(varname, v));
		var = get_sys_var(varname);
	}
	return var;
}

loader_inside_var_t* Loader::set_sys_var_ptr(const char* varname, 
											 unsigned char* ptr,
											 unsigned size) {
	loader_inside_var_t* var = get_sys_var(varname);
	if (var) {
		var->ptr = ptr;
		var->size = size;
		var->is_ptr = true;
		return var;
	} else {
		loader_inside_var_t v;
		memset(&v, 0, sizeof(loader_inside_var_t));
		v.ptr = ptr;
		v.size = size;
		v.is_ptr = true;
		_loader_inside_globals.insert(loader_inside_var_node_t::value_type(varname, v));
		var = get_sys_var(varname);
	}
	return var;
}

loader_inside_var_t* Loader::set_sys_var_buf(const char* varname, 
											 unsigned char* buf,
											 unsigned size) {
	loader_inside_var_t* var = get_sys_var(varname);
	if (var) {
		var->buf = buf;
		var->size = size;
		var->is_buf = true;
		return var;
	} else {
		loader_inside_var_t v;
		memset(&v, 0, sizeof(loader_inside_var_t));
		v.buf = buf;
		v.size = size;
		v.is_buf = true;
		_loader_inside_globals.insert(loader_inside_var_node_t::value_type(varname, v));
		var = get_sys_var(varname);
	}
	return var;
}

loader_outside_var_t* Loader::get_var(const char* varname) {
	XASSERT(varname);
	loader_outside_var_node_t node;
	node = _loader_outside_globals.find(varname);
	if (node != _loader_outside_globals.end()) {
		return &((*node).second);
	}
	return NULL;
}

loader_outside_var_t* Loader::set_var_value(const char* varname, 
											unsigned value) {
	loader_outside_var_t* var = get_var(varname);
	if (var) {
		var->value = value;
		return var;
	} else {
		loader_outside_var_t v;
		memset(&v, 0, sizeof(loader_outside_var_t));
		v.value = value;
		_loader_outside_globals.insert(loader_outside_var_node_t::value_type(varname, v));
		var = get_var(varname);
	}
	return var;
}

loader_outside_var_t* Loader::set_var_buf_value(const char* varname, 
											   unsigned char* ptr) {
	loader_outside_var_t* var = get_var(varname);
	if (var) {
		var->ptr = ptr;
		return var;
	} else {
		loader_outside_var_t v;
		memset(&v, 0, sizeof(loader_outside_var_t));
		v.is_buf = true;
		v.ptr = ptr;
		_loader_outside_globals.insert(loader_outside_var_node_t::value_type(varname, v));
		var = get_var(varname);
	}
	return var;
}

loader_outside_var_t* Loader::set_var_sys_value(const char* varname, 
												const char* sysname) {
	XASSERT(varname);
	XASSERT(sysname);
	loader_outside_var_t* var = get_var(varname);
	if (var) {
		var->is_system = true;
		strcpy(var->system_var_name, sysname);
		return var;
	} else {
		loader_outside_var_t v;
		memset(&v, 0, sizeof(loader_outside_var_t));
		v.is_system = true;
		strcpy(v.system_var_name, sysname);
		_loader_outside_globals.insert(loader_outside_var_node_t::value_type(varname, v));
		var = get_var(varname);
	}
	return var;
}

loader_outside_var_t* Loader::set_var_str_value(const char* varname, 
												const char* value) {
	loader_outside_var_t* var = get_var(varname);
	if (var) {
		strcpy(var->str, value);
		return var;
	} else {
		loader_outside_var_t v;
		memset(&v, 0, sizeof(loader_outside_var_t));
		v.is_str = true;
		strcpy(v.str, value);
		_loader_outside_globals.insert(loader_outside_var_node_t::value_type(varname, v));
		var = get_var(varname);
	}
	return var;
}

loader_outside_var_t* Loader::set_var_offset(const char* varname,
											 unsigned offset) {
	loader_outside_var_t* var = get_var(varname);
	if (var) {
		var->offset = offset;
		return var;
	} else {
		loader_outside_var_t v;
		memset(&v, 0, sizeof(loader_outside_var_t));
		v.offset = offset;
		_loader_outside_globals.insert(loader_outside_var_node_t::value_type(varname, v));
		var = get_var(varname);
	}
	return var;
}

loader_outside_var_t* Loader::set_var_size(const char* varname,
											  unsigned size) {
	loader_outside_var_t* var = get_var(varname);
	if (var) {
		var->size = size;
		return var;
	} else {
		loader_outside_var_t v;
		memset(&v, 0, sizeof(loader_outside_var_t));
		v.size = size;
		_loader_outside_globals.insert(loader_outside_var_node_t::value_type(varname, v));
		var = get_var(varname);
	}
	return var;
}

int Loader::update_vars(unsigned char* target,
						unsigned char* loader_to) {
	XASSERT(target);
	XASSERT(loader_to);

	_target = target;
	_loader_to = loader_to;

	/* 更新 elf_ehdr and elf_phdr */
	Elf32_Ehdr *ehdri = (Elf32_Ehdr*)_target;
	unsigned phnum = get_te16(&ehdri->e_phnum);
	unsigned phoff = get_te32(&ehdri->e_phoff);
	Elf32_Phdr *phdri = (Elf32_Phdr*)(void*)(_target + phoff);
	
	set_sys_var_ptr("ELF_EHDR", (unsigned char*)ehdri, sizeof(Elf32_Ehdr));
	set_sys_var_ptr("ELF_PHDR", (unsigned char*)phdri, 
					sizeof(Elf32_Phdr) * phnum);
	set_sys_var_value("ELF_PHDR_OFFSET", phoff);

	/* 写入外部变量 */
	loader_outside_var_node_t node = _loader_outside_globals.begin();
	for (; node != _loader_outside_globals.end(); node++) {
		loader_outside_var_t* v = &((*node).second);
		unsigned char* t = loader_to + v->offset;
		unsigned size = v->size;
		
		if (v->is_system) {
			/* 通过系统变量名称获取变量 */
			loader_inside_var_t* s = get_sys_var(v->system_var_name);
			if (s == NULL) continue;

			//printf("<%x>%s(%d)=%x\r\n", v->offset, v->system_var_name, size, s->value);

			/* 针对elf头与程度段头 */
			if (strcmp(v->system_var_name, "ELF_EHDR") == 0) {
				if (size < sizeof(Elf32_Ehdr)) {
					ERROR_INTERNAL_EXCEPT("not enough size for memory");
					return -1;
				}
				memcpy(t, s->ptr, sizeof(Elf32_Ehdr));
			} else if (strcmp(v->system_var_name, "ELF_PHDR") == 0) {
				if (size < sizeof(Elf32_Phdr) * phnum) {
					ERROR_INTERNAL_EXCEPT("not enough size for memory");
					return -2;
				}
				memcpy(t, s->ptr, sizeof(Elf32_Phdr) * phnum);
			} else {
				if ((size == 4) || (s->value == 0))
					*(unsigned*)t = s->value;
				else {
					/* 这里也包含了s->buf的操作 */
					unsigned i_size = (s->size > size) ? size : s->size;
					memcpy(t, s->ptr, i_size);
				}/* end else */
			}
		} else if (v->is_str) {
			strcpy((char*)t, v->str);
		} else if (v->is_buf) {
			memcpy((char*)t, v->ptr, size);
		} else {
			if (size == 4)
				*(unsigned*)t = v->value;
			else {
				memcpy(t, v->buffer, size);
			}/* end else */
		}
	}/* end for */

	return 0;
}

