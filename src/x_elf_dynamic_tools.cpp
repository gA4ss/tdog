#include "globals.h"
#include "mem.h"
#include "file.h"
#include "x_elf_tools.h"

ElfDynamicTools::ElfDynamicTools() : ElfTools() {
	init_datas();
}

ElfDynamicTools::ElfDynamicTools(InputFile* fi) : ElfTools(fi) {
	init_datas();
}

ElfDynamicTools::~ElfDynamicTools() {
	if (_file_image) delete [] _file_image;
}

int ElfDynamicTools::init(bool custom_support, bool elfrel) {
	super::init(custom_support, elfrel);
	
	if (ET_DYN != _type) {
		ERROR_CAN_NOT_PROTECT_EXCEPT("invalid elf type %d", _type);
	}

	/* get PT_DYNAMIC context */
	get_pt_dynamic();
	get_dynamic_context();
	elf_get_dynsym_count();  	/* 获取动态符号的数量 */

	if (custom_support == false) {
		/* 设置动态符号表与字符串表 */
		_sec_dynsym = (Elf32_Shdr*)elf_find_section_type(SHT_DYNSYM);
		if (_sec_dynsym)
			_sec_dynstr = get_te32(&_sec_dynsym->sh_link) + _shdri;
		
		_xct_va = get_xct();
		if (_xct_va == 1) {
			ERROR_CAN_NOT_PROTECT_EXCEPT("not found SHF_EXECINSTR section");
		} else if (_xct_va == 2) {
			ERROR_CAN_NOT_PROTECT_EXCEPT("invalid xoffset va");
		}

		_yct_va = get_yct();
		if (_yct_va == 1) {
			ERROR_CAN_NOT_PROTECT_EXCEPT("not found SHF_EXECINSTR section");
		} else if (_yct_va == 2) {
			ERROR_CAN_NOT_PROTECT_EXCEPT("invalid yoffset va");
		}
	}

	get_plt();

	/* elf header size */
	_size_elf_hdrs = _xct_off;

	return 0;
}

int ElfDynamicTools::init_merge(unsigned char* mem, unsigned mem_size) {
	super::init_merge(mem, mem_size);

	if (ET_DYN != _type) {
		ERROR_CAN_NOT_PROTECT_EXCEPT("invalid elf type %d", _type);
	}

	/* get PT_DYNAMIC context */
	get_pt_dynamic();
	get_dynamic_context();
	elf_get_dynsym_count();  	/* 获取动态符号的数量 */

	return 0;
}

int ElfDynamicTools::init_merge_ptr(unsigned char* ptr, unsigned mem_size) {
	super::init_merge_ptr(ptr, mem_size);

	if (ET_DYN != _type) {
		ERROR_CAN_NOT_PROTECT_EXCEPT("invalid elf type %d", _type);
	}

	/* get PT_DYNAMIC context */
	get_pt_dynamic();
	get_dynamic_context();
	elf_get_dynsym_count();  	/* 获取动态符号的数量 */

	return 0;	
}

int ElfDynamicTools::update_merge_mem(unsigned add_size) {
	super::update_merge_mem(add_size);

	/* get PT_DYNAMIC context */
	get_pt_dynamic();
	get_dynamic_context();
	elf_get_dynsym_count();  	/* 获取动态符号的数量 */

	return 0;
}

int ElfDynamicTools::init_datas() {
	_xct_va = 0;
	_xct_va_delta = 0;
	_xct_off = 0;

	_yct_va = 0;
	_yct_va_delta = 0;
	_yct_off = 0;

	_plt_va = 0;
	_plt_va_delta = 0;
	_plt_off = 0;

	_dynseg = NULL;
	_size_dynseg = 0;

	_sec_dynsym = NULL;
	_sec_dynstr = NULL;

	_dynsym_count = 0;

	memset(&_dt_needed, 0, sizeof(struct dynamic_value));
	memset(&_dt_symbolic, 0, sizeof(struct dynamic_value));
	memset(&_dt_hash, 0, sizeof(struct dynamic_value));
	memset(&_dt_strtab,0, sizeof(struct dynamic_value));
	memset(&_dt_strtabsz, 0, sizeof(struct dynamic_value));
	memset(&_dt_symtab,0, sizeof(struct dynamic_value));
	memset(&_dt_syment, 0, sizeof(struct dynamic_value));
	memset(&_dt_jmprel, 0, sizeof(struct dynamic_value));
	memset(&_dt_pltrelsz, 0, sizeof(struct dynamic_value));
	memset(&_dt_rel, 0, sizeof(struct dynamic_value));
	memset(&_dt_relsz, 0, sizeof(struct dynamic_value));
	memset(&_dt_pltgot, 0, sizeof(struct dynamic_value));
	memset(&_dt_debug, 0, sizeof(struct dynamic_value));
	memset(&_dt_init, 0, sizeof(struct dynamic_value));
	memset(&_dt_finit, 0, sizeof(struct dynamic_value));
	memset(&_dt_init_array, 0, sizeof(struct dynamic_value));
	memset(&_dt_init_arraysz, 0, sizeof(struct dynamic_value));
	memset(&_dt_finit_array, 0, sizeof(struct dynamic_value));
	memset(&_dt_finit_arraysz, 0, sizeof(struct dynamic_value));
	memset(&_dt_preinit_array, 0, sizeof(struct dynamic_value));
	memset(&_dt_preinit_arraysz, 0, sizeof(struct dynamic_value));
	memset(&_dt_textrel, 0, sizeof(struct dynamic_value));
	memset(&_dt_gnu_hash, 0, sizeof(struct dynamic_value));
	
	_orig_elftools = NULL;

	_file_image = NULL;
	_size_file_image = 0;

	return 0;
}

void ElfDynamicTools::set_orig_elf_tools(ElfTools* elftools) {
	XASSERT(elftools);
	_orig_elftools = elftools;
}

unsigned ElfDynamicTools::get_text_va() {
	return get_xct();
}

unsigned ElfDynamicTools::get_text_size() {
	bool find_exe_sec = false;
	unsigned size = 0;
	unsigned va = 0;
	Elf32_Shdr const *shdr = _shdri;
	Elf32_Shdr const *curr = _shdri;
	for (int j = _shnum; --j >= 0; ++shdr) {
		/* 遇到可执行节 */
		if (SHF_EXECINSTR & get_te32(&shdr->sh_flags)) {
			/* 这里寻找最后一个可执行节,跳过.plt节 */
			find_exe_sec = true;
			if (va < get_te32(&shdr->sh_addr)) {
				va = get_te32(&shdr->sh_addr);
				curr = shdr;
			}
		}
	}

	if (!find_exe_sec)
		return -1;

	size = curr->sh_size;

	return size;
}

/* 跳过.plt */
unsigned ElfDynamicTools::get_xct() {
	bool find_exe_sec = false;
	_xct_va = _xct_off = 0u;
	Elf32_Shdr const *shdr = _shdri;
	for (int j = _shnum; --j >= 0; ++shdr) {
		/* 遇到可执行节 */
		if (SHF_EXECINSTR & get_te32(&shdr->sh_flags)) {
			/* 这里寻找最后一个可执行节,跳过.plt节 */
			find_exe_sec = true;
			_xct_va = umax(_xct_va, get_te32(&shdr->sh_addr));
		}
	}

	/* 检查验证xct_va */
	if (!find_exe_sec)
		return 1;
	if (check_xct_va() == false) 
		return 2;

   	_xct_off = elf_get_offset_from_address(_xct_va);
	_xct_va_delta = _xct_va - _load_va;
	return _xct_va;
}

/* 包含.plt */
unsigned ElfDynamicTools::get_yct() {
	bool find_exe_sec = false;
	_yct_va = _yct_off = 0xFFFFFFFFu;
	Elf32_Shdr const *shdr = _shdri;
	for (int j = _shnum; --j >= 0; ++shdr) {
		/* 遇到可执行节 */
		if (SHF_EXECINSTR & get_te32(&shdr->sh_flags)) {
			/* 这里寻找最后一个可执行节,跳过.plt节 */
			find_exe_sec = true;
			_yct_va = umin(_yct_va, get_te32(&shdr->sh_addr));
		}
	}
		
	/* 检查验证yct_va */
	if (!find_exe_sec)
		return 1;
	if (check_yct_va() == false) 
		return 2;

   	_yct_off = elf_get_offset_from_address(_yct_va);
	_yct_va_delta = _yct_va - _load_va;
	return _yct_va;
}

bool ElfDynamicTools::check_xct_va() {
	unsigned const va_gash = elf_unsigned_dynamic(DT_GNU_HASH);
	unsigned const va_hash = elf_unsigned_dynamic(DT_HASH);
	if (_xct_va < va_gash || (0 == va_gash && _xct_va < va_hash)
		|| _xct_va < elf_unsigned_dynamic(DT_STRTAB)
		|| _xct_va < elf_unsigned_dynamic(DT_SYMTAB)
		|| _xct_va < elf_unsigned_dynamic(DT_REL)
		|| _xct_va < elf_unsigned_dynamic(DT_RELA)
		|| _xct_va < elf_unsigned_dynamic(DT_JMPREL)
		|| _xct_va < elf_unsigned_dynamic(DT_VERDEF)
		|| _xct_va < elf_unsigned_dynamic(DT_VERSYM)
		|| _xct_va < elf_unsigned_dynamic(DT_VERNEED)) {
		return false;
	}	
	return true;
}

bool ElfDynamicTools::check_yct_va() {
	unsigned const va_gash = elf_unsigned_dynamic(DT_GNU_HASH);
	unsigned const va_hash = elf_unsigned_dynamic(DT_HASH);
	if (_yct_va < va_gash || (0 == va_gash && _yct_va < va_hash)
		|| _yct_va < elf_unsigned_dynamic(DT_STRTAB)
		|| _yct_va < elf_unsigned_dynamic(DT_SYMTAB)
		|| _yct_va < elf_unsigned_dynamic(DT_REL)
		|| _yct_va < elf_unsigned_dynamic(DT_RELA)
		|| _yct_va < elf_unsigned_dynamic(DT_JMPREL)
		|| _yct_va < elf_unsigned_dynamic(DT_VERDEF)
		|| _yct_va < elf_unsigned_dynamic(DT_VERSYM)
		|| _yct_va < elf_unsigned_dynamic(DT_VERNEED)) {
		return false;
	}	
	return true;
}

unsigned ElfDynamicTools::get_plt() {
	_plt_off = _yct_off;
	_plt_va = _yct_va;
	_plt_va_delta = _yct_va_delta;
	return _plt_va;
}

bool ElfDynamicTools::check_plt_va() {
	return true;
}

void ElfDynamicTools::get_dynamic_key_context(struct dynamic_value* v, 
											  unsigned key, bool aux) {
	XASSERT(v);

	v->exist = reinterpret_cast<unsigned>(elf_has_dynamic(key));
	if (0 == v->exist) {
		/* 不存在直接不进行以下操作 */
		return;
	}
	
	v->value = elf_unsigned_dynamic(key);
	if (v->value) {
		if (aux) {
			v->aux_value = elf_get_offset_from_address(v->value);
			v->context = _file + v->aux_value;
		} else
			v->aux_value = 0;		
	}

	v->inside_offset = elf_offset_dynamic(key);
	v->inside = (unsigned char*)_dynseg + v->inside_offset;
}

void ElfDynamicTools::get_dynamic_context() {
	get_dynamic_key_context(&_dt_needed, DT_NEEDED, true);
	get_dynamic_key_context(&_dt_symbolic, DT_SYMBOLIC, true);
	get_dynamic_key_context(&_dt_hash, DT_HASH, true);
	get_dynamic_key_context(&_dt_strtab, DT_STRTAB, true);
	get_dynamic_key_context(&_dt_strtabsz, DT_STRSZ, false);
	get_dynamic_key_context(&_dt_symtab, DT_SYMTAB, true);
	get_dynamic_key_context(&_dt_syment, DT_SYMENT, false);
	get_dynamic_key_context(&_dt_jmprel, DT_JMPREL, true);
	get_dynamic_key_context(&_dt_pltrelsz, DT_PLTRELSZ, false);
	get_dynamic_key_context(&_dt_rel, DT_REL, true);
	get_dynamic_key_context(&_dt_relsz, DT_RELSZ, false);
	get_dynamic_key_context(&_dt_pltgot, DT_PLTGOT, true);
	get_dynamic_key_context(&_dt_debug, DT_DEBUG, true);
	get_dynamic_key_context(&_dt_init, DT_INIT, true);
	get_dynamic_key_context(&_dt_finit, DT_FINI, true);
	get_dynamic_key_context(&_dt_init_array, DT_INIT_ARRAY, true);
	get_dynamic_key_context(&_dt_init_arraysz, DT_INIT_ARRAYSZ, false);
	get_dynamic_key_context(&_dt_finit_array, DT_FINI_ARRAY, true);
	get_dynamic_key_context(&_dt_finit_arraysz, DT_FINI_ARRAYSZ, false);
	get_dynamic_key_context(&_dt_preinit_array, DT_PREINIT_ARRAY, true);
	get_dynamic_key_context(&_dt_preinit_arraysz, DT_PREINIT_ARRAYSZ, false);
	get_dynamic_key_context(&_dt_textrel, DT_TEXTREL, true);
	get_dynamic_key_context(&_dt_gnu_hash, DT_GNU_HASH, true);

	/* 关联辅助节点 */
	_dt_strtab.support = &_dt_strtabsz;
	_dt_symtab.support = &_dt_syment;
	_dt_jmprel.support = &_dt_pltrelsz;
	_dt_rel.support = &_dt_relsz;
	_dt_init_array.support = &_dt_init_arraysz;
	_dt_finit_array.support = &_dt_finit_arraysz;
	_dt_preinit_array.support = &_dt_preinit_arraysz;
}

void ElfDynamicTools::get_pt_dynamic() {
	Elf32_Phdr const *phdr = _phdri;
	_dynseg = NULL;
	for (int j = _phnum; --j >= 0; ++phdr) {
		unsigned const type = get_te32(&phdr->p_type);
		
		/* PT_DYNAMIC */
		if ((PT_DYNAMIC == type) && (!_dynseg)) {
			_dynseg = 
				(Elf32_Dyn*) (get_te32(&phdr->p_offset) + _file);
			_size_dynseg = phdr->p_filesz;
		}/* PT_DYNAMIC */
	}/* end for */
}

Elf32_Dyn const* ElfDynamicTools::elf_has_dynamic(unsigned int const key) {
	Elf32_Dyn const *dynp = _dynseg;
	if (dynp)
		for (; DT_NULL != dynp->d_tag; ++dynp)
			if (get_te32(&dynp->d_tag) == key) {
				return dynp;
			}
	return 0;
}

void const* ElfDynamicTools::elf_find_dynamic(unsigned int const key) {
	Elf32_Dyn const *dynp = _dynseg;
	if (dynp)
		for (; DT_NULL != dynp->d_tag; ++dynp)
			if (get_te32(&dynp->d_tag) == key) {
				unsigned const t = 
					elf_get_offset_from_address(get_te32(&dynp->d_un.d_val));
				if (t) {
					return t + _file;
				}
				break;
			}
	return 0;
}

unsigned ElfDynamicTools::elf_unsigned_dynamic(unsigned int const key) {
	Elf32_Dyn const *dynp = _dynseg;
	if (dynp)
		for (; DT_NULL != dynp->d_tag; ++dynp)
			if (get_te32(&dynp->d_tag) == key) {
				return get_te32(&dynp->d_un.d_val);
			}
	return 0;
}

/* 相对于PT_DYNAMIC段的偏移 */
unsigned ElfDynamicTools::elf_offset_dynamic(unsigned int const key) {
	Elf32_Dyn* dynp = _dynseg;
	if (dynp)
		for (; DT_NULL != dynp->d_tag; ++dynp)
			if (get_te32(&dynp->d_tag) == key) {
				return (unsigned char*)(&(dynp->d_un.d_val)) - 
					(unsigned char*)_dynseg;
			}
	return 0;
}

unsigned ElfDynamicTools::elf_get_dynamic_va() {
	get_pt_dynamic();
	return (unsigned)(_dynseg) - (unsigned)(_file);
}

unsigned ElfDynamicTools::elf_index_dynamic() {
	Elf32_Phdr const *phdr = _phdri;
	for (unsigned i = 0; i < _phnum; i++, ++phdr) {
		unsigned const type = get_te32(&phdr->p_type);
		
		/* PT_DYNAMIC */
		if (PT_DYNAMIC == type) {
			return i;
		}/* PT_DYNAMIC */
	}/* end for */
	return -1;
}

// char* ElfDynamicTools::elf_get_dt_strtab() {
// 	return (char*)elf_find_dynamic(DT_STRTAB);
// }

// Elf32_Sym32* ElfDynamicTools::elf_get_dt_symtab() {
// 	return (Elf32_Sym32*)elf_find_dynamic(DT_SYMTAB);
// }

unsigned ElfDynamicTools::elf_get_rel_sym_index(vector<unsigned>& ilist) {
	Elf32_Rel* rel1 = (Elf32_Rel*)(_dt_rel.context);
	Elf32_Rel* rel2 = (Elf32_Rel*)(_dt_jmprel.context);
	Elf32_Sym* symtab = (Elf32_Sym*)(_dt_symtab.context);

	unsigned size1 = _dt_relsz.size;
	unsigned size2 = _dt_pltrelsz.size;
	
	unsigned i = 0, c = 0;
	for (; i < (size1 / sizeof(Elf32_Rel)); i++, rel1++) {
		unsigned sym = ELF32_R_SYM(rel1->r_info);
		if (sym) {
			if (symtab[sym].st_name) {
				ilist.push_back(symtab[sym].st_name);
				c++;
			}
		}
	}

	i = 0;
	for (; i < (size2 / sizeof(Elf32_Rel)); i++, rel2++) {
		unsigned sym = ELF32_R_SYM(rel2->r_info);
		if (sym) {
			if (symtab[sym].st_name) {
				ilist.push_back(symtab[sym].st_name);
				c++;
			}
		}/* end if */
	}
	
	return c;
	
}

unsigned ElfDynamicTools::elf_get_dynsym_count() {
	/* 符号的数量从哈希表中的nchain中提取 */
	if (_dt_hash.exist == 0)
		return 0;
	
	unsigned* v = (unsigned*)(_dt_hash.context);
	if (!v) return 0;

	_dynsym_count = *((unsigned*)v + 1);

	return _dynsym_count;
}

unsigned ElfDynamicTools::gnu_hash(char const *q) {
	XASSERT(q);

	unsigned char const *p = (unsigned char const *) q;
	unsigned h;

	for (h = 5381; 0 != *p; ++p) {
		h += *p + (h << 5);
	}
	return h;
}

unsigned ElfDynamicTools::elf_hash(char const *p) {
	XASSERT(p);

	unsigned h;
	for (h = 0; 0 != *p; ++p) {
		h = *p + (h << 4);
		{
			unsigned const t = 0xf0000000u & h;
			h &= ~t;
			h ^= t >> 24;
		}
	}
	return h;
}

Elf32_Sym* ElfDynamicTools::elf_lookup(char const *name) {
	XASSERT(name);

	unsigned* hashtab = (unsigned*)_dt_hash.context;
	Elf32_Sym* dynsym = (Elf32_Sym*)_dt_symtab.context;
	char* dynstr = (char*)_dt_strtab.context;

	if (hashtab && dynsym && dynstr) {
		unsigned nbucket = get_te32(&hashtab[0]);
		unsigned* buckets = &hashtab[2];
		unsigned* chains = &buckets[nbucket];
		unsigned m = elf_hash(name) % nbucket;
		unsigned si;
		for (si = get_te32(&buckets[m]); 0 != si; si = get_te32(&chains[si])) {
			char* p = get_te32(&dynsym[si].st_name) + dynstr;
			if (0 == strcmp(name, p)) {
				return &dynsym[si];
			}
		}
	}

	char* gashtab = (char*)_dt_gnu_hash.context;
	if (gashtab && dynsym && dynstr) {
		unsigned n_bucket = get_te32(&gashtab[0]);
		unsigned symbias = get_te32(&gashtab[1]);
		unsigned n_bitmask = get_te32(&gashtab[2]);
		unsigned gnu_shift = get_te32(&gashtab[3]);
		unsigned* bitmask = (unsigned*)&gashtab[4];
		unsigned* buckets = &bitmask[n_bitmask];

		unsigned h = gnu_hash(name);
		unsigned hbit1 = 037 & h;
		unsigned hbit2 = 037 & (h >> gnu_shift);
		unsigned w = get_te32(&bitmask[(n_bitmask - 1) & (h >> 5)]);

		if (1 & (w >> hbit1) & (w >> hbit2)) {
			unsigned bucket = get_te32(&buckets[h % n_bucket]);
			if (0 != bucket) {
				Elf32_Sym* dsp = dynsym;
				unsigned* const hasharr = &buckets[n_bucket];
				unsigned* hp = &hasharr[bucket - symbias];

				dsp += bucket;
				do {
					if (0 == ((h ^ get_te32(hp)) >> 1)) {
						char* p = get_te32(&dsp->st_name) + dynstr;
						if (0 == strcmp(name, p)) {
							return dsp;
						}
					}/* end if */
				} while (++dsp, 0 == (1u & get_te32(hp++)));
			}/* end if */
		}/* end if */
	}
	return 0;
}

unsigned ElfDynamicTools::get_dt_init_array_value(unsigned i) {
	if ((_dt_init_arraysz.size > 0) && 
		(i < _dt_init_arraysz.size)) {
		void* p = (void*)(_dt_init_arraysz.context + (i * sizeof(unsigned)));
		unsigned ret = get_te32(p);
		return ret;
	}
	return 0;
}

bool ElfDynamicTools::is_has_DT_INIT() {
	return !!elf_find_dynamic(DT_INIT);
}

bool ElfDynamicTools::is_has_DT_INIT_ARRAY() {
	return !!elf_find_dynamic(DT_INIT_ARRAY);
}

bool ElfDynamicTools::is_compile_with_pic() {
	return !!!elf_has_dynamic(DT_TEXTREL);
}

int ElfDynamicTools::analyze(elf_analyze_options* opts/*=NULL*/) {
	int res = ElfTools::analyze(opts);
	if (res != 0) {
		ERROR_INTERNAL_EXCEPT("elftools analyze failed");
		return -1;
	}

	unsigned char *fptr = (unsigned char*)_xfile->file_buffer;
	//char *dynstr = (char*)(fptr + _sec_dynstr->sh_offset);
	
	/* 动态段 */
	Elf32_Dyn *dyn_item = _dynseg;
	Elf32_Rel *jmprel = NULL;
	//unsigned jmprel_idx = 0;
	unsigned jmprel_count = 0;
	Elf32_Rel *rel = NULL;
	//unsigned rel_idx = 0;
	unsigned rel_count = 0;
	Elf32_Sym *symtab = NULL;
	char *strtab = NULL;
	for (unsigned i = 0; i < _size_dynseg; i += sizeof(Elf32_Dyn)) {
		elf_dynamic_item dyn;
		dyn.type = dyn_item->d_tag;
		dyn.value = dyn_item->d_un.d_val;

		/* 通过不同的类型设定不同的值 */
		switch (dyn.type) {
		case DT_HASH:
			break;
		case DT_STRTAB:
			strtab = (char *)
				(fptr + elf_get_offset_from_address(dyn_item->d_un.d_ptr));
			break;
		case DT_SYMTAB:
			symtab = (Elf32_Sym *)
				(fptr + elf_get_offset_from_address(dyn_item->d_un.d_ptr));
			break;
		case DT_PLTREL:
			break;
		case DT_JMPREL:
			jmprel = (Elf32_Rel*)
				(fptr + elf_get_offset_from_address(dyn_item->d_un.d_ptr));
			//jmprel_idx = _xfile->dynamics.size();
			break;
		case DT_PLTRELSZ:
			jmprel_count = dyn_item->d_un.d_val / sizeof(Elf32_Rel);
			break;
		case DT_REL:
			rel = (Elf32_Rel*)
				(fptr + elf_get_offset_from_address(dyn_item->d_un.d_ptr));
			//rel_idx = _xfile->dynamics.size();
			break;
		case DT_RELSZ:
			rel_count = dyn_item->d_un.d_val / sizeof(Elf32_Rel);
			break;
		case DT_PLTGOT:
			_xfile->plt_got = (unsigned*)
				(fptr + elf_get_offset_from_address(dyn_item->d_un.d_ptr));
			_xfile->plt_got_address = dyn_item->d_un.d_ptr;
			break;
		case DT_DEBUG:
			break;
		case DT_RELA:
			break;
		case DT_INIT:
			break;
		case DT_FINI:
			break;
		case DT_INIT_ARRAY:
			break;
		case DT_INIT_ARRAYSZ:
			break;
		case DT_FINI_ARRAY:
			break;
		case DT_FINI_ARRAYSZ:
			break;
		case DT_PREINIT_ARRAY:
			break;
		case DT_PREINIT_ARRAYSZ:
			break;
		case DT_TEXTREL:
			_xfile->textrel = 1;
			break;
		case DT_SYMBOLIC:
			break;
		case DT_NEEDED:
			dyn.libname = (char*)
				(strtab + elf_get_offset_from_address(dyn_item->d_un.d_val));
			break;
		case DT_FLAGS:
			break;
		default:
			break;
		}
		/* 压入 */
		_xfile->dynamics.push_back(dyn);
		
		/* 下一个动态项 */
		dyn_item++;
	}

	/* 在这里重新建立重定位项目 */
	if (jmprel) {
		for (unsigned i = 0; i < jmprel_count; i++) {
			elf_reloc_item robj;
			robj.offset = elf_get_offset_from_address(jmprel[i].r_offset);
			robj.address = jmprel[i].r_offset;
			robj.info = jmprel[i].r_info;
			robj.type = ELF32_R_TYPE(jmprel[i].r_info);
			robj.sym_value = ELF32_R_SYM(jmprel[i].r_info);
			robj.sym_name = strtab + symtab[robj.sym_value].st_name;
			
			if ((robj.address >= _xfile->plt_got_address) &&
				(robj.address < _xfile->plt_got_address + 
				 _xfile->plt_got_size)) {
				robj.in_got = 1;
			}

			_xfile->relocs.push_back(robj);
		}
	}

	if (rel) {
		for (unsigned i = 0; i < rel_count; i++) {
			elf_reloc_item robj;
			robj.offset = elf_get_offset_from_address(rel[i].r_offset);
			robj.address = rel[i].r_offset;
			robj.info = rel[i].r_info;
			robj.type = ELF32_R_TYPE(rel[i].r_info);
			robj.sym_value = ELF32_R_SYM(rel[i].r_info);
			robj.sym_name = strtab + symtab[robj.sym_value].st_name;

			if ((robj.address >= _xfile->plt_got_address) &&
				(robj.address < _xfile->plt_got_address + 
				 _xfile->plt_got_size)) {
				robj.in_got = 1;
			}

			_xfile->relocs.push_back(robj);
		}
	}

	/* 对重定位表进行排序 */
	std::sort(_xfile->relocs.begin(),
			  _xfile->relocs.end(),
			  sort_reloc_table);

	/* 读取所有符号 */
	if (_sec_dynsym) {
		Elf32_Sym *sym_item = (Elf32_Sym*)(fptr + _sec_dynsym->sh_offset);
		unsigned sym_size = _sec_dynsym->sh_size;
		for (unsigned i = 0; i < sym_size; i += sizeof(Elf32_Sym)) {
			elf_symbol sym;
			sym.name = strtab + sym_item->st_name;
			//sym.offset = sym_item->st_value;
			sym.value = sym_item->st_value;
			//sym.address = sym_item->st_value;
			sym.size = sym_item->st_size;
			sym.bind = ELF32_ST_BIND(sym_item->st_info);
			sym.type = ELF32_ST_TYPE(sym_item->st_info);
			sym.visibly = sym_item->st_other;
			sym.ndx = sym_item->st_shndx;
			sym.is_mapping_symbol = make_sure_symbol_is_mapping(sym.name);
			sym.mapping_type = make_sure_symbol_mapping_type(sym.name);
		
			/* 关联重定位 */
			vector<elf_reloc_item>::iterator iter_rel = 
				_xfile->relocs.begin();
			vector<elf_reloc_item>::iterator iter_rel_end = 
				_xfile->relocs.end();
			for (; iter_rel != iter_rel_end; iter_rel++) {
				if (((*iter_rel).sym_name != NULL) && 
					(strlen((*iter_rel).sym_name) > 0)) {
					if (strcmp((*iter_rel).sym_name, sym.name) == 0) {
						sym.has_reloc = 1;
						sym.reloc_address = (*iter_rel).address;
					}
				}
			}/* end for */

			_xfile->symbols.push_back(sym);

			/* 下一个符号 */
			sym_item++;
		}
		std::sort(_xfile->symbols.begin(),
				  _xfile->symbols.end(),
				  sort_symbols);
	}

	/* 加入所有的函数 */
	if (_xfile->symbols.size()) {
		vector<elf_symbol>::iterator iter = 
			_xfile->symbols.begin();
		vector<elf_symbol>::iterator iter_end = 
			_xfile->symbols.end();
		for (; iter != iter_end; iter++) {
			/* 符号是函数 */
			if ((*iter).type == STT_FUNC) {
				elf_function func;
				func.name = (*iter).name;
				func.offset = (*iter).offset;
				func.size = (*iter).size;
				func.bind = (*iter).bind;
				func.type = (*iter).type;
				func.visibly = (*iter).visibly;

				/* 是否是导入符号 */
				if ((func.offset == 0) && (func.bind = STB_GLOBAL)) {
					func.func_attribute.is_import = 1;
				}
				
				/* 地址 */
				func.func_attribute.address = func.offset;
				func.func_attribute.offset = 
					elf_get_offset_from_address(func.offset);

				_xfile->functions.push_back(func);
			}
		}

		/* 排序 */
		std::sort(_xfile->functions.begin(),
				  _xfile->functions.end(),
				  sort_functions);
	}

	/* 进行反汇编 */
	if (opts->disasm) {
		disasm(_xfile);
	}

	return res;
}
