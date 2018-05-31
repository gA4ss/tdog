#include "globals.h"
#include "except.h"
#include "mem.h"
#include "file.h"
#include "x_elf_tools.h"
#include "mapper.h"
#include "make_ld.h"
#include "loader.h"
#include "dis.h"
#include "Markup.h"

Dis::Dis() : Loader(),
						 _symnum(0),
						 _make_ld(NULL), 
						 _ld_orig_elftools(NULL),
						 _ld_elftools(NULL), 
						 _target_hashtab(NULL), 
						 _loader_hashtab(NULL),
						 _target_strtab(NULL),
						 _loader_strtab(NULL),
						 _target_strtabsz(0),
						 _loader_strtabsz(0),
						 _new_dynamic(NULL),
						 _target_dynamic(NULL),
						 _target_dynamic_size(0),
						 _target_symtab(NULL),
	_target_pltrel(NULL),
	_target_rel(NULL),
	_target_pltrel_count(0),
	_target_rel_count(0),
	_target_finit(NULL),
	_loader_needed_dynamic_size(0),
	_loader_symtab(NULL),
			 _loader_pltrel(NULL),
	_loader_rel(NULL),
	_loader_pltrel_count(0),
	_loader_rel_count(0),
	_new_pltrel(NULL),
	_new_pltrelsz(0),
	_new_rel(NULL),
	_new_relsz(0),
	_new_dynamic_offset(0),
	_new_hashtab_offset(0),
	_new_dynsym_offset(0),
	_new_dynstr_offset(0),
	_new_pltrel_offset(0),
	_new_rel_offset(0),
	_new_finit_offset(0),
	_save_target_pltrel_offset(0),
	_save_target_pltrel_size(0),
	_save_target_rel_offset(0),
	_save_target_rel_size(0),
	_save_target_pltrel(NULL),
	_save_target_rel(NULL),
	_exspace_offset(0),
	_exspace_size(0),
	_exspace(NULL),
	_target_old_finit_offset(0),
	_add_needed(NULL),
	_add_needed_size(0)
{
	memset(&_symbase, 0, sizeof(elf_tools_symtab));
}

Dis::~Dis() {
	if (_new_dynamic) delete [] _new_dynamic;
	if (_make_ld) delete _make_ld;
	if (_ld_orig_elftools) delete _ld_orig_elftools;
	if (_ld_elftools) delete _ld_elftools;
	if (_loader) delete [] _loader;
	if (_new_pltrel) delete [] _new_pltrel;
	if (_new_rel) delete [] _new_rel;
	if (_save_target_pltrel) delete [] _save_target_pltrel;
	if (_save_target_rel) delete [] _save_target_rel;
	if (_add_needed) delete [] _add_needed;
	_target_strtab_strings.clear();
	_relobj_log.clear();
	_needed_name.clear();
}

void Dis::build_loader(unsigned char* target,
											 unsigned char* loader_to) {
	update_vars(target, loader_to);

	InputFile fi;
	/* 打开loader库文件 */
	if (open_file(_opts.loader_path, &fi)) {
		return;
	}

	_ld_orig_elftools = new ElfDynamicTools(&fi);
	if (_ld_orig_elftools == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new ElfDynamicTools");
		return;
	}
	_ld_orig_elftools->set_machine(_opts.arch);
	if (_ld_orig_elftools->init()) {
		return;
	}

	_make_ld = new MakeLD;
	if (_make_ld == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new MakeLD");
		return;
	}
	_make_ld->set_options(&_opts);
	/* 生成loader */
	if (_make_ld->make(&fi)) {
		return;
	}

	/* 获取loader以及长度 */
	unsigned ld_size = _make_ld->get_ld_size();
	/* 这里进行页对齐 */
	_lsize = upx(ld_size);
	_loader_code_offset = _ld_orig_elftools->get_text_va();
	_loader_code_size = _ld_orig_elftools->get_text_size();   /* 仅代码长度 */
	_loader = new unsigned char [_lsize];
	if (_loader == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new unsigned char []");
		return;
	}
	memcpy(_loader, _make_ld->get_ld(), ld_size);
	/* 合并头 */
	_ld_orig_elftools->reset_phdr(_loader, ld_size, 1);

	_ld_elftools = new ElfDynamicTools(&fi);
	if (_ld_elftools == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new ElfDynamicTools");
		return;
	}

	_ld_elftools->set_machine(_opts.arch);
	if (_ld_elftools->init_merge_ptr(_loader, ld_size)) {
		return;
	}
	_ld_elftools->set_orig_elf_tools(_ld_orig_elftools);

	/* 进行生成 */
	if (fill_globals()) {
		return;
	}

	/* 生成loader段 */
	if (make_loader(target, loader_to)) {
		return;
	}

	/* 关闭加载器文件 */
	if (_ld_orig_elftools) delete _ld_orig_elftools;
	_ld_orig_elftools = NULL;
	if (_ld_elftools) delete _ld_elftools;
	_ld_elftools = NULL;
	fi.close(); /* 这里没关闭不影响整体流程 */

	return;
}

int Dis::handle_target_hashtab(unsigned char* hashtab) {
	XASSERT(hashtab);

	int ret = 0;
	unsigned nbucket = *(unsigned*)(hashtab);
	unsigned nchain = *(unsigned*)(hashtab + 4);
	unsigned* target_bucket = (unsigned*)(hashtab + 8);
	unsigned* target_chain = (unsigned*)(hashtab + 8 + (4 * nbucket));

	/* bucket */
	ret = loop_handle_target_symtab(&_symbase, 
																	_target_symtab, _target_strtab,
																	_target_pltrel, _target_pltrel_count,
																	_target_rel, _target_rel_count,
																	target_bucket, nbucket);
	if (ret) return ret;

	/* chain */
	ret = loop_handle_target_symtab(&_symbase, 
																	_target_symtab, _target_strtab,
																	_target_pltrel, _target_pltrel_count,
																	_target_rel, _target_rel_count,
																	target_chain, nchain);
	if (ret) return ret;
	return 0;
}

int Dis::handle_loader_hashtab(unsigned char* hashtab,
							   unsigned fix_offset) {
	XASSERT(hashtab);

	int ret = 0;
	unsigned nbucket = *(unsigned*)(hashtab);
	unsigned nchain = *(unsigned*)(hashtab + 4);
	unsigned* loader_bucket = (unsigned*)(hashtab + 8);
	unsigned* loader_chain = (unsigned*)(hashtab + 8 + (4 * nbucket));

	/* bucket */
	ret = loop_handle_loader_symtab(&_symbase, 
																	_loader_symtab, _loader_strtab,
																	_loader_pltrel, _loader_pltrel_count,
																	_loader_rel, _loader_rel_count,
																	loader_bucket, nbucket, fix_offset);
	if (ret) return ret;

	/* chain */
	ret = loop_handle_loader_symtab(&_symbase, 
																	_loader_symtab, _loader_strtab,
																	_loader_pltrel, _loader_pltrel_count,
																	_loader_rel, _loader_rel_count,
																	loader_chain, nchain, fix_offset);
	if (ret) return ret;

	/* 处理重定位 */
	ret = fix_rel_offset(_loader_pltrel, _loader_pltrel_count, fix_offset);
	if (ret) return ret;

	ret = fix_rel_offset(_loader_rel, _loader_rel_count, fix_offset);
	if (ret) return ret;
	
	return 0;
}

int Dis::make_loader(unsigned char* target,
										 unsigned char* loader_to) {
	XASSERT(target);
	XASSERT(loader_to);

	unsigned target_nbucket = 0, target_nchain = 0;
	unsigned loader_nbucket = 0, loader_nchain = 0;
	unsigned fix_offset = (unsigned)(loader_to - target);

	/* 计算新符号表的符号个数 */
	if (get_target_hashtab() == NULL) {
		ERROR_INTERNAL_EXCEPT("get target hashtab");
		return -1;
	}
	if (get_loader_hashtab() == NULL) {
		ERROR_INTERNAL_EXCEPT("get loader hashtab");
		return -1;
	}
	if (get_target_symtab() == NULL) {
		ERROR_INTERNAL_EXCEPT("get target symtab");
		return -1;
	}
	if (get_loader_symtab() == NULL) {
		ERROR_INTERNAL_EXCEPT("get loader symtab");
		return -1;
	}
	if (get_target_strtab() == NULL) {
		ERROR_INTERNAL_EXCEPT("get target strtab");
		return -1;
	}
	if (get_loader_strtab() == NULL) {
		ERROR_INTERNAL_EXCEPT("get loader strtab");
		return -1;
	}
	if (get_target_pltrel() == NULL) {
		info_msg("miss target pltrel");
	}
	if (get_loader_pltrel() == NULL) {
		ERROR_INTERNAL_EXCEPT("get loader pltrel");
		return -1;
	}
	if (get_target_rel() == NULL) {
		info_msg("miss target rel");
	}
	if (get_loader_rel() == NULL) {
		ERROR_INTERNAL_EXCEPT("get loader rel");
		return -1;
	}
	if (get_target_finit() == NULL) {
		info_msg("miss target finit");
	}

	count_hashsym(_target_hashtab, &target_nbucket, &target_nchain);
	count_hashsym(_loader_hashtab, &loader_nbucket, &loader_nchain);
	
	/* 创建新的符号表
	 * 如果要添加新的符号绑定，从这里开始
	 */
	unsigned nbucket = target_nbucket + loader_nbucket;
	unsigned nchain = target_nchain + loader_nchain;
	int ret = elf_symbase_init(&_symbase, nbucket, nchain);
	if (ret) return ret;

	/**********************/
	// 生成新的PT_DYNAMIC,
	// 这里添加了自己要新添加
	// 的DYNAMIC项
	/**********************/
	unsigned dynamic_size = make_new_dynamic();

	/* 合并两个SO的符号表 */
	ret = handle_target_hashtab(_target_hashtab);
	if (ret) return ret;
	ret = handle_loader_hashtab(_loader_hashtab, fix_offset);
	if (ret) return ret;

	/* 添加新的符号 */

	/* 更新分析工具 */
	_elftools->update_merge_mem(0);
	_ld_elftools->update_merge_mem(0);

	/* 合成新的重定位表 */
	_new_pltrel = make_new_reltab(true, &_new_pltrelsz);
	if (_new_pltrel == NULL) {
		ERROR_INTERNAL_EXCEPT("make_new_reltab(pltrel) failed");
		return -1;
	}

	_new_rel = make_new_reltab(false, &_new_relsz);
	if (_new_rel == NULL) {
		ERROR_INTERNAL_EXCEPT("make_new_reltab(rel) failed");
		return -1;
	}

	/* 如果选项保留了对目标程序重定位 */
	if (_opts.save_target_rel) {
		_save_target_pltrel = save_target_reltab(true, 
																						 &_save_target_pltrel_size);
		if (_save_target_pltrel == NULL) {
			ERROR_INTERNAL_EXCEPT("save_target_reltab(pltrel) failed");
			return -1;
		}

		_save_target_rel = save_target_reltab(false, &_save_target_rel_size);
		if (_save_target_rel == NULL) {
			ERROR_INTERNAL_EXCEPT("save_target_reltab(rel) failed");
			return -1;
		}
	}

	/* 清除target与loader的旧的xct部分 */
	clean_target_loader_xct();

	/* 重新分配loader的内存并且将新的符号表以及重定位表附着到其后 */
	_symnum = _symbase.symc;
	unsigned sym_size = up4(_symbase.symtab_size);
	unsigned str_size = up4(_symbase.strtab_size);
	unsigned hash_size = up4(_symbase.hashtab_size);

	/* 如果想给目标添加其余内存块，在这里添加 
	 */
	unsigned curr_offset = fix_offset + _lsize;/*_lsize是经过页对齐的大小*/
	_new_dynamic_offset = curr_offset;
	curr_offset += dynamic_size;
	_new_hashtab_offset = curr_offset;
	curr_offset += hash_size;
	_new_dynsym_offset = curr_offset;
	curr_offset += sym_size;
	_new_dynstr_offset = curr_offset;
	curr_offset += str_size;
	_new_pltrel_offset = curr_offset;	
	curr_offset += _new_pltrelsz;
	_new_rel_offset = curr_offset;
	curr_offset += _new_relsz;
	/* 如果选项保留了对目标程序重定位 */
	if (_opts.save_target_rel) {
		_save_target_pltrel_offset = curr_offset;
		curr_offset += _save_target_pltrel_size;
		_save_target_rel_offset = curr_offset;
		curr_offset += _save_target_rel_size;
	}
	
	/* 设置扩展空间 */
	if (_exspace) {
		_exspace_offset = curr_offset;
		curr_offset += upx(_exspace_size);
	}

	/* 新的loader的长度 */
	unsigned new_ld_size = upx(curr_offset - fix_offset);
	unsigned char* new_loader = new unsigned char [new_ld_size];
	if (new_loader == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new unsigned char []");
		return -1;
	}
	memset(new_loader, 0, new_ld_size);
	memcpy(new_loader, _loader, _lsize);
	delete [] _loader;
	_loader = new_loader;
	unsigned old_ld_size = _lsize;
	UNUSED(old_ld_size);
	_lsize = new_ld_size;

	/* 修复loader的.got表 */
	fix_loader_got(_loader, fix_offset);

	/* 复制各种表 */
	memcpy(_loader + _new_hashtab_offset - fix_offset, 
		   (unsigned char*)(_symbase.hashtab),
		   _symbase.hashtab_size);

	memcpy(_loader + _new_dynsym_offset - fix_offset, 
		   (unsigned char*)(_symbase.symtab), 
		   _symbase.symtab_size);

	memcpy(_loader + _new_dynstr_offset - fix_offset, 
		   (unsigned char*)(_symbase.strtab), 
		   _symbase.strtab_size);

	memcpy(_loader + _new_pltrel_offset - fix_offset, 
		   (unsigned char*)_new_pltrel, 
		   _new_pltrelsz);

	memcpy(_loader + _new_rel_offset - fix_offset, 
		   (unsigned char*)_new_rel, 
		   _new_relsz);

	if (_opts.save_target_rel) {
		memcpy(_loader + _save_target_pltrel_offset - fix_offset, 
			   (unsigned char*)_save_target_pltrel, 
			   _save_target_pltrel_size);

		memcpy(_loader + _save_target_rel_offset - fix_offset, 
			   (unsigned char*)_save_target_rel, 
			   _save_target_rel_size);
	}

	/* 复制扩展空间数据 */
	if (_exspace) {
		memcpy(_loader + _exspace_offset - fix_offset, 
			   (unsigned char*)_exspace, _exspace_size);
	}

	/* 修订重定位表以及其余表的偏移,
	 * 这里必须保证以下的动态项目，必须都存在于新的动态节内
	 */
	unsigned* target_pt_hashtab_offset = 
		get_dynamic_object_offset_ptr((Elf32_Dyn*)_new_dynamic, DT_HASH);
	unsigned* target_pt_symtab_offset = 
		get_dynamic_object_offset_ptr((Elf32_Dyn*)_new_dynamic, DT_SYMTAB);
	unsigned* target_pt_strtab_offset = 
		get_dynamic_object_offset_ptr((Elf32_Dyn*)_new_dynamic, DT_STRTAB);
	unsigned* target_pt_strtabsz_size = 
		get_dynamic_object_offset_ptr((Elf32_Dyn*)_new_dynamic, DT_STRSZ);
	unsigned* target_pt_pltrel_offset = 
		get_dynamic_object_offset_ptr((Elf32_Dyn*)_new_dynamic, DT_JMPREL);
	unsigned* target_pt_pltrelsz_size = 
		get_dynamic_object_offset_ptr((Elf32_Dyn*)_new_dynamic, DT_PLTRELSZ);
	unsigned* target_pt_rel_offset = 
		get_dynamic_object_offset_ptr((Elf32_Dyn*)_new_dynamic, DT_REL);
	unsigned* target_pt_relsz_size = 
		get_dynamic_object_offset_ptr((Elf32_Dyn*)_new_dynamic, DT_RELSZ);
	unsigned* target_pt_finit_offset = 
		get_dynamic_object_offset_ptr((Elf32_Dyn*)_new_dynamic, DT_FINI);
	UNUSED(target_pt_finit_offset);

	*target_pt_hashtab_offset = _new_hashtab_offset;
	*target_pt_symtab_offset = _new_dynsym_offset;
	*target_pt_strtab_offset = _new_dynstr_offset;
	/* 2016.4.14 devilogic修改，這裏使用strsz這是內部的緩存大小 */
	*target_pt_strtabsz_size = _symbase.strtab_size;
	*target_pt_pltrel_offset = _new_pltrel_offset;
	*target_pt_pltrelsz_size = _new_pltrelsz;
	*target_pt_rel_offset = _new_rel_offset;
	*target_pt_relsz_size = _new_relsz;
	/* finit就是个值而已，可以直接设置 */
	//*target_pt_finit_offset = _new_finit_offset;

	/* 复制新的dynamic segments */
	memcpy(_loader + _new_dynamic_offset - fix_offset, 
		   (unsigned char*)(_new_dynamic),
		   dynamic_size);

	/* 修正程序头的动态段偏移与长度 */
	fix_new_dynamic_in_phdrs(_new_dynamic_offset, dynamic_size);

	/* 更新目标文件工具 */
	_elftools->update_merge_mem(0);

	/* 释放符号库 */
	elf_symbase_done(&_symbase);
	return 0;
}

int Dis::count_hashsym(unsigned char* hashtab, 
					   unsigned* nbucket,
					   unsigned* nchain) {
	XASSERT(hashtab);
	XASSERT(nbucket);
	XASSERT(nchain);

	*nbucket = *(unsigned*)hashtab;        /* number of bucket */
	*nchain = *(unsigned*)(hashtab + 4);   /* number of chain */
	return 0;
}

unsigned char* Dis::get_target_hashtab() {
	struct dynamic_value* hashtab_v = &(_elftools->_dt_hash);
	if (hashtab_v->exist == 0) {
		return NULL;
	}

	_target_hashtab = (unsigned char*)(hashtab_v->context);
	return _target_hashtab;
}

unsigned char* Dis::get_loader_hashtab() {
	struct dynamic_value* hashtab_v = &(_ld_elftools->_dt_hash);
	if (hashtab_v->exist == 0) {
		return NULL;
	}

	_loader_hashtab = (unsigned char*)(hashtab_v->context);
	return _loader_hashtab;
}

Elf32_Sym* Dis::get_target_symtab() {
	struct dynamic_value* symtab_v = &(_elftools->_dt_symtab);
	if (symtab_v->exist == 0) {
		return NULL;
	}

	_target_symtab = (Elf32_Sym*)(symtab_v->context);
	return _target_symtab;
}

Elf32_Sym* Dis::get_loader_symtab() {
	struct dynamic_value* symtab_v = &(_ld_elftools->_dt_symtab);
	if (symtab_v->exist == 0) {
		return NULL;
	}

    _loader_symtab = (Elf32_Sym*)(symtab_v->context);
	return _loader_symtab;
}

char* Dis::get_target_strtab() {
	struct dynamic_value* strtab_v = &(_elftools->_dt_strtab);
	if (strtab_v->exist == 0) {
		return NULL;
	}

	struct dynamic_value* strtab_size_v = &(_elftools->_dt_strtabsz);
	if (strtab_size_v->exist == 0) {
		return NULL;
	}

	_target_strtab = (char*)(strtab_v->context);
	_target_strtabsz = strtab_size_v->size;
	return _target_strtab;
}

char* Dis::get_loader_strtab() {
	struct dynamic_value* strtab_v = &(_ld_elftools->_dt_strtab);
	if (strtab_v->exist == 0) {
		return NULL;
	}

	struct dynamic_value* strtab_size_v = &(_ld_elftools->_dt_strtabsz);
	if (strtab_size_v->exist == 0) {
		return NULL;
	}

	_loader_strtab = (char*)(strtab_v->context);
	_loader_strtabsz = strtab_size_v->size;
	return _loader_strtab;
}


Elf32_Rel* Dis::get_target_pltrel() {
	struct dynamic_value* pltrel_v = &(_elftools->_dt_jmprel);
	if (pltrel_v->exist == 0) {
		return NULL;
	}

	struct dynamic_value* pltrel_size_v = &(_elftools->_dt_pltrelsz);
	if (pltrel_size_v->exist == 0) {
		return NULL;
	}
	
	_target_pltrel = (Elf32_Rel*)(pltrel_v->context);
	_target_pltrel_count = pltrel_size_v->size / sizeof(Elf32_Rel);
	return _target_pltrel;
}

Elf32_Rel* Dis::get_loader_pltrel() {
	struct dynamic_value* pltrel_v = &(_ld_elftools->_dt_jmprel);
	if (pltrel_v->exist == 0) {
		return NULL;
	}

	struct dynamic_value* pltrel_size_v = &(_ld_elftools->_dt_pltrelsz);
	if (pltrel_size_v->exist == 0) {
		return NULL;
	}

	_loader_pltrel = (Elf32_Rel*)(pltrel_v->context);
	_loader_pltrel_count = pltrel_size_v->size / sizeof(Elf32_Rel);
	return _loader_pltrel;
}

Elf32_Rel* Dis::get_target_rel() {
	struct dynamic_value* rel_v = &(_elftools->_dt_rel);
	if (rel_v->exist == 0) {
		return NULL;
	}

	struct dynamic_value* rel_size_v = &(_elftools->_dt_relsz);
	if (rel_size_v->exist == 0) {
		return NULL;
	}
	
	_target_rel = (Elf32_Rel*)(rel_v->context);
	_target_rel_count = rel_size_v->size / sizeof(Elf32_Rel);
	return _target_rel;
}

Elf32_Rel* Dis::get_loader_rel() {
	struct dynamic_value* rel_v = &(_ld_elftools->_dt_rel);
	if (rel_v->exist == 0) {
		return NULL;
	}

	struct dynamic_value* rel_size_v = &(_ld_elftools->_dt_relsz);
	if (rel_size_v->exist == 0) {
		return NULL;
	}
	
	_loader_rel = (Elf32_Rel*)(rel_v->context);
	_loader_rel_count = rel_size_v->size / sizeof(Elf32_Rel);
	return _loader_rel;
}

unsigned* Dis::get_target_finit() {
	struct dynamic_value* finit_v = &(_elftools->_dt_finit);
	if (finit_v->exist == 0) {
		_target_finit = NULL;
		return NULL;
	}

	_target_finit = (unsigned*)finit_v->context;
	_target_old_finit_offset = *(unsigned*)_target_finit;
	return _target_finit;
}

Elf32_Dyn* Dis::get_target_dynamic() {
	Elf32_Phdr const *phdr = _elftools->_phdri;
	_target_dynamic = NULL;
	for (int j = _elftools->_phnum; --j >= 0; ++phdr) {
		unsigned const type = get_te32(&phdr->p_type);
		
		/* PT_DYNAMIC */
		if ((PT_DYNAMIC == type) && (!_target_dynamic)) {
			_target_dynamic = 
				(Elf32_Dyn*) (get_te32(&phdr->p_offset) + 
							  _elftools->_file);
			break;
		}/* PT_DYNAMIC */
	}/* end for */

	if (_target_dynamic == NULL) return NULL;

	/* 计算它的大小 */
	_target_dynamic_size = 0;
	Elf32_Dyn* d = _target_dynamic;
	while (d->d_tag) {
		_target_dynamic_size += 8;
		d++;
	}

	return _target_dynamic;
}

int Dis::fix_needed_sym_idx(Elf32_Dyn* dyn, char* strtab) {
	XASSERT(dyn);
	XASSERT(strtab);
	Elf32_Dyn* d = dyn;

	for (; d->d_tag; d++) {
		switch(d->d_tag) {
		case DT_NEEDED:
			unsigned str_idx = d->d_un.d_val;
			char* name = strtab + str_idx;
			int id = elf_strtab_add(&_symbase, name);
			d->d_un.d_val = id;
			break;
		}
	}
	return 0;
}

Elf32_Dyn* Dis::get_loader_dynamic_needed(Elf32_Dyn* buf, unsigned* usesize) {
	Elf32_Dyn* d = _ld_elftools->_dynseg;
	unsigned i = 0;
	unsigned size = 0;

	if (buf != NULL) {
		size = *usesize;
	} else {
		for (; d->d_tag; d++) {
			switch(d->d_tag) {
			case DT_NEEDED:
				i++;
				break;
			}
		}
		size = i * sizeof(Elf32_Dyn);
		*usesize = size;
		return NULL;
	}

	int c = 0;
	d = _ld_elftools->_dynseg;
	char* strtab = _loader_strtab;
	for (; d->d_tag; d++) {
		switch(d->d_tag) {
		case DT_NEEDED:
			unsigned str_idx = d->d_un.d_val;
			char* name = strtab + str_idx;
			int id = elf_strtab_find(&_symbase, name);
			/* 不在表中表示可以进行添加 */
			if (id == 0) {
				memcpy((unsigned char*)&buf[c], 
					   (unsigned char*)d, sizeof(Elf32_Dyn));
				/* 修改 */
				buf[c].d_un.d_val = elf_strtab_add(&_symbase, name);
				c++;
			}
			break;
		}
	}	
	
	/* 重新核算长度 */
	*usesize = c * sizeof(Elf32_Dyn);

	return buf;
}

int Dis::fix_new_dynamic_in_phdrs(unsigned offset, unsigned size) {
	Elf32_Phdr const *phdr = _elftools->_phdri;
	for (int j = _elftools->_phnum; --j >= 0; ++phdr) {
		unsigned const type = get_te32(&phdr->p_type);
		
		/* PT_DYNAMIC */
		if (PT_DYNAMIC == type) {
			set_te32((void*)&(phdr->p_offset), offset);
			set_te32((void*)&(phdr->p_vaddr), offset);
			set_te32((void*)&(phdr->p_paddr), offset);
			set_te32((void*)&(phdr->p_filesz), size);
			set_te32((void*)&(phdr->p_memsz), size);
			break;
		}/* PT_DYNAMIC */
	}/* end for */
	return 0;
}

void Dis::fix_loader_got(unsigned char* ld, unsigned fix_offset) {
	XASSERT(ld);

	Elf32_Shdr* got = _ld_orig_elftools->get_got();
	if (got == NULL) return;

	unsigned size = got->sh_size;
	unsigned count = size / 4;
	unsigned va = got->sh_addr;

	unsigned* g = (unsigned *)(ld + va);
	for (unsigned i = 0; i < count; i++, g++) {
		if (*g) {
			*g += fix_offset;
		}
	}
}

static char* get_line(FILE*fp) {
	static char line[80];

	if (fp == NULL) return NULL;

	memset(line, 0, 80);

	if (feof(fp)) return NULL;
	
	int ch = 0;
	int i = 0;
	while (!feof(fp)) {
		ch = fgetc(fp);
		if ((ch == '\r') || (ch == '\n')) {
			line[i] = '\0';
			return &line[0];
		}/* end if */
		line[i++] = ch;
	}/* end while */
	
	return NULL;
}
void Dis::add_needed(int type, char *neededs) {
	int id;
	_add_needed_size = 0;
	if (type == 1) {
		/* 分析 */
		char *pel = strtok(neededs, ",");
		while (pel) {
			/* 添加符号 */
			id = elf_strtab_add(&_symbase, pel);
			info_msg("add needed = [%d]%s\n", id, pel);
			_needed_name.push_back(id);
			_add_needed_size += sizeof(Elf32_Dyn);
			pel = strtok(NULL, ",");
		}
	} else {
		/* 打开文件依次读取 */
		FILE* fp = fopen(neededs, "rb");
		if (fp == NULL) {
			ERROR_CAN_NOT_OPEN_FILE_EXCEPT("can not open file:%s", 
										   neededs);
			return;
		}
		fseek(fp, 0, SEEK_END);
		unsigned fsize = ftell(fp);
		fseek(fp, 0, SEEK_SET);

		if (fsize == 0) return;
		
		/* 依次读取每一行 */
		while (!feof(fp)) {
			char* p = get_line(fp);
			if (p == NULL) continue;
			/* 添加符号 */
			id = elf_strtab_add(&_symbase, p);
			info_msg("add needed = [%d]%s\n", id, p);
			_needed_name.push_back(id);
			_add_needed_size += sizeof(Elf32_Dyn);
		}
		fclose(fp);
	}/* end else */

	_add_needed = new Elf32_Dyn [_add_needed_size];
	if (_add_needed == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new Elf32_Dyn");
		return;
	}

	vector<int>::iterator iter = _needed_name.begin();
	int count = (_add_needed_size / sizeof(Elf32_Dyn));
	for (int i = 0; i < count; i++) {
		_add_needed[i].d_tag = DT_NEEDED;
		_add_needed[i].d_un.d_val = *iter;
		iter++;
	}
}

/* 添加新的功能就是在这个表中 
 * 基础使用target的动态节,从
 * loader的needed中添加数据
 */
unsigned Dis::make_new_dynamic() {
	/* 重构pt_dynamic,并修改needed */
	if (get_target_dynamic() == NULL) {
		ERROR_INTERNAL_EXCEPT("get target dynamic");
		return -1;
	}

	/* 2016.4.15 devilogic添加
	 * 修正目标的DT_SONAME
	 * 支持android7
	 */
	int target_SONAME_idx = 0;
	int target_SONAME_ret = fix_target_SONAME(&target_SONAME_idx);

	/* devilogic 2016.4.11 凌晨添加 为支持android6
	 * 清除xxx
	 */
	clear_dynamic_xxx(_target_dynamic);
	
	/* 修订needed的符号索引 */
	fix_needed_sym_idx(_target_dynamic, _target_strtab);

	/* 获取loader的needed */
	unsigned loader_dynamic_needed_size = 0;
	get_loader_dynamic_needed(NULL, &loader_dynamic_needed_size);
	
	unsigned char* loader_dynamic_needed = 
		new unsigned char [loader_dynamic_needed_size];
	if (loader_dynamic_needed == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new unsigned char []");
		return -1;
	}

	if (get_loader_dynamic_needed((Elf32_Dyn*)loader_dynamic_needed,
								  &loader_dynamic_needed_size) == NULL) {
		ERROR_INTERNAL_EXCEPT("get loader dynamic needed");
		return -1;
	}

	/* 因为是以target程序的dynamic段为基础进行设定，所以这里遍历目标
	 * 的dynamic然后进行添加，有些
	 */

	unsigned add_dynamic_count = 0;
	Elf32_Dyn pltrel_dyn, rel_dyn, pltrel_size_dyn, rel_size_dyn,
		finit_dyn;

	// 判断目标是否存在重定位节
	if (_target_pltrel == NULL) {
		add_dynamic_count += 2;
		pltrel_dyn.d_tag = DT_JMPREL;
		pltrel_dyn.d_un.d_val = 0;
		
		pltrel_size_dyn.d_tag = DT_PLTRELSZ;
		pltrel_size_dyn.d_un.d_val = 0;
	}

	if (_target_rel == NULL) {
		add_dynamic_count += 2;
		rel_dyn.d_tag = DT_REL;
		rel_dyn.d_un.d_val = 0;

		rel_size_dyn.d_tag = DT_RELSZ;
		rel_size_dyn.d_un.d_val = 0;
	}

	/* 如果目标存在finit_array则复用，否则添加一个 */
	if (_target_finit == NULL) {
		add_dynamic_count++;
		finit_dyn.d_tag = DT_FINI;
		/* 这里添加新的稀构函数的内存偏移 */
		finit_dyn.d_un.d_val = 0;
	}

	// if (_opts.new_dt_init) {
	// }

	// if (_opts.use_dt_init_array) {
	// }

	// if (_opts.use_dt_finit_array) {
	// }

	/* 添加新的needed */
	if (_opts.add_needed) {
		add_needed(_opts.add_needed, _opts.needed_name);
	}

	/* target_SONAME_idx == -1表示目标target没有DT_SONAME，
	 * 所以，我们就要给它添加上一个
	 */
	unsigned SONAME_size = 0;
	if (target_SONAME_ret == -1) {
		SONAME_size = sizeof(Elf32_Dyn);
	}

	/* 新的dynamic的长度 */
	unsigned dynamic_size = up4(_target_dynamic_size + 
															loader_dynamic_needed_size + 
															_add_needed_size +
															(add_dynamic_count * sizeof(Elf32_Dyn)) +
															SONAME_size +
															sizeof(Elf32_Dyn)); /* 最后加一个空项 */

	/* 添加xdebugger项目 */
	if (_opts.xdebugger) {
		dynamic_size += sizeof(Elf32_Dyn);
	}

	_new_dynamic = new unsigned char [dynamic_size + 0x10];
	if (_new_dynamic == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new unsigned char []");
		return -1;
	}

	/* 复制 */
	memset(_new_dynamic, 0, dynamic_size);
	memcpy((unsigned char*)_new_dynamic, loader_dynamic_needed,
				 loader_dynamic_needed_size);
	memcpy((unsigned char*)_new_dynamic + loader_dynamic_needed_size,
				 (unsigned char*)_target_dynamic, _target_dynamic_size);
	memcpy((unsigned char*)_new_dynamic + 
				 loader_dynamic_needed_size + 
				 _target_dynamic_size,
				 (unsigned char*)_add_needed,
				 _add_needed_size);
	
	/* 添加xdebugger内容 */
	if (_opts.xdebugger) {
		add_DT_DEBUG((unsigned char*)_new_dynamic + 
					 loader_dynamic_needed_size +
					 _target_dynamic_size +
					 _add_needed_size);
	}

	/* 添加SONAME */
	if (target_SONAME_ret == -1) {
		add_DT_SONAME((unsigned char*)_new_dynamic + 
									loader_dynamic_needed_size +
									_target_dynamic_size +
									_add_needed_size +
									sizeof(Elf32_Dyn),
									target_SONAME_idx);
	}

	/* 核算下一个偏移 */
	unsigned next_offset = loader_dynamic_needed_size + 
		_target_dynamic_size + _add_needed_size;
	if (_opts.xdebugger)
		next_offset += sizeof(Elf32_Dyn);

	if (_target_pltrel == NULL) {
		memcpy((unsigned char*)_new_dynamic + next_offset, 
			   (void*)&pltrel_dyn,
			   sizeof(Elf32_Dyn));

		memcpy((unsigned char*)_new_dynamic + next_offset + sizeof(Elf32_Dyn), 
			   (void*)&pltrel_size_dyn,
			   sizeof(Elf32_Dyn));

		next_offset += (sizeof(Elf32_Dyn) * 2);
	}

	if (_target_rel == NULL) {
		memcpy((unsigned char*)_new_dynamic + next_offset, 
			   (void*)&rel_dyn,
			   sizeof(Elf32_Dyn));

		memcpy((unsigned char*)_new_dynamic + next_offset + sizeof(Elf32_Dyn), 
			   (void*)&rel_size_dyn,
			   sizeof(Elf32_Dyn));

		next_offset += (sizeof(Elf32_Dyn) * 2);
	}
	
	if (_target_finit == NULL) {
		memcpy((unsigned char*)_new_dynamic + next_offset, 
			   (void*)&finit_dyn,
			   sizeof(Elf32_Dyn));
		next_offset += sizeof(Elf32_Dyn);
	}

	/* 释放 */
	if (loader_dynamic_needed) delete [] loader_dynamic_needed;

	/* 更新elftools */
	//_elftools->update_merge_mem(0);
	return dynamic_size;
}

unsigned* Dis::get_dynamic_object_offset_ptr(Elf32_Dyn* dyn, unsigned key) {
	XASSERT(dyn);
	Elf32_Dyn* dynp = dyn;
	for (; DT_NULL != dynp->d_tag; ++dynp) {
		if (get_te32(&dynp->d_tag) == key) {
			return (unsigned*)(&(dynp->d_un.d_val));
		}
	}
	return NULL;
}

int Dis::is_in_target_strtab_strings(char* name) {
	if (name == NULL) return 0;

	vector<string>::iterator iter = _target_strtab_strings.begin();
	vector<string>::iterator iter_end = _target_strtab_strings.end();
	
	for (; iter != iter_end; iter++) {
		if (*iter != name)
			continue;
		else 
			return 1;
	}

	return 0;
}

int Dis::fix_rel_offset(Elf32_Rel* rel, unsigned relc,
						unsigned fix_offset) {
	XASSERT(rel);
	
	Elf32_Rel* d = rel;
	for (unsigned i = 0; i < relc; i++, d++) {
		d->r_offset += fix_offset;
	}

	return 0;
}

unsigned Dis::fix_rel_symidx(Elf32_Rel* rel, unsigned relc, 
							 unsigned old_symidx, unsigned new_symidx) {
	XASSERT(rel);

	Elf32_Rel* d = rel;
	unsigned fc = 0;
	/* 这里要跑完所有的重定位项目
	 * 因为有可能同一个符合作用于多个
	 * 重定位项目
	 */
	for (unsigned i = 0; i < relc; i++, d++) {
		unsigned rel_sym_index = ELF32_R_SYM(d->r_info);
		if (rel_sym_index == 0) continue;   /* 符号索引为0,表示没有符号 */
		
		/* 在表中处理过的直接跳过 */
		if (find_relobj_log((unsigned)d)) continue;

		if (rel_sym_index == old_symidx) {
			unsigned rel_sym_type = ELF32_R_TYPE(d->r_info);
			unsigned new_info = ELF32_R_INFO(new_symidx, rel_sym_type);
			d->r_info = new_info;
			/* 加入表 */
			// _relobj_log.push_back((unsigned)d);
			/* 如果表中为空则写入 */
			if (_relobj_log.find((unsigned)d) == _relobj_log.end())
				_relobj_log[(unsigned)d] = (unsigned)d;
			fc++;
		}
	}

	return fc;
}

Elf32_Rel* Dis::find_relobj_log(unsigned relobj) {
	// vector<unsigned>::iterator iter = _relobj_log.begin();
	// for(; iter != _relobj_log.end(); iter++) {
	// 	if (*iter == relobj) {
	// 		return (Elf32_Rel*)(*iter);
	// 	}
	// }
	if (_relobj_log.find(relobj) == _relobj_log.end())
		return NULL;

	return (Elf32_Rel*)_relobj_log[relobj];
}

int Dis::loop_handle_target_symtab(elf_tools_symtab* symbase,
								   Elf32_Sym* symtab, char* strtab,
								   Elf32_Rel* pltreltab, unsigned pltrelc,
								   Elf32_Rel* reltab, unsigned reltabc,
								   unsigned* hashlist, unsigned hashcount) {
	XASSERT(symbase);
	XASSERT(symtab);
	XASSERT(strtab);
	XASSERT(hashlist);

	int ret = 0;

	/* 按照选项进行分组 */
	//int thread_group = 0;
	for (unsigned i = 0; i < hashcount; i++) {
		if (hashlist[i] == 0) continue;

		unsigned sym_index = hashlist[i];

		Elf32_Sym* sym = &(symtab[sym_index]);
		if (sym == NULL) continue;

		char* name = strtab + sym->st_name;
		if (name == NULL) continue;

		unsigned bind = ELF32_ST_BIND(sym->st_info);
		unsigned type = ELF32_ST_TYPE(sym->st_info);

		// printf("name=%s, idx=%d, type=%d, bind=%d, new=%d\n",
	    // 	   name, sym_index, type, bind, symbase->index);

		/* 将所有的字符串放置到一个表中，如果随后的loader发生
		 * 同名则修改loader中的。只要loader被修改的符号不被
		 * 导出引用则程序不会发生错误
		 */
		_target_strtab_strings.push_back(name);   /* 多线程这里需要同步锁 */

		/* 修改对应重定位表的符号索引 
		 * 由于这里一个符号对应一个重定位表,这里
		 * 不需要同步锁,线程直接读取写入就好
		 */
		unsigned rel_ret = 0, pltrel_ret = 0;
		
		if (reltab) {
			rel_ret = fix_rel_symidx(reltab, 
									 reltabc,
									 sym_index,
									 symbase->index);
		}

		if (pltreltab) {
			pltrel_ret = fix_rel_symidx(pltreltab, 
										pltrelc, 
										sym_index,
										symbase->index);
		}
		
		/* 符号在对应的重定位表中没有项目 */
		if ((rel_ret == 0) && (pltrel_ret == 0)) {
			/* FIXME:... */
		}

		/* 添加新的, 写入索引的时候*/
		ret = elf_symbase_add((void*)symbase,
							  name, 
							  sym->st_value,
							  sym->st_size,
							  bind,
							  type,
							  sym->st_other,
							  sym->st_shndx,
							  _opts.muti_string);
		if (ret) return ret;
	}

	return 0;
}

int Dis::loop_handle_loader_symtab(elf_tools_symtab* symbase,
								   Elf32_Sym* symtab, char* strtab,
								   Elf32_Rel* pltreltab, unsigned pltrelc,
								   Elf32_Rel* reltab, unsigned reltabc,
								   unsigned* hashlist, unsigned hashcount,
								   unsigned fix_offset) {
	XASSERT(symbase);
	XASSERT(symtab);
	XASSERT(strtab);
	XASSERT(hashlist);

	int ret = 0;

	for (unsigned i = 0; i < hashcount; i++) {
		if (hashlist[i] == 0) continue;
		unsigned sym_index = hashlist[i];

		Elf32_Sym* sym = &(_loader_symtab[sym_index]);
		if (sym == NULL) continue;

		char* name = strtab + sym->st_name;
		if (name == NULL) continue;

		unsigned bind = ELF32_ST_BIND(sym->st_info);
		unsigned type = ELF32_ST_TYPE(sym->st_info);
		unsigned st_value = sym->st_value;

		/* 如果是本地符号则一个检验表中，用于loader的检查 
		 * 避免两个so在加载时的本地符号冲突.
		 */
		char name_tmp[128] = {0};
		if (is_in_target_strtab_strings(name) && 
			(st_value != 0)) {
			strcpy(name_tmp, name);
			if (name_tmp[0] != '0')
				name_tmp[0] = '0';
			else
				name_tmp[0] = '1';
			name = &name_tmp[0];
		}

		/* 修改对应重定位表的符号索引 */
		unsigned rel_ret = 0, pltrel_ret = 0;

		if (reltab) {
			rel_ret = fix_rel_symidx(reltab, 
									 reltabc, 
									 sym_index,
									 symbase->index);
		}
		
		if (pltreltab) {
			pltrel_ret = fix_rel_symidx(pltreltab, 
										pltrelc, 
										sym_index,
										symbase->index);
		}
		
		/* 符号在对应的重定位表中没有项目 */
		if ((rel_ret == 0) && (pltrel_ret == 0)) {
			/* FIXME:... */
		}

		unsigned sym_new_value = sym->st_value;
		if (sym->st_shndx == SHN_ABS) {
			/* 如果是一个绝对值符号则不进行符号的偏移修订 */
			;
		} else if (sym->st_shndx == SHN_COMMON) {
			/* 在非obj文件中，应该不会出现这个类型 */
			;
		} else if (sym->st_shndx == SHN_UNDEF) {
			/* 外部引入符号也不用定义什么 */
			;
		} else {
			/* 正常内部符号 */
			sym_new_value += fix_offset;
		}
		
		/* 增加到新的符号表 */
		ret = elf_symbase_add((void*)symbase,
													name, 
													sym_new_value,
													sym->st_size,
													bind,
													type,
													sym->st_other,
													sym->st_shndx,
													_opts.muti_string);
		if (ret) return ret;
	}

	return 0;
}

unsigned char* Dis::make_new_reltab(bool pltrel, unsigned* relsz) {
	if (pltrel) {
		/* 抽取target的pltrel */
		unsigned char* target_pltrel = (unsigned char*)_target_pltrel;
		unsigned target_pltrel_size = _target_pltrel_count * sizeof(Elf32_Rel);

		unsigned char* loader_pltrel = (unsigned char*)_loader_pltrel;
		unsigned loader_pltrel_size = _loader_pltrel_count * sizeof(Elf32_Rel);

		if (_opts.save_target_rel) {
			_new_pltrelsz = up4(loader_pltrel_size);
		} else {
			_new_pltrelsz = up4(target_pltrel_size + loader_pltrel_size);
		}
		_new_pltrel = new unsigned char [_new_pltrelsz];
		if (_new_pltrel == NULL) {
			return NULL;
		}

		if (_opts.save_target_rel) {
			memcpy(_new_pltrel, loader_pltrel, loader_pltrel_size);
		} else {
			memcpy(_new_pltrel, target_pltrel, target_pltrel_size);
			memcpy(_new_pltrel + target_pltrel_size, loader_pltrel, 
				   loader_pltrel_size);
		}

		*relsz = _new_pltrelsz;
		return _new_pltrel;
	} else {
		unsigned char* target_rel = (unsigned char*)_target_rel;
		unsigned target_rel_size = _target_rel_count * sizeof(Elf32_Rel);

		unsigned char* loader_rel = (unsigned char*)_loader_rel;
		unsigned loader_rel_size = _loader_rel_count * sizeof(Elf32_Rel);

		if (_opts.save_target_rel) {
			_new_relsz = up4(loader_rel_size);
		} else {
			_new_relsz = up4(target_rel_size + loader_rel_size);
		}
		_new_rel = new unsigned char [_new_relsz];
		if (_new_rel == NULL) {
			return NULL;
		}

		if (_opts.save_target_rel) {
			memcpy(_new_rel, loader_rel, loader_rel_size);
		} else {
			memcpy(_new_rel, target_rel, target_rel_size);
			memcpy(_new_rel + target_rel_size, loader_rel, loader_rel_size);
		}

		*relsz = _new_relsz;
		return _new_rel;
	}
	return NULL;
}

unsigned char* Dis::save_target_reltab(bool pltrel, unsigned* relsz) {
	if (pltrel) {
		unsigned char* target_pltrel = (unsigned char*)_target_pltrel;
		unsigned target_pltrel_size = _target_pltrel_count * sizeof(Elf32_Rel);
		_save_target_pltrel_size = up4(target_pltrel_size);
		_save_target_pltrel = new unsigned char [_save_target_pltrel_size];
		if (_save_target_pltrel == NULL) {
			return NULL;
		}
		memset(_save_target_pltrel, 0, _save_target_pltrel_size);
		memcpy(_save_target_pltrel, target_pltrel, target_pltrel_size);

		*relsz = _save_target_pltrel_size;
		return _save_target_pltrel;
	} else {
		unsigned char* target_rel = (unsigned char*)_target_rel;
		unsigned target_rel_size = _target_rel_count * sizeof(Elf32_Rel);
		_save_target_rel_size = up4(target_rel_size);
		_save_target_rel = new unsigned char [_save_target_rel_size];
		if (_save_target_rel == NULL) {
			return NULL;
		}
		memset(_save_target_rel, 0, _save_target_rel_size);
		memcpy(_save_target_rel, target_rel, target_rel_size);

		*relsz = _save_target_rel_size;
		return _save_target_rel;
	}
	return NULL;
}

void Dis::clean_target_loader_xct() {
	unsigned char* ptr = (unsigned char*)(void*)(_elftools->_phdri);
	unsigned char* start = ptr + (sizeof(Elf32_Phdr) * _elftools->_phnum);
	unsigned char* end = _elftools->_file + 
		((ElfDynamicTools*)(_elftools->_orig_elftools))->_yct_off;
	unsigned size = (unsigned)(end - start);
	memset(start, 0, size);

	ptr = (unsigned char*)(void*)(_ld_elftools->_phdri);
	start = ptr + (sizeof(Elf32_Phdr) * _ld_elftools->_phnum);
	end = _ld_elftools->_file + _ld_orig_elftools->_yct_off;
	size = (unsigned)(end - start);
	memset(start, 0, size);	

}

void Dis::add_DT_DEBUG(unsigned char *ptr) {
	Elf32_Dyn dt_debug;
	dt_debug.d_tag = DT_DEBUG;
	dt_debug.d_un.d_val = 0;

	memcpy(ptr, &dt_debug, sizeof(Elf32_Dyn));
}

/* devilogic 2016.4.10添加仅为支持android6以后的系统 */
void Dis::clear_dynamic_xxx(Elf32_Dyn* dyn) {
	Elf32_Dyn* d = dyn;
	while (d->d_tag) {
		if ((d->d_tag == DT_VERSYM) || 
				(d->d_tag == DT_VERDEF) ||
				(d->d_tag == DT_VERDEFNUM) ||
				(d->d_tag == DT_VERNEED) ||
				(d->d_tag == DT_VERNEEDNUM)) {
			d->d_tag = DT_BIND_NOW;
			d->d_un.d_ptr = 0;
		}
		d++;
	}
}

/* 0:表示成功
 * -1:表示不存在DT_SONAME 
 * -2:表示添加字符串不成功
 */
int Dis::fix_target_SONAME(int *idx) {
	Elf32_Dyn *d = _target_dynamic;
	while (d->d_tag) {
		if (d->d_tag == DT_SONAME) break;
		d++;
	}

	char *str = NULL;

	/* 由于elftools有个小bug，所以这里采用临时解决方案，
	 * 不从DT_SONAME中提取字符串，直接从libname中设置
	 */
	str = _opts.libname;/* 默认使用文件名或者用户指定 */

#if 0
	/* 以下内容，等修复elftools后启用 */
	if ((d->d_tag != DT_NULL) && (d->d_tag == DT_SONAME)) {
		str = &(_elftools->_orig_elftools->_strings[d->d_un.d_val]);
	} else {
		str = _opts.libname;/* 默认使用文件名或者用户指定 */
	}
#endif

	/* 添加到当前的字符串表中 */
	int ret = elf_strtab_add(&_symbase, str, false);
	if (ret == -1) {
		ERROR_INTERNAL_EXCEPT("add target SONAME %s to strtab failed", str);
		return -2;
	}

	/* 保存一个索引，当target没有SONAME时使用 */
	if (idx) *idx = ret;

	if (d->d_tag == DT_SONAME) {
		d->d_un.d_val = ret;
		return 0;
	}
	
	/* 当没有DT_SONAME时返回-1 */
	return -1;
}

void Dis::add_DT_SONAME(unsigned char *ptr, int idx) {
	Elf32_Dyn d;
	d.d_tag = DT_SONAME;
	d.d_un.d_val = idx;

	memcpy(ptr, &d, sizeof(Elf32_Dyn));
}

int Dis::fill_globals() {
	/* 读取XML设置全局变量 */
	CMarkup xml;
	Elf32_Sym *symnode = NULL;
	MCD_STR tag, value, attribute;
	unsigned size = 0;

	/* 加载XML */
	if (!xml.Load(_opts.loader_descript)) {
		ERROR_INTERNAL_EXCEPT("load xml : %s failed", _opts.loader_descript);
		return -1;
	}

	/* 重新设置位置 */
	xml.ResetMainPos();

	/* 找到自定义加载器的节点 */
	if (xml.FindChildElem("dis")) {
		// attribute = xml.GetChildAttrib("entry");
		// if (attribute == "") {
		// 	ERROR_INTERNAL_EXCEPT("read xml attribute invalid");
		// 	return -1;		
		// }
		// char* entry_name = (char*)(attribute.c_str());
		// Elf32_Sym* entry_sym = _ld_elftools->elf_lookup(entry_name);
		// if (entry_sym == NULL) {
		// 	ERROR_INTERNAL_EXCEPT("entry symbol not found");
		// 	return -1;
		// }
		// _loader_entry = entry_sym->st_value;

		xml.IntoElem();
		/* 查询子节点 */
		while (xml.FindChildElem()) {
			/* 获取节点名称, 值, 属性 */
			tag = xml.GetChildTagName();
			value = xml.GetChildData();
			attribute = xml.GetChildAttrib("size");

			if (tag == "" || value == "") {
				ERROR_INTERNAL_EXCEPT("read xml tag is empty");
				return -1;
			}

			if (attribute == "") {
				size = 4;
			} else {
				/* FIXME:这里验证不严密 */
				//ERROR_INTERNAL_EXCEPT("read xml attribute invalid");
				size = atoi(attribute.c_str());
			}

			/* 获取标记 */
			char* n = const_cast<char*>(tag.c_str());
			char *v = const_cast<char*>(value.c_str());
			if (!v) continue;
			
			/* 三个特殊变量 */
			if (strcmp(n, "X") == 0) {
				symnode = _ld_elftools->elf_lookup(v);
				if (symnode == NULL) {
					ERROR_INTERNAL_EXCEPT("entry symbol not found");
					return -1;
				}
				_loader_entry = symnode->st_value;
				_loader_entry_size = symnode->st_size;
			} else if (strcmp(n, "Y") == 0) {
				symnode = _ld_elftools->elf_lookup(v);
				if (symnode == NULL) {
					ERROR_INTERNAL_EXCEPT("exit symbol not found");
					return -1;
				}
				_loader_exit = symnode->st_value;
			} else if (strcmp(n, "Z") == 0) {
				symnode = _ld_elftools->elf_lookup(v);
				if (symnode == NULL) {
					ERROR_INTERNAL_EXCEPT("control symbol not found");
					return -1;
				}
				_loader_control = symnode->st_value;
			}

			/* 找到这个符号 */
			Elf32_Sym* sym = _ld_elftools->elf_lookup(n);
			if (sym) {
				unsigned offset = sym->st_value;
				unsigned size_sym = sym->st_size;
				
				/* 对比大小,外部指定的大小一定要小于符号本身的缓存大小 */
				if (size_sym < size) {
					ERROR_INTERNAL_EXCEPT("export symbal size invalid");
					return -1;
				}
				fill_node(n, v, offset, size);
			}
		}
		xml.OutOfElem();

	} else {
		// unknown node
		ERROR_INTERNAL_EXCEPT("unknown xml node");
		return -1;
	}

	return 0;
}

unsigned Dis::get_save_target_pltjmp_offset() {
	return _save_target_pltrel_offset;
}

unsigned Dis::get_save_target_pltjmp_size() {
	return _save_target_pltrel_size;
}

unsigned Dis::get_save_target_rel_offset() {
	return _save_target_rel_offset;
}

unsigned Dis::get_save_target_rel_size() {
	return _save_target_rel_size;
}

unsigned Dis::get_exspace_offset() {
	return _exspace_offset;
}

unsigned Dis::get_exspace_size() {
	return _exspace_size;
}

void Dis::set_exspace_size(unsigned size) {
	_exspace_size = size;
}

unsigned char *Dis::get_exspace() {
	return _exspace;
}

void Dis::set_exspace(unsigned char *p) {
	_exspace = p;
}
