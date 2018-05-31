#include "dog_common.h"
#include "crc.h"

bool DogTools::the_symbol_is_not_need_rel(unsigned sym_idx) {
	UNUSED(sym_idx);
	return false;
}

/* 加密内部符号,在write_loader中进行调用 */
unsigned DogTools::encrypt_inside_symbols(unsigned key) {
	return encrypt_inside_symbols_dis(key);
}

/* 加密内部符号,使用dis技术 */
#include <vector>
using namespace std;
unsigned DogTools::encrypt_inside_symbols_dis(unsigned key) {
	/* 无论如何都先更新一下elf工具 */
	_pack_elftools->update_merge_mem(0);
	/* 获取在重定位下的符号，这些符号不能加密 */
	vector<unsigned> ilist;

	/* 因为动态库的符号节是在第一个加载段中是在xct_off内的所以
	 * 原先的和现在的一致
	 */
	Elf32_Dyn* dynsym = (Elf32_Dyn*)(_pack_elftools->_dt_symtab.dyn);
	Elf32_Dyn* dynstr = (Elf32_Dyn*)(_pack_elftools->_dt_strtab.dyn);
	unsigned char* ptr = (unsigned char*)_pack_obuf;

	/* 从原始文件中读取，按照合并后的内存进行计算偏移 */

	/* 在文件中的符合表 */
	Elf32_Sym* pSym = (Elf32_Sym*)(ptr + dynsym->d_un.d_val);
	/* 在文件中的字符串表 */
	unsigned str_off = (unsigned)(ptr + dynstr->d_un.d_val);

	/* 符号的数量 */
	unsigned symnum = ((Dis*)_loader)->_symnum;

	// 写入字符串表的文件偏移
	unsigned disp = 0;
	unsigned len = _pack_obuf_offset;
	unsigned cur = len;

	/* 写入字符串表偏移 */
	set_te32(&disp, dynstr->d_un.d_val);
	_encrypt_inside_data_strtab_offset = disp;
	cur += sizeof(unsigned);

	// 写入符号表的文件偏移
	set_te32(&disp, dynsym->d_un.d_val);
	_encrypt_inside_data_symtab_offset = disp;
	cur += sizeof(unsigned);

	// 写入符号个数
	set_te32(&disp, symnum);
	_encrypt_inside_data_symnum = disp;
	cur += sizeof(unsigned);

	/* 写入密钥 */
	set_te32(&disp, key);
	_encrypt_inside_data_key = disp;
	cur += sizeof(unsigned);

	/* 忽略重定位表中的符号 */
	if (_opts.skip_string_in_reloc) {
		_pack_elftools->elf_get_rel_sym_index(ilist);
	}

	for (unsigned i = 0; i < symnum; i++, pSym++) {
		// 遍历符号表
		bool b = false;
		/* 单加密内部符号 */
		if ((pSym->st_value != 0) && (pSym->st_name != 0)) {
			/* 确定是否已经加密 */
			vector<unsigned>::iterator iter = ilist.begin();
			for (; iter != ilist.end(); iter++) {
				if (*iter == (unsigned)(pSym->st_name)) {
					/* 忽略此符号 */
					b = true;
					break;
				}
			}/* end for */
			if (b == true)
				continue;
			
			/* 这里是以上字符串的文件偏移 */
			unsigned char* memptr = (unsigned char*)(str_off + pSym->st_name);
			unsigned strlens = strlen((const char*)(memptr));
			
			/* 进行加密 */
			if (_dog_encrypt_inside_name) {
				_dog_encrypt_inside_name(pSym,
			 							 memptr, strlens,
			 							 memptr, (int*)&strlens,
			 							 key);
			} else {
			 	XorArray(key, memptr, memptr, strlens);
			}
			
			/* 已经加密的添加到忽略表中 */
			ilist.push_back(pSym->st_name);
		}/* end if */
	}/* end for  */
	
	ilist.clear();
	return (cur - len);
}

/* 复制原生重定位表 */
unsigned DogTools::copy_orig_rel(MemBuffer *membuf, 
								 unsigned now_offset,
								 unsigned new_pt_dynamic_offset,
								 unsigned pt_dynamic_idx,
								 struct dynamic_value *dt,
								 Elf32_Dyn **relsize_dyn,
								 unsigned added) {
	XASSERT(membuf);
	XASSERT(dt);

	/* 判断重定位表 */
	unsigned char* orel = NULL;
	unsigned orel_size = 0;
	unsigned orel_pt_dynamic = 0;
	unsigned orel_size_pt_dynamic = 0;
	unsigned len = 0;
	unsigned char *ptr = NULL;

	if (dt->exist) {
		orel = dt->context;
		orel_size = dt->support->size;
		orel_pt_dynamic = dt->inside_offset - sizeof(unsigned);
		orel_size_pt_dynamic = dt->support->inside_offset - sizeof(unsigned);

		len = orel_size;

		/* 写入原始的重定位表 */
		writeTarget(NULL, orel, orel_size, TDOG_DEBUG,
					"Orig reltab", now_offset, true, (void*)membuf);

		ptr = (unsigned char*)(*membuf);

		/* 读取一个头 */
		Elf32_Ehdr* header = (Elf32_Ehdr*)(unsigned char*)ptr;
		unsigned phoff = get_te32(&header->e_phoff);
		Elf32_Phdr* phdr = (Elf32_Phdr*)((unsigned char*)ptr + phoff);
		phdr += pt_dynamic_idx;

		/* 重新修订重定位表的指针 */
		Elf32_Dyn* dyn = (Elf32_Dyn*)(ptr + get_te32(&phdr->p_offset) + 
									  orel_pt_dynamic);
		set_te32(&dyn->d_un.d_val, new_pt_dynamic_offset);
		
		/* 重新修订重定位表的大小 */
		dyn = (Elf32_Dyn*)(ptr + get_te32(&phdr->p_offset) + 
						   orel_size_pt_dynamic);
		unsigned orig_val = get_te32(&dyn->d_un.d_val);
		orig_val += added;
		set_te32(&dyn->d_un.d_val, orig_val);
		if (relsize_dyn) *relsize_dyn = dyn;
	}

	return len;
}

/* 使用重定位加密loader或者目标代码段 */
unsigned DogTools::rel_encrypt_loader_and_codes(unsigned now_offset, 
												Elf32_Dyn** relsize_dyn) {
	XASSERT(relsize_dyn);

	unsigned len = 0, write_size = 0;
	unsigned char *ptr = (unsigned char*)_pack_obuf;
	Elf32_Rel *loader_rel_key = NULL, *codes_rel_key = NULL;
	unsigned key = 0;
	unsigned i = 0;
	unsigned added = 0;

	/* 新重定位表内存偏移 */
	unsigned new_rel_va = now_offset;

	/* 加密loader */
	if (_opts.reloc_encrypt_loader) {
		unsigned loader_count = 0;
		unsigned *loader = NULL;
		unsigned loader_entry_size = _loader->get_loader_entry_size();

		key = _loader_start_va + _loader_code_offset;
		loader = (unsigned*)(ptr + 
							 _loader_start_va + 
							 _loader_code_offset);
		loader_count = _loader_code_size / sizeof(unsigned);
		if (_opts.skip_entry) {
			/* 跳过入口点 */
			loader_count -= loader_entry_size / sizeof(unsigned);
		}
		
		loader_rel_key = new Elf32_Rel [loader_count];
		if (loader_rel_key == NULL) {
			ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new Elf32_Rel []");
			return 0;
		}
		
		for (i = 0; i < loader_count; i++) {

			if (_opts.skip_entry) {
				/* 判断似乎跳过入口点 */
				if (key == _loader_entry_va) {
					loader = (unsigned *)
						((unsigned char*)loader + loader_entry_size);
					key += loader_entry_size;
					i--;
					continue;
				}
			}

			/* 添加重定位项 */
			if (_opts.skip_entry)
				loader_rel_key[i].r_offset = key + 0x150501;
			else
				loader_rel_key[i].r_offset = key;
			loader_rel_key[i].r_info = ELF32_R_INFO(0, R_ARM_REL32);
			*loader += key;
			
			/* 增加 */
			loader++;
			key += sizeof(unsigned);
		}

		write_size = loader_count * sizeof(Elf32_Rel);

		/* 写入新重定位项目 */
		writeTarget(NULL, (void*)loader_rel_key, write_size, TDOG_DEBUG, 
					"Loader relkey", now_offset, true, (void*)(&_pack_obuf));
		
		if (loader_rel_key) delete [] loader_rel_key;

		/* 递增偏移 */
		now_offset += write_size;
		added += write_size;
		len += write_size;
	}

	/* 加密代码,这里有时需要大内存支持 */
	if (_opts.reloc_encrypt_codes) {
		unsigned codes_count = 0;
		unsigned *codes = NULL;

		key = _plaintext_offset;
		codes = (unsigned*)(ptr + _plaintext_offset);
		codes_count = _plaintext_size / sizeof(unsigned);
		
		codes_rel_key = new Elf32_Rel [codes_count];
		if (codes_rel_key == NULL) {
			ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new Elf32_Rel []");
			return 0;
		}

		for (i = 0; i < codes_count; i++) {
			/* 如果key在排除表内，则跳过 */

			codes_rel_key[i].r_offset = key;
			codes_rel_key[i].r_info = ELF32_R_INFO(0, R_ARM_REL32);
			*codes += key;
			
			/* 增加 */
			codes++;
			key += sizeof(unsigned);
		}

		write_size = codes_count * sizeof(Elf32_Rel);

		/* 写入新重定位项目 */
		writeTarget(NULL, (void*)codes_rel_key, write_size, TDOG_DEBUG, 
					"Codes relkey", now_offset, true, (void*)(&_pack_obuf));
		if (codes_rel_key) delete [] codes_rel_key;

		/* 递增偏移 */
		now_offset += write_size;
		added += write_size;
		len += write_size;
	}
	
	/**********************/
	/* 这以下是重新构造重定位动态段的内容 */
	
	/* 判断重定位表 */
	unsigned pt_dynamic_idx = _pack_elftools->elf_index_dynamic();

	/* .jmprel表 */
	write_size = copy_orig_rel(&_pack_obuf, 
							   now_offset, 
							   new_rel_va,
							   pt_dynamic_idx, 
							   &(_pack_elftools->_dt_jmprel),
							   relsize_dyn,
							   added);
	now_offset += write_size;
	len += write_size;
	
	if (write_size == 0) {
		/* 如果不存在则使用.rel表,因为在linker中
		 * 是先定位.jmpplt然后在定位.rel
		 */
		write_size = copy_orig_rel(&_pack_obuf, 
								   now_offset, 
								   new_rel_va,
								   pt_dynamic_idx, 
								   &(_pack_elftools->_dt_rel),
								   relsize_dyn,
								   added);
		now_offset += write_size;
		len += write_size;
	}

	if (len == 0) {
		/* 异常 */
		ERROR_INTERNAL_EXCEPT("relocal table is none");
		return 0;
	}

	return len;
}

unsigned DogTools::rel_remove_elf_header(unsigned rel_append_offset,
										 Elf32_Dyn** relsize_dyn) {
	XASSERT(relsize_dyn);

	//unsigned char* ptr = (unsigned char*)_pack_obuf;
	/* 计算ELF头 + 程序段表头的长度 */
	unsigned size = _pack_elftools->_phoff + 
		_pack_elftools->_phnum * sizeof(Elf32_Phdr);

	if (size % 4 != 0) {
		/* 这里应该做出错处理 */
		ERROR_INTERNAL_EXCEPT("phdr list size is not 4 align");
		return 0;
	}

	/* 要添加重定位的项目数量 */
	unsigned count = size / 4;

	/* 更新动态项的长度并设置 */
	if (*relsize_dyn != NULL) {
		Elf32_Dyn *r = *relsize_dyn;
		unsigned orig_size = get_te32(&r->d_un.d_val);
		orig_size += sizeof(Elf32_Rel) * count;
		set_te32(&r->d_un.d_val, orig_size);
	}

	/* 写入 */
	Elf32_Rel* rel_remove = new Elf32_Rel [count];
	if (rel_remove == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new Elf32_Rel");
	}

	unsigned remove = _pack_elftools->_load_va;
	for (unsigned i = 0; i < count; i++) {
		rel_remove[i].r_offset = remove;
		rel_remove[i].r_info = ELF32_R_INFO(0, R_ARM_JUMP_SLOT);
		remove += sizeof(unsigned);
	}

	unsigned len = sizeof(Elf32_Rel) * count;
	writeTarget(NULL, rel_remove, len, TDOG_DEBUG, 
				"Append rel remove hdr", 
				rel_append_offset, true,
				(void*)(&_pack_obuf));

	if (rel_remove) delete [] rel_remove;

	/* 如果没有创建新的重定位动态项则创建 */
	if (*relsize_dyn == NULL) {
		/* 新重定位表内存偏移 */
		unsigned new_rel_va = rel_append_offset;
		rel_append_offset += len;
		
		/* 判断重定位表 */
		unsigned pt_dynamic_idx = _pack_elftools->elf_index_dynamic();

		/* .jmprel表 */
		len += copy_orig_rel(&_pack_obuf, 
							 rel_append_offset, 
							 new_rel_va,
							 pt_dynamic_idx, 
							 &(_pack_elftools->_dt_jmprel),
							 relsize_dyn,
							 len);
		rel_append_offset += len;
		
		if (len == 0) {
			/* 如果不存在则使用.rel表,因为在linker中
			 * 是先定位.jmpplt然后在定位.rel
			 */
			len = copy_orig_rel(&_pack_obuf, 
								rel_append_offset, 
								new_rel_va,
								pt_dynamic_idx, 
								&(_pack_elftools->_dt_rel),
								relsize_dyn,
								len);
			rel_append_offset += len;
		}
		
		if (len == 0) {
			/* 异常 */
			ERROR_INTERNAL_EXCEPT("relocal table is none");
			return 0;
		}
	}

	return len;
}

unsigned DogTools::hide_entry(unsigned rel_append_offset, 
							  Elf32_Dyn **relsize_dyn) {
	UNUSED(rel_append_offset);
	UNUSED(relsize_dyn);
#if 0
	XASSERT(relsize_dyn);
	unsigned len = 0;
	/* 如果没有创建新的重定位动态项则创建 */
	if (*relsize_dyn == NULL) {
		/* 新重定位表内存偏移 */
		unsigned new_rel_va = rel_append_offset;
		/* 判断重定位表 */
		unsigned pt_dynamic_idx = _pack_elftools->elf_index_dynamic();

		/* .jmprel表 */
		len += copy_orig_rel(&_pack_obuf, 
							 rel_append_offset, 
							 new_rel_va,
							 pt_dynamic_idx, 
							 &(_pack_elftools->_dt_jmprel),
							 relsize_dyn,
							 len);
		rel_append_offset += len;
		
		if (len == 0) {
			/* 如果不存在则使用.rel表,因为在linker中
			 * 是先定位.jmpplt然后在定位.rel
			 */
			len += copy_orig_rel(&_pack_obuf, 
								 rel_append_offset, 
								 new_rel_va,
								 pt_dynamic_idx, 
								 &(_pack_elftools->_dt_rel),
								 relsize_dyn,
								len);
			rel_append_offset += len;
		}
		
		if (len == 0) {
			/* 异常 */
			ERROR_INTERNAL_EXCEPT("relocal table is none");
			return 0;
		}
	}
	_pack_elftools->update_merge_mem(0);

	/* 要添加重定位的项目数量,就DT_INIT一项 */
	unsigned count = 1;

	/* 更新动态项的长度并设置 */
	if (*relsize_dyn != NULL) {
		Elf32_Dyn *r = *relsize_dyn;
		unsigned orig_size = get_te32(&r->d_un.d_val);
		orig_size += sizeof(Elf32_Rel) * count;
		set_te32(&r->d_un.d_val, orig_size);
	}

	/* 写入 */
	Elf32_Rel* dt_init = new Elf32_Rel [count];
	if (dt_init == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new Elf32_Rel");
	}
	
	unsigned dt_init_va = _pack_elftools->elf_offset_dynamic(DT_INIT);
	dt_init_va += _pack_elftools->elf_get_dynamic_va();
	
	dt_init->r_offset = dt_init_va;
	dt_init->r_info = ELF32_R_INFO(0, R_ARM_JUMP_SLOT);

	unsigned ws = sizeof(Elf32_Rel) * count;
	writeTarget(NULL, dt_init, ws, TDOG_DEBUG, 
				"Append rel remove hdr", 
				rel_append_offset, true,
				(void*)(&_pack_obuf));
	
	len += ws;
	if (dt_init) delete [] dt_init;

	return len;
#endif

	return 0;
}

/* 写入加载器 */
void DogTools::write_loader() {
	//unsigned disp = 0;
	unsigned char* ptr = (unsigned char*)_pack_obuf;
	
	/****************************************************/
	// 加载器的初始VA地址
	/****************************************************/
	_loader_start_va = _pack_obuf_offset;

	/****************************************************/
	// 设置扩展空间
	/****************************************************/
	if (1) {
		Dis *dis = (Dis*)_loader;
		dis->set_exspace_size(_exspace_size);
		dis->set_exspace(_exspace);
	}

	/****************************************************/
	// 合成加载器全局变量
	/****************************************************/
	_loader->build_loader(ptr, ptr + _loader_start_va);
	_loader_size = _loader->get_loader_size();
	_loader_code_size = _loader->get_loader_code_size();
	_loader_code_offset = _loader->get_loader_code_offset();

	/****************************************************/
	// 写入加载器
	/****************************************************/
	_loader->write_loader(ptr, _pack_obuf_offset);
	_pack_obuf_offset += _loader_size;
	_pack_elftools->update_merge_mem(_loader_size); /* 更新ELF工具 */

	/****************************************************/
	// 修订loader的入口VA
	/****************************************************/
	_loader_entry_va = _loader_start_va + _loader->get_loader_entry_offset();
	_loader_exit_va = _loader_start_va + _loader->get_loader_exit_offset();
	_loader_control_va = 
		_loader_start_va + _loader->get_loader_control_offset();

	/****************************************************/
	// 加密字符串表
	/****************************************************/
	if (_opts.encrypt_inside_data_name) {
		unsigned key = _opts.encrypt_inside_data_name_key;
		/* 这里应该增加0x14个字节 */
		_size_loader_encrypt_inside_data_size = encrypt_inside_symbols(key);
		_pack_obuf_offset += _size_loader_encrypt_inside_data_size;
	}

	/****************************************************/
	// 在写入全局变量前，写入加密导出函数代码
	/****************************************************/
	if (_opts.encrypt_global_codes) {
		write_en_functions(&_pack_obuf, _pack_obuf_offset,
						   _abs_export_function_list,
						   _abs_export_function_list_size);
		_abs_export_function_list_va = _pack_obuf_offset;
		unsigned align_size = up4(_abs_export_function_list_size);
		_pack_obuf_offset += align_size;
		_pack_elftools->update_merge_mem(align_size);

		/* 准备进行hook */
		if (_opts.control_exp_func) {
			if (hook_abs_export_functions(_loader_control_va)) {
				ERROR_INTERNAL_EXCEPT("hook abs export function failed");
				return;
			}
		}/* end if */
	}

	/****************************************************/
	// 写入加密指定函数代码
	/****************************************************/
	if (_opts.encrypt_func) {
		write_en_functions(&_pack_obuf, _pack_obuf_offset,
						   _en_function_list,
						   _en_function_list_size);
		_en_function_list_va = _pack_obuf_offset;
		unsigned align_size = up4(_en_function_list_size);
		_pack_obuf_offset += align_size;
		_pack_elftools->update_merge_mem(align_size);
		/* 准备进行hook */
		// if (_opts.control_exp_func) {
		// 	if (hook_abs_export_functions(_loader_control_va)) {
		// 		ERROR_INTERNAL_EXCEPT("hook abs export function failed");
		// 		return;
		// 	}
		// }/* end if */
	}

	/****************************************************/
	// 写入当前可以获取的全局变量
	/****************************************************/
	write_globals();

	/****************************************************/
	// 刷入全局变量
	/****************************************************/
	_loader->update_vars(ptr, ptr + _loader_start_va);

	/****************************************************/
	// 这里是一组用重定位表操作,目前版本仅在ARM下起作用
	/****************************************************/
	if (_opts.arch == ARCH_ARM) {
		Elf32_Dyn *dyn_tmp = NULL;
		/* 使用重定位表加密加载器或者代码段 */
		if ((_opts.reloc_encrypt_loader) || (_opts.reloc_encrypt_codes)) {
			unsigned rs = rel_encrypt_loader_and_codes(_pack_obuf_offset, 
													   &dyn_tmp);
			_pack_obuf_offset += rs;
			_pack_elftools->update_merge_mem(rs); 		/* 更新ELF工具 */
		}

		/* 使用重定位表加密elf头 */
		if (_opts.reloc_remove_elf_header) {
			unsigned rs = rel_remove_elf_header(_pack_obuf_offset, &dyn_tmp);
			_pack_obuf_offset += rs;
			_pack_elftools->update_merge_mem(rs); 		/* 更新ELF工具 */
		}

		/* 隐藏入口点 */
		if (_opts.hide_entry) {
			unsigned rs = hide_entry(_pack_obuf_offset, &dyn_tmp);
			_pack_obuf_offset += rs;
			_pack_elftools->update_merge_mem(rs); 		/* 更新ELF工具 */
		}
	} else {
		warning_msg("not support options in this arch\n");
	}

	/****************************************************/
	// 写入hack数据,这些数据是在loader之后
	/****************************************************/
	_size_hack_data = write_hack_data(_pack_obuf_offset);
	_pack_obuf_offset += _size_hack_data;

	/****************************************************/
	// 更新ELF工具
	/****************************************************/
	_pack_elftools->update_merge_mem(_size_hack_data);
}

void DogTools::write_globals() {
	unsigned disp = 0, exspace_offset = 0;
	Dis *dis = NULL;

	/* 扩展空间 */
	dis = (Dis*)_loader;
	exspace_offset = dis->get_exspace_offset();
	set_te32(&disp, exspace_offset);
	_loader->set_sys_var_value("EXSPACE_OFFSET", disp);
	info_msg("EXSPACE_OFFSET = 0x%X\n", disp);

	set_te32(&disp, dis->get_exspace_size());
	_loader->set_sys_var_value("EXSPACE_SIZE", disp);
	info_msg("EXSPACE_SIZE = 0x%X\n", disp);

	_loader->set_sys_var_value("LOADER_OFFSET", _loader_start_va);
	info_msg("LOADER_OFFSET = 0x%X\n", _loader_start_va);

	_loader->set_sys_var_value("LOADER_CODE_OFFSET", _loader_code_offset);
	info_msg("LOADER_CODE_OFFSET = 0x%X\n", _loader_code_offset);

	_loader->set_sys_var_value("LOADER_SIZE", _loader_size);
	info_msg("LOADER_SIZE = 0x%X\n", _loader_size);

	_loader->set_sys_var_value("LOADER_CODE_SIZE", _loader_code_size);
	info_msg("LOADER_CODE_SIZE = 0x%X\n", _loader_code_size);

	_loader->set_sys_var_value("CURR_ENTRY", _loader_entry_va);
	info_msg("CURR_ENTRY = 0x%X\n", _loader_entry_va);

	_loader->set_sys_var_value("CURR_EXIT", _loader_exit_va);
	info_msg("CURR_EXIT = 0x%X\n", _loader_exit_va);

	set_te32(&disp, _loader->get_loader_entry_size());
	_loader->set_sys_var_value("ENTRY_SIZE", disp);
	info_msg("ENTRY_SIZE = 0x%X\n", disp);

	_loader->set_sys_var_value("XCT_OFFSET", _elftools->_xct_va_delta);
	info_msg("XCT_OFFSET = 0x%X\n", _elftools->_xct_va_delta);

	_loader->set_sys_var_value("ELF_EHDR_OFFSET", 0);
	info_msg("ELF_EHDR_OFFSET = 0x%X\n", 0);

	_loader->set_sys_var_value("ELF_PHDR_OFFSET", _elftools->_ehdri->e_phoff);
	info_msg("ELF_PHDR_OFFSET = 0x%X\n", _elftools->_ehdri->e_phoff);

	_loader->set_sys_var_value("TARGET_OLD_OFFSET", _offset_encrypt_text);
	info_msg("TARGET_OLD_OFFSET = 0x%X\n", _offset_encrypt_text);

	_loader->set_sys_var_value("TARGET_OLD_SIZE", _size_encrypt_text);
	info_msg("TARGET_OLD_SIZE = 0x%X\n", _size_encrypt_text);

	/* 如果 _opts.keep_code_local 开启则说明是在原本的位置放置加密后的代码。
	 * 此时，不需要修订，否则当前的offset_decrypt_code_tab就是相对于扩展空间的
	 * 偏移
	 */
	if (_opts.keep_code_local == 0) {
		set_te32(&disp, exspace_offset + _offset_encrypted_text);
	} else {
		set_te32(&disp, _offset_encrypted_text);
	}
	_loader->set_sys_var_value("TARGET_NEW_OFFSET", disp);
	info_msg("TARGET_NEW_OFFSET = 0x%X\n", disp);

	_loader->set_sys_var_value("TARGET_NEW_SIZE", _size_encrypted_text);
	info_msg("TARGET_NEW_SIZE = 0x%X\n", _size_encrypted_text);

	if (_opts.encrypt_codes_key_file) {
		_loader->set_sys_var_value("CODE_KEY", 0);
		info_msg("CODE_KEY = 0x%X\n", 0);

		_loader->set_sys_var_value("CODE_KEY_BY_FILE", 1);
		info_msg("CODE_KEY_BY_FILE = 0x%X\n", 1);
	} else {
		_loader->set_sys_var_value("CODE_KEY", _opts.code_key);
		info_msg("CODE_KEY = 0x%X\n", _opts.code_key);

		_loader->set_sys_var_value("CODE_KEY_BY_FILE", 0);
		info_msg("CODE_KEY_BY_FILE = 0x%X\n", 0);
	}
	_loader->set_sys_var_value("SKIP_ENCRYPT_RELOC_STRING", 
							   _opts.skip_string_in_reloc);
	info_msg("SKIP_ENCRYPT_RELOC_STRING = 0x%X\n", _opts.skip_string_in_reloc);
	

	/* 计算加密前的代码CRC32, 加密后代码的CRC32 */
	_loader->set_sys_var_value("CODE_CRC32_SIGN", _code_crc32_sign);
	info_msg("CODE_CRC32_SIGN = 0x%X\n", _code_crc32_sign);

	_loader->set_sys_var_value("CODE_EN_CRC32_SIGN", _code_en_crc32_sign);
	info_msg("CODE_EN_CRC32_SIGN = 0x%X\n", _code_en_crc32_sign);

	/* 写入新的PT_DYNAMIC段偏移 */
	unsigned pt_dynamic_va = 
		(unsigned)(_pack_elftools->_dynseg) - (unsigned)(_pack_elftools->_file);
	set_te32(&disp, pt_dynamic_va); 
	_loader->set_sys_var_value("PT_DYNAMIC_OFFSET", disp);
	info_msg("PT_DYNAMIC_OFFSET = 0x%X\n", disp);

	/* 写入新的PT_DYNAMIC段的长度 */
	unsigned pt_dynamic_size = _pack_elftools->_size_dynseg;
	set_te32(&disp, pt_dynamic_size);
	_loader->set_sys_var_value("PT_DYNAMIC_SIZE", disp);
	info_msg("PT_DYNAMIC_SIZE = 0x%X\n", disp);

	/* 是否加密字符串 */
	if (_opts.encrypt_inside_data_name) {
	    set_te32(&disp, 1);
		_loader->set_sys_var_value("STRTAB_OFFSET", 
								   _encrypt_inside_data_strtab_offset);
		info_msg("STRTAB_OFFSET = 0x%X\n", _encrypt_inside_data_strtab_offset);
	
		_loader->set_sys_var_value("SYMTAB_OFFSET", 
								   _encrypt_inside_data_symtab_offset);
		info_msg("SYMTAB_OFFSET = 0x%X\n", _encrypt_inside_data_symtab_offset);

		_loader->set_sys_var_value("SYMNUM", 
								   _encrypt_inside_data_symnum);
		info_msg("SYMNUM = 0x%X\n", _encrypt_inside_data_symnum);

		_loader->set_sys_var_value("ENCRYPT_INSIDE_DATA_NAME_KEY", 
								   _encrypt_inside_data_key);
		info_msg("ENCRYPT_INSIDE_DATA_NAME_KEY = 0x%X\n", 
				 _encrypt_inside_data_key);
	} else {
	 	set_te32(&disp, 0);
	 	_loader->set_sys_var_value("STRTAB_OFFSET", disp);
		info_msg("STRTAB_OFFSET = 0x%X\n", disp);

	 	_loader->set_sys_var_value("SYMTAB_OFFSET", disp);
		info_msg("SYMTAB_OFFSET = 0x%X\n", disp);

	 	_loader->set_sys_var_value("SYMNUM", disp);
		info_msg("SYMNUM = 0x%X\n", disp);

	 	_loader->set_sys_var_value("ENCRYPT_INSIDE_DATA_NAME_KEY", disp);
		info_msg("ENCRYPT_INSIDE_DATA_NAME_KEY = 0x%X\n", disp);
	}
	_loader->set_sys_var_value("ENCRYPT_INSIDE_DATA_NAME", disp);
	info_msg("ENCRYPT_INSIDE_DATA_NAME = 0x%X\n", disp);

	/* DT_INIT入口相关 */
	if (_opts.use_dt_init_array == 0) {/* 不使用--use-dt-init-array选项 */
		if (_pack_elftools->_dt_init.exist) {
			set_te32(&disp, _pack_elftools->_dt_init.value);
		} else {
			set_te32(&disp, 0);
		}
	} else {
		set_te32(&disp, 0);
	}
	_loader->set_sys_var_value("ORIG_ENTRY", disp);
	info_msg("ORIG_ENTRY = 0x%X\n", disp);

	/* 是否使用重定位加密 */
	set_te32(&disp, _opts.reloc_encrypt_loader);
	_loader->set_sys_var_value("REL_ENCRYPT_LOADER", disp);
	info_msg("REL_ENCRYPT_LOADER = 0x%X\n", disp);
	
	/* 使用重定位加密elf头 */
	set_te32(&disp, _opts.reloc_remove_elf_header);
	_loader->set_sys_var_value("REL_CLEAN_ELF_EHDR", disp);
	info_msg("REL_CLEAN_ELF_EHDR = 0x%X\n", disp);

	/* 使用重定位表加密代码 */
	set_te32(&disp, _opts.reloc_encrypt_codes);
	_loader->set_sys_var_value("REL_ENCRYPT_CODES", disp);
	info_msg("REL_ENCRYPT_CODES = 0x%X\n", disp);

	/* 平台 */
	set_te32(&disp, _opts.arch);
	_loader->set_sys_var_value("ARCH", disp);
	info_msg("ARCH = 0x%X\n", disp);

	/* 目标重定位相关 */
	set_te32(&disp, dis->get_save_target_pltjmp_offset());
	_loader->set_sys_var_value("TARGET_PLTJMP_RELOC_TABLE_OFFSET", disp);
	info_msg("TARGET_PLTJMP_RELOC_TABLE_OFFSET = 0x%X\n", disp);

	set_te32(&disp, dis->get_save_target_pltjmp_size());
	_loader->set_sys_var_value("TARGET_PLTJMP_RELOC_TABLE_SIZE", disp);
	info_msg("TARGET_PLTJMP_RELOC_TABLE_SIZE = 0x%X\n", disp);

	set_te32(&disp, dis->get_save_target_rel_offset());
	_loader->set_sys_var_value("TARGET_REL_RELOC_TABLE_OFFSET", disp);
	info_msg("TARGET_REL_RELOC_TABLE_OFFSET = 0x%X\n", disp);

	set_te32(&disp, dis->get_save_target_rel_size());
	_loader->set_sys_var_value("TARGET_REL_RELOC_TABLE_SIZE", disp);
	info_msg("TARGET_REL_RELOC_TABLE_SIZE = 0x%X\n", disp);

	/* 加密导出函数相关 */
	set_te32(&disp, _opts.encrypt_global_codes);
	_loader->set_sys_var_value("ENCRYPT_ABS_EXPORT_FUNCTION", disp);
	info_msg("ENCRYPT_ABS_EXPORT_FUNCTION = 0x%X\n", disp);

	set_te32(&disp, _abs_export_function_list_va);
	_loader->set_sys_var_value("ABS_EXPORT_FUNCTION_BLOCK_OFFSET", disp);
	info_msg("ABS_EXPORT_FUNCTION_BLOCK_OFFSET = 0x%X\n", disp);

	set_te32(&disp, _abs_export_function_list_size);
	_loader->set_sys_var_value("ABS_EXPORT_FUNCTION_BLOCK_SIZE", disp);
	info_msg("ABS_EXPORT_FUNCTION_BLOCK_SIZE = 0x%X\n", disp);

	set_te32(&disp, _opts.global_code_key);
	_loader->set_sys_var_value("ABS_EXPORT_FUNCTION_KEY", disp);
	info_msg("ABS_EXPORT_FUNCTION_KEY = 0x%X\n", disp);

	set_te32(&disp, _abs_export_function_list_count);
	_loader->set_sys_var_value("ABS_EXPORT_FUNCTION_BLOCK_COUNT", disp);
	info_msg("ABS_EXPORT_FUNCTION_BLOCK_COUNT = 0x%X\n", disp);

	/* 加密指定函数相关 */
	set_te32(&disp, _opts.encrypt_func);
	_loader->set_sys_var_value("ENCRYPT_FUNCTION", disp);
	info_msg("ENCRYPT_FUNCTION = 0x%X\n", disp);

	set_te32(&disp, _en_function_list_va);
	_loader->set_sys_var_value("ENCRYPT_FUNCTION_BLOCK_OFFSET", disp);
	info_msg("ENCRYPT_FUNCTION_BLOCK_OFFSET = 0x%X\n", disp);

	set_te32(&disp, _en_function_list_size);
	_loader->set_sys_var_value("ENCRYPT_FUNCTION_BLOCK_SIZE", disp);
	info_msg("ENCRYPT_FUNCTION_BLOCK_SIZE = 0x%X\n", disp);

	set_te32(&disp, _opts.encrypt_func_key);
	_loader->set_sys_var_value("ENCRYPT_FUNCTION_KEY", disp);
	info_msg("ENCRYPT_FUNCTION_KEY = 0x%X\n", disp);

	set_te32(&disp, _en_function_list_count);
	_loader->set_sys_var_value("ENCRYPT_FUNCTION_BLOCK_COUNT", disp);
	info_msg("ENCRYPT_FUNCTION_BLOCK_COUNT = 0x%X\n", disp);

	/* 支持代码重定位 */
	_loader->set_sys_var_value("HAS_DT_TEXTREL", _has_DT_TEXTREL);
	info_msg("HAS_DT_TEXTREL = 0x%X\n", _has_DT_TEXTREL);

	/* 设置重定位表 */
	_loader->set_sys_var_buf("TEXTREL_OFFSET_TABLE", 
							 (unsigned char*)_textrel_tab, 
							 _size_textrel_tab);
	//info_msg("TEXTREL_OFFSET_TABLE = 0x%X\n", _size_textrel_tab);

	_loader->set_sys_var_value("TEXTREL_OFFSET_TABLE_SIZE", _size_textrel_tab);
	info_msg("TEXTREL_OFFSET_TABLE_SIZE = 0x%X\n", _size_textrel_tab);
	
	set_te32(&disp, exspace_offset + _offset_code_sign);
	_loader->set_sys_var_value("CODE_SIGN_OFFSET", disp);
	info_msg("CODE_SIGN_OFFSET = 0x%X\n", disp);

	set_te32(&disp, _code_sign_size);
	_loader->set_sys_var_value("CODE_SIGN_LENGTH", disp);
	info_msg("CODE_SIGN_LENGTH = 0x%X\n", disp);

	set_te32(&disp, exspace_offset + _offset_code_en_sign);
	_loader->set_sys_var_value("CODE_EN_SIGN_OFFSET", disp);
	info_msg("CODE_EN_SIGN_OFFSET = 0x%X\n", disp);

	set_te32(&disp, _code_en_sign_size);
	_loader->set_sys_var_value("CODE_EN_SIGN_LENGTH", disp);
	info_msg("CODE_EN_SIGN_LENGTH = 0x%X\n", disp);

	set_te32(&disp, exspace_offset + _offset_decode_key);
	_loader->set_sys_var_value("CODE_KEY_OFFSET", disp);
	info_msg("CODE_KEY_OFFSET = 0x%X\n", disp);

	set_te32(&disp, _decode_key_size);
	_loader->set_sys_var_value("CODE_KEY_LENGTH", disp);
	info_msg("CODE_KEY_LENGTH = 0x%X\n", disp);

	set_te32(&disp, _opts.encrypt_codes);
	_loader->set_sys_var_value("ENCRYPT_CODES", disp);
	info_msg("ENCRYPT_CODES = 0x%X\n", disp);

	set_te32(&disp, _opts.cipher_type);
	_loader->set_sys_var_value("CIPHER_TYPE", disp);
	info_msg("CIPHER_TYPE = 0x%X\n", disp);

	set_te32(&disp, _opts.keep_code_local);
	_loader->set_sys_var_value("KEEP_CODE_LOCAL", disp);
	info_msg("KEEP_CODE_LOCAL = 0x%X\n", disp);

	set_te32(&disp, exspace_offset + _offset_encrypt_code_tab);
	_loader->set_sys_var_value("ECT_OFFSET", disp);
	info_msg("ECT_OFFSET = 0x%X\n", disp);

	set_te32(&disp, _encrypt_code_tab_size);
	_loader->set_sys_var_value("ECT_LENGTH", disp);
	info_msg("ECT_LENGTH = 0x%X\n", disp);

	set_te32(&disp, exspace_offset + _offset_decrypt_code_tab);
	_loader->set_sys_var_value("DCT_OFFSET", disp);
	info_msg("DCT_OFFSET = 0x%X\n", disp);

	set_te32(&disp, _decrypt_code_tab_size);
	_loader->set_sys_var_value("DCT_LENGTH", disp);
	info_msg("DCT_LENGTH = 0x%X\n", disp);

	set_te32(&disp, _orig_finit_offset);
	_loader->set_sys_var_value("ORIG_FINIT_OFFSET", disp);
	info_msg("ORIG_FINIT_OFFSET = 0x%X\n", disp);
}
