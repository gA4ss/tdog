#include "dog_common.h"

/* 针对DT_INIT做的专门的处理 */
#ifdef DT_INIT_SPECIAL
bool DogTools::dt_init_special() {
	if ((_pack_elftools->_dt_init.exist == 0) && 
		(_pack_elftools->_dt_symbolic.exist != 0)) {
		/* 直接在DT_SYMBOLIC上进行修订 
		 * 将DT_SYMBOLIC项目修订为DT_INIT
		 * 然后将值变换为LOADER的入口点地址
		 * 因为没有原始入口,所有LOADER的全局变量区域
		 * 依然保持0即可
		 */
		_pack_elftools->_dt_init.inside_offset = 
			_pack_elftools->_dt_symbolic.inside_offset;
		return true;
	}
	return false;
}
#endif

#define __set_hack_data__(dt_, len_, dynamic_, dynamic_idx_) {	\
		(dt_).offset = (len_);									\
		(dt_).va = _elftools->_load_va + (len_);				\
		if ((dynamic_) && ((dynamic_)->support))				\
			(dt_).size = (dynamic_)->support->size;				\
		else													\
			(dt_).size = 0;										\
		(dt_).pt_dynamic_index = (dynamic_idx_);				\
		(dt_).pt_index = 0;										\
		(dt_).dv = (dynamic_);									\
		(dt_).rel = 0;											\
	}
unsigned DogTools::write_hack_data(unsigned curr_offset) {
	unsigned dynamic_idx = _pack_elftools->elf_index_dynamic();
	unsigned curr = 0, len = 0;
	unsigned now_off = curr_offset;
	_hack_data_offset = now_off;

	/* dt_init */
	__set_hack_data__(_hack_data_dt_init, now_off, 
					  &(_pack_elftools->_dt_init), dynamic_idx);
	curr = handle_hack_data_dt_init(&_hack_data_dt_init);
	now_off += curr;

	/* dt_finit */
	__set_hack_data__(_hack_data_dt_finit, now_off, 
					  &(_pack_elftools->_dt_finit), dynamic_idx);
	curr = handle_hack_data_dt_finit(&_hack_data_dt_finit);
	now_off += curr;

	/* dt_init_array */
	__set_hack_data__(_hack_data_dt_init_array, now_off, 
					  &(_pack_elftools->_dt_init_array), dynamic_idx);
	curr = handle_hack_data_dt_init_array(&_hack_data_dt_init_array);
	now_off += curr;

	/* dt_finit_array */
	__set_hack_data__(_hack_data_dt_finit_array, now_off, 
					  &(_pack_elftools->_dt_finit_array), dynamic_idx);
	curr = handle_hack_data_dt_finit_array(&_hack_data_dt_finit_array);
	now_off += curr;

	/* dt_plt_rel */
	__set_hack_data__(_hack_data_dt_plt_rel, now_off,
					  &(_pack_elftools->_dt_jmprel), dynamic_idx);
	curr = handle_hack_data_dt_plt_rel(&_hack_data_dt_plt_rel);
	now_off += curr;

	/* dt_rel */
	__set_hack_data__(_hack_data_dt_rel, now_off, 
					  &(_pack_elftools->_dt_rel), dynamic_idx);
	curr = handle_hack_data_dt_rel(&_hack_data_dt_rel);
	now_off += curr;

	/* dt_symtab */
	__set_hack_data__(_hack_data_dt_symtab, now_off, 
					  &(_pack_elftools->_dt_symtab), dynamic_idx);
	curr = handle_hack_data_dt_symtab(&_hack_data_dt_symtab);
	now_off += curr;

	/* dt_strtab */
	__set_hack_data__(_hack_data_dt_strtab, now_off, 
					  &(_pack_elftools->_dt_strtab), dynamic_idx);
	curr = handle_hack_data_dt_strtab(&_hack_data_dt_strtab);
	now_off += curr;

	/* dt_hash */
	__set_hack_data__(_hack_data_dt_hash, now_off, 
					  &(_pack_elftools->_dt_hash), dynamic_idx);
	curr = handle_hack_data_dt_hash(&_hack_data_dt_hash);
	now_off += curr;

	now_off = up4(now_off);

	len = now_off - _hack_data_offset;
	return len;
}

unsigned DogTools::encrypt_or_write(unsigned char* in, unsigned size, 
									unsigned offset, bool en) {
	XASSERT(in);
	int ret = 0;

	if (en) {
		/* 加密 */
		ret = dog_encrypt_stream(in, _obuf, size,
								 (int*)&(_opts.code_key), sizeof(unsigned));
		if (ret != 0) {
			ERROR_ENCRYPT_FAILED_EXCEPT("stream encrypt failed, err = %x", ret);
		}/* end if */
		writeTarget(NULL,
					(unsigned char*)_obuf, size, TDOG_DEBUG, "X(Data)",
					offset, true, (void*)(&_pack_obuf));
	} else {
		writeTarget(NULL,
					(unsigned char*)in, size, TDOG_DEBUG, "X(Data)",
					offset, true, (void*)(&_pack_obuf));
	}
	size = up4(size);
	return size;
}

unsigned DogTools::handle_hack_data_dt_init(struct hack_data* h) {
	XASSERT(h);
	if (_opts.use_dt_init_array == 1) {
		/* 关闭_use_dt_init */
		_use_dt_init = false;
		return 0;
	}

	if (h->dv->exist) {
		_use_dt_init = true;
	} else {
#ifdef DT_INIT_SPECIAL
		_use_dt_init = dt_init_special();
#endif
	}
	return 0;
}

unsigned DogTools::handle_hack_data_dt_finit(struct hack_data* h) {
	XASSERT(h);
	// if (h->dv->exist) {
		
	// }
	return 0;
}

unsigned DogTools::handle_hack_data_dt_init_array(struct hack_data* h) {
	XASSERT(h);

	if ((_opts.use_dt_init_array == 0) && (_use_dt_init)) {
		/* 如果存在DT_INIT入口点则直接退出
		 * 如果选项指定DT_INIT_ARRAY则忽略_dt_init
		 * 不进行任何处理 */
		_dt_init_array_in_rel_type = 0;
		return 0;
	}

	/* 无论如何关闭dt_init */
	_use_dt_init = false;

	unsigned now_offset = h->offset;
	unsigned v = (unsigned)(_pack_elftools->_dt_init_array.context - 
							_pack_elftools->_file);
	v = _pack_elftools->elf_get_va_from_offset(v);

	if (_pack_elftools->elf_if_rel_object((Elf32_Rel*)(_pack_elftools->_dt_jmprel.context),
										  _pack_elftools->_dt_pltrelsz.size / 8,
										  v)) {
		_dt_init_array_in_rel_type = 1;
	}
	else if (_pack_elftools->elf_if_rel_object((Elf32_Rel*)(_pack_elftools->_dt_rel.context),
											   _pack_elftools->_dt_relsz.size / 8,
											   v)) {
		_dt_init_array_in_rel_type = 2;
	}
	else {
		_dt_init_array_in_rel_type = 1;
	}

	/* 多复制一个4字节用于保存新的入口点 */
	unsigned char* tmp = new unsigned char[_pack_elftools->_dt_init_arraysz.size + 0x10];
	if (tmp == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new unsigned char");
	}

	/* 增加dt_init_array项的第一个为加载器 */
	memcpy(tmp,
		   (unsigned char*)&_loader_entry_va,
		   sizeof(unsigned));
	
	/* 复制原先的 */
	memcpy(tmp + sizeof(unsigned),
		   _pack_elftools->_dt_init_array.context,
		   _pack_elftools->_dt_init_arraysz.size);


	unsigned len = encrypt_or_write(tmp, 
									_pack_elftools->_dt_init_arraysz.size + 4,
									now_offset,
									false);
	if (len != _pack_elftools->_dt_init_arraysz.size + 4) {
		unsigned arraysz = _pack_elftools->_dt_init_arraysz.size + 4;
		ERROR_ENCRYPT_FAILED_EXCEPT("size of after encrypt = %d(0x%X) != %d(0x%X)\n",
									len, len, arraysz, arraysz);
	}
	
	delete [] tmp;
	return len;
}

unsigned DogTools::handle_hack_data_dt_finit_array(struct hack_data* h) {
	UNUSED(h);
	// unsigned len = offset;
	// len += encrypt_or_write(_elftools->_dt_finit_array.context, 
	// 						_elftools->_dt_finit_arraysz.value,
	// 						false);
	// len = fpad4(_fo);
	// return len;
	return 0;
}

void DogTools::fix_dt_init_array_for_new_rel(hack_data* h, unsigned char* c) {
	XASSERT(h);
	XASSERT(c);

	/* 因为原始的dt_init_array发生的位置上的变化,所以遍历整个重定位表
	 * 修订每个原始的项的位置信息
	 *
	 * 又因为这些数据是在第一个加载段，所以文件偏移与内存偏移一致。因为BASE为0
	 */
	Elf32_Rel* modify_r = (Elf32_Rel*)c;
	unsigned fix_offset = _hack_data_dt_init_array.offset + sizeof(unsigned);  /* 第一个位置是加载器的位置 */
	unsigned init_array_list = _pack_elftools->_dt_init_array.value;
	unsigned init_array_list_count = _pack_elftools->_dt_init_arraysz.size / sizeof(unsigned);
	for (unsigned list_idx = 0; list_idx < init_array_list_count;
		 init_array_list+=sizeof(unsigned),
			 list_idx++,
			 fix_offset+=sizeof(unsigned),
			 modify_r++) {
		unsigned va = init_array_list;
		/* 获取重定表 */
		Elf32_Rel* r = (Elf32_Rel*)(h->dv->context);
		unsigned count = h->size / 8;
		for (unsigned idx = 0; idx < count; ++idx, ++r) {
			unsigned reloc = (unsigned)(r->r_offset);
			if (reloc == va) {
				modify_r->r_offset = fix_offset;				/* 修订 */
			}	
		}/* end for */
	}/* end for */
}

unsigned DogTools::handle_rel_table(hack_data* h) {
	XASSERT(h);
	
	unsigned now_offset = h->offset;
	unsigned size = h->size + sizeof(Elf32_Rel);
	unsigned char* tmp = new unsigned char [size];
	if (tmp == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new unsigned char");
	}
	memcpy(tmp, h->dv->context, h->size);   /* 复制原始重定位表 */
	fix_dt_init_array_for_new_rel(h, tmp);

	/* 添加一个新的位置，以便存放新的入口点 */
	Elf32_Rel t;
	unsigned rv = R_ARM_RELATIVE;
	if (_opts.arch == ARCH_X86) {
		rv = R_386_RELATIVE;
	} else if (_opts.arch == ARCH_MIPS) {
		rv = R_ARM_RELATIVE;
	} else {
		rv = R_ARM_RELATIVE;
	}
	t.r_info = ELF32_R_INFO(0, rv); /* 符号位为0表示无符号 */
	/* 由于都是在第一个段,文件偏移 与 段偏移 可以互换 
	 * 因为基地址为0
	 */
	t.r_offset = _hack_data_dt_init_array.offset;
	memcpy(tmp + h->size,
		   &t,
		   sizeof(t));

	unsigned len = encrypt_or_write(tmp, 
									size,
									now_offset,
									false);
	if (len != size) {
		ERROR_ENCRYPT_FAILED_EXCEPT("size of after encrypt = %d(0x%X) != %d(0x%X)\n",
									len, len, size, size);
	}

	delete [] tmp;
	return len;
}

unsigned DogTools::handle_hack_data_dt_plt_rel(struct hack_data* h) {
	XASSERT(h);
	//unsigned len = h->offset;
	if (_dt_init_array_in_rel_type == 1) {
		return handle_rel_table(h);
	}
	return 0;
}

unsigned DogTools::handle_hack_data_dt_rel(struct hack_data* h) {
	XASSERT(h);
	//unsigned len = h->offset;

	if (_dt_init_array_in_rel_type == 2) {
		return handle_rel_table(h);
	}
	return 0;
}

unsigned DogTools::handle_hack_data_dt_symtab(struct hack_data* h) {
	UNUSED(h);
	// unsigned len = offset;
	// len += encrypt_or_write(_elftools->_dt_symtab.context, 
	// 						_elftools->_dt_syment.value,
	// 						false);
	// len = fpad4(_fo);
	// return len;
	return 0;
}

unsigned DogTools::handle_hack_data_dt_strtab(struct hack_data* h) {
	UNUSED(h);
	// unsigned len = offset;
	// len += encrypt_or_write(_elftools->_dt_strtab.context, 
	// 						_elftools->_dt_strtabsz.,
	// 						false);
	// len = fpad4(_fo);
	// return len;
	return 0;
}

unsigned DogTools::handle_hack_data_dt_hash(struct hack_data* h) {
	UNUSED(h);
	// unsigned len = offset;
	// len += encrypt_or_write(_elftools->_dt_hash.context, 
	// 						_elftools->_dt_strtabsz.value,
	// 						false);
	// len = fpad4(_fo);
	// return len;
	return 0;
}
