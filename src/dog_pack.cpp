#include "dog_common.h"
#include "crc.h"

#include <vector>
#include <algorithm>
using namespace std;

// void DogTools::fix_soname_stridx(unsigned char* ptr) {
// 	XASSERT(ptr);
// 	Elf32_Ehdr *ehdr = (Elf32_Ehdr*)ptr;	

// 	unsigned phdr_count = get_te32(&(ehdr->e_phnum));
// 	unsigned phdr_offset = get_te32(&(ehdr->e_phoff));

// 	Elf32_Phdr *dyn_phdr = (Elf32_Phdr*)(ptr + phdr_offset);
// 	for (unsigned i = 0; i < phdr_count; i++, dyn_phdr++) {
// 		unsigned const type = get_te32(&dyn_phdr->p_type);
// 		/* PT_DYNAMIC */
// 		if (PT_DYNAMIC == type) {
// 			break;
// 		}/* PT_DYNAMIC */
// 	}/* end for */

// 	Elf32_Dyn* d = (Elf32_Dyn*)(ptr + dyn_phdr->p_offset);
// 	while (d->d_tag) {
// 		if (d->d_tag == DT_SONAME) {
// 			break;
// 		}
// 		d++;
// 	}

// 	if (d->d_tag == DT_NULL) return;/* 有些so没有这个字段 */

// 	/* android6.0+ 必有
// 	 * 在新的映射中查找soname
// 	 */
// 	Elf32_Sym* sym = _pack_elftools->elf_lookup(_opts.libname);
// 	if (sym == NULL) {
// 		ERROR_INTERNAL_EXCEPT("can not found libname");
// 		return;
// 	}

// 	/* 修正 */
// 	d->d_un.d_val = sym->st_name;
// }


void DogTools::fix_ElfHeader(unsigned char* ptr, unsigned x) {
	XASSERT(ptr);
	
	Elf32_Ehdr* ehdr = (Elf32_Ehdr*)ptr;
	
	/* 修订节相关 
	 * 2016.4.11 devilogic添加
	 * 这里与write_sections里相关联
	 * x之后即是新的节头，参见write_sections的内容
	 */
	set_te32(&ehdr->e_shoff, x);
	set_te16(&ehdr->e_shnum, 4);
	set_te16(&ehdr->e_shentsize, sizeof(Elf32_Shdr));
	set_te16(&ehdr->e_shstrndx, 3);

	/* 修订段相关 */
	unsigned phoff = get_te32(&ehdr->e_phoff);
	unsigned phnum = get_te16(&ehdr->e_phnum);
	Elf32_Phdr* phdr = (Elf32_Phdr*)(ptr + phoff);

	int j = phnum;
	for (; --j >= 0; ++phdr) {
		
		if (PT_LOAD == get_te32(&phdr->p_type)) {
			set_te32(&phdr->p_filesz, x);

			/* 进行页对齐后设置 */
			x = upx(x);
			set_te32(&phdr->p_memsz, x);
		} else if (PT_DYNAMIC == get_te32(&phdr->p_type)) {
			if (_opts.fake_pt_dynamic_offset) {
				if (phdr->p_offset > 0x1000)
					phdr->p_offset -= 0x1000;
			}
		}/* end else if  */
	}/* end for */
}

static int textrel_compare(const void *_d1, const void *_d2) {
	unsigned d1 = 0, d2 = 0;

	d1 = *(unsigned *)_d1;
	d2 = *(unsigned *)_d2;

	if (d1 == d2) return 0;
	else if (d1 > d2) return 1;
	else return -1;

	return -1;
}

void DogTools::fill_textrel_tab(unsigned** buf, unsigned* size,
								unsigned start, unsigned range) {

	struct dynamic_value* textrel_v = &(_elftools->_dt_textrel);
	if (textrel_v->exist == 0) {
		if (size) *size = 0;
		return;
	}

	/****************************************/

	struct dynamic_value* pltrel_v = &(_elftools->_dt_jmprel);
	if (pltrel_v->exist == 0) {
		return;
	}

	struct dynamic_value* pltrel_size_v = &(_elftools->_dt_pltrelsz);
	if (pltrel_size_v->exist == 0) {
		return;
	}

	Elf32_Rel* pltrel = (Elf32_Rel*)(pltrel_v->context);
	unsigned pltrel_count = pltrel_size_v->size / sizeof(Elf32_Rel);
	info_msg("pltrel table count = %d\n", pltrel_count);

	/****************************************/

	struct dynamic_value* rel_v = &(_elftools->_dt_rel);
	if (rel_v->exist == 0) {
		return;
	}

	struct dynamic_value* rel_size_v = &(_elftools->_dt_relsz);
	if (rel_size_v->exist == 0) {
		return;
	}
	
	Elf32_Rel* rel = (Elf32_Rel*)(rel_v->context);
    unsigned rel_count = rel_size_v->size / sizeof(Elf32_Rel);
	info_msg("rel table count = %d\n", rel_count);

	/****************************************/
	unsigned count = rel_count + pltrel_count;
	
	/* 分配内存 */
	unsigned bufsize = count * sizeof(unsigned);
	*buf = new unsigned [bufsize];
	if (*buf == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new []");
		return;
	}
	memset(*buf, 0, bufsize);

	/* 写入 */
	unsigned* p = *buf;
	unsigned textcount = 0;
	Elf32_Rel* curr = NULL;

	curr = rel;
	while (rel_count--) {
		/* 判断范围 */
		if ((curr->r_offset >= start) && 
			(curr->r_offset < (start + range))) {
			*p++ = curr->r_offset;
			textcount++;
		}
		curr++;
	}

	curr = pltrel;
	while (pltrel_count--) {
		/* 判断范围 */
		if ((curr->r_offset >= start) && 
			(curr->r_offset < (start + range))) {
			*p++ = curr->r_offset;
			textcount++;
		}
		curr++;
	}

	/* 这里进行数组的排序，从小到大 */
	qsort(*buf, textcount, sizeof(unsigned), textrel_compare);

	/* 代码计数 */
	if (size) *size = (textcount * sizeof(unsigned));

	return;
}

void DogTools::auto_fill_textrel_tab() {
	unsigned start = 0, range = 0;
	unsigned k = 0, nx = 0;
	/* 这里仅加密第一个段 */
	for (k = 0; k < _elftools->_phnum; ++k) {
		if (PT_LOAD == get_te32(&_elftools->_phdri[k].p_type)) {
			start = get_te32(&_elftools->_phdri[k].p_vaddr);
			range = get_te32(&_elftools->_phdri[k].p_filesz);
			if (0 == nx) { /* 第一个可加载段必须在0偏移处 */
				break;
			}
			++nx;
		}/* end if */
	}/* end for */

	/* 填充表 */
	fill_textrel_tab(&_textrel_tab, &_size_textrel_tab,
					 start, range);
}

typedef struct _exclude_address {
	unsigned va;
	unsigned size;
} exclude_address;

static bool exclude_list_sort(const exclude_address &T1, 
							  const exclude_address &T2) {
	return T1.va < T2.va; /* 升序 */
}

static bool exclude_list_found(vector<exclude_address> &excludes,
							   unsigned va) {
	vector<exclude_address>::iterator iter = excludes.begin();
	if (excludes.size() == 0) return false;

	for(; iter != excludes.end(); iter++) {
		if (va == (*iter).va) {
			return true;
		}
	}
	return false;
}

Extent *DogTools::fill_plaintext(unsigned char **buf, unsigned *size,
								 unsigned char **encrypt_code_tab,
								 unsigned *encrypt_code_tab_size) {
	unsigned *textrel_tab = NULL;
	unsigned textrel_count = 0;
    static Extent y;

	unsigned k = 0;
	exclude_address ex;

	/* 一些需要排除的地址,遍历节表 */
	vector<exclude_address> excludes;

	XASSERT(buf);
	XASSERT(size);
	XASSERT(encrypt_code_tab);
	XASSERT(encrypt_code_tab_size);

	/* 仅针对于第一个可加载段的重定位信息 */
	textrel_tab = (unsigned*)_textrel_tab;
	textrel_count = _size_textrel_tab / sizeof(unsigned);

	/* 将重定位表的信息加入到排除表中 */
	if (textrel_tab != NULL) {
		ex.size = sizeof(unsigned);
		unsigned textrel_v = 0;
		for (k = 0; k < textrel_count; ++k) {
			textrel_v = textrel_tab[k];
			/* 如果已经在表中则更新长度则不重复添加 */
			if (exclude_list_found(excludes, textrel_v) == false) {
				info_msg("excludes table push<0x%4X>\n", textrel_v);
				ex.va = textrel_v;
				excludes.push_back(ex);
			}
		}/* end for */
	}

	/* 这里仅加密第一个段 */
	unsigned start = 0, range = 0;
	unsigned nx = 0;
	unsigned type = 0;
	for (k = 0; k < _elftools->_phnum; ++k) {
		type = get_te32(&_elftools->_phdri[k].p_type);
		/* 第一个段是最终要的 */
		if (PT_LOAD == type) {
			if (0 == nx) { /* 第一个可加载段必须在0偏移处 */
				start = get_te32(&_elftools->_phdri[k].p_vaddr);
				/* 不支持第一个段的开始地址不为0的so */
				if (start != 0) {
					ERROR_INTERNAL_EXCEPT("not suport this type so\n");
					return NULL;
				}
				range = get_te32(&_elftools->_phdri[k].p_filesz);
				if (range == 0) {
					ERROR_INTERNAL_EXCEPT("not suport this type so\n");
					return NULL;
				}
				++nx;
				info_msg("1th PT_LOAD segment = 0x%4X:%0X\n", start, range);
			}
		} else if (PT_ARM_EXIDX == type) {
			ex.va = get_te32(&_elftools->_phdri[k].p_vaddr);
			ex.size = get_te32(&_elftools->_phdri[k].p_filesz);
			/* 如果值已经存在，则更新长度为更大的那个 */
			if (exclude_list_found(excludes, ex.va) == false) {
				excludes.push_back(ex);
				info_msg("excludes table push<0x%4X>\n", ex.va);
			}
		}
	}/* end for */

	/* 对排除表进行升序排序 */
	sort(excludes.begin(), excludes.end(), exclude_list_sort);

	/* 再一次限定保护的范围 */
	if (_opts.just_protect_code) { 	/* 仅加密代码节 */
		Elf32_Shdr* stext = _elftools->get_text();
		start = stext->sh_addr;
		range = stext->sh_size;
		info_msg("just protect code segment\n");
	} else {
		/* 再次决定要加密的范围 */
		unsigned delta = _elftools->get_yct();
		start += delta;
		range -= delta;
		info_msg("delta(mix execute section offset) = 0x%4X\n", delta);
	}
	y.offset = _plaintext_offset = start;
	y.size = range;

	/* 遍历这个代码段，如果在重定位指定的位置则不记录 */
	*buf = new unsigned char [range];
	if (*buf == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new unsigned char");
		return NULL;
	}
	memset(*buf, 0, range);
	if (size) *size = range;
	
	unsigned encrypt_code_tab_count = excludes.size();

	/* 这里判断是否为空 */
	if (encrypt_code_tab_count == 0) {
		unsigned char *tmp = (unsigned char*)_pack_obuf + start;
		memcpy(*buf, tmp, range);
		if (size) *size = range;

		*encrypt_code_tab_size = sizeof(unsigned) * 2;

		*encrypt_code_tab = new unsigned char [*encrypt_code_tab_size];
		if (*encrypt_code_tab == NULL) {
			ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new unsigned char\n");
			return NULL;
		}
		memset(*encrypt_code_tab, 0, *encrypt_code_tab_size);

		/* 构造加密代码表 */
		unsigned tmp2 = start;
		memcpy(*encrypt_code_tab, (unsigned char*)&tmp2, 
			   sizeof(unsigned));

		memcpy((*encrypt_code_tab) + sizeof(unsigned), 
			   (unsigned char*)&range,
			   sizeof(unsigned));
		
		info_msg("encrypt code table count == 0\n");
		return &y;
	}

	/* 分配加密代码区域描述表 */
	unsigned encrypt_code_tab_alloc_size = (encrypt_code_tab_count + 1) * 
		sizeof(unsigned) * 2;/* 乘以2的原因是要记录偏移与长度 */

	*encrypt_code_tab = new unsigned char [encrypt_code_tab_alloc_size];
	if (*encrypt_code_tab == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new unsigned char\n");
		return NULL;
	}
	memset(*encrypt_code_tab, 0, encrypt_code_tab_alloc_size);

	/* 开始统计可以加密的明文 */
	unsigned offset = 0, len = 0, skip = 0;
	unsigned char *from = (unsigned char*)_pack_obuf + start;
	unsigned char *to = *buf;
	unsigned char *ect = *encrypt_code_tab;
	vector<exclude_address>::iterator iter = excludes.begin();

	/* 遍历 */
	unsigned code_block_count = 0;
	unsigned last_iter_size = 0;
	unsigned ect_iter = 0;
	for(; iter != excludes.end(); iter++) {
		/* 这里出现的错误就是,va比start要小 
		 * 按照道理来说，这是不太可能的，但是很难说
		 * 所以这里只要是比start小的重定位项直接忽略
		 * 还要注意的是忽略的偏移不能比目标要大，大也直接忽略
		 */
		last_iter_size = (*iter).size;

		if ((*iter).va < start) {
			continue;
		}

		/* 这里是因为排除表中的数据是升序排列 */
		if ((*iter).va > (start + range)) {
			break;
		}

		/* 在这个范围内的所有都不加密 */
		if (((*iter).va + (*iter).size) > (start + range)) {
			break;
		}

		/* (*iter).va是相对于基地址来计算的 */
		offset = (*iter).va - start;
		len = offset - skip; /* 这里得到长度是与_update标签中的相互匹配的 */
		if (len == 0) {
			goto _update;
		}

		/* 复制数据 */
		info_msg("<plaintext:%d>offset = 0x%4X, size = 0x%4X, skip = 0x%4X\n", 
				 code_block_count, offset, len, skip);
		memcpy(to, from, len);
		
		/* 如果没有开启保护则不清除明文 */
		if (_opts.encrypt_codes) {
			memset(from , 0, len);
		}
		code_block_count++;

		/* 记录 */
		ect_iter = (unsigned)(from - 
							  (unsigned char*)_pack_obuf);
		*(unsigned*)ect = ect_iter;
		*(unsigned*)(ect + sizeof(unsigned)) = len;
		ect += (sizeof(unsigned) * 2);
		info_msg("ect iter = 0x%4X\n", ect_iter);

		/* 更新 */
	_update:
		skip = offset + (*iter).size;
		from = (unsigned char*)_pack_obuf + start + skip;
		to = *buf + skip;
	}/* end for */

	/* 这里是为了复制最后末尾的那段数据 */
	if (offset + last_iter_size < range) {
		len = range - offset - last_iter_size;
		offset += last_iter_size;

		/* 复制末尾数据 */
		info_msg("<plaintext:%d>offset = 0x%4X, size = 0x%4X, skip = 0x4X\n", 
				 code_block_count, offset, len, skip);
		memcpy(to, from, len);
		/* 如果没有开启保护则不清除明文 */
		if (_opts.encrypt_codes) {
			memset(from , 0, len);
		}
		code_block_count++;
		/* 记录 */
		ect_iter = (unsigned)(from - 
							  (unsigned char*)_pack_obuf);
		*(unsigned*)ect = (unsigned)ect_iter;
		*(unsigned*)(ect + sizeof(unsigned)) = len;
		ect += (sizeof(unsigned) * 2);
		info_msg("ect iter = 0x%4X\n", ect_iter);
	}/* end if */

	/* 重新计算空间 */
	if (encrypt_code_tab_size) *encrypt_code_tab_size = 
								   code_block_count * (sizeof(unsigned) * 2);

	excludes.clear();
	return &y;
}

unsigned* DogTools::get_textrel_offset_tab() {
	return _textrel_tab;
}
unsigned DogTools::get_textrel_tab_size() {
	return _size_textrel_tab;
}

bool DogTools::is_compile_with_pic() {
	return _has_DT_TEXTREL;
}

/* devilogic 2016.4.11 添加为了支持android7 
 * 新附加的节表结构
 * 0 - 0头
 * 1 - 动态段表
 * 2 - 动态字符串表
 * 3 - 节名称表
 * 节名称表
 */
static const char s_shstrtab[] = 
	"\0.dynamic\0.dynstr\0.shstrtab\0\0";
void DogTools::write_sections(unsigned char* ptr) {
	XASSERT(ptr);
	Elf32_Ehdr *ehdr = (Elf32_Ehdr*)ptr;

	Elf32_Shdr shdrs[4];
	memset(&shdrs, 0, sizeof(Elf32_Shdr) * 4);

	unsigned phdr_count = get_te32(&(ehdr->e_phnum));
	unsigned phdr_offset = get_te32(&(ehdr->e_phoff));

	Elf32_Phdr *dyn_phdr = (Elf32_Phdr*)(ptr + phdr_offset);
	for (unsigned i = 0; i < phdr_count; i++, dyn_phdr++) {
		unsigned const type = get_te32(&dyn_phdr->p_type);
		/* PT_DYNAMIC */
		if (PT_DYNAMIC == type) {
			break;
		}/* PT_DYNAMIC */
	}/* end for */

	/* 新的动态表 */
	set_te32(&(shdrs[1].sh_name), 1);
	set_te32(&(shdrs[1].sh_type), SHT_DYNAMIC);
	set_te32(&(shdrs[1].sh_flags), SHF_ALLOC | SHF_WRITE);
	set_te32(&(shdrs[1].sh_addr), dyn_phdr->p_vaddr);
	set_te32(&(shdrs[1].sh_offset), dyn_phdr->p_offset);
	set_te32(&(shdrs[1].sh_size), dyn_phdr->p_filesz);
	set_te32(&(shdrs[1].sh_link), 2);
	set_te32(&(shdrs[1].sh_info), 0);
	set_te32(&(shdrs[1].sh_addralign), 4);
	set_te32(&(shdrs[1].sh_entsize), sizeof(Elf32_Dyn));

	Elf32_Dyn *dyn = (Elf32_Dyn*)(ptr + dyn_phdr->p_offset);
	Elf32_Dyn *str_dyn = NULL, *strsz_dyn = NULL;
	while (dyn->d_tag) {
		if (dyn->d_tag == DT_STRTAB) {
			str_dyn = dyn;
		} else if (dyn->d_tag == DT_STRSZ) {
			strsz_dyn = dyn;
		}
		dyn++;
	}

	/* 动态表的字符串表 */
	set_te32(&(shdrs[2].sh_name), 10);
	set_te32(&(shdrs[2].sh_type), SHT_STRTAB);
	set_te32(&(shdrs[2].sh_flags), SHF_ALLOC);
	set_te32(&(shdrs[2].sh_addr), str_dyn->d_un.d_ptr);
	set_te32(&(shdrs[2].sh_offset), str_dyn->d_un.d_ptr);
	set_te32(&(shdrs[2].sh_size), strsz_dyn->d_un.d_val);
	set_te32(&(shdrs[2].sh_link), 0);
	set_te32(&(shdrs[2].sh_info), 0);
	set_te32(&(shdrs[2].sh_addralign), 1);
	set_te32(&(shdrs[2].sh_entsize), 0);

	/* 节表名称表 */
	set_te32(&(shdrs[3].sh_name), 18);
	set_te32(&(shdrs[3].sh_type), SHT_STRTAB);
	set_te32(&(shdrs[3].sh_flags), 0);
	set_te32(&(shdrs[3].sh_addr), 0);
	unsigned shdrs_offset = _pack_obuf_offset + sizeof(Elf32_Shdr) * 4;
	set_te32(&(shdrs[3].sh_offset), shdrs_offset);
	set_te32(&(shdrs[3].sh_size), sizeof(s_shstrtab));
	set_te32(&(shdrs[3].sh_link), 0);
	set_te32(&(shdrs[3].sh_info), 0);
	set_te32(&(shdrs[3].sh_addralign), 1);
	set_te32(&(shdrs[3].sh_entsize), 0);

	/* 写入节表，与fix_ElfHeader相关 */
	writeTarget(_fo, (void*)&shdrs, sizeof(Elf32_Shdr) * 4,
							TDOG_DEBUG, "New sections", _pack_obuf_offset,
							false);
	_pack_obuf_offset += sizeof(Elf32_Shdr) * 4;	/* 更新偏移 */

	/* 写入节名字符串表 */
	writeTarget(_fo, (void*)s_shstrtab, sizeof(s_shstrtab), 
							TDOG_DEBUG, "New section names", _pack_obuf_offset,
							false);
	_pack_obuf_offset += up4(sizeof(s_shstrtab));	/* 更新偏移 */
}

void DogTools::write_header() {
	/* 写入头 */
	_dog_header.version = TDOG_VERSION_NUM;
	_dog_header.method = _method;
	_dog_header.magic = TDOG_MAGIC_LE32;
	writeTarget(_fo, (void*)&_dog_header, sizeof(_dog_header), 
							TDOG_DEBUG, "packer header", _pack_obuf_offset,
							false);
}

bool DogTools::can_pack() {
	InputFile* fi = _elftools->_fi;
	UNUSED(fi);
	unsigned file_size = _elftools->_size_file_buffer;

	// if (_elftools->find_entry_symbols_in_so() == false) {
	// 	if (_elftools->get_android_jni_onload() == 1) {
	// 		//fprintf(stderr, "[warring] can not found entry symbol\r\n");
	// 		//throwCantPack("JNI_ONLOAD symbol found; re-compile it");
	// 	}
	// }

	// if (_elftools->is_has_DT_INIT() == false) {
	// 	//throwCantPack("DT_INIT not found; re-compile with -init=xxx");
	// 	//fprintf(stderr, "[warring] can not found DT_INIT symbol\r\n");
	// }
	/* 如果不存在-fPIC的选项,这个就比较麻烦了 */
	if (_elftools->is_compile_with_pic() == false) {
		/* 当前文件存在对代码进行重定位 */
		info_msg("the target compile without -fPIC\n");
		_has_DT_TEXTREL = true;
		//ERROR_CAN_NOT_PROTECT_EXCEPT("DT_TEXTREL found; re-compile with -fPIC");
		//return false;
	}

	// if (_elftools->is_has_DT_INIT_ARRAY() == false) {
	// 	//throwCantPack("DT_INIT_ARRAY not found; re-compile");
	// }

	/* test file size */
    if (file_size < 4096) {
        ERROR_CAN_NOT_PROTECT_EXCEPT("file is too small");
		return false;
	}

	return true;
}

void DogTools::pack() {
	_ibuf.clear();
	_obuf.clear();	

	/* 进行合并 */
	unsigned tmps = 0;
	unsigned char* tmp = merge_mem(&tmps);
	_merge_ibuf.alloc(tmps);
	memcpy((unsigned char*)_merge_ibuf, tmp, tmps);
	if (tmp) delete [] tmp; tmp = NULL;

	/* 进行合并后的分析 */
	_merge_elftools = new ElfDynamicTools;
	if (_merge_elftools == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new ElfDynamicTools");
	}
	_merge_elftools->set_machine(_opts.arch);
	_merge_elftools->init_merge((unsigned char*)_merge_ibuf, 
															_merge_ibuf.getSize());
	/* 分配输出空间 */
	unsigned cache_size = _opts.cache_size;

	/* 进行页对齐 */
	unsigned pack_size = upx(cache_size);
	_pack_obuf.alloc(_merge_ibuf.getSize() + pack_size);

	/* 写入原先的内存 */
	writeTarget(NULL, 
							(unsigned char*)_merge_ibuf,
							_merge_ibuf.getSize(), 
							TDOG_DEBUG, 
							"Orig File", 
							0xFFFFFFFF, true,
							(void*)(&_pack_obuf));
	_pack_obuf_offset = _merge_ibuf.getSize();

	/* 初始化壳ELF工具 */
	_pack_elftools = new ElfDynamicTools;
	if (_pack_elftools == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new ElfDynamicTools");
	}
	_pack_elftools->set_machine(_opts.arch);
	_pack_elftools->init_merge_ptr((unsigned char*)_pack_obuf, 
																 _pack_obuf.getSize());

	/* 生成加载器 */
	if (_opts.import_loader) {
		_loader = new Dis;
	}

	if (_loader == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new Loader");
		return;
	}

	/* 设置原始elftools */
	_pack_elftools->set_orig_elf_tools(_elftools);
	_loader->set_options(&_opts);
	if (_loader->init(_pack_elftools)) {
		ERROR_INTERNAL_EXCEPT("loader init failed");
		return;
	}

	/* 填充text rel表 */
	//if (_has_DT_TEXTREL) {
	auto_fill_textrel_tab();
	//}

	/* 记录原始dt_dynamic的信息 */
	fill_orig_dynamic_info();

	/* 开启加壳 */
	set_input_file_seek(0, SEEK_SET);
	pack0();
	pack1();
	pack2();
	pack3();

	if (_merge_elftools) delete _merge_elftools; _merge_elftools = NULL;
	if (_pack_elftools) delete _pack_elftools; _pack_elftools = NULL;
}

/* 在加密整体代码段之前，针对代码段做修改 */
void DogTools::pack0() {
	/* 加密所有导出函数 */
	if (_opts.encrypt_global_codes) {
		/* 加密导出函数 */
		if (encrypt_functions(&_abs_export_function_list,
							  &_abs_export_function_list_size,
							  &_abs_export_function_list_count,
							  _opts.include_exp_fun,
							  _opts.is_ef_name,
							  _opts.ef_name,
							  _opts.libname, 
							  _opts.include_enfunc_filepath,
							  _opts.global_code_key,
							  is_encrypt_export_function,
							  "./Gfunc.txt")) {
			ERROR_INTERNAL_EXCEPT("encrypt export function failed");
			return;
		}
	}

	/* 加密所有指定函数 */
	if (_opts.encrypt_func) {
		if (encrypt_functions(&_en_function_list,
							  &_en_function_list_size,
							  &_en_function_list_count,
							  1,
							  _opts.is_en_func_file,
							  _opts.en_func_name,
							  _opts.libname,
							  NULL,
							  _opts.encrypt_func_key,
							  is_encrypt_include_function,
							  "./Ffunc.txt")) {
			ERROR_INTERNAL_EXCEPT("encrypt specify function failed");
			return;
		}		
	}
}

/* 这里是加密.plt到段末尾
 * 但是这里有时会存在ARM.extab
 * ARM.exidx, .rodata
 * 前两者在linker加载时会使用到
 * 但是此时并没有进行解密,是否会
 * 存在错误,总是崩溃这里我修改为
 * 仅加密"代码节"
 */
void DogTools::pack1() {
	Extent x;
	Extent *y = NULL;
	unsigned k;
	int nx = 0, ret = 0;

	/* 这里仅加密第一个段 */
	for (k = 0; k < _elftools->_phnum; ++k) {
		if (PT_LOAD == get_te32(&_pack_elftools->_phdri[k].p_type)) {
			x.offset = get_te32(&_pack_elftools->_phdri[k].p_vaddr);
			x.size = get_te32(&_elftools->_phdri[k].p_filesz);
			if (0 == nx) { /* 第一个可加载段必须在0偏移处 */
				break;
			}
			++nx;
		}/* end if */
	}/* end for */
	
	// /* 仅加密代码节 */
	// if (_opts.just_protect_code) {
	// 	Elf32_Shdr* stext = _elftools->get_text();
	// 	x.offset = stext->sh_offset;
	// 	x.size = stext->sh_size;
	// 	info_msg("just protect code segment\n");
	// } else {
	// 	/* 跳过符号表,字符串表,'.plt'节等数据 */
	// 	unsigned delta = _elftools->_xct_off;
	// 	x.offset += delta;
	// 	x.size -= delta;
	// 	info_msg("delta = 0x%4X\n", delta);
	// }

	/* 填充明文 */
	y = fill_plaintext(&_plaintext, &_plaintext_size,
					   &_encrypt_code_tab, &_encrypt_code_tab_size);
	if (y == NULL) {
		ERROR_INTERNAL_EXCEPT("fill plaintext error\n");
		return;
	}
	x.offset = y->offset;
	x.size = y->size; /* 要加密代码明文大小 */

	/* 开始加密代码 */
	if (_opts.encrypt_codes) {
		encrypt_code(x);
	} else {
		/* 计算当前代码明文的hash值 */
		unsigned char *ptr = _plaintext;
		_size_encrypt_text = _plaintext_size;

		if (_dog_hash) {
			_code_sign_size = MAX_SIGN_LENGTH;
			ret = _dog_hash(ptr, _size_encrypt_text,
							_code_sign, (int*)&_code_sign_size);
			if (ret != 0) {
				ERROR_HASH_FAILED_EXCEPT("errcode = %x", ret);
				return;
			}/* end if */
		} else {
			unsigned crc32_v = 0;
			crc32_v = crc32(ptr, _size_encrypt_text);
			memcpy(_code_sign, &crc32_v, sizeof(unsigned));
			_code_sign_size = sizeof(unsigned);
		}

		/* 计算当前代码的crc值 */
		info_msg("size of total of encrypt data on memory = %d(0x%X)\n", 
				 _size_encrypt_text, _size_encrypt_text);
		_size_encrypted_text = _size_encrypt_text;

		/* 计算CRC32 */
		_code_crc32_sign = crc32(ptr, _size_encrypted_text);
		info_msg("hash of code is 0x%4X\n", _code_crc32_sign);
		_code_en_crc32_sign = _code_crc32_sign;

		/* 扩展空间中，仅存在明文的哈希值 */
		_exspace_size = 0;
		_offset_code_sign = _exspace_size;
		_exspace_size += _code_sign_size;
		_exspace_size = upx(_exspace_size);

		/* 填充扩展空间 */
		_exspace = new unsigned char [_exspace_size];
		if (_exspace == NULL) {
			ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new unsigned char []");
			return;
		}

		unsigned char *curr = _exspace;
		/* 写入明文HASH值 */
		memcpy(curr, _code_sign, _code_sign_size);
		curr += _code_sign_size;
	}/* end else */
}

void DogTools::pack2() {
	/* 写入加载器 */
	write_loader();

	/* 修订入口点 */
	fix_entry();

	/* 修订退出点 */
	fix_exit();
}

/* 写入加载器以及其全局变量区域遍历 */
void DogTools::pack3() {
	unsigned char* ptr = (unsigned char*)_pack_obuf;

	/* 修订当前的PT_LOAD段的内存大小与文件大小 */
	fix_ElfHeader(ptr, _pack_obuf_offset);

	/* 重新设置loader变量 */
	//_loader->update_vars(ptr, ptr + _loader_start_va);

	/* 修订soname为了支持6.0+ */
	//fix_soname_stridx(ptr);

	/* 写入文件 */
	_fo->seek(0, SEEK_SET);
	writeTarget(_fo, ptr, _pack_obuf_offset, 
							TDOG_DEBUG, "Flush memory to File");

	/* 写入辅助节 */
	write_sections(ptr);

	/* 写入TDOG标记以及壳描述 */
	write_header();
}

void DogTools::fill_orig_dynamic_info() {
	_orig_finit_offset = _elftools->_dt_finit.value;
}
