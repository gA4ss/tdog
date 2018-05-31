#include "globals.h"
#include "mem.h"
#include "file.h"
#include "x_elf_tools.h"

ElfTools::ElfTools() {
	init_datas();
}

ElfTools::ElfTools(InputFile* fi) {
	init_datas();
	_fi = fi;
}

ElfTools::~ElfTools() {
	if (_buildid) delete [] _buildid;
	if (_xfile) delete _xfile;
}

int ElfTools::init_datas() {
	_size_elf_hdrs = 0;

	_load_va = 0;
	_lg2_page = 0;
	_page_size = 0;
	_page_mask = 0;

	_ei_class = ELFCLASS32;
	_ei_data = ELFDATA2LSB;
	_ei_machine = EM_ARM;
	_ei_osabi = ELFOSABI_LINUX;
	_ei_version = EV_CURRENT;

	_strtab = NULL;
	_size_strtab = 0;
	_strtab_inside_offset = 0;

	_symtab = NULL;
	_size_symtab = 0;
	_symtab_inside_offset = 0;

	_ehdri = NULL;
	_phdri = NULL;
	_shdri = NULL;

	_sec_strndx = NULL;
	_shstrtab = NULL;

	_phoff = 0;
	_shoff = 0;

	_type = 0;
	_sz_phdrs = 0;

	_buildid = NULL;
	_size_buildid = 0;
	_note = NULL;
	_size_note = 0;

	_fi = NULL;
	_size_file_buffer = 0;
	_file = NULL;

	_xfile = NULL;

	return 0;
}

int ElfTools::init(bool skip_note/*=false*/, bool elfrel/*=false*/) {
	_elfrel = elfrel;

    _size_file_buffer = _fi->st_size();
	_file_buffer.alloc(_size_file_buffer + 1);

	_fi->seek(0, SEEK_SET);
	_fi->readx((unsigned char*)_file_buffer, _size_file_buffer);
	_file = (unsigned char*)_file_buffer;

	/* 读取一个头 */
	_ehdri = (Elf32_Ehdr*)_file;

	/* 检查elf头是否正确 */
	if (false == elfrel) {
		if (check_elf_header(_ehdri) != 0)
			ERROR_ELF_FORMAT_INVALID_EXCEPT("invalid Ehdr");
	} else {
		if (check_elf_object_header(_ehdri) != 0)
			ERROR_ELF_FORMAT_INVALID_EXCEPT("invalid Object Ehdr");
	}

	/* 检查elf头是否正确 */
	if (check_android_elf_header(_ehdri) != 0)
		ERROR_ELF_FORMAT_INVALID_EXCEPT("invalid android Elf Ehdr");

	/* 判断elf头的大小是否符合要求 */
	if (get_te16(&_ehdri->e_ehsize) != sizeof(*_ehdri)) {
		ERROR_ELF_FORMAT_INVALID_EXCEPT("invalid Ehdr e_ehsize");
	}

	_type = get_te16(&_ehdri->e_type);
	_phnum = get_te16(&_ehdri->e_phnum);
	if (_phnum >= 14) {
		ERROR_ELF_FORMAT_INVALID_EXCEPT("too many Elf32_Phdr");
	}
	_shnum = get_te16(&_ehdri->e_shnum);
	if (_ehdri->e_ident[EI_CLASS] != ELFCLASS32) {
		_phoff = 0;
		_shoff = 0;
		_sz_phdrs = 0;
		ERROR_ELF_FORMAT_INVALID_EXCEPT("class is not match");
	}

	/* 程序段头偏移 */
	_phoff = get_te32(&_ehdri->e_phoff);
	if (false == elfrel) {
		if (_phoff == 0) {
			ERROR_ELF_FORMAT_INVALID_EXCEPT("program header offset is zero");
		}
		/* 保证程序头表跟elf头结构是连续的 相邻的 */
		if (_phoff != sizeof(*_ehdri)) {
			ERROR_ELF_FORMAT_INVALID_EXCEPT("non-contiguous Ehdr/Phdr");
		}
	}

	_shoff = get_te32(&_ehdri->e_shoff);
	_sz_phdrs = _phnum * get_te16(&_ehdri->e_phentsize);

	if (false == elfrel)
		_phdri = (Elf32_Phdr *) (_phoff + _file);
	else
		_phdri = NULL;
	_shdri = (Elf32_Shdr *) (_shoff + _file);

	/* 设置节名符号表 */
	_sec_strndx = _shdri + _ehdri->e_shstrndx;
	_shstrtab = (char*)(_file + get_te32(&_sec_strndx->sh_offset));

	/* 获取符号表与字符串表 */
	get_symtab();
	get_strtab();

	/* 获取一系列数据 */
	if (false == elfrel) {
		/* get datas */
		get_load_va();
		get_lg2_page();

		/* 跳过note */
		if (skip_note == false) {
			get_buildid();
			get_note();
		}
	
		/* get elf header size */
		_size_elf_hdrs = _sz_phdrs + sizeof(Elf32_Ehdr);
	} else {
		_size_elf_hdrs = sizeof(Elf32_Ehdr);
	}
	return 0;
}

int ElfTools::init_merge(unsigned char* mem, unsigned mem_size) {
	XASSERT(mem);
	XASSERT(mem_size > 0);

    _size_file_buffer = mem_size;
	_file_buffer.alloc(_size_file_buffer + 1);

	memcpy((unsigned char*)_file_buffer, mem, _size_file_buffer);

	return init_merge_ptr((unsigned char*)_file_buffer, 
						  _size_file_buffer);
}

int ElfTools::init_merge_ptr(unsigned char* ptr, unsigned mem_size) {
	XASSERT(ptr);
	XASSERT(mem_size > 0);

	_file = ptr;
	_size_file_buffer = mem_size;

	/* 读取一个头 */
	_ehdri = (Elf32_Ehdr*)_file;

	/* 检查elf头是否正确 */
	if (check_elf_header(_ehdri) != 0)
		ERROR_ELF_FORMAT_INVALID_EXCEPT("invalid Ehdr");

	/* 检查elf头是否正确 */
	if (check_android_elf_header(_ehdri) != 0)
		ERROR_ELF_FORMAT_INVALID_EXCEPT("invalid Android Ehdr");

	/* 判断elf头的大小是否符合要求 */
	if (get_te16(&_ehdri->e_ehsize) != sizeof(*_ehdri)) {
		ERROR_ELF_FORMAT_INVALID_EXCEPT("invalid Ehdr e_ehsize");
	}

	_type = get_te16(&_ehdri->e_type);
	_phnum = get_te16(&_ehdri->e_phnum);
	if (_phnum >= 14) {
		ERROR_ELF_FORMAT_INVALID_EXCEPT("too many Elf32_Phdr");
	}
	_shnum = get_te16(&_ehdri->e_shnum);
	if (_ehdri->e_ident[EI_CLASS] != ELFCLASS32) {
		_phoff = 0;
		_shoff = 0;
		_sz_phdrs = 0;
		ERROR_ELF_FORMAT_INVALID_EXCEPT("class is not match");
	}

	/* 程序段头偏移 */
	_phoff = get_te32(&_ehdri->e_phoff);
	if (_phoff == 0) {
		ERROR_ELF_FORMAT_INVALID_EXCEPT("program header offset is zero");
	}
	/* 保证程序头表跟elf头结构是连续的 相邻的 */
	if (_phoff != sizeof(*_ehdri)) {
		ERROR_ELF_FORMAT_INVALID_EXCEPT("non-contiguous Ehdr/Phdr");
	}

	_shoff = 0;
	_sz_phdrs = _phnum * get_te16(&_ehdri->e_phentsize);

	_phdri = (Elf32_Phdr *) (_phoff + _file);
	_shdri = NULL;

	/* 设置节名符号表 */
	_sec_strndx = NULL;
	_shstrtab = NULL;

	/* 获取一系列数据 */
	get_load_va();
	get_lg2_page();

	/* get elf header size */
	_size_elf_hdrs = _sz_phdrs + sizeof(Elf32_Ehdr);

	return 0;	
}

int ElfTools::update_merge_mem(unsigned add_size) {
	/* 读取一个头 */
	_ehdri = (Elf32_Ehdr*)_file;
	_type = get_te16(&_ehdri->e_type);
	_phnum = get_te16(&_ehdri->e_phnum);
	_shnum = get_te16(&_ehdri->e_shnum);
	_phoff = get_te32(&_ehdri->e_phoff);
	_shoff = 0;
	_sz_phdrs = _phnum * get_te16(&_ehdri->e_phentsize);

	_phdri = (Elf32_Phdr *) (_phoff + _file);

	if (add_size != 0) {
		/* 修订程序头段的长度 */
		unsigned i = _phnum;
		Elf32_Phdr* p = _phdri;
		while (--i) {
			unsigned type = get_te32(&p->p_type);
			if (type == PT_LOAD) {
				break;
			}
			p++;
		}
		/* 增加长度 */
		unsigned s = get_te32(&p->p_filesz);
		s += add_size;
		set_te32(&p->p_filesz, s);
		
		s = get_te32(&p->p_memsz);
		s += add_size;
		set_te32(&p->p_memsz, s);
	}
	

	_shdri = NULL;

	/* 设置节名符号表 */
	_sec_strndx = NULL;
	_shstrtab = NULL;

	/* 获取一系列数据 */
	get_load_va();
	get_lg2_page();

	/* get elf header size */
	_size_elf_hdrs = _sz_phdrs + sizeof(Elf32_Ehdr);

	return 0;	
}

int ElfTools::set_target_file(InputFile* fi) {
	if (fi)
		_fi = fi;
	return !_fi;
}

bool ElfTools::is_objfile() {
	return _elfrel;
}

void ElfTools::reset_phdr(unsigned char* outbuf, 
													unsigned outsize,
													int dummy_it/*=1*/) {
	/* 遍历段表并写入 */
	int nx = 0;
	unsigned phnum = _phnum;
	Elf32_Phdr* phdr = _phdri;
	for (unsigned i = 0; i < phnum; phdr++, i++) {
		unsigned type = get_te32(&phdr->p_type);
		unsigned o = (unsigned)phdr - (unsigned)(_ehdri);		/* 得到在fo中的位置 */
		if (type != PT_LOAD) {
			/* 如果是在PT_LOAD中 */
			if (is_in_PT_LOAD(get_te32(&phdr->p_offset))) {
				Elf32_Phdr load_phdr;
				memcpy(&load_phdr, phdr, sizeof(Elf32_Phdr));
				unsigned mem_offset = get_te32(&load_phdr.p_vaddr);
				set_te32(&load_phdr.p_offset, mem_offset);
				/* 重写头 */
				memcpy(outbuf + o, &load_phdr, sizeof(Elf32_Phdr));
			}
		} else {
			/* 只写入一个可加载段 */
			if (nx == 0) {
				Elf32_Phdr merge_phdr;
				memcpy(&merge_phdr, phdr, sizeof(Elf32_Phdr));
				set_te32(&merge_phdr.p_filesz, outsize);
				set_te32(&merge_phdr.p_memsz, outsize);
				/* 文件偏移与内存偏移相同 */
				unsigned mem_offset = get_te32(&phdr->p_vaddr);
				set_te32(&phdr->p_offset, mem_offset);
				unsigned flags = get_te32(&merge_phdr.p_flags);
				flags |= PF_R;
				flags |= PF_W;
				flags |= PF_X;
				set_te32(&merge_phdr.p_flags, flags);
				memcpy(outbuf + o, &merge_phdr, sizeof(Elf32_Phdr));
			} else {
				/* 清空其余可加载段 */
				if (dummy_it) {
					Elf32_Phdr dummy;
					set_te32(&dummy.p_type, PT_NOTE);
					set_te32(&dummy.p_offset, rand());
					set_te32(&dummy.p_vaddr, rand());
					set_te32(&dummy.p_paddr, rand());
					set_te32(&dummy.p_filesz, rand());
					set_te32(&dummy.p_memsz, rand());
					set_te32(&dummy.p_flags, PF_R);
					set_te32(&dummy.p_align, 1);
					memcpy(outbuf + o, &dummy, sizeof(Elf32_Phdr));
				}/* end if */
			}
			nx++;
		}/* end else */
	}/* end for */
}

Elf32_Shdr* ElfTools::get_got() {
	char* sh = _shstrtab;
	unsigned shn = _shnum;
	Elf32_Shdr* sec = _shdri;

	for (unsigned i = 0; i < shn; i++, sec++) {
		char* name = sh + sec->sh_name;
		if ((strcmp(name, ".got") == 0) &&
			(sec->sh_type == SHT_PROGBITS)) {
			return sec;
		}
	}

	return NULL;
}

Elf32_Shdr* ElfTools::get_text() {
	char* sh = _shstrtab;
	unsigned shn = _shnum;
	Elf32_Shdr* sec = _shdri;

	for (unsigned i = 0; i < shn; i++, sec++) {
		char* name = sh + sec->sh_name;
		if ((strcmp(name, ".text") == 0) &&
			(sec->sh_type == SHT_PROGBITS)) {
			return sec;
		}
	}

	return NULL;	
}

/* 检查ELF头 */
int ElfTools::check_elf_header(Elf32_Ehdr const *ehdr) {
	XASSERT(ehdr);

    const unsigned char * const buf = ehdr->e_ident;

	/* 检查头标志 */
    if (0!=memcmp(buf, "\x7f\x45\x4c\x46", 4)  // "\177ELF"
		||  buf[EI_CLASS]!=_ei_class
		||  buf[EI_DATA] !=_ei_data
		) {
        return -1;
    }

	/* 不能针对FreeBSD程序进行加壳 */
    if (!memcmp(buf+8, "FreeBSD", 7))                   // branded
        return 1;

	/* 获取文件类型 */
    int const type = get_te16(&ehdr->e_type);
	
	/* 检查类型是否时 应用程序 或者 是一个动态库(so) */
    if (type != ET_EXEC && type != ET_DYN)
		//if (type != Elf32_Ehdr::ET_DYN)
        return 2;

	/* 检查硬件类型是否匹配 */
    if (get_te16(&ehdr->e_machine) != _ei_machine)
        return 3;

	/* 检查ELF文件格式版本 */
    if (get_te32(&ehdr->e_version) != EV_CURRENT)
        return 4;

	/* 检查程序头段数量是否合法 */
    if (get_te16(&ehdr->e_phnum) < 1)
        return 5;

	/* 检查一个程序头段项长度是否合法 */
    if (get_te16(&ehdr->e_phentsize) != sizeof(Elf32_Phdr))
        return 6;

    return 0;
}

int ElfTools::check_elf_object_header(Elf32_Ehdr const *ehdr) {
    const unsigned char * const buf = ehdr->e_ident;

	/* 检查头标志 */
    if (0!=memcmp(buf, "\x7f\x45\x4c\x46", 4)  // "\177ELF"
		||  buf[EI_CLASS]!=_ei_class
		||  buf[EI_DATA] !=_ei_data
		) {
        return -1;
    }

	/* 不能针对FreeBSD程序进行加壳 */
    if (!memcmp(buf+8, "FreeBSD", 7))                   // branded
        return 1;

	/* 获取文件类型 */
    int const type = get_te16(&ehdr->e_type);
	
	/* 检查类型是否是可重定位文件 */
    if (type != ET_REL)
        return 2;

	/* 检查硬件类型是否匹配 */
    if (get_te16(&ehdr->e_machine) != _ei_machine)
        return 3;

	/* 检查ELF文件格式版本 */
    if (get_te32(&ehdr->e_version) != EV_CURRENT)
        return 4;

	return 0;
}

int ElfTools::check_android_elf_header(Elf32_Ehdr* ehdr) {
	UNUSED(ehdr);
	return 0;
}

bool ElfTools::is_in_PT_LOAD(unsigned value) {
    unsigned min_offset = 0xFFFFFFFFU;
    unsigned max_offset = 0x00000000U;
	Elf32_Phdr* phdr = _phdri;

	for (unsigned i = 0; i < _phnum; i++, phdr++) {
		unsigned type = get_te32(&phdr->p_type);

		if (type != PT_LOAD)
			continue;

		unsigned offset = get_te32(&phdr->p_offset);
		unsigned file_size = get_te32(&phdr->p_filesz);
        if (offset < min_offset) {
            min_offset = offset;
        }

        if (offset + file_size > max_offset) {
            max_offset = offset + file_size;
        }
	}

	if (min_offset > max_offset) {
        return false;
    }

	if (value >= max_offset)
		return false;

	return true;
}

unsigned ElfTools::sizeof_PT_LOAD_file() {
    unsigned min_offset = 0xFFFFFFFFU;
    unsigned max_offset = 0x00000000U;
	Elf32_Phdr* phdr = _phdri;

	for (unsigned i = 0; i < _phnum; i++, phdr++) {
		unsigned type = get_te32(&phdr->p_type);

		if (type != PT_LOAD)
			continue;

		unsigned offset = get_te32(&phdr->p_offset);
		unsigned file_size = get_te32(&phdr->p_filesz);
        if (offset < min_offset) {
            min_offset = offset;
        }

        if (offset + file_size > max_offset) {
            max_offset = offset + file_size;
        }
	}

	if (min_offset > max_offset) {
        return 0;
    }

	return max_offset - min_offset;
}

// unsigned ElfTools::sizeof_PT_LOAD_mem() {
//     unsigned min_vaddr = 0xFFFFFFFFU;
//     unsigned max_vaddr = 0x00000000U;
// 	Elf32_Phdr* phdr = _phdri;

//     for (unsigned short i = 0; i < phdr_count; i++, phdr++) {
//         if (phdr->p_type != Elf32_Phdr::PT_LOAD) {
//             continue;
//         }

//         if (phdr->p_vaddr < min_vaddr) {
//             min_vaddr = phdr->p_vaddr;
//         }

//         if (phdr->p_vaddr + phdr->p_memsz > max_vaddr) {
//             max_vaddr = phdr->p_vaddr + phdr->p_memsz;
//         }
//     }

//     if (min_vaddr > max_vaddr) {
//         return 0;
//     }

//     min_vaddr = PAGE_START(min_vaddr);
//     max_vaddr = PAGE_END(max_vaddr);

//     return max_vaddr - min_vaddr;
// }

void ElfTools::get_symtab() {
	Elf32_Shdr* shdr = _shdri;

	/* 遍历节表 */
	for (unsigned i = 0; i < _shnum; shdr++, i++) {
		unsigned size = get_te32(&shdr->sh_size);

		/* 发现0空间的节直接跳过 */
		if (size == 0) {
			continue;
		}

		/* 判断是否是符号表 */
		unsigned type = get_te32(&shdr->sh_type);
		if (type == SHT_SYMTAB) {
			_symtab = shdr;
			_size_symtab = size;
			_symtab_inside_offset = (unsigned)_symtab - (unsigned)_file;
			break;
		}
	}
}

void ElfTools::get_strtab() {
	Elf32_Shdr* shdr = _shdri;

	/* 遍历节表 */
	for (unsigned i = 0; i < _shnum; shdr++, i++) {
		unsigned size = get_te32(&shdr->sh_size);

		/* 发现0空间的节直接跳过 */
		if (size == 0) {
			continue;
		}

		/* 判断是否是字符串表 */
		unsigned type = get_te32(&shdr->sh_type);
		if (type == SHT_STRTAB) {
			_strtab = shdr;
			unsigned offset = get_te32(&_strtab->sh_offset);
			_strings = (char*)(_file + offset);

			/* 如果当前类型非可重定位文件则检测程序段 */
			if (false == _elfrel) {
				/* !!!bug: 2016.4.15 如果一个so中只有.dynstr则这里会出错 */
				/* 不能在可加载段内 */
				if (is_in_PT_LOAD(offset)) {
					continue;
				}
			}

			/* 不能是程序节名串表 */
			if (_strings == _shstrtab) {
				continue;
			}

			_size_strtab = size;
			_strtab_inside_offset = (unsigned)_strtab - (unsigned)_file;
			break;
		}
	}
}

unsigned ElfTools::get_load_va() {
	Elf32_Phdr const *phdr = _phdri;
	for (int j = _phnum; --j >= 0; ++phdr) {
		unsigned const type = get_te32(&phdr->p_type);
		
		/* PT_LOAD */
		if (PT_LOAD == type) {
			/* 找到段加载基地址 */
			unsigned const offset = get_te32(&phdr->p_offset);
			if (offset != 0) {
				return 1;
			}
			_load_va = get_te32(&phdr->p_vaddr);
			return _load_va;
		}/* PT_LOAD */
	}
	return 1;
}

unsigned ElfTools::get_lg2_page() {
	Elf32_Phdr const *phdr = _phdri;
	for (int j = _phnum; --j >= 0; ++phdr) {
		unsigned const type = get_te32(&phdr->p_type);
		
		/* PT_LOAD */
		if (PT_LOAD == type) {
			/* 找到最大掩码 */
			unsigned x = get_te32(&phdr->p_align) >> _lg2_page;
			while (x >>= 1) {
				++_lg2_page;
			}
		}/* PT_LOAD */
	}

	_page_size = 1u << _lg2_page;
	_page_mask = ~0u << _lg2_page;
	
	return 0;
}

void ElfTools::get_buildid(const char* b/*=.note.gnu.build-id*/) {
	Elf32_Shdr const *buildid = elf_find_section_name(b);
	if (buildid) {
		if (_buildid) delete _buildid;
		_size_buildid = get_te32(&buildid->sh_size);
		_buildid = new unsigned char[_size_buildid];
		memset(_buildid, 0, _size_buildid);
		memcpy(_buildid, _file + get_te32(&buildid->sh_offset), _size_buildid);		
	}
}

void ElfTools::alloc_note_space() {
	Elf32_Phdr const *phdr = _phdri;
	_size_note = 0;
	// 计算note的大小，主要是为了分配适当的空间。
	for (unsigned j = 0; j < _phnum; ++phdr, ++j) {
		if (PT_NOTE == get_te32(&phdr->p_type)) {
			_size_note += up4(get_te32(&phdr->p_filesz));
		}
	}
	if (_size_note) {
		if (_note) delete _note;
		_note = new unsigned char[_size_note];
	}
	_size_note = 0;
}

void ElfTools::get_note() {
	alloc_note_space();

	Elf32_Phdr const *phdr = _phdri;
	for (int j = _phnum; --j >= 0; ++phdr) {
		unsigned const type = get_te32(&phdr->p_type);
		/* PT_NOTE */
		if (PT_NOTE == type) {
			unsigned const len = get_te32(&phdr->p_filesz);
			unsigned char* pnote = _file + get_te32(&phdr->p_offset);
			memcpy(&_note[_size_note], pnote, len);
			_size_note += up4(len);
		}
	}/* end for */
}

void ElfTools::set_machine(int v) {
	if (v == ARCH_ARM) {
		_ei_machine = EM_ARM;
	} else if (v == ARCH_X86) {
		_ei_machine = EM_386;
	} else if (v == ARCH_MIPS) {
		//_ei_machine = EM_MIPS;
		_ei_machine = EM_ARM;
	} else {
		_ei_machine = EM_ARM;
	}
}

unsigned ElfTools::elf_get_offset_from_address(unsigned const addr) {
	Elf32_Phdr const *phdr = _phdri;
	int j = _phnum;
	for (; --j >= 0; ++phdr)
		if (PT_LOAD == get_te32(&phdr->p_type)) {
			unsigned const t = addr - get_te32(&phdr->p_vaddr);
			if (t < get_te32(&phdr->p_filesz)) {
				return t + get_te32(&phdr->p_offset);
			}
		}
	return 0;
}

unsigned ElfTools::elf_get_va_from_offset(unsigned const offset) {
	Elf32_Phdr const *phdr = _phdri;
	int j = _phnum;
	for (; --j >= 0; ++phdr)
		if (PT_LOAD == get_te32(&phdr->p_type)) {
			unsigned const t = offset - get_te32(&phdr->p_offset);
			if (t < get_te32(&phdr->p_memsz)) {
				return t + get_te32(&phdr->p_vaddr);
			}
		}
	return 0;	
}

Elf32_Shdr* ElfTools::elf_find_section_name(char const * const name) {
	XASSERT(name);
	Elf32_Shdr *shdr = (Elf32_Shdr*)_shdri;
	int j = _shnum;
	for (; 0 <= --j; ++shdr) {
		if (0 == strcmp(name, &_shstrtab[get_te32(&shdr->sh_name)])) {
			return shdr;
		}
	}
	return 0;
}

Elf32_Shdr* ElfTools::elf_find_section_type(unsigned const type) {
	Elf32_Shdr *shdr = (Elf32_Shdr*)_shdri;
	int j = _shnum;
	for (; 0 <= --j; ++shdr) {
		if (type == get_te32(&shdr->sh_type)) {
			return shdr;
		}
	}
	return 0;
}

Elf32_Rel* ElfTools::elf_if_rel_object(Elf32_Rel* r, unsigned count, unsigned va) {
	Elf32_Rel* rel = r;
	for (unsigned idx = 0; idx < count; ++idx, ++rel) {
		unsigned reloc = (unsigned)(rel->r_offset);
		if (reloc == va)
			return r;
	}
	return NULL;
}

int ElfTools::analyze(elf_analyze_options* opts/*=NULL*/) {
	unsigned char *fptr = NULL;

	if (true == _elfrel) {
		ERROR_INTERNAL_EXCEPT("it's object file not support");
		return -1;
	}

	/* 分配内存 */
	_xfile = new elf_file;
	if (_xfile == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new elf file failed");
		return -1;
	}
	memset(_xfile, 0, sizeof(elf_file));

	/* 复制参数选项 */
	memcpy(&(_xfile->analyze_opt), opts, sizeof(elf_analyze_options));

	/* 映射文件 */
	_xfile->size_file_buffer = _fi->st_size();
	_xfile->file_buffer.alloc(_xfile->size_file_buffer + 1);

	_fi->seek(0, SEEK_SET);
	_fi->readx((unsigned char*)_xfile->file_buffer, _xfile->size_file_buffer);
	fptr = (unsigned char*)_xfile->file_buffer;

	/* 读取节信息 */
	for (unsigned i = 0; i < _phnum; i++) {
		elf_segment segment;
		segment.type = _phdri[i].p_type;
		segment.offset = _phdri[i].p_offset;
		segment.address = _phdri[i].p_vaddr;
		segment.phys_address = _phdri[i].p_paddr;
		segment.filesize = _phdri[i].p_filesz;
		segment.memsize = _phdri[i].p_memsz;
		segment.flag = _phdri[i].p_flags;
		segment.align = _phdri[i].p_align;
		
		_xfile->segments.push_back(segment);
	}
	std::sort(_xfile->segments.begin(),
			  _xfile->segments.end(),
			  sort_segments);

	/* 读取段信息 */
	for (unsigned i = 0; i < _shnum; i++) {
		elf_section section;
		section.name = _shstrtab + _shdri[i].sh_name;
		section.offset = _shdri[i].sh_offset;
		section.address = _shdri[i].sh_addr;
		section.size = _shdri[i].sh_size;
		section.type = _shdri[i].sh_type;
		section.es = _shdri[i].sh_entsize;
		section.flag = _shdri[i].sh_flags;
		section.link = _shdri[i].sh_link;
		section.info = _shdri[i].sh_info;
		section.align = _shdri[i].sh_addralign;
		
		/* 判断特定的节 */
		if (strcmp(section.name, ".got") == 0) {
			_xfile->plt_got_size = section.size;
		}

		/* 确定节所属段 */
		section.segment = make_sure_section_to_segment(_xfile, section.offset);
		_xfile->sections.push_back(section);
	}
	std::sort(_xfile->sections.begin(),
			  _xfile->sections.end(),
			  sort_sections);

	/* 读取所有符号 */
	if (_symtab) {
		Elf32_Sym *sym_item = (Elf32_Sym*)(fptr + _symtab->sh_offset);
		for (unsigned i = 0; i < _size_symtab; i += sizeof(Elf32_Sym)) {
			elf_symbol sym;
			sym.name = _strings + sym_item->st_name;
			//sym.offset = sym_item->st_value;
			//sym.address = sym_item->st_value;
			sym.value = sym_item->st_value;
			sym.size = sym_item->st_size;
			sym.bind = ELF32_ST_BIND(sym_item->st_info);
			sym.type = ELF32_ST_TYPE(sym_item->st_info);
			sym.visibly = sym_item->st_other;
			sym.ndx = sym_item->st_shndx;
			sym.is_mapping_symbol = make_sure_symbol_is_mapping(sym.name);
			sym.mapping_type = make_sure_symbol_mapping_type(sym.name);
		
			_xfile->symbols.push_back(sym);

			/* 下一个符号 */
			sym_item++;
		}
		std::sort(_xfile->symbols.begin(),
				  _xfile->symbols.end(),
				  sort_symbols);
	}

	return 0;
}
