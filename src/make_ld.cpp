#include "globals.h"
#include "mem.h"
#include "file.h"
#include "x_elf_tools.h"
#include "mapper.h"
#include "make_ld.h"

#include <sys/mman.h>

MakeLD::MakeLD() {
	memset(&_opts, 0, sizeof(struct arguments));
	_elftools = NULL;
	_phdr_table = NULL;
	_phdr_table_size = 0;
	_phdr_holder = NULL;
	_load_start = NULL;
	_load_size = 0;
	_load_bias = 0;
}

MakeLD::~MakeLD() {
    if (_fi.isOpen())
		_fi.closex();

	if (_phdr_table) munmap(_phdr_table, _phdr_table_size);
	if (_phdr_holder) _mapper.free_phdr_ptr(&_phdr_holder);
	if ((_load_start) && (_load_size)) munmap(_load_start, _load_size);
}

void MakeLD::set_options(struct arguments* opts) {
	if (opts) memcpy(&_opts, opts, sizeof(struct arguments));
}

void MakeLD::set_elftools(ElfTools* elftools) {
	_elftools = elftools;
}

int MakeLD::make(const char* ld_path) {
	/* 1.打开文件
	 * 2.使用ELF文件工具初始化文件
	 * 3.提取出LOAD段，并读入到缓冲中
	 * 4.从ELF头获取入口点地址
	 * 5.清除ELF文件头，以及对应的程序段头表
	 */
	XASSERT(ld_path);
	int ret = open_file(ld_path, &_fi);
	if (ret != 0) {
		return -1;
	}
	
	/* 初始化ELFTOOLS */
	_elftools = new ElfTools(&_fi);
	if (_elftools == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new ElfTools");
		return -2;
	}
	_elftools->set_machine(_opts.arch);
	_elftools->init(_opts.custom_format, false);

	/* 分配内存 */	
	_phdr_holder = new struct phdr_ptr;
	memset(_phdr_holder, 0, sizeof(struct phdr_ptr));
	
	/* 设置页位移 */
	if (_opts.set_page_shift) {
		_mapper.set_page_shift(_opts.page_shift);
	}

	/* 映射文件 */
	if (map_file(&_fi) != 0) {
		ERROR_INTERNAL_EXCEPT("map file failed");
		return -3;
	}

	return 0;
}

int MakeLD::make(InputFile* fi) {
	/* 1.打开文件
	 * 2.使用ELF文件工具初始化文件
	 * 3.提取出LOAD段，并读入到缓冲中
	 * 4.从ELF头获取入口点地址
	 * 5.清除ELF文件头，以及对应的程序段头表
	 */
	XASSERT(fi);
	
	/* 初始化ELFTOOLS */
	_elftools = new ElfTools(fi);
	if (_elftools == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new ElfTools");
		return -1;
	}
	_elftools->set_machine(_opts.arch);
	_elftools->init(_opts.custom_format, false);

	/* 分配内存 */	
	_phdr_holder = new struct phdr_ptr;
	memset(_phdr_holder, 0, sizeof(struct phdr_ptr));
	
	/* 设置页位移 */
	if (_opts.set_page_shift) {
		_mapper.set_page_shift(_opts.page_shift);
	}

	/* 映射文件 */
	if (map_file(fi) != 0) {
		ERROR_INTERNAL_EXCEPT(NULL);
		return -2;
	}

	return 0;
}

unsigned MakeLD::get_ld_size() {
	return _load_size;
}

unsigned char* MakeLD::get_ld() {
	return (unsigned char*)_load_start;
}

unsigned MakeLD::get_ld_bias() {
	return _load_bias;
}

int MakeLD::map_file(InputFile* fi) {
	/* 映射 */
	fi->seek(0, SEEK_SET);

	Elf32_Ehdr header;
	memcpy(&header, _elftools->_ehdri, sizeof(Elf32_Ehdr));
	/* 映射到程序段头表 */
    int ret = 
		_mapper.phdr_table_load(fi->getFd(), 
								get_te32(&header.e_phoff), 
								get_te16(&header.e_phnum),
								&(_phdr_holder->phdr_mmap), 
								&(_phdr_holder->phdr_size),
								&_phdr_table);
    if (ret < 0) {
        ERROR_INTERNAL_EXCEPT(NULL);
		return -1;
    }

	/* 段表总长度 */
	_phdr_table_size = _phdr_holder->phdr_size;

	/* 获取段数量 */
    unsigned short phdr_count = get_te16(&header.e_phnum);

    /* 获取可加载段总长度 */
    unsigned ext_sz = _mapper.phdr_table_get_load_size(_phdr_table, phdr_count);
    if (ext_sz == 0) {
		ERROR_INTERNAL_EXCEPT(NULL);
        return -2;
    }

	/* 解析地址空间为所有的可加载段 */
    // void* load_start = NULL;
    // unsigned load_size = 0;
    // unsigned load_bias = 0;
    ret = _mapper.phdr_table_reserve_memory(_phdr_table,
										   phdr_count,
										   &_load_start,
										   &_load_size,
										   &_load_bias);
	/* load_bias 为 load_start - 第一个可加载段的内存偏移 */
    if (ret < 0) {
		ERROR_INTERNAL_EXCEPT(NULL);
        return -3;
    }

    /* Map all the segments in our address space with default protections */
	/* 映射所有的段在我们的地址空间使用默认的保护属性 */
    ret = _mapper.phdr_table_load_segments(_phdr_table,
										  phdr_count,
										  _load_bias,
										  fi->getFd());
    if (ret < 0) {
		ERROR_INTERNAL_EXCEPT(NULL);
        return -4;
    }

	return 0;
}

unsigned MakeLD::calc_page_align(unsigned x) {
	return _mapper.PAGE_END(x);
}
