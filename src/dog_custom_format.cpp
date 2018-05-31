#include "dog_common.h"
#include "xor.h"

void DogTools::custom_format() {
	unsigned char* buf = NULL;
	unsigned buf_size = 0;
	buf = merge_mem(&buf_size);
	if (buf == NULL) {
	    ERROR_INTERNAL_EXCEPT("merge mem failed");
	}
	/* 合并后开始自定义结构 
	 * magic code (0xA521613A)
	 * key1
	 * key2
	 * 0,占位置
	 * ofs
	 * code_size
	 * pt_dynamic_va
	 * pt_dynamic_size
	 * exidx_va
	 * exidx_size
	 * 是否需要解密段 > 0x19831210 则解密否则则不做任何操作
	 * 随机填充1
	 * 整个第一个段
	 */
	
	/* 1.提取整个段表
	 * 2.提取代码段
	 */
	unsigned char* codes = NULL;
	unsigned size_codes = 0;
	unsigned pt_dynamic_va = 0;
	unsigned pt_dynamic_size = 0;
	unsigned key1 = rand() ^ 0xA521613A;
	unsigned key2 = rand() ^ 0xA19930613A;

	unsigned fill1 = rand() ^ 0xFFDDBBCC;
	//unsigned fill2 = rand() ^ 0x11223344;
	//unsigned fill3 = rand() ^ 0xF1E2D3C4;

	unsigned exidx_va = 0;
	unsigned exidx_size = 0;

	Elf32_Ehdr* hdr = (Elf32_Ehdr*)buf;
	Elf32_Phdr* phdr = (Elf32_Phdr*)(buf + hdr->e_phoff);
	unsigned num_phdr = get_te16(&hdr->e_phnum);
	bool ch = false;
	unsigned ofs = sizeof(Elf32_Ehdr) + (num_phdr * sizeof(Elf32_Phdr));
	for (unsigned i = 0; i < num_phdr; i++, phdr++) {
		if ((PT_LOAD == get_te32(&phdr->p_type)) &&
			(ch == false)) {
			ch = true;

			size_codes = get_te32(&phdr->p_filesz) - ofs;
			codes = new unsigned char [size_codes];
			if (codes == NULL) {
			    ERROR_ALLOC_MEMORY_FAILED_EXCEPT("codes = new unsigned char");
			}
			memcpy(codes, buf + get_te32(&phdr->p_offset) + ofs, size_codes);
		}

		if (PT_DYNAMIC == get_te32(&phdr->p_type)) {
			pt_dynamic_va = get_te32(&phdr->p_vaddr);
			pt_dynamic_size = get_te32(&phdr->p_filesz);
		}

		if (PT_ARM_EXIDX == get_te32(&phdr->p_type)) {
			exidx_va = get_te32(&phdr->p_vaddr);
			exidx_size = get_te32(&phdr->p_filesz);
		}
	}
	
	/* 合成 */
	if (buf) delete [] buf;
	unsigned file_size = 3 * 0x10 + size_codes;
	buf = new unsigned char [file_size];
	if (buf == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("buf = new unsigned char");
	}
	memset(buf, 0, file_size);

	/* 设置 */
	set_te32(buf, 0xA521613A);
	set_te32(buf + 0x04, key1);
	set_te32(buf + 0x08, key2);
	set_te32(buf + 0x0C, 0);

	set_te32(buf + 0x10, ofs);
	set_te32(buf + 0x14, size_codes);
	set_te32(buf + 0x18, pt_dynamic_va);
	set_te32(buf + 0x1C, pt_dynamic_size);

	set_te32(buf + 0x20, exidx_va);
	set_te32(buf + 0x24, exidx_size);

	info_msg("Key1 = 0x%4X\n", key1);
	info_msg("Key2 = 0x%4X\n", key2);
	info_msg("Offset to code = 0x%4X\n", ofs);
	info_msg("Code size = 0x%4X\n", size_codes);
	info_msg("PT DYNAMIC_VA = 0x%4X\n", pt_dynamic_va);
	info_msg("PT_DYNAMIC_SIZE = 0x%4X\n", pt_dynamic_size);
	info_msg("PT_EXIDX_VA = 0x%4X\n", exidx_va);
	info_msg("PT_EXIDX_SIZE = 0x%4X\n", exidx_size);

	if (_opts.encrypt_cf_codes) { 		/* 加密 */
		set_te32(buf + 0x28, 0x1983FFFF);
		XorArray(key2, codes, codes, size_codes);
		memcpy(buf + 3*0x10, codes, size_codes);
	} else {
		set_te32(buf + 0x28, 0x19930613);
		memcpy(buf + 3*0x10, codes, size_codes);
	}
	info_msg("Encrypt Codes = 0x%4X\n", *(unsigned*)(buf + 0x28));

	set_te32(buf + 0x2C, fill1);
	//set_te32(buf + 0x28, fill2);
	//set_te32(buf + 0x2C, fill3);

	/* 加密头 */
	XorArray(key1, buf + 0x08, buf + 0x08, 3*0x10-0x08);
	
	if (buf != NULL) {
		_fo->seek(0, SEEK_SET);
		writeTarget(_fo, (void*)buf, file_size, TDOG_DEBUG, "Custom Format");
		unsigned tail = 0xF521613F;
		writeTarget(_fo, (void*)&tail, sizeof(unsigned), TDOG_DEBUG, "Tail Sign"); /* 写入一个结尾标记 */
	}
	if (buf) delete [] buf;
	if (codes) delete [] codes;
}
