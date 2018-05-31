#include "dog_common.h"
#include "xor.h"

#define TDOG_MERGE_SIGN       0x19831210

bool DogTools::check_merge_sign(FileBase* fi) {
	XASSERT(fi);

	unsigned buf = 0;
	InputFile* file = (InputFile*)fi;
	bool ret = false;

	file->seek(4, SEEK_END);
	file->readx(&buf, 4);
	buf = get_te32(&buf);
	if (buf != TDOG_MERGE_SIGN)
		ret = false;
	else
		ret = true;

	set_input_file_seek(0, SEEK_SET);

	return ret;
}

void DogTools::merge() {
	unsigned char* buf = NULL;
	unsigned buf_size = 0;
	buf = merge_mem(&buf_size);
	if (buf != NULL) {
		_fo->seek(0, SEEK_SET);
		writeTarget(_fo, (void*)buf, buf_size, TDOG_DEBUG, "Merge Memory");
	}
	if (buf) delete [] buf;
}

unsigned char* DogTools::merge_mem(unsigned* size) {
	/* 清空缓存 */
	_ibuf.clear();
	_obuf.clear();

	/* 开启加壳 */
	set_input_file_seek(0, SEEK_SET);

	/* 统计可加载段的数量 */
	unsigned phnum = _elftools->_phnum;
	if (phnum <= 1) {
		/* 没有合并的必要 */
		return NULL;
	}

	/* 将目标通过内存展开 */
	MakeLD* mld = new MakeLD;
	mld->set_options(&_opts);
	mld->make(_fi);

	unsigned char* load_segments = (unsigned char*)mld->get_ld();
	unsigned load_size = (unsigned)mld->get_ld_size();
	unsigned char* outbuf = new unsigned char [load_size + 0x1024];
	if (outbuf == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new unsigned char [load_size + 0x1024]");
		return NULL;
	}

	/* 写入 */
	memcpy(outbuf, load_segments, load_size);
	if (mld) delete mld; mld = NULL;
	
	/* 合并头 */
	_elftools->reset_phdr(outbuf, load_size, 1);

	// /* 遍历段表并写入 */
	// int nx = 0;
	// Elf32_Phdr* phdr = _elftools->_phdri;
	// for (unsigned i = 0; i < phnum; phdr++, i++) {
	// 	unsigned type = get_te32(&phdr->p_type);
	// 	unsigned o = (unsigned)phdr - (unsigned)(_elftools->_ehdri);		/* 得到在fo中的位置 */
	// 	if (type != PT_LOAD) {
	// 		/* 如果是在PT_LOAD中 */
	// 		if (_elftools->is_in_PT_LOAD(get_te32(&phdr->p_offset))) {
	// 			Elf32_Phdr load_phdr;
	// 			memcpy(&load_phdr, phdr, sizeof(Elf32_Phdr));
	// 			unsigned mem_offset = get_te32(&load_phdr.p_vaddr);
	// 			set_te32(&load_phdr.p_offset, mem_offset);
	// 			/* 重写头 */
	// 			memcpy(outbuf + o, &load_phdr, sizeof(Elf32_Phdr));
	// 		}
	// 	} else {
	// 		/* 只写入一个可加载段 */
	// 		if (nx == 0) {
	// 			Elf32_Phdr merge_phdr;
	// 			memcpy(&merge_phdr, phdr, sizeof(Elf32_Phdr));
	// 			set_te32(&merge_phdr.p_filesz, load_size);
	// 			set_te32(&merge_phdr.p_memsz, load_size);
	// 			/* 文件偏移与内存偏移相同 */
	// 			unsigned mem_offset = get_te32(&phdr->p_vaddr);
	// 			set_te32(&phdr->p_offset, mem_offset);
	// 			unsigned flags = get_te32(&merge_phdr.p_flags);
	// 			flags |= PF_R;
	// 			flags |= PF_W;
	// 			flags |= PF_X;
	// 			set_te32(&merge_phdr.p_flags, flags);
	// 			memcpy(outbuf + o, &merge_phdr, sizeof(Elf32_Phdr));
	// 		} else {
	// 			/* 清空其余可加载段 */
	// 			Elf32_Phdr dummy;
	// 			set_te32(&dummy.p_type, PT_NOTE);
	// 			set_te32(&dummy.p_offset, rand());
	// 			set_te32(&dummy.p_vaddr, rand());
	// 			set_te32(&dummy.p_paddr, rand());
	// 			set_te32(&dummy.p_filesz, rand());
	// 			set_te32(&dummy.p_memsz, rand());
	// 			set_te32(&dummy.p_flags, PF_R);
	// 			set_te32(&dummy.p_align, 1);
	// 			memcpy(outbuf + o, &dummy, sizeof(Elf32_Phdr));
	// 		}
	// 		nx++;
	// 	}/* end else */
	// }/* end for */

	if (size) *size = load_size;
	return outbuf;

	/* 写入标志 */
	// unsigned sign = 0;
	// set_te32(&sign, TDOG_MERGE_SIGN);
	// memcpy(outbuf + load_size, &sign, 4);
	// if (size) *size = load_size + 4;
	// return outbuf;
}
