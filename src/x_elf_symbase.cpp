#include "globals.h"
#include "mem.h"
#include "file.h"
#include "x_elf_tools.h"

int elf_strtab_find(void* symbase, const char* s) {
	XASSERT(symbase);
	XASSERT(s);

	elf_tools_symtab* base = (elf_tools_symtab*)symbase;
	unsigned strlens = 0;
	char* name = base->strtab + 1; /* 跳过第一个0字符 */
	unsigned offset = 1;
	for (unsigned i = 0; i < base->strc; i++) {
		if (strcmp(name, s) == 0) {
			return offset;
		}
		strlens = strlen(name) + 1;
		offset += strlens;
		name = base->strtab + offset;
	}
	return 0;
}

int elf_strtab_add(void* symbase, const char* s, int muti_string) {
	XASSERT(symbase);
	XASSERT(s);

	/* 判断是否需要重复添加 */
	if (muti_string == 0) {
		/* 首先先寻找,找到则返回 */
		int ret = elf_strtab_find(symbase, s);
		if (ret) return ret;
	}

	elf_tools_symtab* base = (elf_tools_symtab*)symbase;

	int strtab_offset = base->strtab_offset;
	int strlens = strlen(s);

	/* 重新分配字符串表的空间 */
	unsigned x = (unsigned)(strtab_offset + strlens + 1);
	if (x > base->strsz) {
		base->strsz += (0x10 * DEF_SYMNAME_LEN);   /* 更新空间大小 */
		char* tmp = new char [base->strsz];
		if (tmp == NULL)  {
			ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new char []");
			return -1;
		}
		
		memcpy(tmp, base->strtab, strtab_offset);
		delete [] base->strtab;
		base->strtab = tmp;
	}

	/* 复制新值 */
	memcpy(base->strtab + strtab_offset, s, strlens+1);

	/* 索引增加 */
	int ret_offset = strtab_offset;
	strtab_offset += (strlens+1);
	base->strtab_offset = strtab_offset;

	/* 增加字符串计数 */
	base->strc++;

	return ret_offset;
}

unsigned elf_hashtab_hash(const char *str) {
	XASSERT(str);

	const unsigned char *name = (const unsigned char *)str;
	unsigned h = 0, g;

	while(*name) {
		h = (h << 4) + *name++;
		g = h & 0xf0000000;
		h ^= g;
		h ^= g >> 24;
	}
	return h;
}

void* elf_hashtab_create(unsigned n, unsigned syms) {
	unsigned nbucket = n;
	unsigned nchain = syms + 1;/* 0索引的空符号 */
	unsigned hashtab_size = 4 + 4 + (4 * nbucket) + (4 * nchain);
	unsigned char* hashtab = new unsigned char [hashtab_size];
	memset(hashtab, 0, hashtab_size);

	*(unsigned*)hashtab = nbucket;
	*((unsigned*)hashtab + 1) = nchain;

	return (void*)hashtab;
}

void elf_hashtab_release(void** p) {
	if ((p) && (*p)) {
		delete [] (unsigned char*)*p;
		*p = NULL;
	}
}

int elf_hashtab_chain_add(unsigned* chain, int index, 
						  int symtab_index) {
	if (chain[index] == 0) {
		/* 有空位,直接返回,添加成功 */
		chain[index] = symtab_index;
		chain[symtab_index] = 0;
		return 0;
	}

	/* 如果没有空位,继续添加 */
	index = chain[index];
	return elf_hashtab_chain_add(chain, index, symtab_index);
}

int elf_hashtab_add(void* hashtab, const char* name, 
					int symtab_index) {
	XASSERT(name);
	XASSERT(hashtab);

	if (hashtab == NULL) return -1;
	if (strlen(name) == 0) return -2;
	if (symtab_index <= 0) return -3;

	unsigned nbucket = *(unsigned*)hashtab;
	unsigned nchain = *((unsigned*)hashtab + 1);
	if ((unsigned)symtab_index > nchain) return -4;

	unsigned hash = elf_hashtab_hash(name);
	unsigned index = hash % nbucket;
	unsigned* bucket = (unsigned*)((unsigned char*)hashtab + 8);
	unsigned* chain = (unsigned*)((unsigned char*)hashtab + 8 + (4 * nbucket));
	
	if (bucket[index] == 0) {
		bucket[index] = symtab_index;
	} else {
		index = bucket[index];
		return elf_hashtab_chain_add(chain, index, symtab_index);
	}

	return 0;
}

Elf32_Sym* elf_symtab_create(int count, int* psize) {
	unsigned size = sizeof(Elf32_Sym) * (count + 2);
	unsigned char* s = new unsigned char [size];
	if (s == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new unsigned char [%d]", size);
		return NULL;
	}
	memset(s, 0, size);
	if (psize) *psize = size;
	return (Elf32_Sym*)s;
}

void elf_symtab_release(void** symtab) {
	if ((symtab) && (*symtab)) {
		delete [] (unsigned char*)*symtab;
		*symtab = NULL;
	}
}

int elf_symtab_add(Elf32_Sym* symtab, 
				   int index,
				   unsigned st_name,
				   unsigned st_value,
				   unsigned st_size,
				   unsigned bind,
				   unsigned type,
				   unsigned char st_other,
				   unsigned short st_shndx) {
	XASSERT(symtab);

	Elf32_Sym v;
	unsigned char st_info = ELF32_ST_INFO(bind, type);

	v.st_name = st_name;
	v.st_value = st_value;
	v.st_size = st_size;
	v.st_info = st_info;
	v.st_other = st_other;
	v.st_shndx = st_shndx;
	memcpy(symtab + index, &v, sizeof(Elf32_Sym));

	return 0;
}

int elf_symbase_init(void* symbase, int nbucket, int nchain) {
	if (symbase == NULL) return -1;

	if (nbucket == 0) nbucket = DEF_HASH_NBUCKET;
	int syms = nchain;
	elf_tools_symtab* base = (elf_tools_symtab*)symbase;
	int curr_size = nbucket + nchain;
	
	/* 第一个符号为空符号 */
	base->symc = syms + 1;
	base->strc = 0;
	Elf32_Sym* symtab = elf_symtab_create(curr_size, &curr_size);
	if (symtab == NULL) return -2;

	base->symtab = symtab;
	base->hashtab = elf_hashtab_create(nbucket, syms);
	if (base->hashtab == NULL) return -3;

	base->strsz = base->symc * DEF_SYMNAME_LEN;
	base->strtab = new char [base->strsz];
	if (base->strtab == NULL)
		return -4;
	memset(base->strtab, 0, base->strsz);
	base->strtab_offset = 1;

	/* 设置符号项与哈稀表长度 */
	base->symtab_size = curr_size;
	base->hashtab_size = (nbucket + nchain + 1) * sizeof(unsigned);

	/* 忽略第一个空符号 */
	base->index = 1;
	return 0;
}

int elf_symbase_close(void* symbase) {
	if (symbase == NULL) return -1;
	elf_tools_symtab* base = (elf_tools_symtab*)symbase;

	if (base->symtab) elf_symtab_release((void**)&(base->symtab));
	if (base->hashtab) elf_hashtab_release(&(base->hashtab));
	if (base->strtab) {
		delete [] base->strtab;
		base->strtab = NULL;
	}

	memset(base, 0, sizeof(*base));
	return 0;
}

int elf_symbase_add(void* symbase,
					const char* name,
					unsigned st_value,
					unsigned st_size,
					unsigned bind,
					unsigned type,
					unsigned char st_other,
					unsigned short st_shndx,
					int muti_string) {
	if ((name == NULL) || (strlen(name) == 0)) return -1;
	if (symbase == NULL) return -2;

	elf_tools_symtab* base = (elf_tools_symtab*)symbase;

	/* 添加到字符串表 */
	unsigned st_name = elf_strtab_add(symbase, name, muti_string);
	
	/* 添加到符号表 */
	int index = base->index;
	int ret = elf_symtab_add(base->symtab,
							 index,
							 st_name,
							 st_value,
							 st_size,
							 bind,
							 type,
							 st_other,
							 st_shndx);
	if (ret != 0) return -3;

	/* 添加到哈稀表 */
	ret = elf_hashtab_add(base->hashtab, name, index);
	if (ret != 0) return -4;

	/* 索引增加 */
	index++;
	base->index = index;
	
	return 0;
}

int elf_symbase_done(void* symbase) {
	XASSERT(symbase);
	elf_tools_symtab* base = (elf_tools_symtab*)symbase;
	elf_hashtab_release((void**)&base->hashtab);
	elf_symtab_release((void**)&base->symtab);
	if (base->strtab)
		delete [] base->strtab;

	memset(base, 0, sizeof(elf_tools_symtab));
	return 0;
}
