#include "dog_common.h"
#include "errs.h"
#include <string.h>
#include <vector>
using namespace std;

#define MIN_EN_FUNCTION_SIZE      20

bool DogTools::is_encrypt_export_function(Elf32_Sym *pSym) {
	XASSERT(pSym);
	/* 值不为空，并存在函数名 */
	if ((pSym->st_value != 0) && 
		(pSym->st_name != 0) &&
		(pSym->st_size != 0)) {
		unsigned bind = ELF32_ST_BIND(pSym->st_info);
		unsigned type = ELF32_ST_TYPE(pSym->st_info);
		/* 绑定类型为GLOBAL,TYPE是函数 */
		if ((bind == STB_GLOBAL) && 
			(type == STT_FUNC)) {
			/* 此符号不能是未定义 */
			if (pSym->st_shndx != STN_UNDEF) {
				return true;
			}
		}
	}

	return false;
}

bool DogTools::is_encrypt_include_function(Elf32_Sym *pSym) {
	XASSERT(pSym);
	/* 值不为空，并存在函数名 */
	if ((pSym->st_value != 0) && 
		(pSym->st_name != 0) &&
		(pSym->st_size != 0)) {
		//unsigned bind = ELF32_ST_BIND(pSym->st_info);
		unsigned type = ELF32_ST_TYPE(pSym->st_info);
		/* 如果是函数,并且函数体不为空 */
		if (type == STT_FUNC) {
			/* 此符号不能是未定义 */
			if (pSym->st_shndx != STN_UNDEF) {
				return true;
			}
		}
	}

	return false;
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

static void print_func(const char *filename,
					   unsigned char* ptr, 
					   unsigned size, 
					   char* name, 
					   unsigned offset) {

	if (filename == NULL) return;

	static FILE *g_func = NULL;
	
	if (ptr == NULL) {
		if (g_func != NULL) {
			fclose(g_func);
			g_func = NULL;
		}
		return;
	}

	if (g_func == NULL) {
		g_func = fopen(filename, "w");
		if (g_func == NULL) {
			ERROR_CAN_NOT_OPEN_FILE_EXCEPT("can not open file:%s", filename);
			return;
		}
	}

	fprintf(g_func, "<0x%x:%d>%s\r\n", offset, size, name);
	//printf("<0x%x:%d>%s\r\n", offset, size, name);
	/* 打印内容 */
	for (unsigned i = 0; i < size; i++) {
		if ((i != 0) && (i % 16 == 0)) {
			fprintf(g_func, "\r\n");
			//printf("\r\n");
		}
		if (ptr[i] < 16) {
			fprintf(g_func, "0%x ", ptr[i]);
			//printf("0%x ", ptr[i]);
		} else {
			fprintf(g_func, "%x ", ptr[i]);
			//printf("%x ", ptr[i]);
		}
	}/* end for */
	fprintf(g_func, "\r\n----------\r\n");
	//printf("\r\n----------\r\n");
}

static void write_exp_file(const char *filename,
						   const char *libname,
						   const char *procname,
						   unsigned char* ptr, 
						   unsigned size, 
						   unsigned offset,
						   unsigned key) {
	XASSERT(libname);
	XASSERT(procname);
	XASSERT(ptr);
	XASSERT(size);
	
	if (filename == NULL)
		return;

	static FILE *g_exp_func = NULL;
	
	if (ptr == NULL) {
		if (g_exp_func != NULL)
			fclose(g_exp_func);
		return;
	}

	g_exp_func = fopen(filename, "a+");
	if (g_exp_func == NULL) {
		ERROR_CAN_NOT_OPEN_FILE_EXCEPT("can not open file:%s", filename);
		return;
	}

	/* hash一个so名称->proc名称 */
	char hash_str[256];
	unsigned hash_str_length = 0;

	memset(hash_str, 0, 256);

	sprintf(hash_str, "%s->%s", libname, procname);
	hash_str_length = strlen(hash_str);

	unsigned nhash = crc32((unsigned char*)hash_str, 
						   (unsigned)hash_str_length);
	
	/* 写入 */
	unsigned disp = key;
	fwrite(&disp, sizeof(unsigned), 1, g_exp_func);
	set_te32(&disp, nhash ^ key);
	fwrite(&disp, sizeof(unsigned), 1, g_exp_func);
	set_te32(&disp, offset ^ key);
	fwrite(&disp, sizeof(unsigned), 1, g_exp_func);
	set_te32(&disp, size ^ key);
	fwrite(&disp, sizeof(unsigned), 1, g_exp_func);

	/* 写入函数密文 */
	fwrite(ptr, size, 1, g_exp_func);

	fflush(g_exp_func);
	fclose(g_exp_func);
}

bool DogTools::find_hook_functions(unsigned char*list, unsigned count,
								   unsigned va){
	unsigned char *p = list;
	for (unsigned i = 0; i < count; i++) {
		unsigned old_va = *(unsigned *)p;
		unsigned old_size = *(unsigned *)(p + sizeof(unsigned));
		
		if (va == old_va) {
			return true;
		}

		/* 跳到下一项 */
		p += (sizeof(unsigned) * 2);
		p += old_size;
	}

	return false;
}

unsigned DogTools::hook_abs_export_functions(unsigned va) {
	/* 读取导出表,并将所有的导出函数修订到该有的偏移处 */
	_pack_elftools->update_merge_mem(0);
	unsigned char *ptr = (unsigned char*)_pack_obuf;
	Elf32_Dyn* dynsym = (Elf32_Dyn*)(_pack_elftools->_dt_symtab.dyn);
	Elf32_Dyn* dynstr = (Elf32_Dyn*)(_pack_elftools->_dt_strtab.dyn);
	Elf32_Sym* pSym = (Elf32_Sym*)(ptr + dynsym->d_un.d_val);
	char* pStr = (char*)(ptr + dynstr->d_un.d_val);
	unsigned symnum = _pack_elftools->elf_get_dynsym_count();
	UNUSED(pStr);
	/* 遍历符号表 */
	for (unsigned i = 0; i < symnum; i++, pSym++) {
		/* 判断是否要加密 */
		unsigned target_va = pSym->st_value;
		if (find_hook_functions(_abs_export_function_list,
								_abs_export_function_list_count,
								target_va)) {
			pSym->st_value = va;
		}
	}

	return 0;
}

unsigned DogTools::infect_darkcode(unsigned char *list, unsigned count) {
	unsigned char* ptr = (unsigned char*)_pack_obuf;
	UNUSED(ptr);
	unsigned char *p = list;
	/* 写入黑暗代码 */
	for (unsigned i = 0; i < count; i++) {
		unsigned old_va = *(unsigned *)p;
		unsigned old_size = *(unsigned *)(p + sizeof(unsigned));
		
		/* 得到原始函数的位置 */
		ptr = (unsigned char*)_pack_obuf + old_va;

		/* 可以进行填充黑暗代码了 */
		if (_opts.arch == ARCH_ARM) {
			
		} else if (_opts.arch == ARCH_X86) {
			
		} else if (_opts.arch == ARCH_MIPS) {
			
		} else {
			
		}

		/* 跳到下一项 */
		p += (sizeof(unsigned) * 2);
		p += old_size;
	}
	return 0;
}

/* 这里做导出函数的抽取,是目标程序的抽取 */
unsigned DogTools::encrypt_functions(unsigned char **list,
									 unsigned *plist_size,
									 unsigned *plist_count,
									 int has_include_func,
									 int is_include_func_file,
									 const char *include_names,
									 const char *libname,
									 const char *out_name,
									 unsigned key,
									 is_encrypt_func_fn is_encrypt_function,
									 const char *log_filename) {

	XASSERT(list);
	XASSERT(plist_size);
	XASSERT(plist_count);

	_pack_elftools->update_merge_mem(0);
	Elf32_Dyn* dynsym = (Elf32_Dyn*)(_pack_elftools->_dt_symtab.dyn);
	Elf32_Dyn* dynstr = (Elf32_Dyn*)(_pack_elftools->_dt_strtab.dyn);
	unsigned char* ptr = (unsigned char*)_pack_obuf;
	vector<Elf32_Sym*> ilist;
	vector<unsigned char*> enlist;
	vector<unsigned> keylist;
	char* ef_list = NULL;
	int ret = 0;
	unsigned poly_key = key;
	//const char *exp_name = _opts.include_exp_file;
	//char libname[128]; strcpy(libname, _opts.libname);

	/* 首先判断是否拥有排除文件 */
	if (has_include_func) {
		/* 是包含文件 */
		if (is_include_func_file == 0) {
			unsigned ef_name_len = strlen(include_names) * 2;
			ef_list = new char [ef_name_len];
			if (ef_list == NULL) {
				ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new char []");
				return -1;
			}
			memset(ef_list, 0, ef_name_len);

			/* 分析 */
			char *pel = NULL;
			unsigned index = 0;
			pel = strtok((char*)include_names, ",;-/");
			while (pel) {
				strcpy(&ef_list[index], pel);
				index += strlen(pel);
				ef_list[index] = '\0';
				index++;
				pel = strtok(NULL, ",;-/");
			}
		} else {
			/* 打开文件依次读取 */
			FILE* fp = fopen(include_names, "rb");
			if (fp == NULL) {
				ERROR_CAN_NOT_OPEN_FILE_EXCEPT("can not open file:%s", 
											   include_names);
				return -1;
			}
			fseek(fp, 0, SEEK_END);
			unsigned fsize = ftell(fp);
			fseek(fp, 0, SEEK_SET);

			ef_list = new char [fsize * 2];
			if (ef_list == NULL) {
				ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new char []");
				return -1;
			}
			memset(ef_list, 0, fsize * 2);
			
			unsigned index = 0;
			/* 依次读取每一行 */
			while (!feof(fp)) {
				char* p = get_line(fp);
				if (p == NULL) continue;
				strcpy(&ef_list[index], p);
				index += strlen(p);
				ef_list[index] = '\0';
				index++;
			}
			fclose(fp);
		}
	}

	/* 在文件中的符合表 */
	Elf32_Sym* pSym = (Elf32_Sym*)(ptr + dynsym->d_un.d_val);
	char* pStr = (char*)(ptr + dynstr->d_un.d_val);

	/* 符号的数量 */
	unsigned symnum = _pack_elftools->elf_get_dynsym_count();

	/* 遍历符号表 */
	for (unsigned i = 0; i < symnum; i++, pSym++) {
		/* 加密严格导出函数 */
		if (is_encrypt_function(pSym)) {
			unsigned en_size = pSym->st_size;
			unsigned char* func = ptr + pSym->st_value;
			char *name = pStr + pSym->st_name;
			unsigned char *enbuf = NULL;

			/* 判断是否是thumb指令 */
			if (pSym->st_value % 2) {
				en_size--;
			}

			if (ef_list == NULL) {

				/* 打印函数内容 */
				unsigned sym_offset = pSym->st_value;
				print_func(log_filename, func, en_size, name, sym_offset);

				/* 保存数据 */
				ilist.push_back(pSym);
				/* 进行加密 */
				enbuf = new unsigned char [en_size];
				if (enbuf == NULL) {
					ERROR_ALLOC_MEMORY_FAILED_EXCEPT("alloc encrypt buffer failed");
					return -1;
				}

				/* 生成密码 */
				poly_key = PolyXorKey(poly_key);
				keylist.push_back(poly_key);

				ret = dog_encrypt_stream(func, enbuf, en_size,
										 (int*)&poly_key, sizeof(unsigned));
				if (ret != 0) {
					ERROR_ENCRYPT_FAILED_EXCEPT("stream encrypt failed, err = %x", ret);
					return -1;
				}
				
				/* 写入文件 */
				write_exp_file(out_name, libname, name, 
							   enbuf, en_size, sym_offset, poly_key);

				memset(func, 0, en_size); /* 清除原始函数 */
				enlist.push_back(enbuf);
				if (plist_size)
					(*plist_size) += en_size;
			} else {
				/* 遍历ef_list */
				unsigned index;

				index = 0;
				while (ef_list[index] != '\0') {
					/* 在表中的才进行加密 */
					if (strcmp(&ef_list[index], pStr + pSym->st_name) == 0) {

						unsigned sym_offset = pSym->st_value;
						/* 打印函数内容 */
						print_func(log_filename, func, en_size, 
								   name, sym_offset);

						/* 保存数据 */
						ilist.push_back(pSym);

						/* 分配内存 */
						enbuf = new unsigned char [en_size];
						if (enbuf == NULL) {
							ERROR_ALLOC_MEMORY_FAILED_EXCEPT("alloc encrypt buffer failed");
							return -1;
						}
						memset(enbuf, 0, en_size);

						/* 生成密码 */
						poly_key = PolyXorKey(poly_key);
						keylist.push_back(poly_key);

						/* 进行加密 */
						ret = dog_encrypt_stream(func, enbuf, en_size,
												 (int*)&poly_key, sizeof(unsigned));
						if (ret != 0) {
							ERROR_ENCRYPT_FAILED_EXCEPT("stream encrypt failed, err = %x", ret);
							return -1;
						}/* end if */
						
						/* 写入文件 */
						write_exp_file(out_name, libname, name, 
									   enbuf, en_size, sym_offset, poly_key);

						memset(func, 0, en_size); /* 清除原始函数 */
						enlist.push_back(enbuf);
						if (plist_size)
							(*plist_size) += en_size;
					}/* end if */
					/* 跳过字符串最后一个空字符 */
					index += (strlen(&ef_list[index]) + 1);
				}/* end while */
			}/* end else */


		}/* end if */
	}/* end for  */

	/* 释放空间 */
	if (has_include_func) {
		if (ef_list) delete [] ef_list;
	}

	/* 分配空间 */
	if (plist_count)
		(*plist_count) = ilist.size();
	if (plist_size)
		(*plist_size) += (sizeof(unsigned) * 3) * ilist.size();
	if (list)
		(*list) = new unsigned char [(*plist_size) + 0x10];

	/* 检查分配错误 */
	if ((*list) == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new unsigned char");
	}
	
	/* 写入信息 */
	unsigned char* elist = (unsigned char*)(*list);
	unsigned plus = 0;
	vector<Elf32_Sym*>::iterator iter = ilist.begin();
	vector<unsigned char*>::iterator iter_buf = enlist.begin();
	vector<unsigned>::iterator iter_key = keylist.begin();
	unsigned funcsize = 0;
	unsigned char *pbuf = NULL;
	unsigned disp = 0;
	DEBUG_INFO("------------------------------\n");
	DEBUG_INFO("输出loader的函数密文表\n");
	for (; iter != ilist.end(); iter++, iter_buf++, iter_key++) {
		/* 写入密钥 */
		set_te32(&disp, *iter_key);
		*(unsigned *)(elist + plus) = disp;
		plus += sizeof(unsigned);
		DEBUG_INFO("key = 0x%04x\n", disp);

		/* 写入偏移 */
		DEBUG_INFO("offset = 0x%04x\n", (*iter)->st_value);
		set_te32(&disp, (*iter)->st_value ^ *iter_key);
		*(unsigned *)(elist + plus) = disp;
		plus += sizeof(unsigned);

		/* 写入长度 */
		/* 为了兼容thumb指令 */
		funcsize = (*iter)->st_size;
		if ((*iter)->st_value % 2) funcsize--;
		DEBUG_INFO("size = 0x%04x\n", funcsize);
		set_te32(&disp, funcsize ^ *iter_key);
		*(unsigned *)(elist + plus) = disp;
		plus += sizeof(unsigned);

		/* 写入数据 */
		pbuf = (*iter_buf);
		memcpy(elist + plus, pbuf, funcsize);
		plus += funcsize;
	}/* end for */
	DEBUG_INFO("------------------------------\n");

	/* 使用自身的密钥加密这块内存 */
	ret = dog_encrypt_stream(elist, elist, plus,
							 (int*)&key, sizeof(unsigned));
	if (ret != 0) {
		ERROR_ENCRYPT_FAILED_EXCEPT("stream encrypt failed, err = %x", ret);
		return -1;
	}/* end if */
	
	/* 释放内存 */
	iter_buf = enlist.begin();
	for (; iter_buf != enlist.end(); iter_buf++) {
		if (*iter_buf != NULL) delete [] (*iter_buf);
	}

	enlist.clear();
	ilist.clear();
	keylist.clear();
	print_func(log_filename, NULL, 0, NULL, 0);

	/* 植入黑暗代码
	 */
	infect_darkcode(*list, *plist_count);

	return 0;
}

void DogTools::write_en_functions(MemBuffer *ptr, unsigned offset,
								  unsigned char* list, 
								  unsigned list_size) {
	XASSERT(ptr);
	
	if ((list) && 
		(list_size)) {
		writeTarget(NULL, (void*)list, list_size,
					TDOG_DEBUG, "Encrypt functions", 
					offset, true, (void*)ptr);
	}
}
