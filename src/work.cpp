#include "globals.h"
#include "mem.h"
#include "file.h"
#include "fuck.h"
#include "hack.h"
#include "x_elf_tools.h"
#include "mapper.h"
#include "make_ld.h"
#include "loader.h"
#include "dog.h"
#include <dlfcn.h>

extern FILE* g_output_fp;/* main */

#if !defined(SH_DENYRW)
#  define SH_DENYRW     (-1)
#endif
#if !defined(SH_DENYWR)
#  define SH_DENYWR     (-1)
#endif

#define IGNORE_ERROR(var)        UNUSED(var)

/* 对一个文件进行处理 */
typedef void (*_handle_file)(InputFile*, OutputFile*, void*, void*);
static void do_one_file(const char *iname, char *oname, 
						_handle_file hacker, void* user_data, void* user_result) {
	XASSERT(iname);

    int r;
    InputFile fi;
	OutputFile fo;

	/* 打开输入文件 */
	r = open_file(iname, &fi, false);

	/* 获取输入文件的时间戳 */
#if (USE_FTIME)
    struct ftime fi_ftime;
	r = get_file_time(&fi, &fi_time);
#endif


	/* 可以没有输出文件 */
	if (oname) {

		/* 输出到某个文件 */
		char tname[128];
		if (oname)
			strcpy(tname,oname);
		else {
			if (!maketempname(tname, sizeof(tname), iname, ".tdog"))
				ERROR_IO_EXCEPT("could not create a temporary file name %s", tname);
		}

		/* 首先改变权限,然后删除 */
		if (file_exists(tname)) {
#if (HAVE_CHMOD)
			File::chmod(tname, 0777);
#endif
			File::unlink(tname);
		}

		int flags = O_CREAT | O_WRONLY | O_BINARY | O_EXCL;
		int shmode = SH_DENYWR;
#if defined(__MINT__)
		flags |= O_TRUNC;
		shmode = O_DENYRW;
#endif
		/*
		 * 不能使用open()因为umask
		 * int omode = st.st_mode | 0600;
		 */
		int omode = 0600;
		omode = 0666;
		r = open_file(tname, flags, shmode, omode, &fo, true);
	}

	/* 是否启用了--auto-cache-size选项 */
	if (g_opts.auto_cache_size) {
		unsigned fi_cache_size = up4(fi.st_size() / 2);
		unsigned loader_cache_size = 0;

		/* 如果没有keep-code-local选项则加大空间 */
		if (g_opts.keep_code_local == 0) {
			fi_cache_size += fi.st_size();
		}

		/* 计算导入的加载器的大小 */
		if (g_opts.import_loader) {
			InputFile loader_fi;
			open_file(g_opts.loader_path, &loader_fi, false);
			loader_cache_size = up4(loader_fi.st_size() * 1.5);
			loader_fi.closex();
		}

		/* 如果存在重定位表构造 */
		if (g_opts.reloc_encrypt_codes) {
			fi_cache_size += up4(fi.st_size() * 2);
		}

		if (g_opts.reloc_encrypt_loader) {
			fi_cache_size += up4(loader_cache_size);
		}

		if (g_opts.reloc_remove_elf_header) {
			fi_cache_size += up4(fi.st_size());
		}

		fi_cache_size *= 2;

		unsigned new_cache_size = fi_cache_size + loader_cache_size;
		g_opts.cache_size = new_cache_size;
	}

	/* 处理命令 
	 * 向壳管理器传入输入文件与选项
	 */
	hacker(&fi, &fo, user_data, user_result);

	if (oname) {
		// 复制输入文件的时间戳到输出文件的时间戳
		if (oname[0] && fo.isOpen()) {
#if (USE_FTIME)
			r = set_file_time(&fo, &fi_ftime);
			IGNORE_ERROR(r);
#endif
		}

		/* 关闭文件 */
		fo.closex();
	}
	
	/* 关闭输入文件 */
	fi.closex();

	if (oname) {
		/* 备份文件 */
		if (g_opts.backup) {
			/* 符合illa的需求 */
			/* 原文件名为备份，后缀有tdog则为保护过后的 */
			// if (oname[0]) {
			// 	/* 备份文件 */
			// 	char bakname[128];
			// 	if (!makebakname(bakname, sizeof(bakname), iname))
			// 		ERROR_INTERNAL_EXCEPT("could not create a backup file name %s", bakname);
			// 	File::rename(iname,bakname);
			// 	File::rename(oname,iname);
			// }/* endif */
		} else {
			File::unlink(iname);
			/* 指定输出路径 */
			if (g_opts.output_file)
				File::rename(oname, g_opts.output_path);
			else
				File::rename(oname, iname);
		}/* end else */

		/* 复制文件属性 */
		if (g_opts.copy_file_attribute) {
			if (oname[0]) {
				r = copy_file_attribute(oname);
				IGNORE_ERROR(r);
			}/* end if */
		}/* end if */
	}/* end if */
}

/* 设置断点 */
#define bkpt 0xe7f001f0
void set_breakpoint(InputFile* fi, OutputFile* fo, 
					void* _offset, void* result) {
	XASSERT(fi);
	XASSERT(fo);

	off_t offset = (off_t)_offset;
	if (result) *(unsigned*)result = 0;

	/* 读取 */
	unsigned file_size = fi->st_size();
	unsigned char* buf = new unsigned char [file_size];
	if (buf == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new unsigned char []");
		return;
	}
	fi->readx(buf, file_size);
	fi->closex();
	fo->write(buf, file_size);
	if (buf) delete [] buf; buf = NULL;

	/* 读取原始的值 */
	fo->seek(offset, SEEK_SET);
	unsigned orign = 0;
	fo->readx(&orign, sizeof(unsigned));
	orign = get_te32(&orign);

	/* 写入断点 */
	unsigned bk = 0;
	set_te32(&bk, bkpt);
	fo->seek(offset, SEEK_SET);
	fo->rewrite(&bk, sizeof(unsigned));
	fo->closex();

	if (result) *(unsigned*)result = orign;

	return;
}

/* 打印代码重定位偏移表的大小 */
void print_trt_size(InputFile* fi, OutputFile* fo, 
					void* opts, void* result) {
	XASSERT(fi);
	XASSERT(fo);
	XASSERT(opts);
	UNUSED(result);
	
	g_dog = new DogTools(fi, fo);
	g_dog->set_options((struct arguments*)opts);

	/* 检查是否已经被加壳 */
	if (g_dog->check_already_packed(fi) == true) {
		ERROR_ALREADY_PROTECTED_EXCEPT(NULL);
	}

	g_dog->init();

	if (g_dog->can_pack() == false) {
		ERROR_CAN_NOT_PROTECT_EXCEPT(NULL);
	}
	
	if (g_dog->is_compile_with_pic() == false) {
		printf_msg("this target has not text relocate table\n");
		return;
	}

	g_dog->auto_fill_textrel_tab();

	unsigned size = g_dog->get_textrel_tab_size();
	printf_msg("textrel table size = %d\n", size);	
}

/* 剔除无用的信息 */
void strip_unused(InputFile* fi, OutputFile* fo, 
				  void* param, void* result) {
	XASSERT(fi);
	XASSERT(fo);

	UNUSED(param);
	UNUSED(result);

	Elf32_Ehdr hdr;
	Elf32_Phdr phdr_table[0x10];
	unsigned phdr_count;
	int file_size;

	file_size = (int)fi->st_size();
	printf_msg("before file size = %d bytes\n", file_size);

	fi->seek(0, SEEK_SET);
	fi->readx(&hdr, sizeof(Elf32_Ehdr));
	
	phdr_count = hdr.e_phnum;
	if (phdr_count > 0x10) {
		return;
	}

	fi->seek(hdr.e_phoff, SEEK_SET);
	fi->readx(&phdr_table, sizeof(Elf32_Phdr) * phdr_count);

	/* 计算PT_LOAD段所需的大小 */

    unsigned min_offset = 0xFFFFFFFFU;
    unsigned max_offset = 0x00000000U;

    for (unsigned short i = 0; i < phdr_count; ++i) {
        const Elf32_Phdr* phdr = &phdr_table[i];

        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        if (phdr->p_offset < min_offset) {
            min_offset = phdr->p_offset;
        }

        if (phdr->p_offset + phdr->p_filesz > max_offset) {
            max_offset = phdr->p_offset + phdr->p_filesz;
        }
    }

    if (min_offset > max_offset) {
        return;
    }

    unsigned load_file_size = max_offset - min_offset;
	unsigned char* buf = new unsigned char [load_file_size + 0x10];
	fi->seek(0, SEEK_SET);
	fi->readx(buf, load_file_size);

	/* 写入 */
	fo->seek(0, SEEK_SET);
	fo->write(buf, load_file_size);
	fpad4(fo);
	fo->seek(0, SEEK_END);

	file_size = (int)fo->st_size();
	printf_msg("after file size = %d bytes\n", file_size);

	return;
}

/* 调用unlink删除文件 */
static void unlink_ofile(char *oname)
{
	if (oname && oname[0]) {
#if (HAVE_CHMOD)
		File::chmod(oname, 0777);
#endif
		File::unlink(oname);
		oname[0] = 0;
	}
}

/* 主程序入口 
 * i : 第一个目标文件在命令行中的索引
 * argc, argv : 命令行
 */
void do_files(int i, int argc, char *argv[]) {
	/* 遍历获取所有要加壳的文件 */
	if (i >= argc) {
		if (g_opts.show_help) {
			show_help();
		}
		
		if (g_opts.show_version) {
			printf_msg("%s\n", TDOG_VERSION);
		}
	} else {
		for ( ; i < argc; i++) {
			const char *iname = argv[i];                /* 获取要加壳的文件名 */
			char oname[128];

			/* 输出文件名 */
			strcpy(oname, iname);
			strcat(oname, ".tdog");

			try {
				if (g_opts.protect) {
					do_one_file(iname, oname, 
								fuckyou, (void*)&(g_opts), NULL);
				} else if (g_opts.analyze) {
					do_one_file(iname, NULL, hackme,
								(void*)&(g_opts), NULL);
				} else if (g_opts.merge_segments) {
					do_one_file(iname, oname, 
								fuckme, (void*)&(g_opts), NULL);
				} else if (g_opts.custom_format) {
					do_one_file(iname, oname, 
								fuckher, (void*)&(g_opts), NULL);
				} else if (g_opts.set_breakpoint) {
					off_t offset = g_opts.breakpoint;
					unsigned orig_v = 0;

					printf_msg("set offset = 0x%x\n", (unsigned)offset);
					do_one_file(iname, oname, 
								set_breakpoint, (void*)offset, (void*)&orig_v);
					printf_msg("orig value = 0x%x\n", orig_v);
				} else if (g_opts.strip_unused) {
					do_one_file(iname, oname, 
								strip_unused, NULL, NULL);
				} 
				else if (g_opts.print_textrel_tab_size) {
					do_one_file(iname, NULL, 
								print_trt_size, (void*)&(g_opts), NULL);
				} 
				else {
				}/* end else */
			} catch (const ExceptionBase &e) {
				unlink_ofile(oname);
				printf_msg(e.what());
				if (g_opts.output_file)
					if (g_output_fp) fclose(g_output_fp);
			}
		}/* end for */
	}/* end else */
}
