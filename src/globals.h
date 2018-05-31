#if !defined(__TDOG_GLOBALS_H__)
#define __TDOG_GLOBALS_H__

#include "conf.h"

/*******************************************************************************/
typedef struct {
	unsigned l_checksum;          /* 校验和 */
	unsigned l_magic;             /* 魔幻数 */
	unsigned short l_lsize;       /* 长度 */
	unsigned char l_version;      /* 版本 */
	unsigned char l_format;       /* 格式 */
} l_info;

typedef struct {
	unsigned p_progid;        /* 程序ID */
	unsigned p_filesize;      /* 文件长度 */
	unsigned p_blocksize;     /* 块大小 */
} p_info;

class DogTools;
extern DogTools* g_dog;

#define MAX_PATH 0x128
/* options.cpp */
struct arguments {
	int strip_unused;
	int use_dt_init_array;
	int hide_entry;
	int copy_file_attribute;
	int backup;
	int set_breakpoint;
	int preserve_build_id;
	int show_help;
	int show_version;
	int protect;
	int import_loader;
	int import_loader_descript;
	int encrypt_inside_data_name;
	int merge_segments;
	int set_page_shift;
	int reloc_encrypt_loader;
	int reloc_remove_elf_header;
	int reloc_encrypt_codes;
	int xdebugger;
	int import_loader_cipher;
	int cipher_thread;
	int quiet;
	int output_file;
	int just_protect_code;
	int muti_string;
	int auto_cache_size;
	int skip_string_in_reloc;
	int fake_pt_dynamic_offset;
	int encrypt_codes;
	int encrypt_codes_key_file;
	int not_throw_except;
	int print;
	int set_arch;
	int save_target_rel;
	int custom_format;
	int encrypt_cf_codes;
	int encrypt_global_codes;
	int control_exp_func;
	int include_exp_fun;
	int print_textrel_tab_size;
	int keep_code_local;
	int select_cipher_type;
	int skip_entry;
	int analyze;
	int disasm;
	int encrypt_func;
	int is_en_func_file;
	int add_needed;
	int encrypt_file;
	int decrypt_file;
	int crypt_key;

	union {
		char needed_name[MAX_PATH];
		char needed_file[MAX_PATH];
	};

	union {
		char en_file_name[MAX_PATH];
		char en_file_list[MAX_PATH];
		char de_file_name[MAX_PATH];
		char de_file_list[MAX_PATH];
	};

	/* 函数加密表 */
	union {
		char en_func_name[MAX_PATH];
		char en_func_file[MAX_PATH];
	};

	union{
		char loader_path[MAX_PATH];
		//char loader_maker[128];
	};
	union {
		char ef_name[MAX_PATH];
		char ef_file[MAX_PATH];
	};
	int cipher_type;   // 1:stream 2:symmetric
	int is_ef_name;
	char loader_descript[MAX_PATH];
	char loader_cipher[MAX_PATH];
	char output_path[MAX_PATH];
	char print_path[MAX_PATH];
	char libname[MAX_PATH];
	const char *include_enfunc_filepath;

	unsigned arch;                         /* 要加密的平台 */
	unsigned code_key;                     /* 加密代码的密钥 */
	unsigned global_code_key;              /* 加密导出函数的key */
	unsigned encrypt_func_key;             /* 加密函数所需的key */
	unsigned breakpoint;                   /* 断点位置 */
	unsigned encrypt_inside_data_name_key; /* 加密内部符号名的密钥 */
	unsigned page_shift;                   /* 页位移 */
	unsigned cache_size;                   /* 缓存大小 */
	int file_count;                        /* 目标文件技术 */
};
extern struct arguments g_opts;    /* 命令选项 */
void usage();
void show_help();
int handle_arguments(int argc, char* argv[]);

/********************************************************************************/
class InputFile;
class OutputFile;
unsigned umin(unsigned a, unsigned b);
unsigned umax(unsigned a, unsigned b);
unsigned up4(unsigned x);
unsigned upx(unsigned x);
unsigned fpad4(OutputFile *fo);
unsigned funpad4(InputFile *fi);
void writeTarget(void* out, void* buf, unsigned len, bool dbg = true, const char* s = NULL, unsigned off = 0xFFFFFFFF, bool mem = false, void *mv = NULL);

unsigned get_te16(const void *p);
unsigned get_te24(const void *p);
unsigned get_te32(const void *p);
void set_te16(void *p, unsigned v);
void set_te24(void *p, unsigned v);
void set_te32(void *p, unsigned v);

long safe_read(int fd, void* buf, long size);
long safe_write(int fd, const void* buf, long size);
int l_isatty(int fd);
int l_set_binmode(int fd, int binary);

#endif
