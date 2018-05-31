#ifndef __TDOG_X_ELF_TOOLS_H__
#define __TDOG_X_ELF_TOOLS_H__

#include "analyze.h"

class ElfTools {
 public:
	ElfTools();
	ElfTools(InputFile* fi);
	virtual ~ElfTools();

 public:
	virtual int init_datas();
	virtual int init(bool skip_note=false, bool elfrel=false);
	virtual int init_merge(unsigned char* mem, unsigned mem_size);
	virtual int init_merge_ptr(unsigned char* ptr, unsigned mem_size);
	virtual int update_merge_mem(unsigned add_size=0);
	virtual int set_target_file(InputFile* fi);
	virtual bool is_objfile();

 public:
	void reset_phdr(unsigned char* outbuf, 
					unsigned outsize,
					int dummy_it=1);
	int analyze(elf_analyze_options* opts = NULL);
	Elf32_Shdr* get_got();
	Elf32_Shdr* get_text();
	int check_elf_header(Elf32_Ehdr const *ehdr);
	int check_elf_object_header(Elf32_Ehdr const *ehdr);
	int check_android_elf_header(Elf32_Ehdr* ehdr);

	bool is_in_PT_LOAD(unsigned value);
	unsigned sizeof_PT_LOAD_file();
	// unsigned sizeof_PT_LOAD_mem();
	void get_symtab();
	void get_strtab();
	unsigned get_load_va();
	unsigned get_lg2_page();
	void get_buildid(const char* b = ".note.gnu.build-id");
	void alloc_note_space();
	void get_note();
	void set_machine(int v);

	unsigned elf_get_offset_from_address(unsigned const addr);
	unsigned elf_get_va_from_offset(unsigned const offset);

	Elf32_Shdr *elf_find_section_name(char const * const name);
	Elf32_Shdr *elf_find_section_type(unsigned const type);

	Elf32_Rel* elf_if_rel_object(Elf32_Rel* r, unsigned count, unsigned va);
 public:
	unsigned _size_elf_hdrs;

	unsigned _load_va;
	unsigned _lg2_page;
	unsigned _page_size;
	unsigned _page_mask;

	unsigned _ei_class;
	unsigned _ei_data;
	unsigned _ei_machine;
	unsigned _ei_osabi;
	unsigned _ei_version;

	Elf32_Shdr* _strtab;
	char* _strings;
	unsigned _size_strtab;
	unsigned _strtab_inside_offset;

	Elf32_Shdr* _symtab;
	unsigned _size_symtab;
	unsigned _symtab_inside_offset;

	Elf32_Ehdr* _ehdri;
	Elf32_Phdr* _phdri;
	Elf32_Shdr* _shdri;

	/* section name list */
	Elf32_Shdr* _sec_strndx;
	char* _shstrtab;
	
	unsigned _phoff;
	unsigned _shoff;

	unsigned _phnum;
	unsigned _shnum;

	unsigned _type;
	unsigned _sz_phdrs;

	unsigned char* _buildid;
	unsigned _size_buildid;
	unsigned char* _note;
	unsigned _size_note;

 public:
	InputFile* _fi;                                            /* 输入文件 */
	unsigned _size_file_buffer;                                /* 文件大小 */
	unsigned char* _file;                                      /* 以文件形式打开的映像*/
	MemBuffer _file_buffer;                                    /* 文件缓存 */
	elf_file *_xfile;

 private:
	bool _elfrel;                                              /* 重定位文件 */
};

/* dynamic中的数据 */
struct dynamic_value {
	union {
		unsigned exist;                                            /* 当前这个项是否存在 */
		Elf32_Dyn* dyn;
	};

	union {
		unsigned value;                                        /* dt_dynamic的值部分 */
		unsigned va;
		unsigned size;
	};

	union {
		unsigned aux_value;                                    /* 辅助数据,按照每个dt_dynamic
																* 不同而不同
																*/
		unsigned offset;
	};
	unsigned char* context;                                    /* 辅助值所指向的内容 */
	unsigned inside_offset;                                    /* 值所在PT_DYNAMIC的文件偏移 */
	unsigned char* inside;                                     /* 值位置的文件指针 */

	/* 关联的dynamic项 */
	struct dynamic_value* support;
};

class ElfDynamicTools : public ElfTools {
	typedef ElfTools super;
 public:
	ElfDynamicTools();
	ElfDynamicTools(InputFile* fi);
	virtual ~ElfDynamicTools();

 public:
	virtual int init(bool custom_support=false, bool elfrel=false);
	virtual int init_merge(unsigned char* mem, unsigned mem_size);
	virtual int init_merge_ptr(unsigned char* ptr, unsigned mem_size);
	virtual int update_merge_mem(unsigned add_size=0);
	virtual int init_datas();

 public:
	void set_orig_elf_tools(ElfTools* elftools);
	int analyze(elf_analyze_options* opts = NULL);

 public:
	unsigned get_text_va();
	unsigned get_text_size();
	unsigned get_xct();
	bool check_xct_va();
	unsigned get_yct();
	bool check_yct_va();
	unsigned get_plt();
	bool check_plt_va();
	void get_dynamic_key_context(struct dynamic_value* v, unsigned key, bool aux);
	void get_dynamic_context();
	void get_pt_dynamic();

	Elf32_Dyn const *elf_has_dynamic(unsigned int const key);
	void const *elf_find_dynamic(unsigned int const key);
	unsigned elf_unsigned_dynamic(unsigned int const key);
	unsigned elf_offset_dynamic(unsigned int const key);
	unsigned elf_get_dynamic_va();
	unsigned elf_index_dynamic();

	/* 获取动态的字符串表与符号表 */
	/* char* elf_get_dt_strtab(); */
	/* Elf32_Sym32* elf_get_dt_symtab(); */
	unsigned elf_get_rel_sym_index(vector<unsigned>& ilist);

	/* 2014.10.24添加,动态符号表的数量 */
	unsigned elf_get_dynsym_count();
	
	unsigned gnu_hash(char const *q);
	unsigned elf_hash(char const *p);
	Elf32_Sym* elf_lookup(char const *name);
	unsigned get_dt_init_array_value(unsigned i);
	bool is_has_DT_INIT();
	bool is_has_DT_INIT_ARRAY();
	bool is_compile_with_pic();

 public:
	unsigned _xct_va;
	unsigned _xct_va_delta;
	unsigned _xct_off;

	unsigned _yct_va;
	unsigned _yct_va_delta;
	unsigned _yct_off;

	unsigned _plt_va;
	unsigned _plt_va_delta;
	unsigned _plt_off;

	Elf32_Dyn* _dynseg;
	unsigned _size_dynseg;

	/* 以下在文件形式中可用 */
	Elf32_Shdr* _sec_dynsym;
	Elf32_Shdr* _sec_dynstr;

	/* 2014.10.24添加,动态符号表的数量 */
	unsigned _dynsym_count;

	/* 一些重要的数据 */
	struct dynamic_value _dt_needed;                          /* 依赖库 */
	struct dynamic_value _dt_symbolic;                        /* 符号,ARM忽略 */
	struct dynamic_value _dt_hash;                            /* 字符串哈希表 */
	struct dynamic_value _dt_strtab;                          /* 字符串表 */
	struct dynamic_value _dt_strtabsz;                        /* 字符串表大小 */
	struct dynamic_value _dt_symtab;                          /* 符号表 */
	struct dynamic_value _dt_syment;                          /* 一个符号表项大小 */
	struct dynamic_value _dt_jmprel;                          /* PLT重定位项 */
	struct dynamic_value _dt_pltrelsz;                        /* PLT重定项大小 */
	struct dynamic_value _dt_rel;                             /* 重定表 */
	struct dynamic_value _dt_relsz;                           /* 重定表项大小 */
	struct dynamic_value _dt_pltgot;                          /* PLTGOT */
	struct dynamic_value _dt_debug;                           /* 调试表 */
	struct dynamic_value _dt_init;                            /* 构造函数 */
	struct dynamic_value _dt_finit;                           /* 析构函数 */
	struct dynamic_value _dt_init_array;                      /* 构造函数列表 */
	struct dynamic_value _dt_init_arraysz;                    /* 构造函数列表大小 */
	struct dynamic_value _dt_finit_array;                     /* 析构函数列表 */
	struct dynamic_value _dt_finit_arraysz;                   /* 析构函数列表大小 */
	struct dynamic_value _dt_preinit_array;                   /* 预初始化列表 */
	struct dynamic_value _dt_preinit_arraysz;                 /* 预初始化列表大小 */
	struct dynamic_value _dt_textrel;                         /* 对代码段的重定位 */
	struct dynamic_value _dt_gnu_hash;                        /* GNU哈希表 */

 public:
	ElfTools* _orig_elftools;                                 /* 原始elftools */

 public:
	unsigned char* _file_image;                               /* 以内存形式打开的影像 */
	unsigned _size_file_image;                                /* 加载到内存后的文件映像大小 */
};

class ElfAndroidDynamicTools : public ElfDynamicTools {
	typedef ElfDynamicTools super;
 public:
	ElfAndroidDynamicTools();
	ElfAndroidDynamicTools(InputFile* fi);
	virtual ~ElfAndroidDynamicTools();

 public:
	virtual int init(bool custom_support=false, bool elfrel=false);
	virtual int init_merge_ptr(unsigned char* ptr, unsigned mem_size);
	virtual int update_merge_mem(unsigned add_size=0);
	virtual int init_datas();

 public:
	unsigned get_android_jni_onload();
	bool find_entry_symbols_in_so();
	int analyze(elf_analyze_options* opts = NULL);

 public:
	Elf32_Sym* _jni_onload_sym;
	unsigned _jni_onload_va;
};

/******************************************************************************/
// 构造符号表
/******************************************************************************/
typedef struct {
	unsigned symc;
	unsigned strc;
	unsigned strsz;/* 這裏表示的是在內部維護時所用的緩衝大小 */
	
	Elf32_Sym* symtab;
	char* strtab;
	void* hashtab;
	
	int index;
	union {/* 這裏保存的是最終的字符串表的長度 */
		unsigned strtab_size;
		int strtab_offset;
	};
	unsigned symtab_size;
	unsigned hashtab_size;
} elf_tools_symtab;

	/* 构造符号表相关 */
#define DEF_HASH_NBUCKET 0x20
#define DEF_SYMNAME_LEN  0x100

int elf_strtab_find(void* symbase, const char* s);
int elf_strtab_add(void* symbase, const char* s, int muti_string = 0);
unsigned elf_hashtab_hash(const char* str);
void* elf_hashtab_create(unsigned n, unsigned syms);
void elf_hashtab_release(void** p);
int elf_hashtab_chain_add(unsigned* chain, int index, int symtab_index);
int elf_hashtab_add(void* hashtab, const char* name, int symtab_index);
Elf32_Sym* elf_symtab_create(int count, int* psize);
void elf_symtab_release(void** symtab);
int elf_symtab_add(Elf32_Sym* symtab, 
				   int index,
				   unsigned st_name,
				   unsigned st_value,
				   unsigned st_size,
				   unsigned bind,
				   unsigned type,
				   unsigned char st_other,
				   unsigned short st_shndx);

int elf_symbase_init(void* symbase, int nbucket, int nchain);
int elf_symbase_close(void* symbase);
int elf_symbase_add(void* symbase,
					const char* name,
					unsigned st_value,
					unsigned st_size,
					unsigned bind,
					unsigned type,
					unsigned char st_other,
					unsigned short st_shndx,
					int muti_string = 0);
int elf_symbase_done(void* symbase);

#endif
