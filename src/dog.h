#ifndef __DOG_H__
#define __DOG_H__

struct Extent {
	off_t offset;
	off_t size;
};

struct hack_data {
	unsigned offset;             /* 在壳中的文件偏移 */
	unsigned va;                 /* 在壳中的内存地址 */
	unsigned size;               /* 在壳中的大小 */
	unsigned pt_dynamic_index;   /* 值所在dynamic段的索引 */
	unsigned pt_index;           /* 自身所在段的索引 */

	struct dynamic_value* dv;
	unsigned rel;                /* 用于重定位 */
};

struct dog_header {
	unsigned version;
	unsigned method;
	unsigned magic;
};

typedef int (*pdog_hash)(void *buf, int len, 
						 void *hashv, int *hashv_len);

typedef int (*pdog_encrypt_symmetric)(void *plaintext, int plaintext_size,
									  void **ciphertext, int *ciphertext_size,
									  void *key, int *key_len);

typedef int (*pdog_decrypt_symmetric)(void *ciphertext, int ciphertext_size, 
									  void **plaintext, int *plaintext_size,
									  void *key, int key_len);

typedef int (*pdog_encrypt_stream)(void *plaintext, void *ciphertext, int size, 
								   void *key, int key_len);

typedef int (*pdog_decrypt_stream)(void *ciphertext, void *plaintext, int size,
								   void *key, int key_len);

typedef int (*pdog_encrypt_inside_name)(void *sym,
										void* src, int src_len, 
										void* dst, int *dst_len, 
										unsigned key);

typedef int (*pdog_decrypt_inside_name)(void *sym,
										void *src, int src_len,
										void *dst, int *dst_len,
										unsigned key);
class DogTools {
 public:
	DogTools(InputFile* fi, OutputFile* fo);
	virtual ~DogTools();

 public:
	virtual void init();
	virtual bool can_pack();
	virtual void pack();
	virtual void merge();
	virtual void custom_format();
	virtual bool check_merge_sign(FileBase* fi);

 public:
	void set_options(struct arguments* opts);
	bool check_already_packed(InputFile* fi);

 public:
	int dog_hash(void *buf, int len, 
				 void *hashv, int *hashv_len);
	/* 这套接口是针对分组加密的，也就是允许加密后的密体比
	 * 明文要长
	 */
	int dog_encrypt_symmetric(void *plaintext, int plaintext_size,
							  void **ciphertext, int *ciphertext_size,
							  void *key, int *key_len);
	int dog_decrypt_symmetric(void *ciphertext, int ciphertext_size, 
							  void **plaintext, int *plaintext_size,
							  void *key, int key_len);
	/* 这套接口函数，是流加密的，明文与密体一样长 */
	int dog_encrypt_stream(void *plaintext, void *ciphertext, int size, 
						   void *key, int key_len);
	int dog_decrypt_stream(void *ciphertext, void *plaintext, int size,
						   void *key, int key_len);

	/* 加解密文件 */
	void encrypt_file(const char *name, unsigned key);
	void decrypt_file(const char *name, unsigned key);

 public:
	unsigned* get_textrel_offset_tab();
	unsigned get_textrel_tab_size();
	bool is_compile_with_pic();
	void auto_fill_textrel_tab();

 private:
	virtual unsigned char* merge_mem(unsigned* size);
	virtual bool find_tdog_sign(const void* b, int blen);

	virtual void pack0();
	virtual void pack1();
	virtual void pack2();
	virtual void pack3();

 private:
#ifdef DT_INIT_SPECIAL
	bool dt_init_special();
#endif
	bool the_symbol_is_not_need_rel(unsigned sym_idx);
	unsigned encrypt_inside_symbols(unsigned key);
	unsigned encrypt_inside_symbols_dis(unsigned key);
	//unsigned encrypt_inside_symbols_custom_loader(unsigned key);
	bool find_hook_functions(unsigned char*list, unsigned count, unsigned va);
	unsigned hook_abs_export_functions(unsigned va);
	unsigned infect_darkcode(unsigned char *list, unsigned count);

	static bool is_encrypt_export_function(Elf32_Sym *pSym);
	static bool is_encrypt_include_function(Elf32_Sym *pSym);

typedef bool (*is_encrypt_func_fn)(Elf32_Sym *pSym);/* 加密函数原型 */
	unsigned encrypt_functions(unsigned char **list,
							   unsigned *plist_size,
							   unsigned *plist_count,
							   int has_include_func,
							   int is_include_func_file,
							   const char *include_names,
							   const char *libname,
							   const char *out_name,
							   unsigned key,
							   is_encrypt_func_fn is_encrypt_function,
							   const char *log_filename);
	void fix_entry();
	void fix_exit();
	/* devilogic 2016.4.11 15:56添加
	 * 目标是支持android6.0+
	 * 动态段中的SONAME一定要指向正确的位置
	 */
	//void fix_soname_stridx(unsigned char* ptr);
	void write_loader();
	/* devilogic 2016.4.11添加 */
	void write_sections(unsigned char* ptr);
	void write_header();
	void write_en_functions(MemBuffer *ptr, unsigned offset,
							unsigned char* list, unsigned list_size);
	unsigned copy_orig_rel(MemBuffer *membuf, 
						   unsigned now_offset,
						   unsigned new_pt_dynamic_offset,
						   unsigned pt_dynamic_idx,
						   struct dynamic_value *dt,
						   Elf32_Dyn **relsize_dyn,
						   unsigned added);
	unsigned rel_encrypt_loader_and_codes(unsigned now_offset,
										  Elf32_Dyn **relsize_dyn);
	unsigned rel_remove_elf_header(unsigned rel_append_offset,
								   Elf32_Dyn **relsize_dyn);
	unsigned hide_entry(unsigned rel_append_offset, Elf32_Dyn **relsize_dyn);
	unsigned write_hack_data(unsigned curr_offset);

	void set_input_file_seek(int offset, int where);
	void encrypt_code(const Extent &x);
	//unsigned find_LOAD_gap(Elf32_Phdr const * const phdr,
	//					   unsigned const k, unsigned const nph);
	unsigned encrypt_or_write(unsigned char* in, unsigned size, 
							  unsigned offset, bool en);
	
 private:
	void fill_exspace();

 protected:
	virtual unsigned handle_hack_data_dt_init(struct hack_data* h);
	virtual unsigned handle_hack_data_dt_finit(struct hack_data* h);
	virtual unsigned handle_hack_data_dt_init_array(struct hack_data* h);
	virtual unsigned handle_hack_data_dt_finit_array(struct hack_data* h);
	virtual unsigned handle_hack_data_dt_plt_rel(struct hack_data* h);
	virtual unsigned handle_hack_data_dt_rel(struct hack_data* h);
	virtual unsigned handle_hack_data_dt_symtab(struct hack_data* h);
	virtual unsigned handle_hack_data_dt_strtab(struct hack_data* h);
	virtual unsigned handle_hack_data_dt_hash(struct hack_data* h);

 protected:
	virtual void write_globals();

 private:
	void fix_dt_init_array_for_new_rel(hack_data* h, unsigned char* c);
	unsigned handle_rel_table(hack_data* h);
	void fix_ElfHeader(unsigned char* ptr, unsigned x);
	void fill_textrel_tab(unsigned** buf, unsigned* size,
						  unsigned start, unsigned range);
	Extent *fill_plaintext(unsigned char **buf, unsigned *size,
						   unsigned char **encrypt_code_tab,
						   unsigned *encrypt_code_tab_size);

	void init_encrypt_function();
	void fill_orig_dynamic_info();

 protected:
	bool _use_dt_init;                                        /* 使用dt_init入口 */
	bool _dt_symbolic_is_null;                                /* DT_SYMBOLIC项为NULL */
	bool _has_DT_TEXTREL;                                     /* 存在DT_TEXTREL的动态项目 */
	unsigned* _textrel_tab;
	unsigned _size_textrel_tab;

	/* CRC32的值 */
	unsigned _code_crc32_sign;
	unsigned _code_en_crc32_sign;

#define MAX_SIGN_LENGTH     256    // 2048位

	unsigned char _code_sign[MAX_SIGN_LENGTH];
	unsigned _code_sign_size;
	unsigned _offset_code_sign;

	unsigned char _code_en_sign[MAX_SIGN_LENGTH];
	unsigned _code_en_sign_size;
	unsigned _offset_code_en_sign;

	/* 解密密钥 */
	unsigned char *_decode_key;
	unsigned _decode_key_size;
	unsigned _offset_decode_key;

	unsigned _method;                               /* 加密算法 */
	unsigned _size_encrypt_text;                    /* 加密数据的大小 */
	unsigned _offset_encrypt_text;                  /* 加密数据偏移 */
	unsigned _size_encrypted_text;                  /* 加密数据之后长度 */
	unsigned _offset_encrypted_text;                /* 加密数据之后的偏移 */
	unsigned _offset_encrypt_code_tab;
	unsigned _offset_decrypt_code_tab;

	/* 加密后的缓存 */
	unsigned char *_encode_buf;

	/* 加载器加密内部符号全局变量大小 */
	unsigned _size_loader_encrypt_inside_data_size;
	unsigned _encrypt_inside_data_strtab_offset;
	unsigned _encrypt_inside_data_symtab_offset;
	unsigned _encrypt_inside_data_symnum;
	unsigned _encrypt_inside_data_key;

	unsigned _size_hack_data;                       /* hack数据长度 */
	unsigned _hack_data_offset;                     /* hack数据大小 */
	unsigned _loader_size;                          /* loader全部长度 */
	unsigned _loader_code_size;                     /* loader仅代码长度 */
	unsigned _loader_code_offset;                   /* loader的代码偏移 */
	unsigned _loader_entry_va;                      /* loader的入口点偏移 */
	unsigned _loader_exit_va;                       /* loader的退出点偏移 */
	unsigned _loader_control_va;                    /* loader控制函数的偏移 */
	unsigned _loader_start_va;                      /* loader开始的偏移 */

	struct hack_data _hack_data_dt_init;
	struct hack_data _hack_data_dt_finit;
	struct hack_data _hack_data_dt_init_array;
	struct hack_data _hack_data_dt_finit_array;
	struct hack_data _hack_data_dt_plt_rel;
	struct hack_data _hack_data_dt_rel;
	struct hack_data _hack_data_dt_symtab;
	struct hack_data _hack_data_dt_strtab;
	struct hack_data _hack_data_dt_hash;

	int _dt_init_array_in_rel_type;                 /* dt_init_array 在 重定位表的类型 */

	ElfAndroidDynamicTools* _elftools;
	ElfDynamicTools* _merge_elftools;
	ElfDynamicTools* _pack_elftools;
	
	Loader* _loader;
	
	InputFile* _fi;
	OutputFile* _fo;

	MemBuffer _ibuf;
	MemBuffer _obuf;

	MemBuffer _merge_ibuf;
	MemBuffer _pack_obuf;
	unsigned _pack_obuf_offset;

	p_info _pinfo;
	struct arguments _opts;
	struct dog_header _dog_header;

	Elf32_Phdr _new_phdrs[0x10];

	void* _cipher_handle;
	pdog_hash _dog_hash;
	pdog_encrypt_symmetric _dog_encrypt;
	pdog_decrypt_symmetric _dog_decrypt;
	pdog_encrypt_stream _dog_encrypt_stream;
	pdog_decrypt_stream _dog_decrypt_stream;
	pdog_encrypt_inside_name _dog_encrypt_inside_name;
	pdog_decrypt_inside_name _dog_decrypt_inside_name;

	/* 供加密导出函数使用 */
	unsigned char* _abs_export_function_list;
	unsigned _abs_export_function_list_size;
	unsigned _abs_export_function_list_count;
	unsigned _abs_export_function_list_va;

	/* 供加密一般不为空函数使用 
	 * 在当前为wdog提供帮助
	 */
	unsigned char* _en_function_list;
	unsigned _en_function_list_size;
	unsigned _en_function_list_count;
	unsigned _en_function_list_va;

	/* 扩展空间的大小 */
	unsigned _exspace_size;
	unsigned char *_exspace;

	/* 代码明文表 */
	unsigned char *_plaintext;
	unsigned _plaintext_offset;
	unsigned _plaintext_size;
	unsigned char *_encrypt_code_tab; /* 一项8(unsigned)字节 */
	unsigned _encrypt_code_tab_size;
	unsigned char *_decrypt_code_tab; /* 一项8(unsigned)字节 */
	unsigned _decrypt_code_tab_size;

	/* 原finit在内存中的偏移 */
	unsigned _orig_finit_offset;

	/* 目标文件的exidx段的位置与长度 */
	unsigned _exidx_va;
	unsigned _exidx_size;
};

#endif
