#include "dog_common.h"

DogTools::DogTools(InputFile* fi, OutputFile* fo) {
	_use_dt_init = false;
	_dt_symbolic_is_null = false;
	_has_DT_TEXTREL = false;
	_textrel_tab = NULL;
	_size_textrel_tab = 0;

	_code_crc32_sign = 0;
	_code_en_crc32_sign = 0;

	memset(_code_sign, 0, MAX_SIGN_LENGTH * sizeof(unsigned char));
	_code_sign_size = 0;
	_offset_code_sign = 0;

	memset(_code_en_sign, 0, MAX_SIGN_LENGTH * sizeof(unsigned char));
	_code_en_sign_size = 0;
	_offset_code_en_sign = 0;

	_decode_key = NULL;
	_decode_key_size = 0;
	_offset_decode_key = 0;

	_method = 0;

	_size_encrypt_text = 0;
	_offset_encrypt_text = 0;
	_size_encrypted_text = 0;
	_offset_encrypted_text = 0;
	_offset_encrypt_code_tab = 0;
	_offset_decrypt_code_tab = 0;

	_encode_buf = NULL;

	_size_loader_encrypt_inside_data_size = 0;
	_encrypt_inside_data_strtab_offset = 0;
	_encrypt_inside_data_symtab_offset = 0;
	_encrypt_inside_data_symnum = 0;
	_encrypt_inside_data_key = 0;

	_size_hack_data = 0;
	_hack_data_offset = 0;
	_loader_size = 0;
	_loader_code_size = 0;
	_loader_code_offset = 0;
	_loader_entry_va = 0;
	_loader_exit_va = 0;
	_loader_control_va = 0;
	_loader_start_va = 0;

	memset(&_hack_data_dt_init, 0, sizeof(struct hack_data));
	memset(&_hack_data_dt_finit, 0, sizeof(struct hack_data));
	memset(&_hack_data_dt_init_array, 0, sizeof(struct hack_data));
	memset(&_hack_data_dt_finit_array, 0, sizeof(struct hack_data));
	memset(&_hack_data_dt_plt_rel, 0, sizeof(struct hack_data));
	memset(&_hack_data_dt_rel, 0, sizeof(struct hack_data));
	memset(&_hack_data_dt_symtab, 0, sizeof(struct hack_data));
	memset(&_hack_data_dt_strtab, 0, sizeof(struct hack_data));
	memset(&_hack_data_dt_hash, 0, sizeof(struct hack_data));

	_dt_init_array_in_rel_type = 0;

	_elftools = NULL;
	_merge_elftools = NULL;
	_pack_elftools = NULL;

	_loader = NULL;

	_fi = fi;
	_fo = fo;

	memset(&_pinfo, 0, sizeof(_pinfo));
	memset(&_opts, 0, sizeof(_opts));
	memset(&_dog_header, 0, sizeof(_dog_header));
	memset(&_new_phdrs, 0, sizeof(Elf32_Phdr) * 0x10);

	_pack_obuf_offset = 0;

	_cipher_handle = NULL;
	_dog_hash = NULL;
	_dog_encrypt = NULL;
	_dog_decrypt = NULL;
	_dog_encrypt_stream = NULL;
	_dog_decrypt_stream = NULL;
	_dog_encrypt_inside_name = NULL;
	_dog_decrypt_inside_name = NULL;

	_abs_export_function_list = NULL;
	_abs_export_function_list_size = 0;
	_abs_export_function_list_va = 0;
	_abs_export_function_list_count = 0;

	_en_function_list = NULL;
	_en_function_list_size = 0;
	_en_function_list_va = 0;
	_en_function_list_count = 0;

	_exspace_size = 0;
	_exspace = NULL;

	_plaintext = NULL;
	_plaintext_offset = 0;
	_plaintext_size = 0;
	_encrypt_code_tab = NULL;
	_encrypt_code_tab_size = 0;
	_decrypt_code_tab = NULL;
	_decrypt_code_tab_size = 0;

	_orig_finit_offset = 0;

	_exidx_va = 0;
	_exidx_size = 0;
}

DogTools::~DogTools() {
	if (_plaintext) delete [] _plaintext;
	if (_encrypt_code_tab) delete [] _encrypt_code_tab;
	if (_decrypt_code_tab) delete [] _decrypt_code_tab;
	if (_exspace) delete [] _exspace;
	if ((_encode_buf) && (_size_encrypted_text)) delete [] _encode_buf;
	if ((_decode_key) && (_decode_key_size)) delete [] _decode_key;
	if (_textrel_tab) delete [] _textrel_tab;
	if (_pack_elftools) delete _pack_elftools;
	if (_merge_elftools) delete _merge_elftools;
	if (_elftools) delete _elftools;
	if (_loader) delete _loader;
	if (_cipher_handle) dlclose(_cipher_handle);
	if (_abs_export_function_list) delete [] _abs_export_function_list;
}

void DogTools::init_encrypt_function() {
	/* 获取密码学函数 */
	_dog_hash = (pdog_hash)dlsym(_cipher_handle, "tdog_cipher_hash");
	if (_dog_hash == NULL) {
		ERROR_IO_EXCEPT("dlsym failed : tdog_cipher_hash");
		return;
	}
		
	_dog_encrypt = (pdog_encrypt_symmetric)dlsym(_cipher_handle, 
												 "tdog_cipher_encrypt");
	if (_dog_encrypt == NULL) {
		ERROR_IO_EXCEPT("dlsym failed : tdog_cipher_encrypt");
		return;
	}

	_dog_encrypt_stream = (pdog_encrypt_stream)dlsym(_cipher_handle, 
													 "tdog_encrypt_stream");
	if (_dog_encrypt_stream == NULL) {
		ERROR_IO_EXCEPT("dlsym failed : tdog_encrypt_stream");
		return;
	}

	/* 解密函数不是必须的 */
	_dog_decrypt = (pdog_decrypt_symmetric)dlsym(_cipher_handle, 
												 "tdog_cipher_decrypt");
	if (_dog_encrypt == NULL) {
		info_msg("dlsym failed : tdog_cipher_decrypt");
		return;
	}

	_dog_decrypt_stream = (pdog_decrypt_stream)dlsym(_cipher_handle, 
													 "tdog_decrypt_stream");
	if (_dog_encrypt_stream == NULL) {
		info_msg("dlsym failed : tdog_decrypt_stream");
		return;
	}

	_dog_encrypt_inside_name = 
		(pdog_encrypt_inside_name)dlsym(_cipher_handle,
										"tdog_encrypt_inside_name");
	if (_dog_encrypt_inside_name == NULL) {
		info_msg("dlsym failed : tdog_encrypt_inside_name");
		return;
	}

	_dog_decrypt_inside_name = 
		(pdog_decrypt_inside_name)dlsym(_cipher_handle,
										"tdog_decrypt_inside_name");
	if (_dog_decrypt_inside_name == NULL) {
		info_msg("dlsym failed : tdog_decrypt_inside_name");
		return;
	}
}

void DogTools::init() {
	/* 这里加载加解密SO文件 */
	if (_opts.import_loader_cipher) {
		_cipher_handle = dlopen(_opts.loader_cipher, RTLD_NOW);
		if (_cipher_handle == NULL) {
			ERROR_IO_EXCEPT("dlopen failed : %s", _opts.loader_cipher);
			return;
		}

		init_encrypt_function();
	} else {
		_cipher_handle = NULL;
	}

	_elftools = new ElfAndroidDynamicTools(_fi);
	if (_elftools == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new ElfAndroidDynamicTools");
		return;
	}

	_elftools->set_machine(g_opts.arch);
	_elftools->init(_opts.custom_format, false);
	
	/* 分配缓冲区,一定要在elftools初始化后才进行分配 */
	_ibuf.alloc(_elftools->_size_file_buffer);
	_obuf.alloc(_elftools->_size_file_buffer + 0x1000);
}

bool DogTools::check_already_packed(InputFile* fi) {
	XASSERT(fi);

	unsigned char buf[256];
	off_t offset = fi->st_size() - sizeof(buf);
    fi->seek(offset, SEEK_SET);
    fi->readx(buf, sizeof(buf));
	fi->seek(0, SEEK_SET);
	
	return find_tdog_sign(buf, sizeof(buf));
}

bool DogTools::find_tdog_sign(const void* b, int blen) {
	XASSERT(b);

	unsigned what = TDOG_MAGIC_LE32;
	int boff = find(b, blen, &what, 4);
    if (boff < 0)
        return false;
	return true;
}

struct arguments g_def_opts;
void DogTools::set_options(struct arguments* opts) {
	if (opts)
		memcpy(&_opts, opts, sizeof(_opts));
	else
		memcpy(&_opts, &g_def_opts, sizeof(g_def_opts));
}

void DogTools::set_input_file_seek(int offset, int where) {
	_elftools->_fi->seek(offset, where);
}
