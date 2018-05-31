#include "dog_common.h"

#include <vector>
#include <algorithm>
using namespace std;

static int get_safe_enbuf_size(int size) {
	return up4(size);
}

void DogTools::fill_exspace() {
	_exspace = new unsigned char [_exspace_size];
	if (_exspace == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new unsigned char []");
		return;
	}
	
	unsigned char *curr = _exspace;
	/* 写入明文HASH值 */
	memcpy(curr, _code_sign, _code_sign_size);
	curr += _code_sign_size;

	/* 写入密钥 */
	memcpy(curr, _decode_key, _decode_key_size);
	curr += _decode_key_size;

	/* 写入密文 */
	if (_opts.keep_code_local == 0) {
		memcpy(curr, _encode_buf, _size_encrypted_text);
		curr += _size_encrypted_text;
	} else {
		/* 明文位置与密文位置相同 */
		//_offset_encrypted_text = _offset_encrypt_text;
	}

	/* 写入密文HASH值 */
	memcpy(curr, _code_en_sign, _code_en_sign_size);
	curr += _code_en_sign_size;

	/* 写入加密代码偏移表 */
	memcpy(curr, _encrypt_code_tab, _encrypt_code_tab_size);
	curr += _encrypt_code_tab_size;

	/* 写入解密代码偏移表 */
	memcpy(curr, _decrypt_code_tab, _decrypt_code_tab_size);
	curr += _decrypt_code_tab_size;

	/* 检验 */
	if (((unsigned)(curr - _exspace)) > _exspace_size) {
		ERROR_INTERNAL_EXCEPT("write size is bigger than exspace");
		return;
	}
}

typedef struct _encode_block {
	unsigned char *buf;
	unsigned size;
} encode_block;

void DogTools::encrypt_code(const Extent &x) {
	vector<encode_block> encode_blocks;
	vector<encode_block>::iterator iter;
	int ret = 0, i = 0;
	unsigned char *ptr = (unsigned char*)_plaintext;

	/* 要加密代码的偏移与长度 */
	_offset_encrypt_text = x.offset;
	_size_encrypt_text = x.size;
	
	/* 再次清空一下，不为别的只为强调从这里开始为0 */
	_exspace_size = 0;

	info_msg("offset of total of encrypt data on memory = 0x%X\n", 
			 _offset_encrypt_text);
	info_msg("size of total of encrypt data on memory = 0x%X\n", 
			 _size_encrypt_text);

	/* 计算当前代码明文的hash值 */
	if (_dog_hash) {
		_code_sign_size = MAX_SIGN_LENGTH;
		ret = _dog_hash(ptr, _size_encrypt_text,
						_code_sign, (int*)&_code_sign_size);
		if (ret != 0) {
			ERROR_HASH_FAILED_EXCEPT("errcode = %x", ret);
			return;
		}
	} else {
		unsigned crc32_v = 0;
		crc32_v = crc32(ptr, _size_encrypt_text);
		memcpy(_code_sign, &crc32_v, sizeof(unsigned));
		_code_sign_size = sizeof(unsigned);
	}

	/* 打印原始代码的CRC32值 */
	{
		_code_crc32_sign = crc32(ptr, _size_encrypt_text);
		info_msg("hash of code is 0x%4X\n", _code_crc32_sign);
	}

	/* 原始代码HASH值 */
	_offset_code_sign = _exspace_size;
	_exspace_size += _code_sign_size;

	/* 生成key */
	_decode_key_size = sizeof(unsigned);
	_decode_key = new unsigned char [_decode_key_size];
	if (_decode_key == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new unsigned char");
		return;
	}
	memcpy(_decode_key, &_opts.code_key, sizeof(unsigned));

	/* 密钥的偏移 */
	_offset_decode_key = _exspace_size;

	/*!!!
	 * 以下加密算法可能会改变密钥的长度，这样会影响_exspace_size的值，所以
	 * 从这里不能随意的改动_exspace_size的大小。
	 */
	_exspace_size += _decode_key_size;

	/* 开始加密 */
	unsigned start = x.offset;//, range = x.size;
	unsigned offset = 0, block_size = 0;
	unsigned *ect = (unsigned*)_encrypt_code_tab;
	unsigned char *enptr = NULL;
	unsigned len = 0;
	encode_block eb;
	_size_encrypted_text = 0;

	/* 把加密后的数据分配内存，并记录到一个队列当中 */
	const unsigned ect_count = 
		_encrypt_code_tab_size / (sizeof(unsigned) * 2);
	for (i = 0; i < (int)ect_count; i++) {
		offset = *ect++;
		block_size = *ect++;
		ptr = _plaintext + (offset - start);
		
		/* 加密 */
		if (_opts.cipher_type) {
			/* 分组加密 */
			/*!!! 这里也许会改变密钥的长度 */
			unsigned orig_decode_key_size = _decode_key_size;
			ret = dog_encrypt_symmetric(ptr, block_size,
										(void**)&enptr, (int*)&len,
										_decode_key, (int*)&_decode_key_size);
			if (ret != 0) {
				ERROR_ENCRYPT_FAILED_EXCEPT("symmetric encrypt failed");
				return;
			}
			
			/* 更新密钥 */
			if (_decode_key_size != orig_decode_key_size) {
				warning_msg(
							"decode key size is not eqv orig decode key size\n"
							);
				_exspace_size -= orig_decode_key_size;
				_exspace_size += _decode_key_size;
			}
			
		} else {
			/* 流加密 */
			enptr = new unsigned char [block_size+0x10];
			if (enptr == NULL) {
				ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new unsigned char []");
				return;
			}
			ret = dog_encrypt_stream(ptr, enptr, 
									 block_size,
									 _decode_key, _decode_key_size);
			if (ret != 0) {
				ERROR_ENCRYPT_FAILED_EXCEPT("stream encrypt failed");
				return;
			}
			/* 明文密文长度相同 */
			len = block_size;
		}
		_size_encrypted_text += len;
		
		info_msg("encrypt len = %d, decrypt len = %d\n", block_size, len);

		eb.buf = enptr;
		eb.size = len;
		
		encode_blocks.push_back(eb);
		
		enptr = NULL;
		len = 0;
	}/* end for */

	/* 合成一块内存 */
	_encode_buf = new unsigned char [_size_encrypted_text + 0x10];
	if (_encode_buf == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new unsigned char []");
		return;
	}
	
	/* 遍历 */
	unsigned char *tmp = _encode_buf;
	for(iter = encode_blocks.begin();
		iter != encode_blocks.end(); iter++) {
		memcpy(tmp, (*iter).buf, (*iter).size);
		tmp += (*iter).size;
	}
	
	/* 计算解密后的存放数据的内存偏移 */
	if (_opts.keep_code_local == 0) {
		_offset_encrypted_text = _exspace_size;
		_exspace_size += _size_encrypted_text;
	} else {
		_offset_encrypted_text = _offset_encrypt_text;
		/* 密文放到原文的地方,只能是流加密 */
		if (_opts.cipher_type) {
			ERROR_INTERNAL_EXCEPT("keep-code-local just support stream cipher");
			return;
		}

		/* 遍历明文记录表 */
		enptr = _encode_buf;
		ect = (unsigned*)_encrypt_code_tab;
		for (i = 0; i < (int)ect_count; i++) {
			offset = *ect++;
			block_size = *ect++;
			/* 明文位置 */
			ptr = _pack_obuf + offset;
			memcpy(ptr, enptr, block_size);

			/* 密文位置 */
			enptr += block_size;
		}/* end for */
	}

	/* 计算密文的HASH值 */
	if (_dog_hash) {
		_code_en_sign_size = MAX_SIGN_LENGTH;
		ret = _dog_hash(_encode_buf, _size_encrypted_text, 
						_code_en_sign, (int*)&_code_en_sign_size);
		if (ret != 0) {
			ERROR_HASH_FAILED_EXCEPT("errcode = %x", ret);
		}
	} else {
		unsigned crc32_v = 0;
		crc32_v = crc32(_encode_buf, _size_encrypted_text);
		memcpy(_code_en_sign, &crc32_v, sizeof(unsigned));
		_code_en_sign_size = sizeof(unsigned);
	}

	/* 打印加密代码的CRC32值 */
	{
		_code_en_crc32_sign = crc32(_encode_buf, _size_encrypted_text);
		info_msg("hash of encrypted code is 0x%4X\n", _code_en_crc32_sign);
	}

	_offset_code_en_sign = _exspace_size;
	_exspace_size += _code_en_sign_size;
	
	/* 加密代码偏移表 */	
	_offset_encrypt_code_tab = _exspace_size;
	_exspace_size += _encrypt_code_tab_size;

	/* 解密表构造 */
	_decrypt_code_tab_size = _encrypt_code_tab_size;
	_decrypt_code_tab = new unsigned char [_decrypt_code_tab_size];
	if (_decrypt_code_tab == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new unsigned char []");
		return;
	}
	memset(_decrypt_code_tab, 0, _decrypt_code_tab_size);

	/* 解密代码偏移表 */
	_offset_decrypt_code_tab = _exspace_size;
	_exspace_size += _decrypt_code_tab_size;

	/* 遍历并释放内存 */
	iter = encode_blocks.begin();
	unsigned *dett = (unsigned*)_decrypt_code_tab;
	unsigned next_iter = _offset_encrypted_text;
	for(; iter != encode_blocks.end(); iter++) {
		if ((*iter).buf) {
			/* 如果将密文写入到其他位置 */
			if (_opts.keep_code_local == 0) {
				*dett = next_iter;
				*(dett+1) = (*iter).size;
				next_iter += (*iter).size;
				dett += 2;
			}
			
			delete [] (*iter).buf;
		}
	}
	encode_blocks.clear();

	/* 如果将密文写入到原位置,
	 * 与写入到扩展空间不同的是，扩展空间中的密文是纯密文，
	 * 如果中间夹杂的重定位信息则掠过了这些重定位信息
	 */
	if (_opts.keep_code_local) {
		memcpy(_decrypt_code_tab, _encrypt_code_tab, _encrypt_code_tab_size);
	}

	/* 计算扩展空间的大小 */
	_exspace_size = up4(_exspace_size);

	/* 填充扩展空间 */
	fill_exspace();
}

// unsigned DogTools::find_LOAD_gap(Elf32_Phdr const * const phdr,
// 								 unsigned const k, unsigned const nph) {
// 	if (PT_LOAD != get_te32(&phdr[k].p_type)) {
// 		return 0;
// 	}
// 	unsigned const hi = get_te32(&phdr[k].p_offset)
// 		+ get_te32(&phdr[k].p_filesz);
// 	unsigned lo = _elftools->_size_file_buffer;
// 	if (lo < hi)
// 		ERROR_CAN_NOT_PROTECT_EXCEPT("bad input: PT_LOAD beyond end-of-file");
// 	unsigned j = k;
// 	for (;;) { /* 周期性检查 */
// 		++j;
// 		if (nph == j) {
// 			j = 0;
// 		}
// 		if (k == j) {
// 			break;
// 		}
// 		if (PT_LOAD == get_te32(&phdr[j].p_type)) {
// 			unsigned const t = get_te32(&phdr[j].p_offset);
// 			if ((t - hi) < (lo - hi)) {
// 				lo = t;
// 				if (hi == lo) {
// 					break;
// 				}
// 			}
// 		}
// 	}/* end for */
// 	return lo - hi;
// }
