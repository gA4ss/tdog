#include "dog_common.h"

int DogTools::dog_hash(void *buf, int len, 
					   void *hashv, int *hashv_len) {
	if (_dog_hash) {
		int ret = 0;
		ret = _dog_hash(buf, len, hashv, hashv_len);
		if (ret != 0) {
			ERROR_HASH_FAILED_EXCEPT("dog_hash errcode = %x", ret);
			return -1;
		}
	}

	return 0;
}

int DogTools::dog_encrypt_symmetric(void *plaintext, int plaintext_size,
									void **ciphertext, int *ciphertext_size,
									void *key, int *key_len) {
	if (_dog_encrypt) {
		int ret = 0;
		ret =  _dog_encrypt(plaintext, plaintext_size,
							ciphertext, ciphertext_size, 
							key, key_len);
		if (ret != 0) {
			ERROR_ENCRYPT_FAILED_EXCEPT("dog_encrypt errcode = %x", ret);
			return -1;
		}
	} else {
		*ciphertext_size = plaintext_size;
		*ciphertext = (void*)new unsigned char [plaintext_size];
		if (*ciphertext == NULL) {
		    ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new unsigned char");
			return -1;
		}
		memcpy(*ciphertext, plaintext, plaintext_size);
	}
	return 0;
}

int DogTools::dog_decrypt_symmetric(void *ciphertext, int ciphertext_size, 
									void **plaintext, int *plaintext_size,
									void *key, int key_len) {
	if (_dog_decrypt) {
		int ret = 0;
		ret =_dog_decrypt(ciphertext, ciphertext_size, 
						  plaintext, plaintext_size, 
						  key, key_len);
		if (ret != 0) {
			ERROR_ENCRYPT_FAILED_EXCEPT("dog_decrypt errcode = %x", ret);
			return -1;	
		}
	} else {
		*plaintext_size = ciphertext_size;
		*plaintext = (void*)new unsigned char [ciphertext_size];
		if (*plaintext == NULL) {
		    ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new unsigned char");
			return -1;
		}
		memcpy(*plaintext, ciphertext, ciphertext_size);
	}
	return 0;
}

int DogTools::dog_encrypt_stream(void *plaintext, void *ciphertext, int size, 
								 void *key, int key_len) {
	if (_dog_encrypt_stream) {
		int ret = 0;
		ret = _dog_encrypt_stream(plaintext, ciphertext, size, 
								  key, key_len);
		if (ret != 0) {
			ERROR_ENCRYPT_FAILED_EXCEPT("stream encrypt err = %x", ret);
			return -1;
		}
	} else {
		memcpy(ciphertext, plaintext, size);
	}
	return 0;
}

int DogTools::dog_decrypt_stream(void *ciphertext, void *plaintext, int size,
								 void *key, int key_len) {
	if (_dog_decrypt_stream) {
		int ret = 0;
		ret = _dog_decrypt_stream(ciphertext, plaintext, size, 
								  key, key_len);
		if (ret != 0) {
			ERROR_ENCRYPT_FAILED_EXCEPT("stream decrypt err = %x", ret);
			return -1;
		}
	} else {
		memcpy(plaintext, ciphertext, size);
	}
	return 0;
}

void DogTools::encrypt_file(const char *name, unsigned key) {
	FILE *fp = fopen(name, "rw");
	if (fp == NULL) {
		ERROR_CAN_NOT_OPEN_FILE_EXCEPT("can not open file:%s", name);
		return;
	}

	fseek(fp, 0, SEEK_END);
	int fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	
	unsigned char *ptr = new unsigned char [fsize + 0x10];
	if (ptr == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new char []");
		return;
	}
	memset(ptr, 0, fsize + 0x10);

	/* 读取数据 */
	int ret = fread(ptr, 1, fsize, fp);
	if (ret != fsize) {
		ERROR_READ_FILE_FAILED_EXCEPT("read file failed, err = %x", ret);
		return;
	}

	/* 进行加密 */
	ret = dog_encrypt_stream(ptr, ptr, fsize,
							 (int*)&key, sizeof(unsigned));
	if (ret != 0) {
		ERROR_ENCRYPT_FAILED_EXCEPT("stream encrypt failed, err = %x", ret);
		return;
	}/* end if */

	/* 写入数据 */
	ret = fwrite(ptr, 1, fsize, fp);
	if (ret != fsize) {
		ERROR_WRITE_FILE_FAILED_EXCEPT("write file failed, err = %x", ret);
		return;
	}
	
	fclose(fp);
}

void DogTools::decrypt_file(const char *name, unsigned key) {
	FILE *fp = fopen(name, "r");
	if (fp == NULL) {
		ERROR_CAN_NOT_OPEN_FILE_EXCEPT("can not open file:%s", name);
		return;
	}

	fseek(fp, 0, SEEK_END);
	int fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	
	unsigned char *ptr = new unsigned char [fsize + 0x10];
	if (ptr == NULL) {
		ERROR_ALLOC_MEMORY_FAILED_EXCEPT("new char []");
		return;
	}
	memset(ptr, 0, fsize + 0x10);

	/* 读取数据 */
	int ret = fread(ptr, 1, fsize, fp);
	if (ret != fsize) {
		ERROR_READ_FILE_FAILED_EXCEPT("read file failed, err = %x", ret);
		return;
	}

	/* 进行加密 */
	ret = dog_decrypt_stream(ptr, ptr, fsize,
							 (int*)&key, sizeof(unsigned));
	if (ret != 0) {
		ERROR_ENCRYPT_FAILED_EXCEPT("stream decrypt failed, err = %x", ret);
		return;
	}/* end if */

	/* 写入数据 */
	ret = fwrite(ptr, 1, fsize, fp);
	if (ret != fsize) {
		ERROR_WRITE_FILE_FAILED_EXCEPT("write file failed, err = %x", ret);
		return;
	}
	
	fclose(fp);
}

