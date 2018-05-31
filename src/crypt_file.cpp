#include "globals.h"
#include "mem.h"
#include "file.h"
#include "crc.h"
#include "xor.h"
#include <dlfcn.h>
#include <string.h>

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

pdog_hash g_dog_hash = NULL;
pdog_encrypt_symmetric g_dog_encrypt = NULL;
pdog_decrypt_symmetric g_dog_decrypt = NULL;
pdog_encrypt_stream g_dog_encrypt_stream = NULL;
pdog_decrypt_stream g_dog_decrypt_stream = NULL;
void *g_cipher_handle = NULL;

void crypt_file_init() {

	/* 这里加载加解密SO文件 */
	if (g_opts.import_loader_cipher) {
		g_cipher_handle = dlopen(g_opts.loader_cipher, RTLD_NOW);
		if (g_cipher_handle == NULL) {
			ERROR_IO_EXCEPT("dlopen failed : %s", g_opts.loader_cipher);
			return;
		}
	}

	/* 获取密码学函数 */
	g_dog_hash = (pdog_hash)dlsym(g_cipher_handle, "tdog_cipher_hash");
	if (g_dog_hash == NULL) {
		ERROR_IO_EXCEPT("dlsym failed : tdog_cipher_hash");
		return;
	}
		
	g_dog_encrypt = (pdog_encrypt_symmetric)dlsym(g_cipher_handle, 
												  "tdog_cipher_encrypt");
	if (g_dog_encrypt == NULL) {
		ERROR_IO_EXCEPT("dlsym failed : tdog_cipher_encrypt");
		return;
	}

	g_dog_encrypt_stream = (pdog_encrypt_stream)dlsym(g_cipher_handle, 
													  "tdog_encrypt_stream");
	if (g_dog_encrypt_stream == NULL) {
		ERROR_IO_EXCEPT("dlsym failed : tdog_encrypt_stream");
		return;
	}

	/* 解密函数不是必须的 */
	g_dog_decrypt = (pdog_decrypt_symmetric)dlsym(g_cipher_handle, 
												  "tdog_cipher_decrypt");
	if (g_dog_encrypt == NULL) {
		info_msg("dlsym failed : tdog_cipher_decrypt");
		return;
	}

	g_dog_decrypt_stream = (pdog_decrypt_stream)dlsym(g_cipher_handle, 
													  "tdog_decrypt_stream");
	if (g_dog_encrypt_stream == NULL) {
		info_msg("dlsym failed : tdog_decrypt_stream");
		return;
	}
}

static void backup_file(char *filename, char* outfilename) {
	FILE *fp = fopen(filename, "r");
	if (fp == NULL) {
		ERROR_CAN_NOT_OPEN_FILE_EXCEPT("can not open file:%s", filename);
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
	fclose(fp);fp = NULL;

	char wfilename[128];
	strcpy(wfilename, filename);
	strcat(wfilename, ".bk");
	fp = fopen(wfilename, "w");
	if (fp == NULL) {
		ERROR_CAN_NOT_OPEN_FILE_EXCEPT("can not open file:%s", wfilename);
		return;
	}
	
	ret = fwrite(ptr, 1, fsize, fp);
	if (ret != fsize) {
		ERROR_WRITE_FILE_FAILED_EXCEPT("write file failed, err = %x", ret);
		return;
	}
	fclose(fp);
	
	if (ptr)
		delete [] ptr;

	strcpy(outfilename, wfilename);
}

static int dog_hash(void *buf, int len, 
					void *hashv, int *hashv_len) {
	if (g_dog_hash) {
		int ret = 0;
		ret = g_dog_hash(buf, len, hashv, hashv_len);
		if (ret != 0) {
			ERROR_HASH_FAILED_EXCEPT("dog_hash errcode = %x", ret);
			return -1;
		}
	}

	return 0;
}

/* 这套接口是针对分组加密的，也就是允许加密后的密体比
 * 明文要长
 */
static int dog_encrypt_symmetric(void *plaintext, int plaintext_size,
								 void **ciphertext, int *ciphertext_size,
								 void *key, int *key_len) {
	if (g_dog_encrypt) {
		int ret = 0;
		ret =  g_dog_encrypt(plaintext, plaintext_size,
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

static int dog_decrypt_symmetric(void *ciphertext, int ciphertext_size, 
								 void **plaintext, int *plaintext_size,
								 void *key, int key_len) {
	if (g_dog_decrypt) {
		int ret = 0;
		ret = g_dog_decrypt(ciphertext, ciphertext_size, 
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
/* 这套接口函数，是流加密的，明文与密体一样长 */
static int dog_encrypt_stream(void *plaintext, void *ciphertext, int size,
							  void *key, int key_len) {
	if (g_dog_encrypt_stream) {
		int ret = 0;
		ret = g_dog_encrypt_stream(plaintext, ciphertext, size, 
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

static int dog_decrypt_stream(void *ciphertext, void *plaintext, int size,
							  void *key, int key_len) {
	if (g_dog_decrypt_stream) {
		int ret = 0;
		ret = g_dog_decrypt_stream(ciphertext, plaintext, size, 
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

typedef struct _enf_header {
	unsigned int magic;
	unsigned int old_size;
	unsigned int new_size;
	unsigned int type;
} enf_header;

void encrypt_file(const char *name, unsigned key, int type) {
	enf_header hdr;
	char curr_name[128];
	backup_file((char*)name, curr_name);

	FILE *fp = fopen(curr_name, "r");
	if (fp == NULL) {
		ERROR_CAN_NOT_OPEN_FILE_EXCEPT("can not open file:%s", curr_name);
		return;
	}

	fseek(fp, 0, SEEK_END);
	int fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	
	hdr.magic = 0xFAC4250B;
	hdr.old_size = fsize;

	if (type == 1) {
		hdr.type = 1;
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
		fclose(fp); fp = NULL;
		
		/* 进行加密 */
		ret = dog_encrypt_stream(ptr, ptr, fsize,
								 (int*)&key, sizeof(unsigned));
		if (ret != 0) {
			ERROR_ENCRYPT_FAILED_EXCEPT("stream encrypt failed, err = %x", ret);
			return;
		}/* end if */
		hdr.new_size = fsize;

		fp = fopen(name, "w");
		if (fp == NULL) {
			ERROR_CAN_NOT_OPEN_FILE_EXCEPT("can not open file:%s", name);
			return;
		}
		
		/* 写入头 */
		ret = fwrite((void*)&hdr, 1, sizeof(hdr), fp);
		if (ret != sizeof(hdr)) {
			ERROR_WRITE_FILE_FAILED_EXCEPT("write file failed, err = %x", ret);
			return;
		}

		/* 写入数据 */
		ret = fwrite(ptr, 1, fsize, fp);
		if (ret != fsize) {
			ERROR_WRITE_FILE_FAILED_EXCEPT("write file failed, err = %x", ret);
			return;
		}
		fclose(fp);
		delete [] ptr;
	} else if (type == 2) {
		hdr.type = 2;
		int key_len = sizeof(unsigned);
		int en_size = 0;
		unsigned char *en_ptr = NULL;
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
		fclose(fp); fp = NULL;
		
		/* 进行加密 */
		ret = dog_encrypt_symmetric(ptr, fsize, (void**)&en_ptr, &en_size, 
									(void*)&key, (int*)&key_len);
		if (ret != 0) {
			ERROR_ENCRYPT_FAILED_EXCEPT("symmetric encrypt failed, err = %x", ret);
			return;
		}/* end if */
		hdr.new_size = en_size;

		fp = fopen(name, "w");
		if (fp == NULL) {
			ERROR_CAN_NOT_OPEN_FILE_EXCEPT("can not open file:%s", name);
			return;
		}
		
		/* 写入头 */
		ret = fwrite((void*)&hdr, 1, sizeof(hdr), fp);
		if (ret != sizeof(hdr)) {
			ERROR_WRITE_FILE_FAILED_EXCEPT("write file failed, err = %x", ret);
			return;
		}

		/* 写入数据 */
		ret = fwrite(en_ptr, 1, en_size, fp);
		if (ret != en_size) {
			ERROR_WRITE_FILE_FAILED_EXCEPT("write file failed, err = %x", ret);
			return;
		}
		fclose(fp);
		delete [] ptr;
		delete [] en_ptr;
	}
}

#if 0
void decrypt_file(const char *name, unsigned key) {
}
#endif

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

/* 加解密文件 */
void encrypt_files(const char *name, unsigned key, int type) {
	if (g_opts.encrypt_file == 1) {
		char *pel = NULL;
		pel = strtok(g_opts.en_file_name, ",");
		while (pel) {
			encrypt_file(pel, key, type);
			pel = strtok(NULL, ",");
		}
	} else if (g_opts.encrypt_file == 2) {
		/* 打开文件依次读取 */
		FILE* fp = fopen(g_opts.en_file_list, "rb");
		if (fp == NULL) {
			ERROR_CAN_NOT_OPEN_FILE_EXCEPT("can not open file:%s", 
										   g_opts.en_file_list);
			return;
		}

		/* 依次读取每一行 */
		while (!feof(fp)) {
			char* p = get_line(fp);
			if (p == NULL) continue;
			encrypt_file(p, key, type);
		}
		fclose(fp);
	}
}

#if 0
void decrypt_files(const char *name, unsigned key, int type) {
}
#endif
