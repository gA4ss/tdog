#include "globals.h"
#include "file.h"
#include "mem.h"
#include "x_elf_tools.h"
#include "loader.h"
#include "mapper.h"
#include "make_ld.h"
#include "dog.h"

#include <stdio.h>
#include <stdlib.h>

static
int test_pack() {
	if (g_dog->can_pack())
		return 0;
	return 1;
}

void fuckyou(InputFile* fi, OutputFile* fo, 
			 void* user_data, void* result) {
	XASSERT(fi);
	XASSERT(fo);
	XASSERT(user_data);
	UNUSED(result);

	struct arguments opts;
	memcpy(&opts, (struct arguments*)user_data, sizeof(struct arguments));

	g_dog = new DogTools(fi, fo);
	g_dog->set_options(&opts);

	/* 检查是否已经被加壳 */
	if (g_dog->check_already_packed(fi) == true) {
		ERROR_ALREADY_PROTECTED_EXCEPT(NULL);
	}

	g_dog->init();

	if (test_pack() != 0) {
		ERROR_CAN_NOT_PROTECT_EXCEPT(NULL);
	}

	g_dog->pack();
}

void fuckme(InputFile* fi, OutputFile* fo, 
			void* user_data, void* result) {

	XASSERT(fi);
	XASSERT(fo);
	XASSERT(user_data);
	UNUSED(result);

	struct arguments opts;
	memcpy(&opts, (struct arguments*)user_data, sizeof(struct arguments));

	g_dog = new DogTools(fi, fo);
	g_dog->set_options(&opts);
	g_dog->init();

	if (test_pack() != 0) {
		ERROR_ELF_FORMAT_INVALID_EXCEPT(NULL);
	}

	g_dog->merge();
}

void fuckher(InputFile* fi, OutputFile* fo, 
			 void* user_data, void* result) {

	XASSERT(fi);
	XASSERT(fo);
	XASSERT(user_data);
	UNUSED(result);

	struct arguments opts;
	memcpy(&opts, (struct arguments*)user_data, sizeof(struct arguments));

	g_dog = new DogTools(fi, fo);
	g_dog->set_options(&opts);
	g_dog->init();

	if (test_pack() != 0) {
		ERROR_ELF_FORMAT_INVALID_EXCEPT(NULL);
	}

	g_dog->custom_format();
}
