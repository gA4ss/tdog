#ifndef __TDOG_ERRS_H__
#define __TDOG_ERRS_H__

#include "except.h"

void printf_msg(const char* fmt, ...);
void info_msg(const char* fmt, ...);
void warning_msg(const char* fmt, ...);
int error_exit(int e, int tr, const char* fmt, ...);

void set_error(FILE* x);
void set_out(FILE* y);

extern int exit_code;

/* 出错抛出异常 */
#define ERROR_EXCEPT(e, f, args...) error_exit(e, 1, f, ##args)
#define ERROR_OUT_OF_MEMORY_EXCEPT(f, args...)			\
	error_exit(EXCEPT_OUT_OF_MEMORY, 1, f, ##args)
#define ERROR_ALLOC_MEMORY_FAILED_EXCEPT(f, args...)	\
	error_exit(EXCEPT_ALLOC_MEMORY_FAILED, 1, f, ##args)
#define ERROR_CAN_NOT_OPEN_FILE_EXCEPT(f, args...)	\
	error_exit(EXCEPT_CAN_NOT_OPEN_FILE, 1, f, ##args)
#define ERROR_READ_FILE_FAILED_EXCEPT(f, args...)	\
	error_exit(EXCEPT_READ_FILE_FAILED, 1, f, ##args)
#define ERROR_WRITE_FILE_FAILED_EXCEPT(f, args...)	\
	error_exit(EXCEPT_WRITE_FILE_FAILED, 1, f, ##args)
#define ERROR_IO_EXCEPT(f, args...)				\
	error_exit(EXCEPT_IO, 1, f, ##args)
#define ERROR_ELF_FORMAT_INVALID_EXCEPT(f, args...)		\
	error_exit(EXCEPT_ELF_FORMAT_INVALID, 1, f, ##args)
#define ERROR_CAN_NOT_PROTECT_EXCEPT(f, args...)			\
	error_exit(EXCEPT_CAN_NOT_PROTECT, 1, f, ##args)
#define ERROR_HASH_FAILED_EXCEPT(f, args...)				\
	error_exit(EXCEPT_HASH_FAILED, 1, f, ##args)
#define ERROR_ENCRYPT_FAILED_EXCEPT(f, args...)		\
	error_exit(EXCEPT_ENCRYPT_FAILED, 1, f, ##args)
#define ERROR_ALREADY_PROTECTED_EXCEPT(f, args...)	\
	error_exit(EXCEPT_ALREADY_PROTECTED, 1, f, ##args)
#define ERROR_INTERNAL_EXCEPT(f, args...)		\
	error_exit(EXCEPT_INTERNAL, 1, f, ##args)
#define ERROR_ASSERT_EXCEPT(f, args...)			\
	error_exit(EXCEPT_ASSERT, 1, f, ##args)

/* 出错直接退出,不抛出异常 */
#define ERROR_EXIT(e, f, args...) error_exit(e, 0, f, ##args)
#define ERROR_OUT_OF_MEMORY_EXIT(f, args...)	\
	error_exit(EXCEPT_OUT_OF_MEMORY, 0, f, ##args)
#define ERROR_ALLOC_MEMORY_FAILED_EXIT(f, args...)	\
	error_exit(EXCEPT_ALLOC_MEMORY_FAILED, 0, f, ##args)
#define ERROR_CAN_NOT_OPEN_FILE_EXIT(f, args...)	\
	error_exit(EXCEPT_CAN_NOT_OPEN_FILE, 0, f, ##args)
#define ERROR_READ_FILE_FAILED_EXIT(f, args...)		\
	error_exit(EXCEPT_READ_FILE_FAILED, 0, f, ##args)
#define ERROR_WRITE_FILE_FAILED_EXIT(f, args...)	\
	error_exit(EXCEPT_WRITE_FILE_FAILED, 0, f, ##args)
#define ERROR_IO_EXIT(f, args...)				\
	error_exit(EXCEPT_IO, 0, f, ##args)
#define ERROR_ELF_FORMAT_INVALID_EXIT(f, args...)		\
	error_exit(EXCEPT_ELF_FORMAT_INVALID, 0, f, ##args)
#define ERROR_CAN_NOT_PROTECT_EXIT(f, args...)		\
	error_exit(EXCEPT_CAN_NOT_PROTECT, 0, f, ##args)
#define ERROR_HASH_FAILED_EXIT(f, args...)		\
	error_exit(EXCEPT_HASH_FAILED, 0, f, ##args)
#define ERROR_ENCRYPT_FAILED_EXIT(f, args...)			\
	error_exit(EXCEPT_ENCRYPT_FAILED, 0, f, ##args)
#define ERROR_ALREADY_PROTECTED_EXIT(f, args...)	\
	error_exit(EXCEPT_ALREADY_PROTECTED, 0, f, ##args)
#define ERROR_INTERNAL_EXIT(f, args...)			\
	error_exit(EXCEPT_INTERNAL, 0, f, ##args)
#define ERROR_ASSERT_EXIT(f, args...)			\
	error_exit(EXCEPT_ASSERT, 0, f, ##args)

#if TDOG_DEBUG == 1
#define DEBUG_INFO(f, args...)   info_msg(f, ##args)
#else
#define DEBUG_INFO(f, args...)   do {} while(0)
#endif

/* 断言 */
#define XASSERT(v) do {									\
		if (!!!(v)) ERROR_ASSERT_EXCEPT(NULL);			\
	} while (0)
	  
#define XASSERT2(v)  do {								\
		if (!!!(v)) ERROR_ASSERT_EXIT(NULL);			\
	} while (0)

#define XASSERT_MSG(v, f, args...) do {							\
		if (!!!(v)) ERROR_ASSERT_EXCEPT(f, ##args);				\
	} while (0)
	  
#define XASSERT2_MSG(v, f, args...)  do {					\
		if (!!!(v)) ERROR_ASSERT_EXIT(f, ##args);			\
	} while (0)

#endif
