#ifndef __TDOG_CONF_H
#define __TDOG_CONF_H 1

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <utime.h>
#include <errno.h>
#include <error.h>
#include <elf.h>

/**************************************************************************/
// 编译选项相关
/**************************************************************************/
//#define UNUSED(var)           (var __attribute__((unused)))
#define UNUSED(var)           ((void) &var)
#define INLINE                __inline__ __attribute__((__always_inline__))
#define NORET                 __attribute__((__noreturn__))
#define NOTHROW               throw()

/**************************************************************************/
// 关闭动态分配
/**************************************************************************/
#define DISABLE_NEW_DELETE												\
	protected: static void operator delete(void*) NOTHROW { }			\
	static void operator delete[](void*) NOTHROW { }					\
private: static void* operator new(size_t) { return NULL; }				\
	static void* operator new[](size_t) { return NULL; }

/**************************************************************************/
// 可移植性
/**************************************************************************/
#ifndef STDIN_FILENO
#  define STDIN_FILENO      (fileno(stdin))
#endif
#ifndef STDOUT_FILENO
#  define STDOUT_FILENO     (fileno(stdout))
#endif
#ifndef STDERR_FILENO
#  define STDERR_FILENO     (fileno(stderr))
#endif

/* #if !defined(S_IWUSR) && defined(_S_IWUSR) */
/* #  define S_IWUSR           _S_IWUSR */
/* #elif !defined(S_IWUSR) && defined(_S_IWRITE) */
/* #  define S_IWUSR           _S_IWRITE */
/* #endif */

/* #if !defined(S_IFMT) && defined(_S_IFMT) */
/* #  define S_IFMT            _S_IFMT */
/* #endif */
/* #if !defined(S_IFREG) && defined(_S_IFREG) */
/* #  define S_IFREG           _S_IFREG */
/* #endif */
/* #if !defined(S_IFDIR) && defined(_S_IFDIR) */
/* #  define S_IFDIR           _S_IFDIR */
/* #endif */
/* #if !defined(S_IFCHR) && defined(_S_IFCHR) */
/* #  define S_IFCHR           _S_IFCHR */
/* #endif */

/* #if !defined(S_ISREG) */
/* #  if defined(S_IFMT) && defined(S_IFREG) */
/* #    define S_ISREG(m)      (((m) & S_IFMT) == S_IFREG) */
/* #  else */
/* #    error "S_ISREG" */
/* #  endif */
/* #endif */
/* #if !defined(S_ISDIR) */
/* #  if defined(S_IFMT) && defined(S_IFDIR) */
/* #    define S_ISDIR(m)      (((m) & S_IFMT) == S_IFDIR) */
/* #  else */
/* #    error "S_ISDIR" */
/* #  endif */
/* #endif */
/* #if !defined(S_ISCHR) */
/* #  if defined(S_IFMT) && defined(S_IFCHR) */
/* #    define S_ISCHR(m)      (((m) & S_IFMT) == S_IFCHR) */
/* #  endif */
/* #endif */

#if !defined(O_BINARY)
#  define O_BINARY  0
#endif

#if !defined(PT_ARM_EXIDX)
#  define PT_ARM_EXIDX    0x70000001      /* .ARM.exidx segment */
#endif

/**************************************************************************/
// 内部头文件
/**************************************************************************/
#include "version.h"
#include "util.h"
#include "errs.h"

/*************************************************************************
// 系统库包含
**************************************************************************/

/* Valgrind内存检测 */
#if (WITH_VALGRIND)
#  include <valgrind/memcheck.h>
#endif

#if !defined(VALGRIND_MAKE_WRITABLE)
#  define VALGRIND_MAKE_WRITABLE(addr,len)      0
#endif
#if !defined(VALGRIND_MAKE_READABLE)
#  if 0
#    define VALGRIND_MAKE_READABLE(addr,len)    (memset(addr,0,len), 0)
#  else
#    define VALGRIND_MAKE_READABLE(addr,len)    0
#  endif
#endif
#if !defined(VALGRIND_DISCARD)
#  define VALGRIND_DISCARD(handle)              ((void)(&handle))
#endif

/* 不能复制结构 */
struct noncopyable
{
protected:
    inline noncopyable() {}
    inline ~noncopyable() {}
private:
    noncopyable(const noncopyable &); // undefined
    const noncopyable& operator=(const noncopyable &); // undefined
};

/* TDOG标志 */
#define TDOG_MAGIC_LE32          0x19831210      /* "TDOG!" */
#define TDOG_MAGIC2_LE32         0x20120214

/*************************************************************************
// 支持平台
**************************************************************************/
#define ARCH_ARM         0
#define ARCH_X86         1
#define ARCH_MIPS        2

/*************************************************************************
// 全局配置
**************************************************************************/
/* main.cpp */
extern const char *progname;

/* work.cpp */
void do_one_file(const char *iname, char *oname);
void do_files(int i, int argc, char *argv[]);

#endif
