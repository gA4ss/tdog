#include "globals.h"
#include "mem.h"
#include "file.h"
#include "x_elf_tools.h"
#include "loader.h"
#include "mapper.h"
#include "make_ld.h"
#include "dog.h"

#include <stdio.h>
#include <stdlib.h>

DogTools* g_dog = NULL;

/********************************************************************************/

unsigned umin(unsigned a, unsigned b) {
	return (a < b) ? a : b;
}

unsigned umax(unsigned a, unsigned b) {
	return (a >= b) ? a : b;
}

unsigned up4(unsigned x) {
	return ~3u & (3 + x);
}

unsigned upx(unsigned x) {
	unsigned page_size = 1 << g_opts.page_shift;
	unsigned page_mask = page_size - 1;
	return ~(page_mask) & (page_mask + x);
}

unsigned fpad4(OutputFile *fo) {
	XASSERT(fo);
	unsigned len = fo->st_size();
	unsigned d = 3u & (0 - len);
	unsigned zero = 0;
	writeTarget(fo, &zero, d, TDOG_DEBUG, "Align");
	return d + len;
}

unsigned funpad4(InputFile *fi) {
	XASSERT(fi);
	unsigned d = 3u & (0 - fi->tell());
	if (d)
		fi->seek(d, SEEK_CUR);
	return d;
}

static unsigned g_dbg_off = 0;
static FILE* g_dbg_file = NULL;
static const char* g_dbg_file_path = "./.tdog.dbg";
void writeTarget(void* out, 
								 void* buf, 
								 unsigned len, 
								 bool dbg /*= true*/, 
								 const char* s /*=NULL*/, 
								 unsigned off /*= 0xFFFFFFFF*/, 
								 bool mem /*=false */, 
								 void *mv /*=NULL*/) {
	OutputFile* fo = NULL;
	unsigned char* mo = NULL;
	MemBuffer *membuf = (MemBuffer *)mv;

	XASSERT(buf);

	if ((out == NULL) && (mv == NULL)) {
		ERROR_INTERNAL_EXCEPT("write buffer is empty");
		return;
	}

	if (off == 0xFFFFFFFF)
		g_dbg_off = 0;

	if ((out == NULL) && (mem)) {
		out = (void*)((unsigned char*)(*membuf));
	}

	// /* 检查缓存 */
	if ((mem) && (mv)) {
		unsigned curr_size = membuf->getSize();
		unsigned now_offset = (off == 0xFFFFFFFF) ? 0 : off;
		now_offset += len;
		/* 重新分配内存 */
		if (curr_size < now_offset) {
			unsigned add_size = up4((now_offset - curr_size) * 2);
			membuf->append_alloc(add_size);
		}

		out = (void*)((unsigned char*)(*membuf));
	}

	if (mem) mo = (unsigned char*)out;
	else fo = (OutputFile*)out;

	if (off != 0xFFFFFFFF) {
		if (mem) mo += off;
		else fo->seek(off, SEEK_SET);
	}

	/* 写入 */
	if (mem)
		memcpy(mo, (unsigned char*)buf, len);
	else
		fo->write((unsigned char*)buf, len);

	if (dbg) {

		g_dbg_file = fopen(g_dbg_file_path, "a+");
		if (NULL == g_dbg_file) { 
			DEBUG_INFO("\'%s\' file not open\n", g_dbg_file_path);
			return;
		}

		if (off != 0xFFFFFFFF) {
			if (off > g_dbg_off) {
				g_dbg_off = off;
			} else if (off < g_dbg_off) {
				/* 这是重写需求，直接忽略 */
			}
		}

		if (s) {
			if (g_dbg_file) 
				fprintf(g_dbg_file, 
								"%4X --- %4X(%d) --- %s\n", 
								g_dbg_off, 
								len, 
								len, 
								s);
		} else 
			if (g_dbg_file) 
				fprintf(g_dbg_file, 
								"%4X --- %4X(%d)\n", 
								g_dbg_off, 
								len, 
								len);

		if (g_dbg_file) fflush(g_dbg_file);
		fclose(g_dbg_file);
		g_dbg_off += len;
	}
}

/********************************************************************************/
unsigned get_te16(const void *p) {
	XASSERT(p);
	return (unsigned)(*(unsigned short*)(p));
}

unsigned get_te24(const void *p) {
	XASSERT(p);
	return (unsigned)((*(unsigned*)(p)) & 0xFFFFFF);
}

unsigned get_te32(const void *p) { 
	XASSERT(p);
	return (unsigned)(*(unsigned*)(p));
}

void set_te16(void *p, unsigned v) { 
	XASSERT(p);
	(*(unsigned short*)(p)) = (unsigned short)v;
}

void set_te24(void *p, unsigned v) {
	XASSERT(p);
	*(unsigned*)(p) = (((*(unsigned*)(p)) >> 24) << 24) | (v & 0xFFFFFF);
}

void set_te32(void *p, unsigned v) { 
	XASSERT(p);
	(*(unsigned*)(p)) = (unsigned)v;
}

long safe_read(int fd, void* buf, long size) {
	XASSERT(fd);
	XASSERT(buf);

    unsigned char* b = (unsigned char*) buf;
    long l = 0;
    int saved_errno;
    saved_errno = errno;
    while (l < size) {
        long n = size - l;
        errno = 0; n = read(fd, b, n);
        if (n == 0)
            break;
        if (n < 0) {
#if defined(EAGAIN)
            if (errno == (EAGAIN)) continue;
#endif
#if defined(EINTR)
            if (errno == (EINTR)) continue;
#endif
            if (errno == 0) errno = 1;
            return l;
        }
        b += n; l += n;
    }
    errno = saved_errno;
    return l;
}

long safe_write(int fd, const void* buf, long size) {
	XASSERT(fd);
	XASSERT(buf);

    const unsigned char* b = (const unsigned char*) buf;
    long l = 0;
    int saved_errno;
    saved_errno = errno;
    while (l < size) {
        long n = size - l;
        errno = 0; n = write(fd, b, n);
        if (n == 0)
            break;
        if (n < 0) {
#if defined(EAGAIN)
            if (errno == (EAGAIN)) continue;
#endif
#if defined(EINTR)
            if (errno == (EINTR)) continue;
#endif
            if (errno == 0) errno = 1;
            return l;
        }
        b += n; l += n;
    }
    errno = saved_errno;
    return l;
}

int l_isatty(int fd) {
    if (fd < 0)
        return 0;
	return (isatty(fd)) ? 1 : 0;
}

int l_set_binmode(int fd, int binary) {
    if (fd < 0) return -1;
    UNUSED(binary);
    return 1;
}
