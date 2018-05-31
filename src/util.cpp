#include "conf.h"
#include "util.h"
#include "crc.h"

#include <stdio.h>
#include <string.h>

/*************************************************************************
// find util
**************************************************************************/

int find(const void *b, int blen, const void *what, int wlen) {
	XASSERT(b);
	XASSERT(what);
    if (b == NULL || blen <= 0 || what == NULL || wlen <= 0)
        return -1;

    int i;
    const unsigned char *base = (const unsigned char *) b;
    unsigned char firstc = * (const unsigned char *) what;

    blen -= wlen;
    for (i = 0; i <= blen; i++, base++)
        if (*base == firstc && memcmp(base, what, wlen) == 0)
            return i;

    return -1;
}

int mem_replace(void *bb, int blen, const void *what, int wlen, const void *r) {
	XASSERT(bb);
	XASSERT(what);
	XASSERT(r);

    unsigned char *b = (unsigned char *) bb;
    int boff = 0;
    int n = 0;

    while (blen - boff >= wlen)
    {
        int off = find(b + boff, blen - boff, what, wlen);
        if (off < 0)
            break;
        boff += off;
        memcpy(b + boff, r, wlen);
        boff += wlen;
        n++;
    }
    return n;
}


/*************************************************************************
// filename util
**************************************************************************/

#ifdef WIN32

static const char dir_sep[] = "/\\";
#define fn_is_drive(s)      (s[0] && s[1] == ':')
#define fn_is_sep(c)        (strchr(dir_sep,c) != NULL)
#define fn_skip_drive(s)    (fn_is_drive(s) ? (s) + 2 : (s))
#define fn_tolower(c)       (tolower(((unsigned char)(c))))

#else

static const char dir_sep[] = "/";
#define fn_is_drive(s)      (0)
#define fn_is_sep(c)        ((c) == '/')
#define fn_skip_drive(s)    (s)
#define fn_tolower(c)       (c)

#endif


char *fn_basename(const char *name) {
	XASSERT(name);
    const char *n, *nn;

    name = fn_skip_drive(name);
    for (nn = n = name; *nn; nn++)
        if (fn_is_sep(*nn))
            n = nn + 1;
    return const_cast<char *>(n);
}

bool fn_has_ext(const char *name, const char *ext, bool ignore_case) {
	XASSERT(name);
	XASSERT(ext);

    const char *n, *e;

    name = fn_basename(name);
    for (n = e = name; *n; n++)
        if (*n == '.')
            e = n;
    if (ignore_case)
        return (strcasecmp(ext,e+1) == 0);
    else
        return (fn_strcmp(ext,e+1) == 0);
}


void fn_addslash(char *name, bool slash) {
	XASSERT(name);

    char *p;

    name = fn_skip_drive(name);
    p = name + strlen(name);
    while (p > name && fn_is_sep(p[-1]))
        *p-- = 0;
    if (p > name)
    {
        if (slash)
            *p++ = dir_sep[0];
        *p = 0;
    }
}


char *fn_strlwr(char *n) {
	XASSERT(n);

    char *p;
    for (p = n; *p; p++)
        *p = (char) fn_tolower(*p);
    return n;
}


int fn_strcmp(const char *n1, const char *n2) {
	XASSERT(n1);
	XASSERT(n2);

    for (;;)
    {
        if (*n1 != *n2)
        {
            int c = fn_tolower(*n1) - fn_tolower(*n2);
            if (c)
                return c;
        }
        if (*n1 == 0)
            return 0;
        n1++; n2++;
    }
}


bool fn_is_same_file(const char *n1, const char *n2) {
    /* very simple... */
    if (fn_strcmp(n1, n2) == 0)
        return 1;
    return 0;
}


/*************************************************************************
// time util
**************************************************************************/
#ifdef HAVE_LOCALTIME
void tm2str(char *s, size_t size, const struct tm *tmp) {
	XASSERT(s);
	XASSERT(tmp);

    snprintf(s, size, "%d_%d_%d_%d_%d_%d",
			 (int) tmp->tm_year + 1900, (int) tmp->tm_mon + 1,
			 (int) tmp->tm_mday,
			 (int) tmp->tm_hour, (int) tmp->tm_min, (int) tmp->tm_sec);

    // snprintf(s, size, "%04d-%02d-%02d %02d:%02d:%02d",
	// 		 (int) tmp->tm_year + 1900, (int) tmp->tm_mon + 1,
	// 		 (int) tmp->tm_mday,
	// 		 (int) tmp->tm_hour, (int) tmp->tm_min, (int) tmp->tm_sec);
}
#endif

#define HAVE_CTIME
void time2str(char *s, size_t size, const time_t *t) {
    XASSERT(size >= 18);
#ifdef HAVE_LOCALTIME
    tm2str(s, size, localtime(t));
#elifdef HAVE_CTIME
    const char *p = ctime(t);
    memset(s, ' ', 16);
    memcpy(s + 2, p + 4, 6);
    memcpy(s + 11, p + 11, 5);
    s[16] = 0;
#else
	UNUSED(t);
    s[0] = 0;
#endif
}

/*************************************************************************
// misc.
**************************************************************************/
void center_string(char *buf, size_t size, const char *s) {
	XASSERT(buf);

    size_t l1 = size - 1;
    size_t l2 = strlen(s);
    XASSERT(size > 0);
    XASSERT(l2 < size);
    memset(buf, ' ', l1);
    memcpy(buf+(l1-l2)/2, s, l2);
    buf[l1] = 0;
}


bool file_exists(const char *name) {
	XASSERT(name);

    int fd, r;
    struct stat st;

    /* return true if we can open it */
    fd = open(name, O_RDONLY, 0);
    if (fd >= 0) {
        (void) close(fd);
        return true;
    }

    /* return true if we can stat it */
    //memset(&st, 0, sizeof(st));
    r = stat(name, &st);
    if (r != -1)
        return true;

    /* return true if we can lstat it */
#if (HAVE_LSTAT)
    //memset(&st, 0, sizeof(st));
    r = lstat(name, &st);
    if (r != -1)
        return true;
#endif

    return false;
}


bool maketempname(char *ofilename, size_t size,
                  const char *ifilename, const char *ext, bool force) {
	XASSERT(ofilename);
	XASSERT(ifilename);

    char *ofext = NULL, *ofname;
    int ofile;

    if (size <= 0)
        return false;

    strcpy(ofilename, ifilename);
    for (ofname = fn_basename(ofilename); *ofname; ofname++)
    {
        if (*ofname == '.')
            ofext = ofname;
    }
    if (ofext == NULL)
        ofext = ofilename + strlen(ofilename);
    strcpy(ofext, ext);

    for (ofile = 0; ofile < 1000; ofile++)
    {
        assert(strlen(ofilename) < size);
        if (!file_exists(ofilename))
            return true;
        if (!force)
            break;
        snprintf(ofext, 5, ".%03d", ofile);
    }

    ofilename[0] = 0;
    return false;
}


bool makebakname(char *ofilename, size_t size,
                 const char *ifilename, bool force)
{
    char *ofext = NULL, *ofname;
    int ofile;

    if (size <= 0)
        return false;

    strcpy(ofilename, ifilename);
    for (ofname = fn_basename(ofilename); *ofname; ofname++)
    {
        if (*ofname == '.')
            ofext = ofname;
    }
    if (ofext == NULL)
    {
        ofext = ofilename + strlen(ofilename);
        strcpy(ofext, ".~");
    }
    else if (strlen(ofext) < 1 + 3)
        strcat(ofilename, "~");
    else
        ofext[strlen(ofext)-1] = '~';

    for (ofile = 0; ofile < 1000; ofile++)
    {
        XASSERT(strlen(ofilename) < size);
        if (!file_exists(ofilename))
            return true;
        if (!force)
            break;
        snprintf(ofext, 5, ".%03d", ofile);
    }

    ofilename[0] = 0;
    return false;
}

unsigned get_ratio(unsigned u_len, unsigned c_len) {
    const unsigned n = 1000000;
    if (u_len <= 0)
        return c_len <= 0 ? 0 : n;
    return (unsigned) ((c_len * (double)n) / u_len);
}

int change_path(char* path) {
	XASSERT(path);
	
	char *plocal = NULL;
	plocal = realpath(path, NULL); 
	if (plocal) strcpy(path, plocal); //文件不存在返回NULL
	free(plocal);
	plocal = NULL;
	
	return 0;
}

unsigned handle_thread_group(unsigned total, unsigned group,
							 vector<thread_group_range>& range) {
	UNUSED(range);
	UNUSED(total);
	/* 如果进行了分组 */
	if (group) {
		
	} else {
		
	}

	return 0;
}

unsigned crc32_file(char* path) {
	FILE* fp = fopen(path, "rb");
	if (fp == NULL) return 0;

	fseek(fp, 0, SEEK_END);
	unsigned size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	unsigned char* buf = new unsigned char [size+1];
	fread(buf, 1, size, fp);
	unsigned crc = 0;
	crc = crc32(buf, size);
	if (buf) delete [] buf;
	fclose(fp);
	return crc;
}
