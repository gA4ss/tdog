#ifndef __TDOG_UTIL_H
#define __TDOG_UTIL_H 1

/*************************************************************************
// 支持函数
**************************************************************************/
#include <vector>
using namespace std;

char *fn_basename(const char *name);
int fn_strcmp(const char *n1, const char *n2);
char *fn_strlwr(char *n);
bool fn_has_ext(const char *name, const char *ext, bool ignore_case=true);

bool file_exists(const char *name);
bool maketempname(char *ofilename, size_t size,
                  const char *ifilename, const char *ext, bool force=true);
bool makebakname(char *ofilename, size_t size,
                 const char *ifilename, bool force=true);

unsigned get_ratio(unsigned u_len, unsigned c_len);
void center_string(char *buf, size_t size, const char *s);

int find(const void *b, int blen, const void *what, int wlen);
int mem_replace(void *b, int blen, const void *what, int wlen, const void *r);

void time2str(char *s, size_t size, const time_t *t);
int change_path(char* path);

typedef struct {
	unsigned begin;
	unsigned end;
} thread_group_range;
	
unsigned handle_thread_group(unsigned total, unsigned group,
							 vector<thread_group_range>& range);
unsigned crc32_file(char* path);

#endif
