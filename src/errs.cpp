#include "globals.h"
#include "except.h"
//#include "errs.h" 已经在conf.h中包含

FILE* g_fp_error = stderr;
FILE* g_fp_out = stdout;
int exit_code = 0;

static 
void inside_print(char* buf, FILE* fp, int t, const char* fmt, va_list args) {
	char msg[512];
	char outbuf[1024];

	if ((fmt == NULL) || (fp == NULL)) {
		return;
	}

    //va_start(args, fmt);
    vsprintf(msg, fmt, args);
    //va_end(args);

	if (t != 0) {
		/* 去掉末尾的换行符号 */
		if (msg[strlen(msg)-1] == '\n') msg[strlen(msg)-1] = '\0';
	}

	/* 格式化字符串 */
	char* err_str = dlerror();
	if (t == 1)
		sprintf(outbuf, "[error:%s(errno = %d)]%s\n", err_str, errno, msg);
	else if (t == 2) 
		sprintf(outbuf, "[warning]%s\n", msg);
	else if (t == 3)
		sprintf(outbuf, "[info]%s\n", msg);
	else if (t == 0)
		sprintf(outbuf, "%s", msg);

	/* 输出 */
	fprintf(fp, "%s", outbuf);
	fflush(fp);

	if (buf) strcpy(buf, outbuf);
}

void info_msg(const char* fmt, ...) {
	va_list args;

	if (g_opts.quiet) return;

	va_start(args, fmt);
	inside_print(NULL, g_fp_out, 3, fmt, args);
	va_end(args);
}

void printf_msg(const char* fmt, ...) {
	va_list args;

	if (g_opts.quiet) return;

	va_start(args, fmt);
	inside_print(NULL, g_fp_out, 0, fmt, args);
	va_end(args);
}

void warning_msg(const char* fmt, ...) {
	va_list args;
	
	if (g_opts.quiet) return;

	va_start(args, fmt);
	inside_print(NULL, g_fp_error, 2, fmt, args);
	va_end(args);
}

int error_exit(int e, int tr, const char* fmt, ...) {
	char outbuf[1024];
	va_list args;
	
	exit_code = e;
	memset(outbuf, 0, 1024);

	if (g_opts.quiet == 0) {
		va_start(args, fmt);
		inside_print(outbuf, g_fp_error, 1, fmt, args);
		va_end(args);
	} else {
		sprintf(outbuf, "%d-%d", e, tr);
	}

	/* 抛出异常 */
	if (g_opts.not_throw_except == 0) {
		if (tr)
			throwExcept(e, outbuf);
	} else {
		exit(e);
	}
	return exit_code;
}

void set_error(FILE* x) {
	g_fp_error = x;
}

void set_out(FILE* y) {
	g_fp_out = y;
}
