#include "globals.h"
// #include "mem.h"
// #include "file.h"
// #include "x_elf_tools.h"
// #include "mapper.h"
// #include "loader.h"
// #include "make_ld.h"

/* 程序名与参数 */
const char *argv0 = "";
const char *progname = "";
FILE* g_output_fp = NULL;
FILE* g_use_log_fp = NULL;
time_t g_time = {0};
static void write_use_log(int argc, char* argv[]) {
	
	char path[128];
	strcpy(path, ".tdog.use");
	change_path(path);

	g_use_log_fp = fopen(path, "wb");
	if (g_use_log_fp == NULL)  return;

	fseek(g_use_log_fp, 0, SEEK_END);
	int size = ftell(g_use_log_fp);

	/* 如果超过2MB则备份 */
	if (size >= 1024*1024*2) {
		fclose(g_use_log_fp);
		char tmp[128];
		char path2[128];
		time2str(tmp, 128, &g_time);
		sprintf(path2, ".tdog_use.%s", tmp);
		change_path(path2);
		rename(path, path2);
		
		g_use_log_fp = fopen(path, "wb");
		if (g_use_log_fp == NULL)  return;
	}

	char tmp_time[128];
	time2str(tmp_time, 128, &g_time);
	fprintf(g_use_log_fp, "<%s>\n", tmp_time);
	for (int i = 0; i < argc; i++) {
		if (i != argc-1)
			fprintf(g_use_log_fp, "%s ", argv[i]);
		else
			fprintf(g_use_log_fp, "%s", argv[i]);
	}
	fprintf(g_use_log_fp, "\n");
	fclose(g_use_log_fp);
	return;
}

#include "crc.h"
#include "xor.h"

/* 以下两个函数在crypt_file.cpp中定义 */
extern void crypt_file_init();
extern void encrypt_files(const char *name, unsigned key, int type);

int main(int argc, char* argv[]) {
	int i = 0;
    static char default_argv0[] = "tdog";

    if (!argv[0] || !argv[0][0])
        argv[0] = default_argv0;
    argv0 = argv[0];
	
    while (progname[0] == '.' && progname[1] == '/'  && progname[2])
        progname += 2;

	/* 随机时钟种子 */
    srand((int) clock());

	/* 处理命令行 */
	i = handle_arguments(argc, argv);
	if (i == -1) {
		/* 命令行处理出错，直接退出 */
		//ERROR_INTERNAL_EXCEPT("handle arguments error");
		return i;
	}

	/* 写入日志 */
	//write_use_log(argc, argv);

	/* 打开输出文件 */
	if (g_opts.print) {
		g_output_fp = fopen(g_opts.print_path, "w");
		if (g_output_fp) {
			set_error(g_output_fp);
			set_out(g_output_fp);
		}
	}

	/* 一些工具 */
	if (g_opts.encrypt_file) {
		crypt_file_init();
		encrypt_files(g_opts.en_file_name, 
					  g_opts.crypt_key,
					  1);
		return exit_code;
	}

	// Loader ld;
	// ld.set_options(&g_opts);
	// ld.build_loader();

    /* 开始工作 */
	do_files(i,argc,argv);

	if (g_opts.output_file)
		fclose(g_output_fp);

    return exit_code;
}
