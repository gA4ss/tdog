#include "globals.h"
#include "crc.h"

#include <getopt.h>

struct arguments g_opts;

static 
void init_opts() {
	memset(&g_opts, 0, sizeof(g_opts));	
}

void usage() {
	printf_msg("tdog [options] files...\n");
	printf_msg("http://www.nagapt.com\n");
	printf_msg("%s\n", TDOG_VERSION);
}

void show_help() {
	printf_msg("\t----------------------------------------\n");
	printf_msg("\t|==== Android Native Lib Protector ====|\n");
	printf_msg("\t----------------------------------------\n");
	printf_msg("tdog [options] files...\n");
	printf_msg("[analyze]\n");
	printf_msg("-A, --analyze                           analyze target\n");
	printf_msg("--dis-asm                               disassemble target\n");
	printf_msg("[protect]\n");
	printf_msg("-P, --protect                           protect target file\n");
	printf_msg("--just-protect-code                     encrypt \'.text\' section\n");
	printf_msg("-S, --encrypt-inside-data-name=<key>    encrypt inside symbol name with <key>\n");
	printf_msg("-E, --encrypt-codes=<key>               encrypt code key\n");
	printf_msg("--encrypt-codes-key-file=<path>         encrypt code by key, which is computed\n"); 
    printf_msg("                                        by file\n");
	printf_msg("--keep-code-local                       encrypt code in local\n");
	printf_msg("--select-cipher-type=<stream|symmetric> select cipher type\n");
	printf_msg("--skip-string-in-reloc                  not encrypt string in reloc tab\n");
	printf_msg("--fake-pt-dynamic-offset                fake PT_DYNAMIC offset\n");
	printf_msg("--set-arch=<arm|x86|mips>               set machine arch\n");
	printf_msg("--save-target-rel                       save target reloc table, but not use\n");
	printf_msg("-G, --encrypt-global-codes=<key>        encrypt export codes\n");
	printf_msg("--include-exp-fun=<@func name|#file>    include export function name\n");
	printf_msg("--libname=<name>                        set libname\n");
	printf_msg("--control-exp-func                      control export function\n");
	printf_msg("-F, --encrypt-func=<key>                encrypt functions\n");
	printf_msg("--include-func=<@func name|#file>       include function\n");
	
#ifdef USE_MUTI_THREAD
	/* 启用多线程 */
	printf_msg("--cipher-thread=<num>                   number of cipher thread\n");
#endif
	printf_msg("[modify entry point]\n");
	printf_msg("--use-dt-init-array                     dt init array function as entry point\n");
	//printf_msg("--hide-entry                            hide entry pointer\n");
	printf_msg("[debug tools]\n");
	printf_msg("-B, --set-breakpoint=<offset(hex)>      set breakpoint on offset\n");
	printf_msg("[loader]\n");
	printf_msg("-l1, --import-loader=<path>             import loader source\n");
	printf_msg("-lx, --import-loader-descript=<path>    import loader descript file\n");
	printf_msg("-lc, --import-loader-cipher=<path>      import loader cipher lib\n");
	printf_msg("--muti-string                           when use dis muti string\n");
	printf_msg("[anti cracker]\n");
	printf_msg("-r1, --reloc-encrypt-loader             encrypt loader use reloc structs\n");
	printf_msg("-r2, --reloc-remove-elf-header          remove elf header use reloc\n");
	printf_msg("-r3, --reloc-encrypt-codes              encrypt code use reloc\n");
	printf_msg("--skip-entry                            skip entry\n");
	printf_msg("--xdebugger                             control debugger\n");
	printf_msg("[assist]\n");
	printf_msg("--add-needed=<@so name|#file>           add needed so\n");
	printf_msg("--encrypt-file=<@filen|#filelist>       encrypt file\n");
	//printf_msg("--decrypt-file=<@filen|#filelist>       decrypt file\n");
	printf_msg("--crypt-key <key>                       select crypt key\n");
	printf_msg("[custom format]\n");
	printf_msg("-C, --custom-format                     use custom file format\n");
	printf_msg("--encrypt-cf-codes                      encrypt custom format codes\n");
	printf_msg("[misc]\n");
	printf_msg("--preserve-build-id                     preserve build id\n");
	printf_msg("--copy-file-attribute                   copy file attribute\n");
	printf_msg("--strip-unused                          strip unused info from file\n");
	printf_msg("-M, --merge-segments                    merge all segments to one\n");
	printf_msg("--set-page-shift=<shift>                set page shift(DEF 12bits-4KB)\n");
	printf_msg("--cache-size=<size>                     set cache size,default size is 4MB\n");
	printf_msg("--auto-cache-size                       auto set cache size(DEF open)\n");
	printf_msg("--print-textrel-tab-size                print size of text rel table\n");
	printf_msg("-q, --quiet                             not output anything\n");
	printf_msg("-o, --output=<file>                     output to file\n");
	printf_msg("--print=<file>                          print info to file\n");
	printf_msg("--not-throw-except                      not throw except\n");
	printf_msg("--help                                  show help\n");
	printf_msg("--version                               show version\n");
	printf_msg("--backup                                backup orig file\n");
	printf_msg("\n");
	printf_msg("http://tdog.nagain.com\n");
	printf_msg("%s", TDOG_VERSION);
	printf_msg("\n");
}

static char* handle_short_optarg(char* args) {
	if (args == NULL) return NULL;

	if (*args == '=')
		return args+1;

	while (*args) {
		if (*args != ' ') {
			return args;
		}
		
		args++;
	}

	return NULL;
}

int handle_arguments(int argc, char* argv[]) {
	int opt;
	int longidx;
	int strip_unused = 0, use_dt_init_array = 0, hide_entry = 0,
		copy_file_attribute = 0,
		set_breakpoint = 0, preserve_build_id = 0, help = 0, version = 0,
		protect = 0, import_loader = 0, import_loader_descript = 0, backup = 0,
		encrypt_inside_data_name = 0, merge_segments = 0, set_page_shift = 0,
        cache_size = 0, reloc_encrypt_loader = 0, reloc_remove_elf_header = 0,
		reloc_encrypt_codes = 0, xdebugger = 0,
		import_loader_cipher = 0, cipher_thread = 0,
		quiet = 0, output_file = 0, just_protect_code = 0, muti_string = 0,
		auto_cache_size = 0, skip_string_in_reloc = 0, 
		fake_pt_dynamic_offset = 0, 
		encrypt_codes = 0, encrypt_codes_key_file = 0, not_throw_except = 0, 
		print = 0, set_arch = 0, save_target_rel = 0, custom_format = 0,
		encrypt_cf_codes = 0, encrypt_global_codes = 0, include_exp_fun = 0,
		print_textrel_tab_size = 0, keep_code_local = 0, select_cipher_type = 0,
		skip_entry = 0, analyze = 0, disasm = 0, control_exp_func = 0,
		encrypt_func = 0, include_func = 0, add_needed = 0, libname = 0,
		encrypt_file = 0, decrypt_file = 0, crypt_key = 0;

    init_opts();
	if (argc == 1) {
		usage();
        return -1;
    }

    /* 默认缓存大小1页空间 */
	g_opts.code_key = 0x19930613;
	g_opts.encrypt_func_key = 0x19831210;
    g_opts.page_shift = 12;
    g_opts.cache_size = (1 << g_opts.page_shift) * 1024;
	g_opts.auto_cache_size = 1;
	strcpy(g_opts.loader_path, "./loader.out");
	strcpy(g_opts.loader_descript, "./loader_descript.xml");
	strcpy(g_opts.loader_cipher, "./libnanan.so");
	strcpy(g_opts.output_path, "./tdog.output");
	g_opts.include_enfunc_filepath = "./wdog.list";

	const char* short_opts = ":B:E:PMCAql:S:r:o:G:F:";
	struct option long_opts[] = {
		{ "strip-unused", 0, &strip_unused, 1 },
	 	{ "use-dt-init-array", 0, &use_dt_init_array, 2 },
		{ "copy-file-attribute", 0, &copy_file_attribute, 3 },
	 	{ "set-breakpoint", 1, &set_breakpoint, 4 },
	 	{ "preserve-build-id", 0, &preserve_build_id, 5 },
	 	{ "help", 0, &help, 6 },
	 	{ "version", 0, &version, 7 },
		{ "protect", 0, &protect, 8 },
		{ "backup", 0, &backup, 9 },
		{ "encrypt-inside-data-name", 1, &encrypt_inside_data_name, 0x0a },
		{ "import-loader", 1, &import_loader, 0x0b },
		{ "import-loader_descript", 1, &import_loader_descript, 0x0c },
		{ "merge-segments", 0, &merge_segments, 0x0d },
		{ "set-page-shift", 1, &set_page_shift, 0x0e },
		{ "cache-size", 1, &cache_size, 0x0f },
		{ "reloc-encrypt-loader", 0, &reloc_encrypt_loader, 0x10 },
		{ "reloc-remove-elf-header", 0, &reloc_remove_elf_header, 0x11 },
	    { "reloc-encrypt-codes", 1, &reloc_encrypt_codes, 0x12},
		{ "import-loader-cipher", 1, &import_loader_cipher, 0x13 },
		{ "cipher-thread", 0, &cipher_thread, 0x14 },
		{ "quiet", 0, &quiet, 0x15 },
		{ "output", 1, &output_file, 0x16 },
		{ "just-protect-code", 0, &just_protect_code, 0x17 },
		{ "muti-string", 0, &muti_string, 0x18 },
		{ "auto-cache-size", 0, &auto_cache_size, 0x19 },
		{ "skip-string-in-reloc", 0, &skip_string_in_reloc, 0x1a },
		{ "fake-pt-dynamic-offset", 0, &fake_pt_dynamic_offset, 0x1b },
		{ "encrypt-codes", 1, &encrypt_codes, 0x1c },
		{ "encrypt-codes-key-file", 1, &encrypt_codes_key_file, 0x1d },
		{ "not-throw-except", 0, &not_throw_except, 0x1e },
		{ "print", 0, &print, 0x1f },
		{ "set-arch", 1, &set_arch, 0x20 },
		{ "save-target-rel", 1, &save_target_rel, 0x21 },
		{ "custom-format", 0, &custom_format, 0x22 },
		{ "encrypt-cf-codes", 0, &encrypt_cf_codes, 0x23 },
		{ "encrypt-global-codes", 1, &encrypt_global_codes, 0x24 },
		{ "include-exp-fun", 1, &include_exp_fun, 0x25 },
		{ "print-textrel-tab-size", 0, &print_textrel_tab_size, 0x26 },
		{ "keep-code-local", 0, &keep_code_local, 0x27 },
		{ "select-cipher-type", 1, &select_cipher_type, 0x28 },
		{ "hide-entry", 0, &hide_entry, 0x29 },
		{ "xdebugger", 0, &xdebugger, 0x2a },
		{ "skip-entry", 0, &skip_entry, 0x2b },
		{ "analyze", 0, &analyze, 0x2c },
		{ "disasm", 0, &disasm, 0x2d },
		{ "control-exp-func", 0, &control_exp_func, 0x2e },
		{ "encrypt-func", 1, &encrypt_func, 0x2f },
		{ "include-func", 1, &include_func, 0x30 },
		{ "add-needed", 1, &add_needed, 0x31 },
		{ "libname", 1, &libname, 0x32 },
		{ "encrypt-file", 1, &encrypt_file, 0x33 },
		{ "decrypt-file", 1, &decrypt_file, 0x34 },
		{ "crypt-key", 1, &crypt_key, 0x35 },
		//{ "new-dt-init", 1, &new_dt_init, 0x29 },
		//{ "add-dt-finit-array", 1, &add_dt_finit_array, 0x30 },
		//{ "add-new-needed", 1, &add_new_needed, 0x31 },
	 	{ 0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, 
							  short_opts, long_opts, 
							  &longidx)) != -1) {
		switch (opt) {
		case 0:
			if (strip_unused == 1) {
				g_opts.strip_unused = 1;
				strip_unused = 0;
			} else if (use_dt_init_array == 2) {
				g_opts.use_dt_init_array = 1;
				use_dt_init_array = 0;
			} else if (copy_file_attribute == 3) {
				g_opts.copy_file_attribute = 1;
				copy_file_attribute = 0;
			} else if (set_breakpoint == 4) {
				g_opts.set_breakpoint = 1;
				g_opts.breakpoint = strtol(optarg, NULL, 16);
				set_breakpoint = 0;
			} else if (preserve_build_id == 5) {
				g_opts.preserve_build_id = 1;
				preserve_build_id = 0;
			} else if (help == 6) {
				g_opts.show_help = 1;
				help = 0;
			} else if (version == 7) {
				g_opts.show_version = 1;
				version = 0;
			} else if (protect == 8) {
				g_opts.protect = 1;
				protect = 0;
			} else if (backup == 9) {
				g_opts.backup = 1;
				backup = 0;
			} else if (encrypt_inside_data_name == 0x0a) {
				g_opts.encrypt_inside_data_name = 1;
				g_opts.encrypt_inside_data_name_key = 
					crc32((unsigned char*)optarg, strlen(optarg));
				encrypt_inside_data_name = 0;
			} else if (import_loader == 0x0b) {
				g_opts.import_loader = 1;
				strcpy(g_opts.loader_path, optarg);
				import_loader = 0;
			} else if (import_loader_descript == 0x0c) {
				g_opts.import_loader_descript = 1;
				strcpy(g_opts.loader_descript, optarg);
				import_loader_descript = 0;
			} else if (merge_segments == 0x0d) {
				g_opts.merge_segments = 1;
				merge_segments = 0;
			} else if (set_page_shift == 0x0e) {
				g_opts.set_page_shift = 1;
				g_opts.page_shift = atol(optarg);
				set_page_shift = 0;
            } else if (cache_size == 0x0f) {
                g_opts.cache_size = atol(optarg);
				cache_size = 0;
			} else if (reloc_encrypt_loader == 0x10) {
				g_opts.reloc_encrypt_loader = 1;
				reloc_encrypt_loader = 0;
			} else if (reloc_remove_elf_header == 0x11) {
				g_opts.reloc_remove_elf_header = 1;
				reloc_remove_elf_header = 0;
			} 
			else if (reloc_encrypt_codes == 0x12) {
			 	g_opts.reloc_encrypt_codes= 1;
				reloc_encrypt_codes = 0;
			}
			else if (import_loader_cipher == 0x13) {
				g_opts.import_loader_cipher = 1;
				strcpy(g_opts.loader_cipher, optarg);
				import_loader_cipher = 0;
			} else if (cipher_thread == 0x14) {
				g_opts.cipher_thread = atoi(optarg);
				cipher_thread = 0;
			} else if (quiet == 0x15) {
				g_opts.quiet = 1;
				quiet = 0;
			} else if (output_file == 0x16) {
				g_opts.output_file = 1;
				strcpy(g_opts.output_path, optarg);
				output_file = 0;
			} else if (just_protect_code == 0x17) {
				g_opts.just_protect_code = 1;
				just_protect_code = 0;
			} else if (muti_string == 0x18) {
				g_opts.muti_string = 1;
				muti_string = 0;
			} else if (auto_cache_size == 0x19) {
				g_opts.auto_cache_size = 1;
				auto_cache_size = 0;
			} else if (skip_string_in_reloc == 0x1a) {
				g_opts.skip_string_in_reloc = 1;
				skip_string_in_reloc = 0;
			} else if (fake_pt_dynamic_offset == 0x1b) {
				g_opts.fake_pt_dynamic_offset = 1;
				fake_pt_dynamic_offset = 0;
			} else if (encrypt_codes == 0x1c) {
				g_opts.encrypt_codes = 1;
				g_opts.code_key = strtol(optarg, NULL, 16);
				encrypt_codes = 0;
			} else if (encrypt_codes_key_file == 0x1d) {
				g_opts.encrypt_codes = 1;
				g_opts.encrypt_codes_key_file = 1;
				unsigned ck = crc32_file(optarg);
				if (ck) {
					g_opts.code_key = ck;
				}
				encrypt_codes_key_file = 0;
			} else if (not_throw_except == 0x1e) {
				g_opts.not_throw_except = 1;
				not_throw_except = 0;
			} else if (print == 0x1f) {
				g_opts.print = 1;
				strcpy(g_opts.print_path, optarg);
				print = 0;
			} else if (set_arch == 0x20) {
				g_opts.set_arch = 1;
				if (strcmp(optarg, "arm") == 0) {
					g_opts.arch = ARCH_ARM;
				} else if (strcmp(optarg, "x86") == 0) {
					g_opts.arch = ARCH_X86;
				} else if (strcmp(optarg, "mips") == 0) {
					g_opts.arch = ARCH_MIPS;
				} else {
					g_opts.arch = ARCH_ARM;
				}
				set_arch = 0;
			} else if (save_target_rel == 0x21) {
				g_opts.save_target_rel = 1;
				save_target_rel = 0;
			} else if (custom_format == 0x22) {
				g_opts.custom_format = 1;
				custom_format = 0;
			} else if (encrypt_cf_codes == 0x23) {
				g_opts.encrypt_cf_codes = 1;
				encrypt_cf_codes = 0;
			} else if (encrypt_global_codes == 0x24) {
				g_opts.encrypt_global_codes = 1;
				g_opts.global_code_key = 
					crc32((unsigned char*)optarg, strlen(optarg));
				encrypt_global_codes = 0;
			} else if (include_exp_fun == 0x25) {
				g_opts.include_exp_fun = 1;
				if (optarg[0] == '@') {
					strcpy(g_opts.ef_name, &optarg[1]);
					g_opts.is_ef_name = 0;
				} else {
					strcpy(g_opts.ef_file, &optarg[1]);
					g_opts.is_ef_name = 1;
				}
				include_exp_fun = 0;
			} else if (print_textrel_tab_size == 0x26) {
				g_opts.print_textrel_tab_size = 1;
				print_textrel_tab_size = 0;
			} else if (keep_code_local == 0x27) {
				g_opts.keep_code_local = 1;
				keep_code_local = 0;
			} else if (select_cipher_type == 0x28) { 
				g_opts.select_cipher_type = 1;
				if (strcmp(optarg, "symmetric") == 0) {
					g_opts.cipher_type = 1;
				} else {
					g_opts.cipher_type = 0;
				}
				select_cipher_type = 0;
			} else if (hide_entry == 0x29) {
				g_opts.hide_entry = 1;
				hide_entry = 0;
			} else if (xdebugger == 0x2a) {
				g_opts.xdebugger = 1;
				xdebugger = 0;
			} else if (skip_entry == 0x2b) {
				g_opts.skip_entry = 1;
				skip_entry = 0;
			} else if (analyze == 0x2c) {
				g_opts.analyze = 1;
				analyze = 0;
			} else if (disasm == 0x2d) {
				g_opts.disasm = 1;
				disasm = 0;
			} else if (control_exp_func == 0x2e) {
				g_opts.control_exp_func = 1;
				control_exp_func = 0;
			} else if (encrypt_func == 0x2f) {
				g_opts.encrypt_func_key = 
					crc32((unsigned char*)optarg, strlen(optarg));
				g_opts.encrypt_func = 1;
				encrypt_func = 0;
			} else if (include_func == 0x30) {
				if (optarg[0] == '@') {
					strcpy(g_opts.en_func_name, &optarg[1]);
					g_opts.is_en_func_file = 0;
				} else {
					strcpy(g_opts.en_func_file, &optarg[1]);
					g_opts.is_en_func_file = 1;
				}
				include_func = 0;
			} else if (add_needed == 0x31) {
				if (optarg[0] == '@') {
					strcpy(g_opts.needed_name, &optarg[1]);
					g_opts.add_needed = 1;
				} else {
					strcpy(g_opts.needed_file, &optarg[1]);
					g_opts.add_needed = 2;
				}
				add_needed = 0;
			} else if (libname == 0x32) {
				strcpy(g_opts.libname, optarg);
				libname = 0;
			} else if (encrypt_file == 0x33) {
				if (optarg[0] == '@') {
					strcpy(g_opts.en_file_name, &optarg[1]);
					g_opts.encrypt_file = 1;
				} else {
					strcpy(g_opts.en_file_list, &optarg[1]);
					g_opts.encrypt_file = 2;
				}
				encrypt_file = 0;
			} else if (decrypt_file == 0x34) {
				if (optarg[0] == '@') {
					strcpy(g_opts.de_file_name, &optarg[1]);
					g_opts.decrypt_file = 1;
				} else {
					strcpy(g_opts.de_file_list, &optarg[1]);
					g_opts.decrypt_file = 2;
				}
				decrypt_file = 0;
			} else if (crypt_key == 0x35) {
				strcpy(g_opts.libname, optarg);
				g_opts.crypt_key = crc32((unsigned char*)optarg, 
										 strlen(optarg));
				crypt_key = 0;
			} else {
				printf_msg("unknow options: %c\n", optopt);
				return -1;
			}
			break;
		case 'G':
			g_opts.encrypt_global_codes = 1;
			g_opts.global_code_key = 
				crc32((unsigned char*)optarg, strlen(optarg));
			break;
		case 'F':
			g_opts.encrypt_func = 1;
			g_opts.encrypt_func_key = 
				crc32((unsigned char*)optarg, strlen(optarg));
			break;
		case 'E':
			g_opts.encrypt_codes = 1;
			g_opts.code_key = strtol(optarg, NULL, 16);
			break;
		case 'q':
			g_opts.quiet = 1;
			break;
		case 'o':
			g_opts.output_file = 1;
			strcpy(g_opts.output_path, optarg);
			break;
		case 'r':
			if (optarg[0] == '1') {
				g_opts.reloc_encrypt_loader = 1;
			} else if (optarg[0] == '2') {
				g_opts.reloc_remove_elf_header = 1;
			} else if (optarg[0] == '3') {
				g_opts.reloc_encrypt_codes = 1;
			} else {
				printf_msg("unknow \'-r\' options arguments: %s\n", optarg);
			}
			break;
		case 'M':
			g_opts.merge_segments = 1;
			break;
		case 'C':
			g_opts.custom_format = 1;
			break;
		case 'l':
			if (optarg[0] == '1') {
				g_opts.import_loader = 1;
				strcpy(g_opts.loader_path, 
					   handle_short_optarg(&optarg[1]));
			} 
			else if (optarg[0] == 'x') {
				g_opts.import_loader_descript = 1;
				strcpy(g_opts.loader_descript, 
					   handle_short_optarg(&optarg[1]));
			} else if (optarg[0] == 'c') {
				g_opts.import_loader_cipher = 1;
				strcpy(g_opts.loader_cipher, 
					   handle_short_optarg(&optarg[1]));
			} else {
				printf_msg("unknow \'-l\' options arguments: %s\n", optarg);
				return -1;
			}
			break;
		case 'A':
			g_opts.analyze = 1;
			break;
		case 'B':
			g_opts.set_breakpoint = 1;
			g_opts.breakpoint = strtol(optarg, NULL, 16);
			break;
		case 'S':
			g_opts.encrypt_inside_data_name = 1;
			g_opts.encrypt_inside_data_name_key =
				crc32((unsigned char*)optarg, strlen(optarg));
			break;
		case 'P':
			g_opts.protect = 1;
			break;
		case '?':
			printf_msg("unknow options: %c\n", optopt);
			return -1;
			break;
		case ':':
			printf_msg("option need a option\n");
			return -1;
			break;
		}
	}/* end while */

	g_opts.file_count = argc - optind;
	// for (i = 0; optind < argc; optind++, i++) {
	// 	g_arguments.files[i] = (char*) malloc(256);
	// 	strcpy(g_arguments.files[i], argv[optind]);
	// }

	/* 转换路径 */
	change_path(g_opts.loader_path);
	change_path(g_opts.loader_descript);
	change_path(g_opts.loader_cipher);

	/* 库名称 */
	if ((strlen(g_opts.libname) == 0) && (g_opts.protect)) {
		/* 取目标文件名称 */
		strcpy(g_opts.libname, 
			   (strrchr(argv[optind], '/') + 1));
	}

	return optind;
}
