#include "globals.h"
#include "mem.h"
#include "file.h"
#include "analyze.h"

unsigned make_sure_section_to_segment(elf_file *ef, unsigned sec_addr) {
	UNUSED(ef);
	UNUSED(sec_addr);
	return 0;
}

unsigned make_sure_symbol_is_mapping(char *name) {
	UNUSED(name);
	return 0;
}

unsigned make_sure_symbol_mapping_type(char *name) {
	UNUSED(name);
	return 0;
}

bool sort_sections(const elf_section &v1, const elf_section &v2) {
	return v1.address < v2.address;
}

bool sort_segments(const elf_segment &v1, const elf_segment &v2) {
	return v1.address < v2.address;
}
bool sort_reloc_table(const elf_reloc_item &v1, const elf_reloc_item &v2) {
	return v1.offset < v2.offset;
}
bool sort_symbols(const elf_symbol &v1, const elf_symbol &v2) {
	return v1.address < v2.address;
}
bool sort_functions(const elf_function &v1, const elf_function &v2) {
	return v1.address < v2.address;
}

static void print_info(elf_file *ef) {
	printf_msg("<info>\r\n");
	printf_msg("<textrel>%d</textrel>\r\n", ef->textrel);
	printf_msg("<pltgot>x%x</pltgot>\r\n", ef->plt_got_address);
	printf_msg("<pltgot_size>x%x</pltgot_size>\r\n", ef->plt_got_size);
	printf_msg("</info>\r\n");
}

static void print_sections(elf_file *ef) {
	vector<elf_section>::iterator iter = 
		ef->sections.begin();
	vector<elf_section>::iterator iter_end = 
		ef->sections.end();
	unsigned count = ef->sections.size();
	printf_msg("<Sections num = \"%d\">\r\n", count);
	for (; iter != iter_end; iter++) {
		printf_msg("<section name = \"%s\">\r\n", (*iter).name);
		printf_msg("<offset>x%x</offset>\r\n", (*iter).offset);
		printf_msg("<address>x%x</address>\r\n", (*iter).address);
		printf_msg("<size>x%x</size>\r\n", (*iter).size);
		printf_msg("<type>x%x</type>\r\n", (*iter).type);
		printf_msg("<es>x%x</es>\r\n", (*iter).es);
		printf_msg("<flag>x%x</flag>\r\n", (*iter).flag);
		printf_msg("<link>x%x</link>\r\n", (*iter).link);
		printf_msg("<info>x%x</info>\r\n", (*iter).info);
		printf_msg("<align>x%x</align>\r\n", (*iter).align);
		printf_msg("<segment>x%x</segment>\r\n", (*iter).segment);
		printf_msg("</section>\r\n");
	}
	printf_msg("</Sections>\r\n");
}

static void print_segments(elf_file *ef) {
	vector<elf_segment>::iterator iter = 
		ef->segments.begin();
	vector<elf_segment>::iterator iter_end = 
		ef->segments.end();
	unsigned count = ef->segments.size();
	printf_msg("<Segments num = \"%d\">\r\n", count);
	for (; iter != iter_end; iter++) {
		printf_msg("<segment>\r\n");
		printf_msg("<offset>x%x</offset>\r\n", (*iter).offset);
		printf_msg("<address>x%x</address>\r\n", (*iter).address);
		printf_msg("<paddress>x%x</paddress>\r\n", (*iter).phys_address);
		printf_msg("<type>x%x</type>\r\n", (*iter).type);
		printf_msg("<fsize>x%x</fsize>\r\n", (*iter).filesize);
		printf_msg("<memsize>x%x</memsize>\r\n", (*iter).memsize);
		printf_msg("<flag>x%x</flag>\r\n", (*iter).flag);
		printf_msg("<align>x%x</align>\r\n", (*iter).align);
		printf_msg("</segment>\r\n");
	}
	printf_msg("</Segments>\r\n");
}

static void print_relocs(elf_file *ef) {
	vector<elf_reloc_item>::iterator iter = 
		ef->relocs.begin();
	vector<elf_reloc_item>::iterator iter_end = 
		ef->relocs.end();
	unsigned count = ef->relocs.size();
	printf_msg("<Relocs num = \"%d\">\r\n", count);
	for (; iter != iter_end; iter++) {
		printf_msg("<reloc>\r\n");
		printf_msg("<offset>x%x</offset>\r\n", (*iter).offset);
		printf_msg("<address>x%x</address>\r\n", (*iter).address);
		printf_msg("<type>x%x</type>\r\n", (*iter).type);
		printf_msg("<info>x%x</info>\r\n", (*iter).info);
		printf_msg("<symv>x%x</symv>\r\n", (*iter).sym_value);
		printf_msg("<symn>%s</symn>\r\n", (*iter).sym_name);
		printf_msg("<in_got>%d</in_got>\r\n", (*iter).in_got);
		printf_msg("</reloc>\r\n");
	}
	printf_msg("</Relocs>\r\n");
}

static void print_dynamics(elf_file *ef) {
	vector<elf_dynamic_item>::iterator iter = 
		ef->dynamics.begin();
	vector<elf_dynamic_item>::iterator iter_end = 
		ef->dynamics.end();
	unsigned count = ef->dynamics.size();
	printf_msg("<Dynamics num = \"%d\">\r\n", count);
	for (; iter != iter_end; iter++) {
		printf_msg("<dynamic>\r\n");
		printf_msg("<type>x%x</type>\r\n", (*iter).type);
		if ((*iter).type == DT_NEEDED) {
			printf_msg("<value>%s</value>\r\n", (*iter).libname);
		} else {
			printf_msg("<value>x%x</value>\r\n", (*iter).value);
		}
		printf_msg("</dynamic>\r\n");
	}
	printf_msg("</Dynamics>\r\n");
}

static void print_symbols(elf_file *ef) {
	vector<elf_symbol>::iterator iter = 
		ef->symbols.begin();
	vector<elf_symbol>::iterator iter_end = 
		ef->symbols.end();
	unsigned count = ef->symbols.size();
	printf_msg("<Symbols num = \"%d\">\r\n", count);
	for (; iter != iter_end; iter++) {
		printf_msg("<symbol name = \"%s\">\r\n", (*iter).name);
		printf_msg("<address>x%x</address>\r\n", (*iter).address);
		printf_msg("<size>x%x</size>\r\n", (*iter).size);
		printf_msg("<type>x%x</type>\r\n", (*iter).type);
		printf_msg("<bind>x%x</bind>\r\n", (*iter).bind);
		printf_msg("<vis>x%x</vis>\r\n", (*iter).visibly);
		printf_msg("<ndx>x%x</ndx>\r\n", (*iter).ndx);
		printf_msg("<mapping>%d</mapping>\r\n", (*iter).is_mapping_symbol);
		if ((*iter).is_mapping_symbol) {
			printf_msg("<mapping_type>%d</mapping_type>\r\n", 
					   (*iter).mapping_type);
		}
		if ((*iter).has_reloc) {
			printf_msg("<reloc_addr>x%x</reloc_addr>\r\n", 
					   (*iter).reloc_address);
		}
		printf_msg("</symbol>\r\n");
	}
	printf_msg("</Symbols>\r\n");
}

static void print_functions(elf_file *ef) {
	vector<elf_function>::iterator iter = 
		ef->functions.begin();
	vector<elf_function>::iterator iter_end = 
		ef->functions.end();
	unsigned count = ef->functions.size();
	printf_msg("<Functions num = \"%d\">\r\n", count);
	for (; iter != iter_end; iter++) {
		printf_msg("<function name = \"%s\">\r\n", (*iter).name);
		printf_msg("<address>x%x</address>\r\n", (*iter).address);
		printf_msg("<size>x%x</size>\r\n", (*iter).size);
		printf_msg("<type>x%x</type>\r\n", (*iter).type);
		printf_msg("<bind>x%x</bind>\r\n", (*iter).bind);
		printf_msg("<vis>x%x</vis>\r\n", (*iter).visibly);
		printf_msg("<ndx>x%x</ndx>\r\n", (*iter).ndx);
		if ((*iter).has_reloc) {
			printf_msg("<reloc_addr>x%x</reloc_addr>\r\n", 
					   (*iter).reloc_address);
		}
		printf_msg("<import>%d</import>\r\n", 
				   (*iter).func_attribute.is_import);
		printf_msg("</function>\r\n");
	}
	printf_msg("</Functions>\r\n");
}

static void print_disasm(elf_file *ef) {
	UNUSED(ef);
}

void analyze_report(elf_file *ef) {
	printf_msg("<AEFAR>\r\n");
	
	print_info(ef);
	print_segments(ef);
	print_sections(ef);
	print_symbols(ef);
	print_dynamics(ef);
	print_relocs(ef);
	print_functions(ef);

	if (ef->analyze_opt.disasm) {
		print_disasm(ef);
	}

	printf_msg("</AEFAR>\r\n");
}
