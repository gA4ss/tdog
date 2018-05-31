#ifndef __MAKE_LD__
#define __MAKE_LD__

class MakeLD {
 public:
	MakeLD();
	virtual ~MakeLD();
 public:
	void set_options(struct arguments* opts);
	void set_elftools(ElfTools* elftools);

	int make(const char* ld_path);
	int make(InputFile* fi);
	unsigned get_ld_size();
	unsigned char* get_ld();
	unsigned get_ld_bias();

	unsigned calc_page_align(unsigned x);
 private:
	int map_file(InputFile* fi);

 private:
	struct arguments _opts;

	InputFile _fi;
	Mapper _mapper;

	ElfTools* _elftools;

	Elf32_Phdr* _phdr_table;
	unsigned _phdr_table_size;
    struct phdr_ptr* _phdr_holder;

	void* _load_start;
	unsigned _load_size;
	unsigned _load_bias;
};

#endif
