#ifndef __MAPPER_H__
#define __MAPPER_H__

struct phdr_ptr {
    void* phdr_mmap;
    unsigned phdr_size;
};

class Mapper {
 public:
	Mapper();
	virtual ~Mapper();

 public:
	void set_page_shift(int shift);
	unsigned PAGE_START(unsigned x);
	unsigned PAGE_OFFSET(unsigned x);
	unsigned PAGE_END(unsigned x);
	unsigned PAGE_SIZE();
	unsigned PAGE_MASK();
	
	int phdr_table_load(int fd,
						unsigned phdr_offset,
						unsigned short phdr_num,
						void** phdr_mmap,
						unsigned* phdr_size,
						/*const*/
						Elf32_Phdr** phdr_table);

	void phdr_table_unload(void* phdr_mmap, unsigned phdr_memsize);

	unsigned phdr_table_get_load_size(const Elf32_Phdr* phdr_table,
									  unsigned short phdr_count);

	int phdr_table_reserve_memory(const Elf32_Phdr* phdr_table,
								  unsigned short phdr_count,
								  void** load_start,
								  unsigned* load_size,
								  unsigned* load_bias);

	int phdr_table_load_segments(const Elf32_Phdr* phdr_table,
								 unsigned short    phdr_count,
								 unsigned          load_bias,
								 int               fd);
	int phdr_table_set_load_prot(const Elf32_Phdr* phdr_table,
								 unsigned short    phdr_count,
								 unsigned          load_bias,
								 int               extra_prot_flags);

	int phdr_table_protect_segments(const Elf32_Phdr* phdr_table,
									unsigned short phdr_count,
									unsigned load_bias);

	int phdr_table_unprotect_segments(const Elf32_Phdr* phdr_table,
									  unsigned short phdr_count,
									  unsigned load_bias);

	int phdr_table_set_gnu_relro_prot(const Elf32_Phdr* phdr_table,
									  unsigned short    phdr_count,
									  unsigned          load_bias,
									  int               prot_flags);


	int phdr_table_protect_gnu_relro(const Elf32_Phdr* phdr_table,
									 unsigned short phdr_count,
									 unsigned load_bias);

	const Elf32_Phdr* phdr_table_get_loaded_phdr(const Elf32_Phdr* phdr_table,
												 unsigned short phdr_count,
												 unsigned load_bias);

	int phdr_table_get_arm_exidx(const Elf32_Phdr* phdr_table,
								 unsigned short phdr_count,
								 unsigned load_bias,
								 unsigned** arm_exidx,
								 unsigned* arm_exidix_count);

	void free_phdr_ptr(struct phdr_ptr** ptr);	

 public:
	unsigned _page_shift;
	unsigned _page_size;
	unsigned _page_mask;
};


#endif
