#if !defined(__TDOG_DIS_H__)
#define __TDOG_DIS_H__

#include <string>
#include <vector>
#include <map>

using namespace std;
class Dis : public Loader {
	typedef Loader super;
 public:
	Dis();
	virtual ~Dis();
 public:
	virtual void build_loader(unsigned char* target,
														unsigned char* loader_to);
	virtual int fill_globals();
	virtual unsigned get_save_target_pltjmp_offset();
	virtual unsigned get_save_target_pltjmp_size();
	virtual unsigned get_save_target_rel_offset();
	virtual unsigned get_save_target_rel_size();

	virtual unsigned get_exspace_offset();
	virtual unsigned get_exspace_size();
	virtual void set_exspace_size(unsigned size);
	virtual unsigned char *get_exspace();
	virtual void set_exspace(unsigned char *p);

 protected:
	virtual int make_loader(unsigned char* target,
													unsigned char* loader_to);
	virtual int handle_target_hashtab(unsigned char* hashtab);
	virtual int handle_loader_hashtab(unsigned char* hashtab, 
																		unsigned fix_offset);
 protected:
	virtual int count_hashsym(unsigned char* hashtab, 
														unsigned* nbucket, unsigned* nchain);
	virtual unsigned char* get_target_hashtab();
	virtual unsigned char* get_loader_hashtab();
	
	virtual Elf32_Sym* get_target_symtab();
	virtual Elf32_Sym* get_loader_symtab();

	virtual char* get_target_strtab();
	virtual char* get_loader_strtab();

	virtual Elf32_Rel* get_target_pltrel();
	virtual Elf32_Rel* get_loader_pltrel();

	virtual Elf32_Rel* get_target_rel();
	virtual Elf32_Rel* get_loader_rel();

	virtual unsigned* get_target_finit();

	virtual Elf32_Dyn* get_target_dynamic();
	virtual int fix_needed_sym_idx(Elf32_Dyn* dyn, char* strtab);
	virtual Elf32_Dyn* get_loader_dynamic_needed(Elf32_Dyn* buf, 
																							 unsigned* usesize);
	virtual int fix_new_dynamic_in_phdrs(unsigned offset, unsigned size);
	virtual void fix_loader_got(unsigned char* ld, unsigned fix_offset);
	virtual void add_needed(int type, char *neededs);
	virtual unsigned make_new_dynamic();
	virtual unsigned* get_dynamic_object_offset_ptr(Elf32_Dyn* dyn, 
																									unsigned key);

 protected:
	virtual int is_in_target_strtab_strings(char* name);
	virtual int fix_rel_offset(Elf32_Rel* rel, unsigned relc,
														 unsigned fix_offset);
	virtual unsigned fix_rel_symidx(Elf32_Rel* rel, unsigned relc,
																	unsigned old_symidx, unsigned new_symidx);
	virtual Elf32_Rel* find_relobj_log(unsigned relobj);
	virtual int loop_handle_target_symtab(elf_tools_symtab* symbase,
																				Elf32_Sym* symtab, char* strtab,
																				Elf32_Rel* pltreltab, unsigned pltrelc,
																				Elf32_Rel* reltab, unsigned reltabc,
																				unsigned* hashlist, 
																				unsigned hashcount);
	virtual int loop_handle_loader_symtab(elf_tools_symtab* symbase,
																				Elf32_Sym* symtab, char* strtab,
																				Elf32_Rel* pltreltab, unsigned pltrelc,
																				Elf32_Rel* reltab, unsigned reltabc,
																				unsigned* hashlist, 
																				unsigned hashcount,
																				unsigned fix_offset);
	virtual unsigned char* make_new_reltab(bool pltrel, unsigned* relsz);
	virtual unsigned char* save_target_reltab(bool pltrel, unsigned* relsz);
	virtual void clean_target_loader_xct();
	virtual void add_DT_DEBUG(unsigned char *ptr);

	/* devilogic 2016.4.11 00:16添加 
	 * 目的是支持android6.0 
	 * 动态段中存在了DT_VERDEF DT_VERNEED等
	 * 但是又不是必须的，所以直接清空
	 */
	virtual void clear_dynamic_xxx(Elf32_Dyn* dyn);
	virtual int fix_target_SONAME(int *idx);
	virtual void add_DT_SONAME(unsigned char *ptr, int idx);

 public:
	unsigned _symnum;
 protected:
	MakeLD* _make_ld;
	ElfDynamicTools* _ld_orig_elftools;
	ElfDynamicTools* _ld_elftools;
	unsigned char* _target_hashtab;
	unsigned char* _loader_hashtab;
	char* _target_strtab;
	char* _loader_strtab;
	unsigned _target_strtabsz;
	unsigned _loader_strtabsz;

	unsigned char* _new_dynamic;

	Elf32_Dyn* _target_dynamic;
	unsigned _target_dynamic_size;
	Elf32_Sym* _target_symtab;
	Elf32_Rel* _target_pltrel;
	Elf32_Rel* _target_rel;
	unsigned _target_pltrel_count;
	unsigned _target_rel_count;

	unsigned *_target_finit;

	unsigned _loader_needed_dynamic_size;
	Elf32_Sym* _loader_symtab;
	Elf32_Rel* _loader_pltrel;
	Elf32_Rel* _loader_rel;
	unsigned _loader_pltrel_count;
	unsigned _loader_rel_count;

	unsigned char* _new_pltrel;
	unsigned _new_pltrelsz;

	unsigned char* _new_rel;
	unsigned _new_relsz;

	unsigned _new_dynamic_offset;
	unsigned _new_hashtab_offset;
	unsigned _new_dynsym_offset;
	unsigned _new_dynstr_offset;
	unsigned _new_pltrel_offset;
	unsigned _new_rel_offset;
	unsigned _new_finit_offset;

	/* --save-target-rel选项相关 */
	unsigned _save_target_pltrel_offset;
	unsigned _save_target_pltrel_size;
	unsigned _save_target_rel_offset;
	unsigned _save_target_rel_size;
	unsigned char* _save_target_pltrel;
	unsigned char* _save_target_rel;

	/* 扩展空间 */
	unsigned _exspace_offset;
	unsigned _exspace_size;
	unsigned char *_exspace;

	elf_tools_symtab _symbase;
	vector<string> _target_strtab_strings;
	/* 2016.5.10,读取16年2月23日的邮件
	 * 小松发现,使用vector当重定位项过多时，容易
	 * 造成速度过慢。所以这里换成map
	 */
	//vector<unsigned> _relobj_log;
	map<unsigned, unsigned> _relobj_log;

	unsigned _target_old_finit_offset;

	/* 要添加needed的索引 */
	vector<int> _needed_name;
	Elf32_Dyn *_add_needed;
	unsigned _add_needed_size;
};

#endif
