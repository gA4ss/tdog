#if !defined(__TDOG_LOADER_H__)
#define __TDOG_LOADER_H__

#include <string>
#include <map>

#include "mem.h"

typedef struct {
	bool is_ptr;
	bool is_buf;
	union{
		unsigned value;
		unsigned char* ptr;
		unsigned char* buf;
	};
	
	unsigned size;
} loader_inside_var_t;

#define SYSTEM_VAR_NAME_LENGTH   64
#define MAX_OUTSIDE_VAR_LENGTH   256
typedef struct {
	bool is_system;
	bool is_str;
	bool is_buf;
	char system_var_name[SYSTEM_VAR_NAME_LENGTH];
	unsigned offset;
	union {
		unsigned size;
		unsigned exist;
	};
	
	union {
		unsigned value;
		char str[MAX_OUTSIDE_VAR_LENGTH];
		unsigned char buffer[MAX_OUTSIDE_VAR_LENGTH];
		unsigned char* ptr;
	};
} loader_outside_var_t;

typedef std::map<std::string, loader_inside_var_t> loader_inside_vars_t;
typedef loader_inside_vars_t::iterator loader_inside_var_node_t;

typedef std::map<std::string, loader_outside_var_t> loader_outside_vars_t;
typedef loader_outside_vars_t::iterator loader_outside_var_node_t;

class Loader {
 public:
	Loader();
	virtual ~Loader();

 public:
	void set_options(struct arguments* opts); 	/* 设置选项参数 */

 public:
	virtual int init(void* elftools);
	virtual void write_loader(unsigned char* mem, unsigned offset);
	virtual void write_loader(MemBuffer *mem, unsigned offset);
	virtual void write_loader(OutputFile* fo);
    virtual unsigned char* get_loader(bool clear_elf=false);
	virtual unsigned get_loader_size();
	virtual unsigned get_loader_code_size();
	virtual unsigned get_loader_code_offset();
	virtual unsigned get_loader_entry_offset();
	virtual unsigned get_loader_entry_size();
	virtual unsigned get_loader_exit_offset();
	virtual unsigned get_loader_control_offset();
	virtual void build_loader(unsigned char* target, unsigned char* loader_to);
	virtual unsigned get_xml_int_value(char* v);
	virtual char* get_xml_string_value(char* v);
	virtual int get_xml_file_buf(char* filename, 
								 unsigned char** buf,
								 unsigned* size);
	virtual int fill_globals();
	virtual int fill_node(const char* name, 
						  const char* value,
						  unsigned offset,
						  unsigned size);

	virtual loader_inside_var_t* get_sys_var(const char* varname);
	virtual loader_inside_var_t* set_sys_var_value(const char* varname, 
												   unsigned value);
	virtual loader_inside_var_t* set_sys_var_ptr(const char* varname,
												 unsigned char* ptr,
												 unsigned size);
	virtual loader_inside_var_t* set_sys_var_buf(const char* varname, 
												 unsigned char* buf,
												 unsigned size);
	virtual loader_outside_var_t* get_var(const char* varname);
	virtual loader_outside_var_t* set_var_value(const char* varname, 
												unsigned value);
	virtual loader_outside_var_t* set_var_sys_value(const char* varname, 
													const char* sysname);
	virtual loader_outside_var_t* set_var_str_value(const char* varname, 
													const char* value);
	virtual loader_outside_var_t* set_var_buf_value(const char* varname, 
													unsigned char* ptr);
	virtual loader_outside_var_t* set_var_offset(const char* varname,
												 unsigned offset);
	virtual loader_outside_var_t* set_var_size(const char* varname,
											   unsigned size);


	virtual int update_vars(unsigned char* target,
							unsigned char* loader_to);

 /* protected: */
 /* 	virtual void patch_loader_checksum(); */

 public:
	l_info _linfo;

 protected:
	unsigned char* _loader;
	unsigned _lsize;
	unsigned _loader_code_size;
	unsigned _loader_code_offset;
	unsigned _loader_entry;
	unsigned _loader_entry_size;
	unsigned _loader_exit;
	unsigned _loader_control;
	ElfDynamicTools* _elftools;
	unsigned char* _loader_to;
	unsigned char* _target;
	struct arguments _opts;
	loader_inside_vars_t _loader_inside_globals;     /* 系统变量表 */
	loader_outside_vars_t _loader_outside_globals;   /* 外部变量表 */
};

#endif
 
