#include "dog_common.h"

/* 修订退出点 */
void DogTools::fix_exit() {
	unsigned word = 0;
	/* 从_pack_obuf中读取各种数据 */
	Elf32_Ehdr* header = (Elf32_Ehdr*)(unsigned char*)_pack_obuf;
	unsigned phoff = get_te32(&header->e_phoff);
	Elf32_Phdr* phdr0 = (Elf32_Phdr*)((unsigned char*)_pack_obuf + phoff);
	Elf32_Phdr* phdr = NULL;

	unsigned dt_finit_offset = 0;
	/* 修订在新PT_DYNAMIC中的DT_INIT的值 */
	phdr = phdr0 + _hack_data_dt_finit.pt_dynamic_index;
	dt_finit_offset = _hack_data_dt_finit.dv->inside_offset - sizeof(unsigned);
	dt_finit_offset += get_te32(&phdr->p_offset);
		
	/* 修订新的入口点 */
	set_te32(&word, _loader_exit_va);
	memcpy((unsigned char*)_pack_obuf + dt_finit_offset + sizeof(unsigned),
		   &word, sizeof(unsigned));

	set_te32(&word, DT_FINI);
	memcpy((unsigned char*)_pack_obuf + dt_finit_offset,
		   &word, sizeof(unsigned));
}

/* 修订入口点 */
void DogTools::fix_entry() {
	unsigned word = 0;
	/* 从_pack_obuf中读取各种数据 */
	Elf32_Ehdr* header = (Elf32_Ehdr*)(unsigned char*)_pack_obuf;
	unsigned phoff = get_te32(&header->e_phoff);
	Elf32_Phdr* phdr0 = (Elf32_Phdr*)((unsigned char*)_pack_obuf + phoff);
	Elf32_Phdr* phdr = NULL;

	if (_use_dt_init) {
		unsigned dt_init_offset = 0;
		/* 修订在新PT_DYNAMIC中的DT_INIT的值 */
		phdr = phdr0 + _hack_data_dt_init.pt_dynamic_index;
		dt_init_offset = 
			_hack_data_dt_init.dv->inside_offset - sizeof(unsigned);
		dt_init_offset += get_te32(&phdr->p_offset);
		
		/* 修订新的入口点 */
		set_te32(&word, _loader_entry_va);
		memcpy((unsigned char*)_pack_obuf + dt_init_offset + sizeof(unsigned),
			   &word, sizeof(unsigned));

		/* 重写类型,为了DT_INIT_SPECIAL函数的兼容 */
		set_te32(&word, DT_INIT);
		memcpy((unsigned char*)_pack_obuf + dt_init_offset,
			   &word, sizeof(unsigned));
	} else {
		/* 找到INIT_ARRAY以及INIT_ARRAYSZ的新位置 */
		unsigned dt_init_array_offset = 0, dt_init_arraysz_offset = 0;

		phdr = phdr0 + _hack_data_dt_init_array.pt_dynamic_index;

		dt_init_array_offset = _hack_data_dt_init_array.dv->inside_offset;
		dt_init_array_offset += get_te32(&phdr->p_offset);

		set_te32(&word, _hack_data_dt_init_array.offset);
		memcpy((unsigned char*)_pack_obuf + dt_init_array_offset,
			   &word, sizeof(unsigned));

		/* 设置INIT_ARRAYSZ */
		dt_init_arraysz_offset = _pack_elftools->_dt_init_arraysz.inside_offset;
		dt_init_arraysz_offset += get_te32(&phdr->p_offset);

		set_te32(&word, _pack_elftools->_dt_init_arraysz.size + 
				 sizeof(unsigned));
		memcpy((unsigned char*)_pack_obuf + dt_init_arraysz_offset,
			   &word, sizeof(unsigned));

		/* 设置新的重定位表 */
		if (_dt_init_array_in_rel_type == 2) {
			unsigned dt_rel_offset = 0;
			phdr = phdr0 + _hack_data_dt_rel.pt_dynamic_index;

			dt_rel_offset = _hack_data_dt_rel.dv->inside_offset;
			dt_rel_offset += get_te32(&phdr->p_offset);

			set_te32(&word, _hack_data_dt_rel.offset);
			memcpy((unsigned char*)_pack_obuf + dt_rel_offset,
				   &word, sizeof(unsigned));

			/* 修改长度 */
			unsigned dt_rel_size_offset = 0;
			dt_rel_size_offset = _hack_data_dt_rel.dv->support->inside_offset;
			dt_rel_size_offset += get_te32(&phdr->p_offset);

			set_te32(&word, _hack_data_dt_rel.size + 8);
			memcpy((unsigned char*)_pack_obuf + dt_rel_size_offset,
				   &word, sizeof(unsigned));
		} else {
			unsigned dt_plt_rel_offset = 0;
			phdr = phdr0 + _hack_data_dt_plt_rel.pt_dynamic_index;
			
			dt_plt_rel_offset = _hack_data_dt_plt_rel.dv->inside_offset;
			dt_plt_rel_offset += get_te32(&phdr->p_offset);

			set_te32(&word, _hack_data_dt_plt_rel.offset);
			memcpy((unsigned char*)_pack_obuf + dt_plt_rel_offset,
				   &word, sizeof(unsigned));

			/* 修改长度 */
			unsigned dt_plt_rel_size_offset = 0;
			dt_plt_rel_size_offset = _hack_data_dt_plt_rel.dv->support->inside_offset;
			dt_plt_rel_size_offset += get_te32(&phdr->p_offset);

			set_te32(&word, _hack_data_dt_plt_rel.size + 8);
			memcpy((unsigned char*)_pack_obuf + dt_plt_rel_size_offset,
				   &word, sizeof(unsigned));
		}/* end else */
	}/* end else */

	/* 更新elf工具 */
	_pack_elftools->update_merge_mem();
}
