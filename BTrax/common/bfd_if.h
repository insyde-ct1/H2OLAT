/*****************************************************************************/
/* The development of this program is partly supported by IPA                */
/* (Information-Technology Promotion Agency, Japan).                         */
/*****************************************************************************/

/*****************************************************************************/
/*  bfd_if.h - BFD library interface header                                  */
/*  Copyright: Copyright (c) Hitachi, Ltd. 2005-2009                         */
/*             Authors: Yumiko Sugita (yumiko.sugita.yf@hitachi.com),        */
/*                      Satoshi Fujiwara (sa-fuji@sdl.hitachi.co.jp)         */
/*                                                                           */
/*  This program is free software; you can redistribute it and/or modify     */
/*  it under the terms of the GNU General Public License as published by     */
/*  the Free Software Foundation; either version 2 of the License, or        */
/*  (at your option) any later version.                                      */
/*                                                                           */
/*  This program is distributed in the hope that it will be useful,          */
/*  but WITHOUT ANY WARRANTY; without even the implied warranty of           */
/*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            */
/*  GNU General Public License for more details.                             */
/*                                                                           */
/*  You should have received a copy of the GNU General Public License        */
/*  along with this program; if not, write to the Free Software              */
/*  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111 USA      */
/*****************************************************************************/

#ifndef __BFD_IF_H__
#define __BFD_IF_H__

//#include <bfd.h>
//#include <dis-asm.h>
//#include <libiberty.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
//#include <elf.h>
#ifdef HAVE_LIBDW
#  include <argp.h>
#  include <dwarf.h>
#  include <elfutils/libdwfl.h>
#endif
#include "avltree.h"

struct sect_cache {
	asection	*sect;
	bfd_vma		vma;
	bfd_size_type	size;
	bfd_byte	*data;
};

struct code_sect {
	asection		*section;
};

// define and structure for kernel patch information
#define MCOUNT_START		"__start_mcount_loc"
#define MCOUNT_STOP		"__stop_mcount_loc"
#define	MCOUNT_SECT		"__mcount_loc"
#define	INIT_RODATA_SECT	"__init_rodata"
#define	ALT_INST_SECT		".altinstructions"
#define	REP_INST_SECT		".altinstr_replacement"
#define	PARA_INST_SECT		".parainstructions"
#define NOP_INST		0x90
#define CALL_INST		0xe8
#define JMP_INST		0xe9

//	Kernel's structure
struct alt_instr {
	unsigned char *instr;
	unsigned char *replacement;
	unsigned char cpuid;
	unsigned char instrlen;
	unsigned char replacementlen;
	unsigned char pad;
};
struct paravirt_patch {
	unsigned char *instr;
	unsigned char instrtype;
	unsigned char len;
	unsigned short clobbers;
};

//	Format for the paravirt patch info log data
struct pvpatch_log {
	// copy from 'struct paravirt_patch'
	union {
		struct {
			unsigned char instrtype;
			unsigned char len;
			unsigned short clobbers;
		} k;
		unsigned int orig_info;
	};
	unsigned char type;
	#define PVPT_NOP	0
	#define PVPT_JMP	1
	#define PVPT_CALL	2
	#define PVPT_INSN	3

	unsigned char len;	// JMP or CALL: 4, INSN: N
	unsigned char *p;	// JMP or CALL: target, INSN: pointer to N-data
};

struct kpatch_info {
	unsigned long		koffset;
	unsigned char		*altinst_bitmap;
	int			n_pvinst;
	struct pvpatch_log	**pvinst_array;
};

struct bfd_if {
	bfd			*abfd;
	asymbol			**p_syms;
	int			n_syms;
	asymbol			**p_dynsyms;
	int			n_dynsyms;
	asymbol			*p_synsyms;
	int			n_synsyms;
	asymbol			**p_fsyms;
	int			n_fsyms;
	arelent			**p_relocs;
	int			n_relocs;
	struct disassemble_info	info;
	struct sect_cache	cache;
	bool_t			has_debuginfo;
	unsigned long		load_vaddr;

	// This structure has all code section other than modules' ".init".
	struct code_sect	*p_code_sects;
	int			n_code_sects;
#ifdef HAVE_LIBDW
	Dwfl			*dwfl;
#endif
	unsigned long		begin;
	unsigned long		end;
	struct kpatch_info	kpatch_info;
};

enum branch_type {
	BTYPE_BRANCH,
	BTYPE_JMP,
	BTYPE_CALL,
	BTYPE_RET,
	BTYPE_IRET,
	BTYPE_INT,
	BTYPE_BREAK,
	BTYPE_OTHER,
};
/* When limiting the coverage output by function-list, limitted paths are
 * marked as "invalid".
 */
#define IS_INVALID_PATH		(1 << 31)

#define	RELOC_TYPE_PC32		2

struct jmp_to {
	void		*r2n;
	unsigned long	addr;
};

struct unknown {
	struct jmp_to	jmp_to;
	unsigned int	cnt;
	struct unknown	*next;
};

struct path {
	unsigned long	addr;		/* state start address */
	int		cnt;		/* -1 means next and jmp not linked */
	int		type;
	unsigned long	base;		/* last instruction address in a path */
	unsigned long	next;		/* fallthrough address
					 * ('next' equals next-path's 'addr')
					 */
	int		next_cnt;	/* -1 means switch case jump */
	struct jmp_to	jmp_to;
	/*unsigned long	jmp;*/		/* branch/jmp/call destination address
					 * if jmp == UNKNOWN_BADDR then jmp_cnt
					 * is pointer to 'struct unknown'
					 */
	long		jmp_cnt;
};

// structure for read from IMF
struct imf_esym {
	int 	      i;	// index of 'p_fsyms'
	unsigned long a_addr;	// resolved address (by using 'kallsyms')
};
struct imf_esym_info {
	struct imf_esym esym;
	struct imf_esym_info *next;
};
struct imf_bi_info {
	unsigned long kern_offset;
	unsigned int pt_num;
	unsigned int sym_num;
	struct imf_esym_info *esym_info;
};

typedef int (*t_func_for_fsym)(unsigned long, const char*, void*);


/*------ proto-type ------*/
/* initialize */
int init_bfd_if(struct bfd_if*, const char*, const char*, char*,
		struct imf_bi_info*);
int read_kpatchinf(struct bfd_if*, unsigned long, char*);
unsigned long get_offset_addr(struct bfd_if*, unsigned long);
void get_kernel_min_max_addr(struct bfd_if*, unsigned long*, unsigned long*);
void remove_useless_fsyms(struct bfd_if*, unsigned long, unsigned long,
			  unsigned long);
/* path-tree */
int chk_path_tree(struct bfd_if*, struct path***, int*, bool_t);
bool_t kernel_has_ud2_src_info(struct bfd_if*);
struct path* find_path_in_path_array(struct path**, int*, unsigned long);
void free_path(struct path*);

/* utility */
int init_dwarf(struct bfd_if *bi, const char *obj_name);
void free_bi(struct bfd_if *bi);
int get_source_info(struct bfd_if*, unsigned long, const char**,
		    const char**, const char**, int*);
int addr_to_func_name_and_offset(struct bfd_if*, unsigned long,
				 const char**, size_t*);
void* get_section_data(struct bfd_if *bi, const char *name, size_t *len,
		       unsigned long *addr);
int addr_in_init_sect(struct bfd_if *bi, unsigned long addr);
int f_cmp_pvplog(const void *p1, const void *p2);
void printf_func_name(const char*, size_t);
int printf_mnemonic(struct bfd_if*, unsigned long, unsigned long*);
asymbol* get_symbol(struct bfd_if*, unsigned long, unsigned long*);
int get_data_addr_of_symbol(struct bfd_if*, const char*, unsigned long*);
int get_addr_of_symbol(struct bfd_if*, const char*, unsigned long*);
int get_addr_of_symbol_all(struct bfd_if*, const char*, unsigned long**);
bool_t get_begin_of_func(struct bfd_if*, unsigned long, unsigned long*);
bool_t get_end_of_func(struct bfd_if*, unsigned long, unsigned long*);
int for_each_fsymbols(struct bfd_if *bi, t_func_for_fsym f, void *data);
void dump_bfd_symbols(struct bfd_if*, unsigned long, unsigned long);
#ifdef RELOC_TEST
void enable_reloc_test(void);
#endif

extern bool_t ignore_elf_errors;
#endif /* __BFD_IF_H__ */
