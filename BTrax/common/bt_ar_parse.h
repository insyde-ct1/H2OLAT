/*****************************************************************************/
/* The development of this program is partly supported by IPA                */
/* (Information-Technology Promotion Agency, Japan).                         */
/*****************************************************************************/

/*****************************************************************************/
/*  bt_ar_parse.h - /proc/modules and /proc/PID/maps parse header            */
/*  Copyright: Copyright (c) Hitachi, Ltd. 2005-2010                         */
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

#ifndef __BT_AR_PARSE_H__
#define __BT_AR_PARSE_H__

#include "bt.h"
//#include "bfd_if.h"
#include "bt_utils.h"
//#include <libgen.h>
#include <limits.h>
#include <io.h>

#define	ALL_PID			-1
#define KERNEL			"vmlinux"

struct addr_range {
	unsigned long		begin;
	unsigned long		end;
	struct addr_range	*next;
};

struct pid_range {
	pid_t				pid;
	struct addr_range	*range;
	struct pid_range	*next;
};

#define MAX_FIX_FROM_CACHE	1024
struct fix_from_cache {
	UINT64					from;
	UINT64					to;
	UINT64					fixed_from;
	struct range_to_name	*r2n;
	struct path				*path;
	int						id;
	struct fix_from_cache	*next;
};

enum elf_type {
	ETYPE_KERNEL,
	ETYPE_OUT_OF_RANGE_KERNEL,
	ETYPE_MODULE,
	ETYPE_LIB,
	ETYPE_APPLICATION,
};

struct range_to_name {
	UINT64			begin;
	UINT64			end;
	unsigned long	offset;
	char			name[PATH_MAX];
	char			*dirname;
	char			*basename;
	int				etype;
	bool_t			skip_ud2_srcinfo;

	struct bfd_if	bi;
	struct path		**path_array;
	int				num_path_array;

	struct fix_from_cache	*fix_from_cache;
};
static inline int is_kernel(struct range_to_name *r2n)
{
	return r2n->etype == ETYPE_KERNEL ||
			r2n->etype == ETYPE_OUT_OF_RANGE_KERNEL;
}
static inline int is_oor_kernel(struct range_to_name *r2n)
{
	return r2n->etype == ETYPE_OUT_OF_RANGE_KERNEL;
}
static inline int is_module(struct range_to_name *r2n)
{
	return r2n->etype == ETYPE_MODULE;
}
static inline int is_lib(struct range_to_name *r2n)
{
	return r2n->etype == ETYPE_LIB;
}
static inline int is_app(struct range_to_name *r2n)
{
	return r2n->etype == ETYPE_APPLICATION;
}
static inline int is_lib_or_app(struct range_to_name *r2n)
{
	return r2n->etype == ETYPE_LIB || r2n->etype == ETYPE_APPLICATION;
}
#define for_each_path(r2n, i, p) \
	for ((i) = 0; \
	     (i) < (r2n)->num_path_array && ((p) = (r2n)->path_array[(i)]); \
	     (i)++)
#define get_r2n_offset(r2n)						\
	((r2n) ? (r2n)->offset : 0)
#define get_r2n_path_array(r2n)						\
	((r2n) ? (r2n)->path_array : NULL)
#define get_jmp_a_addr(jmp_to) 						\
	((jmp_to).addr + get_r2n_offset((struct range_to_name*)(jmp_to).r2n))
#define same_a_addr(jmp_to, a_addr)					\
	(get_jmp_a_addr(jmp_to) == a_addr)
#define r2n_name_of_jmp(r2n, jmp_to)					\
	((jmp_to).r2n ?							\
	 ((jmp_to).r2n == (r2n) ?					\
	  "(self)" : ((struct range_to_name*)(jmp_to).r2n)->basename) : "")

struct r2n_info {
	struct range_to_name	**all_r2n;
	int			num_r2n;
	bool_t			from_is_next;
	char			*uname_r;

	// used for merging different logs
	struct range_to_name	**all_r2n_unmapped;
	int			num_r2n_unmapped;
};

#define eprintf(...)	fprintf(stderr, __VA_ARGS__)
#ifdef DEBUG
#define dprintf(...)	do { if ((verbose)) printf(__VA_ARGS__) }
#define ddprintf(...)	do { if ((verbose) >=2 ) printf(__VA_ARGS__) }
#else
#define dprintf(...)
#define ddprintf(...)
#endif

void alloc_pid_range(pid_t);
void free_ranges(void);
char* range2ulongs(char*, unsigned long*, unsigned long*);
int add_range(pid_t, unsigned long, unsigned long);
int del_range(pid_t, unsigned long, unsigned long);
void dump_ranges(void);
struct pid_range *get_all_ranges(void);
struct addr_range *get_pid_addr_range(pid_t);
bool_t is_addr_range_match(unsigned long, unsigned long, struct addr_range*);
int get_symbol_dest(struct r2n_info*, const char*, struct jmp_to*);
int get_symbol_dest_all(struct r2n_info*, const char*, struct jmp_to**);
const char* get_fname(struct jmp_to* fdest);
const char* get_fname_and_offset(struct jmp_to* fdest, unsigned long *offset);
bool_t get_func_info(struct jmp_to*, UINT64*);
struct path *find_path_by_a_addr(struct range_to_name*, int*, UINT64);
struct path *find_path_by_addr(struct range_to_name*, int*, UINT64);
void printf_path(struct range_to_name*, struct path*);
void dump_path_tree(struct range_to_name*);

bool_t get_maps_fpath(char*, char*);

void set_elf_path_prefix(char *prefix);
char* get_elf_path_prefix(void);
int chk_maps_in_log(struct r2n_info*, union bt_record*);
int parse_modules(struct r2n_info*, char *dir, bool_t for_coverage,
		  bool_t verbose);
int parse_maps(struct r2n_info*, char *maps_fpath, bool_t verbose);
int create_path_trees(struct r2n_info*, bool_t);
void sort_r2n_by_elf_path(struct r2n_info*);
int mapping_r2n(struct map_info*, void*);
void save_lib_and_app_as_unmapped(struct r2n_info*);
void save_oor_kernel_as_unmapped(struct r2n_info*);
void save_r2n_as_unmapped(struct r2n_info*);
void restore_r2n_as_mapped(struct r2n_info*);
void chk_and_modify_same_basename(struct r2n_info*);

#define	FROM_IS_NEXT_FNAME	"from_is_next"
bool_t chk_from_is_next(char*);

typedef int (*func_each_r2n)(struct r2n_info*, struct range_to_name*, void *);
int for_each_r2n(struct r2n_info *r2i, func_each_r2n f, void *data);

void dump_r2n(struct r2n_info*);
void free_r2n(struct r2n_info*);
struct range_to_name* addr_to_r2n(struct r2n_info*, UINT64);
void fix_x86_64_core2_from(struct bt_log*);
int chk_fix_from_cache(struct r2n_info*, UINT64*, UINT64, 
		       struct range_to_name**, struct path**, int*);
int set_uname(struct r2n_info*, char*);

/* checking enter to and leave from functions or interrupt */
void chk_nest_initialize(void);

typedef enum {
	EL_NONE_FROM_AND_TO_OOR = 0,	// 'OOR' stands for 'out of range'
	EL_NONE_BRANCH_OR_JUMP,
	EL_ENTER,
	EL_LEAVE,
} enter_leave_t;

enter_leave_t chk_enter_leave(struct r2n_info *r2i, struct bt_log *p,
			      int *inst_type, int *type, int *nest,
			      struct range_to_name **p_r2n_from,
			      struct range_to_name **p_r2n_to,
			      struct path **pp_from, int *p_idx_from);

#endif /* __BT_AR_PARSE_H__ */
