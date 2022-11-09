/*****************************************************************************/
/* The development of this program is partly supported by IPA                */
/* (Information-Technology Promotion Agency, Japan).                         */
/*****************************************************************************/

/*****************************************************************************/
/*  bt_utils.h - utilities header                                            */
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

#ifndef __BT_UTILS_H__
#define __BT_UTILS_H__

#include <windows.h>
#include "bt.h"
#include "avltree.h"
//#include <libgen.h>
#include <limits.h>
#include <tchar.h>
#include "dispdb.h"

#define VERSION			"100.00.03.02"
#define RELEASE_YEAR	"2017"
#define pid_t			UINT64 //long
#define PATH_MAX		1024 //260
#define inline
//#define HGLOBAL			unsigned __int64
//typedef unsigned char	*PBYTE;		
//typedef void (*ReportProgressFtn) (int);

int u_open(const char*, off_t*);
int u_close(int);
off_t u_lseek(int, off_t, int);
size_t u_read(int, void*, size_t);
size_t u_write(int, const void*, size_t);
int read_4b_aligned_string(int, char*, int);
int write_4b_aligned_string(int, char*);
char* conv_slash2underscore(char*, bool_t);

typedef int (*t_func_each_bt_record)(FILE*, union bt_record*, off_t, void*);
int for_each_block_record(FILE*, int, off_t, off_t, t_func_each_bt_record, void*);

typedef int (*proc_cpu_files_t)(int cpu, char *cpu_path, size_t size, void *dt);
int proc_cpu_files(char *dir_path, proc_cpu_files_t handler, void *dt);
int count_cpu_files(char *dir_path);

typedef struct _FUNC_DESC1 {
	unsigned __int64	StartAddr;
	unsigned __int64	Length;
	unsigned long		slno;
	unsigned long		elno;
	CHAR				Name[80];
} FUNC_DESC1;

struct bfd_if {
	UINT64				BaseAddr;
	UINT64				EntryPoint;
	long				BaseAddrAdjust;
	unsigned long		Size;
	unsigned long		SerialNumber;
	unsigned long		CpuMode;
	char				ModuleFullName[256];
	char				**SourceNameList;
	long				NumOfSourceNames;
	VAR_DESC			*GlobalVarList;
	FUNC_DESC1			*FuncList;
	long				NumOfGlobalVars;
	long				NumOfFuncs;
	FILETIME			FileTime;
	void				*PdbDataSource;
	void				*PdbSession;
	void				*PdbBuffer;
	HGLOBAL				PdbBufferHandle;
	UINT64				begin;
	UINT64				end;
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

#define IS_INVALID_PATH		(1 << 31)

struct jmp_to {
	void		*r2n;
	UINT64		addr;
};

struct unknown {
	struct jmp_to	jmp_to;
	unsigned int	cnt;
	struct unknown	*next;
};

struct branch_node {
	UINT64 addr_to;
	UINT64 addr_from;
	unsigned long cnt;
	//int isTo;
	struct branch_node *next;
};

struct path {
	UINT64			addr;		/* state start address */
	int				cnt;		/* -1 means next and jmp not linked */
	int				type;
	UINT64			base;		/* last instruction address in a path */
	UINT64			next;		/* fallthrough address
					 * ('next' equals next-path's 'addr')
					 */
	int				next_cnt;	/* -1 means switch case jump */
	struct jmp_to	jmp_to;
	/*unsigned long	jmp;*/		/* branch/jmp/call destination address
					 * if jmp == UNKNOWN_BADDR then jmp_cnt
					 * is pointer to 'struct unknown'
					 */
	long			jmp_cnt;
	
	unsigned long	length;
	unsigned long	slno, elno;
	struct branch_node *exec_node, *last_to_node;
	unsigned long	num_exec_node;
	//struct path		*child;
};

/* check the log file's split point */
#define MAX_CPU_FILES	64
struct log_file_info {
	char			*fpath;
	int			fd;
	off_t			size;
};
struct tv {
	unsigned int		tv_sec;
	unsigned int		tv_usec;
};
struct __pid_info {
	struct log_file_info	*finfo;
	unsigned long long	clocks;
	off_t			i_rec;
	off_t			n_rec;
};
struct pid_log_info {
	pid_t			pid;
	char			comm[BT_COMM_LEN + 1];
	unsigned long long	comm_clocks;
	node			*info;	// avl-tree of struct __pid_info
};
typedef int (*proc_pid_log_info_t)(struct pid_log_info *p, void *data);

int initialize_log_info(char *files[]);
void finalize_log_info(void);

int chk_pid_pos(char *files[], bool_t is_search,unsigned long search_addr);
void print_pid_info(void);

struct map_info {
	unsigned long vm_start, vm_end;
	int left_epath_len;
	char epath[PATH_MAX];
};
typedef int (*hook_maps_in_log_t)(struct map_info*, void*);
int do_maps_in_log(union bt_record*, char*, struct map_info*,
		   hook_maps_in_log_t, void*);

void dump_pid_pos(void);
int for_each_pid_log_info(proc_pid_log_info_t func, void *data);
inline struct log_file_info *get_log_file_info(struct __pid_info *p);
void free_path(struct path *p);
int get_source_info(struct bfd_if *bi, UINT64 addr,
			   char **comp_dir, char **src_name,
			   char **func_name, DWORD *line, size_t *offset //int *lno
			   );
void printf_func_name(const char*, size_t);

#endif /* __BT_UTILS_H__ */
