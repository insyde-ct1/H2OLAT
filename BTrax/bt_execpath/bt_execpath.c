/*****************************************************************************/
/* The development of this program is partly supported by IPA                */
/* (Information-Technology Promotion Agency, Japan).                         */
/*****************************************************************************/

/*****************************************************************************/
/*  bt_execpath.c - execution path display program                           */
/*  Copyright: Copyright (c) Hitachi, Ltd. 2005-2010                         */
/*             Authors: Yumiko Sugita (yumiko.sugita.yf@hitachi.com),        */
/*                      Satoshi Fujiwara (sa-fuji@sdl.hitachi.co.jp)         */
/*                      Akihiro Nagai (akihiro.nagai.hw@hitachi.com)         */
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

#include "chk_repeat.h"
#include "bt_ar_parse.h"
#include "bt_utils.h"
#include "..\bt_coverage\bt_hconv.h"
#include <stdio.h>
#include <stdlib.h>
#include <direct.h>
//#include "..\BTrax.h"
#include "Getopt.h"
#include "dispdb.h"

#define BT_EXECPATH_VER	VERSION
#define	COPYRIGHT	"Copyright (c) Hitachi, Ltd. 2005-" RELEASE_YEAR

struct proc_each_rec_data {
	struct addr_range	*range;
};

struct proc_each_range_data {
	int	fd;
	off_t	i_rec_max;
	off_t	i_start;
	off_t	i_stop;
	bool_t	match_found;
	off_t	match_i_rec;
};

typedef enum {
	SUMMARY_NORMAL,
	SUMMARY_DETAIL,
}summary_t;

bool_t output_summary = FALSE;
summary_t summary_type = SUMMARY_NORMAL;
bool_t verbose = FALSE;
bool_t output_binary = FALSE;	// don't get source information
//unsigned long glevel = 0;
//bool_t gjump_back = FALSE;

struct r2n_info r2n_info;

//PPDB_FUNCS gPdb = NULL;

void __print_nest_space(FILE*, int);

/*----------------------------------------------------------------------------
 *  get function name and mnemonic
 *----------------------------------------------------------------------------
 */
int get_source_info(struct bfd_if *bi, UINT64 addr,
			   char **comp_dir, char **src_name,
			   char **func_name, DWORD *line, size_t *offset //int *lno
			   ) //need_inline_func_caller
{
	//int rc = FAILURE;
	//asection *sect;
	//UINT64 laddr = 0;
	//LINE_DESC lines = {0};

	//laddr += addr;
	*src_name = *func_name = NULL;
	*line = 0;
	*offset = 0;
#ifdef TEST
	return FAILURE;
#endif
	/*
	if (!bi->has_debuginfo)
		return FAILURE;
	sect = get_sect_has_addr(bi, addr);
	if (!sect)
		return FAILURE;
	rc = bfd_find_nearest_line(bi->abfd, sect,
				   bi->n_syms ? bi->p_syms : bi->p_dynsyms,
				   (bfd_vma)addr - sect->vma,
				   src_name, func_name, (unsigned int*)lno);
	*/
	if (PdbQueryModuleByAddr(addr, src_name, line, func_name)) {
		//if (lines->NumOfLines > 10)
		//	return FAILURE;
		//*lno = lines.LastLine;
		return SUCCESS;
	}
	return FAILURE;
}

//void printf_func_name(FILE *f, const char *func_name, size_t offset)
void printf_func_name(const char *func_name, size_t offset)
{
	if (offset)
		printf("%s:%d", func_name, offset);
	else
		printf("%s", func_name);
}

static struct range_to_name *s_last_r2n = NULL;
struct path *s_last_p = NULL;
static void *s_levels[4096] = {0};
static int s_last_level = 0;
static size_t s_last_lno = 0;
static char s_dir[_MAX_DIR];
static char s_mname[_MAX_FNAME];
static char s_fname[_MAX_FNAME];
static char s_fext[_MAX_EXT];

void initvars()
{
	s_last_r2n = NULL;
	s_last_p = NULL;
	s_last_lno = 0;
	s_dir[0] = 0;
	s_mname[0] = 0;
	s_fname[0] = 0;
	s_fext[0] = 0;
	s_last_level = 0;
	memset(s_levels, 0, sizeof(void*) * 4096);
}

void print_exec_line(FILE *f, UINT64 a_addr, struct range_to_name *r2n, int nest, unsigned long cnt, unsigned short isTo)
{
	int rc;
	size_t offset = 0;
	char *comp_dir = NULL, *src_name, *func_name;
	struct bfd_if *bi;
	UINT64 addr;
	//BYTE isprint_mname;
	BOOL isprint_newline; //, force_newlevel;
	struct path *p;
	//void *cur_p, *tmp_p;
	DWORD line;
	int i;

	if (r2n)
	{
		bi = &r2n->bi;
		addr = a_addr - r2n->offset;
		rc = output_binary ?
			FAILURE : get_source_info(bi, addr, &comp_dir, &src_name,
						  &func_name, &line, &offset);
		if (rc == SUCCESS && src_name) {
			i = r2n->num_path_array;
			p = find_path_by_a_addr(r2n, &i, addr);
			if (!p)
				return;
			//isprint_mname = 0;
			if (s_last_r2n != r2n) {
				//isprint_mname = 1;
				s_last_r2n = r2n;
				_splitpath_s(bi->ModuleFullName, NULL, 0, s_dir, _MAX_DIR, s_mname, _MAX_FNAME, NULL, 0);
			}

			//force_newlevel = FALSE;
			if (s_last_p != p) {
				_splitpath_s(src_name, NULL, 0, s_dir, _MAX_DIR, s_fname, _MAX_FNAME, s_fext, _MAX_EXT);

				// Handle return
				//if (s_last_p && (s_last_lno == s_last_p->elno) && (line != p->slno)) {
				if (line != p->slno) {
					//if (s_last_p && (s_last_lno != s_last_p->elno)) {
					//	force_newlevel = TRUE;
					//} else {
						isprint_newline = FALSE;
						while (s_last_level && (s_levels[s_last_level] != (void*)p)) {
							s_last_level--;
							isprint_newline = TRUE;
							fprintf(f, "</ul>");
						}
						if (isprint_newline) fprintf(f, "\n");
					//}
				}
				s_last_p = p;
				s_last_lno = 0;			
			}
			
			//if ((!s_last_level && (line != p->elno)) || (line == p->slno) ) {
			//if (!s_last_level || (line == p->slno) || force_newlevel) {
			if (!s_last_level || (line == p->slno)) {
				s_levels[++s_last_level] = (void*)p;
				fprintf(f, "<li class=\"folder\" title=\"Module: %s&#10;Path: %s%s%s\">%s\n<ul>\n", 
					s_mname, s_dir, s_fname, s_fext, func_name);
			}
			
			if (s_last_lno != line) {
				s_last_lno = line;

				if (nest) {
					fprintf(f, "<li title=\"Repeat %d times\" %s>", cnt, isTo ? "data-to=\"1\"":"");
					//if (isTo)
					//	fprintf(f, " data-to=\"1\"");
					//fprintf(f, ">");
					__print_nest_space(f, nest);
				} else {
					//fprintf(f, isTo? "<li title=\"%s-%d\" data-to=\"1\">":"<li title=\"%s-%d\">", func_name, s_last_level);
					fprintf(f, isTo? "<li data-to=\"1\">":"<li>");
				}
				fprintf(f, "L(%d):%d\n", isTo, line);
				/*
				if (line == p->elno) {
					isprint_newline = FALSE;
					while (s_last_level ) {
						isprint_newline = TRUE;
						fprintf(f, "</ul>");
						if (s_levels[s_last_level--] == (void*)p)
							break;
					}
					if (isprint_newline) fprintf(f, "\n");
				}
				*/
			}
		}
	}
}

/*----------------------------------------------------------------------------
 *  normal output support
 *----------------------------------------------------------------------------
 */
bool_t __cmp_N(const void *p1, const void *p2)
{
	return ((ULONGLONG)p1 == (ULONGLONG)p2);
}

void __print_nest_space(FILE *f, int nest)
{
	int i;

	for (i = 0; i < nest; i++)
		fprintf(f, "> "); // &nbsp;
}

void __print_nest_space_N(int nest)
{
	int i;

	for (i = 0; i < nest; i++)
		printf("  ");
}

void __print_data_N(FILE *f, int nest, const void *p, unsigned long cnt, unsigned short isTo)
{
	struct range_to_name *r2n;
	unsigned long addr = (unsigned long)p;
	ULONGLONG lladdr = 0;

	lladdr += addr;
	//fprintf(f, "<tr><td>");
	//__print_nest_space_N(f, nest);
	r2n = addr_to_r2n(&r2n_info, addr);
	/*
	if (!r2n) {
		if (addr != 0) {
			//fprintf(f, "--------\t0x%08x", addr);
			fprintf(f, "<tr><td></td><td>");
			__print_nest_space(f, nest);
			fprintf(f, "0x%010x", addr); //</td><td>
		}
	} else
	*/
		print_exec_line(f, lladdr, r2n, nest, cnt, isTo);
#ifdef _OUT_TABLE
	fprintf(f, "</td></tr>\n");
#endif
}

void __print_start_repeat_N(FILE *f, int nest, unsigned long cnt)
{
	//__print_nest_space_N(f, nest);
	//printf("===> repeat %ld times\n", cnt);
#ifdef _OUT_TABLE
	fprintf(f, "<tr><td></td><td>");
	__print_nest_space(f, nest);
	fprintf(f, "===> repeat %ld times</td></tr>", cnt); //<td></td>
#endif
}

struct chk_repeat_funcs chk_repeat_funcs_N =
{
	__cmp_N,
	NULL,
	__print_data_N,
	__print_start_repeat_N,
	NULL,
};

void proc_each_addr(FILE *f, UINT64 addr, unsigned short isTo)
{
	static UINT64 last_addr = 0;

	if (addr == last_addr)
		return;
	last_addr = addr;
	
	chk_repeat_each(f, (const void*)addr, isTo);
}

void print_a_record(union bt_record *p)
{
	static FILE *f = NULL;
	struct range_to_name *r2n;
	struct bfd_if *bi;
	DWORD line;
	int rc; //, lno;
	size_t offset = 0;
	char *comp_dir = NULL, *src_name, *func_name;
	UINT64 addr;
	errno_t err;
	//unsigned long i;

	if (!f)
	{
		char szWorkingDir[PATH_MAX] = {0}, szOutFile[PATH_MAX] = {0};
		
		_getcwd(szWorkingDir, PATH_MAX);		
		sprintf_s(szOutFile, PATH_MAX, "%s\\out\\Addr2Func.data", szWorkingDir);
		err = fopen_s(&f, szOutFile, "w");
	}

	// from
	r2n = addr_to_r2n(&r2n_info, (unsigned long)p->log.from);
	if (r2n)
	{
		bi = &r2n->bi;
		addr = p->log.from - r2n->offset;
		rc = get_source_info(bi, addr, &comp_dir, &src_name,
						  &func_name, &line, &offset);
		if (rc == SUCCESS)
		{
			fprintf(f, "0x%09I64x(0): %s:%d", addr, func_name, line);
			/*
			if (lines.NumOfLines > 1)
			{
				fprintf(f, "(");
				for (i = 0; i < lines.NumOfLines; i++)
				{
					fprintf(f, "%d,", lines.Lines[i]);
				}
				fprintf(f, ")");
			}
			*/
			fprintf(f, "\n");
		}
	}
	
	// to
	r2n = addr_to_r2n(&r2n_info, (unsigned long)p->log.to);
	if (r2n)
	{
		bi = &r2n->bi;
		addr = p->log.to - r2n->offset;
		rc = get_source_info(bi, addr, &comp_dir, &src_name,
						  &func_name, &line, &offset);
		if (rc == SUCCESS)
		{
			fprintf(f, "0x%09I64x(1): %s:%d", addr, func_name, line);
			/*
			if (lines.NumOfLines > 1)
			{
				fprintf(f, "(");
				for (i = 0; i < lines.NumOfLines; i++)
				{
					fprintf(f, "%d,", lines.Lines[i]);
				}
				fprintf(f, ")");
			}
			*/
			fprintf(f, "\n");
		}
	}
}

static struct map_info map_info;

int proc_each_record_for_normal(FILE *f, union bt_record *__p, off_t i_rec, void *data)
{
	//int rc;
	struct proc_each_rec_data *dt = data;
	union bt_record p = *__p;
	/*
	if (is_warn_record(&p)) {
		printf("WARN: bts left only: %d\n", p.warn.left);
		return CONTINUE;
	}
	if (is_pid_record(&p) || is_comm_record(&p))
		return CONTINUE;
	if (is_map_record(&p) || is_epath_record(&p)) {
		rc = do_maps_in_log(&p, get_elf_path_prefix(), &map_info,
				   mapping_r2n, &r2n_info);
		if (rc == FAILURE)
			return FAILURE;
		else if (rc == SKIP)
			return CONTINUE;

		if (is_map_record(&p)) {
			chk_repeat_end(f);
			chk_repeat_start(&chk_repeat_funcs_N);
		}
		return CONTINUE;
	}
	*/
	//fix_x86_64_core2_from(&p.log);
	//chk_fix_from_cache(&r2n_info, &p.log.from, p.log.to, NULL, NULL, NULL);
	//if (!is_addr_range_match(p.log.from, p.log.to, dt->range))
	//	return CONTINUE;
	//print_a_record(__p);

	proc_each_addr(f, p.log.from, 0);
	proc_each_addr(f, p.log.to, 1);
	return CONTINUE;
}

/*----------------------------------------------------------------------------
 *  summary output support
 *----------------------------------------------------------------------------
 */
#define PRINTABLE_NEST_MAX	20
#define PRINTABLE_NEST_STEP	20

struct summary {
	int		type;
	int		nest;
	UINT64	from;
	UINT64	to;
};

bool_t __cmp_S(const void *p1, const void *p2) //FILE *f, 
{
	const struct summary *s1 = p1, *s2 = p2;

	return (s1->type == s2->type &&
		s1->nest == s2->nest &&
		s1->from == s2->from &&
		s1->to == s2->to);
}

void __free_S(const void *p)
{
	free((struct summary*)p);
}

void __print_nest_space_S(int nest)
{
	int i;

	for (i = 0; i < nest; i++)
		printf("  ");
}

void __print_each_addr_S(UINT64 a_addr)
{
	UINT64 addr;
	//size_t offset;
	//const char *func_name;
	struct range_to_name *r2n;

	r2n = addr_to_r2n(&r2n_info, a_addr);
	if (!r2n) {
		printf("0x%08llx", a_addr);
		return;
	}
	addr = a_addr - r2n->offset;
	/*
	if (addr_to_func_name_and_offset(&r2n->bi, addr, &func_name,
					 &offset) == FAILURE) {
		printf("0x%08lx", addr);
		return;
	}
	printf_func_name(func_name, offset);
	*/
	return;
}

void __print_data_S(FILE *f, int nest, const void *p, unsigned long cnt, unsigned short isTo)
{
	struct summary *s = (struct summary*)p;
	int i;
	char c;

	if (s->nest > PRINTABLE_NEST_MAX) {
		int n;
		n = s->nest % PRINTABLE_NEST_STEP;
		if (n == 0)
			n += PRINTABLE_NEST_STEP;
		printf("(N:%4d)", s->nest - n);
		for (i = 0; i < n; i++)
			printf("+-");
	} else {
		for (i = 0; i < s->nest; i++)
			printf("+-");
	}
	switch (s->type) {
	case BTYPE_JMP:  c = 'J'; break;
	case BTYPE_CALL: c = 'C'; break;
	case BTYPE_INT:
	case BTYPE_BREAK:c = 'I'; break;
	default:         c = '?'; break;
	}
	printf("%c ", c);
	__print_each_addr_S(s->to);
	printf(" (");
	printf("0x%08llx", s->from);
	printf(")\n");
}

void __print_start_repeat_S(FILE *f, int nest, unsigned long cnt)
{
	__print_nest_space_S(nest);
	printf("===> repeat %ld times\n", cnt);
}

void __print_end_repeat_S(FILE *f, int nest)
{
	__print_nest_space_S(nest);
	printf("<===\n");
}

struct chk_repeat_funcs chk_repeat_funcs_S =
{
	__cmp_S,
	__free_S,
	__print_data_S,
	__print_start_repeat_S,
	__print_end_repeat_S,
};

int chk_print_elt(enter_leave_t elt)
{
	if (elt == EL_NONE_BRANCH_OR_JUMP || elt == EL_ENTER)
		return TRUE;
	if (summary_type == SUMMARY_DETAIL && elt == EL_LEAVE)
		return TRUE;
	return FALSE;
}

int proc_each_record_for_summary(FILE *f, union bt_record *__p, off_t i_rec, void *data)
{
	union bt_record p = *__p;
	int inst_type, type, nest;
	enter_leave_t elt;
	struct summary *s;

	/*
	if (is_warn_record(&p)) {
		printf("WARN: bts left only: %d\n", p.warn.left);
		return CONTINUE;
	}
	if (is_pid_record(&p) || is_comm_record(&p))
		return CONTINUE;
	if (is_map_record(&p) || is_epath_record(&p)) {
		if (do_maps_in_log(&p, get_elf_path_prefix(), &map_info,
				   mapping_r2n, &r2n_info) == FAILURE)
			return FAILURE;
		if (is_map_record(&p)) {
			chk_repeat_end();
			chk_repeat_start(&chk_repeat_funcs_S);
		}
		return CONTINUE;
	}
	fix_x86_64_core2_from(&p.log);
	*/
	elt = chk_enter_leave(&r2n_info, &p.log, &inst_type, &type, &nest,
			      NULL, NULL, NULL, NULL);
	if (!chk_print_elt(elt))
		return CONTINUE;
	/* normal jump or enter */
	switch (type) {
	case BTYPE_JMP:
	case BTYPE_CALL:
	case BTYPE_INT:
	case BTYPE_BREAK:
		s = calloc(1, sizeof(*s));
		s->type = type;
		s->nest = nest;
		s->from = p.log.from;
		s->to = p.log.to;
		chk_repeat_each(f, (const void*)s, 0);
	}
	return CONTINUE;
}

/* search address option */
bool_t search;
char *search_sym;
unsigned long search_addr;
off_t before;
off_t after;
off_t display_from;
off_t display_to;
/* for debug (hidden options: -W) */
bool_t search_warn;

/*----------------------------------------------------------------------------
 *  program core
 *----------------------------------------------------------------------------
 */
/* Don't check p->from cause Pentium-M's p->from is not correct. */
#define __is_search_record(p)	\
	(is_bt_record(p) && (p)->log.to == search_addr)

static int is_search_record(union bt_record *p, off_t i_rec)
{
	if (search_warn)
		return is_warn_record(p);
	else if (display_from)
		return (i_rec == display_from);
	else
		return __is_search_record(p);
}

int __get_block_range(FILE*f, union bt_record *p, off_t i_rec, void *data)
{
	struct proc_each_range_data *dt = data;

	if (!is_search_record(p, i_rec))
		return CONTINUE;
	dt->match_found = TRUE;
	dt->match_i_rec = i_rec + 1;
	//printf("FOUND  :%lld:%lld\n", i_rec, dt->match_i_rec);
	return BREAK;
}

int get_block_range(FILE *f, union bt_record *p, off_t i_rec, void *data)
{
	struct proc_each_range_data *dt = data;
	off_t i_tmp;

	dt->match_found = FALSE;
	dt->match_i_rec = -1;

	if (!is_search_record(p, i_rec))
		return CONTINUE;
	if (dt->i_start < 0) {
		dt->i_start = i_rec - before;
		if (dt->i_start < 0)
			dt->i_start = 0;
	}
	dt->match_found = TRUE;
	dt->match_i_rec = i_rec + 1;

	if (display_to) {
		dt->i_stop = display_to;
		if (dt->i_stop > dt->i_rec_max || dt->i_stop < 0)
			dt->i_stop = dt->i_rec_max;
		return BREAK;
	}

	/* Check whether 'before' or 'after' range contains the search
	 * address.
	 */
	while (dt->match_found) {
		i_tmp = dt->match_i_rec + (after > before ? after : before);
		if (i_tmp > dt->i_rec_max) {
			i_tmp = dt->i_rec_max;
			break;
		}
		dt->match_found = FALSE;
		for_each_block_record(f, dt->fd, dt->match_i_rec, i_tmp,
				      __get_block_range, dt);
	}
	dt->i_stop = dt->match_i_rec + after;
	if (dt->i_stop > dt->i_rec_max)
		dt->i_stop = dt->i_rec_max;
	return BREAK;
}

int proc_block_records(FILE *f, int fd, off_t from, off_t to)
{
	struct proc_each_rec_data data = { NULL };

	if (to < from) {
		//fprintf(stderr, "from-recnum is bigger than to-recnum\n");
		return FAILURE;
	}
	data.range = get_pid_addr_range(ALL_PID);
	if (output_summary) {
		chk_repeat_start(&chk_repeat_funcs_S);
		if (for_each_block_record(f, fd, from, to,
					  proc_each_record_for_summary,
					  &data) == FAILURE)
			return FAILURE;
		chk_repeat_end(f);
	} else {
		chk_repeat_start(&chk_repeat_funcs_N);
		if (for_each_block_record(f, fd, from, to,
					  proc_each_record_for_normal,
					  &data) == FAILURE)
			return FAILURE;
		chk_repeat_end(f);
	}
	return SUCCESS;
}

/* Return value: BREAK    = Find Next (Continue)
 *               ALL_DONE = Not Found
 *               FAILURE  = Error
 */
int proc_search_range(FILE *f, off_t i_rec, void *data)
{
	struct proc_each_range_data *dt = data;

	dt->i_start = dt->i_stop = -1;
	if (for_each_block_record(f, dt->fd, i_rec, dt->i_rec_max,
				  get_block_range, dt) == FAILURE)
		return FAILURE;
	if (dt->i_start < 0 || dt->i_stop < 0)
		return ALL_DONE;
	printf("======== records from " PF_OFFTD " to " PF_OFFTD " ========\n",
	       dt->i_start, dt->i_stop);
	if (proc_block_records(f, dt->fd, dt->i_start, dt->i_stop) ==FAILURE)
		return FAILURE;
	printf("\n");
	if (display_to)
		return ALL_DONE;
	return BREAK;
}

int chk_maps(union bt_record *rec, off_t i_rec, void *data)
{
	struct r2n_info *r2i = data;

	return chk_maps_in_log(r2i, rec);
}

int proc_logfile(FILE *f, char *logfile)
{
	int fd, rc, tmp;
	bool_t maps_not_found = FALSE;
	off_t size, n_recs;
	char *dir; //, maps_fpath[PATH_MAX];
	struct proc_each_range_data data;

	rc = FAILURE;
	if ((fd = u_open(logfile, &size)) < 0)
		goto EXIT;
	n_recs = size / sizeof(union bt_record);

	dir = logfile; // dirname()
	/*
	if (get_maps_fpath(dir, maps_fpath)) {

		if (parse_maps(&r2n_info, maps_fpath, TRUE) == FAILURE)
			goto EXIT;
	} else {
		maps_not_found = TRUE;
		if (for_each_block_record(fd, 0, n_recs, chk_maps, &r2n_info)
		    == FAILURE)
			goto EXIT;
	}
	*/
	if (parse_modules(&r2n_info, dir, FALSE, TRUE) == FAILURE)
		goto EXIT;
	if (create_path_trees(&r2n_info, TRUE) == FAILURE)
		goto EXIT;
	r2n_info.from_is_next = FALSE; //chk_from_is_next(dir);
	/*
	if (search_sym) {
		struct jmp_to dest;
		if (get_symbol_dest(&r2n_info, search_sym, &dest) == 0) {
			fprintf(stderr, "symbol not found(%s).\n", search_sym);
			goto EXIT;
		}
		search_addr = get_jmp_a_addr(dest);
	}
	*/
	//printf("Start execution paths analysis...\n");
	out_execpath_html_start(f);

	/* Here, we unmap the application and libraries because traced
	 * application doesn't execute 'execv'.
	 * So, the mapping haven't changed as the applications one.
	 * We map these on 'map' record in each record process.
	 */
	//if (maps_not_found)
	//	save_lib_and_app_as_unmapped(&r2n_info);

	if (verbose)
		dump_r2n(&r2n_info);
	if (search || display_from || search_warn) {
		if (search) {
			if (search_sym)
				printf("search: %s(0x%08lx)",
				       search_sym, search_addr);
			else
				printf("search: 0x%08lx", search_addr);
			printf(" -B " PF_OFFTD " -A " PF_OFFTD "\n",
			       before, after);
		}
		data.fd = fd;
		data.i_rec_max = n_recs;
		data.i_start = -1;
		data.i_stop = 0;
		data.match_found = FALSE;
		data.match_i_rec = -1;
		do {
			tmp = proc_search_range(f, data.i_stop, &data);
			if (tmp == FAILURE)
				goto EXIT;
		} while (tmp == BREAK);	// match found
	} else {
		if (proc_block_records(f, fd, 0, n_recs) == FAILURE)
			goto EXIT;
	}
	rc = SUCCESS;
EXIT:
	u_close(fd);
	out_execpath_html_end(f);
	//printf("End of execution paths analysis\n");
	return rc;
}

void err_exit(void)
{
	free_ranges();
	free_r2n(&r2n_info);
	exit(EXIT_FAILURE);
}

static void usage(void)
{
	//fprintf(stderr, "Log Analyzer %s\n", BT_EXECPATH_VER);
	//fprintf(stderr, "    %s\n\n", COPYRIGHT);
	fprintf(stderr, "Insyde H2OLAT (Log Analyzer Tool) Version %s\n", BT_EXECPATH_VER);	
	fprintf(stderr, "Copyright (c) 2012 - 2017, Insyde Software Corp. All Rights Reserved.\n\n");

/*
#if 0
	fprintf(stderr, "bt_execpath [-s] [-a top:end] [-d top:end] [--usr|--ker|--all]\n");
	fprintf(stderr, "            [-S aors|-F recnum] [-B n] [-A n|-T recnum] -f logfile\n");
#else
	fprintf(stderr, "bt_execpath [-sb] [-a top:end] [-d top:end]" \
		        " [--usr|--ker|--all] -f logfile\n");
#endif
*/
	fprintf(stderr, "  -l: log file path including name\n");
	fprintf(stderr, "  -o: output path\n");
	fprintf(stderr, "  -s: source path\n");
	//fprintf(stderr, "  -ss: output more execution path summary\n");
	//fprintf(stderr, "  -b: output binary (do not display source" \
	//	        " information)\n");
	//fprintf(stderr, "  -a: add address range\n");
	//fprintf(stderr, "  -d: delete address range\n");
	//fprintf(stderr, "  --usr: alias of '-a %ld:" PF_LH "'\n",
	//	USER_START, USER_END);
	//fprintf(stderr, "  --ker: alias of '-a " PF_LH ":" PF_LH "'\n",
	//	KERNEL_START, KERNEL_END);
	//fprintf(stderr, "  --all: alias of '-a %ld:" PF_LH "'\n",
	//	USER_START, KERNEL_END);
#if 0
	fprintf(stderr, "  -S: search address or symbol\n");
	fprintf(stderr, "  -B: print n records before the record of -S or -F option\n");
	fprintf(stderr, "  -A: print n records after the record of -S or -F option\n");
	fprintf(stderr, "  -F: specify the start record number\n");
	fprintf(stderr, "  -T: specify the end record number\n");
#endif
	//fprintf(stderr, "  -f: logfile\n");
	//fprintf(stderr, "  --ignore-elf-errors: skip the file btrax cannot"
	//		" recognize as valid ELF\n");
}

//extern int coveragemain(char*, char*, char*, ReportProgressFtn);
extern int coveragemain(char*, char*, char*);

//int execpathmain(char *logfile, char *outpath, char *srcpath, char livemode, ReportProgressFtn iReport, PPDB_FUNCS Pdb)
//int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
int main(int argc, char* argv[])
{
	int opt_index;
	char c; //*p_end, *logfile = "BTSData.bts"
	char *btsfile = NULL; //, *srcpath = NULL; 
	//unsigned long begin, end;
	//long tmp;
	//off_t tmp_index;
	//int summary_level = SUMMARY_DETAIL; //SUMMARY_NORMAL
	char *logfile = NULL, *outpath = NULL, *srcpath = NULL;
	char szBtsFileName[PATH_MAX] = {0}, szOutDir[PATH_MAX] = {0}, szOutFile[PATH_MAX] = {0};
	char szCurWorkingDir[PATH_MAX] = {0};
	FILE *pFile = NULL, *pOutFile = NULL;
	unsigned long rSize, lSize;
	struct cov_out_data dt = {0};
	errno_t err;

	//gPdb = Pdb;
	//output_summary = TRUE;
	
	struct option long_options[] = {
		//{_T("mf"), ARG_REQ, NULL, 0},
		{_T("log"), ARG_REQ, NULL, 0},
		{_T("out"), ARG_REQ, NULL, 0},
		{_T("src"), ARG_REQ, NULL, 0},
		//{ ARG_NULL , ARG_NULL , ARG_NULL , ARG_NULL },
	};

	//alloc_pid_range(ALL_PID);
	//while ((c = getopt_long(argc, argv, _T("hm:l:o:s:"), long_options, &opt_index)) != -1) {
	while ((c = getopt_long(argc, argv, _T("hl:o:s:"), long_options, &opt_index)) != -1) {
		switch (c) {
		case 0:
			switch (opt_index) {
			//case 0: // log
			//	modulefile = optarg;
			//	break;
			case 0: // log
				logfile = optarg; //btsfile
				break;
			case 1: // out
				outpath = optarg;
				break;
			case 2: // src
				srcpath = optarg;
				break;
			}
			break;
		//case 'm':
		//	modulefile = optarg;
		//	break;
		case 'l':
			logfile = optarg;
			break;
		case 'o':
			outpath = optarg;
			break;
		//case 'v':
		//	verbose = TRUE;
		//	break;
		case 's':
			srcpath = optarg;
			break;
		case 'h':
		default:
			usage();
			err_exit();
		}
	}
	
	if (optind < argc ||
	    !logfile || !outpath) {
		usage();
		err_exit();
	}
	
	printf("Start execution paths analysis...\n");
	// Init Pdb library
	_getcwd(szCurWorkingDir, PATH_MAX);
	if (!PdbInit(szCurWorkingDir))
		return (EXIT_FAILURE);

	// Create BTS records file & modules list
	//initvars();
	err = fopen_s(&pFile, logfile, "rb");
	if (err == 0) {
		BYTE *buffer, *pCh;
		MODULE_DESC ModuleInfo; //*pModuleDesc
		IMAGE_INFO *pImageInfo = NULL; //ImageInfo
		bts_log_header *btsheader;
		//FILE *pImageFile;

		fseek(pFile, 0, SEEK_END);
		lSize = ftell(pFile);
		// allocate memory to contain the whole file:
		buffer = (BYTE*) malloc(lSize);

		// copy the file into the buffer:
		//fseek(pFile, 0, SEEK_SET);
		rewind(pFile);
		fread(buffer, 1, lSize, pFile);
		fclose(pFile);
		
		// obtain bts header info:
		lSize = 0;
		btsheader = (bts_log_header*)buffer;
		if (btsheader->signature == 'HSTB' && 
			(btsheader->version == 0x10000 || btsheader->version == 0x10001))
		{
			// Save BTS records file
			sprintf_s(szBtsFileName, PATH_MAX, "%s(bts).tmp", logfile);
			btsfile = szBtsFileName;
			err = fopen_s(&pOutFile, btsfile, "wb");
			if (err == 0)
			{
				fwrite(buffer + btsheader->bts_offset, 1, btsheader->bts_size, pOutFile);
				fclose(pOutFile);
			}
			
			pImageInfo = (IMAGE_INFO*)(buffer + btsheader->imginfo_offset);
			lSize = btsheader->imginfo_size;
		}
		
		//pModuleDesc = (MODULE_DESC*)buffer;
		//if (!livemode)
		{
			rSize = 0;
			
			//pImageFile = fopen("ImageInfo.txt", "wb");
			do {
				// Transfer image info to module info
				memset(&ModuleInfo, 0, sizeof(MODULE_DESC));
				ModuleInfo.BaseAddr = pImageInfo->ImageBase;
				ModuleInfo.EntryPoint = pImageInfo->ImageEntry;
				ModuleInfo.BaseAddrAdjust = pImageInfo->ImageBaseAdjust;
				ModuleInfo.Size = pImageInfo->ImageSize;
				ModuleInfo.CpuMode = pImageInfo->CpuMode;
				memcpy(ModuleInfo.ModuleFullName, pImageInfo->ModuleName, MAX_MODULE_NAME);
				if (srcpath && strlen(srcpath))
				{
					pCh = strchr(pImageInfo->ModuleName, '\\');
					if (pCh)
						pCh = strchr(pCh + 1, '\\');
					if (pCh)
						sprintf_s(ModuleInfo.ModuleFullName, MAX_MODULE_NAME, "%s%s", srcpath, pCh);
				}
				/*
				ImageInfo.ImageBase = pModuleDesc->BaseAddr;
				ImageInfo.ImageEntry = pModuleDesc->EntryPoint;
				ImageInfo.ImageBaseAdjust = pModuleDesc->BaseAddrAdjust;
				ImageInfo.ImageSize = pModuleDesc->Size;
				ImageInfo.CpuMode = pModuleDesc->CpuMode;
				memcpy(ImageInfo.ModuleInfo, pModuleDesc->ModuleFullName, MAX_MODULE_NAME);
				*/
				PdbRegisterModule(&ModuleInfo, NULL);
				//PdbRegisterModule(pModuleDesc++, NULL);
				pImageInfo++;
				//rSize += sizeof(MODULE_DESC);
				rSize += sizeof(IMAGE_INFO);
			
				//fwrite(&ImageInfo, sizeof(IMAGE_INFO), 1, pImageFile);
			} while(rSize < lSize);
		}

		//fclose(pImageFile);
		free(buffer);
	}
	else
	{
		return EXIT_FAILURE;
	}
	//if (iReport) iReport(10);

	r2n_info.num_r2n = 0;
	r2n_info.all_r2n = NULL;

	//sprintf(szOutDir, "%s\\%s", szCurWorkingDir, outpath);
	sprintf_s(szOutDir, PATH_MAX, "%s", outpath);
	if (szOutDir) {
		if (dir_chk_and_create(szOutDir, FALSE) == FAILURE)
			return EXIT_FAILURE;
	}
	dt.outdir = szOutDir;
	init_html2_output(&dt);
	sprintf_s(szOutFile, PATH_MAX, "%s\\%s", szOutDir, "execpaths.html");
	err = fopen_s(&pOutFile, szOutFile, "w");
	if (err == 0) {
		if (proc_logfile(pOutFile, btsfile) == FAILURE)
			err_exit();
		free_ranges();
		free_r2n(&r2n_info);
		fclose(pOutFile);
	}
	printf("End of execution paths analysis\n");
	//if (iReport) iReport(50);
	
	// Coverage Processing
	if (srcpath && strlen(srcpath))
		coveragemain(btsfile, szOutDir, srcpath);
	else
		coveragemain(btsfile, szOutDir, NULL);
	//if (iReport) iReport(100);

	// Reset Pdb library
	//if (!livemode)
	//	PdbReset();
	PdbShutdown();

	// Delete temporary bts log file
	remove(btsfile);

	return EXIT_SUCCESS;
}
