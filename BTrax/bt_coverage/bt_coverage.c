/*****************************************************************************/
/* The development of this program is partly supported by IPA                */
/* (Information-Technology Promotion Agency, Japan).                         */
/*****************************************************************************/

/*****************************************************************************/
/*  bt_coverage.c - coverage information display program                     */
/*  Copyright: Copyright (c) Hitachi, Ltd. 2005-2009                         */
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

#include <limits.h>
#include <stdio.h>
#include "bt_ar_parse.h"
#include "bt_utils.h"
#include "bt_hconv.h"
//#include "Getopt.h"
#include "dispdb.h"

#define BT_COVERAGE_VER	VERSION
#define	COPYRIGHT	"Copyright (c) Hitachi, Ltd. 2005-" RELEASE_YEAR

#ifdef _EXEC
bool_t output_summary = FALSE;
bool_t verbose = FALSE;
#else
extern bool_t output_summary;
extern bool_t verbose;
#endif
bool_t eliminate_out_of_context = FALSE;
bool_t print_enter_leave = FALSE;
bool_t check_contradict = FALSE;
int chk_type;
char *outdir;
char *includes;
char *excludes;

//extern PPDB_FUNCS gPdb;


struct r2i_pack r2p1, r2p2;

#define HTML_OUTPUT	(outdir != NULL)
#define LIMIT_BY_FUNCS	(r2p1.include_funcs != NULL)

#define INC_CNT(p_cnt)						\
	do {							\
		if (*(p_cnt) != INT_MAX)			\
			*(p_cnt) += 1;				\
	} while(0)

#define ADD_CNT(p_cnt, cnt)					\
	do {							\
		*(p_cnt) += (cnt);				\
		if (*(p_cnt) < (cnt))				\
			*(p_cnt) = INT_MAX;			\
	} while(0)

static inline void
add_tracking_cnt_with_addr(struct path *p, struct range_to_name *r2n,
			   UINT64 addr, long cnt)
{
	struct unknown *uk;

	for (uk = (struct unknown *)p->jmp_cnt; uk; uk = uk->next) {
		if (uk->jmp_to.r2n == r2n && uk->jmp_to.addr == addr) {
			ADD_CNT(&uk->cnt, (UINT)cnt);
			return;
		}
	}
	uk = calloc(1, sizeof(*uk));
	uk->jmp_to.r2n = r2n;
	uk->jmp_to.addr = addr;
	uk->cnt = cnt;
	uk->next = (struct unknown*)p->jmp_cnt;
	p->jmp_cnt = (long)uk;
	return;
}

static void
inc_tracking_cnt_with_a_addr(struct path *p, struct range_to_name *r2n,
			     UINT64 a_addr)
{
	add_tracking_cnt_with_addr(p, r2n, a_addr - get_r2n_offset(r2n), 1);
}

/*-----------------------------------------------------------------------------
 *  filter by function name support
 *-----------------------------------------------------------------------------
 */
#define is_addr_range_in(__r2n, fc) \
	((fc) == NULL || ((fc)->dest.r2n == (__r2n)))

static inline int f_cmp_jmp_to(struct jmp_to *d1, struct jmp_to *d2)
{
	void *p1, *p2;

	// Note that we should NOT using r2n->offset to compare the function
	// address. When merge the different logs, it is possible that the
	// different ELFs have same offset.
	// Ex) log1   offset      log2   offset
	//     bt_mod 0xf8c21000  bt_mod 0xf8bc8000
	//     floppy 0xf8bc8000  ---

	p1 = get_r2n_path_array((struct range_to_name*)d1->r2n);
	p2 = get_r2n_path_array((struct range_to_name*)d2->r2n);
	if (p1 < p2)
		return -1;
	if (p1 > p2)
		return 1;
	if (d1->addr < d2->addr)
		return -1;
	if (d1->addr > d2->addr)
		return 1;
	return 0;
}

static int f_cmp_fdest(void *d1, void *d2)
{
	return f_cmp_jmp_to(d1, d2);
}

int create_filter_funcs(struct r2i_pack *r2p, char *funcs,
			bool_t is_include_funcs)
{
	node **list;
	char *p, *tmp, *context;
	struct jmp_to *dests;
	int i, n, rc;

	if (!funcs)
		return SUCCESS;
	list = is_include_funcs ? &r2p->include_funcs : &r2p->exclude_funcs;
	tmp = _strdup(funcs);
	p = strtok_s(tmp, ",", &context);
	rc = FAILURE;
	while (p) {
		n = get_symbol_dest_all(&r2p->r2i, p, &dests);
		for (i = 0; i < n; i++) {
			struct range_to_name *r2n = dests[i].r2n;

			// Function belongs to 'out of range kernel'?
			if (r2n && is_oor_kernel(r2n))
				continue;
			if (!search_tree(&dests[i], *list, f_cmp_fdest)) {
				struct jmp_to *d;

				d = malloc(sizeof(*d));
				d->r2n = r2n;
				d->addr = dests[i].addr;
				*list = insert_tree(d, *list, f_cmp_fdest,
						    NULL);
			}
		}
		if (n)
			free(dests);
		p = strtok_s(NULL, ",", &context);
	}
	if (!*list) {
		printf("WARN: include functions were not found.\n");
		goto EXIT;
	}
	rc = SUCCESS;
EXIT:
	free(tmp);
	return rc;
}

int create_both_filter_funcs(struct r2i_pack *r2p)
{
	if (create_filter_funcs(r2p, includes, TRUE) == FAILURE)
		return FAILURE;
	if (create_filter_funcs(r2p, excludes, FALSE) == FAILURE)
		return FAILURE;
	return SUCCESS;
}

bool_t is_include_fdest(struct r2i_pack *r2p, struct jmp_to *dest)
{
	return (search_tree(dest, r2p->include_funcs, f_cmp_fdest)
		&& !search_tree(dest, r2p->exclude_funcs, f_cmp_fdest));
}

bool_t is_exclude_fdest(struct r2i_pack *r2p, struct jmp_to *dest)
{
	return (search_tree(dest, r2p->exclude_funcs, f_cmp_fdest) != NULL);
}

/*-----------------------------------------------------------------------------
 *  process each record
 *-----------------------------------------------------------------------------
 */
struct enter_leave_dt {
	int		nest;
	UINT64	a_addr;
};

typedef enum {
	CS_OUT_OF_CONTEXT = 0,
	CS_INTO_THE_CONTEXT,
	CS_INTERRUPT_FROM_CONTEXT,
	CS_UK_CALL_FROM_CONTEXT,
	CS_EXCLUDE_CALL_FROM_CONTEXT,
} context_status_t;

#define IN_CONTEXT(context_status)  ((context_status) == CS_INTO_THE_CONTEXT)

struct proc_each_rec_data {
	struct r2i_pack *r2p;
	struct addr_range *range;
	UINT64 last;

	/* checking out of context execution */
	context_status_t context_status;
	struct enter_leave_dt leave;	/* valid when context_status ==
					 * CS_INTO_THE_CONTEXT
					 */
	struct enter_leave_dt enter;	/* valid when context_status ==
					 * CS_XXX_FROM_CONTEXT
					 */
};

void debug_print_symbol_name(struct range_to_name *r2n, UINT64 a_addr)
{
	char *fname;
	size_t offset;
	char *comp_dir = NULL, *src_name;
	DWORD lno; //rc, 
	//LINE_DESC lines;
	//unsigned long line;

	if (!r2n)
		goto PRINT_HEX;
	get_source_info(&r2n->bi, a_addr - r2n->offset, &comp_dir, &src_name,
					 &fname, &lno, &offset);
	//addr_to_func_name_and_offset(&r2n->bi, a_addr - r2n->offset,
	//			     &fname, &offset);
	if (!fname)
		goto PRINT_HEX;
	printf_func_name(fname, offset);
	return;
PRINT_HEX:
	printf("%08llx", a_addr);
}

inline void debug_print_eltype(enter_leave_t elt, int type, int inst_type)
{
	switch (type) {
	case BTYPE_CALL:
		switch (inst_type) {
		case BTYPE_CALL:
			printf("(C)");
			break;
		case BTYPE_JMP:
			printf("(C')");
			break;
		case BTYPE_RET:
			printf("(R)");
			break;
		default:
			goto PRINT_RAW;
		}
		break;
	case BTYPE_INT:
		switch (inst_type) {
		case BTYPE_IRET:
			printf("(Q)");
			break;
		default:
			if (elt == EL_ENTER)
				printf("(I)");
			else
				goto PRINT_RAW;
			break;
		}
		break;
	default:
		goto PRINT_RAW;
	}
	printf(" ");
	return;
PRINT_RAW:
	printf("(%d:%d) ", type, inst_type);
}

static void
debug_print_enter_leave(enter_leave_t elt, context_status_t context_status,
			int type, int inst_type, int nest,
			struct range_to_name *r2n_from,
			struct range_to_name *r2n_to, struct bt_log *p)
{
	int i;

	if (!(elt == EL_ENTER || elt == EL_LEAVE || verbose))
		return;
	if (IN_CONTEXT(context_status))
		printf("ooooo ");
	else
		printf("__(%d) ", context_status);
	printf(r2n_from ? "F" : "_");
	printf(r2n_to ?   "T" : "_");
	if (elt == EL_ENTER || elt == EL_LEAVE) {
		for (i = 0; i < nest; i++)
			printf("+-");
		printf("%s ", (elt == EL_ENTER ? ">" : "<"));
		debug_print_eltype(elt, type, inst_type);
	} else { /* verbose */
		for (i = 0; i < nest; i++)
			printf("+-");
		printf(". (-,%d)", inst_type);
	}
	debug_print_symbol_name(r2n_from, p->from);
	printf(" ");
	debug_print_symbol_name(r2n_to, p->to);
	printf(" (%08llx => %08llx)\n", p->from, p->to);
}

static void
update_context_status(struct bt_log *log, struct range_to_name *r2n,
		      struct range_to_name *r2n_to,
		      struct path *p_from, struct proc_each_rec_data *dt,
		      int inst_type, int type, bool_t is_enter, int nest)
{
	struct jmp_to dest = { r2n_to, log->to - get_r2n_offset(r2n_to) };

	/* When return from unfound address (i.e. in case of iret),
	 * 'p_from' variable is NULL.
	 */
	switch (dt->context_status) {
	case CS_OUT_OF_CONTEXT:
		if (p_from && inst_type == BTYPE_CALL &&
		    is_include_fdest(dt->r2p, &dest)) {
			dt->leave.a_addr = r2n->offset + p_from->next;
			dt->leave.nest = nest;
			dt->context_status = CS_INTO_THE_CONTEXT;
		}
		break;
	case CS_INTO_THE_CONTEXT:
		if (inst_type == BTYPE_RET && dt->leave.a_addr == log->to)
			dt->context_status = CS_OUT_OF_CONTEXT;
		else if (inst_type != BTYPE_INT && type == BTYPE_INT) {
			/* out of context (interrupt) */
			dt->enter.a_addr = log->from;
			dt->enter.nest = nest;
			dt->context_status = CS_INTERRUPT_FROM_CONTEXT;
		} else if (p_from && inst_type == BTYPE_CALL &&
			   p_from->jmp_to.addr == UNKNOWN_BADDR) {
			/* out of context (unknown call) */
			dt->enter.a_addr = r2n->offset + p_from->next;
			dt->enter.nest = nest;
			dt->context_status = CS_UK_CALL_FROM_CONTEXT;
		} else if (p_from && inst_type == BTYPE_CALL &&
			   is_exclude_fdest(dt->r2p, &dest)) {
			/* out of context (excluded function call) */
			dt->enter.a_addr = r2n->offset + p_from->next;
			dt->enter.nest = nest;
			dt->context_status = CS_EXCLUDE_CALL_FROM_CONTEXT;
		}
		break;
	case CS_INTERRUPT_FROM_CONTEXT:
		/* Checking for 'fixup_exception'.
		 * For detail, refer to the src/common/bt_ar_parse.c.
		 */
		if ((inst_type == BTYPE_IRET || inst_type == BTYPE_OTHER)
		    && type == BTYPE_INT && !is_enter && nest == dt->enter.nest)
			dt->context_status = CS_INTO_THE_CONTEXT;
		break;
	case CS_UK_CALL_FROM_CONTEXT:
	case CS_EXCLUDE_CALL_FROM_CONTEXT:
		if (dt->enter.a_addr == log->to)
			dt->context_status = CS_INTO_THE_CONTEXT;
		break;
	}
}

static int f_chk_one_exec_path(struct range_to_name *r2n, UINT64 addr, int isTo)
{
	struct path *p_tmp;
	struct branch_node *exec_node_next, *exec_node_last; //, *exec_node_tmp;
	int i;
	
	if (r2n)
	{
		i = r2n->num_path_array;
		p_tmp = find_path_by_a_addr(r2n, &i, addr);
		if (p_tmp)
		{
			if (p_tmp->addr == addr || !p_tmp->cnt) // Entry point
			{
				p_tmp->cnt++;
				p_tmp->last_to_node = NULL;
			}
			exec_node_last = NULL;
			exec_node_next = p_tmp->exec_node;
			if (isTo)
			{
				while (exec_node_next)
				{
					exec_node_last = exec_node_next;
					if (exec_node_next->addr_to && (exec_node_next->addr_to == addr))
						//(exec_node_next->isTo == isTo))
					{
						exec_node_next->cnt++;
						p_tmp->last_to_node = exec_node_next;
						break;
					}
					exec_node_next = exec_node_last->next;
				}
			}
			else
			{
				if (p_tmp->last_to_node && p_tmp->last_to_node->addr_to)
				{
					//exec_node_next = p_tmp->last_to_node;
					if (exec_node_next->addr_from < addr)
						exec_node_next->addr_from = addr;
					//p_tmp->last_to_node = NULL;
				}
				else
				{
					while (exec_node_next)
					{
						exec_node_last = exec_node_next;
						if (!exec_node_next->addr_to && (exec_node_next->addr_from == addr))
						{
							exec_node_next->cnt++;
							//p_tmp->last_to_node = NULL;
							break;
						}
						exec_node_next = exec_node_last->next;
					}
				}
				p_tmp->last_to_node = NULL;
			}
			
			if (!exec_node_next)
			{
				exec_node_next = calloc(1, sizeof(struct branch_node));
				if (isTo)
					exec_node_next->addr_to = addr;
				else
					exec_node_next->addr_from = addr;
				//exec_node_tmp->isTo = isTo;
				exec_node_next->cnt = 1;
				
				if (exec_node_last)
					exec_node_last->next = exec_node_next;
				else
					p_tmp->exec_node = exec_node_next;
				
				p_tmp->num_exec_node++;
				if (isTo)
					p_tmp->last_to_node = exec_node_next;
			}
		}
		else
		{
			return FAILURE;
		}
	}
	return SUCCESS;
}

static struct map_info map_info;

int proc_each_record(FILE *f, union bt_record *rec, off_t i_rec, void *data)
{
	struct bt_log log;
	struct proc_each_rec_data *dt = data;
	int i, idx_last, idx_from; //, j
	bool_t chk_fallthrough;
	struct r2n_info *r2i = &dt->r2p->r2i;
	struct range_to_name *r2n, *r2n_to, *r2n_from;
	struct path *p, *p_last, *p_from, *p_to = NULL; //, *p_tmp
	enter_leave_t elt;
	int rc, inst_type, type, nest;
	context_status_t prev_st;
	/*
	if (is_warn_record(rec)) {
		printf("WARN: bts left only: %d\n", rec->warn.left);
		dt->context_status = CS_OUT_OF_CONTEXT;
		return CONTINUE;
	}
	if (is_pid_record(rec)) {
		if (print_enter_leave && verbose)
			printf("CX CHG\n");
		return CONTINUE;
	}
	if (is_comm_record(rec))
		return CONTINUE;
	if (is_map_record(rec) || is_epath_record(rec)) {
		if (do_maps_in_log(rec, get_elf_path_prefix(), &map_info,
				   mapping_r2n, r2i) == FAILURE)
			return FAILURE;
		return CONTINUE;
	}
	*/
	log = rec->log;
	//fix_x86_64_core2_from(&log);
	prev_st = dt->context_status;
	if (LIMIT_BY_FUNCS && eliminate_out_of_context) {
		elt = chk_enter_leave(r2i, &log, &inst_type, &type, &nest,
				      &r2n, &r2n_to, &p_from, &idx_from);
		if (print_enter_leave)
			debug_print_enter_leave(elt, dt->context_status,
						type, inst_type, nest,
						r2n, r2n_to, &log);
		if (elt == EL_NONE_FROM_AND_TO_OOR)
			goto EXIT;
		if (elt != EL_NONE_BRANCH_OR_JUMP) {
			/* enter or leave occured */
			update_context_status(&log, r2n, r2n_to, p_from, dt,
					      inst_type, type,
					      (elt == EL_ENTER), nest);
			if (print_enter_leave && verbose &&
			    prev_st != dt->context_status)
				printf("ST CHG(%d) %d->%d (%08llx, %08llx)\n",
				       nest, prev_st, dt->context_status,
				       log.from, log.to);
		}
		rc = SUCCESS;
	} else {
		r2n_from = addr_to_r2n(r2i, log.from);
		f_chk_one_exec_path(r2n_from, log.from, 0);
		r2n_to = addr_to_r2n(r2i, log.to);
		f_chk_one_exec_path(r2n_to, log.to, 1);
		rc = chk_fix_from_cache(r2i, &log.from, log.to,
					&r2n, &p_from, &idx_from);
	}
#ifdef RAW_DEBUG
	printf("RAW INFO: %s:%08lx(%d) =>\t%s:%08lx\n",
	       r2n && rc == SUCCESS ? r2n->basename : "---",
	       r2n && rc == SUCCESS ? log.from - r2n->offset : log.from,
	       (int)(rec->log.from - log.from),
	       r2n_to ? r2n_to->basename : "---",
	       r2n_to ? log.to - r2n_to->offset : log.to);
#endif

	/* check to */
	if (r2n_to && IN_CONTEXT(dt->context_status)) {
		i = r2n_to->num_path_array;
		p_to = find_path_by_a_addr(r2n_to, &i, log.to);
		/* Kprobe's hook points are traced as described below (on P-M).
		 *   c011c7e5 c011c0ca	call c011c0ca <do_exit>
		 *   c011c0cb c0371530	(int 3) -> <int3>
		 *   ...
		 *   dfa7d946 c011c0cb	(reti)
		 * Return from kprobes continues the original code, so 'p_to'
		 * is checked twice. We want to check this 'p_to' only once,
		 * so, if the p_to->addr is not the same as log.to, don't check
		 * it.
		 */
		if (p_to && r2n_to->offset + p_to->addr == log.to) {
			/* If this branch record is the 'iret' from exception,
			 * then jump address is already checked.
			 * So, we don't check this jump address here.
			 * For more details, see the comment in
			 * 'src/common/bt_ar_parse.c:add_range_to_name'
			 * function.
			 */
			struct path *p_to_prev = NULL;
			if (i > 0)
				p_to_prev = r2n_to->path_array[i - 1];
			if (!(rc == SUCCESS && p_from &&
			      p_from->type == BTYPE_IRET &&
			      p_from->base == log.from - r2n->offset &&
			      p_to_prev && p_to_prev->type != BTYPE_INT))
				INC_CNT(&p_to->cnt);
		}
	}
	if (rc == FAILURE || r2n == NULL || p_from == NULL)
		goto EXIT;

	idx_last = r2n->num_path_array;
	p_last = find_path_by_a_addr(r2n, &idx_last, dt->last);
	if (p_last) {
		/* check fallthrough */
		chk_fallthrough = TRUE;
		for (i = idx_last; i < idx_from; i++) {
			p = r2n->path_array[i];
			/* The address becomes an execution address when
			 * interrupt enters the branch ahead when returning
			 * from interrupt.
			 * Therefore, after it returns from the int instruction,
			 * it becomes fallthrough check from passing the int
			 * instruction.
			 */
			if (i == idx_last && p->type == BTYPE_INT)
				continue;
			if (p->type != BTYPE_BRANCH && p->type != BTYPE_OTHER) {
				chk_fallthrough = FALSE;
				/* The error occurs because the address between
				 * from turning off the bts facility to turning
				 * on seems to drop off.
				 * When the error occurs in bt_mod.ko, the
				 * fallthrough check is not done, and the
				 * following processing is done.
				 */
				if (strcmp(r2n->basename, MOD_NAME MOD_EXT)
				    != 0){
					printf("WARN: detect lack of log");
					printf(" (0x%08llx) -> 0x%08llx ->" \
					       " 0x%08llx\n", dt->last,
					       log.from, log.to);
					break;
				}
			}
		}
		if (chk_fallthrough && IN_CONTEXT(prev_st))
			for (i = idx_last; i < idx_from; i++) {
				p = r2n->path_array[i];
				if (i != idx_last)
					INC_CNT(&p->cnt);
				if (p->type == BTYPE_BRANCH)
					INC_CNT(&p->next_cnt);
			}
	}
	if (p_last != p_from && IN_CONTEXT(prev_st))
		INC_CNT(&p_from->cnt);

	/* check branch */
	if (r2n->offset + p_from->base == log.from) {
		if (p_from->jmp_to.addr == UNKNOWN_BADDR &&
		    (IN_CONTEXT(prev_st) || IN_CONTEXT(dt->context_status)))
			inc_tracking_cnt_with_a_addr(p_from, r2n_to, log.to);
		else if (get_jmp_a_addr(p_from->jmp_to) == log.to &&
			 IN_CONTEXT(dt->context_status))
			INC_CNT(&p_from->jmp_cnt);
	}
EXIT:
	dt->last = log.to;
	return CONTINUE;
}

static void printf_funcname(struct bfd_if *bi, UINT64 addr)
{
	int rc; //, lno;
	size_t offset;
	char *comp_dir = NULL, *sep = "", *src_name, *func_name;
	DWORD line;

	rc = get_source_info(bi, addr, &comp_dir, &src_name, &func_name, &line, &offset);
	//rc = addr_to_func_name_and_offset(bi, addr, &func_name, &offset);
	if (rc == SUCCESS) {
		printf_func_name(func_name, offset);
		//rc = get_source_info(bi, addr, &comp_dir, &src_name, &func_name,
		//		     &lno, TRUE);
		if (rc == SUCCESS && src_name && line) {
			if (comp_dir)
				sep = "/";
			else
				comp_dir = "";
			printf(":%s%s%s", comp_dir, sep, src_name);
		}
	} else
		printf("0x%08llx", addr);
}

void printf_srcname_and_lno(struct range_to_name *r2n, UINT64 addr)
{
	//int lno;
	char *comp_dir = NULL, *sep = "", *src_name, *func_name;
	size_t offset;
	DWORD line;

	if (r2n
	    && get_source_info(&r2n->bi, addr, &comp_dir, &src_name, &func_name,
			    &line, &offset) == SUCCESS
	    && src_name && line) {
		if (comp_dir)
			sep = "/";
		else
			comp_dir = "";
		printf("%s%s%s", comp_dir, sep, src_name);
	} else
		printf("0x%08llx", addr);
}

/*-----------------------------------------------------------------------------
 *  display function coverage
 *-----------------------------------------------------------------------------
 */
static int f_cmp_dest2fc(void *data, void *elem)
{
	struct jmp_to *tdest = data;
	struct func_chk *fc = elem;

	return f_cmp_jmp_to(tdest, &fc->dest);
}

static int f_cmp_fc(void *p1, void *p2)
{
	struct func_chk *fc1 = p1;
	struct func_chk *fc2 = p2;

	return f_cmp_jmp_to(&fc1->dest, &fc2->dest);
}

#define CNT_AS_UK(r2p, dest, from_uk) \
	(LIMIT_BY_FUNCS && (from_uk) && !is_include_fdest(r2p, dest))

/*
 * return value: 'SUCCESS' when a function checked or had been checked already
 *               'FAILURE' when error occured
 */
static int __chk_func(struct r2i_pack *r2p, node **fc_list, struct jmp_to *dest)
{
	struct func_chk *fc;
	struct path *p;
	INT i;
	struct range_to_name *r2n;

	fc = search_tree(dest, *fc_list, f_cmp_dest2fc);
	if (fc)
		return SUCCESS;
	if (!dest->r2n)
		return SUCCESS;

	/* When we traced a static-linked application with libc, then '0' is
	 * checked as function address.
	 * It's because weak symbol was not resolved on link process and this
	 * symbol was initialized as '0'.
	 * We don't wan't to check these functions, so we simply ignore it.
	 */
	r2n = dest->r2n;
	if (dest->addr < r2n->begin - r2n->offset ||
	    dest->addr >= r2n->end - r2n->offset)
		return SUCCESS;
	i = r2n->num_path_array;
	p = find_path_by_addr(r2n, &i, dest->addr);
	if (!p)
		return SUCCESS;

	fc = calloc(1, sizeof(*fc));
	fc->dest.r2n = dest->r2n;
	fc->dest.addr = dest->addr;
	fc->cnt = p->cnt;
	SET_FC_VALID(fc);

	*fc_list = insert_tree(fc, *fc_list, f_cmp_fc, free);
	if (!(*fc_list))
		return FAILURE;
	return SUCCESS;
}

struct get_valid_funcs_pack {
	node		*valid_funcs;
	func_compare	f_cmp;
};

static void f_free_unnecessary_fc(void *elem)
{
	struct func_chk *fc = elem;

	if (!IS_CHECKED_FC(fc))
		free(fc);
}

#if 0 // DEBUG
static int f_dp_fclist(void *elem, void *data)
{
	struct func_chk *fc = elem;

	if (!fc->dest.r2n)
		return CONTINUE;
	printf("FC_LIST: %s:%08lx(%s:%lx) (%ld): %x -> %p\n",
	       ((struct range_to_name*)fc->dest.r2n)->basename, fc->dest.addr,
	       get_fname(&fc->dest), fc->offset, fc->cnt,
	       fc->invalid, fc->childs);
	return CONTINUE;
}
static void debug_print_fclist(node *fc_list)
{
	for_each_node(fc_list, f_dp_fclist, NULL);
}

static int f_dp_contradict_funcs(void *elem, void *data)
{
	struct func_chk *fc = elem;
	struct range_to_name *r2n;
	struct path *p;
	long i;

	if (!IS_VALID_FC(fc))
		return CONTINUE;
	r2n = fc->dest.r2n;
	if (!r2n)
		return CONTINUE;
	i = r2n->cnt;
	p = find_path_by_addr(r2n, &i, fc->dest.addr);
	if (!p || (fc->cnt && p->cnt) || (!fc->cnt && !p->cnt))
		return CONTINUE;
	printf("CONTRADICT FUNC: %s:%08lx(%s) (pt:%ld, but :%ld)\n",
	       r2n->basename, fc->dest.addr, get_fname(&fc->dest),
	       p->cnt, fc->cnt);
	return CONTINUE;
}
static void debug_print_contradict_funcs(node *fc_list)
{
	for_each_node(fc_list, f_dp_contradict_funcs, NULL);
}
#endif

static long debug_cnt_uk_exec(struct path *p)
{
	long n = 0;
	struct unknown *uk;

	for (uk = (struct unknown*)p->jmp_cnt; uk; uk = uk->next)
		n += uk->cnt;
	return n;
}

static void print_contradict_path(struct r2n_info *r2i)
{
	struct range_to_name *r2n;
	INT i, j;
	struct path *p;
	bool_t contradict;

	for (i = 0; i < r2i->num_r2n; i++) {
		r2n = r2i->all_r2n[i];
		for_each_path(r2n, j, p) {
			contradict = FALSE;
			switch (p->type) {
			case BTYPE_BRANCH:
				if (p->jmp_to.addr == UNKNOWN_BADDR) {
					if (p->cnt != debug_cnt_uk_exec(p)
								+ p->next_cnt)
						contradict = TRUE;
				} else {
					if (p->cnt != p->jmp_cnt + p->next_cnt)
						contradict = TRUE;
				}
				break;
			case BTYPE_JMP:
			case BTYPE_CALL:
				if (p->jmp_to.addr == UNKNOWN_BADDR) {
					if (p->cnt != debug_cnt_uk_exec(p))
						contradict = TRUE;
				} else {
					if (p->cnt != p->jmp_cnt)
						contradict = TRUE;
				}
				break;
			}
			if (contradict) {
				printf("Contradict path(%s): ",
				       r2n->basename);
				printf_path(r2n, p);
			}
		}
	}
}

static int f_slim_down_flist(void *elem, void *data)
{
	struct func_chk *fc = elem;
	struct get_valid_funcs_pack *pack = data;

	if (!IS_CHECKED_FC(fc))
		return CONTINUE;
	pack->valid_funcs = insert_tree(fc, pack->valid_funcs, pack->f_cmp,
					NULL);
	return CONTINUE;
}

static void slim_down_flist(node **fc_list, func_compare f_cmp)
{
	struct get_valid_funcs_pack pack;

	pack.valid_funcs = NULL;
	pack.f_cmp = f_cmp;
	for_each_node(*fc_list, f_slim_down_flist, &pack);
	free_tree(*fc_list, f_free_unnecessary_fc);
	*fc_list = pack.valid_funcs;
}

static int f_cmp_fc_tree_weight(void *p1, void *p2)
{
	struct func_chk *fc1 = p1;
	struct func_chk *fc2 = p2;

	if (fc1->tree_weight > fc2->tree_weight)
		return -1;
	if (fc1->tree_weight < fc2->tree_weight)
		return 1;
	return f_cmp_jmp_to(&fc1->dest, &fc2->dest);
}

static inline void get_excluded_tcnt_func_list(node **fc_list)
{
	slim_down_flist(fc_list, f_cmp_fc_tree_weight);
}

// 'end' is relative address
int mark_valid_path(struct r2i_pack *r2p, struct jmp_to *root,
		    struct func_chk *fc, UINT64 end, node *fc_list);

int mark_vp(struct r2i_pack *r2p, struct jmp_to *root, struct func_chk *fc,
	    struct jmp_to *fdest, node *fc_list, bool_t from_uk)
{
	UINT64 c_end;
	struct func_chk *c_fc;

	/* If 'fdest' is the other includes function, 'fdest' would be validate
	 * in other includes function's validate process.
	 */
	if (f_cmp_jmp_to(root, fdest) != 0 && is_include_fdest(r2p, fdest))
		return SUCCESS;

	if (!is_exclude_fdest(r2p, fdest) && get_func_info(fdest, &c_end)) {
		c_fc = search_tree(fdest, fc_list, f_cmp_dest2fc);
		if (c_fc) {
			if (from_uk) {
				if (c_fc->cnt)
					SET_FC_UT(c_fc);
				return SUCCESS;
			}
			fc->childs = insert_tree(c_fc, fc->childs, f_cmp_fc,
						 NULL);
			if (!(fc->childs))
				return FAILURE;
			if (IS_CHECKED_FC(c_fc))
				return SUCCESS;
			SET_FC_VALID(c_fc);
			if (mark_valid_path(r2p, root, c_fc, c_end, fc_list)
			    == FAILURE)
				return FAILURE;
		}
	}
	return SUCCESS;
}

int mark_valid_path(struct r2i_pack *r2p, struct jmp_to *root,
		    struct func_chk *fc, UINT64 end, node *fc_list)
{
	struct range_to_name *r2n = fc->dest.r2n;
	struct path *p;
	INT i, top;
	struct unknown *uk;

	top = r2n->num_path_array;
	p = find_path_by_addr(r2n, &top, fc->dest.addr);
	if (!p) {
		//fprintf(stderr,
		//	"function is not in path-tree.(%s:0x%08lx:0x%08lx)\n",
		//	r2n->basename, fc->dest.addr, end);
		return FAILURE;
	}
	fc->end = end;
	for (i = top; i < r2n->num_path_array; i++) {
		p = r2n->path_array[i];
		if (p->addr >= end)
			break;
		p->type &= ~IS_INVALID_PATH;
		switch (p->type) {
		case BTYPE_CALL:
		case BTYPE_JMP:
		case BTYPE_BRANCH:
			/* Function calls by the indirect addressing are not
			 * included in the function call tree.
			 */
			if (p->jmp_to.addr == UNKNOWN_BADDR) {
				if (chk_type != CHK_SINGLE)
					break;
				for (uk = (struct unknown*)p->jmp_cnt; uk;
				     uk = uk->next) {
					if (mark_vp(r2p, root, fc, &uk->jmp_to,
						    fc_list, TRUE) == FAILURE)
						return FAILURE;
				}
			} else {
				if (mark_vp(r2p, root, fc, &p->jmp_to, fc_list,
					    FALSE) == FAILURE)
					return FAILURE;
			}
			break;
		}
	}
	return SUCCESS;
}

struct f_chk_func_data {
	struct r2i_pack *r2p;
	struct range_to_name *r2n;
	node **fc_list;
};

static int f_chk_func(unsigned long addr, const char *name, void *data)
{
	struct f_chk_func_data *dt = data;
	struct jmp_to fdest;

	fdest.r2n = dt->r2n;
	fdest.addr = addr;
	return __chk_func(dt->r2p, dt->fc_list, &fdest);
}

typedef int (*t_func_for_fsym)(unsigned long, const char*, void*);
int for_each_fsymbols(struct bfd_if *bi, t_func_for_fsym f, void *data)
{
	int rc;
	long i;
	//asymbol *sym, **symbols = bi->p_fsyms;
	//bfd_vma val, sect_offset;
	//asection *sect;

	//for (i = 0; i < bi->n_fsyms; i++) {
	for (i = 0; i < bi->NumOfFuncs; i++) {
		//val = bfd_asymbol_value(sym);
		//sect = sym->section;
		//sect_offset = get_sect_offset(bi, sect);
		//rc = f((unsigned long)val, sym->name, data);
		rc = f((unsigned long)bi->FuncList[i].StartAddr, bi->FuncList[i].Name, data);
		if (rc != CONTINUE)
			return rc;
	}
	
	return ALL_DONE;
}

int chk_all_func_syms(node **fc_list, struct r2i_pack *r2p,
		      struct range_to_name *r2n)
{
	struct f_chk_func_data dt;

	dt.r2p = r2p;
	dt.r2n = r2n;
	dt.fc_list = fc_list;
	if (for_each_fsymbols(&r2n->bi, f_chk_func, &dt) == FAILURE)
		return FAILURE;
	return SUCCESS;
}

static void f_fc_free(void *elem)
{
	struct func_chk *fc = elem;

	free(fc);
}

static int f_mark_include_funcs(void *elem, void *data)
{
	struct jmp_to *fdest = elem;
	struct r2i_pack *r2p = data;
	UINT64 end;
	struct func_chk *fc;
	
	if (is_exclude_fdest(r2p, fdest) || !get_func_info(fdest, &end))
		return CONTINUE;
	fc = search_tree(fdest, r2p->fc_list, f_cmp_dest2fc);
	if (!fc)
		return CONTINUE;
	r2p->include_fcs = insert_tree(fc, r2p->include_fcs, f_cmp_fc, NULL);
	if (IS_CHECKED_FC(fc))
		return CONTINUE;
	SET_FC_VALID(fc);
	if (mark_valid_path(r2p, fdest, fc, end, r2p->fc_list) == FAILURE)
		return FAILURE;
	return CONTINUE;
}

static int f_all_fc_mark_invalid(void *elem, void *data)
{
	struct func_chk *cc = elem;

	SET_FC_NOT_CHECKED(cc);
	return CONTINUE;
}

static int f_get_fname(void *elem, void *data)
{
	struct func_chk *fc = elem;

	fc->fname = get_fname_and_offset(&fc->dest, &fc->offset);
	if (fc->fname == NULL)	// external function?
		fc->fname = "";
	return CONTINUE;
}

static int f_cmp_fc_fname(void *p1, void *p2)
{
	struct func_chk *fc1 = p1;
	struct func_chk *fc2 = p2;
	int rc;

	rc = strcmp(fc1->fname, fc2->fname);
	if (rc != 0)
		return rc;
	if (fc1->dest.r2n < fc2->dest.r2n)
		return -1;
	else if (fc1->dest.r2n > fc2->dest.r2n)
		return 1;
	return f_cmp_jmp_to(&fc1->dest, &fc2->dest);
}

static int f_chk_same_fname(void *elem, void *data)
{
	struct func_chk **p_prev_fc = data;
	struct func_chk *fc = elem, *prev_fc = *p_prev_fc;

	if (prev_fc && strcmp(fc->fname, prev_fc->fname) == 0 &&
	    fc->dest.r2n == prev_fc->dest.r2n &&
	    fc->dest.addr - fc->offset != prev_fc->dest.addr - prev_fc->offset){
		SET_FC_SAME_NAME_EXISTS(fc);
		SET_FC_SAME_NAME_EXISTS(prev_fc);
	}
	*p_prev_fc = fc;
	return CONTINUE;
}

static inline void get_fname_sorted_func_list(struct r2i_pack *r2p)
{
	struct func_chk *prev_fc = NULL;

	slim_down_flist(&r2p->fc_list, f_cmp_fc);
	for_each_node(r2p->fc_list, f_get_fname, NULL);
	// sort by fname for all r2n
	slim_down_flist(&r2p->fc_list, f_cmp_fc_fname);
	for_each_node(r2p->fc_list, f_chk_same_fname, &prev_fc);
}

int chk_func_coverage(struct r2i_pack *r2p)
{
	long i, j;
	struct r2n_info *r2i = &r2p->r2i;
	struct range_to_name *r2n;
	struct path *p;
	node **fc_list = &r2p->fc_list;
	long cnt;

	*fc_list = NULL;
	for (i = 0; i < r2i->num_r2n; i++) {
		r2n = r2i->all_r2n[i];
		if (chk_all_func_syms(fc_list, r2p, r2n) == FAILURE)
			goto ERR_EXIT;
		/* There are some functions that don't define in the symbols.
		 * So, we register the called addresses as functions.
		 * Note that the addresses called by indirect addressing
		 * are not registered. (We call these 'UK' functions.)
		 * It because UK functions are different by each execution.
		 * If we register these UK functions, number of the total
		 * functions would be different by each execution.
		 */
		for_each_path(r2n, j, p) {
			int type = p->type & ~IS_INVALID_PATH;
			if (type == BTYPE_CALL &&
			    p->jmp_to.addr != UNKNOWN_BADDR &&
			    __chk_func(r2p, fc_list, &p->jmp_to) == FAILURE)
				goto ERR_EXIT;
		}
	}

	if (LIMIT_BY_FUNCS) {
		/* When limiting the coverage output by function-list, mark all
		 * paths as invalid. Then, mark the valid function paths as
		 * valid.
		 */
		for_each_node(*fc_list, f_all_fc_mark_invalid, NULL);
		for (i = 0; i < r2i->num_r2n; i++) {
			r2n = r2i->all_r2n[i];
			for_each_path(r2n, j, p)
				p->type |= IS_INVALID_PATH;
		}
		for_each_node(r2p->include_funcs, f_mark_include_funcs, r2p);
		slim_down_flist(fc_list, f_cmp_fc);
		for (i = 0; i < r2i->num_r2n; i++) {
			r2n = r2i->all_r2n[i];
			cnt = 0;
			for_each_path(r2n, j, p) {
				if ((p->type & IS_INVALID_PATH)) {
					free_path(p);
					continue;
				}
				r2n->path_array[cnt++] = p;
			}
			r2n->num_path_array = cnt;
		}
	}
	if (chk_type == CHK_DIFF)
		get_fname_sorted_func_list(r2p);
	return SUCCESS;

ERR_EXIT:
	free_tree(*fc_list, f_fc_free);
	return FAILURE;
}

struct fc_cnt {
	int	called;
	int	all;
};

struct call_cnt_pack {
	struct fc_cnt		*fc_cnt;
	struct range_to_name	*r2n;
};

static int f_cnt_each_fc(void *elem, void *data)
{
	struct call_cnt_pack *pack = data;
	struct fc_cnt *cnt = pack->fc_cnt;
	struct range_to_name *r2n = pack->r2n;
	struct func_chk *cc = elem;

	if (is_addr_range_in(r2n, cc)) {
		if (IS_VALID_FC(cc) || IS_SAME_NAME_EXISTS_FC(cc)) {
			cnt->all++;
			if (cc->cnt)
				cnt->called++;
		}
	}
	return CONTINUE;
}

static void get_all_fc_cnt(struct r2i_pack *r2p, struct fc_cnt *cnt)
{
	struct call_cnt_pack pack;

	cnt->all = 0;
	cnt->called = 0;
	pack.fc_cnt = cnt;
	pack.r2n = r2p->r2n;
	for_each_node(r2p->fc_list, f_cnt_each_fc, &pack);
}

#define __print_one_func_cov(fc, cnt) \
do { \
	struct range_to_name *r2n = (fc)->dest.r2n; \
	printf_funcname(&r2n->bi, (fc)->dest.addr); \
	if ((fc)->tree_weight > 0) { \
		printf("\t(%d, F:%d)\n", cnt, (fc)->tree_weight); \
	} else { \
		if (cnt) \
			printf("\t(%d)\n", cnt); \
		else \
			printf("\n"); \
	} \
} while(0)

static int f_dump_each_fc(void *elem, void *data)
{
	struct cov_out_data *dt = data;
	struct func_chk *cc = elem;
	struct range_to_name *r2n = dt->r2p[0]->r2n;

	if (is_addr_range_in(r2n, cc)) {
		if (!(IS_VALID_FC(cc) || IS_SAME_NAME_EXISTS_FC(cc)))
			return CONTINUE;
		if (HTML_OUTPUT)
			out_func_html_each(dt, cc);
		else {
			printf(cc->cnt ? "(OK) " : "(NT) ");
			__print_one_func_cov(cc, cc->cnt);
		}
	}
	return CONTINUE;
}

struct print_ftree_data {
	struct r2i_pack		*r2p;
	node			*fc_list;
	node			**printed;
	int			nest;
	struct cov_out_data	*cov_out_dt;
};

struct excluded_chk_pack {
	struct func_chk	*exclude_from;
	node		*excludes;
	node		*checked;
	node		*fc_list;
};

static int f_cnt_tree_leaf(void *elem, void *data)
{
	struct func_chk *fc = elem;
	struct excluded_chk_pack *pack = data;

	if (search_tree(fc, pack->excludes, f_cmp_fc))
		return CONTINUE;
	pack->excludes = insert_tree(fc, pack->excludes, f_cmp_fc, NULL);
	return for_each_node(fc->childs, f_cnt_tree_leaf, pack);
}

static int f_chk_not_exclude_fc(void *elem, void *data)
{
	struct func_chk *fc = elem;
	struct excluded_chk_pack *pack = data;

	if (fc == pack->exclude_from)
		return CONTINUE;

	if (search_tree(fc, pack->checked, f_cmp_fc))
		return CONTINUE;
	pack->checked = insert_tree(fc, pack->checked, f_cmp_fc, NULL);

	if (search_tree(fc, pack->excludes, f_cmp_fc))
		pack->excludes = delete_tree(fc, pack->excludes, f_cmp_fc,
					     NULL);
	return for_each_node(fc->childs, f_chk_not_exclude_fc, pack);
}

static void get_tree_weight(struct print_ftree_data *dt, node *fc_list,
			    struct func_chk *fc)
{
	struct excluded_chk_pack pack;

	if (fc->tree_weight > 0)
		return;
	pack.exclude_from = fc;
	pack.excludes = NULL;
	pack.checked = NULL;
	pack.fc_list = fc_list;

	/* 1. Check all exclude function's f-tree. */
	f_cnt_tree_leaf(fc, &pack);

	/* 2. Check the include functions' f-tree but exclude function's,
	 *    and if these valid functions are found in exclude functions,
	 *    then delete it from the exclude function list.
	 */
	for_each_node(dt->r2p->include_fcs, f_chk_not_exclude_fc, &pack);

	/* 3. Count exclude functions, and subtract from total function count.
	 */
	fc->tree_weight = get_node_cnt(pack.excludes);
	free_tree(pack.excludes, NULL);
	free_tree(pack.checked, NULL);
	return;
}

static void __f_print_func_tree(struct func_chk *fc,
				struct print_ftree_data *p_ftree_dt,
				int type, bool_t has_child)
{
	int i, nest = p_ftree_dt->nest;
	struct cov_out_data *dt = p_ftree_dt->cov_out_dt;
	node *fc_list = p_ftree_dt->fc_list;

	dt->r2p[0]->r2n = fc->dest.r2n;
	get_tree_weight(p_ftree_dt, fc_list, fc);
	if (HTML_OUTPUT)
		out_func_tree_html_each_enter(dt, 0, fc, nest, type, has_child);
	else {
		switch (type) {
		case BCOV_TYPE_OK:
			printf("(OK) ");
			break;
		case BCOV_TYPE_NT:
			printf("(NT) ");
			break;
		default:
			printf("(--) ");
			break;
		}
		for (i = 0; i < nest; i++)
			printf("+-");
		__print_one_func_cov(fc, fc->cnt);
	}
}

static int f_print_invalid_func(void *elem, void *data)
{
	struct print_ftree_data *dt = data;
	struct func_chk *fc = elem;

	dt->cov_out_dt->r2p[0]->r2n = fc->dest.r2n;
	if (IS_UT_FC(fc)) {
		if (HTML_OUTPUT)
			out_func_tree_html_each_invalid(dt->cov_out_dt, 0, fc);
		else {
			printf("(UT) ");
			__print_one_func_cov(fc, fc->cnt);
		}
	}
	return CONTINUE;
}

static int f_print_func_tree(void *elem, void *data)
{
	struct print_ftree_data dt = *(struct print_ftree_data*)data;
	struct func_chk *fc = elem;
	int printed, type;
	bool_t has_child;

	printed = search_tree(&fc->dest, *dt.printed, f_cmp_dest2fc) != NULL;
	if (printed) {
		if (dt.nest) {
			has_child = FALSE;
			__f_print_func_tree(fc, &dt, BCOV_TYPE_HT, has_child);
			goto EXIT;
		}
		return CONTINUE;
	}
	*dt.printed = insert_tree(fc, *dt.printed, f_cmp_fc, NULL);
	if (!(*dt.printed))
		return FAILURE;
	type = fc->cnt ? BCOV_TYPE_OK : BCOV_TYPE_NT;
	has_child = fc->childs != NULL;
	__f_print_func_tree(fc, &dt, type, has_child);
	dt.nest++;
	if (for_each_node(fc->childs, f_print_func_tree, &dt) == FAILURE)
		return FAILURE;
	dt.nest--;
EXIT:
	if (HTML_OUTPUT)
		out_func_tree_html_each_exit(dt.cov_out_dt, dt.nest,has_child);
	return CONTINUE;
}

void print_func_tree(struct r2i_pack *r2p, struct cov_out_data *cov_out_dt)
{
	int i;
	struct r2n_info *r2i = &r2p->r2i;
	struct range_to_name *r2n;
	struct fc_cnt cnt = { 0, 0 };
	struct call_cnt_pack pack = { &cnt, NULL };
	node *fc_list = r2p->fc_list;
	node *printed = NULL;
	struct print_ftree_data dt;
	char *s_inc, *s_exc;

	s_inc = includes ? includes : "(--)";
	s_exc = excludes ? excludes : "(--)";
	if (HTML_OUTPUT)
		out_func_tree_html_start(cov_out_dt, s_inc, s_exc);
	for (i = 0; i < r2i->num_r2n; i++) {
		r2n = r2i->all_r2n[i];
		pack.r2n = r2n;
		for_each_node(fc_list, f_cnt_each_fc, &pack);
	}
	dt.r2p = r2p;
	dt.fc_list = fc_list;
	dt.printed = &printed;
	dt.nest = 0;
	dt.cov_out_dt = cov_out_dt;
	if (!HTML_OUTPUT) {
		printf("====== includes: %s ======\n", s_inc);
		printf("====== excludes: %s ======\n", s_exc);
		printf("====== function tree (%d/%d=%.2f%%) ======\n",
		       cnt.called, cnt.all, get_percent(cnt.called, cnt.all));
	}
	for_each_node(r2p->include_fcs, f_print_func_tree, &dt);
	for_each_node(fc_list, f_print_invalid_func, &dt);
	if (HTML_OUTPUT)
		out_func_tree_html_end(cov_out_dt);
	free_tree(printed, NULL);
}

struct func_diff_chk {
	const char	*fname;
	struct func_chk	*fc1;
	struct func_chk	*fc2;
};

static int f_cmp_fdc(const void *p1, const void *p2)
{
	int rc;
	struct func_diff_chk *fdc1 = (struct func_diff_chk*)p1;
	struct func_diff_chk *fdc2 = (struct func_diff_chk*)p2;
	unsigned long offset1, offset2;

	rc = strcmp(fdc1->fname, fdc2->fname);
	if (rc)
		return rc;
	offset1 = fdc1->fc1 ? fdc1->fc1->offset : fdc1->fc2->offset;
	offset2 = fdc2->fc1 ? fdc2->fc1->offset : fdc2->fc2->offset;
	if (offset1 < offset2)
		return -1;
	else if (offset1 > offset2)
		return 1;
	return 0;
}

struct pack_fdc {
	int			type;
	int			side;	/* r2p1 or r2p2 */
	struct range_to_name	*r2n;
	int			i;
	int			n;
	struct func_diff_chk	*fdc;
};

static int f_cp_fc2fdc(void *elem, void *data)
{
	struct func_chk *fc = elem;
	struct pack_fdc *pack = data;
	struct func_diff_chk *fdc, tmp = {NULL}; //{ .fc2 = NULL};

	if (IS_SAME_NAME_EXISTS_FC(fc))
		return CONTINUE;
	if (!is_addr_range_in(pack->r2n, fc))
		return CONTINUE;
	if (pack->side == 0) {	/* Are we processing 'r2p1'? */
		/* processing 'r2p1' */
		fdc = &pack->fdc[pack->i++];
		fdc->fname = fc->fname;
		fdc->fc1 = fc;
		return CONTINUE;
	}
	/* processing 'r2p2' */
	if (pack->n == 0) {
		pack->n = pack->i;
		if (pack->type == CHK_SAME)
			pack->i = 0;
	}
	if (pack->type == CHK_SAME) {
		fdc = &pack->fdc[pack->i++];
		fdc->fc2 = fc;
	} else {
		tmp.fc1 = fc;
		tmp.fname = fc->fname;
		fdc = bsearch(&tmp, pack->fdc, pack->n, sizeof(*fdc),f_cmp_fdc);
		if (fdc) {
			fdc->fc2 = fc;
		} else {
			fdc = &pack->fdc[pack->i++];
			fdc->fname = fc->fname;
			fdc->fc2 = fc;
		}
	}
	return CONTINUE;
}

static int f_cp_double_name_fc2fdc(void *elem, void *data)
{
	struct func_chk *fc = elem;
	struct pack_fdc *pack = data;
	struct func_diff_chk *fdc;

	if (!IS_SAME_NAME_EXISTS_FC(fc))
		return CONTINUE;
	if (!is_addr_range_in(pack->r2n, fc))
		return CONTINUE;
	fdc = &pack->fdc[pack->i++];
	fdc->fname = fc->fname;
	if (pack->side == 0)
		fdc->fc1 = fc;
	else
		fdc->fc2 = fc;
	return CONTINUE;
}

void dump_func_coverage(struct cov_out_data *dt,
			struct fc_cnt *cnt, struct fc_cnt *cnt2)
{
	long i, n, same = 0, diff = 0;
	struct pack_fdc pack = { chk_type, 0, NULL, 0, 0, NULL };
	struct func_diff_chk *fdc;
	struct range_to_name *r2n = dt->r2p[0]->r2n, *r2n2 = NULL;

	if (chk_type != CHK_SINGLE) {
		r2n2 = dt->r2p[1]->r2n;
		n = chk_type == CHK_DIFF ? cnt->all + cnt2->all : cnt->all;
		pack.fdc = calloc(n, sizeof(*pack.fdc));
		for (i = 0; i < 2; i++) {
			pack.side = i;
			pack.r2n = dt->r2p[i]->r2n;
			for_each_node(dt->r2p[i]->fc_list, f_cp_fc2fdc, &pack);
		}
		if (chk_type == CHK_DIFF) {
			qsort(pack.fdc, pack.i, sizeof(*pack.fdc), f_cmp_fdc);
			for (i = 0; i < 2; i++) {
				pack.side = i;
				pack.r2n = dt->r2p[i]->r2n;
				for_each_node(dt->r2p[i]->fc_list,
					      f_cp_double_name_fc2fdc, &pack);
			}
		} else {
			same = diff = 0;
			for (i = 0; i < pack.i; i++) {
				fdc = &pack.fdc[i];
				if (!is_addr_range_in(r2n, fdc->fc1) ||
				    !is_addr_range_in(r2n2, fdc->fc2))
					continue;
				out_func_html_each2(dt, fdc->fc1, fdc->fc2,
						    &same, &diff);
			}
		}
	}
	if (HTML_OUTPUT) {
		out_summary_html_func(dt, 0, cnt->called, cnt->all);
		if (chk_type != CHK_SINGLE)
			out_summary_html_func(dt, 1, cnt2->called, cnt2->all);
		out_func_html_start(dt, same, diff);
	} else
		printf("------ function coverage (%d/%d=%.2f%%) ------\n",
		       cnt->called, cnt->all,
		       get_percent(cnt->called, cnt->all));
	if (output_summary)
		goto EXIT;
	if (chk_type == CHK_SINGLE) {
		if (LIMIT_BY_FUNCS)
			get_excluded_tcnt_func_list(&r2p1.fc_list);
		for_each_node(dt->r2p[0]->fc_list, f_dump_each_fc, dt);
		goto EXIT;
	}
	for (i = 0; i < pack.i; i++) {
		fdc = &pack.fdc[i];
		if (!is_addr_range_in(r2n, fdc->fc1) ||
		    !is_addr_range_in(r2n2, fdc->fc2))
			continue;
		out_func_html_each2(dt, fdc->fc1, fdc->fc2, NULL, NULL);
	}
	free(pack.fdc);
EXIT:
	if (HTML_OUTPUT)
		out_func_html_end(dt);
}

/*-----------------------------------------------------------------------------
 *  display branch coverage
 *-----------------------------------------------------------------------------
 */
struct unknown_diff {
	struct jmp_to	dest;
	unsigned int	cnt1;
	unsigned int	cnt2;
};

/* Note that when comparing two same ELF's logs, each r2n are th different
 * instances.
 */
static int f_cmp_ud_dest(struct jmp_to *dest1, struct jmp_to *dest2)
{
	int rc;

	if (dest1->r2n && !dest2->r2n)
		return -1;
	if (!dest1->r2n && dest2->r2n)
		return 1;
	rc = strcmp(((struct range_to_name*)dest1->r2n)->dirname,
		    ((struct range_to_name*)dest2->r2n)->dirname);
	if (rc != 0)
		return rc;
	rc = strcmp(((struct range_to_name*)dest1->r2n)->basename,
		    ((struct range_to_name*)dest2->r2n)->basename);
	if (rc != 0)
		return rc;
	if (dest1->addr < dest2->addr)
		return -1;
	if (dest1->addr > dest2->addr)
		return 1;
	return 0;
}

static int f_cmp_ud(const void *p1, const void *p2)
{
	struct unknown_diff *ud1 = (struct unknown_diff*)p1;
	struct unknown_diff *ud2 = (struct unknown_diff*)p2;

	return f_cmp_ud_dest(&ud1->dest, &ud2->dest);
}

static struct unknown_diff* get_unknown_diff(struct path *p1, long n1,
					     struct path *p2, long n2)
{
	struct unknown_diff *p_ud;
	struct unknown *uk;
	long i = 0, j;
	bool_t found;

	p_ud = calloc(n1 + n2 + 1, sizeof(*p_ud));	// +1 for sentinel
	for (uk = (struct unknown*)p1->jmp_cnt; uk; uk = uk->next, i++) {
		p_ud[i].dest = uk->jmp_to;
		p_ud[i].cnt1 = uk->cnt;
	}
	for (uk = (struct unknown*)p2->jmp_cnt; uk; uk = uk->next) {
		found = FALSE;
		for (j = 0; j < n1; j++) {
			if (f_cmp_ud_dest(&p_ud[j].dest, &uk->jmp_to) == 0) {
				p_ud[j].cnt2 = uk->cnt;
				found = TRUE;
				break;
			}
		}
		if (found)
			continue;
		p_ud[i].dest = uk->jmp_to;
		p_ud[i].cnt2 = uk->cnt;
		i++;
	}
	qsort(p_ud, i, sizeof(*p_ud), f_cmp_ud);
	return p_ud;
}

long get_unknown_bcnt(struct path *p)
{
	long i = 0;
	struct unknown *uk;

	if (IS_SWITCH_JMP(p) ||
	    (p->type == BTYPE_BRANCH && p->jmp_to.addr == UNKNOWN_BADDR)) {
		for (uk = (struct unknown*)p->jmp_cnt; uk; uk = uk->next, i++);
		return i;
	}
	return 0;
}

void __dump_one_branch_coverage(struct cov_out_data *dt, int side,
				int bcov_type, struct branch_info *bi)
{
	struct range_to_name *r2n = dt->r2p[side]->r2n;

	if (HTML_OUTPUT)
		out_branch_html_each(dt, side, bi);
	else {
		switch (bcov_type) {
		case BCOV_TYPE_OK: printf("(OK) "); break;
		case BCOV_TYPE_HT: printf("(HT) "); break;
		case BCOV_TYPE_NT: printf("(NT) "); break;
		case BCOV_TYPE_UT: printf("(UT) "); break;
		case BCOV_TYPE_UN: printf("(UN) "); break;
		}
		printf_srcname_and_lno(r2n, bi->base);
		printf(" [%d/", bi->b_cnt);
		if (bi->fall == UNKNOWN_BADDR)
			printf("x] ");
		else
			printf("%d] ", bi->f_cnt);
		if (get_jmp_a_addr(bi->branch) == UNKNOWN_BADDR)
			printf("----------:");
		else {
			printf_srcname_and_lno(bi->branch.r2n, bi->branch.addr);
			printf(":");
		}
		if (bi->fall == UNKNOWN_BADDR)
			printf("xxxxxxxxxx\n");
		else {
			printf_srcname_and_lno(r2n, bi->fall);
			printf("\n");
		}
	}
}

inline void do_one_branch_coverage(struct cov_out_data *dt, int side,
				   struct path *p, func_do_one_bcov func)
{
	struct unknown *uk;
	int bcov_type;
	struct branch_info bi;

	bi.base = p->base;
	bi.uk_id = 0;
	if (IS_SWITCH_JMP(p) ||		/* switch case */
	    p->jmp_to.addr == UNKNOWN_BADDR) {	/* indirect addressing branch */
		bi.fall = UNKNOWN_BADDR;
		bi.f_cnt = 0;
		if (get_unknown_bcnt(p)) {
			for (uk = (struct unknown*)p->jmp_cnt; uk;
			     uk = uk->next) {
				bcov_type = BCOV_TYPE_UT;
				bi.branch = uk->jmp_to;
				bi.b_cnt = uk->cnt;
				func(dt, side, bcov_type, &bi);
				bi.uk_id++;
			}
		} else {
			bcov_type = BCOV_TYPE_UN;
			bi.branch.r2n = NULL;
			bi.branch.addr = UNKNOWN_BADDR;
			bi.b_cnt = 0;
			func(dt, side, bcov_type, &bi);
		}
	} else {
		if (p->jmp_cnt != 0 && p->next_cnt != 0) {
			bcov_type = BCOV_TYPE_OK;
		} else if (p->jmp_cnt == 0 && p->next_cnt == 0) {
			bcov_type = BCOV_TYPE_NT;
		} else {
			bcov_type = BCOV_TYPE_HT;
		}
		bi.branch = p->jmp_to;
		bi.b_cnt = p->jmp_cnt;
		bi.fall = p->next;
		bi.f_cnt = p->next_cnt;
		func(dt, side, bcov_type, &bi);
	}
}

static inline void dump_one_branch_coverage2(struct cov_out_data *dt,
					     struct path *p, struct path *p2,
					     long *same, long *diff)
{
	struct unknown_diff *p_ud, *ud;
	long i, n_uk, n_uk2;
	struct branch_info bi, bi2;

	bi.base = bi2.base = p->base;
	if (IS_SWITCH_JMP(p) ||		/* switch case */
	    p->jmp_to.addr == UNKNOWN_BADDR) {	/* indirect addressing branch */
		bi.fall = bi2.fall = UNKNOWN_BADDR;
		bi.f_cnt = bi2.f_cnt = 0;
		n_uk = get_unknown_bcnt(p);
		n_uk2 = get_unknown_bcnt(p2);
		if (n_uk == n_uk2 && n_uk == 0) {
			bi.branch.r2n = bi2.branch.r2n = NULL;
			bi.branch.addr = bi2.branch.addr = UNKNOWN_BADDR;
			bi.b_cnt = bi2.b_cnt = 0;
			out_branch_html_each2(dt, &bi, &bi2, same, diff);
		} else {
			p_ud = get_unknown_diff(p, n_uk, p2, n_uk2);
			for (i = 0; i < n_uk + n_uk2; i++) {
				ud = &p_ud[i];
				if (get_jmp_a_addr(ud->dest) == 0) // sentinel?
					break;
				bi.branch = bi2.branch = ud->dest;
				bi.b_cnt = ud->cnt1;
				bi2.b_cnt = ud->cnt2;
				out_branch_html_each2(dt, &bi, &bi2, same,diff);
			}
			free(p_ud);
		}
	} else {
		bi.branch = bi2.branch = p->jmp_to;
		bi.b_cnt = p->jmp_cnt;
		bi2.b_cnt = p2->jmp_cnt;
		bi.fall = bi2.fall = p->next;
		bi.f_cnt = p->next_cnt;
		bi2.f_cnt = p2->next_cnt;
		out_branch_html_each2(dt, &bi, &bi2, same, diff);
	}
}

void dump_one_branch_coverage(struct cov_out_data *dt, int side,
			      struct path *p)
{
	do_one_branch_coverage(dt, side, p, __dump_one_branch_coverage);
}

struct branch_cnts {
	unsigned int ok;
	unsigned int nt;
	unsigned int ht;
	unsigned int uk_through;
	unsigned int uk_not_through;
};

void dump_branch_coverage(struct cov_out_data *dt)
{
	long i, uk_bcnt, same, diff;
	struct range_to_name *r2n, *r2n2;
	struct branch_cnts bcs = {0,0,0,0,0};
	struct path *p, *p2;
	unsigned int n_all_branch, n_all_uk;
	int side, side_max;

	side_max = chk_type == CHK_SINGLE ? 1 : 2;
	for (side = 0; side < side_max; side++) {
		r2n = dt->r2p[side]->r2n;
		bcs.ok = bcs.nt = bcs.ht = 0;
		bcs.uk_through = bcs.uk_not_through = 0;
		for_each_path(r2n, i, p) {
			if (p->type != BTYPE_BRANCH && !IS_SWITCH_JMP(p))
				continue;
			if (p->jmp_to.addr == UNKNOWN_BADDR) {
				uk_bcnt = get_unknown_bcnt(p);
				if (!uk_bcnt)
					bcs.uk_not_through++;
				else
					bcs.uk_through++;
			} else if (p->jmp_cnt != 0 && p->next_cnt != 0)
				bcs.ok++;
			else if (p->jmp_cnt == 0 && p->next_cnt == 0)
				bcs.nt++;
			else
				bcs.ht++;
		}
		n_all_branch = (bcs.ok + bcs.ht + bcs.nt) * 2;
		n_all_uk = bcs.uk_through + bcs.uk_not_through;
		if (HTML_OUTPUT)
			out_summary_html_branch(dt, side, bcs.ok,
						bcs.uk_through, bcs.ht, bcs.nt,
						n_all_branch, n_all_uk);
		else {
			printf("------ branch coverage (OK:%d,HT:%d,NT:%d/%d=" \
			       "%.2f%%", bcs.ok, bcs.ht, bcs.nt, n_all_branch,
			       get_percent(bcs.ok * 2 + bcs.ht, n_all_branch));
			printf(" UK:%d/%d=%.2f%%) ------\n",
			       bcs.uk_through, n_all_uk,
			       get_percent(bcs.uk_through, n_all_uk));
		}
		if (output_summary || chk_type == CHK_SAME)
			continue;
		if (HTML_OUTPUT)
			out_branch_html_start(dt, 0, 0);
		for_each_path(r2n, i, p) {
			if (p->type != BTYPE_BRANCH && !IS_SWITCH_JMP(p))
				continue;
			dump_one_branch_coverage(dt, side, p);
		}
		if (HTML_OUTPUT)
			out_branch_html_end(dt);
	}
	if (chk_type != CHK_SAME)
		return;
	r2n = dt->r2p[0]->r2n;
	r2n2 = dt->r2p[1]->r2n;
	same = diff = 0;
	for_each_path(r2n, i, p) {
		if (p->type != BTYPE_BRANCH && !IS_SWITCH_JMP(p))
			continue;
		p2 = r2n2->path_array[i];
		dump_one_branch_coverage2(dt, p, p2, &same, &diff);
	}
	out_branch_html_start(dt, same, diff);
	for_each_path(r2n, i, p) {
		if (p->type != BTYPE_BRANCH && !IS_SWITCH_JMP(p))
			continue;
		p2 = r2n2->path_array[i];
		dump_one_branch_coverage2(dt, p, p2, NULL, NULL);
	}
	out_branch_html_end(dt);
}

struct state_cnts {
	unsigned int ok;
	unsigned int nt;
};

/*-----------------------------------------------------------------------------
 *  display state coverage
 *-----------------------------------------------------------------------------
 */
void dump_state_coverage(struct cov_out_data *dt)
{
	long i, diff, same;
	struct range_to_name *r2n, *r2n2;
	struct state_cnts scs;
	struct path *p, *p2;
	int is_exec, is_exec2, side, side_max;

	side_max = chk_type == CHK_SINGLE ? 1 : 2;
	for (side = 0; side < side_max; side++) {
		r2n = dt->r2p[side]->r2n;
		scs.ok = scs.nt = 0;
		for_each_path(r2n, i, p) {
			if (p->cnt > 0)
				scs.ok += 1;
			else
				scs.nt += 1;
		}
		if (HTML_OUTPUT)
			out_summary_html_state(dt, side, scs.ok,
					       scs.ok + scs.nt);
		else
			printf("------ state coverage (%d/%d=%.2f%%) ------\n",
			       scs.ok, scs.ok + scs.nt,
			       get_percent(scs.ok, scs.ok + scs.nt));

		if (output_summary || chk_type == CHK_SAME)
			continue;
		if (HTML_OUTPUT)
			out_state_html_start(dt, 0, 0);
		for_each_path(r2n, i, p) {
			is_exec = p->cnt > 0;
			if (HTML_OUTPUT)
				out_state_html_each(dt, side, is_exec, p);
			else {
				if (is_exec)
					printf("(OK) ");
				else
					printf("(NT) ");
				printf_srcname_and_lno(r2n, p->addr);
				printf("\n");
			}
		}
		if (HTML_OUTPUT)
			out_state_html_end(dt);
	}
	if (chk_type != CHK_SAME)
		return;
	r2n = dt->r2p[0]->r2n;
	r2n2 = dt->r2p[1]->r2n;
	same = diff = 0;
	for_each_path(r2n, i, p) {
		p2 = r2n2->path_array[i];
		is_exec = p->cnt > 0;
		is_exec2 = p2->cnt > 0;
		if (is_exec == is_exec2)
			same++;
		else
			diff++;
	}
	out_state_html_start(dt, same, diff);
	for_each_path(r2n, i, p) {
		p2 = r2n2->path_array[i];
		is_exec = p->cnt > 0;
		is_exec2 = p2->cnt > 0;
		out_state_html_each2(dt, is_exec, is_exec2, p);
	}
	out_state_html_end(dt);
}

/*-----------------------------------------------------------------------------
 *  display coverage
 *-----------------------------------------------------------------------------
 */
static int f_chk_ifuncs_are_executed(void *elem, void *data)
{
	struct jmp_to *fdest = elem;
	struct r2i_pack *r2p = data;
	struct range_to_name *r2n = fdest->r2n;
	UINT64 end;
	struct func_chk *fc;

	if (is_exclude_fdest(r2p, fdest) || !get_func_info(fdest, &end))
		return CONTINUE;
	fc = search_tree(fdest, r2p->include_fcs, f_cmp_dest2fc);
	if (!fc || !fc->cnt) {
		printf("WARN: ");
		printf_funcname(&r2n->bi, fdest->addr);
		printf(" was not executed.\n");
	}
	return CONTINUE;
}

static struct range_to_name*
find_comparable_pair(struct r2n_info *r2i, struct range_to_name *pair_r2n,
		     int type)
{
	int i;
	bool_t found = FALSE;
	struct range_to_name *r2n;

	switch (type) {
	case CHK_SINGLE:
		break;
	case CHK_SAME:
		// find same path
		for (i = 0; i < r2i->num_r2n; i++) {
			r2n = r2i->all_r2n[i];
			if (strcmp(r2n->dirname, pair_r2n->dirname) == 0 &&
			    strcmp(r2n->basename, pair_r2n->basename) == 0) {
				found = TRUE;
				break;
			}
		}
		break;
	case CHK_DIFF:
		// find same basename
		for (i = 0; i < r2i->num_r2n; i++) {
			r2n = r2i->all_r2n[i];
			if (strcmp(r2n->basename, pair_r2n->basename) == 0) {
				found = TRUE;
				break;
			}
		}
		break;
	}
	if (!found)
		return NULL;
	if (type == CHK_SAME
	    && r2n->num_path_array != pair_r2n->num_path_array) {
		return NULL;
	}
	return r2n;
}

static int get_chk_type(struct r2n_info *r2i, struct r2n_info *r2i2, int cmp)
{
	int i;
	struct range_to_name *r2n, *r2n_pair;

	if (!cmp)
		return CHK_SINGLE;
	for (i = 0; i < r2i->num_r2n; i++) {
		r2n = r2i->all_r2n[i];
		r2n_pair = find_comparable_pair(r2i2, r2n, CHK_DIFF);
		if (!r2n_pair)
			continue;
		// If the basename match and dirname not match, then
		// we check this pattern as the 'CHK_DIFF'.
		if (strcmp(r2n->dirname, r2n_pair->dirname) != 0)
			return CHK_DIFF;
	}
	return CHK_SAME;
}

int dump_coverage(void)
{
	int i, num_compared; //, j, k
	struct r2n_info *r2i = &r2p1.r2i;
	struct r2n_info *r2i2 = &r2p2.r2i;
	struct range_to_name *r2n, *r2n2;
	struct cov_out_data dt;
	struct fc_cnt cnt, cnt2;
	//char drive[_MAX_DRIVE], fname[_MAX_FNAME], dir[_MAX_DIR], ext[_MAX_EXT];

	if (!r2i->all_r2n)
		return SUCCESS;

	memset(&dt, 0, sizeof(dt));
	dt.outdir = outdir;
	dt.limit_by_funcs = LIMIT_BY_FUNCS;
	dt.chk_type = chk_type;
	dt.r2p[0] = &r2p1;
	if (chk_type != CHK_SINGLE)
		dt.r2p[1] = &r2p2;
	if (HTML_OUTPUT) {
		if (init_html_output(&dt) == FAILURE)
			return FAILURE;
	}
	if (chk_func_coverage(&r2p1) == FAILURE)
		return FAILURE;
	if (chk_type != CHK_SINGLE) {
		if (chk_func_coverage(&r2p2) == FAILURE)
			return FAILURE;
	}
#if 0 // DEBUG
	debug_print_contradict_funcs(r2p1.fc_list);
#endif
	if (check_contradict)
		print_contradict_path(&r2p1.r2i);

	if (chk_type == CHK_SINGLE) {
		if (LIMIT_BY_FUNCS) {
			/* Check if the inculde functions are executed. */
			for_each_node(r2p1.include_funcs,
				      f_chk_ifuncs_are_executed, &r2p1);
			if (!output_summary)
				print_func_tree(&r2p1, &dt);
		}
		for (i = 0; i < r2i->num_r2n; i++) {
			r2n = r2i->all_r2n[i];
			r2p1.r2n = r2n;
			get_all_fc_cnt(&r2p1, &cnt);
			if (!cnt.all)
				continue;
			//for (j = 0; j < r2n->bi.NumOfSourceNames; j++) {
			//	_splitpath(r2n->bi.SourceNameList[j], drive, dir, fname, ext);
			//	if (_stricmp(ext, ".c"))
			//		continue;
				if (HTML_OUTPUT) {
					//strcat(fname, ext);
					dt.cur_ELFname = r2n->basename; //fname;
					out_summary_html_name(&dt);
				} else
					printf("====== %s coverage ======\n",
					       r2n->bi.SourceNameList[i]); //r2n->basename
				dump_func_coverage(&dt, &cnt, NULL);
				//dump_branch_coverage(&dt);
				//dump_state_coverage(&dt);
			//}
		}
	} else {
		num_compared = 0;
		for (i = 0; i < r2i->num_r2n; i++) {
			r2n = r2i->all_r2n[i];
			r2n2 = find_comparable_pair(r2i2, r2n, chk_type);
			if (!r2n2)
				continue;
			r2p1.r2n = r2n;
			get_all_fc_cnt(&r2p1, &cnt);
			r2p2.r2n = r2n2;
			get_all_fc_cnt(&r2p2, &cnt2);
			if (cnt.all == cnt2.all && cnt.all == 0)
				continue;
			num_compared++;
			if (chk_type == CHK_SAME)
				r2p2.srcdir = r2p1.srcdir;
			dt.cur_ELFname = r2n->basename;
			out_summary_html_name(&dt);
			dump_func_coverage(&dt, &cnt, &cnt2);
			dump_branch_coverage(&dt);
			dump_state_coverage(&dt);
		}
		if (!num_compared) {
			//fprintf(stderr, "There is no comparable ELF files.\n");
			return FAILURE;
		}
	}
	if (HTML_OUTPUT) {
		if (exit_html_output(&dt, LIMIT_BY_FUNCS) == FAILURE)
			return FAILURE;
	}
	return SUCCESS;
}

static int chk_maps(FILE *f, union bt_record *rec, off_t i_rec, void *data)
{
	struct r2n_info *r2i = data;

	return chk_maps_in_log(r2i, rec);
}

static int chk_maps_block_log(void *elem, void *data)
{
	FILE *f = 0; 
	struct __pid_info *__p = elem;
	struct log_file_info *log_info = get_log_file_info(__p);

	return for_each_block_record(f, log_info->fd, __p->i_rec,
				     __p->i_rec + __p->n_rec, chk_maps, data);
}

static int chk_maps_for_one_pid(struct pid_log_info *p, void *data)
{
	return for_each_node(p->info, chk_maps_block_log, data);
}

static int
chk_elf_files(struct r2i_pack *r2p, char *logfile, bool_t chk_elf_verbose)
{
	bool_t maps_not_found = FALSE;
	int rc;
	char *tmp = _strdup(logfile);
	char *dir; //, maps_fpath[PATH_MAX];
	struct r2n_info *r2i = &r2p->r2i;

	rc = FAILURE;
	dir = tmp; //dirname(tmp)
	/*
	if (get_maps_fpath(dir, maps_fpath)) {
		if (parse_maps(r2i, maps_fpath, chk_elf_verbose) == FAILURE)
			goto EXIT;
	} else {
		maps_not_found = TRUE;
		if (for_each_pid_log_info(chk_maps_for_one_pid, r2i)
		    == FAILURE)
			goto EXIT;
	}
	*/
	if (parse_modules(r2i, dir, TRUE, chk_elf_verbose) == FAILURE)
		goto EXIT;
	if (create_path_trees(r2i, chk_elf_verbose) == FAILURE)
		goto EXIT;
	r2i->from_is_next = chk_from_is_next(dir);

	if (chk_elf_verbose)
		printf("start\n");

	if (create_both_filter_funcs(r2p) == FAILURE)
		goto EXIT;

	/* Here, we unmap the application and libraries because traced
	 * application doesn't execute 'execv'.
	 * So, the mapping haven't changed as the applications one.
	 * We map these on 'map' record in each record process.
	 */
	if (maps_not_found)
		save_lib_and_app_as_unmapped(&r2p->r2i);
	rc = SUCCESS;
EXIT:
	free(tmp);
	return rc;
}

int proc_pid_block_log(void *elem, void *data)
{
	struct __pid_info *__p = elem;
	struct log_file_info *log_info = get_log_file_info(__p);

	if (print_enter_leave && verbose)
		printf("======== %s\t" PF_OFFTD ":" PF_OFFTD " ========\n",
		       log_info->fpath, __p->i_rec, __p->n_rec);
	return for_each_block_record(stdout, log_info->fd,
				     __p->i_rec, __p->i_rec + __p->n_rec,
				     proc_each_record, data);
}

int proc_pid_logfiles(struct pid_log_info *p, void *data)
{
	struct proc_each_rec_data d;

#ifdef RAW_DEBUG
	printf("RAW INFO: ");
#else
	if (print_enter_leave)
#endif
		printf("PID:%lld >>>>>>>>\n", p->pid);
	d.r2p = data;
	d.range = get_pid_addr_range(ALL_PID);
	d.last = UNKNOWN_BADDR;
	d.context_status = LIMIT_BY_FUNCS && eliminate_out_of_context ?
					CS_OUT_OF_CONTEXT : CS_INTO_THE_CONTEXT;
	save_lib_and_app_as_unmapped(&d.r2p->r2i);
	return for_each_node(p->info, proc_pid_block_log, &d);
}

int proc_one_log_dir(char *files[], void *data)
{
	struct r2i_pack *r2p = data;
	bool_t chk_elf_verbose;

	chk_elf_verbose = output_summary || HTML_OUTPUT ? FALSE : TRUE;

	save_r2n_as_unmapped(&r2p->r2i);
	if (initialize_log_info(files) == FAILURE)
		return FAILURE;
	if (chk_pid_pos(files, FALSE, 0) == FAILURE)
		return FAILURE;
	if (chk_elf_files(data, files[0], chk_elf_verbose) == FAILURE)
		return FAILURE;
	chk_nest_initialize();
	if (for_each_pid_log_info(proc_pid_logfiles, data) == FAILURE)
		return FAILURE;
	finalize_log_info();
	return SUCCESS;
}

int proc_all_log_dirs(struct r2i_pack *r2p, char *log, int n_logfs)
{
	int i, j, n_dirs;
	//bool_t flags[n_logfs];
	bool_t *flags = (bool_t *)malloc(n_logfs * sizeof(bool_t));
	char *files[MAX_CPU_FILES + 1];
	char *f, *target_dir = NULL, *tmp, *dir;

	r2p->r2i.num_r2n = 0;
	r2p->r2i.all_r2n = NULL;
	for (i = 0; i < n_logfs; i++)
		flags[i] = FALSE;
	n_dirs = 0;
	j = 0;
	for (;;) {
		for (f = log, i = 0; i < n_logfs; i++, f += strlen(f) + 1) {
			if (flags[i])
				continue;
			tmp = _strdup(f);
			dir = tmp; //dirname(tmp)
			if (target_dir) {
				if (strcmp(target_dir, dir) != 0)
					goto FREE_AND_NEXT;
			} else
				target_dir = _strdup(dir);
			files[j++] = f;
			flags[i] = TRUE;
FREE_AND_NEXT:
			free(tmp);
		}
		if (j == 0)
			break;
		files[j] = NULL;
		j = 0;
		free(target_dir);
		target_dir = NULL;

		/* do process with 'files' */
		if (proc_one_log_dir(files, r2p) == FAILURE)
			return FAILURE;
		n_dirs++;
	}
	restore_r2n_as_mapped(&r2p->r2i);
	save_oor_kernel_as_unmapped(&r2p->r2i);
	chk_and_modify_same_basename(&r2p->r2i);
	if (flags) free(flags);
	return SUCCESS;
}

int replace_comma_with_null(char *top, int *n)
{
	char *prev, *cur, *context;

	*n = 0;
	prev = NULL;
	cur = strtok_s(top, ",", &context);
	while (cur) {
		(*n)++;
		if ((!prev && cur != top) ||
		    (prev && cur != prev + strlen(prev) + 1))
			return FAILURE;
		prev = cur;
		cur = strtok_s(NULL, ",", &context);
	}
	return SUCCESS;
}

static void free_fc(void *elem)
{
	struct func_chk *fc = elem;

	if (fc->childs)
		free_tree(fc->childs, NULL);
	free(fc);
}

static void free_r2p(struct r2i_pack *r2p)
{
	long i;

	for (i = 0; i < r2p->src_info_num; i++) {
		struct src_info *si;

		si = r2p->src_info[i];
		free(si->exec_types);
		free(si);
	}
	free(r2p->src_info);

	free_tree(r2p->include_funcs, NULL);
	free_tree(r2p->include_fcs, NULL);
	free_tree(r2p->exclude_funcs, NULL);
	free_tree(r2p->fc_list, free_fc);
	free_r2n(&r2p->r2i);
	memset(r2p, 0, sizeof(struct r2i_pack));
}

void err_exit1(void)
{
	exit(EXIT_FAILURE);
}

static void usage(void)
{
	/*
	fprintf(stderr, "bt_coverage %s\n", BT_COVERAGE_VER);
	fprintf(stderr, "    %s\n\n", COPYRIGHT);
	fprintf(stderr, "bt_coverage [-se] [-a top:end] [-d top:end]" \
		        " [--usr|--ker|--all]\n");
	fprintf(stderr, "            [-I func[,...]] [-E func[,...]]" \
		        " [[-S src_dir] -o html_out_dir]\n");
	fprintf(stderr, "            [-u kver] -f logfile[,...]\n");
	fprintf(stderr, "            [[[--u2 kver] --S2 src_dir]" \
		        " --f2 logfile[,...]]\n");
	fprintf(stderr, "  -s: output coverage summary\n");
	fprintf(stderr, "  -e: exclude out-of-context path (experimental)\n");
	fprintf(stderr, "  -a: add address range\n");
	fprintf(stderr, "  -d: delete address range\n");
	fprintf(stderr, "  --usr: alias of '-a %ld:" PF_LH "'\n",
		USER_START, USER_END);
	fprintf(stderr, "  --ker: alias of '-a " PF_LH ":" PF_LH "'\n",
		KERNEL_START, KERNEL_END);
	fprintf(stderr, "  --all: alias of '-a %ld:" PF_LH "'\n",
		USER_START, KERNEL_END);
	fprintf(stderr, "  -I: include function name(s)\n");
	fprintf(stderr, "  -E: exclude function name(s)\n");
	fprintf(stderr, "      This option excludes only included function by" \
		        " -I option.\n");
	fprintf(stderr, "  -S: source directory\n");
	fprintf(stderr, "  -o: html output directory\n");
	fprintf(stderr, "      -o and -S options cannot be used with -s" \
		        " option.\n");
	fprintf(stderr, "  -u: kernel version ('uname -r')\n");
	fprintf(stderr, "  -f: logfile(s)\n");
	fprintf(stderr, "  --u2,--S2,--f2: display differences between two" \
		        " trace-log(s).\n");
	fprintf(stderr, "         These options should be used with -o" \
		        " option.\n");
	fprintf(stderr, "  --ignore-elf-errors: skip the file btrax cannot"
			" recognize as valid ELF\n");
	*/
}

void err_usage(void)
{
	usage();
	err_exit1();
}

//int coveragemain(char *btsfile, char *outpath, char *srcpath, ReportProgressFtn iReport)
int coveragemain(char *btsfile, char *outpath, char *srcpath)
{
	int rc/*, opt_index*/, n_logfs = 1, n_logfs2 = 0;
	char *logfs_top = NULL, *logfs_top2 = NULL; //c, 
	//char *modulefile = NULL, *logfile = NULL, *outpath = NULL, *srcpath = NULL;
	//unsigned long begin, end;
	//char szCurWorkingDir[_MAX_PATH] = {0}, szOutputDir[_MAX_PATH] = {0}; //, szSrcDir[_MAX_PATH] = "D:\\Romley";

	printf("Start code coverage analysis...\n");
	alloc_pid_range(ALL_PID);
	add_range(ALL_PID, USER_START, KERNEL_END);

	// Init Pdb library
	//_getcwd(szCurWorkingDir, _MAX_PATH);

	r2p1.srcdir = srcpath;
	logfs_top = btsfile;
	//sprintf(szOutputDir, "%s\\%s", szCurWorkingDir, outpath);
	outdir = outpath; //szOutputDir;
	if (outdir) {
		if (dir_chk_and_create(outdir, FALSE) == FAILURE) //TRUE
			err_exit1();
	}
	rc = FAILURE;
	if (proc_all_log_dirs(&r2p1, logfs_top, n_logfs) == FAILURE)
		goto FREE_EXIT;
	if (logfs_top2) {
		if (proc_all_log_dirs(&r2p2, logfs_top2, n_logfs2) == FAILURE)
			goto FREE_EXIT;
	}
	chk_type = get_chk_type(&r2p1.r2i, &r2p2.r2i, logfs_top2 != NULL);
	//if (iReport) iReport(60);
	rc = SUCCESS;
	if (print_enter_leave)
		goto FREE_EXIT;
	if (verbose) {	/* hidden option for debug */
		dump_r2n(&r2p1.r2i);
		if (logfs_top2) {
			printf("======== other kernel ========\n");
			dump_r2n(&r2p2.r2i);
		}
	}
	//if (iReport) iReport(70);
	rc = dump_coverage();
	//if (iReport) iReport(99);

FREE_EXIT:
	free_ranges();
	free_r2p(&r2p1);
	free_r2p(&r2p2);

	// Release Pdb library
	//PdbShutdown();
	printf("End of code coverage analysis\n");

	//exit(rc == FAILURE ? EXIT_FAILURE : EXIT_SUCCESS);
	return (rc == FAILURE ? EXIT_FAILURE : EXIT_SUCCESS);
}

