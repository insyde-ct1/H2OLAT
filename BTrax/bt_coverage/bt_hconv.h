/*****************************************************************************/
/* The development of this program is partly supported by IPA                */
/* (Information-Technology Promotion Agency, Japan).                         */
/*****************************************************************************/

/*****************************************************************************/
/*  bt_hconv.h - coverage output to html converter header                    */
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

#ifndef __BT_HCONV_H__
#define __BT_HCONV_H__

#define IS_SWITCH_JMP(p)	\
	((p)->type == BTYPE_JMP \
	 && (p)->jmp_to.addr == UNKNOWN_BADDR && (p)->next_cnt < 0)

#define SET_FC_NOT_CHECKED(fc)		(fc)->invalid = 0
#define SET_FC_VALID(fc)		(fc)->invalid |= (1<<0)
#define SET_FC_UT(fc)			(fc)->invalid |= (1<<1)
#define SET_FC_SAME_NAME_EXISTS(fc)	(fc)->invalid |= (1<<2)

#define IS_VALID_FC(fc)			((fc)->invalid & (1<<0))
#define IS_UT_FC(fc)			(!((fc)->invalid & (1<<0)) && \
					 (fc)->invalid & (1<<1) && \
					 (fc)->cnt != 0)
#define IS_SAME_NAME_EXISTS_FC(fc)	((fc)->invalid & (1<<2))
#define IS_CHECKED_FC(fc)		(IS_VALID_FC(fc) || IS_UT_FC(fc) || \
					 IS_SAME_NAME_EXISTS_FC(fc))

enum {
	CHK_SINGLE,
	CHK_SAME,
	CHK_DIFF,
};

struct func_chk {
	struct jmp_to	dest;
	unsigned int	cnt;
	int				invalid;
	node			*childs;
	unsigned int	tree_weight;
	/* Below members are used for checking the difference of two logs */
	const char		*fname;	/* This field used for only CHK_DIFF_KERNEL */
	unsigned long	offset;
	/* Below members are used for caching valid path's information */
	UINT64			end;
};

struct src_info {
	char	path[PATH_MAX + 1];	/* absolute path */
	char	srcpath[PATH_MAX + 1];	/* absolute path */
	int	    ln_max;
	char	*exec_types;		/* execute-type per line */

	/* cache data that is used for convert abs-path to html-path */
	bool_t	is_ref;
	char	html_out_path[PATH_MAX + 1];
};

struct r2i_pack {
	char			*srcdir;
	node			*include_funcs;	/* avl tree of ulong address */
	node			*include_fcs;	/* avl tree of func_chk */
	node			*exclude_funcs;
	struct r2n_info		r2i;
	struct range_to_name	*r2n;
	node			*fc_list;
	struct src_info		**src_info;
	int			src_info_num;
};

struct cov_out_data {
	FILE		*in;
	FILE		*summary_out;
	FILE		*ftree_out;
	FILE		*cur_out;
	char		*outdir;
	char		*cur_ELFname;
	char		abs_path[PATH_MAX + 1];
	int		limit_by_funcs;
	int		chk_type;
	struct r2i_pack	*r2p[2];
};

struct branch_info {
	UINT64	base;
	struct jmp_to	branch;
	int		b_cnt;
	UINT64	fall;
	int		f_cnt;
	int		uk_id;	// for checking whether it's the first uk.
};

#define BCOV_TYPE_OK	0
#define BCOV_TYPE_HT	1
#define BCOV_TYPE_NT	2
#define BCOV_TYPE_UT	3
#define BCOV_TYPE_UN	4

#define get_percent(n_exec, n_total) \
	((n_total) == 0 ? (double)100.00 : (double)(n_exec) * 100 / (n_total))

typedef void (*func_do_one_bcov)(struct cov_out_data *dt, int side,
				 int bcov_type, struct branch_info *bi);
inline void do_one_branch_coverage(struct cov_out_data *dt, int side,
				   struct path *p, func_do_one_bcov func);

int dir_chk_and_create(char *path, bool_t err_on_exists);
long get_unknown_bcnt(struct path *p);
int init_html_output(struct cov_out_data*);
void out_summary_html_name(struct cov_out_data*);

/* function tree */
void out_func_tree_html_start(struct cov_out_data*, char *s_inc, char *s_exc);
void out_func_tree_html_each_enter(struct cov_out_data *dt, int side,
				   struct func_chk *fc, int nest, int type,
				   bool_t has_child);
void out_func_tree_html_each_exit(struct cov_out_data *dt, int nest,
				  bool_t has_child);
void out_func_tree_html_each_invalid(struct cov_out_data *dt, int side,
				     struct func_chk *fc);
void out_func_tree_html_end(struct cov_out_data*);

/* function coverage */
void out_summary_html_func(struct cov_out_data *dt, int side,
			   long n_func, long n_func_all);
void out_func_html_start(struct cov_out_data*, long same, long diff);
void out_func_html_each(struct cov_out_data *dt, struct func_chk *fc);
void out_func_html_each2(struct cov_out_data *dt,
			 struct func_chk *fc1, struct func_chk *fc2,
			 long *same, long *diff);
void out_func_html_end(struct cov_out_data*);

/* branch coverage */
void out_summary_html_branch(struct cov_out_data *dt, int side,
			     long n_br_ok, long n_br_uk,
			     long n_br_ht, long n_br_nt,
			     long n_br_all, long n_uk_all);
void out_branch_html_start(struct cov_out_data*, long same, long diff);
void out_branch_html_each(struct cov_out_data *dt, int side,
			  struct branch_info *bi);
void out_branch_html_each2(struct cov_out_data *dt,
			   struct branch_info *bi, struct branch_info *bi2,
			   long *same, long *diff);
void out_branch_html_end(struct cov_out_data*);

/* state coverage */
void out_summary_html_state(struct cov_out_data *dt, int side,
			    long n_ok, long n_states);
void out_state_html_start(struct cov_out_data*, long same, long diff);
void out_state_html_each(struct cov_out_data *dt, int side, bool_t is_exec,
			 struct path*);
void out_state_html_each2(struct cov_out_data *dt, bool_t is_exec,
			  bool_t is_exec2, struct path*);
#define out_state_html_end out_branch_html_end

int exit_html_output(struct cov_out_data*, int limit_by_funcs);

int init_html2_output(struct cov_out_data *dt);
void out_execpath_html_start(FILE *f);
void out_execpath_html_end(FILE *f);

#endif /*__BT_HCONV_H__*/

