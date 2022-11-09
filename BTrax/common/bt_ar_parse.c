/*****************************************************************************/
/* The development of this program is partly supported by IPA                */
/* (Information-Technology Promotion Agency, Japan).                         */
/*****************************************************************************/

/*****************************************************************************/
/*  bt_ar_parse.c - /proc/modules and /proc/PID/maps parser                  */
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

#include <stdlib.h>
#include <stdio.h>
//#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
//#include <sys/mman.h>
//#include <sys/utsname.h>
#include <fcntl.h>
//#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <share.h>
#include "bt_ar_parse.h"
#include "dispdb.h"

//extern PPDB_FUNCS gPdb;

static struct pid_range *ranges;

/*----------------------------------------------------------------------------*/
/*  range_to_name support functions                                           */
/*----------------------------------------------------------------------------*/
int for_each_r2n(struct r2n_info *r2i, func_each_r2n f, void *data)
{
	int i, rc = ALL_DONE;
	struct range_to_name *r2n;

	for (i = 0; i < r2i->num_r2n; i++) {
		r2n = r2i->all_r2n[i];
		if ((rc = f(r2i, r2n, data)) != CONTINUE)
			break;
	}
	return rc;
}

void printf_path(struct range_to_name *r2n, struct path *p)
{
	struct unknown *uk;
	int type = p->type;

	if (type & IS_INVALID_PATH) {
		printf("(INV)\t ");
		type &= ~IS_INVALID_PATH;
	} else
		printf("(%d)\t ", p->cnt);
	printf("0x%08llx", p->addr);
	switch (type) {
	case BTYPE_BRANCH:
		printf(" JXX  "); break;
	case BTYPE_JMP:
		printf(" JMP  "); break;
	case BTYPE_CALL:
		printf(" CALL "); break;
	case BTYPE_RET:
		printf(" RET  "); break;
	case BTYPE_IRET:
		printf(" IRET "); break;
	case BTYPE_INT:
		printf(" INT  "); break;
	case BTYPE_BREAK:
		printf(" BRK  "); break;
	default:
		printf(" ---  0x%08llx => --------:----------(-) : ", p->base);
		printf("0x%08llx(%d)\n", p->next, p->cnt);
		return;
	}
	printf("0x%08llx => ", p->base);
	switch (type) {
	case BTYPE_BRANCH:
	case BTYPE_CALL:
	case BTYPE_JMP:
		if (p->jmp_to.addr == UNKNOWN_BADDR) {
			uk = (struct unknown*)p->jmp_cnt;
			if (p->cnt < 0 || !uk)
				printf("--------:XXXXXXXXXX(0) : ");
			else {
				for (; uk; uk = uk->next) {
					printf("%8s:0x%08llx(%d), ",
					       r2n_name_of_jmp(r2n, uk->jmp_to),
					       uk->jmp_to.addr, uk->cnt);
				}
				printf(": ");
			}
		} else {
			printf("%8s:0x%08llx(%ld) : ",
			       r2n_name_of_jmp(r2n, p->jmp_to),
			       p->jmp_to.addr, p->jmp_cnt);
		}
		if (type == BTYPE_JMP)
			printf("----------(-)");
		else
			printf("0x%08llx(%d)", p->next, p->next_cnt);
		break;
	case BTYPE_RET:
	case BTYPE_IRET:
	case BTYPE_INT:
	case BTYPE_BREAK:
		printf("--------:");
		printf("----------(-) : ----------(-)");
		break;
	}
	printf("\n");
}

void dump_path_tree(struct range_to_name *r2n)
{
	long i;
	struct path *p;

	printf("------ path tree ------\n");
	for_each_path(r2n, i, p)
		printf_path(r2n, p);
}

void dump_r2n(struct r2n_info *r2i)
{
	int i;
	struct range_to_name *p;

	for (i = 0; i < r2i->num_r2n; i++) {
		p = r2i->all_r2n[i];
		printf("====== 0x%08llx:0x%08llx:0x%08lx\t%s/%s ======\n",
		       p->begin, p->end, p->offset, p->dirname, p->basename);
		//dump_bfd_symbols(&p->bi, p->begin, p->end);
		dump_path_tree(p);
	}
}

static void free_path_tree(struct range_to_name *r2n)
{
	long i;
	struct path *p;

	if (!r2n || !r2n->path_array)
		return;
	for_each_path(r2n, i, p)
		free_path(p);
	free(r2n->path_array);
	r2n->path_array = NULL;
	r2n->num_path_array = 0;
}

static void free_fix_from_cache(struct range_to_name *r2n)
{
	struct fix_from_cache *p, *p_next;

	for (p = r2n->fix_from_cache; p; p = p_next) {
		p_next = p->next;
		free(p);
	}
	r2n->fix_from_cache = NULL;
}

static void free_one_r2n(struct range_to_name *r2n)
{
	//free_bi(&r2n->bi);
	free_path_tree(r2n);
	free_fix_from_cache(r2n);
	free(r2n);
}

void free_r2n(struct r2n_info *r2i)
{
	int i;
	struct range_to_name *p;

	for (i = 0; i < r2i->num_r2n; i++) {
		p = r2i->all_r2n[i];
		free_one_r2n(p);
	}
	if (r2i->all_r2n)
		free(r2i->all_r2n);
	if (r2i->all_r2n_unmapped)
		free(r2i->all_r2n_unmapped);
	if (r2i->uname_r)
		free(r2i->uname_r);
}

struct range_to_name* addr_to_r2n(struct r2n_info *r2i, UINT64 addr)
{
	int i;
	struct range_to_name *p;

	for (i = 0; i < r2i->num_r2n; i++) {
		p = r2i->all_r2n[i];
		if (addr >= p->begin && addr <= p->end)
			return p;
	}
	return NULL;
}

static struct range_to_name*
get_same_name_r2n(struct r2n_info *r2i, char *name)
{
	int i, len;
	struct range_to_name *r2n;

	for (i = 0; i < r2i->num_r2n; i++) {
		r2n = r2i->all_r2n[i];
		len = (int)strlen(r2n->dirname);
		if (((INT)strlen(name) > (len + 1)) && name[len] == '/' &&
		    strncmp(r2n->dirname, name, len) == 0 &&
		    strcmp(r2n->basename, &name[len + 1]) == 0)
			return r2n;
	}
	return NULL;
}

static struct range_to_name*
get_same_name_unmapped_r2n(struct r2n_info *r2i, char *name)
{
	int i, j, len;
	struct range_to_name *r2n;

	for (i = 0; i < r2i->num_r2n_unmapped; i++) {
		r2n = r2i->all_r2n_unmapped[i];
		len = (int)strlen(r2n->dirname);
		if (((INT)strlen(name) > (len + 1)) && name[len] == '/' &&
		    strncmp(r2n->dirname, name, len) == 0 &&
		    strcmp(r2n->basename, &name[len + 1]) == 0) {
			for (j = i + 1; j < r2i->num_r2n_unmapped; j++) {
				r2i->all_r2n_unmapped[j - 1] =
					r2i->all_r2n_unmapped[j];
			}
			r2i->num_r2n_unmapped -= 1;
			return r2n;
		}
	}
	return NULL;
}

/* Size of the 'buf' must be PATH_MAX */
static char*
get_pt_fpath(char *buf, struct range_to_name *r2n, char *uname_r,
	     bool_t is_read)
{
	/*
	int i;
	struct stat st;
	char *dirs[] = { "/tmp" };

	for (i = 0; i < ARRAY_SIZE(dirs); i++) {
		if (is_lib_or_app(r2n)) {
			_snprintf(buf, PATH_MAX, "%s/btrax.pt.%s_%s",
				 dirs[i], r2n->dirname, r2n->basename);
			conv_slash2underscore(&buf[ strlen(dirs[i]) + 1 ],
					      FALSE);
		} else
			_snprintf(buf, PATH_MAX, "%s/btrax.pt.%s-%s",
				 dirs[i], r2n->basename, uname_r);
		if (is_read) {
			if (_stat(buf, &st) >= 0 && S_ISREG(st.st_mode))
				return buf;
		} else {
			if (_stat(dirs[i], &st) >= 0 && S_ISDIR(st.st_mode))
				return buf;
		}
	}
	*/
	return NULL;
}

#if 1
static int pt_needs_update(char *self, char *pt)
{
	struct _stat self_st, pt_st;

	if (_stat(self, &self_st) < 0 || _stat(pt, &pt_st) < 0)
		return TRUE;
	if (self_st.st_mtime >= pt_st.st_mtime)
		return TRUE;
	return FALSE;
}
#endif

#define MAX_VERSION_LEN		31
#define read_dt(fd, dt, label) \
	if (u_read((fd), &(dt), sizeof(dt)) != sizeof(dt)) goto label

static int read_pt_from_file(struct range_to_name *r2n, char *elf_path,
			     struct stat *elf_st, char *uname_r)
{
	int i;
	int fd, len;
	struct stat st;
	char ver[MAX_VERSION_LEN + 1], pt_path[PATH_MAX], path[PATH_MAX];
	struct path *p;
	errno_t err;

	if (is_module(r2n))
		return FAILURE;
	if (!get_pt_fpath(pt_path, r2n, uname_r, TRUE))
		return FAILURE;
	//if ((fd = _open(pt_path, O_RDONLY)) < 0) {
	err = _sopen_s(&fd, pt_path, _O_RDONLY, _SH_DENYNO,  _S_IREAD | _S_IWRITE);
	if (err) {
		//fprintf(stderr, "'%s' open failed.(%s)\n",
		//	pt_path, strerror(errno));
		return FAILURE;
	}
#if 1
	/* If this program's modified time is newer than path-tree file,
	 * there is posibility of updating of binutils.
	 */
	/*
	if ((len = readlink("/proc/self/exe", path, PATH_MAX)) < 0) {
		fprintf(stderr, "readlink failed.(%s)\n", strerror(errno));
		goto ERR_EXIT;
	}
	*/
	path[len] = '\0';
	if (pt_needs_update(path, pt_path))
		return FAILURE;
#endif

	read_dt(fd, len, ERR_EXIT);
	if (len > MAX_VERSION_LEN)
		goto ERR_EXIT;
	if (read_4b_aligned_string(fd, ver, MAX_VERSION_LEN + 1) < 0)
		goto ERR_EXIT;
	ver[len] = '\0';
	//if (strcmp(VERSION, ver) != 0)
	//	goto ERR_EXIT;
	read_dt(fd, len, ERR_EXIT);
	if (read_4b_aligned_string(fd, path, PATH_MAX) < 0)
		goto ERR_EXIT;
	path[len] = '\0';
	if (strcmp(elf_path, path) != 0)
		goto ERR_EXIT;
	read_dt(fd, st.st_size, ERR_EXIT);
	if (elf_st->st_size != st.st_size)
		goto ERR_EXIT;
	read_dt(fd, st.st_mtime, ERR_EXIT);
	if (elf_st->st_mtime != st.st_mtime)
		goto ERR_EXIT;
	read_dt(fd, r2n->num_path_array, ERR_EXIT);
	r2n->path_array = malloc(sizeof(*r2n->path_array)
						* r2n->num_path_array);
	for (i = 0; i < r2n->num_path_array; i++) {
		p = malloc(sizeof(*p));
		read_dt(fd, *p, ERR_EXIT);
		if (p->jmp_to.r2n)
			p->jmp_to.r2n = r2n;
		r2n->path_array[i] = p;
	}
	_close(fd);
	return SUCCESS;

ERR_EXIT:
	_close(fd);
	return FAILURE;
}

#define write_dt(fd, dt, label) \
	if (u_write((fd), &(dt), sizeof(dt)) < 0) goto label

static int write_pt_to_file(struct range_to_name *r2n, char *elf_path,
			    struct stat *st, char *uname_r)
{
	char pt_path[PATH_MAX];
	int i;
	int fd, len;
	struct path *p;
	errno_t err;

	/* Only kernel module's path-tree needs reference to the other modules
	 * or the kernel.
	 * We want the code simple, so we don't want to write the reference to
	 * the other ELF file.
	 * Kernel modules usually have small size, and less advantage for
	 * caching. So, we ignore the kernel module's caching.
	 */
	if (is_module(r2n))
		return SUCCESS;
	if (!get_pt_fpath(pt_path, r2n, uname_r, FALSE))
		return FAILURE;
	//if ((fd = _open(pt_path,
	//		_O_CREAT|_O_RDWR)) < 0) {
	err = _sopen_s(&fd, pt_path, _O_CREAT|_O_RDWR, _SH_DENYNO, _S_IREAD | _S_IWRITE);
	if (err) {
		//fprintf(stderr, "'%s' open failed.(%s)\n",
		//	pt_path, strerror(errno));
		return FAILURE;
	}
	/* The 'sticky' bit on a temporary directory is typically set.
	 * In this case, the 'creat' function can not set the write permission
	 * for another users. So, we call 'chmod' function.
	 */
	//chmod(pt_path, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);

	len = (int)strlen(VERSION);
	write_dt(fd, len, ERR_EXIT);
	if (write_4b_aligned_string(fd, VERSION) < 0)
		goto ERR_EXIT;
	len = (int)strlen(elf_path);
	write_dt(fd, len, ERR_EXIT);
	if (write_4b_aligned_string(fd, elf_path) < 0)
		goto ERR_EXIT;
	write_dt(fd, st->st_size, ERR_EXIT);
	write_dt(fd, st->st_mtime, ERR_EXIT);
	write_dt(fd, r2n->num_path_array, ERR_EXIT);
	for_each_path(r2n, i, p) {
		if (p->jmp_to.r2n && p->jmp_to.r2n != r2n) {
			//struct range_to_name *r2n_to = p->jmp_to.r2n;
			//fprintf(stderr,
			//	"%s refers %s, so couldn't create cache file\n",
			//	r2n->basename, r2n_to->basename);
			goto ERR_EXIT;
		}
		write_dt(fd, *p, ERR_EXIT);
	}
	_close(fd);
	return SUCCESS;
ERR_EXIT:
	_chsize(fd, 0);
	_close(fd);
	return FAILURE;
}

static int get_kernel_offset(struct range_to_name *r2n, char *kallsyms)
{
	return FAILURE;
	/*
	char *ksym_name = "_stext";
	unsigned long addr1, addr2;
	FILE *f = NULL;
	char buf[MAX_LINE_LEN + 1], type, sym[MAX_LINE_LEN];
	bool_t found;
	int num;

	if (get_addr_of_symbol(&r2n->bi, ksym_name, &addr1) < 1){
		fprintf(stderr, "Symbol '%s' not found in kernel.\n",
			ksym_name);
		return FAILURE;
	}
	if (kallsyms == NULL) {
		fprintf(stderr, "kallsyms was not logged.\n");
		return FAILURE;
	}
	if ((f = fopen(kallsyms, "r")) == NULL) {
		fprintf(stderr, "fopen \"%s\" failed.(%s)\n",
			kallsyms, strerror(errno));
		return FAILURE;
	}
	buf[MAX_LINE_LEN] = '\0';
	found = FALSE;
	while (fgets(buf, MAX_LINE_LEN, f)) {
		num = sscanf(buf, "%lx %c %s\n", &addr2, &type, sym);
		if (num == 3 && strcmp(sym, ksym_name) == 0) {
			found = TRUE;
			break;
		}
	}
	fclose(f);
	if (!found) {
		fprintf(stderr, "Symbol '%s' not found in '%s'.\n",
			ksym_name, kallsyms);
		return FAILURE;
	}
	r2n->offset = addr2 - addr1;
	return SUCCESS;
	*/
}

static int prepare_obj_file(struct range_to_name *r2n, char *kpatchinf,
			    char *kallsyms, char *mod_name, char *uname_r,
			    struct imf_bi_info *imf_info)
{
	int rc;
	char path[PATH_MAX]; //, kpi_path[PATH_MAX];
	struct stat st; //, kpi_st;

	_snprintf_s(path, PATH_MAX, PATH_MAX - 1, "%s/%s", r2n->dirname, r2n->basename);
	if (stat(path, &st) < 0) {
		//fprintf(stderr, "'%s' stat failed.(%s)\n",
		//	path, strerror(errno));
		return FAILURE;
	}
	rc = 0; //init_bfd_if(&r2n->bi, path,
			//is_kernel(r2n) ? NULL : kallsyms, mod_name, imf_info);
	if (rc)
		return rc;
	/*if (is_kernel(r2n)) {
		if (imf_info)
			r2n->offset = imf_info->kern_offset;
		else {
			unsigned long min, max;

			if (get_kernel_offset(r2n, kallsyms) == FAILURE)
				return FAILURE;
			get_kernel_min_max_addr(&r2n->bi, &min, &max);
			r2n->begin = min + r2n->offset;
			r2n->end = max + r2n->offset;
		}
	} else {*/
		r2n->offset = 0; //get_offset_addr(&r2n->bi, r2n->begin);
	//}
	r2n->bi.begin = r2n->begin - r2n->offset;
	r2n->bi.end = r2n->end - r2n->offset;
	/*
	if (kpatchinf) {
		_snprintf(kpi_path, sizeof(kpi_path), "%s/%s",
			 kpatchinf, r2n->basename);
		if (stat(kpi_path, &kpi_st) == 0) {
			if (read_kpatchinf(&r2n->bi, r2n->offset, kpi_path)
			    == FAILURE)
				return FAILURE;
		}
	}
	if (!is_module(r2n)
	    && init_dwarf(&r2n->bi, (const char*)path) == FAILURE)
		return FAILURE;
	remove_useless_fsyms(&r2n->bi, r2n->begin, r2n->end, r2n->offset);
	*/
	return SUCCESS;
}

static int
add_range_to_name(struct r2n_info *r2i,
		  UINT64 begin, UINT64 end, char *name,
		  char *kpatchinf, char *kallsyms, char *mod_name,
		  bool_t for_coverage, struct imf_bi_info *imf_info)
{
	int i; //rc, 
	//char path_buffer[_MAX_PATH];
	//char drive[_MAX_DRIVE];
	char dir[_MAX_DIR];
	char fname[_MAX_FNAME];	//bool_t found_r2n = FALSE;
	struct range_to_name *r2n;
	//char *tmp;
	//struct addr_range *range = get_pid_addr_range(ALL_PID);

	/*
	tmp = realpath(name, NULL);
	if (!tmp) {
		if (errno == ENOENT)
			fprintf(stderr, "traced ELF file is already deleted"
				" (%s).\n", name);
		else
			fprintf(stderr, "\"%s\" realpath failed(%s).\n",
				name, strerror(errno));
		return FAILURE;
	}
	if ((r2n = get_same_name_unmapped_r2n(r2i, tmp))) {
		found_r2n = TRUE;
		if (!is_kernel(r2n)) {
			r2n->offset = r2n->offset + (begin - r2n->begin);
			r2n->begin = begin;
			r2n->end = end;
		}
	}
	*/
	//if (!found_r2n) {
		r2n = calloc(1, sizeof(*r2n));
		r2n->begin = begin;
		r2n->end = end;
		_snprintf_s(r2n->name, PATH_MAX, PATH_MAX - 1, "%s", name); //tmp
		_splitpath_s(r2n->name, NULL, 0, dir, _MAX_DIR, fname, _MAX_FNAME, NULL, 0);
		r2n->basename = _strdup(fname);
		r2n->dirname = _strdup(dir);
		r2n->etype = ETYPE_MODULE;
		if (imf_info)
			memcpy(&r2n->bi, imf_info, sizeof(MODULE_DESC));
		//r2n->basename = basename(r2n->name);
		//r2n->dirname = dirname(r2n->name);
		//r2n->etype = strcmp(r2n->basename, KERNEL) == 0 ? ETYPE_KERNEL :
		//		(mod_name ? ETYPE_MODULE : ETYPE_APPLICATION);
	//}
	//free(tmp);

	i = r2i->num_r2n;
	r2i->all_r2n = realloc(r2i->all_r2n, (i + 1) * sizeof(*r2i->all_r2n));
	r2i->num_r2n += 1;
	r2i->all_r2n[i] = r2n;
	//if (found_r2n)
		return SUCCESS;
	/*
	rc = prepare_obj_file(r2n, kpatchinf, kallsyms, mod_name, r2i->uname_r,
			      imf_info);  
	if (rc == FAILURE)
		return FAILURE;
	if (rc == SKIP) {
		r2i->num_r2n--;
		free(r2n);
	}
	if (rc)
		return rc;

	if (bfd_get_file_flags(r2n->bi.abfd) & DYNAMIC)
		r2n->etype = ETYPE_LIB;
	*/
	/* When analyzing the coverage with the '--user' option, kernel's 'r2n'
	 * is created even though the address is out of range.
	 * It because we have to check the 'iret' instructions.
	 *
	 * In the case of the first libc-function call, function is not
	 * allocated on the page. So page fault occured.
	 * After allocating the function, it return by 'iret' instruction.
	 * This case's branch log is shown below.
	 *                              from		to
	 *   1. libc-function call      aaa		func
	 *   2. page fault		func		kernel's handler
	 *   3. iret			iret		func
	 *   4. execute function	...
	 *
	 *  As shown above, 'func' address traced twice, even though it was
	 *  executed once. So, we do not check 'iret to SOMEWHERE'.
	 *
	 *  Note that 'iret' from 'int X' case is different.
	 *  In this case, we have to check 'iret to NEXT_TO_INT_N'.
	 */
	/*
	if (is_kernel(r2n) &&
	    !is_addr_range_match(r2n->begin - r2n->offset,
				 r2n->end - r2n->offset, range)) {
		if (for_coverage) {
			r2n->etype = ETYPE_OUT_OF_RANGE_KERNEL;
			return SUCCESS;
		}
		free_one_r2n(r2n);
		r2i->num_r2n -= 1;
		r2i->all_r2n[i] = NULL;
	}
	return SUCCESS;
	*/
}

static int cmp_path_to_addr(struct path *p, UINT64 addr)
{
	//if (p->cnt < 0) {
		if (addr < p->addr)
			return -1;
		if (addr >= (p->addr + p->length))
			return 1;
	//} else {
	//	if (addr < p->addr)
	//		return -1;
	//	if (addr >= p->next)
	//		return 1;
	//}
	return 0;
}

static int f_find_path_in_array(const void *p1, const void *p2)
{
	UINT64 addr = *((UINT64*)p1);
	struct path *p = *(struct path**)p2;

#ifdef DBG_CHK_PATH
	printf("DBG:0x%08lx:0x%08lx\n", addr, p->addr);
#endif
	return cmp_path_to_addr(p, addr);
}

struct path* find_path_in_path_array(struct path **tree, int *cnt,
				     UINT64 addr)
{
	struct path **p;

	p = (struct path**)bsearch(&addr, tree, *cnt, sizeof(*p),
				   f_find_path_in_array);
	if (p) {
		*cnt = (int)(p - tree);
		return *p;
	} else
		return NULL;
}

// 'find_path_by_a_addr' take the 'absolute address' for the argument.
inline struct path *find_path_by_a_addr(struct range_to_name *r2n, int *n,
					  UINT64 a_addr)
{
	return find_path_in_path_array(r2n->path_array, n, a_addr - r2n->offset);
}

// 'find_path_by_addr' take the 'relative address' for the argument.
inline struct path *find_path_by_addr(struct range_to_name *r2n, int *n,
					UINT64 addr)
{
	return find_path_in_path_array(r2n->path_array, n, addr);
}

/*
 * On the x86_64 architecture, Core 2 Processor's BTS facility may record
 * the wrong 'from-address' in each record.
 * This code tries to fix this bug.
 */
void fix_x86_64_core2_from(struct bt_log *log)
{
#ifndef __i386__
	if ((log->from & 0xffffffff00000000) == 0x0000ffff00000000)
		log->from |= 0xffff000000000000;
#endif
}

/*
 * return value: 'SUCCESS' when from address was fixed
 *               'FAILURE' when from address was out of range
 */
static int fix_from_addr_and_get_info(struct r2n_info *r2i,
				      UINT64 *from, UINT64 to,
				      struct range_to_name **__r2n,
				      struct path **__p, int *__id)
{
	struct range_to_name *r2n;
	struct path *p = NULL;
	UINT64 tmp;
	int i;

	/* The from address that logged by the Pentium-M's BTS facility isn't
	 * same as Pentium-4 or Xeon's.
	 * Pentium-M logged next instruction's address as from address.
	 * But note that in interrupt branch record, Pentium-M logged current
	 * instruction's address as from address.
	 */
	/* When 'INT' instruction was executed, then, from-address is point to
	 * the next instruction (both of the Pentium4 and PentiumM).
	 *
	 * Ex:
	 *   0x0805e1e1 int 0x80
	 *   0x0805e1e3 (next instruction)
	 */
	tmp = *from - 1;
	r2n = addr_to_r2n(r2i, tmp);
	if (r2n) {
		i = r2n->num_path_array;
		p = find_path_by_a_addr(r2n, &i, tmp);
		if (p && p->type == BTYPE_INT &&
		    p->next + r2n->offset == *from) {
			*from = p->base + r2n->offset;
			goto MYFIXED;
		}
	}
	if (!r2i->from_is_next) {
		r2n = NULL;
		p = NULL;
		goto MYFIXED;
	}
	if (!r2n || !p)
		return FAILURE;

	/* check from address is next instruction address or not */
	switch (p->type) {
	case BTYPE_BRANCH:
	case BTYPE_JMP:
	case BTYPE_CALL:
		if (p->next + r2n->offset == *from &&
		    (p->jmp_to.addr == UNKNOWN_BADDR ||
		     get_jmp_a_addr(p->jmp_to) == to)) {
			*from = p->base + r2n->offset;
			goto MYFIXED;
		}
		break;
	case BTYPE_RET:
	case BTYPE_IRET:
		if (p->next + r2n->offset == *from) {
			*from = p->base + r2n->offset;
			goto MYFIXED;
		}
		break;
	}

	/* Case of interrupt (not by 'int' instruction) branch record.
	 * There is no need to change the from address.
	 */
	if (*from < r2n->begin || *from > r2n->end) {
		r2n = NULL;
		p = NULL;
	} else if (*from < (p->addr + r2n->offset) ||
		   *from >= (p->next + r2n->offset)) {
		if (i < r2n->num_path_array - 1) {
			p = r2n->path_array[++i];
			if (*from < (p->addr + r2n->offset) ||
			    *from >= (p->next + r2n->offset))
				p = NULL;
		} else
			p = NULL;
	}
MYFIXED:
	if ((__r2n || __p || __id) && !r2n) {
		r2n = addr_to_r2n(r2i, *from);
		if (!r2n)
			return FAILURE;
	}
	if (__r2n)
		*__r2n = r2n;
	if ((__p || __id) && !p) {
		i = r2n->num_path_array;
		p = find_path_by_a_addr(r2n, &i, *from);
		if (!p) {
			//fprintf(stderr, "path not found(0x%08lx:%s).\n",
			//	*from, r2n->basename);
			return FAILURE;
		}
	}
	if (__p)
		*__p = p;
	if (__id)
		*__id = i;
	return SUCCESS;
}

/*
 * return value: 'SUCCESS' when from address was fixed
 *               'FAILURE' when from address was out of range
 */
int chk_fix_from_cache(struct r2n_info *r2i,
		       UINT64 *from, UINT64 to,
		       struct range_to_name **__r2n, struct path **__path,
		       int *__id)
{
	int i, rc;
	struct fix_from_cache *p, *p_prev;
	struct range_to_name *r2n;

	r2n = addr_to_r2n(r2i, *from);
	if (!r2n) {
		if (!r2i->from_is_next)
			return FAILURE;
		r2n = addr_to_r2n(r2i, *from - 1);
		if (!r2n)
			return FAILURE;
	}
	for (i = 0, p_prev = NULL, p = r2n->fix_from_cache; p;
	     i++, p_prev = p, p = p->next) {
		if (p->from == *from && p->to == to) {
			if (p_prev) {
				p_prev->next = p->next;
				p->next = r2n->fix_from_cache;
				r2n->fix_from_cache = p;
			}
			/* else case means found element is already cache top.*/
			*from = p->fixed_from;
			if (__r2n)
				*__r2n = p->r2n;
			if (__path)
				*__path = p->path;
			if (__id)
				*__id = p->id;
			//printf("CACHE HIT\n");
			return SUCCESS;
		}
	}
	//printf("CACHE MISS\n");
	if (i >= MAX_FIX_FROM_CACHE) {
		/* free last element */
		for (p = r2n->fix_from_cache; p && p->next && p->next->next;
		     p = p->next);
		free(p->next);
		p->next = NULL;
	}
	/* add new element */
	p = malloc(sizeof(*p));
	p->from = *from;
	p->to = to;
	rc = fix_from_addr_and_get_info(r2i, from, to, __r2n, __path, __id);
	if (rc == FAILURE) {
		free(p);
		return rc;
	}
	p->fixed_from = *from;
	p->r2n = __r2n ? *__r2n : NULL;
	p->path = __path ? *__path : NULL;
	p->id = __id ? *__id : -1;
	p->next = r2n->fix_from_cache;
	r2n->fix_from_cache = p;
	return SUCCESS;
}

/*----------------------------------------------------------------------------*/
/*  parse address range support functions                                     */
/*----------------------------------------------------------------------------*/
void alloc_pid_range(pid_t pid)
{
	struct pid_range **p, *p_prev;

	p = &ranges;
	p_prev = *p;
	while (*p) {
		if ((*p)->pid == pid)
			return;
		p_prev = *p;
		p = &(*p)->next;
	}
	*p = malloc(sizeof(**p));
	(*p)->pid = pid;
	(*p)->range = NULL;
	(*p)->next = NULL;
	if (p_prev)
		p_prev->next = *p;
	return;
}

static struct pid_range* get_pid_range(pid_t pid)
{
	struct pid_range *p;

	p = ranges;
	while (p) {
		if (p->pid == pid)
			return p;
		p = p->next;
	}
	return p;
}

static void free_one_range(struct addr_range **p_ar)
{
	struct addr_range *p_tmp;

	if (!*p_ar)
		return;
	p_tmp = (*p_ar)->next;
	free(*p_ar);
	*p_ar = p_tmp;
}

static char *elf_path_prefix = "";

void set_elf_path_prefix(char *prefix)
{
	elf_path_prefix = prefix; //realpath(, NULL)
	if (!elf_path_prefix) {
		//fprintf(stderr, "\"%s\" realpath failed(%s).\n",
		//	prefix, strerror(errno));
		elf_path_prefix = "";
	}
}

char* get_elf_path_prefix(void)
{
	return elf_path_prefix;
}

void free_ranges(void)
{
	struct pid_range *p, *p_next;

	if (strlen(elf_path_prefix)) {
		free(elf_path_prefix);
		elf_path_prefix = "";
	}
	p = ranges;
	while (p) {
		while (p->range)
			free_one_range(&p->range);
		p_next = p->next;
		free(p);
		p = p_next;
	}
	ranges = NULL;
}

char* range2ulongs(char *p, unsigned long *begin, unsigned long *end)
{
	char *p_end;

	*begin = strtoul(p, &p_end, 0);
	if (*p_end != ':') {
		eprintf("begin address invalid(%s)\n", p);
		return NULL;
	}
	*end = strtoul(p_end + 1, &p_end, 0);
	if (*p_end != '\0' && *p_end != '\n' && *p_end != ' ') {
		eprintf("end address invalid(%s)\n", p);
		return NULL;
	}
	if (*begin >= *end) {
		eprintf("begin address greater or equal end address(%s)\n", p);
		return NULL;
	}
	return p_end;
}

static bool_t is_overlap(unsigned long b1, unsigned long e1,
			 unsigned long b2, unsigned long e2, bool_t continue_ok)
{
	unsigned long long len1, len2;

	len1 = e1 - b1;
	len2 = e2 - b2;

	if (continue_ok) {
		len1++;
		len2++;
	}
	if (b2 == b1 ||
	    (b2 > b1 && b2 - b1 <= len1) ||
	    (b2 < b1 && b1 - b2 <= len2))
		return TRUE;
	return FALSE;
}

int add_range(pid_t pid, unsigned long begin, unsigned long end)
{
	struct pid_range *p;
	struct addr_range **pp_ar, *p_ar, *p_tmp;

	ddprintf("------ ADD RANGE (0x%08lx, 0x%08lx) ------\n", begin, end);
	if (!(p = get_pid_range(pid))) {
		// error print
		return FAILURE;
	}
	/* detect overlapped range */
	pp_ar = &p->range;
	while ((p_ar = *pp_ar)) {
		ddprintf("CHECK\n");
		/* overlapped ? */
		if (is_overlap(p_ar->begin, p_ar->end, begin, end, TRUE)) {
			ddprintf("OVERLAP DETECT\n");
			/* expand the range */
			if (begin < p_ar->begin)
				p_ar->begin = begin;
			if (end > p_ar->end) {
				p_ar->end = end;
				/* check upper ranges */
				p_tmp = p_ar->next;
				while (p_tmp) {
					if (p_tmp->begin <= p_ar->end ||
					    (p_tmp->begin > p_ar->end &&
					     p_tmp->begin - 1 == p_ar->end)){
						if (p_tmp->end > p_ar->end)
							p_ar->end = p_tmp->end;
						free_one_range(&p_ar->next);
						p_tmp = p_ar->next;
					} else {
						break;
					}
				}
			}
			return SUCCESS;
		}
		if (p_ar->begin > end) {
			ddprintf("BREAK\n");
			break;
		}
		pp_ar = &p_ar->next;
	}
	/* not overlapped */
	p_tmp = malloc(sizeof(*p_tmp));
	p_tmp->begin = begin;
	p_tmp->end = end;
	if (p->range) {
		p_tmp->next = *pp_ar;
		*pp_ar = p_tmp;
	} else {
		p_tmp->next = NULL;
		p->range = p_tmp;
	}
	return SUCCESS;
}

int del_range(pid_t pid, unsigned long begin, unsigned long end)
{
	struct pid_range *p;
	struct addr_range **pp_ar, *p_ar, *p_tmp;

	ddprintf("------ DEL RANGE (0x%08lx, 0x%08lx) ------\n", begin, end);
	if (!(p = get_pid_range(pid))) {
		return FAILURE;
	}
	/* detect overlapped range */
	pp_ar = &p->range;
	while ((p_ar = *pp_ar)) {
		ddprintf("CHECK\n");
		/* overlapped ? */
		if (is_overlap(p_ar->begin, p_ar->end, begin, end, FALSE)) {
			ddprintf("OVERLAP DETECT\n");
			if (p_ar->begin >= begin && p_ar->end <= end) {
				/* delete range include existance range */
				free_one_range(pp_ar);
			} else if (p_ar->begin < begin && p_ar->end > end){
				/* existence range include delete range */
				p_tmp = malloc(sizeof(*p_tmp));
				p_tmp->begin = end + 1;
				p_tmp->end = p_ar->end;
				p_ar->end = begin - 1;
				p_tmp->next = p_ar->next;
				p_ar->next = p_tmp;
				pp_ar = &p_ar->next;
			} else if (p_ar->begin < begin) {
				/* existence range overlapped (upper part) */
				p_ar->end = begin - 1;
				pp_ar = &p_ar->next;
			} else {
				/* existence range overlapped (lower part) */
				p_ar->begin = end + 1;
				pp_ar = &p_ar->next;
			}
		}
		if (p_ar->begin > end) {
			ddprintf("BREAK\n");
			break;
		}
		pp_ar = &p_ar->next;
	}
	return SUCCESS;
}

void dump_ranges(void)
{
	struct pid_range *p;
	struct addr_range *p_ar;

	p = ranges;
	while (p) {
		printf("------ pid: %lld ------\n", p->pid);
		p_ar = p->range;
		while (p_ar) {
			printf("0x%08lx:0x%08lx\n", p_ar->begin, p_ar->end);
			p_ar = p_ar->next;
		}
		p = p->next;
	}
}

struct pid_range *get_all_ranges(void)
{
	return ranges;
}

struct addr_range *get_pid_addr_range(pid_t pid)
{
	struct pid_range *p;

	p = ranges;
	while (p) {
		if (p->pid == pid)
			return p->range;
		p = p->next;
	}
	return NULL;
}

/* for speed up, this routine should be convert to the macro... */
bool_t is_addr_range_match(unsigned long from, unsigned long to,
			   struct addr_range *r)
{
	while (r) {
		if ((from >= r->begin && from <= r->end) ||
		    (to >= r->begin && to <= r->end))
			return TRUE;
		r = r->next;
	}
	return FALSE;
}

static int find_under_path(char *dirname, int max_len, const char *name,
			   bool_t down)
{
	return FAILURE;
	/*
	DIR *dir;
	struct dirent *d;
	int dlen, rc;
	struct stat stat;

	rc = FAILURE;
	if (!(dir = opendir(dirname)))
		return FAILURE;
	while ((d = readdir(dir)) != NULL) {
		if (strcmp(".", d->d_name) == 0 || strcmp("..", d->d_name) == 0)
			continue;
		dlen = strlen(dirname);
		if (strcmp(name, d->d_name) == 0) {
			_snprintf(dirname + dlen, max_len - dlen,
				 "/%s", d->d_name);
			rc = SUCCESS;
			goto EXIT;
		}
		if (!down)
			continue;
		_snprintf(dirname + dlen, max_len - dlen, "/%s", d->d_name);
		if (_stat(dirname, &stat) < 0)
			goto EXIT;
		if (S_ISDIR(stat.st_mode)
		    && find_under_path(dirname, max_len, name, down) ==SUCCESS){
				rc = SUCCESS;
				goto EXIT;
		}
		dirname[dlen] = '\0';
	}
EXIT:
	closedir(dir);
	return rc;
	*/
}

static int get_module_full_path(char *buf, int buf_len, const char *name,
				char *uname_r)
{
	int len;

	len = _snprintf_s(buf, buf_len, buf_len - 1, "%s/lib/modules/%s",
		       elf_path_prefix, uname_r);
	if (len >= buf_len) {
		//fprintf(stderr, "!!! too short buf size(%d)\n", buf_len);
		return FAILURE;
	}
	return find_under_path(buf, buf_len, name, TRUE);
}

static int __get_vmlinux_full_path(char *buf, int buf_len)
{
	int rc;

	rc = find_under_path(buf, buf_len, KERNEL, FALSE);
	if (rc == SUCCESS)
		return rc;
	return find_under_path(buf, buf_len, KERNEL, TRUE);
}

static int get_vmlinux_full_path(char *buf, int buf_len, char *uname_r)
{
	_snprintf_s(buf, buf_len, buf_len - 1, "%s/usr/lib/debug/lib/modules/%s",
		 elf_path_prefix, uname_r);
	if (__get_vmlinux_full_path(buf, buf_len) == SUCCESS)
		return SUCCESS;
	_snprintf_s(buf, buf_len, buf_len - 1, "%s/lib/modules/%s/build",
		 elf_path_prefix, uname_r);
	if (__get_vmlinux_full_path(buf, buf_len) == SUCCESS)
		return SUCCESS;
	return FAILURE;
}

static bool_t change_module_name(char *name)
{
	bool_t changed;
	char *p;

	changed = FALSE;
	for (p = name; p && *p; p++) {
		switch (*p) {
		case '-':
		case '_':
			changed = TRUE;
			if (*p == '-')
				*p = '_';
			else
				*p = '-';
		}
	}
	return changed;
}

#define MAX_IRQS	256
static UINT64 irq_addrs[MAX_IRQS + 1];
static int irq_addrs_cnt;

static int cmp_address(const void *p_a1, const void *p_a2)
{
	UINT64 a1 = *(UINT64*)p_a1;
	UINT64 a2 = *(UINT64*)p_a2;

	if (a1 < a2)
		return -1;
	if (a1 > a2)
		return 1;
	return 0;
}

/* return address count */
static int get_uniq_and_sorted_irq_addrs(char *dir, unsigned long addrs[])
{
	int i, j, rc;
	bool_t already_checked;
	char buf[PATH_MAX];
	FILE *f;
	unsigned long a;
	errno_t err;

	if (!dir)
		return 0;
	rc = FAILURE;
	_snprintf_s(buf, PATH_MAX, PATH_MAX - 1, "%s/irq_addrs", dir);
	//if ((f = fopen(buf, "r")) == NULL) {
	err = fopen_s(&f, buf, "r");
	if (err) {
		//fprintf(stderr, "fopen \"%s\" failed.(%s)\n",
		//	buf, strerror(errno));
		goto EXIT;
	}
	i = 0;
	while (fgets(buf, PATH_MAX, f)) {
		if (sscanf_s(buf, "%lx\n", &a) != 1) {
			//fprintf(stderr, "!!! wrong format irq_addrs file\n");
			goto EXIT;
		}
		already_checked = FALSE;
		for (j = 0; j < i; j++)
			if (addrs[j] == a) {
				already_checked = TRUE;
				break;
			}
		if (already_checked)
			continue;
		if (i > MAX_IRQS) {
			//fprintf(stderr, "!!! wrong line-number for" \
			//	" irq_addrs file(%d)\n", i);
			goto EXIT;
		}
		addrs[i++] = a;
	}
	rc = i;
	qsort(addrs, i, sizeof(*addrs), cmp_address);
EXIT:
	if (f)
		fclose(f);
	return rc;
}

static inline int is_irq_addrs(UINT64 a, UINT64 addrs[], int n)
{
	return bsearch(&a, addrs, n, sizeof(*addrs), cmp_address) != NULL;
}
#define IS_IRQ(a)	is_irq_addrs((a), irq_addrs, irq_addrs_cnt)

int parse_modules(struct r2n_info *r2i, char *dir, bool_t for_coverage,
		  bool_t verbose)
{
	MODULE_DESC **pModuleList;
	int i, nNumModules;

	nNumModules = PdbGetAllModules(&pModuleList);
	r2i->all_r2n = realloc(r2i->all_r2n, nNumModules * sizeof(*r2i->all_r2n));
	for (i = 0; i < nNumModules; i++)
	{
		add_range_to_name(r2i, pModuleList[i]->BaseAddr, pModuleList[i]->BaseAddr + pModuleList[i]->Size, 
				      pModuleList[i]->ModuleFullName, NULL, NULL, NULL, FALSE, (struct imf_bi_info *)pModuleList[i]);
	}
	return SUCCESS;
/*
	FILE *fd = NULL;
	int rc, num, len;
	char path[PATH_MAX], kallsyms[PATH_MAX], kpatchinf[PATH_MAX], *kpinf;
	char buf[MAX_LINE_LEN + 1], *p, fullname[MAX_LINE_LEN + 1], *mod_name;
	struct addr_range *range;
	unsigned long from, to;

	rc = FAILURE;
	if (dir) {
		if ((irq_addrs_cnt =
		     get_uniq_and_sorted_irq_addrs(dir, irq_addrs)) == FAILURE)
			goto EXIT;
		_snprintf(kpatchinf, sizeof(kpatchinf), "%s/kpatchinf", dir);
		kpinf = kpatchinf;
	} else {
		dir = "/proc";
		kpinf = NULL;
	}
	_snprintf(kallsyms, sizeof(kallsyms), "%s/kallsyms", dir);
	_snprintf(path, sizeof(path), "%s/modules", dir);

	if ((fd = fopen(path, "r")) == NULL) {
		fprintf(stderr, "can't open %s.(%s)\n", path, strerror(errno));
		goto EXIT;
	}
	buf[MAX_LINE_LEN] = fullname[MAX_LINE_LEN] = '\0';
	range = get_pid_addr_range(ALL_PID);
	while ((p = fgets(buf, MAX_LINE_LEN, fd)) != NULL) {
		len = strlen(p) - 1;
		buf[len] = '\0';
		num = sscanf(buf, "%s %ld %*d %*s %*s %lx",
			     fullname, &to, &from);
		if (num != 3) {
			fprintf(stderr, "modules format error(%d)\n", num);
			goto EXIT;
		}
		to = from + to - 1;
		if (!is_addr_range_match(from, to, range))
			continue;
		_snprintf(buf, MAX_LINE_LEN, "%s" MOD_EXT, fullname);
		mod_name = strdup(buf);
		fullname[0] = '\0';
		if (get_module_full_path(fullname, MAX_LINE_LEN, buf,
					 r2i->uname_r) == FAILURE &&
		    (!change_module_name(buf) ||
		     get_module_full_path(fullname, MAX_LINE_LEN, buf,
					  r2i->uname_r) == FAILURE)) {
			if (verbose)
				printf("WARN: %s not found.\n", buf);
			free(mod_name);
			continue;
		}
		if (add_range_to_name(r2i, from, to, fullname, kpinf, kallsyms,
				      mod_name, for_coverage, NULL)
		    == FAILURE){
			free(mod_name);
			goto EXIT;
		}
		free(mod_name);
	}
	fullname[0] = '\0';
	if (get_vmlinux_full_path(fullname, MAX_LINE_LEN, r2i->uname_r)
	    == FAILURE) {
		if (verbose)
			printf("WARN: vmlinux not found.\n");
	} else {
		if (add_range_to_name(r2i, 0, 0, fullname, kpinf, kallsyms,
				      NULL, for_coverage, NULL) == FAILURE)
			goto EXIT;
	}
	rc = SUCCESS;
EXIT:
	if (fd)
		fclose(fd);
	return rc;
*/
}

/* This function returns the number that a function name was found in.
 * In the 'addr' variable, an address of a function found first is set.
 */
int get_symbol_dest(struct r2n_info *r2i,
		    const char *funcsym, struct jmp_to *dest)
{
	int i, found, tmp;
	struct range_to_name *r2n;
	//unsigned long addr;

	for (found = 0, i = 0; i < r2i->num_r2n; i++) {
		r2n = r2i->all_r2n[i];
		tmp = 0; //get_addr_of_symbol(&r2n->bi, funcsym, &addr);
		if (!found && tmp) {
			dest->r2n = r2n;
			//dest->addr = addr;
		}
		found += tmp;
	}
	return found;
}

int get_symbol_dest_all(struct r2n_info *r2i, const char *funcsym,
			struct jmp_to **__dests)
{
	int i, j, rc, cnt;
	struct range_to_name *r2n;
	struct jmp_to *dests = NULL;
	unsigned long *c_addrs = NULL;

	cnt = 0;
	for (i = 0; i < r2i->num_r2n; i++) {
		r2n = r2i->all_r2n[i];
		rc = 0 ; //get_addr_of_symbol_all(&r2n->bi, funcsym, &c_addrs);
		if (rc == 0)
			continue;
		dests = realloc(dests, (cnt + rc) * sizeof(*dests));
		for (j = 0; j < rc; j++) {
			dests[cnt + j].r2n = r2n;
			dests[cnt + j].addr = c_addrs[j];
		}
		cnt += rc;
		free(c_addrs);
	}
	if (cnt)
		*__dests = dests;
	return cnt;
}

const char* get_fname(struct jmp_to *fdest)
{
	//struct range_to_name *r2n = fdest->r2n;
	//const char *fname;
	//size_t offset;

	//if (!r2n || addr_to_func_name_and_offset(&r2n->bi, fdest->addr, &fname,
	//					 &offset) == FAILURE)
		return NULL;
	//return fname;
}

const char* get_fname_and_offset(struct jmp_to *fdest, unsigned long *offset)
{
	struct range_to_name *r2n = fdest->r2n;
	//const char *fname;

	//if (!r2n || addr_to_func_name_and_offset(&r2n->bi, fdest->addr, &fname,
	//					 (size_t*)offset) == FAILURE) {
		*offset = 0;
		return NULL;
	//}
	//return fname;
}

#if 0
static bool_t get_func_begin(struct range_to_name *r2n, unsigned long addr,
			     unsigned long *p_begin)
{
	unsigned long begin;

	if (r2n) {
		if (get_begin_of_func(&r2n->bi, addr - r2n->offset, &begin)) {
			*p_begin = begin + r2n->offset;
			return TRUE;
		}
	}
	return FALSE;
}
#endif

// 'begin' and 'end' are relative addresses
static bool_t get_func_end(struct range_to_name *r2n, UINT64 begin,
			   UINT64 *p_end)
{
	/*
	unsigned long end;

	if (r2n) {
		end = r2n->end - r2n->offset;
		if (get_end_of_func(&r2n->bi, begin, &end)) {
			*p_end = end;
			return TRUE;
		}
	}
	*/
	return FALSE;
}

// 'end' is the next function's begin address (relative address)
bool_t get_func_info(struct jmp_to *func, UINT64 *p_end)
{
	return get_func_end(func->r2n, func->addr, p_end);
}

bool_t get_maps_fpath(char *dir_path, char fpath[PATH_MAX])
{
	return TRUE;
	/*
	DIR *dir;
	struct dirent* d;
	int len, rc = FALSE;

	if ((dir = opendir(dir_path)) == NULL) {
		fprintf(stderr, "can't open %s\n", dir_path);
		return rc;
	}
	while ((d = readdir(dir)) != NULL) {
		if (strcmp(".", d->d_name) == 0 || strcmp("..", d->d_name) == 0)
			continue;
		len = strlen(d->d_name);
		if (len > MAPS_EXT_LEN
		    && strcmp(MAPS_EXT, &d->d_name[len - MAPS_EXT_LEN]) == 0) {
			snprintf(fpath, PATH_MAX, "%s/%s", dir_path, d->d_name);
			rc = TRUE;
			break;
		}
	}
	closedir(dir);
	return rc;
	*/
}

#define MODE_COLS	5
int parse_maps(struct r2n_info *r2i, char *maps_fpath, bool_t verbose)
{
	FILE *fd;
	int rc, num, len;
	char mode[MODE_COLS + 1], buf[MAX_LINE_LEN + 1];
	char *p, fullname[MAX_LINE_LEN + 1];
	struct addr_range *range;
	unsigned long from, to;
	long size;
	errno_t err;

	rc = FAILURE;
	//if ((fd = fopen(maps_fpath, "r")) == NULL) {
	err = fopen_s(&fd, maps_fpath, "r");
	if (err) {
		//fprintf(stderr, "can't open %s.(%s)\n",
		//	maps_fpath, strerror(errno));
		goto EXIT;
	}
	buf[MAX_LINE_LEN] = fullname[MAX_LINE_LEN] = '\0';
	range = get_pid_addr_range(ALL_PID);
	while ((p = fgets(buf, MAX_LINE_LEN, fd)) != NULL) {
		len = (int)(strlen(p) - 1);
		buf[len] = '\0';
		num = sscanf_s(buf, "%lx-%lx %s %*s %*x %*s %ld",
			     &from, &to, mode, &size); //?
		if (num != 4) {
			//fprintf(stderr, "map format error(%d)\n", num);
			goto EXIT;
		}
		if (size == 0 || mode[2] != 'x')  // Ex: mode="r-xp"
			continue;
		for (; *p != '/' && *p != '\0'; p++);
		if (*p != '/' || buf[len-1] == ')')
			continue;	// e.g. /SYSV00000000 (deleted)
		to -= 1;
		if (!is_addr_range_match(from, to, range))
			continue;
		_snprintf_s(fullname, MAX_LINE_LEN, MAX_LINE_LEN - 1, "%s%s", elf_path_prefix, p);
		if (add_range_to_name(r2i, from, to, fullname, NULL, NULL, NULL,
				      FALSE, NULL) == FAILURE)
			goto EXIT;
	}
	rc = SUCCESS;
EXIT:
	if (fd)
		fclose(fd);
	return rc;
}

static int hook_maps_in_log(struct map_info *info, void *data)
{
	struct addr_range *range;
	struct r2n_info *r2i = data;

	range = get_pid_addr_range(ALL_PID);
	if (is_addr_range_match(info->vm_start, info->vm_end, range)) {
		struct range_to_name *r2n;
		r2n = get_same_name_r2n(r2i, info->epath);
		if (r2n)
			return SUCCESS;
		if (add_range_to_name(r2i, info->vm_start, info->vm_end,
				      info->epath, NULL, NULL, NULL, FALSE,NULL)
		    == FAILURE)
			return FAILURE;
	}
	return SUCCESS;
}

static struct map_info map_info;

int chk_maps_in_log(struct r2n_info *r2i, union bt_record *__rec)
{
	return do_maps_in_log(__rec, elf_path_prefix, &map_info,
			      hook_maps_in_log, r2i);
}

static void get_relocated_baddr(struct r2n_info *r2i, struct range_to_name *r2n,
				UINT64 branch, UINT64 base,
				struct jmp_to *jmp_to)
{
	/*
	asymbol *sym;
	struct bfd_if *bi = &r2n->bi;
	unsigned long offset, addend, sym_addr;

	// set default r2n ('branch' address of the self 'ELF')
	jmp_to->r2n = r2n;
	jmp_to->addr = branch;

	if (!bi->p_relocs)
		return;
	offset = base + 1;	// Always 1byte instruction ('jmp' or 'call')
	sym = get_symbol(bi, offset, &addend);
	if (!sym)
		return;

	sym_addr = (unsigned long)bfd_asymbol_value(sym);
	if (sym->flags & BSF_FUNCTION) {
		/* symbol defined same section of this module *
		jmp_to->addr = sym_addr + branch - offset + addend;
	} else if (sym->flags & BSF_SECTION_SYM) {
		/* symbol defined other section of this module *
		jmp_to->addr = sym_addr + branch - offset + addend
					+ (unsigned long)sym->section->vma;
	} else {
		/* symbol defined outside the module
		 *   note that 'branch' is the absolute address in this case
		 *
		r2n = addr_to_r2n(r2i, sym_addr);
		jmp_to->r2n = r2n;
		jmp_to->addr = sym_addr - get_r2n_offset(r2n);
	}
	*/
}

static void resolve_jmp_to(struct r2n_info *r2i, struct range_to_name *r2n)
{
	long i;
	struct path *p;

	for_each_path(r2n, i, p) {
		if (p->type == BTYPE_OTHER)
			continue;
		if (p->jmp_to.addr != UNKNOWN_BADDR) {
			if (p->type == BTYPE_BRANCH) {
				p->jmp_to.r2n = r2n;
				continue;
			}
			if (p->type != BTYPE_CALL && p->type != BTYPE_JMP)
				continue;
			get_relocated_baddr(r2i, r2n, p->jmp_to.addr, p->base,
					    &p->jmp_to);
		}
	}
}

/*-----------------------------------------------------------------------------
 *  path check
 *-----------------------------------------------------------------------------
 */
typedef struct {
	struct bfd_if		*bi;
	node			*pt;
	node			*node_addrs;
	bool_t			skip_ud2_srcinfo;
} pack_bi_pt;

static int f_find_path_in_tree(void *data, void *elem)
{
	unsigned long addr = *((unsigned long*)data);
	struct path *p = elem;

	return cmp_path_to_addr(p, addr);
}

static struct path* find_path_in_path_tree(node *tree, unsigned long addr)
{
	return (struct path*)search_tree(&addr, tree, f_find_path_in_tree);
}

static int f_chk_addr(void *data, void *elem)
{
	unsigned long a1 = *((unsigned long*)data);
	unsigned long a2 = *((unsigned long*)elem);

	if (a1 < a2)
		return -1;
	if (a1 > a2)
		return 1;
	return 0;
}

static int add_node_addrs(struct bfd_if *bi, node *pt, node **node_addrs,
			  unsigned long addr)
{
	unsigned long *p;

	if (addr == UNKNOWN_BADDR || find_path_in_path_tree(pt, addr)
	    || search_tree(&addr, *node_addrs, f_chk_addr))
		return SUCCESS;

#ifdef DBG_CHK_PATH
	printf("ADD:0x%08lx\n", addr);
#endif
	p = malloc(sizeof(*p));
	*p = addr;
	*node_addrs = insert_tree(p, *node_addrs, f_chk_addr, free);
	return *node_addrs == NULL ? FAILURE : SUCCESS;
}

static int
add_node_addrs_wrapper(struct bfd_if *bi, unsigned long addr, void *data)
{
	return add_node_addrs(bi, NULL, data, addr);
}

static int
for_each_func_and_section_start(struct bfd_if *bi,
				int (*func)(struct bfd_if*,unsigned long,void*),
				void *data)
{
	/*
	int i;
	asymbol *sym;
	asection *s;
	struct arg_do_for_debuginfo_func arg = { func, bi, data, 0 };

	// functions information from symbols and debug-info are different.
	// for example, kernel's "__attribute__((weak)) idle_regs" function
	// is not included in symbol information.
	// So, we check both of these information.
	do_for_all_debuginfo_funcs(bi, &arg);

	for (i = 0; i < bi->n_fsyms; i++) {
		sym = bi->p_fsyms[i];
		if (func(bi, (unsigned long)bfd_asymbol_value(sym), data)
		    == FAILURE)
			return FAILURE;
	}
	for (i = 0; i < bi->n_code_sects; i++) {
		s = bi->p_code_sects[i].section;
		if (func(bi, (unsigned long)s->vma, data) == FAILURE)
			return FAILURE;
	}
	*/
	int i;
	
	for (i = 0; i < bi->NumOfFuncs; i++) {
		if (func(bi, (unsigned long)bi->FuncList[i].StartAddr, data)
			== FAILURE)
			return FAILURE;
	}
	
	return ALL_DONE;
}

static int add_func_and_section_start_addrs(struct bfd_if *bi,
					    node **node_addrs)
{
	return for_each_func_and_section_start(bi, add_node_addrs_wrapper,
					       node_addrs);
}

/*
static asection* get_sect_has_addr(struct bfd_if *bi, unsigned long addr)
{
	struct code_sect *cs;

	cs = bsearch(&addr, bi->p_code_sects, bi->n_code_sects,
		     sizeof(*bi->p_code_sects), cmp_addr_to_code_sect);
	if (cs)
		return cs->section;
	return NULL;
}
*/

static int __get_branch_info(struct bfd_if *bi, UINT64 addr, int *type,
			     UINT64 *addr_next,
			     UINT64 *addr_branch)
{
	/*
	int bytes;
	struct disassemble_info *info = &bi->info;
	fprintf_ftype func_save;

	if (prepare_print_insn(bi, addr) == FAILURE)
		return FAILURE;

	seq_num = 0;
	baddr = 0;
	func_save = info->fprintf_func;
	info->fprintf_func = (fprintf_ftype)chk_btype_dummy_fprintf;
	bytes = print_insn_i386_att((bfd_vma)addr, info);
	if (bytes < 0)
		return FAILURE;

	info->fprintf_func = func_save;
	*addr_next = addr + bytes;
	*addr_branch = 0;
	switch (btype) {
	case BTYPE_JMP:
	case BTYPE_CALL:
	case BTYPE_BRANCH:
		*addr_branch = baddr;
		break;
	}
	*type = btype;
	*/
	return SUCCESS;
}
/*
static int chk_one_node_addr(struct bfd_if *bi,
			     unsigned long begin, unsigned long max,
			     node **node_addrs, node **pt,
			     bool_t skip_ud2_srcinfo)
{
	unsigned long addr, next, branch;
	int rc, type;
	struct path *p;

#ifdef DBG_CHK_PATH
	printf("CHK:0x%08lx", begin);
	printf(" max(0x%08lx)\n", max);
#endif
	for (addr = begin; addr < max; addr = next) {
		rc = __get_branch_info(bi, addr, &type, &next, &branch);
		if (rc != SUCCESS) {
			//fprintf(stderr, "__get_branch_info failed at 0x%08lx",
			//	addr);
			//fprintf(stderr, ".(%d)\n", rc);
			return FAILURE;
		}
		if (type == BTYPE_OTHER && next < max)
			continue;

		p = calloc(1, sizeof(*p));
		p->addr = begin;
		p->cnt = -1;
		p->type = type;
		p->base = addr;
		p->next = next;
		p->jmp_to.addr = branch;
		/* When switch case jump, set next_cnt value to -1. * /
		p->next_cnt = type == BTYPE_JMP ? -1 : 0;
		*pt = insert_tree(p, *pt, f_chk_addr, free);
		if (skip_ud2_srcinfo && type == BTYPE_BREAK)
			break;
		if (!is_reloc_branch(bi, addr)) {
			if ((rc = add_node_addrs(bi, *pt, node_addrs, branch))
			    == FAILURE)
				return rc;
		}
		/* When switch case jmp, we need to check the next code * /
		if ((rc = add_node_addrs(bi, *pt, node_addrs, next)) == FAILURE)
			return rc;
		break;
	}
	return CONTINUE;
}
*/
static int f_chk_each_node_addr(void *elem, void *data)
{
	unsigned long addr = *((unsigned long*)elem);
	pack_bi_pt *pack = data;
	node **node_addrs = &pack->node_addrs;
	/*
	asection *s = get_sect_has_addr(pack->bi, addr);

	if (!s)
		return CONTINUE;
	if (chk_one_node_addr(pack->bi, addr,
			      (unsigned long)s->vma + bfd_get_section_size(s),
			      node_addrs, &pack->pt, pack->skip_ud2_srcinfo)
	    == FAILURE)
		return FAILURE;
	*/
	int i;
	struct path *p;
	int lno = 0;
	size_t offset = 0;
	//const char *comp_dir, *src_name, *func_name;
	
	if (!find_path_in_path_tree(pack->pt, addr)) {
		p = calloc(1, sizeof(*p));
		p->addr = addr;
		p->cnt = -1;
		//p->type = type;
		p->base = addr;
		for (i = 0; i < pack->bi->NumOfFuncs; i++) {
			if (pack->bi->FuncList[i].StartAddr == addr) {
				p->length = (DWORD)pack->bi->FuncList[i].Length;
				p->slno = pack->bi->FuncList[i].slno;
				p->elno = pack->bi->FuncList[i].elno;
				break;
			}
		}
		
		//get_source_info(pack->bi, addr, &comp_dir, &src_name, &func_name, &p->slno, &offset, FALSE);
		//get_source_info(pack->bi, addr + p->length - 1, &comp_dir, &src_name, &func_name, &p->elno, &offset, TRUE);
		
		//p->next = next;
		//p->jmp_to.addr = branch;
		/* When switch case jump, set next_cnt value to -1. */
		//p->next_cnt = type == BTYPE_JMP ? -1 : 0;
		pack->pt = insert_tree(p, pack->pt, f_chk_addr, free);
	}
	
	return CONTINUE;
}

static void f_free_each_node_addr(void *elem)
{
	unsigned long *p = elem;

	if (p)
		free(p);
}

static int chk_node_addrs(pack_bi_pt *pack)
{
	int rc;
	node *tmp;

	if (!pack->node_addrs)
		return SUCCESS;
	tmp = pack->node_addrs;
	pack->node_addrs = NULL;
	rc = for_each_node(tmp, f_chk_each_node_addr, pack);
	if (rc == FAILURE)
		return FAILURE;
	free_tree(tmp, f_free_each_node_addr);
	return SUCCESS;
}

static int loop_chk_req_addrs(pack_bi_pt *pack)
{
	int left_cnt, prev_left, giveup_cnt;

	prev_left = 0;
	for (;;) {
		left_cnt = get_node_cnt(pack->node_addrs);
		if (!left_cnt)
			break;
#ifdef DBG_CHK_PATH
		printf(">>>>>> loop chk (%d) <<<<<<\n", left_cnt);
#endif
		if (prev_left == left_cnt)
			giveup_cnt++;
		else
			giveup_cnt = 0;
		prev_left = left_cnt;

		if (chk_node_addrs(pack) == FAILURE)
			return FAILURE;
	}
	return SUCCESS;
}

static int fix_path_base(struct bfd_if *bi, struct path *p)
{
	UINT64 addr, next, branch;
	int rc, type;

	for (addr = p->addr; addr < p->next; addr = next) {
		rc = __get_branch_info(bi, addr, &type, &next, &branch);
		if (rc != SUCCESS) {
			//fprintf(stderr, "__get_branch_info failed at 0x%08lx",
			//	addr);
			//fprintf(stderr, ".(%d)\n", rc);
			return FAILURE;
		}
		if (type == BTYPE_OTHER && next < p->next)
			continue;
		p->base = addr;
	}
	return SUCCESS;
}

static int fix_all_path(struct bfd_if *bi, struct path **parray, int cnt)
{
	int i;
	struct path *p, *p_next;
	int rc, type;
	UINT64 next, branch;

	for (i = 0; i < cnt; i++) {
		p = parray[i];
		p_next = i + 1 < cnt ? parray[i + 1] : NULL;
		if (p_next && p_next->addr < p->next) {
			p->type = BTYPE_OTHER;
			p->next = p_next->addr;
			p->base = p->jmp_to.addr = 0;
			/* p->base (=last instruction address) is always needed
			 * for colorize each source line in same state.
			 */
			if ((rc = fix_path_base(bi, p)) == FAILURE)
				return rc;
			continue;
		}
		if (p->type != BTYPE_BRANCH && p->type != BTYPE_JMP
		    && p->type != BTYPE_CALL)
			continue;
		rc = __get_branch_info(bi, p->base, &type, &next, &branch);
		if (rc != SUCCESS) {
			//fprintf(stderr, "fix_all_path failed at 0x%08lx.(%d)\n",
			//	p->base, rc);
			return FAILURE;
		}
		if (branch != 0 && branch != UNKNOWN_BADDR)
			p->jmp_to.addr = branch;
		if (p->type != BTYPE_JMP)
			p->next = next;
	}
	return SUCCESS;
}

static void validate_all_path(struct path **parray, int cnt)
{
	int i;
	struct path *p;

	for (i = 0; i < cnt; i++) {
		p = parray[i];
		p->cnt = 0;
	}
}

static int
validate_path(struct bfd_if *bi, struct path **parray, int *__cnt)
{
	validate_all_path(parray, *__cnt);
	return TRUE;
}

static long conv_id;
static int f_conv_node_tree_to_array(void *elem, void *data)
{
	struct path *p = elem;
	struct path **array = data;

	array[conv_id] = p;
	conv_id++;
	return CONTINUE;
}

static int conv_path_tree_to_array(node *pt, struct path ***pt_array, int *cnt)
{
	struct path **__pt;

	*cnt = get_node_cnt(pt);
	__pt = malloc(sizeof(*__pt) * (*cnt));
	conv_id = 0;
	for_each_node(pt, f_conv_node_tree_to_array, __pt);
	free_tree(pt, NULL);

	*pt_array = __pt;
	return SUCCESS;
}

/*
 * Build the path tree
 *   First, we check all path node addresses, and build the path tree.
 *   (At this point, base addr has the possibility of overlapping with the
 *    following path.)
 *   Second, fix the overlapping addresses.
 */
int chk_path_tree(struct bfd_if *bi, struct path ***parray, int *cnt,
		  bool_t skip_ud2_srcinfo)
{
	int rc;
	pack_bi_pt pack;

	rc = FAILURE;
	pack.bi = bi;
	pack.pt = NULL;
	pack.node_addrs = NULL;
	pack.skip_ud2_srcinfo = skip_ud2_srcinfo;

	/* 1st process */
	if (add_func_and_section_start_addrs(bi, &pack.node_addrs) == FAILURE)
		goto EXIT;
	if (loop_chk_req_addrs(&pack) == FAILURE)
		goto EXIT;
	/* 2nd process */
	if (conv_path_tree_to_array(pack.pt, parray, cnt) == FAILURE)
		goto EXIT;
	if (fix_all_path(bi, *parray, *cnt) == FAILURE)
		goto EXIT;
	if (validate_path(bi, *parray, cnt) == FAILURE)
		goto EXIT;
	rc = SUCCESS;
EXIT:
#ifdef DBG_CHK_PATH
	printf("------ after left code check ------\n");
#endif
	return rc;
}

static int create_r2n_pt(struct r2n_info *r2i, struct range_to_name *r2n,
			 void *data)
{
	char path[MAX_LINE_LEN];
	//struct stat st;
	bool_t verbose = (bool_t)(long)data;

	if (r2n->path_array)
		return CONTINUE;
	_snprintf_s(path, MAX_LINE_LEN, MAX_LINE_LEN - 1, "%s%s", r2n->dirname, r2n->basename);
	if (verbose)
		printf("checking %s...\n", path);
	//if (stat(path, &st) < 0) {
	//	fprintf(stderr, "'%s' stat failed.(%s)\n",
	//		path, strerror(errno));
	//	return FAILURE;
	//}
	//if (read_pt_from_file(r2n, path, &st, r2i->uname_r) == SUCCESS)
	//	return CONTINUE;
	//if (is_kernel(r2n)) {
	//	r2n->skip_ud2_srcinfo = kernel_has_ud2_src_info(&r2n->bi);
	//}
	if (chk_path_tree(&r2n->bi, &r2n->path_array, &r2n->num_path_array,
			  r2n->skip_ud2_srcinfo) != SUCCESS)
		return FAILURE;
	//resolve_jmp_to(r2i, r2n);
	//if (write_pt_to_file(r2n, path, &st, r2i->uname_r) == FAILURE)
	//	return FAILURE;
	return CONTINUE;
}

int create_path_trees(struct r2n_info *r2i, bool_t verbose)
{
	if (for_each_r2n(r2i, create_r2n_pt, (void*)(long)verbose) == FAILURE)
		return FAILURE;
	return SUCCESS;
}

static int f_cmp_r2n_path(const void *p1, const void *p2)
{
	struct range_to_name *r2n1, *r2n2;
	int rc;

	r2n1 = *(struct range_to_name**)p1;
	r2n2 = *(struct range_to_name**)p2;

	if ((rc = strcmp(r2n1->dirname, r2n2->dirname)) != 0)
		return rc;
	return strcmp(r2n1->basename, r2n2->basename);
}

/*
 * Obsoleted: this function is not used now.
 * On the newer kernel such as 2.6.29 on x86_64 etc., the kernel's address
 * range is crossed by module's address range.
 * By that, if we check kernel first, we can't see the module's address.
 * So, we should not sort r2n by ELF path.
 *
 * If we really need to sort all r2n, then we should sort r2n by size of the
 * address range. So, it's OK if the address range is crossed.
 */
void sort_r2n_by_elf_path(struct r2n_info *r2i)
{
	qsort(r2i->all_r2n, r2i->num_r2n, sizeof(*r2i->all_r2n),
	      f_cmp_r2n_path);
}

void save_r2n_as_unmapped(struct r2n_info *r2i)
{
	int i, n, m;
	struct range_to_name *r2n;

	n = r2i->num_r2n;
	m = r2i->num_r2n_unmapped;
	if (n == 0)
		return;

	// save r2ns as the unmapped r2ns
	r2i->all_r2n_unmapped = realloc(r2i->all_r2n_unmapped,
					 (n + m)
					   * sizeof(*r2i->all_r2n_unmapped));
	r2i->num_r2n_unmapped = n + m;
	for (i = 0; i < n; i++) {
		r2n = r2i->all_r2n[i];
		free_fix_from_cache(r2n);
		r2i->all_r2n_unmapped[m + i] = r2n;
		r2i->all_r2n[i] = NULL;
	}
	r2i->num_r2n = 0;
	return;
}

typedef int (*r2n_judge)(struct range_to_name*);

static void __save_r2n_as_unmapped(struct r2n_info *r2i, r2n_judge judge)
{
	int i, j, k, n, m;
	struct range_to_name *r2n;

	n = 0;
	for (i = 0; i < r2i->num_r2n; i++) {
		r2n = r2i->all_r2n[i];
		if (judge(r2n))
			n++;
	}
	m = r2i->num_r2n_unmapped;
	if (n == 0)
		return;

	// save r2ns as the unmapped r2ns
	r2i->all_r2n_unmapped = realloc(r2i->all_r2n_unmapped,
					 (n + m)
					   * sizeof(*r2i->all_r2n_unmapped));
	r2i->num_r2n_unmapped = n + m;

	// 'i' is source-index for the 'r2n->all_r2n'
	// 'j' is destination-index for the 'r2n->all_r2n'
	// 'k' is destination-index for the 'r2n->all_r2n_unmapped'
	k = m;
	j = -1;
	for (i = 0; i < r2i->num_r2n; i++) {
		r2n = r2i->all_r2n[i];
		if (judge(r2n)) {
			free_fix_from_cache(r2n);
			r2i->all_r2n_unmapped[k] = r2n;
			if (j < 0)
				j = i;
			k++;
		} else {
			if (j >= 0) {
				r2i->all_r2n[j] = r2i->all_r2n[i];
				j++;
			}
		}
	}
	r2i->num_r2n -= n;
	return;
}

void save_lib_and_app_as_unmapped(struct r2n_info *r2i)
{
	__save_r2n_as_unmapped(r2i, is_lib_or_app);
}

void save_oor_kernel_as_unmapped(struct r2n_info *r2i)
{
	__save_r2n_as_unmapped(r2i, is_oor_kernel);
}

static void __map_r2n(struct r2n_info *r2i, struct range_to_name *r2n)
{
	r2i->all_r2n = realloc(r2i->all_r2n,
				(r2i->num_r2n + 1) * sizeof(*r2i->all_r2n));
	r2i->all_r2n[r2i->num_r2n++] = r2n;
}

int mapping_r2n(struct map_info *info, void *data)
{
	struct r2n_info *r2i = data;
	struct range_to_name *r2n, *old_r2n;
	struct addr_range *range;
	bool_t already_mapped;

#ifdef RAW_DEBUG
	printf("RAW INFO: MAP:%08lx:%08lx:%s\n",
	       info->vm_start, info->vm_end, info->epath);
#endif
	range = get_pid_addr_range(ALL_PID);
	if (!is_addr_range_match(info->vm_start, info->vm_end, range)) {
		return SUCCESS;
	}

	if ((r2n = get_same_name_r2n(r2i, info->epath)))
		already_mapped = TRUE;
	else {
		already_mapped = FALSE;
		r2n = get_same_name_unmapped_r2n(r2i, info->epath);
	}
	if (!r2n) {
		return SUCCESS;
	}

	r2n->begin = info->vm_start;
	r2n->end = info->vm_end;
	// There is no kernel map information in log files.
	r2n->offset = 0; //get_offset_addr(&r2n->bi, r2n->begin);

	if (already_mapped) {
		return SUCCESS;
	}
	/* If the same range is already mapped, then it is the 'execve' case,
	 * such as 'bash' to 'ls'.
	 * So, old application and library's 'r2n' need to be saved as unmapped.
	 */
	if ((old_r2n = addr_to_r2n(r2i, r2n->begin)) ||
	    (old_r2n = addr_to_r2n(r2i, r2n->end))) {
		save_lib_and_app_as_unmapped(r2i);
		__map_r2n(r2i, r2n);
		return SUCCESS;
	}
	__map_r2n(r2i, r2n);
	return SUCCESS;
}

void restore_r2n_as_mapped(struct r2n_info *r2i)
{
	int n, m, i;

	n = r2i->num_r2n;
	m = r2i->num_r2n_unmapped;

	r2i->all_r2n = realloc(r2i->all_r2n, (n + m) * sizeof(*r2i->all_r2n));
	r2i->num_r2n = n + m;
	for (i = 0; i < r2i->num_r2n_unmapped; i++)
		r2i->all_r2n[n + i] = r2i->all_r2n_unmapped[i];
	r2i->num_r2n_unmapped = 0;
}

static void modify_same_basename(int n, struct range_to_name **r2ns)
{
	int i;
	struct range_to_name *r2n;

	for (i = 0; i < n; i++) {
		r2n = r2ns[i];
		//*(r2n->basename - 1) = '/'; // connect dirname and basename
		r2n->dirname = "";
		r2n->basename = ""; // r2n->name;
	}
}

void chk_and_modify_same_basename(struct r2n_info *r2i)
{
	int i, j, n;
	struct range_to_name *r2n, *tmp, **r2ns;

	for (i = 0; i < r2i->num_r2n; i++) {
		n = 1;
		r2ns = NULL;
		r2n = r2i->all_r2n[i];
		for (j = i + 1; j < r2i->num_r2n; j++) {
			tmp = r2i->all_r2n[j];
			if (r2n->begin != tmp->begin || strcmp(r2n->basename, tmp->basename) != 0 ||
			    strcmp(r2n->dirname, tmp->dirname) == 0)
				continue;
			r2ns = realloc(r2ns, (n + 1) * sizeof(*r2ns));
			if (n == 1)
				r2ns[0] = r2n;
			r2ns[n] = tmp;
			n++;
		}
		if (!r2ns)
			continue;
		//modify_same_basename(n, r2ns);
		free(r2ns);
	}
}

bool_t chk_from_is_next(char *dir)
{
	char path[PATH_MAX];
	struct stat st;

	_snprintf_s(path, PATH_MAX, PATH_MAX - 1, "%s/%s", dir, FROM_IS_NEXT_FNAME);
	return (stat(path, &st) == 0);
}

int set_uname(struct r2n_info *r2i, char *log_path)
{
	//struct utsname utsn;
	char *dir, *tmp, path[PATH_MAX], uname_str[MAX_UNAME_LEN], *p;
	FILE *f;
	errno_t err;

	if (r2i->uname_r)
		return SUCCESS;
	if (log_path) {
		tmp = _strdup(log_path);
		dir = tmp; // dirname()
		_snprintf_s(path, PATH_MAX, PATH_MAX - 1, "%s/uname", dir);
		free(tmp);
		//if ((f = fopen(path, "r"))) {
		err = fopen_s(&f, path, "r");
		if (err == 0) {
			p = fgets(uname_str, MAX_UNAME_LEN, f);
			fclose(f);
			if (p) {
				p[strlen(p) - 1] = '\0';
				r2i->uname_r = _strdup(p);
				return SUCCESS;
			}
		}
	}
	/*
	if (uname(&utsn) < 0) {
		fprintf(stderr, "uname failed.(%s)\n", strerror(errno));
		return FAILURE;
	}
	r2i->uname_r = strdup(utsn.release);
	*/
	return SUCCESS;
}

/*----------------------------------------------------------------------------
 *  check enter to and leave from context (function-call and interrupt) 
 *----------------------------------------------------------------------------
 */
#define MAX_NEST	2048

struct ret_chk {
	int			type;
	UINT64		ret_addr;
};

struct st_ret_chk {
	int		nest;
	struct ret_chk	ret_chk[MAX_NEST];
};

static struct st_ret_chk st_ret_chk;

#ifdef DEBUG
static void dump_ret_chk(struct st_ret_chk *retc, int n)
{
	int i;
	struct ret_chk *p;

	for (i = n; i < retc->nest; i++) {
		p = &retc->ret_chk[i];
		printf("%04d:0x%08lx(%d)\n", n, p->ret_addr, p->type);
	}
}
#endif

static void set_expect_ret_addr(struct st_ret_chk *retc, int type,
				UINT64 ret_addr)
{
	struct ret_chk *p;

	if (retc->nest >= MAX_NEST) {
		printf("WARN: MAX_NEST is too small.\n");
		return;
	}
	p = &retc->ret_chk[retc->nest];
	p->type = type;
	p->ret_addr = ret_addr;
	retc->nest++;
}

static void get_nest_from_ret_addr(struct st_ret_chk *retc, UINT64 addr,
				   bool_t ret_maybe_fixup)
{
	int i;
	struct ret_chk *p;

	for (i = retc->nest - 1; i >= 0; i--) {
		p = &retc->ret_chk[i];
		if (ret_maybe_fixup) {
			if (p->type == BTYPE_INT) {
				retc->nest = i;
				return;
			}
		} else {
			if (p->ret_addr == addr) {
				retc->nest = i;
				return;
			}
		}
	}
	/* If there is trace-off and trace-on, 'ret_chk' data is almost meaning
	 * less because real stack was already changed.
	 * But normally, trace-off and trace-on's both nest are the same.
	 * So, if we couldn't find the return address in 'ret_chk', then
	 * simply minus one from nest value.
	 */
	if (retc->nest)
		retc->nest--;
	return;
}

static enter_leave_t
proc_enter(struct st_ret_chk *retc, int type, struct bt_log *p,
	   UINT64 ret)
{
	switch (type) {
	case BTYPE_CALL:
	case BTYPE_INT:
	case BTYPE_BREAK:
		/*
		printf("ENTER(%d): %d, from:%08lx, to:%08lx, ret:%08lx\n",
		       retc->nest, type, p->from, p->to, ret);
		       */
		set_expect_ret_addr(retc, type, ret);
		return EL_ENTER;
	}
	return EL_NONE_BRANCH_OR_JUMP;
}

static int
proc_leave(struct st_ret_chk *retc, int type, struct bt_log *p,
	   bool_t ret_maybe_fixup)
{
	switch (type) {
	case BTYPE_CALL:
	case BTYPE_INT:
	case BTYPE_BREAK:
		/*
		printf("LEAVE(%d): %d, from:%08lx, to:%08lx\n",
		       retc->nest, type, p->from, p->to);
		       */
		get_nest_from_ret_addr(retc, p->to, ret_maybe_fixup);
		return EL_LEAVE;
	}
	return EL_NONE_BRANCH_OR_JUMP;
}

void chk_nest_initialize(void)
{
	st_ret_chk.nest = 0;
}

static inline bool_t dest_is_kernel_func(struct range_to_name *r2n,
					 struct bt_log *p)
{
	return FALSE;
	/*
	const char *fname;
	size_t offset;

	return (is_kernel(r2n) &&
		(addr_to_func_name_and_offset(&r2n->bi, p->to - r2n->offset,
					      &fname, &offset) == SUCCESS) &&
		fname && offset == 0);
	*/
}

#define CALL(type, p, r2n, p_from, elt) \
	do { \
		*(type) = BTYPE_CALL; \
		(elt) = proc_enter(&st_ret_chk, *(type), (p), \
				   (r2n)->offset + (p_from)->next); \
	} while (0)

#define RET(type, p, elt) \
	do { \
		*(type) = BTYPE_CALL; \
		(elt) = proc_leave(&st_ret_chk, *(type), (p), FALSE); \
	} while (0)

#define INT(type, p, elt) \
	do { \
		*(type) = BTYPE_INT; \
		(elt) = proc_enter(&st_ret_chk, *(type), (p), (p)->from); \
	} while (0)

#define IRET(type, p, ret_maybe_fixup, elt) \
	do { \
		*(type) = BTYPE_INT; \
		(elt) = proc_leave(&st_ret_chk, *(type), (p), \
				   (ret_maybe_fixup)); \
	} while (0)

#define JMP(type, p, elt) \
	do { \
		*(type) = BTYPE_JMP; \
		(elt) = proc_enter(&st_ret_chk, *(type), (p), UNKNOWN_BADDR); \
	} while (0)

enter_leave_t chk_enter_leave(struct r2n_info *r2i, struct bt_log *p,
			      int *inst_type, int *type, int *nest,
			      struct range_to_name **p_r2n_from,
			      struct range_to_name **p_r2n_to,
			      struct path **pp_from, int *p_idx_from)
{
	enter_leave_t elt = EL_NONE_FROM_AND_TO_OOR;
	int rc;
	bool_t ret_maybe_fixup = FALSE;
	int idx_from = -1;
	struct range_to_name *r2n = NULL, *r2n_to = NULL;
	struct path *p_from = NULL;

	*nest = st_ret_chk.nest;
	r2n_to = addr_to_r2n(r2i, p->to);
	rc = chk_fix_from_cache(r2i, &p->from, p->to, &r2n, &p_from,
				&idx_from);
	/*
	if (!is_addr_range_match(p->from, p->to, data->range))
		return EL_NONE_FROM_AND_TO_OOR;
		*/
	if (rc == FAILURE) {	/* not fixed? (out of range) */
		/* Branch from unknown-binary */
		if (!r2n_to)
			goto EXIT;
		if (is_kernel(r2n_to)) {
			*inst_type = BTYPE_OTHER;
			if (IS_IRQ(p->to))
				INT(type, p, elt);
			else
				IRET(type, p, ret_maybe_fixup, elt);
		} else {
			/* Branch from unknown-binary to user-land means
			 * iret or ret (from 'vsdo').
			 * We assume it iret because we can't identify these.
			 */
			*inst_type = BTYPE_OTHER;
			IRET(type, p, ret_maybe_fixup, elt);
		}
		goto EXIT;
	}
	*inst_type = p_from->type;
	if (p_from->base + r2n->offset != p->from)
		*inst_type = BTYPE_OTHER;

	if (!r2n_to) {
		/* Branch to unknown-binary */
		if (is_kernel(r2n))
			IRET(type, p, ret_maybe_fixup, elt);
		else {
			if (IS_IRQ(p->to))
				INT(type, p, elt);
			else
				CALL(type, p, r2n, p_from, elt);
		}
		goto EXIT;
	}

	switch (*inst_type) {
	case BTYPE_BRANCH:
	case BTYPE_JMP:
	case BTYPE_CALL:
		if ((p_from->jmp_to.addr != UNKNOWN_BADDR &&
		     get_jmp_a_addr(p_from->jmp_to) == p->to) ||
		    (p_from->jmp_to.addr == UNKNOWN_BADDR &&
		     !IS_IRQ(p->to))) {
			switch (*inst_type) {
			case BTYPE_JMP:
				if (dest_is_kernel_func(r2n_to, p))
					CALL(type, p, r2n, p_from,
					     elt);
				else
					JMP(type, p, elt);
				break;
			case BTYPE_CALL:
				CALL(type, p, r2n, p_from, elt);
				break;
			case BTYPE_BRANCH:
				elt = EL_NONE_BRANCH_OR_JUMP;	/* do nothing */
				break;
			}
		} else
			INT(type, p, elt);
		goto EXIT;
	case BTYPE_RET:
		if (IS_IRQ(p->to)) {
			INT(type, p, elt);
		} else if (!(is_kernel(r2n) || is_kernel(r2n_to)) &&
			   p_from->next + r2n->offset - p->from > 1) {
			/* 'ret n' from user-land to user-land means jump to
			 * the plt library function.
			 */
			JMP(type, p, elt);
		} else
			RET(type, p, elt);
		goto EXIT;
	case BTYPE_INT:
	case BTYPE_BREAK:
	case BTYPE_OTHER:
		INT(type, p, elt);
		goto EXIT;
	case BTYPE_IRET:
		/* If the 'fixup_exception' function executed, then iret address
		 * was changed.
		 * So, in this case, we will not check the return address.
		 */
		ret_maybe_fixup = r2n == r2n_to; /*iret from kernel to kernel?*/
		IRET(type, p, ret_maybe_fixup, elt);
		goto EXIT;
	}
	elt = EL_NONE_FROM_AND_TO_OOR;
EXIT:
	if (elt == EL_LEAVE) /* leave? */
		*nest = st_ret_chk.nest;
	if (p_r2n_from)
		*p_r2n_from = r2n;
	if (p_r2n_to)
		*p_r2n_to = r2n_to;
	if (pp_from)
		*pp_from = p_from;
	if (p_idx_from)
		*p_idx_from = idx_from;
	return elt;
}

