/*****************************************************************************/
/* The development of this program is partly supported by IPA                */
/* (Information-Technology Promotion Agency, Japan).                         */
/*****************************************************************************/

/*****************************************************************************/
/*  bt_utils.c - utilities                                                   */
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
#include <share.h>
#include <errno.h>
//#include <libiberty.h>
#include "bt_utils.h"
#include <io.h>

/*----------------------------------------------------------------------------*/
/*  utility functions                                                         */
/*----------------------------------------------------------------------------*/
int u_open(const char *path, off_t *size)
{
	int fd, rc;
	struct _stat st;
	errno_t err;

	//if ((fd = _open(path, O_RDONLY)) < 0) {
	err = _sopen_s(&fd, path, _O_RDONLY, _SH_DENYNO, _S_IREAD | _S_IWRITE);
	if (err) {
		//fprintf(stderr, "can't open %s.(%s)\n", path, strerror(errno));
		return fd;
	}
	if ((rc = _stat(path, &st)) < 0) {
		//fprintf(stderr, "%s _stat failed.(%s)\n", path,strerror(errno));
		return rc;
	}
	if (size)
		*size = st.st_size;
	return fd;
}

int u_close(int fd)
{
	int rc;

	if (fd < 0)
		return 0;
	
	rc = _close(fd);
	//if ((rc = _close(fd)) < 0)
	//	fprintf(stderr, "close failed.(%s)\n", strerror(errno));
	return rc;
}

off_t u_lseek(int fd, off_t offset, int whence)
{
	off_t rc;

	rc = _lseek(fd, offset, whence);
	//if ((rc = _lseek(fd, offset, whence)) < 0)
	//	fprintf(stderr, "lseek failed.(%s)\n", strerror(errno));
	return rc;
}

size_t u_read(int fd, void *buf, size_t count)
{
	size_t rc = 0;
	size_t tmp;

	for (tmp = count; tmp; tmp -= rc) {
		rc = _read(fd, (PBYTE)buf + (count - tmp), (UINT)tmp);
		if (rc == 0)
			break;
		if (rc < 0) {
			if (errno == EINTR) {
				rc = 0;
				continue;
			}
			//fprintf(stderr, "read failed.(%s)\n", strerror(errno));
			return rc;
		}
	}
	return count - tmp;
}

size_t u_write(int fd, const void *buf, size_t count)
{
	size_t rc = 0;
	size_t tmp;

	for (tmp = count; tmp; tmp -= rc) {
		rc = _write(fd, (PBYTE)buf + (count - tmp), (unsigned int)tmp);
		if (rc == 0)
			break;
		if (rc < 0) {
			if (errno == EINTR) {
				rc = 0;
				continue;
			}
			//fprintf(stderr, "write failed.(%s)\n", strerror(errno));
			return rc;
		}
	}
	return count - tmp;
}

char padding[4];

int read_4b_aligned_string(int fd, char *buf, int max)
{
	off_t old_pos;
	INT rc = 0, padlen;
	CHAR *p;

	if ((old_pos = u_lseek(fd, 0, SEEK_CUR)) < 0)
		return -1;
	for (p = buf; (INT)(p - buf) <= max && (rc = (INT)u_read(fd, p, 1)) == 1 &&
	     				*p != '\0'; p++);
	if (rc < 0)
		return -1;
	rc = (int)(p - buf);
	padlen = 4 - (rc % 4);
	if (u_lseek(fd, old_pos + rc + padlen, SEEK_SET) < 0)
		return -1;
	return rc + padlen;
}

int write_4b_aligned_string(int fd, char *buf)
{
	INT len, padlen;

	len = (INT)strlen(buf);
	if (u_write(fd, buf, len) < 0)
		return -1;
	padlen = 4 - (len % 4);
	if (u_write(fd, padding, padlen) < 0)
		return -1;
	return len + padlen;
}

#if 0
int u_strcmp(const char *s1, const char *s2)
{
	if (!s1 && !s2)
		return 0;
	if (!s1 && s2)
		return -1;
	if (s1 && !s2)
		return 1;
	return strcmp(s1, s2);
}

int u_strncmp(const char *s1, const char *s2, size_t n)
{
	if (!s1 && !s2)
		return 0;
	if (!s1 && s2)
		return -1;
	if (s1 && !s2)
		return 1;
	return strncmp(s1, s2, n);
}
#endif

char* conv_slash2underscore(char *s, bool_t duplicate)
{
	char *p, *tmp;

	tmp = duplicate ? _strdup(s) : s;
	if (!tmp)
		return tmp;
	for (p = tmp; *p != '\0'; p++)
		if (*p == '/')
			*p = '_';
	return tmp;
}

static off_t rec_align_size;

static int gcd(int a, int b)
{
	if (a == 0 || b == 0)
		return 0;
	while (a != b) {
		if (a > b)
			a = a - b;
		else
			b = b - a;
	}
	return a;
}

static int lcm(int a, int b)
{
	if (a == 0 || b == 0)
		return 0;
	return (a / gcd(a, b)) * b;	// lcm = a * b / gcd(a, b)
}

static off_t get_rec_align_offset(off_t offset, bool_t get_next_top)
{
	if (!rec_align_size)
		rec_align_size = lcm(4096, sizeof(union bt_record)); //getpagesize()

	offset = offset / rec_align_size * rec_align_size;
	if (get_next_top)
		offset += rec_align_size;
	return offset;
}

#ifdef MMAP_ALIGN_TEST
struct align_test_data {
	off_t	offset;
	off_t	expect1;
	off_t	expect2;
};

static int __test_get_rec_align_offset(struct align_test_data* data)
{
	off_t r;

	r = get_rec_align_offset(data->offset, FALSE);
	if (r != data->expect1)
		return FAILURE;
	r = get_rec_align_offset(data->offset, TRUE);
	if (r != data->expect2)
		return FAILURE;
	return SUCCESS;
}

static int test_get_rec_align_offset()
{
	int i;
	struct align_test_data data[] = {
		{0,	0,	12288},
		{1,	0,	12288},
		{12287,	0,	12288},
		{12288,	12288,	24576},
		{12289,	12288,	24576},
	};

	for (i = 0; i < ARRAY_SIZE(data); i++) {
		if (__test_get_rec_align_offset(&data[i]) == FAILURE)
			return FAILURE;
	}
	return SUCCESS;
}
#endif

static off_t find_mmappable_size(int fd, off_t size)
{
	//DWORD dwSysGran;      // system allocation granularity
	SYSTEM_INFO SysInfo;  // system information; used to get granularity

	// Get the system allocation granularity.
	GetSystemInfo(&SysInfo);
	size = SysInfo.dwAllocationGranularity * 0x30; // 3MB
	/*
	size_t size2;
	void *p;

#ifdef MMAP_ALIGN_TEST
	printf("TEST_RESULT:%d\n", test_get_rec_align_offset());
#endif
	for (;;) {
		size2 = size;
#ifdef MMAP_ALIGN_TEST
		if (size == size2 && size <= 12288)
#else
		if (size == size2)
#endif
			break;
		size = get_rec_align_offset((size / 2) - 1, TRUE);
	}
	for (;;) {
		p = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (p != MAP_FAILED) {
			munmap(p, size);
			break;
		}
		size = get_rec_align_offset((size / 2) - 1, TRUE);
	}
	*/
	return size;
}

/* For the mmap call, offset value is necessary to be page align.
 * Prefix 'poff_' of the local variables mean page-aligned value.
 */
int for_each_block_record(FILE *pFile, int fd, off_t i_rec_from, off_t i_rec_to,
			  t_func_each_bt_record f, void *dt)
{
	int rc, rec_size = sizeof(union bt_record);
	off_t poff_from, poff_to, mappable_size, from_diff, size;
	off_t map_size, offset, i_rec;
	BYTE *p, *p_max, *buf; //*p_map, 

	if (i_rec_from == i_rec_to)
		return ALL_DONE;
	/* First, we find the mmap-able size */
	poff_from = get_rec_align_offset(i_rec_from * rec_size, FALSE);
	poff_to = get_rec_align_offset(i_rec_to * rec_size, TRUE);
	mappable_size = find_mmappable_size(fd, poff_to - poff_from);

	from_diff = (i_rec_from * rec_size) - poff_from;
	size = (i_rec_to - i_rec_from) * rec_size;

	i_rec = i_rec_from;
	buf = malloc(mappable_size);
	for (offset = poff_from; size; offset += map_size) {
		if (from_diff + size > mappable_size)
			map_size = mappable_size;
		else
			map_size = from_diff + size;
		size -= map_size - from_diff;
		/*
		p_map = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd,offset);
		if (p_map == MAP_FAILED) {
			fprintf(stderr, "mmap failed.(%s)\n", strerror(errno));
			return FAILURE;
		}
		*/
		_read(fd, buf, map_size);
		p = buf;
		p_max = p + map_size;
		if (from_diff) {
			p += from_diff;
			from_diff = 0;
		}
		for (; p < p_max; p += rec_size, i_rec++) {
			rc = f(pFile, (union bt_record*)p, i_rec, dt);
			if (rc == FAILURE || rc == BREAK) {
				//munmap(p_map, map_size);
				if (buf)
					free(buf);
				return rc;
			}
		}
		//munmap(p_map, map_size);
	}
	if (buf)
		free(buf);
	return ALL_DONE;
}

static int
for_each_bt_record(FILE *pFile, int fd, off_t size, t_func_each_bt_record f, void *dt)
{
	return for_each_block_record(pFile, fd, 0, size / sizeof(union bt_record),
				     f, dt);
}

int proc_cpu_files(char *dir_path, proc_cpu_files_t handler, void *dt)
{
	return FAILURE;
/*
	DIR *dir;
	struct dirent* d;
	char path[PATH_MAX];
	struct stat st;
	int rc, cpu;

	if ((dir = opendir(dir_path)) == NULL) {
		fprintf(stderr, "can't open %s\n", dir_path);
		return FAILURE;
	}
	rc = ALL_DONE;
	while ((d = readdir(dir)) != NULL) {
		if (strcmp(".", d->d_name) == 0 || strcmp("..", d->d_name) == 0)
			continue;
		_snprintf(path, PATH_MAX, "%s/%s", dir_path, d->d_name);
		if (_stat(path, &st) < 0) {
			fprintf(stderr, "%s _stat failed.(%s)\n", path,
				strerror(errno));
			rc = FAILURE;
			break;
		}
		if (S_ISDIR(st.st_mode) ||
		    sscanf(d->d_name, "cpu%d", &cpu) != 1)
			continue;
		rc = handler(cpu, path, st.st_size, dt);
		if (rc != CONTINUE)
			break;
	}
	closedir(dir);
	return rc;
*/
}

static int __count_cpu_files(int cpu, char *cpu_path, size_t size, void *dt)
{
	*(int*)dt += 1;
	return CONTINUE;
}

int count_cpu_files(char *dir_path)
{
	int count = 0;

	if (proc_cpu_files(dir_path, __count_cpu_files, &count) == FAILURE)
		return FAILURE;
	return count;
}

int do_maps_in_log(union bt_record *__rec, char *elf_path_prefix,
		   struct map_info *info, hook_maps_in_log_t hook,
		   void *data)
{
	//struct bt_map *r_map;
	//struct bt_epath *r_epath;
	//int n, rc;
/*
	if (is_map_record(__rec)) {
		r_map = &__rec->map;
		if (info->left_epath_len != 0) {
			fprintf(stderr, "!!! log dropped on maps info.\n");
			return FAILURE;
		}
		info->vm_start = r_map->vm_start;
		info->vm_end = r_map->vm_end - 1;
		if (r_map->len + strlen(elf_path_prefix) > PATH_MAX) {
			fprintf(stderr, "!!! epath length is too long.(%d)\n",
				r_map->len);
			return FAILURE;
		}
		sprintf(info->epath, "%s", elf_path_prefix);
		info->left_epath_len = r_map->len;
	} else if (is_epath_record(__rec)) {
		r_epath = &__rec->epath;
		n = info->left_epath_len >= BT_EPATH_LEN ?
			BT_EPATH_LEN : info->left_epath_len;
		strncat(info->epath, r_epath->path, n);
		info->left_epath_len -= n;
		if (info->left_epath_len != 0)
			return CONTINUE;
		rc = hook(info, data);
		info->epath[0] = '\0';
		return rc;
	}
*/
	return CONTINUE;
}

/*----------------------------------------------------------------------------
 *  check the log file's split point
 *----------------------------------------------------------------------------
 */
static int nr_cpu_files;
static struct log_file_info *log_file_info;

static struct pid_log_info **pid_log_info;
static size_t pid_max = 0;

static struct map_info map_info;

static int __dump_map_in_log(struct map_info *info, void *data)
{
	printf("   %s, map:%08lx:%08lx:(%08lx):%s\n",
	       (char*)data, info->vm_start, info->vm_end,
	       info->vm_end - info->vm_start, info->epath);
	return CONTINUE;
}

static int __do_maps_in_log(FILE *f, union bt_record *rec, off_t i_rec, void *data)
{
	return do_maps_in_log(rec, "", &map_info, __dump_map_in_log, data);
}

static int __dump_pid_pos(void *elem, void *data)
{
	FILE *f = 0;
	struct __pid_info *__p = elem;
	struct log_file_info *log_info = get_log_file_info(__p);

	printf("   %s, clocks:%lld (" PF_OFFTD ":" PF_OFFTD ")\n",
	       __p->finfo->fpath, __p->clocks, __p->i_rec, __p->n_rec);
	return for_each_block_record(f, log_info->fd, __p->i_rec,
				     __p->i_rec + __p->n_rec, __do_maps_in_log,
				     __p->finfo->fpath);
}

void dump_pid_pos(void)
{
	size_t i;
	struct pid_log_info *p;

	if (!pid_log_info)
		return;
	for (i = 0; i < pid_max; i++) {
		p = pid_log_info[i];
		printf("pid:%lld (%s) ------>\n", p->pid, p->comm);
		for_each_node(p->info, __dump_pid_pos, NULL);
	}
}

void print_pid_info(void)
{
	size_t i;
	struct pid_log_info *p;

	if (!pid_log_info)
		return;
	for (i = 0; i < pid_max; i++) {
		p = pid_log_info[i];
		printf("%lld %s\n", p->pid, p->comm);
	}
}

static void __free_pid_info(void *elem)
{
	struct __pid_info *__p = elem;

	free(__p);
}

static void free_pid_info(void)
{
	size_t i;
	struct pid_log_info *p;

	if (!pid_log_info)
		return;
	for (i = 0; i < pid_max; i++) {
		p = pid_log_info[i];
		free_tree(p->info, __free_pid_info);
		free(p);
		pid_log_info[i] = NULL;
	}
	free(pid_log_info);
	pid_log_info = NULL;
	pid_max = 0;
}

static void cpu_file_close(void)
{
	int i;
	struct log_file_info *log_info;

	for (i = 0; i < nr_cpu_files; i++) {
		log_info = &log_file_info[i];
		if (log_info->fpath) {
			free(log_info->fpath);
			log_info->fpath = NULL;
		}
		if (log_info->fd) {
			_close(log_info->fd);
			log_info->fd = 0;
		}
	}
	free(log_file_info);
	log_file_info = NULL;
}

int initialize_log_info(char *files[])
{
	if (!files)
		return FAILURE;
	for (nr_cpu_files = 0; files[nr_cpu_files]; nr_cpu_files++);
	if (nr_cpu_files == 0)
		return FAILURE;
	log_file_info = malloc(nr_cpu_files * sizeof(*log_file_info));
	return SUCCESS;
}

void finalize_log_info(void)
{
	free_pid_info();
	cpu_file_close();
}

static struct pid_log_info* find_pid_info_index(pid_t pid)
{
	size_t i;
	struct pid_log_info *p;

	for (i = 0; i < pid_max; i++) {
		p = pid_log_info[i];
		if (p->pid == pid)
			return p;
	}
	/* enlarge pid_log_info area */
	pid_log_info = realloc(pid_log_info,
				(pid_max + 1) *sizeof(*pid_log_info));
	pid_max++;
	p = calloc(1, sizeof(*p));
	p->pid = pid;
	pid_log_info[i] = p;
	return p;
}

static inline int cmp_timestamp(unsigned long long *t1,
				    unsigned long long *t2)
{
	if (*t1 < *t2)
		return 1;
	else if (*t1 > *t2)
		return -1;
	return 0;
}

static int f_cmp_timestamp(void *data, void *elem)
{
	unsigned long long *t1 = &((struct __pid_info*)data)->clocks;
	unsigned long long *t2 = &((struct __pid_info*)elem)->clocks;

	return cmp_timestamp(t2, t1);
}

static struct __pid_info* add_cpu_pid_info(struct log_file_info *finfo,
					   struct bt_pid *rec, off_t i_rec)
{
	struct pid_log_info *p;
	struct __pid_info *__p;

	/* get pid-info */
	p = find_pid_info_index(rec->pid);
	if (!p)
		return NULL;

	/* setup pid-sub-info for add*/
	__p = malloc(sizeof(*__p));
	__p->finfo = finfo;
	__p->clocks = rec->clocks;
	__p->i_rec = i_rec;
	__p->n_rec = 0;

	/* add pid-sub-info */
	p->info = insert_tree(__p, p->info, f_cmp_timestamp, NULL);
	if (!p->info)
		return NULL;
	return __p;
}

static int set_pid_comm(struct bt_pid *pid_rec, char *comm)
{
	struct pid_log_info *p;
	unsigned long long clocks;
	int rc;

	p = find_pid_info_index(pid_rec->pid);
	if (!p)
		return FAILURE;
	clocks = pid_rec->clocks;
	rc = cmp_timestamp(&p->comm_clocks, &clocks);
	if (rc > 0) {
		p->comm_clocks = clocks;
		p->comm[BT_COMM_LEN] = '\0';
		memcpy(p->comm, comm, BT_COMM_LEN);
	}
	return SUCCESS;
}

/* data for chk_pid_pos_per_cpu */
struct chk_pid_args {
	bool_t is_search;
	unsigned long search_addr;
	struct log_file_info *finfo;
	struct bt_pid last_rec;
	struct __pid_info *last_info;
};

static int chk_pid_pos_per_cpu(union bt_record *p, off_t i_rec, void *dt)
{
	struct chk_pid_args *args = dt;
	struct __pid_info *__p;

	//if (is_pid_record(p)) {
		__p = args->last_info;
		if (__p)
			__p->n_rec = i_rec - __p->i_rec;
		args->last_rec = p->pid;
		args->last_info = add_cpu_pid_info(args->finfo, &p->pid, i_rec);
		if (!args->last_info)
			return FAILURE;
		return CONTINUE;
	//}
	if (is_comm_record(p) && args->last_rec.clocks) {
		if (set_pid_comm(&args->last_rec, p->comm.comm) == FAILURE)
			return FAILURE;
		return CONTINUE;
	}
	if (is_warn_record(p)) {
		printf("WARN(%s, rec:" PF_OFFTD "): bts left only: %d\n",
		       args->finfo->fpath, i_rec, p->warn.left);
		return CONTINUE;
	}
	
	if (!args->is_search)
		return CONTINUE;
	/* Don't check p->from cause Pentium-M's p->from is not correct. */
	if (!args->last_rec.clocks || p->log.to != args->search_addr)
		return CONTINUE;
	printf("%20lld " PF_OFFTD_12C " %s %6lld 0x%08lx\n",
	       (unsigned long long)args->last_rec.clocks, i_rec,
	       args->finfo->fpath, args->last_rec.pid, args->search_addr);
	return CONTINUE;
}

int chk_pid_pos(char *files[], bool_t is_search, unsigned long search_addr)
{
	char *f;
	int i, rc;
	struct _stat st;
	struct chk_pid_args args;
	struct log_file_info *log_info;
	struct __pid_info *__p;
	union bt_record rec = {0};
	errno_t err;

	if (!files)
		return FAILURE;
	args.is_search = is_search;
	args.search_addr = search_addr;

	for (i = 0; (f = files[i]); i++) {
		if (_stat(f, &st) < 0) {
			//fprintf(stderr, "%s _stat failed.(%s)\n", f,
			//	strerror(errno));
			return FAILURE;
		}
		log_info = &log_file_info[i];
		log_info->fpath = _strdup(f);
		//if ((log_info->fd = _open(f, O_RDONLY)) < 0) {
		err = _sopen_s(&log_info->fd, f, _O_RDONLY, _SH_DENYNO, _S_IREAD | _S_IWRITE);
		if (err) {
			//fprintf(stderr, "%s open failed.(%s)\n", f,
			//	strerror(errno));
			return FAILURE;
		}
		if (!st.st_size) {
			log_info->size = 0;
			continue;
		}
		log_info->size = st.st_size;
		args.finfo = log_info;
		memset(&args.last_rec, 0, sizeof(args.last_rec));
		args.last_info = NULL;
		//rc = for_each_bt_record(log_info->fd, log_info->size,
		//			chk_pid_pos_per_cpu, &args);
		rc = chk_pid_pos_per_cpu(&rec, 0, &args);
		if (rc == FAILURE)
			return FAILURE;
		__p = args.last_info;
		if (__p)
			__p->n_rec = st.st_size / sizeof(union bt_record)
								- __p->i_rec;
	}
	return SUCCESS;
}

int for_each_pid_log_info(proc_pid_log_info_t func, void *data)
{
	int rc;
	size_t i;
	struct pid_log_info *p;

	for (i = 0; i < pid_max; i++) {
		p = pid_log_info[i];
		rc = func(p, data);
		if (rc != CONTINUE)
			return rc;
	}
	return ALL_DONE;
}

inline struct log_file_info *get_log_file_info(struct __pid_info *p)
{
	if (!p)
		return NULL;
	return p->finfo;
}

void free_path(struct path *p)
{
	struct unknown *uk, *next;
	struct branch_node *execnode, *nextnode;

	if (!p)
		return;
	
	execnode = p->exec_node;
	while (execnode) {
		nextnode = execnode->next;
		free(execnode);
		execnode = nextnode;
	}
	p->num_exec_node = 0;
	
	if (p->jmp_to.addr == UNKNOWN_BADDR) {
		for (uk = (struct unknown*)p->jmp_cnt; uk; uk = next) {
			next = uk->next;
			free(uk);
		}
	}
	free(p);
}
