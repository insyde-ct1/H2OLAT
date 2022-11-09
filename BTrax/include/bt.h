/*****************************************************************************/
/* The development of this program is partly supported by IPA                */
/* (Information-Technology Promotion Agency, Japan).                         */
/*****************************************************************************/

/*****************************************************************************/
/*  bt.h - branch tracer for linux common header                             */
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

#ifndef __BT_H__
#define __BT_H__

#ifdef __KERNEL__
#  include <linux/version.h>
#  include <linux/sched.h>
#  include <linux/file.h>
#  include <linux/proc_fs.h>
#  include <linux/irq.h>
#  ifdef USE_SYS_KPROBES
#    include <linux/kprobes.h>
#  else
#    include "djprobe.h"
#  endif
#  if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#    include <linux/kallsyms.h>
#  endif
#  if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#    include <linux/fdtable.h>
#    include <linux/path.h>
#  endif
#  include <asm/mman.h>
#else
#  include <sys/types.h>
#  ifdef HAVE_CONFIG_H
#    include "config.h"
#  endif
#endif
#define __attribute__(x)

#define MOD_NAME		"bt_mod"

#define BT_FLAG_PID		(1 << 7)
#define BT_FLAG_COMM		(1 << 6)
#define BT_FLAG_DEBUG		(1 << 5)
#define BT_FLAG_WARN		(1 << 4)
#define BT_FLAG_MAP		(1 << 3)
#define BT_FLAG_EPATH		(1 << 2)
#define BT_FLAG_T_STOP		(1 << 1)
#define BT_FLAG_T_START		(1 << 0)

#define	is_bt_record(r)		((r)->log.type == 0)
#define	is_pid_record(r)	((r)->log.type & BT_FLAG_PID)
#define	is_comm_record(r)	((r)->log.type & BT_FLAG_COMM)
#define	is_warn_record(r)	((r)->log.type & BT_FLAG_WARN)
#define	is_map_record(r)	((r)->log.type & BT_FLAG_MAP)
#define	is_epath_record(r)	((r)->log.type & BT_FLAG_EPATH)

#define BT_COMM_LEN		8
#ifdef __i386__
#  define BT_EPATH_LEN		10
#  define PAD_X86_64__32BITS	
#  define PAD_X86_64__3_INT	
#else
#  define BT_EPATH_LEN		22
#  define PAD_X86_64__32BITS	unsigned __int64 __pad64:32;
#  define PAD_X86_64__3_INT	unsigned int __pad64[3];
#endif

#pragma pack(push, 1)
union bt_record {
	struct bt_log {
		unsigned __int64 from;	// data[0]
		unsigned __int64 to;	// data[1]
		unsigned __int64 flags:24;	// data[1], LSB 24bits
		PAD_X86_64__32BITS
		unsigned __int64 type:8;// data[2], MSB 8bits
	} log;
	struct bt_pid {
		unsigned __int64 pid;
		//PAD_X86_64__32BITS
		unsigned __int64 clocks:56; // 32 + 32 - 8
		//unsigned char type:8;	// data[2], MSB 8bits
		unsigned __int64 type:8;	// data[2], MSB 8bits
	} pid;
	struct bt_comm {
		char comm[BT_COMM_LEN];
		PAD_X86_64__3_INT
		unsigned long __pad:24;
		unsigned long type:8;	// data[2], MSB 8bits
	} comm;
	struct bt_warn {
		unsigned int left;
		PAD_X86_64__3_INT
		unsigned __int64 __pad:56; // 32 + 32 - 8
		unsigned __int64 type:8;	// data[2], MSB 8bits
	} warn;
	/*
	struct bt_map {
		unsigned long vm_start;
		unsigned long vm_end;
		unsigned short len;
		PAD_X86_64__32BITS
		unsigned char __pad;
		unsigned char type;	// data[2], MSB 8bits
	} map;
	struct bt_epath {
		char path[BT_EPATH_LEN];
		unsigned char __pad;
		unsigned char type;	// data[2], MSB 8bits
	} epath;
	struct bt_tmr {
		unsigned long long timestamp;
		PAD_X86_64__3_INT
		unsigned short n_syscall;
		unsigned char __pad;
		unsigned char type;	// data[2], MSB 8bits
	} tmr;
	*/
} __attribute__((packed));
#pragma pack(pop)

#ifdef __i386__
#  define KERNEL_START	0xc0000000
#  define KERNEL_END	0xffffffff
#  define PF_LD		"%d"
#  define PF_LH		"0x%08x"
#  define PF_LH_NC	"0x%x"
#  define PF_OFFTD	"%lld"
#  define PF_OFFTD_12C	"%12lld"
#else
#  define KERNEL_START	0xffffffff80000000
#  define KERNEL_END	0xffffffffffffffff
#  define PF_LD		"%ld"
#  define PF_LH		"0x%016lx"
#  define PF_LH_NC	"0x%lx"
#  define PF_OFFTD	"%ld"
#  define PF_OFFTD_12C	"%12ld"
#endif
#define UNKNOWN_BADDR	KERNEL_END
#define USER_START	0L
#define USER_END	(KERNEL_START - 1)

#define MOD_EXT         ".ko"
#define MOD_EXT_LEN     (sizeof(MOD_EXT) - 1)
#define MAPS_EXT         ".maps"
#define MAPS_EXT_LEN     (sizeof(MAPS_EXT) - 1)

/*
 * Result of the iterator
 *
 * Note that if the iterator returns greater than zero, then loop is finished
 * and this value is returned (none-error break).
 */
#define CONTINUE	0
#define BREAK		1
#define SKIP		2
#define FAILURE		(-1)
#define ALL_DONE	0

#define SUCCESS		0

#define FALSE		0
#define TRUE		1

typedef short		bool_t;
/*
typedef enum {
	TRUE = 1,
	FALSE = 0,
} bool_t;
*/

#ifdef __KERNEL__
#include <asm/types.h>

#define DS_MNG_NUM_FIELD	11
struct bts_cpu_attributes {
	int field_size;	// '4' (i386 but not Core2 and Atom) or
			// '8' (x86_64, Core2, Atom)
	int record_size;

	// offset for each field
	int o_base;
	int o_index;
	int o_max;
	int o_threshold;
};

struct sc_time {
	/* rdtsc value for checking the syscall execution time */
	int			n_syscall;
	unsigned long long	syscall_start;
	unsigned long long	syscall_end;
};

struct info_per_cpu {
	void			*ds_manage;
	struct sc_time		sc_time;
	struct proc_dir_entry	*p_cpuN;
	struct proc_dir_entry	*p_on_off_cnt;
	struct proc_dir_entry	*p_produced;
	struct proc_dir_entry	*p_consumed;
	unsigned int		on_off_cnt;
	char			epath[PATH_MAX]; /* work area for writing
						  * vm area information
						  */
};

/* MSRs */
#ifndef MSR_IA32_DS_AREA
#  define MSR_IA32_DS_AREA	0x600
#endif
#define MSR_DEBUGCTL		0x1d9
struct debugctl_bits {
	int	lbr;
	int	tr;
	int	bts;
	int	btint;
};
#define MSR_DEBUGCTL_P4_BITS	{ 1<<0, 1<<2, 1<<3, 1<<4 }
#define MSR_DEBUGCTL_PM_BITS	{ 1<<0, 1<<6, 1<<7, 1<<8 }

#define	BTS_BUF_MIN_SIZE	(sizeof(union bt_record) * 64 * 1024)
#define	MIN_INT_MARGIN_RECS	(1 * 1024)
#define	DEFAULT_INT_MARGIN_RECS	(8 * 1024)

/* chk_syscall_time parameter value */
#define CHK_SCTIME_OFF			0
#define CHK_SCTIME_ON			1
#define CHK_SCTIME_ON_WITHOUT_TRACE	2

#define is_both(mode)		((mode) == 0)
#define is_start(mode)		((mode) == 1)
#define is_stop(mode)		((mode) == 2)
#define is_fr(mode)  		((mode) == 3)
#define is_syscall_pid(mode) 	((mode) == 4)
#define is_upid(mode)  		((mode) == 5)

#define is_user(mode) 		((mode) == 5)
#define is_kern(mode)		((mode) < 5)

#define is_kern_pid_by_hook(mode)	(is_both(mode) || is_start(mode))
#define is_kern_all_by_hook(mode)	(is_stop(mode) || is_fr(mode))
#define is_syscall(mode)	is_syscall_pid(mode)
#define is_enable_by_proc(mode)	(is_syscall(mode) || is_upid(mode))

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
typedef struct irq_chip bt_int_t;
#  define bt_handler chip
#  define bt_d_child d_u.d_child
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
#else
typedef struct hw_interrupt_type bt_int_t;
#  define bt_handler handler
#  define bt_d_child d_child
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
typedef void (*set_irq_chip_and_handler_t)(unsigned int irq,
					   struct irq_chip *chip,
					   irq_flow_handler_t handle);
typedef void (*handle_irq_t)(unsigned int irq, struct irq_desc *desc);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
typedef struct irq_desc *(*irq_to_desc_alloc_cpu_t)(unsigned int irq, int cpu);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
#  define bt_on_each_cpu	on_each_cpu
#  define bt_kill_pid(pid)	kill_pid(find_vpid(pid), SIGKILL, 1)
#else
#  define bt_on_each_cpu(func,info,wait) \
				on_each_cpu(func,info,1,wait)
#  define bt_kill_pid(pid)	kill_proc((pid), SIGKILL, 1)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
#  define bt_platform_legacy_irq(irq)	((irq) < NR_IRQS_LEGACY)
#else
#  define bt_platform_legacy_irq(irq)	platform_legacy_irq(irq)
#endif




/* prototypes */
extern struct debugctl_bits ctl_bits;

extern cpumask_t enable;
extern unsigned long *pid_tbl;
extern unsigned long *syscall_pid_tbl;
extern unsigned long *map_write_pid_tbl;
extern int pid_max;
extern unsigned long syscall_exe_tbl[];
extern unsigned long syscall_filter_tbl[];

extern unsigned long idt_table_p;
extern unsigned long irq_desc_p;
extern unsigned long no_irq_type_p;
extern unsigned long switch_to_addr;
extern int switch_to_size;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,9)
extern spinlock_t *bt_vector_lock;
extern u8 *bt_irq_vector;		// need for i386 (2.6.28 <)
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
extern kallsyms_lookup_name_t kallsyms_lookup_name_f;
extern int *bt_vector_irq;		// need for x86_64 (2.6.18 <=)
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
extern void *bt_per_cpu__vector_irq;	/* need for x86_64 (2.6.19 >=)
					 * or i386 (2.6.28 >=)
					 */
extern set_irq_chip_and_handler_t set_irq_chip_and_handler_f;
extern handle_irq_t handle_edge_irq_f;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
extern irq_to_desc_alloc_cpu_t irq_to_desc_alloc_cpu_f;
#endif
extern unsigned long do_exit_f;

extern int chk_sctime;

extern struct bts_cpu_attributes cpu_attr;
extern size_t btsbuf_size;
extern size_t bts_int_margin_recs;
extern size_t subbuf_size;
extern size_t subbuf_num;
extern size_t subbuf_sleep_threshold;
extern int mode;
extern unsigned long long start_clocks;

extern DEFINE_PER_CPU(struct info_per_cpu, bt_info_per_cpu);

extern int pmi_irq;
extern struct proc_dir_entry *proc_btrax;



extern void bt_enable_per_cpu(void *data);
extern void bt_disable_per_cpu(void *data);
extern void bt_enable(void);
extern void bt_disable(void);
extern void add_pid_tbl(pid_t, unsigned long*);
extern void remove_pid_tbl(pid_t, unsigned long*);
extern void add_syscall_tbl(int, unsigned long*);
extern void bts_log_write(void);

extern int is_trace_pid(pid_t, unsigned long*);
extern int is_trace_syscall(long);
extern void bts_facility_on(void);
extern void bts_facility_off(void);
extern void bts_facility_save_and_off(int*);
extern void bts_facility_restore(int);
extern void bts_on_and_set_pid_info(int, struct task_struct*, int);
extern void bt_start(void);
extern void bt_stop(void);

extern int setup_isr(void);
extern void cleanup_isr(void);
extern int bt_vector_is_free(int vector);
extern void bt_set_vector_irq(int vector, int irq);

extern int reg_probe(void);
extern void unreg_probe(void);

extern int proc_init(void);
extern void proc_cleanup(void);

extern void write_bt_records(void*, size_t);
extern void write_pid_record(pid_t, char*);
extern void write_warn_record(unsigned long);
extern void write_tmr_record(unsigned long long, long);
extern void write_vm_area_info(struct vm_area_struct*, char*);
extern int relfs_init(void);
extern void relfs_cleanup(void);
extern void relfs_flush(void);
extern void check_and_wait_relfs_write(void);



#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)

static inline void task_list_lock(void)
{
	rcu_read_lock();
}
static inline void task_list_unlock(void)
{
	rcu_read_unlock();
}
static inline unsigned long
get_symbol_address(char *symbol_name)
{
	return kallsyms_lookup_name_f(symbol_name);
}

#else

static inline void task_list_lock(void)
{
	read_lock_irq(&tasklist_lock);
}
static inline void task_list_unlock(void)
{
	read_unlock_irq(&tasklist_lock);
}
static inline unsigned long
get_symbol_address(char *symbol_name)
{
	return UNKNOWN_BADDR;
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,29)
static inline irq_desc_t *get_irq_desc_of(unsigned int irq)
{
	int cpu;

	cpu = smp_processor_id();
	return irq_to_desc_alloc_cpu_f(irq, cpu);
}
#else
static inline irq_desc_t *get_irq_desc_of(unsigned int irq)
{
	return &((irq_desc_t*)irq_desc_p)[irq];
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
#  define orig_ax(regs)		(regs).orig_ax
#  define ax(regs)		(regs).ax
#  define dx(regs)		(regs).dx
#  define di(regs)		(regs).di
#  define si(regs)		(regs).si
#  define gate_struct		gate_struct64
#else
#  ifdef CONFIG_X86_64
#    define orig_ax(regs)	(regs).orig_rax
#    define ax(regs)		(regs).rax
#    define dx(regs)		(regs).rdx
#    define di(regs)		(regs).rdi
#    define si(regs)		(regs).rsi
#  else
#    define orig_ax(regs)	(regs).orig_eax
#    define ax(regs)		(regs).eax
#    define dx(regs)		(regs).edx
#  endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
typedef char *(*__d_path_t)(const struct path *, struct path *, char *, int);
#else
typedef char *(*__d_path_t)(struct dentry *, struct vfsmount *,
			struct dentry *, struct vfsmount *, char *, int);
#endif

#ifndef regs_return_value
#  define regs_return_value(regsp) (ax(*regsp))
#endif
// for <= 2.6.19 kernels
#ifndef cpu_has_ds
#  define cpu_has_ds		boot_cpu_has(X86_FEATURE_DTES)
#endif

#ifdef USE_SYS_KPROBES
static inline void
set_kretprobe_point(struct kretprobe *kp, char *symbol_name)
{
	kp->kp.addr = (kprobe_opcode_t*)get_symbol_address(symbol_name);
}
#endif

static inline void chk_procs_using_relfs(struct dentry *d,
					 pid_t **pp_pid, pid_t *p_max)
{
	struct task_struct *p;
	struct files_struct *files;
	struct file *file = NULL;
	unsigned int i;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
	struct fdtable *fdt;
#endif

	task_list_lock();
	for_each_process(p) {
		files = p->files;
		if (!files)
			continue;
		spin_lock(&files->file_lock);
		//serial_prints("chk-pid(%d)\n", p->pid);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
		fdt = files_fdtable(files);
		for (i = 0; i < fdt->max_fds; i++) {
			file = fdt->fd[i];
#else
		for (i = 0; i < files->max_fds; i++) {
			file = files->fd[i];
#endif
			if (file && file->f_dentry == d) {
				*(*pp_pid)++ = p->pid;
				if (*pp_pid >= p_max) {
					spin_unlock(&files->file_lock);
					goto EXIT;
				}
				break;
			}
		}
		spin_unlock(&files->file_lock);
	} while (p != &init_task);
EXIT:
	task_list_unlock();
}

extern void context_switch_probe(int cpu, struct task_struct *prev,
				 struct task_struct *next);
extern int snprintf_sysenter_eip(char *buf, int max);
extern int snprintf_idt_table(char *buf, int max, int i);

#ifdef CONFIG_X86_64

#  define NR_execve		__NR_execve
#  define NR_mmap2		__NR_mmap
#  define MP_SIZE_T		long
#  define BT_SYSCALL_VECTOR	IA32_SYSCALL_VECTOR
#  define UL_HEX_COLS		16
#  define irq_vect_manage_p	vector_irq_p
#  define wrmsr_ds_area(p)	wrmsrl(MSR_IA32_DS_AREA, (unsigned long)(p))
#  define do_context_switch_probe(cpu, regsp)	\
	context_switch_probe(cpu, (struct task_struct*)di(*regsp),	\
			     (struct task_struct*)si(*regsp))

#else	/* CONFIG_X86_32 */

#  define NR_execve		__NR_execve
#  define NR_mmap2		__NR_mmap2
#  define MP_SIZE_T		int
#  define BT_SYSCALL_VECTOR	SYSCALL_VECTOR
#  define UL_HEX_COLS		8
#  if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)
#    define irq_vect_manage_p	vector_irq_p
#  else
#    define irq_vect_manage_p	irq_vector_p
#  endif
#  define wrmsr_ds_area(p)	wrmsr(MSR_IA32_DS_AREA, (unsigned long)p, 0)
#  define do_context_switch_probe(cpu, regsp)	\
	context_switch_probe(cpu, (struct task_struct*)ax(*regsp),	\
			     (struct task_struct*)dx(*regsp))

#endif	/* CONFIG_X86_64 */

#define get_n_syscall(regs)		orig_ax(regs)
#define mmap_arg_has_PROT_EXEC(regs)	(dx(regs) & PROT_EXEC)

/* for serial console prints */
int serial_init(int);
asmlinkage int serial_prints(const char *, ...);

#else

//#define MAX_LINE_LEN	256
#define MAX_LINE_LEN	4096
#define MAX_UNAME_LEN	80

//#define RAW_DEBUG	// for DEBUG

#endif /* __KERNEL__ */

#endif /*__BT_H__*/
