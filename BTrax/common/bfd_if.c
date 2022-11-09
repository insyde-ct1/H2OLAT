/*****************************************************************************/
/* The development of this program is partly supported by IPA                */
/* (Information-Technology Promotion Agency, Japan).                         */
/*****************************************************************************/

/*****************************************************************************/
/*  bfd_if.c - BFD library interface                                         */
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

//#include <unistd.h>
#include "bt.h"
#include "bfd_if.h"
#include "bt_utils.h"

////#define DBG_CHK_PATH

bool_t ignore_elf_errors = FALSE;

/*-----------------------------------------------------------------------------
 *  kpatch check
 *-----------------------------------------------------------------------------
 */
int read_kpatchinf(struct bfd_if *bi, unsigned long offset, char *kpatchinf)
{
	int fd, rc, n, n_altinst;
	struct kpatch_info *kp;
	struct pvpatch_log pvp, *p;

	kp = &bi->kpatch_info;
	kp->koffset = offset;

	rc = FAILURE;
	fd = u_open(kpatchinf, NULL);
	if (fd < 0)
		return rc;

	// Read altinst information.
	n = u_read(fd, &n_altinst, sizeof(n_altinst));
	if (n != sizeof(n_altinst)) {
		fprintf(stderr, "!!!kpatchinf format error(first 4bytes).\n");
		goto EXIT;
	}
	if (n_altinst) {
		kp->altinst_bitmap = xmalloc(n_altinst);
		n = u_read(fd, kp->altinst_bitmap, n_altinst);
		if (n != n_altinst) {
			fprintf(stderr,
				"!!!kpatchinf format error(altinst bitmap).\n");
			goto EXIT;
		}
	}

	// Read altinst information.
	n = offsetof(struct pvpatch_log, p);
	pvp.p = NULL;
	while (u_read(fd, &pvp, n) == n) {
		p = xmalloc(sizeof(*p));
		*p = pvp;
		kp->pvinst_array = xrealloc(kp->pvinst_array,
					    (kp->n_pvinst + 1) *
						sizeof(*kp->pvinst_array));
		kp->pvinst_array[kp->n_pvinst] = p;
		kp->n_pvinst++;
		switch (p->type) {
		case PVPT_JMP:
		case PVPT_CALL:
			if (u_read(fd, &p->p, sizeof(p->p)) != sizeof(p->p))
				goto EXIT;
			break;
		case PVPT_INSN:
			p->p = xmalloc(p->len);
			if (u_read(fd, p->p, p->len) != p->len)
				goto EXIT;
			break;
		}
	}
	rc = SUCCESS;
EXIT:
	if (fd >= 0)
		close(fd);
	return rc;
}

static inline int
is_addr_in_cache(unsigned char *addr, struct sect_cache *cache)
{
	unsigned long vma_start = (unsigned long)cache->vma;
	unsigned long vma_end = (unsigned long)(cache->vma + cache->size);

	return (addr >= (unsigned char*)vma_start
		&& addr < (unsigned char*)vma_end);
}

static int apply_ftrace_patch(struct bfd_if *bi, struct sect_cache *cache)
{
	unsigned long *mccalls = NULL, *p, *p_end;
	unsigned long addr, cache_vma;
	unsigned char *p_cache;
	size_t len;

	// Get section data for mcount pointers.
	if (!(mccalls = get_section_data(bi, MCOUNT_SECT, &len, NULL)) &&
	    !(mccalls = get_section_data(bi, INIT_RODATA_SECT, &len, NULL)))
		goto EXIT;
	p_end = (unsigned long*)((unsigned char*)mccalls + len);
	cache_vma = (unsigned long)cache->vma;
	for (p = mccalls; p < p_end; p++) {
		// 'p' points one byte after the 'call'.
		addr = *p - 1;
		if (addr_in_init_sect(bi, addr))
			continue;
		if (!is_addr_in_cache((unsigned char*)addr, cache))
			continue;
		p_cache = (unsigned char*)(addr - cache_vma
					   + (unsigned long)cache->data);
		if (*p_cache != CALL_INST)
			continue;
		memset(p_cache, NOP_INST, 5);
	}
EXIT:
	if (mccalls)
		free(mccalls);
	return SUCCESS;
}

static int apply_altinst_patch(struct bfd_if *bi, struct sect_cache *cache)
{
	struct kpatch_info *kp;
	struct alt_instr *alts = NULL, *p, *end;
	unsigned char *reps = NULL;
	size_t len, replen;
	unsigned long reptop;
	int rc;
	unsigned char *p_alt, *p_rep, *p_bitmap, shift, *cache_vma;

	rc = FAILURE;
	kp = &bi->kpatch_info;

	// Read data of the 'alt' and 'replace' sections.
	alts = get_section_data(bi, ALT_INST_SECT, &len, NULL);
	if (!alts) {
		printf("!!! get_section_data failed.\n");
		goto EXIT;
	}
	reps = get_section_data(bi, REP_INST_SECT, &replen, &reptop);
	if (!reps) {
		printf("!!! get_section_data failed.\n");
		goto EXIT;
	}

	// Check each paravirt inst.
	p_bitmap = kp->altinst_bitmap;
	shift = 1;
	end = (struct alt_instr*)((unsigned char*)alts + len);
	cache_vma = (unsigned char*)(unsigned long)cache->vma;
	for (p = alts; p < end; p++) {
		if (addr_in_init_sect(bi, (unsigned long)p->instr))
			goto NEXT;
		if ((shift & *p_bitmap) && is_addr_in_cache(p->instr, cache)) {
			p_alt = p->instr - cache_vma + cache->data;
			p_rep = p->replacement - (unsigned char*)reptop + reps;
			memcpy(p_alt, p_rep, p->replacementlen);
			memset(p_alt + p->replacementlen, NOP_INST,
			       p->instrlen - p->replacementlen);
		}
NEXT:
		if (shift == 0x80) {
			p_bitmap++;
			shift = 1;
		} else
			shift <<= 1;
	}
	rc = SUCCESS;
EXIT:
	if (alts)
		free(alts);
	if (reps)
		free(reps);
	return rc;
}

int f_cmp_pvplog(const void *p1, const void *p2)
{
	struct pvpatch_log *l1, *l2;

	l1 = *(struct pvpatch_log**)p1;
	l2 = *(struct pvpatch_log**)p2;
	if (l1->k.instrtype != l2->k.instrtype)
		return l1->k.instrtype - l2->k.instrtype;
	if (l1->k.len != l2->k.len)
		return l1->k.len - l2->k.len;
	return l1->k.clobbers - l2->k.clobbers;
}

static int apply_pvinst_patch(struct bfd_if *bi, struct sect_cache *cache)
{
	struct kpatch_info *kp;
	struct paravirt_patch *data = NULL, *p, *end;
	size_t len;
	int rc;
	struct pvpatch_log log, *tmp, **p_patch, *patch;
	unsigned char *p_inst, *cache_vma;

	rc = FAILURE;
	kp = &bi->kpatch_info;

	// Read data of the 'parainsts' section.
	data = get_section_data(bi, PARA_INST_SECT, &len, NULL);
	if (!data) {
		printf("!!! get_section_data failed.\n");
		goto EXIT;
	}
	// Check each paravirt inst.
	memset(&log, 0, sizeof(log));
	end = (struct paravirt_patch*)((unsigned char*)data + len);
	cache_vma = (unsigned char*)(unsigned long)cache->vma;
	for (p = data; p < end; p++) {
		if (addr_in_init_sect(bi, (unsigned long)p->instr))
			continue;
		if (!is_addr_in_cache(p->instr, cache))
			continue;
		log.k.instrtype = p->instrtype;
		log.k.len = p->len;
		log.k.clobbers = p->clobbers;
		tmp = &log;
		// Get patch information for this instruction.
		p_patch = bsearch(&tmp, kp->pvinst_array, kp->n_pvinst,
				  sizeof(*kp->pvinst_array), f_cmp_pvplog);
		if (!p_patch)
			goto EXIT;
		patch = *p_patch;
		p_inst = p->instr - cache_vma + cache->data;
		switch (patch->type) {
		case PVPT_CALL:
		case PVPT_JMP:
			p_inst[0] =
				patch->type == PVPT_CALL ? CALL_INST : JMP_INST;
			*(int*)&p_inst[1] =
				patch->p - kp->koffset - p->instr - 5;
			memset(&p_inst[5], NOP_INST, p->len - 5);
			break;
		case PVPT_INSN:
			memcpy(p_inst, patch->p, p->len);
			break;
		default:	// PVPT_NOP
			memset(p_inst, NOP_INST, p->len);
			break;
		}
	}
	rc = SUCCESS;
EXIT:
	if (data)
		free(data);
	return rc;
}

static int apply_kpatch(struct bfd_if *bi, struct sect_cache *cache)
{
	if (apply_ftrace_patch(bi, cache) == FAILURE)
		return FAILURE;
	if (bi->kpatch_info.altinst_bitmap &&
	    apply_altinst_patch(bi, cache) == FAILURE)
		return FAILURE;
	if (bi->kpatch_info.n_pvinst &&
	    apply_pvinst_patch(bi, cache) == FAILURE)
		return FAILURE;
	return SUCCESS;
}

/*-----------------------------------------------------------------------------
 *  misc functions
 *-----------------------------------------------------------------------------
 */
#if 0
static void dump_symbols(const char *header, asymbol **symbols, long cnt)
{
	long i;
	asymbol *sym;
	asection *sect;

	printf("%s\n", header);
	for (i = 0; i < cnt; i++) {
		sym = symbols[i];
		sect = sym->section;
		printf("\tSYM 0x%08lx", (unsigned long)bfd_asymbol_value(sym));
		printf(" <%s>%08x\t<%s>%08x:%d\n",
		       sym->name, sym->flags, sect->name, sect->flags,
		       sect->index);
	}
}
static void dump_relocs(struct bfd_if *bi)
{
	long i;
	arelent *r;

	for (i = 0; i < bi->n_relocs; i++) {
		r = bi->p_relocs[i];
		if (r->howto->type != RELOC_TYPE_PC32)
			continue;
		printf("RELOC=> CODE-OFFSET:0x%08lx",
		       (unsigned long)r->address);
		printf(" SYM-ADDR:0x%08lx",
		       (unsigned long)(*r->sym_ptr_ptr)->value);
		printf(" <%s>", (*r->sym_ptr_ptr)->name);
		printf("\n");
	}
}
#endif

#define strcmp2const_str(s, const_str)	\
	strncmp(s, const_str, sizeof(const_str) - 1)

static int cmp_code_sects(const void *p1, const void *p2)
{
	const struct code_sect *cs1 = p1;
	const struct code_sect *cs2 = p2;

	if ((unsigned long)cs1->section->vma < (unsigned long)cs2->section->vma)
		return -1;
	if ((unsigned long)cs1->section->vma > (unsigned long)cs2->section->vma)
		return 1;

	/* There are some sections which has same vma in the one ELF file,
	 * such as module's '.text' and '.init.text' sections.
	 * So, we have to check the 'index' value to prove the argement is
	 * the code section.
	 */
	if (cs1->section->index < cs2->section->index)
		return -1;
	if (cs1->section->index > cs2->section->index)
		return 1;
	return 0;
}

static int cmp_addr_to_code_sect(const void *p1, const void *p2)
{
	const unsigned long *p_addr = p1;
	const struct code_sect *cs = p2;

	if (*p_addr < cs->section->vma)
		return -1;
	if (*p_addr >= cs->section->vma + cs->section->size)
		return 1;
	return 0;
}

#define is_code_sect(s) (((s)->flags & SEC_CODE) && ((s)->flags & SEC_ALLOC))

static bool_t is_valid_code_section(bfd *abfd, asection *s, bool_t is_module)
{
	return (is_code_sect(s)
		&& !(is_module && strcmp2const_str(s->name, ".init") == 0)
		&& strcmp2const_str(s->name, REP_INST_SECT) != 0);
}

static bool_t is_valid_code_sect(struct bfd_if *bi, asection *sect)
{
	struct code_sect *cs;
	struct code_sect key = { .section = sect };

	cs = bsearch(&key, bi->p_code_sects, bi->n_code_sects,
		     sizeof(*bi->p_code_sects), cmp_code_sects);
	return (cs != NULL);
}

static asection* get_sect_has_addr(struct bfd_if *bi, unsigned long addr)
{
	struct code_sect *cs;

	cs = bsearch(&addr, bi->p_code_sects, bi->n_code_sects,
		     sizeof(*bi->p_code_sects), cmp_addr_to_code_sect);
	if (cs)
		return cs->section;
	return NULL;
}

// Return value: -1 = Error
//                0 = addr in none init section
//                1 = addr in '.initxxx' section
int addr_in_init_sect(struct bfd_if *bi, unsigned long addr)
{
	asection *s;
	size_t size;
	const char *init_name = ".init";

	for (s = bi->abfd->sections; s; s = s->next) {
		if ((size = bfd_section_size(bi->abfd, s)) == 0)
			continue;
		if (addr < s->vma || addr >= s->vma + size)
			continue;
		return strncmp(s->name, init_name, strlen(init_name)) == 0;
	}
	return -1;
}

#ifdef RELOC_TEST
bool_t reloc_test;

void enable_reloc_test(void)
{
	reloc_test = TRUE;
}

static void test_print_reloc(struct bfd_if *bi, arelent *r)
{
	asection *s;

	if (!reloc_test)
		return;
	s = get_sect_has_addr(bi, (unsigned long)r->address);
	printf("%s 0x%08lx", s->name, (unsigned long)(r->address - s->vma));
	printf(" %s\n", (*r->sym_ptr_ptr)->name);
}
#else
#  define test_print_reloc(bi, r)
#endif

static int cmp_addr_to_reloc(const void *p1, const void *p2)
{
	bfd_vma addr;
	arelent *r;

	addr = (bfd_vma)(*(unsigned long*)p1);
	r = *(arelent**)p2;
	if (addr < r->address)
		return -1;
	if (addr > r->address)
		return 1;
	return 0;
}

static bool_t is_reloc_branch(struct bfd_if *bi, unsigned long base)
{
	arelent **p;
	unsigned long offset;

	if (!bi->p_relocs)
		return FALSE;
	offset = base + 1;	// Always 1byte instruction ('jmp' or 'call')
	p = bsearch(&offset, bi->p_relocs, bi->n_relocs, sizeof(*bi->p_relocs),
		    cmp_addr_to_reloc);
	return (p != NULL);
}

asymbol* get_symbol(struct bfd_if *bi, unsigned long addr,
		    unsigned long *addend)
{
	arelent **p;

	p = bsearch(&addr, bi->p_relocs, bi->n_relocs, sizeof(*bi->p_relocs),
		    cmp_addr_to_reloc);
	if (!p)
		return NULL;
	test_print_reloc(bi, *p);
	*addend = (*p)->addend;
	return *(*p)->sym_ptr_ptr;
}

/* This routine returns section's data into allocated memory.
 * So, caller must be free it later.
 */
void *get_section_data(struct bfd_if *bi, const char *name, size_t *len,
		       unsigned long *addr)
{
	asection *s;
	size_t size;
	void *data, *tmp;

	for (s = bi->abfd->sections; s; s = s->next) {
		if (strcmp(s->name, name) != 0)
			continue;
		if ((size = bfd_section_size(bi->abfd, s)) == 0)
			return NULL;
		if (s->vma) {
			data = xmalloc(size);
			bfd_get_section_contents(bi->abfd, s, data, 0, size);
		} else {
			if (!s->userdata) {
				// We did not get relocated contents yet.
				tmp = bfd_simple_get_relocated_section_contents
						(bi->abfd, s, NULL, NULL);
				// Once we call this function, the next time's
				// call not function properly (relocation not
				// applied).
				// So, we have to save the relocated contents.
				s->userdata = tmp;
			}
			data = xmalloc(size);
			memcpy(data, s->userdata, size);
		}
		if (len)
			*len = size;
		if (addr)
			*addr = s->vma;
		return data;
	}
	return NULL;
}

static int prepare_print_insn(struct bfd_if *bi, unsigned long addr)
{
	asection *sect;
	struct disassemble_info *info = &bi->info;
	struct sect_cache *cache = &bi->cache;

	if (cache->data) {
		if (addr >= (unsigned long)cache->vma &&
		    addr < (unsigned long)(cache->vma + cache->size)) {
			goto CACHE_FINISH;
		} else {
			free(cache->data);
			cache->data = NULL;
		}
	}
	sect = get_sect_has_addr(bi, addr);
	if (!sect)
		return FAILURE;
	cache->sect = sect;
	cache->vma = sect->vma;
	cache->size = bfd_get_section_size(sect);
	if (cache->size == 0)
		return SUCCESS;
	cache->data = xmalloc(cache->size);
	bfd_get_section_contents(bi->abfd, sect, cache->data, 0, cache->size);
	if (apply_kpatch(bi, cache) == FAILURE)
		return FAILURE;

CACHE_FINISH:
	info->buffer = cache->data;
	info->buffer_vma = cache->vma;
	info->buffer_length = cache->size;
	info->section = cache->sect;
	info->insn_info_valid = 0;
	info->bytes_per_line = 0;
	info->bytes_per_chunk = 0;
	info->flags = 0;
	return SUCCESS;
}

/*-----------------------------------------------------------------------------
 *  intialize
 *-----------------------------------------------------------------------------
 */
#ifdef __i386__
static int chk_elf_header(struct bfd_if *bi, const char *obj_name)
{
	int rc;
	unsigned int i;
	FILE *f;
	unsigned char e_ident[EI_NIDENT];
	Elf32_Ehdr ehdr;
	Elf32_Phdr phdr;

	rc = FAILURE;
	f = fopen(obj_name, "rb");
	if (!f) {
		fprintf(stderr, "%s file can't open.(%s)\n",
			obj_name, strerror(errno));
		goto EXIT;
	}
	if (fread(e_ident, EI_NIDENT, 1, f) != 1) {
		fprintf(stderr, "fread failed.(%s)\n", strerror(errno));
		goto EXIT;
	}
	if (e_ident[EI_DATA] != ELFDATA2LSB) {
		fprintf(stderr, "not little endian object.\n");
		goto EXIT;
	}
	if (e_ident[EI_CLASS] != ELFCLASS32) {
		fprintf(stderr, "not 32-bit architecture object.\n");
		goto EXIT;
	}
	if (fread(&ehdr.e_type, sizeof(ehdr) - EI_NIDENT, 1, f) != 1) {
		fprintf(stderr, "fread failed.(%s)\n", strerror(errno));
		goto EXIT;
	}
	for (i = 0; i < ehdr.e_phnum; i++) {
		if (fread(&phdr, sizeof(phdr), 1, f) != 1) {
			fprintf(stderr, "fread failed.(%s)\n", strerror(errno));
			goto EXIT;
		}
		if (phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_X))
			continue;
		bi->load_vaddr = phdr.p_vaddr;
		break;
	}
	rc = SUCCESS;
EXIT:
	if (f)
		fclose(f);
	return rc;
}
#else // __x86_64__
static int chk_elf_header(struct bfd_if *bi, const char *obj_name)
{
	int rc;
	unsigned int i;
	FILE *f;
	unsigned char e_ident[EI_NIDENT];
	Elf64_Ehdr ehdr;
	Elf64_Phdr phdr;

	rc = FAILURE;
	f = fopen(obj_name, "rb");
	if (!f) {
		fprintf(stderr, "%s file can't open.(%s)\n",
			obj_name, strerror(errno));
		goto EXIT;
	}
	if (fread(e_ident, EI_NIDENT, 1, f) != 1) {
		fprintf(stderr, "fread failed.(%s)\n", strerror(errno));
		goto EXIT;
	}
	if (e_ident[EI_DATA] != ELFDATA2LSB) {
		fprintf(stderr, "not little endian object.\n");
		goto EXIT;
	}
	if (e_ident[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr, "not 32-bit architecture object.\n");
		goto EXIT;
	}
	if (fread(&ehdr.e_type, sizeof(ehdr) - EI_NIDENT, 1, f) != 1) {
		fprintf(stderr, "fread failed.(%s)\n", strerror(errno));
		goto EXIT;
	}
	for (i = 0; i < ehdr.e_phnum; i++) {
		if (fread(&phdr, sizeof(phdr), 1, f) != 1) {
			fprintf(stderr, "fread failed.(%s)\n", strerror(errno));
			goto EXIT;
		}
		if (phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_X))
			continue;
		bi->load_vaddr = phdr.p_vaddr;
		break;
	}
	rc = SUCCESS;
EXIT:
	if (f)
		fclose(f);
	return rc;
}
#endif

static void chk_valid_code_sects(struct bfd_if *bi, bool_t is_module)
{
	struct code_sect *top, *p;
	asection *s;
	int has_reloc;
	bfd_vma sect_offset;

	has_reloc = bfd_get_file_flags(bi->abfd) & HAS_RELOC;
	top = xcalloc(bi->abfd->section_count, sizeof(*top));
	p = top;
	sect_offset = 0;
	for (s = bi->abfd->sections; s; s = s->next) {
		if (is_valid_code_section(bi->abfd, s, is_module)) {
			p->section = s;
			p++;
			if (has_reloc && s->vma == 0) {
				s->vma += sect_offset;
				sect_offset += bfd_get_section_size(s);
			}
		}
	}
	bi->p_code_sects = top;
	bi->n_code_sects = p - top;

	/* There is the kernel which has so many sections, such as x86_64
	 * RHEL5U0's. So, we have to speed up the 'is_valid_code_sect' function.
	 */
	qsort(bi->p_code_sects, bi->n_code_sects,
	      sizeof(*bi->p_code_sects), cmp_code_sects);
}

static void read_all_symbols(bfd *abfd, bool_t is_dynamic, asymbol ***symbols,
			     int *nsyms)
{
	long size;

	if (!(bfd_get_file_flags(abfd) & HAS_SYMS))
		return;

	if (is_dynamic)
		size = bfd_get_dynamic_symtab_upper_bound(abfd);
	else
		size = bfd_get_symtab_upper_bound(abfd);
	if (size <= (long)sizeof(asymbol*))
		return;

	*symbols = xmalloc(size);
	if (is_dynamic)
		*nsyms = bfd_canonicalize_dynamic_symtab(abfd, *symbols);
	else
		*nsyms = bfd_canonicalize_symtab(abfd, *symbols);
	return;
}

static int __cmp_symbols(const void *d1, const void *d2)
{
	asymbol *sym1 = *(asymbol**)d1, *sym2 = *(asymbol**)d2;
	bfd_vma a1, a2;
	flagword f1, f2;
	const char *n1, *n2;

	a1 = bfd_asymbol_value(sym1);
	a2 = bfd_asymbol_value(sym2);
	if (a1 > a2)
		return 1;
	if (a1 < a2)
		return -1;

	if (sym1->section > sym2->section)
		return 1;
	if (sym1->section < sym2->section)
		return -1;

	/* Try to sort global symbols before local symbols before function
	 * symbols before debugging symbols.
	 */
	f1 = sym1->flags;
	f2 = sym2->flags;
	if ((f1 & BSF_DEBUGGING) != (f2 & BSF_DEBUGGING)) {
		if ((f1 & BSF_DEBUGGING))
			return 1;
		else
			return -1;
	}
	if ((f1 & BSF_FUNCTION) != (f2 & BSF_FUNCTION)) {
		if ((f1 & BSF_FUNCTION))
			return -1;
		else
			return 1;
	}
	if ((f1 & BSF_LOCAL) != (f2 & BSF_LOCAL)) {
		if ((f1 & BSF_LOCAL))
			return 1;
		else
			return -1;
	}
	if ((f1 & BSF_GLOBAL) != (f2 & BSF_GLOBAL)) {
		if ((f1 & BSF_GLOBAL))
			return -1;
		else
			return 1;
	}

	/* Symbols that start with '.' might be section names, so sort them
	 * after symbols that don't start '.'.
	 */
	n1 = bfd_asymbol_name(sym1);
	n2 = bfd_asymbol_name(sym2);
	if (n1[0] == '.' && n2[0] != '.')
		return 1;
	if (n1[0] != '.' && n2[0] == '.')
		return -1;

	return strcmp(n1, n2);
}

// This function returns count after remove
static long remove_useless_symbols(struct bfd_if *bi, asymbol **syms,
				   long count)
{
	asymbol **p_in = syms, **p_out = syms, *sym_prev = NULL;
	asection *sect;

	while (--count >= 0) {
		asymbol *sym = *p_in++;
		if (sym->name == NULL || sym->name[0] == '\0')
			continue;
		if (sym->flags & (BSF_DEBUGGING))
			continue;
		sect = sym->section;
		if (bfd_is_com_section(sect))
			continue;
		if (!is_valid_code_sect(bi, sect) && !bfd_is_und_section(sect))
			continue;
		*p_out++ = sym_prev = sym;
	}
	return p_out - syms;
}

static int resolve_undsyms_from_imf(struct bfd_if *bi,
				    struct imf_bi_info *imf_info)
{
	asymbol *sym;
	struct imf_esym_info *info;

	if (bi->n_syms != imf_info->sym_num) {
		fprintf(stderr, "!!! Target ELF file is different"
			" (symbol number differ %d <-> %d)\n",
			bi->n_syms, imf_info->sym_num);
		return FAILURE;
	}
	for (info = imf_info->esym_info; info; info = info->next) {
		sym = bi->p_syms[info->esym.i];
		if (sym->flags != 0) {
			fprintf(stderr, "!!! Trying to change the not-UND"
				" symbol(%s).\n", sym->name);
			return FAILURE;
		}
		sym->value = info->esym.a_addr;
	}
	return SUCCESS;
}

static void
__resolve_undsym(struct bfd_if *bi, char *sname, unsigned long a_addr)
{
	long i;
	asymbol *sym;

	for (i = 0; i < bi->n_syms; i++) {
		sym = bi->p_syms[i];
		if (sym->name[0] != sname[0] || strcmp(sym->name, sname) != 0)
			continue;
		sym->value = a_addr;
		return;
	}
	return;
}

static int
resolve_undsyms(struct bfd_if *bi, const char *kallsyms, char *mod_name)
{
	int rc, len, num;
	FILE *f = NULL;
	char buf[MAX_LINE_LEN + 1], sym[MAX_LINE_LEN], mod[MAX_LINE_LEN], *p;
	char type;
	unsigned long a_addr;

	if (!kallsyms)
		return SUCCESS;
	rc = FAILURE;
	len = strlen(mod_name);
	if (len <= MOD_EXT_LEN
	    || strcmp(&mod_name[len - MOD_EXT_LEN], MOD_EXT) != 0) {
		rc = SUCCESS;	/* target object is not kernel module */
		goto EXIT;
	}
	mod_name[len - MOD_EXT_LEN] = '\0';
	f = fopen(kallsyms, "r");
	if (!f) {
		fprintf(stderr, "%s open failed.\n", kallsyms);
		goto EXIT;
	}
	buf[MAX_LINE_LEN] = '\0';
	while ((p = fgets(buf, MAX_LINE_LEN, f)) != NULL) {
		len = strlen(buf);
		num = sscanf(buf, "%lx %c %s\t[%[^]]]",
			     &a_addr, &type, sym, mod);
		if (num != 4 || (type != 'U' && type != 'u')
		    || strcmp(mod_name, mod) != 0)
			continue;
		__resolve_undsym(bi, sym, a_addr);
	}
	rc = SUCCESS;
EXIT:
	if (f)
		fclose(f);
	return rc;
}

static void chk_relocs_sect(struct bfd_if *bi, asection *sect,
			    bfd_vma sect_offset)
{
	long size, i, n;

	if (!(is_valid_code_sect(bi, sect) && (sect->flags & SEC_RELOC)))
		return;
	size = bfd_get_reloc_upper_bound(bi->abfd, sect);
	if (size < 0 || size == sizeof(*bi->p_relocs))
		return;
	n = size / sizeof(*bi->p_relocs) - 1;
	bi->p_relocs = xrealloc(bi->p_relocs,
				(bi->n_relocs * sizeof(*bi->p_relocs)) + size);
	memset(&bi->p_relocs[bi->n_relocs], 0, size);

	bfd_canonicalize_reloc(bi->abfd, sect,
			       &bi->p_relocs[bi->n_relocs], bi->p_syms);
	if (sect_offset)
		for (i = bi->n_relocs; i < bi->n_relocs + n; i++)
			bi->p_relocs[i]->address += sect_offset;
	bi->n_relocs += n;
}

static int f_cmp_relocs(const void *p1, const void *p2)
{
	arelent *r1, *r2;

	r1 = *(arelent**)p1;
	r2 = *(arelent**)p2;
	if (r1->address < r2->address)
		return -1;
	if (r1->address > r2->address)
		return 1;
	return 0;
}

static void chk_relocs(struct bfd_if *bi)
{
	bfd_vma sect_offset;
	asection *s;

	if (!(bfd_get_file_flags(bi->abfd) & HAS_RELOC))
		return;

	// 'sect_offset' is updated by each section, so, we do this by
	// abfd->sections' order and doesn't use the p_code_sects order.
	sect_offset = 0;
	for (s = bi->abfd->sections; s; s = s->next) {
		if (!is_valid_code_sect(bi, s))
			continue;
		chk_relocs_sect(bi, s, sect_offset);
		sect_offset += bfd_get_section_size(s);
	}
	qsort(bi->p_relocs, bi->n_relocs, sizeof(*bi->p_relocs), f_cmp_relocs);
}

#define free_pointer(p)				\
	do{					\
		if ((p) != NULL) {		\
			free(p);		\
			(p) = NULL;		\
		}				\
	} while (0)

static void free_bi_syms(struct bfd_if *bi)
{
	free_pointer(bi->p_syms);
	free_pointer(bi->p_dynsyms);
	free_pointer(bi->p_synsyms);
	free_pointer(bi->p_fsyms);
	free_pointer(bi->p_relocs);
}

#ifdef HAVE_LIBDW
static void free_bi_dwfl(struct bfd_if *bi)
{
	if (bi->dwfl) {
		dwfl_end(bi->dwfl);
		bi->dwfl = NULL;
	}
}
#else
static void free_bi_dwfl(struct bfd_if *bi) {}
#endif

static void free_kpatch_info(struct bfd_if *bi)
{
	struct kpatch_info *kp;
	int i;
	struct pvpatch_log *pv;

	kp = &bi->kpatch_info;
	kp->koffset = 0;
	if (kp->altinst_bitmap)
		free(kp->altinst_bitmap);
	for (i = 0; i < kp->n_pvinst; i++) {
		pv = kp->pvinst_array[i];
		if (pv->type == PVPT_INSN)
			free(pv->p);
		free(pv);
	}
	kp->n_pvinst = 0;
	free(kp->pvinst_array);
}

void free_bi(struct bfd_if *bi)
{
	struct sect_cache *cache = &bi->cache;

	free_bi_syms(bi);
	if (bi->p_code_sects) {
		free(bi->p_code_sects);
		bi->p_code_sects = NULL;
	}
	if (cache->data) {
		free(cache->data);
		cache->data = NULL;
	}
	if (bi->abfd) {
		if (bi->abfd->filename)
			free((char*)bi->abfd->filename);
		bfd_close(bi->abfd);
		bi->abfd = NULL;
	}
	free_bi_dwfl(bi);
	free_kpatch_info(bi);
}

static int build_sorted_func_symbols(struct bfd_if *bi, const char *obj_name,
				     const char *kallsyms, char *mod_name,
				     struct imf_bi_info *imf_info)
{
	long i;

	bi->n_syms = bi->n_dynsyms = bi->n_synsyms = 0;
	bi->p_syms = bi->p_dynsyms = NULL;
	bi->p_synsyms = NULL;

	read_all_symbols(bi->abfd, FALSE, &bi->p_syms, &bi->n_syms);
	read_all_symbols(bi->abfd, TRUE, &bi->p_dynsyms, &bi->n_dynsyms);

	chk_relocs(bi);
	bi->n_synsyms = bfd_get_synthetic_symtab(bi->abfd,
						 bi->n_syms, bi->p_syms,
						 bi->n_dynsyms, bi->p_dynsyms,
						 &bi->p_synsyms);
	if (bi->n_synsyms < 0)
		goto EXIT;

	bi->n_fsyms = bi->n_syms ? bi->n_syms : bi->n_dynsyms;
	bi->p_fsyms = xmalloc((bi->n_fsyms + bi->n_synsyms)
			      		* sizeof(*bi->p_fsyms));
	memcpy(bi->p_fsyms, bi->n_syms ? bi->p_syms : bi->p_dynsyms,
	       bi->n_fsyms * sizeof(*bi->p_fsyms));
	bi->n_fsyms = remove_useless_symbols(bi, bi->p_fsyms, bi->n_fsyms);

	for (i = 0; i < bi->n_synsyms; i++) {
		bi->p_fsyms[bi->n_fsyms] = bi->p_synsyms + i;
		bi->n_fsyms++;
	}
	if (imf_info) {
		if (resolve_undsyms_from_imf(bi, imf_info) == FAILURE)
			goto EXIT;
	} else {
		if (resolve_undsyms(bi, kallsyms, mod_name) == FAILURE)
			goto EXIT;
	}
	qsort(bi->p_fsyms, bi->n_fsyms, sizeof(*bi->p_fsyms), __cmp_symbols);
	return SUCCESS;
EXIT:
	free_bi_syms(bi);
	return FAILURE;
}

/* We check all section because HAS_DEBUG never set in abfd->flags */
static void chk_has_debuginfo(struct bfd_if *bi)
{
	asection *s;

	for (s = bi->abfd->sections; s; s = s->next)
		if (s->flags & SEC_DEBUGGING) {
			bi->has_debuginfo = TRUE;
			break;
		}
}

#ifdef HAVE_LIBDW
int init_dwarf(struct bfd_if *bi, const char *obj_name)
{
	int argi, n = 3;
	char *s[] = { "", "-e", (char*)obj_name, NULL };

	argp_parse(dwfl_standard_argp(), n, s, 0, &argi, &bi->dwfl);
	if (!bi->dwfl)
		return FAILURE;
	return SUCCESS;
}
#else
int init_dwarf(struct bfd_if *bi, const char *obj_name) { return SUCCESS; }
#endif

int init_bfd_if(struct bfd_if *bi, const char *__obj_name, const char *kallsyms,
		char *mod_name, struct imf_bi_info *imf_info)
{
	struct disassemble_info *info = &bi->info;
	char *obj_name = strdup(__obj_name);
	int len;

	memset(bi, 0, sizeof(*bi));

	if (chk_elf_header(bi, obj_name) == FAILURE) {
		if (ignore_elf_errors) {
			fprintf(stderr, "cannot recognize %s as valid"
					" ELF. btrax ignore this file\n",
					obj_name);
			return SKIP;
		}
		return FAILURE;
	}

	bi->abfd = bfd_openr(obj_name, NULL);
	if (!bi->abfd) {
		fprintf(stderr, "%s bfd_openr failed.\n", obj_name);
		return FAILURE;
	}
	if (!bfd_check_format(bi->abfd, bfd_object)) {
		fprintf(stderr, "%s bfd_check_format failed.\n", obj_name);
		return FAILURE;
	}
	len = strlen(obj_name);
	chk_valid_code_sects(bi, (strcmp2const_str(obj_name + len - MOD_EXT_LEN,
						   MOD_EXT) == 0));
	if (build_sorted_func_symbols(bi, obj_name, kallsyms, mod_name,
				      imf_info) == FAILURE)
		return FAILURE;

	init_disassemble_info(info, stdout, (fprintf_ftype)fprintf);
	info->flavour = bfd_get_flavour(bi->abfd);
	info->arch = bfd_get_arch(bi->abfd);
	info->mach = bfd_get_mach(bi->abfd);
	info->disassembler_options = NULL;
	info->octets_per_byte = bfd_octets_per_byte(bi->abfd);

	if (bfd_big_endian(bi->abfd))
		info->display_endian = info->endian = BFD_ENDIAN_BIG;
	else if (bfd_little_endian(bi->abfd))
		info->display_endian = info->endian = BFD_ENDIAN_LITTLE;
	else
		info->endian = BFD_ENDIAN_UNKNOWN;
	disassemble_init_for_target(info);
	chk_has_debuginfo(bi);
	return SUCCESS;
}

unsigned long get_offset_addr(struct bfd_if *bi, unsigned long begin)
{
	if (bfd_get_file_flags(bi->abfd) & HAS_RELOC)
		return begin;
	return begin - bi->load_vaddr;
}

/* This function is specified for kernel. It doesn't calculate section offset.
 */
void get_kernel_min_max_addr(struct bfd_if *bi,
			     unsigned long *min, unsigned long *max)
{
	bfd_vma sect_max;
	int i;
	asection *s;

	*min = KERNEL_END;	// all '1'
	*max = USER_START;	// all '0'
	for (i = 0; i < bi->n_code_sects; i++) {
		s = bi->p_code_sects[i].section;
		if ((unsigned long)s->vma < *min)
			*min = (unsigned long)s->vma;
		sect_max = s->vma + bfd_get_section_size(s) - 1;
		if ((unsigned long)sect_max > *max)
			*max = (unsigned long)sect_max;
	}
	return;
}

void remove_useless_fsyms(struct bfd_if *bi, unsigned long begin,
			  unsigned long end, unsigned long offset)
{
	long i, cnt;
	asymbol *sym, **symbols = bi->p_fsyms;
	bfd_vma val, prev_val = KERNEL_END;	// all '1'
	asection *sect;

	cnt = 0;
	for (i = 0; i < bi->n_fsyms; i++) {
		sym = symbols[i];
		val = bfd_asymbol_value(sym);
		sect = sym->section;
		if (!is_code_sect(sect))
			continue;
		if (val < sect->vma ||
		    val >= sect->vma + bfd_get_section_size(sect))
			continue;
		if ((unsigned long)val + offset < begin ||
		    (unsigned long)val + offset > end)
			continue;

		if (val != prev_val) {
			symbols[cnt++] = sym;
			prev_val = val;
		}
	}
	bi->n_fsyms = cnt;
}

/*-----------------------------------------------------------------------------
 *  branch check
 *-----------------------------------------------------------------------------
 */
static int btype;
static unsigned long baddr;

#define PRINT_BUF_MAX	128
static char print_buf[PRINT_BUF_MAX + 1];
static int seq_num;
static int offset;
static int baddr_offset;


static int chk_btype_dummy_fprintf(FILE *stream, const char *fmt, ...)
{
	va_list argp;
	int rc;
	char *p_tmp;

	va_start(argp, fmt);
	rc = vsnprintf(print_buf, PRINT_BUF_MAX, fmt, argp);
	if (rc >= PRINT_BUF_MAX) {
		fprintf(stderr, "!!!Too short print_insn buffer size=%d\n",
			PRINT_BUF_MAX);
		exit(EXIT_FAILURE);
	}
	va_end(argp);

	switch (seq_num) {
	case 0:
		if (strcmp2const_str(print_buf, "jmp") == 0 ||
		    strcmp2const_str(print_buf, "ljmp") == 0) {
			btype = BTYPE_JMP;
		} else if (print_buf[0] == 'j' ||
			   strcmp2const_str(print_buf, "loop") == 0) {
			btype = BTYPE_BRANCH;
		} else if (strcmp2const_str(print_buf, "call") == 0) {
			btype = BTYPE_CALL;
		} else if (strcmp2const_str(print_buf, "ret") == 0) {
			btype = BTYPE_RET;
		} else if (strcmp2const_str(print_buf, "iret") == 0 ||
			   strcmp2const_str(print_buf, "sysexit") == 0) {
			btype = BTYPE_IRET;
		} else if (strcmp2const_str(print_buf, "int") == 0 ||
			   strcmp2const_str(print_buf, "sysenter") == 0) {
			btype = BTYPE_INT;
		} else if (strcmp2const_str(print_buf, "ud2") == 0) {
			btype = BTYPE_BREAK;
		} else
			btype = BTYPE_OTHER;
		baddr = 0;
		break;
	case 1:
		switch (btype) {
		case BTYPE_JMP:
		case BTYPE_BRANCH:
		case BTYPE_CALL:
			baddr = strtoul(print_buf, &p_tmp, 0);
			if (p_tmp - print_buf != rc)
				baddr = UNKNOWN_BADDR;
			break;
		}
		break;
	case 2:
		if (btype != BTYPE_OTHER && baddr != UNKNOWN_BADDR) {
			fprintf(stderr, "!!!Sequence error in print_insn");
			exit(EXIT_FAILURE);
		}
		break;
	}
	seq_num++;

	return rc;
}

static int __get_branch_info(struct bfd_if *bi, unsigned long addr, int *type,
			     unsigned long *addr_next,
			     unsigned long *addr_branch)
{
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
	return SUCCESS;
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

static int cmp_path_to_addr(struct path *p, unsigned long addr)
{
	//if (p->cnt < 0) {
		if (addr < p->addr)
			return -1;
		if (addr >= p->addr + p->length)
			return 1;
	/*} else {
		if (addr < p->addr)
			return -1;
		if (addr >= p->next)
			return 1;
	}
	*/
	return 0;
}

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

static int f_find_path_in_array(const void *p1, const void *p2)
{
	unsigned long addr = *((unsigned long*)p1);
	struct path *p = *(struct path**)p2;

#ifdef DBG_CHK_PATH
	printf("DBG:0x%08lx:0x%08lx\n", addr, p->addr);
#endif
	return cmp_path_to_addr(p, addr);
}

struct path* find_path_in_path_array(struct path **tree, int *cnt,
				     unsigned long addr)
{
	struct path **p;

	p = (struct path**)bsearch(&addr, tree, *cnt, sizeof(*p),
				   f_find_path_in_array);
	if (p) {
		*cnt = p - tree;
		return *p;
	} else
		return NULL;
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
	p = xmalloc(sizeof(*p));
	*p = addr;
	*node_addrs = insert_tree(p, *node_addrs, f_chk_addr, free);
	return *node_addrs == NULL ? FAILURE : SUCCESS;
}

/*
 * Check ud2 instruction from 'begin' to 'end', and return the possibility
 * of having source information.
 * If no source information found, this function returns -1.
 */
#ifdef __i386__
int __chk_ud2_src_info(struct bfd_if *bi, unsigned long begin,unsigned long end)
{
	unsigned long addr, next, branch;
	int rc, type;
	struct sect_cache *cache = &bi->cache;

	for (addr = begin; addr < end; addr = next) {
		rc = __get_branch_info(bi, addr, &type, &next, &branch);
		if (rc != SUCCESS) {
			fprintf(stderr, "__get_branch_info failed at 0x%08lx",
				addr);
			fprintf(stderr, ".(%d)\n", rc);
			return -1;
		}
		/* check ud2 instruction */
		if (type != BTYPE_BREAK ||
		    cache->data[addr - (unsigned long)cache->vma] != 0x0f ||
		    cache->data[addr - (unsigned long)cache->vma + 1] != 0x0b)
			continue;
		/* Caution:
		 * At this point, we have to finish checking this function
		 * because we don't know whether we should skip source
		 * information right now.
		 * So, we continue checking from next function's top address.
		 */
		/* ud2 instruction (2bytes) and src info (6bytes) */
		addr += 2 + 5;
		if (addr < (unsigned long)cache->vma ||
		    addr >= (unsigned long)(cache->vma + cache->size))
			return -1;
		return (cache->data[addr - (unsigned long)cache->vma]
				== (addr >> 24));
	}
	return -1;
}
#else // __x86_64__
int __chk_ud2_src_info(struct bfd_if *bi, unsigned long begin,unsigned long end)
{
	/* On the x86_64 arch, the bug frame only need to be skipped for
	 * before 2.6.12 kernel. After 2.6.13 kernel, the bug frames are into
	 * valid instructions.
	 */
	return -1;
}
#endif

#define MAX_CHK_UD2	10
#define MAX_CHK_FUNC	100
bool_t kernel_has_ud2_src_info(struct bfd_if *bi)
{
	int rc, i, cnt, func_cnt;
	asymbol *sym, *sym2;
	asection *s;
	unsigned long begin, end, sect_end;

	cnt = func_cnt = 0;
	for (i = 0; i + 1 < bi->n_fsyms && func_cnt < MAX_CHK_FUNC; i++) {
		sym = bi->p_fsyms[i];
		sym2 = bi->p_fsyms[i+1];
		if (!(sym->flags & BSF_FUNCTION))
			continue;
		if (!cnt)
			func_cnt++;
		/* get 'begin' and 'end' addresses */
		begin = (unsigned long)bfd_asymbol_value(sym);
		end = (unsigned long)bfd_asymbol_value(sym2);
		s = get_sect_has_addr(bi, begin);
		sect_end = (unsigned long)(s->vma + bfd_get_section_size(s));
		if (end > sect_end)
			end = sect_end;
		//printf("checking <%s>:%08lx-%08lx\t", sym->name, begin, end);
		rc = __chk_ud2_src_info(bi, begin, end);
		switch (rc) {
		case -1:
			//printf("---\n");
			continue;
		case 0:
			//printf("ud2 (NO src info)\n");
			return 0;
		case 1:
			//printf("ud2 (WITH src info)\n");
			if (++cnt >= MAX_CHK_UD2)
				return TRUE;
		}
	}
	return FALSE;
}

struct arg_do_for_debuginfo_func {
	int (*func)(struct bfd_if*, unsigned long, void*);
	struct bfd_if *bi;
	void *data;
	Dwarf_Addr dwbias;
};

#ifdef HAVE_LIBDW
struct path_info {
	struct bfd_if *bi;
	struct path **parray;
	int cnt;
	Dwarf_Addr dwbias;
};

static int do_for_debuginfo_func(Dwarf_Die *func, void *__arg)
{
	struct arg_do_for_debuginfo_func *arg = __arg;
	int rc;
	Dwarf_Addr lo = -1;

	if (dwarf_func_inline(func))
		return DWARF_CB_OK;
	if (dwarf_lowpc(func, &lo))
		return DWARF_CB_OK;
	lo += arg->dwbias;
	if (lo < arg->bi->begin || lo > arg->bi->end)
		return DWARF_CB_OK;

	rc = arg->func(arg->bi, (unsigned long)lo, arg->data);
	return (rc == FAILURE) ? DWARF_CB_ABORT : DWARF_CB_OK;
}
static void do_for_all_debuginfo_funcs(struct bfd_if *bi,
				       struct arg_do_for_debuginfo_func *arg)
{
	Dwarf_Die *cu = NULL;

	if (!bi->dwfl)
		return;
	while ((cu = dwfl_nextcu(bi->dwfl, cu, &arg->dwbias)) != NULL)
		dwarf_getfuncs(cu, do_for_debuginfo_func, arg, 0);
}
#else
static void do_for_all_debuginfo_funcs(struct bfd_if *bi,
				       struct arg_do_for_debuginfo_func *arg){}
#endif

static int
for_each_func_and_section_start(struct bfd_if *bi,
				int (*func)(struct bfd_if*,unsigned long,void*),
				void *data)
{
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
	return ALL_DONE;
}

static int
add_node_addrs_wrapper(struct bfd_if *bi, unsigned long addr, void *data)
{
	return add_node_addrs(bi, NULL, data, addr);
}

static int add_func_and_section_start_addrs(struct bfd_if *bi,
					    node **node_addrs)
{
	return for_each_func_and_section_start(bi, add_node_addrs_wrapper,
					       node_addrs);
}

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
			fprintf(stderr, "__get_branch_info failed at 0x%08lx",
				addr);
			fprintf(stderr, ".(%d)\n", rc);
			return FAILURE;
		}
		if (type == BTYPE_OTHER && next < max)
			continue;

		p = xcalloc(1, sizeof(*p));
		p->addr = begin;
		p->cnt = -1;
		p->type = type;
		p->base = addr;
		p->next = next;
		p->jmp_to.addr = branch;
		/* When switch case jump, set next_cnt value to -1. */
		p->next_cnt = type == BTYPE_JMP ? -1 : 0;
		*pt = insert_tree(p, *pt, f_chk_addr, free);
		if (skip_ud2_srcinfo && type == BTYPE_BREAK)
			break;
		if (!is_reloc_branch(bi, addr)) {
			if ((rc = add_node_addrs(bi, *pt, node_addrs, branch))
			    == FAILURE)
				return rc;
		}
		/* When switch case jmp, we need to check the next code */
		if ((rc = add_node_addrs(bi, *pt, node_addrs, next)) == FAILURE)
			return rc;
		break;
	}
	return CONTINUE;
}

static int f_chk_each_node_addr(void *elem, void *data)
{
	unsigned long addr = *((unsigned long*)elem);
	pack_bi_pt *pack = data;
	node **node_addrs = &pack->node_addrs;
	asection *s = get_sect_has_addr(pack->bi, addr);

	if (!s)
		return CONTINUE;
	if (chk_one_node_addr(pack->bi, addr,
			      (unsigned long)s->vma + bfd_get_section_size(s),
			      node_addrs, &pack->pt, pack->skip_ud2_srcinfo)
	    == FAILURE)
		return FAILURE;
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
	__pt = xmalloc(sizeof(*__pt) * (*cnt));
	conv_id = 0;
	for_each_node(pt, f_conv_node_tree_to_array, __pt);
	free_tree(pt, NULL);

	*pt_array = __pt;
	return SUCCESS;
}

static int fix_path_base(struct bfd_if *bi, struct path *p)
{
	unsigned long addr, next, branch;
	int rc, type;

	for (addr = p->addr; addr < p->next; addr = next) {
		rc = __get_branch_info(bi, addr, &type, &next, &branch);
		if (rc != SUCCESS) {
			fprintf(stderr, "__get_branch_info failed at 0x%08lx",
				addr);
			fprintf(stderr, ".(%d)\n", rc);
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
	unsigned long next, branch;

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
			fprintf(stderr, "fix_all_path failed at 0x%08lx.(%d)\n",
				p->base, rc);
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

#ifdef HAVE_LIBDW
static int
validate_func_path(Dwarf_Die *func, void *arg)
{
	Dwarf_Addr lo = -1, hi = -1;
	struct path_info *pi = arg;
	int i;
	struct path *p;

	if (dwarf_func_inline(func))
		return DWARF_CB_OK;
	if (dwarf_lowpc(func, &lo) || dwarf_highpc(func, &hi))
		return DWARF_CB_OK;
	lo += pi->dwbias;
	hi += pi->dwbias;
	if (lo < pi->bi->begin || lo > pi->bi->end)
		return DWARF_CB_OK;

	i = pi->cnt;
	p = find_path_in_path_array(pi->parray, &i, lo);
	if (!p) {
		fprintf(stderr, "function(0x%08lx:%s) not found in paths\n",
			(unsigned long)lo, dwarf_diename(func));
		return DWARF_CB_ABORT;
	}
	for (; i < pi->cnt; i++) {
		p = pi->parray[i];
		p->cnt = 0;
		if (p->next >= hi)
			break;
	}
	return DWARF_CB_OK;
}

static int
validate_to_next_func(struct bfd_if *bi, unsigned long addr, void *data)
{
	struct path_info *pi = data;
	int i;
	struct path *p;

	// 'next_func' means already checked path.
	i = pi->cnt;
	p = find_path_in_path_array(pi->parray, &i, addr);
	if (!p) {
		fprintf(stderr, "BUG: path of the address(0x%08lx) not found\n",
			addr);
		return FAILURE;
	}
	for (; i < pi->cnt; i++) {
		p = pi->parray[i];
		if (p->cnt == 0)	// already checked?
			break;
		p->cnt = 0;
	}
	return CONTINUE;
}

static int
validate_from_func_and_section_start(struct bfd_if *bi, struct path_info *pi)
{
	return for_each_func_and_section_start(bi, validate_to_next_func, pi);
}

static int
validate_path(struct bfd_if *bi, struct path **parray, int *__cnt)
{
	long i, j, cnt = *__cnt;
	struct path_info pi = { bi, parray, *__cnt };
	Dwarf_Die *cu = NULL;
	long n_cu;
	struct path *p;

	if (!bi->dwfl)
		goto VALIDATE_ALL_PATH;

	n_cu = 0;
	while ((cu = dwfl_nextcu(bi->dwfl, cu, &pi.dwbias)) != NULL) {
		n_cu++;
		dwarf_getfuncs(cu, validate_func_path, &pi, 0);
	}
	if (n_cu) {
		// Stub function ('xxx@plt' etc.) and functions which described
		// by assembler language are not validated yet.
		// So, we validate these function's paths here.
		if (validate_from_func_and_section_start(bi, &pi) == FAILURE)
			return FAILURE;

		// Next, we delete the unnecessary paths.
		for (i = 0, j = 0; i < cnt; i++) {
			p = parray[i];
			if (p->cnt < 0)
				continue;
			parray[j++] = p;
		}
		*__cnt = j;
		return SUCCESS;
	}

VALIDATE_ALL_PATH:
	// Kernel modules (bi->dwfl == NULL) and debug-info stripped ELF's case
	validate_all_path(parray, cnt);
	return SUCCESS;
}
#else
static int
validate_path(struct bfd_if *bi, struct path **parray, int *__cnt)
{
	validate_all_path(parray, *__cnt);
}
#endif

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

void free_path(struct path *p)
{
	struct unknown *uk, *next;

	if (!p)
		return;
	if (p->jmp_to.addr == UNKNOWN_BADDR) {
		for (uk = (struct unknown*)p->jmp_cnt; uk; uk = next) {
			next = uk->next;
			free(uk);
		}
	}
	free(p);
}

/*-----------------------------------------------------------------------------
 *  other utility
 *-----------------------------------------------------------------------------
 */
int get_source_info_binutils(struct bfd_if *bi, unsigned long addr,
			     const char **src_name, const char **func_name,
			     int *lno);
#ifdef HAVE_LIBDW
struct arg_chk_inline_func
{
	Dwarf_Die *cudie;
	Dwarf_Addr addr, bias;
	bool_t is_inline;
	const char *file;
	int line;
	int col;
};

static int
chk_inline_func(unsigned int depth, Dwarf_Die *die, void *arg)
{
	struct arg_chk_inline_func *info = arg;
	Dwarf_Attribute attr_mem;
	Dwarf_Files *files;
	Dwarf_Word val;

	if (dwarf_tag(die) != DW_TAG_inlined_subroutine)
		return DWARF_CB_OK;
	if (!dwarf_haspc(die, info->addr))
		return DWARF_CB_OK;
#if DEBUG
	printf("%d-%02x,%08lx:%08lx,%s(%d)\n", depth,
	       dwarf_tag(die),
	       (unsigned long)lo, (unsigned long)hi,
	       dwarf_diename(die),
	       dwarf_func_inline(die));
#endif

	// found matched inline function
	if (!dwarf_hasattr(die, DW_AT_abstract_origin))
		return DWARF_CB_ABORT;

	// get source information
	if (dwarf_getsrcfiles(info->cudie, &files, NULL) != 0)
		return DWARF_CB_ABORT;
	if (dwarf_formudata(dwarf_attr(die, DW_AT_call_file, &attr_mem),
			    &val) != 0)
		return DWARF_CB_ABORT;
	info->file = dwarf_filesrc(files, val, NULL, NULL);
	if (dwarf_formudata(dwarf_attr(die, DW_AT_call_line, &attr_mem),
			    &val) != 0)
		return DWARF_CB_ABORT;
	info->line = val;
	info->col = 0;
	info->is_inline = TRUE;
	return DWARF_CB_ABORT;
}

static int
libdw_visit_scopes(depth, root, previsit, arg)
	unsigned int depth;
	Dwarf_Die *root;
	int (*previsit)(unsigned int depth, Dwarf_Die*, void*);
	void *arg;
{
	Dwarf_Die child;
	int result;
	Dwarf_Attribute attr_mem, *attr;

	if (dwarf_child(root, &child) != 0)
		return -1;

	inline int recurse (void) {
		return libdw_visit_scopes(depth + 1, &child, previsit, arg);
	}

	do {
		if (previsit != NULL) {
			result = (*previsit)(depth + 1, &child, arg);
			if (result != DWARF_CB_OK)
				return result;
		}
		switch (dwarf_tag(&child)) {
		case DW_TAG_compile_unit:
		case DW_TAG_module:
		case DW_TAG_lexical_block:
		case DW_TAG_with_stmt:
		case DW_TAG_catch_block:
		case DW_TAG_try_block:
		case DW_TAG_entry_point:
		case DW_TAG_inlined_subroutine:
		case DW_TAG_subprogram:
		case DW_TAG_namespace:
			if (dwarf_haschildren(&child)) {
				result = recurse();
				if (result != DWARF_CB_OK)
					return result;
			}
			break;
		case DW_TAG_imported_unit:
			attr = dwarf_attr(&child, DW_AT_import, &attr_mem);
			if (dwarf_formref_die(attr, &child) != NULL) {
				result = recurse();
				if (result != DWARF_CB_OK)
					return result;
			}
			break;
		default:
			break;
		}
	} while (dwarf_siblingof(&child, &child) == 0);
	return 0;
}

static Dwarf_Die last_cudie;
static Dwarf_Die last_func;
static Dwarf_Addr last_lo, last_hi;

static int
chk_dies_of_func(Dwarf_Die *func, void *arg)
{
	if (!func)
		return DWARF_CB_ABORT;
	return libdw_visit_scopes(0, func, &chk_inline_func, arg);
}

static int
chk_func_die(Dwarf_Die *func, void *arg)
{
	struct arg_chk_inline_func *info = arg;
	Dwarf_Addr lo = -1, hi = -1;

	if (dwarf_func_inline(func))
		return DWARF_CB_OK;
	if (dwarf_lowpc(func, &lo) || dwarf_highpc(func, &hi))
		return DWARF_CB_OK;
	lo += info->bias;
	hi += info->bias;
	if (info->addr < lo || info->addr >= hi)
		return DWARF_CB_OK;

	chk_dies_of_func(func, arg);
	last_cudie = *info->cudie;
	last_func = *func;
	last_hi = hi;
	last_lo = lo;
	return DWARF_CB_ABORT;
}

static bool_t
get_inline_func_info(Dwfl_Module *mod, Dwarf_Addr addr,
		     const char **file, int *line, int *col)
{
	Dwarf_Die *cudie;
	struct arg_chk_inline_func info = { NULL, addr, 0, FALSE, NULL, 0, 0 };

	if ((cudie = dwfl_module_addrdie(mod, addr, &info.bias)) == NULL)
		return FALSE;

	info.cudie = cudie;

	if (last_cudie.cu == cudie->cu && addr >= last_lo && addr < last_hi)
		chk_dies_of_func(&last_func, &info);
	else
		dwarf_getfuncs(cudie, chk_func_die, &info, 0);
	if (!info.is_inline)
		return FALSE;
	if (file)
		*file = info.file;
	if (line)
		*line = info.line;
	if (col)
		*col = info.col;
	return TRUE;
}

static int
get_source_info_elfutils(struct bfd_if *bi, unsigned long addr,
			 const char **comp_dir, const char **src_name,
			 const char **func_name, int *lno,
			 bool_t need_inline_func_caller)
{
	Dwfl_Module *mod = NULL;
	Dwfl_Line *line = NULL;
	Dwarf_Addr a = addr;

	*src_name = *func_name = NULL; /* func_name is not used */
	*lno = 0;

	mod = dwfl_addrmodule(bi->dwfl, a);
	line = dwfl_module_getsrc(mod, a);
#if 1   // "#if 0" for REGRESSION CHECKING
	if (need_inline_func_caller &&
	    get_inline_func_info(mod, a, src_name, lno, NULL))
		goto GET_COMP_DIR;
#endif
	if (!line ||
	    !(*src_name = dwfl_lineinfo(line, &a, lno, NULL, NULL, NULL)))
		return FAILURE;
GET_COMP_DIR:
	if (*src_name[0] != '/')
		*comp_dir = dwfl_line_comp_dir(line);
	return SUCCESS;
}

inline int get_source_info(struct bfd_if *bi, unsigned long addr,
			   const char **comp_dir, const char **src_name,
			   const char **func_name, int *lno,
			   bool_t need_inline_func_caller)
{
	if (bi->dwfl)
		return get_source_info_elfutils(bi, addr, comp_dir, src_name,
						func_name, lno,
						need_inline_func_caller);
	else
		return get_source_info_binutils(bi, addr, src_name, func_name,
						lno);
}
#else
inline int get_source_info(struct bfd_if *bi, unsigned long addr,
			   const char **comp_dir, const char **src_name,
			   const char **func_name, int *lno,
			   bool_t need_inline_func_caller)
{
	return get_source_info_binutils(bi, addr, src_name, func_name, lno);
}
#endif //HAVE_LIBDW

int get_source_info_binutils(struct bfd_if *bi, unsigned long addr,
			     const char **src_name, const char **func_name,
			     int *lno)
{
	int rc;
	asection *sect;

	*src_name = *func_name = NULL;
	*lno = 0;
#ifdef TEST
	return FAILURE;
#endif
	if (!bi->has_debuginfo)
		return FAILURE;
	sect = get_sect_has_addr(bi, addr);
	if (!sect)
		return FAILURE;
	rc = bfd_find_nearest_line(bi->abfd, sect,
				   bi->n_syms ? bi->p_syms : bi->p_dynsyms,
				   (bfd_vma)addr - sect->vma,
				   src_name, func_name, (unsigned int*)lno);
	return (rc ? SUCCESS : FAILURE);
}

/* This function nearly equal bsearch(3).
 * Except, this function also returns small index if not match found.
 */
static void* __bsearch(const void *key, const void *base, size_t nmemb,
		       size_t size, int (*cmp)(const void*, const void*),
		       size_t *small_index)
{
	size_t min, max, mid = 0;
	const void *p;
	int rc = 0;

	min = 0;
	max = nmemb;
	while (min < max) {
		mid = (min + max) / 2;
		p = (void *)(((const char *)base) + (mid * size));
		rc = (*cmp)(key, p);
		if (rc < 0)
			max = mid;
		else if (rc > 0)
			min = mid + 1;
		else {
			if (small_index)
				*small_index = mid;
			return (void*)p;
		}
	}
	if (small_index)
		*small_index = rc > 0 ? mid : mid - 1;
	return NULL;
}

static int __cmp_fsym_addr(const void *key, const void *elem)
{
	unsigned long addr = *(unsigned long*)key;
	asymbol *sym = *(asymbol**)elem;
	unsigned long sym_addr = (unsigned long)bfd_asymbol_value(sym);

	if (addr > sym_addr)
		return 1;
	else if (addr < sym_addr)
		return -1;
	return 0;
}

/* addr is relative */
int addr_to_func_name_and_offset(struct bfd_if *bi, unsigned long addr,
				 const char **func_name, size_t *foffset)
{
	asymbol *sym, **p_sym;
	size_t sym_index;

	if (addr == UNKNOWN_BADDR)
		goto NOT_FOUND;
	p_sym = __bsearch(&addr, bi->p_fsyms, bi->n_fsyms, sizeof(*bi->p_fsyms),
			  __cmp_fsym_addr, &sym_index);
	if (!p_sym) {
		if (sym_index == -1)
			goto NOT_FOUND;
		sym = bi->p_fsyms[sym_index];
	} else
		sym = *p_sym;
	*func_name = sym->name;
	*foffset = addr - (unsigned long)bfd_asymbol_value(sym);
	return SUCCESS;

NOT_FOUND:
	*func_name = "";
	*foffset = 0;
	return FAILURE;
}

static int dummy_sprintf(FILE *stream, const char *fmt, ...)
{
	va_list argp;
	int rc;

	va_start(argp, fmt);
	if (seq_num == 1)
		baddr_offset = offset;
	rc = vsnprintf(&print_buf[offset], PRINT_BUF_MAX - offset, fmt, argp);
	if (rc < 0)
		return -1;
	offset += rc;
	seq_num++;
	va_end(argp);
	return 0;
}

void printf_func_name(const char *func_name, size_t offset)
{
	if (offset)
		printf("<%s+" PF_LH_NC ">", func_name, offset);
	else
		printf("<%s>", func_name);
}

int printf_mnemonic(struct bfd_if *bi, unsigned long addr,
		    unsigned long *p_baddr)
{
	int rc;
	char *p_tmp;
	struct disassemble_info *info = &bi->info;
	fprintf_ftype func_save;

	if (prepare_print_insn(bi, addr) == FAILURE)
		return FAILURE;

	seq_num = 0;
	offset = baddr_offset = 0;
	func_save = info->fprintf_func;
	info->fprintf_func = (fprintf_ftype)dummy_sprintf;
	rc = print_insn_i386_att(addr, &bi->info);
	info->fprintf_func = func_save;
	
	if (p_baddr) {
		*p_baddr = UNKNOWN_BADDR;
		if (baddr_offset > 0) {
			*p_baddr = strtoul(print_buf + baddr_offset, &p_tmp, 0);
			if (*p_tmp != '\0')
				*p_baddr = UNKNOWN_BADDR;
		}
	}
	if (rc >= 0) {
		printf("%s", print_buf);
		return SUCCESS;
	}
	return FAILURE;
}

static bfd_vma get_sect_offset(struct bfd_if *bi, asection *sect)
{
	bfd_vma sect_offset;
	asection *s;

	if (!(bfd_get_file_flags(bi->abfd) & HAS_RELOC))
		return 0;
	// 'sect_offset' is updated by each section, so, we do this by
	// abfd->sections' order and doesn't use the p_code_sects order.
	sect_offset = 0;
	for (s = bi->abfd->sections; s; s = s->next) {
		/* If the section address already set, then do not add the
		 * section offset (e.g. relocatable kernel).
		 */
		if (!is_valid_code_sect(bi, s) || s->vma)
			continue;
		if (s == sect)
			return sect_offset;
		sect_offset += bfd_get_section_size(s);
	}
	return sect_offset;
}

static int __for_each_fsyms(struct bfd_if *bi,
			    int (*f)(unsigned long,unsigned long, const char*,
				     void*),
			    void *data)
{
	int rc;
	long i;
	asymbol *sym, **symbols = bi->p_fsyms;
	bfd_vma val, sect_offset;
	asection *sect;

	for (i = 0; i < bi->n_fsyms; i++) {
		sym = symbols[i];
		val = bfd_asymbol_value(sym);
		sect = sym->section;
		sect_offset = get_sect_offset(bi, sect);
		rc = f((unsigned long)val, (unsigned long)sect_offset,
		       sym->name, data);
		if (rc != CONTINUE)
			return rc;
	}
	return ALL_DONE;
}

int for_each_fsymbols(struct bfd_if *bi, t_func_for_fsym f, void *data)
{
	int rc;
	long i;
	asymbol *sym, **symbols = bi->p_fsyms;
	bfd_vma val, sect_offset;
	asection *sect;

	for (i = 0; i < bi->n_fsyms; i++) {
		sym = symbols[i];
		val = bfd_asymbol_value(sym);
		sect = sym->section;
		sect_offset = get_sect_offset(bi, sect);
		rc = f((unsigned long)val, sym->name, data);
		if (rc != CONTINUE)
			return rc;
	}
	return ALL_DONE;
}

static int f_print_fsym(unsigned long addr, unsigned long sect_offset,
			const char *name, void *data)
{
	printf("0x%08lx %s\n", addr - sect_offset, name);
	return CONTINUE;
}

void dump_bfd_symbols(struct bfd_if *bi, unsigned long begin, unsigned long end)
{
	printf("------ bfd symbols ------\n");
	__for_each_fsyms(bi, f_print_fsym, NULL);
}

struct find_fsym_data {
	const char *name;
	unsigned long addr;
	int cnt;
};

static int f_find_fsym(unsigned long addr, const char *name, void *data)
{
	struct find_fsym_data *dt = data;

	if (strcmp(name, dt->name) == 0) {
		if (dt->addr == UNKNOWN_BADDR)
			dt->addr = addr;
		dt->cnt++;
	}
	return CONTINUE;
}

/* This function returns the address of the data-symbol.
 * If there are multi entries, then returns the first-found value.
 */
int get_data_addr_of_symbol(struct bfd_if *bi, const char *symstr,
			    unsigned long *addr)
{
	int i;
	asymbol *sym;

	for (i = 0; i < bi->n_syms; i++) {
		sym = bi->p_syms[i];
		if (strcmp(sym->name, symstr) == 0) {
			*addr = (unsigned long)bfd_asymbol_value(sym);
			return SUCCESS;
		}
	}
	return FAILURE;
}

/* This function returns the number that a function name was found in.
 * In the 'addr' variable, an address of a function found first is set.
 */
int get_addr_of_symbol(struct bfd_if *bi, const char *symstr,
		       unsigned long *addr)
{
	struct find_fsym_data dt;

	dt.name = symstr;
	dt.addr = UNKNOWN_BADDR;	/* initialize */
	dt.cnt = 0;
	for_each_fsymbols(bi, f_find_fsym, &dt);
	if (dt.cnt)
		*addr = dt.addr;
	return dt.cnt;
}

struct find_fsym_all_data {
	const char *name;
	unsigned long *addrs;
	int cnt;
};

static int f_find_fsym_all(unsigned long addr, const char *name, void *data)
{
	struct find_fsym_all_data *dt = data;
	int step = 16;

	if (strcmp(name, dt->name) == 0) {
		if (!(dt->cnt % step)) {
			dt->addrs = xrealloc(dt->addrs,
					     (dt->cnt + step) *
						sizeof(*dt->addrs));
		}
		dt->addrs[dt->cnt++] = addr;
	}
	return CONTINUE;
}

int get_addr_of_symbol_all(struct bfd_if *bi, const char *symstr,
			   unsigned long **addrs)
{
	struct find_fsym_all_data dt;

	dt.name = symstr;
	dt.addrs = NULL;
	dt.cnt = 0;
	for_each_fsymbols(bi, f_find_fsym_all, &dt);
	if (dt.cnt)
		*addrs = dt.addrs;
	return dt.cnt;
}

bool_t get_begin_of_func(struct bfd_if *bi, unsigned long addr,
			 unsigned long *begin)
{
	asymbol *sym, **p_sym;
	size_t sym_index;

	p_sym = __bsearch(&addr, bi->p_fsyms, bi->n_fsyms, sizeof(*bi->p_fsyms),
			  __cmp_fsym_addr, &sym_index);
	if (!p_sym) {
		if (sym_index == -1)
			return FALSE;
		sym = bi->p_fsyms[sym_index];
	} else
		sym = *p_sym;
	*begin = (unsigned long)bfd_asymbol_value(sym);
	return TRUE;
}

bool_t get_end_of_func(struct bfd_if *bi, unsigned long begin,
		       unsigned long *end)
{
	asymbol *sym, **p_sym;
	long i;

	p_sym = bsearch(&begin, bi->p_fsyms, bi->n_fsyms, sizeof(*bi->p_fsyms),
			__cmp_fsym_addr);
	if (!p_sym)
		return FALSE;
	sym = *p_sym;
	i = (p_sym - bi->p_fsyms);
	if (i < bi->n_fsyms - 1) {
		sym = bi->p_fsyms[i + 1];
		*end = (unsigned long)bfd_asymbol_value(sym);
	}
	return TRUE;
}

