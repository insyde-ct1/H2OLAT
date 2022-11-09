/*****************************************************************************/
/* The development of this program is partly supported by IPA                */
/* (Information-Technology Promotion Agency, Japan).                         */
/*****************************************************************************/

/*****************************************************************************/
/*  chk_repeat.c - check repeat routines                                     */
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
//#include <libiberty.h>
#include "chk_repeat.h"

static struct chk_repeat_funcs *funcs;

#define TYPE_USER		0
#define TYPE_REPEAT		(1 << 31)
#define is_user(e)		!((e)->type & TYPE_REPEAT)
#define get_repeat_cnt(e)	((e)->type & ~TYPE_REPEAT)

struct element {
	unsigned int	type;	/* Lower 31 bits are used for repeat count */
	const void*		dt;
	unsigned short	isTo;
	struct element*	next;
	struct element*	prev;
};

static size_t element_num;	/* used for checking max elements */
static struct element *top;
static struct element *last;

static bool_t has_same_elements(struct element *e1, struct element *e2)
{
	struct element *c1, *c2;

	if (e1->type != e2->type)
		return FALSE;
	if (e1->isTo != e2->isTo)
		return FALSE;
	if (is_user(e1)) {
		if (funcs->cmp)
			return funcs->cmp(e1->dt, e2->dt);
		else
			return FALSE;
	} else {
		for (c1 = (struct element*)e1->dt, c2 = (struct element*)e2->dt;
		     c1 && c2; c1 = c1->next, c2 = c2->next)
			if (!has_same_elements(c1, c2))
				return FALSE;
		return (!c1 && !c2);
	}
}

static void print_element(FILE *f, int nest, struct element *e, unsigned long cnt)
{
	struct element *c;

	if (is_user(e)) {
		if (funcs->print_data)
			funcs->print_data(f, nest, e->dt, cnt, e->isTo);
	} else {
		unsigned long repeat_cnt = 0;
		if (funcs->print_start_repeat) {
			repeat_cnt = get_repeat_cnt(e);
			funcs->print_start_repeat(f, nest, repeat_cnt);
		}
		for (c = (struct element*)e->dt; c; c = c->next)
			print_element(f, nest + 1, c, repeat_cnt);
		if (funcs->print_end_repeat)
			funcs->print_end_repeat(f, nest);
	}
}

static void free_element(struct element *e)
{
	struct element *c, *c_next;

	if (is_user(e)) {
		if (funcs->free)
			funcs->free(e->dt);
	} else {
		for (c = (struct element*)e->dt; c; c = c_next) {
			c_next = c->next;
			free_element(c);
		}
	}
	free(e);
	element_num--;
}

#ifdef DEBUG
static void dump_chk_list_forward()
{
	struct element *e;

	printf("dump (forward) num: %d\n", element_num);
	for (e = top; e; e = e->next)
		print_element(stdout, 0, e, 0);
}
#endif

static void add_element_of(const void *data, unsigned long cnt, unsigned short isTo)
{
	struct element *e;

	e = calloc(1, sizeof(*e));
	e->type = cnt ? (TYPE_REPEAT | cnt) : TYPE_USER;
	e->dt = data;
	e->isTo = isTo;
	if (last) {
		last->next = e;
		e->prev = last;
	} else
		top = e;
	last = e;
	element_num++;
}

static bool_t cmp_elements_p2c(struct element *e1, struct element *e2, size_t n)
{
	size_t i;

	if (is_user(e1))
		return FALSE;
	for (e1 = (struct element*)e1->dt, i = 0; i < n && e1;
	     i++, e1 = e1->next, e2 = e2->next)
		if (!has_same_elements(e1, e2))
			return FALSE;
	return (!e1 && !e2);
}

static bool_t cmp_elements_p2p(struct element *e1, struct element *e2, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++, e1 = e1->next, e2 = e2->next)
		if (!has_same_elements(e1, e2))
			return FALSE;
	return TRUE;
}

void chk_repeat_start(struct chk_repeat_funcs *__funcs)
{
	funcs = __funcs;
	top = last = NULL;
	element_num = 0;
}

static void chk_repeat_core()
{
	size_t len, cnt = 0, i;
	struct element *e1, *e2, *etmp;
	bool_t is_same;

	e2 = last;
	if (!e2)
		return;
	e1 = e2->prev;
	if (!e1)
		return;
	for (len = 1; len < element_num; len++) {
		is_same = cmp_elements_p2c(e2->prev, e2, len);
		if (is_same && get_repeat_cnt(e2->prev) < ~TYPE_REPEAT) {
			e1 = e2->prev;
			e1->type++;
			e1->next = NULL;
			last = e1;
			for (i = 0; i < len; i++, e2 = etmp)
			{
				etmp = e2->next;
				free_element(e2);
			}
			break;
		}
		is_same = cmp_elements_p2p(e1, e2, len);
		if (is_same) {
			cnt = 2;
			last = e1->prev;
			if (last)
				last->next = NULL;
			else
				top = NULL;
			e2->prev->next = NULL;
			add_element_of(e1, (DWORD)cnt, e1->isTo);
			for (i = 0; i < len; i++, e2 = etmp)
			{
				etmp = e2->next;
				free_element(e2);
			}
			break;
		}
		e2 = e2->prev;
		e1 = e1->prev;
		if (!e1)
			break;
		e1 = e1->prev;
		if (!e1)
			break;
	}
	if (cnt)
		chk_repeat_core();
}

void chk_repeat_each(FILE *f, const void* data, unsigned short isTo)
{
	struct element *e;

	if (element_num >= MAX_ELEMENT_NUM) {
		e = top;
		top = e->next;
		top->prev = NULL;
		print_element(f, 0, e, 0);
		free_element(e);
	}
	add_element_of(data, 0, isTo);
	chk_repeat_core();
#ifdef DEBUG
	dump_chk_list_forward();
#endif
}

void chk_repeat_end(FILE *f)
{
	struct element *e, *e_next;

	for (e = top; e; e = e_next) {
		e_next = e->next;
		print_element(f, 0, e, 0);
		free_element(e);
	}
}
