/*****************************************************************************/
/* The development of this program is partly supported by IPA                */
/* (Information-Technology Promotion Agency, Japan).                         */
/*****************************************************************************/

/*****************************************************************************/
/*  avl_tree.c - AVL tree library                                            */
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
#include "avltree.h"
#include "bt.h"

#ifdef AVL_DBG
#  define dprintf(...)	printf(__VA_ARGS__)
#else
#  define dprintf(...)
#endif

static node* data_to_node(void *data)
{
	node *p;

	p = (node*)calloc(1, sizeof(*p));
	p->dt = data;
	return p;
}

static void __free_tree(node *tree, func_free f_free)
{
	if (f_free && tree->dt)
		f_free(tree->dt);
	if (tree)
		free(tree);
}

static node* __search_node(void *data, node *tree, func_compare f_cmp)
{
	int rc;

	while (tree) {
		rc = f_cmp(data, tree->dt);
		if (rc == 0)
			return tree;
		else if (rc < 0)
			tree = tree->left;
		else if (rc > 0)
			tree = tree->right;
	}
	return NULL;
}

void* search_tree(void *data, node *tree, func_compare f_cmp)
{
	tree = __search_node(data, tree, f_cmp);
	if (!tree)
		return NULL;
	return tree->dt;
}

void free_tree(node *tree, func_free f_free)
{
	if (!tree)
		return;
	if (tree->left)
		free_tree(tree->left, f_free);
	if (tree->right)
		free_tree(tree->right, f_free);
	__free_tree(tree, f_free);
}

static node* __rleft(node *p)
{
	node *tmp;

	tmp = p->right;
	tmp->parent = p->parent;
	if ((p->right = tmp->left) != NULL)
		tmp->left->parent = p;
	tmp->left = p;
	p->parent = tmp;
	return tmp;
}

static node* __rright(node *p)
{
	node *tmp;

	tmp = p->left;
	tmp->parent = p->parent;
	if ((p->left = tmp->right) != NULL)
		tmp->right->parent = p;
	tmp->right = p;
	p->parent = tmp;
	return tmp;
}

static node* rleft(node *p, node *pp, int is_right)
{
	if (is_right)
		return (pp->right = __rleft(p));
	else
		return (pp->left = __rleft(p));
}

static node* rright(node *p, node *pp, int is_right)
{
	if (is_right)
		return (pp->right = __rright(p));
	else
		return (pp->left = __rright(p));
}

static void balance_tree(node *p, int from_right, int is_delete)
{
	node *pp;
	int to_right;

	for (; (pp = p->parent); from_right = to_right, p = pp) {
		to_right = p == pp->right;
		if (from_right ^ is_delete) {		/* right heavy */
			if (++(p->balance) > 1) {
				p->balance--;
				switch (p->right->balance) {
				case 1:			/* single rotate */
					dprintf("L rotote(bal)\n");
					p = rleft(p, pp, to_right);
					p->left->balance = 0;
					p->balance = 0;
					break;
				case 0:			/* single rotate */
					dprintf("L rotate(unb)\n");
					p = rleft(p, pp, to_right);
					p->left->balance = 1;
					p->balance = -1;
					break;
				case -1:		/* double rotate */
					dprintf("RL rotate\n");
					rright(p->right, p, 1);
					p = rleft(p, pp, to_right);
					p->left->balance =
						p->balance < 1 ? 0 : -1;
					p->right->balance =
						p->balance > -1 ? 0 : 1;
					p->balance = 0;
					break;
				}
			}
		} else {				/* left heavy */
			if (--(p->balance) < -1) {
				p->balance++;
				switch (p->left->balance) {
				case -1:		/* single rotate */
					dprintf("R rotate(bal)\n");
					p = rright(p, pp, to_right);
					p->right->balance = 0;
					p->balance = 0;
					break;
				case 0:			/* single rotate */
					dprintf("R rotate(unb)\n");
					p = rright(p, pp, to_right);
					p->right->balance = -1;
					p->balance = 1;
					break;
				case 1:			/* double rotate */
					dprintf("LR rotate\n");
					rleft(p->left, p, 0);
					p = rright(p, pp, to_right);
					p->left->balance =
						p->balance < 1 ? 0 : -1;
					p->right->balance =
						p->balance > -1 ? 0 : 1;
					p->balance = 0;
					break;
				}
			}
		}
		if ((p->balance == 0) ^ is_delete)
			break;
	}
}

static node dummy_top;

/* 'tree' must be unique.
 * If the 'f_cmp' function returns '0', then element is not inserted, and
 * 'f_free' function is called.
 */
node* insert_tree(void *data, node *tree, func_compare f_cmp, func_free f_free)
{
	int rc, is_right;
	node *c, *p = NULL;

	if (!tree)
		return data_to_node(data);

	dummy_top.left = tree;
	tree->parent = p = &dummy_top;
	for (c = tree; c;) {
		rc = f_cmp(data, c->dt);
		if (rc == 0) {
			if (f_free)
				f_free(data);
			dummy_top.left->parent = NULL;
			return tree;
		}
		p = c;
		is_right = rc > 0;
		c = is_right ? c->right : c->left;
	}
	c = data_to_node(data);
	if (is_right)
		p->right = c;
	else
		p->left = c;
	c->parent = p;
	balance_tree(p, is_right, 0);
	if (dummy_top.left)
		dummy_top.left->parent = NULL;
	return dummy_top.left;
}

node *delete_tree(void *data, node *tree, func_compare f_cmp, func_free f_free)
{
	node *p, *c, *pp;
	int is_right;

	p = __search_node(data, tree, f_cmp);
	if (!p)
		return tree;

	if (f_free)
		f_free(p->dt);

	if (p->left == NULL)
		c = p->right;
	else if (p->right == NULL)
		c = p->left;
	else {
		for (c = p->left; c->right; c = c->right);
		p->dt = c->dt;
		p = c;
		c = p->left;
	}
	/* move c into where p was. */
	dummy_top.left = tree;
	tree->parent = &dummy_top;

	pp = p->parent;
	is_right = pp->right == p;
	if (is_right)
		pp->right = c;
	else
		pp->left = c;
	if (c)
		c->parent = pp;
	free(p);
	balance_tree(pp, is_right, 1);
	if (dummy_top.left)
		dummy_top.left->parent = NULL;
	return dummy_top.left;
}

int for_each_node(node *tree, func_each f_each, void *data)
{
	int rc;

	if (!tree)
		return ALL_DONE;
	if (tree->left) {
		rc = for_each_node(tree->left, f_each, data);
		if (rc != CONTINUE)
			return rc;
	}
	rc = f_each(tree->dt, data);
	if (rc != CONTINUE)
		return rc;
	if (tree->right) {
		rc = for_each_node(tree->right, f_each, data);
		if (rc != CONTINUE)
			return rc;
	}
	return ALL_DONE;
}

#ifdef AVL_DBG
typedef int (*func_each_with_nest)(int, node*, void*);

int __for_each_node_WN(int nest, node *tree, func_each_with_nest f_each,
		       void *data)
{
	int rc;

	if (!tree)
		return ALL_DONE;
	if (tree->left) {
		rc = __for_each_node_WN(nest+1, tree->left, f_each, data);
		if (rc != CONTINUE)
			return rc;
	}
	rc = f_each(nest, tree, data);
	if (rc != CONTINUE)
		return rc;
	if (tree->right) {
		rc = __for_each_node_WN(nest+1, tree->right, f_each, data);
		if (rc != CONTINUE)
			return rc;
	}
	return ALL_DONE;
}

int for_each_node_with_nest(node *tree, func_each_with_nest f_each, void *data)
{
	return __for_each_node_WN(0, tree, f_each, data);
}

static func_each f_dump_user;

#define MAX_NEST	30
static int f_dump_debug(int nest, node* n, void *data)
{
	int i, nest_spc = 4;
	char *p, buf[nest_spc * MAX_NEST + 1];

	for (p = buf, i = 0; i < nest * nest_spc; i++)
		p[i] = ' ';
	p[i] = '\0';
	printf("%s(b:%2d) ", buf, n->balance);
	f_dump_user(n->dt, data);
	return CONTINUE;
}
#endif

void dump_tree(node *tree, func_each f_each, void *data)
{
#ifdef AVL_DBG
	f_dump_user = f_each;
	for_each_node_with_nest(tree, f_dump_debug, data);
#else
	for_each_node(tree, f_each, data);
#endif
}

static int f_count_nodes(void *elem, void *data)
{
	int *node_cnt = data;

	*node_cnt += 1;
	return CONTINUE;
}
int get_node_cnt(node *tree)
{
	int node_cnt = 0;

	for_each_node(tree, f_count_nodes, &node_cnt);
	return node_cnt;
}
