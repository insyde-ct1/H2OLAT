/*****************************************************************************/
/* The development of this program is partly supported by IPA                */
/* (Information-Technology Promotion Agency, Japan).                         */
/*****************************************************************************/

/*****************************************************************************/
/*  avl_tree.h - AVL tree library header                                     */
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

#ifndef __AVLTREE_H__
#define __AVLTREE_H__

typedef struct __node {
	void		*dt;
	struct __node	*left;
	struct __node	*right;
	struct __node	*parent;
	int		balance;
} node;

typedef int (*func_compare)(void *data, void *elem);

typedef int (*func_each)(void *elem, void *data);
/* meaning of the func_each return value is below
 *   0:     continue
 *   other: break and return this (other) value
 */
typedef void (*func_free)(void *elem);
void* search_tree(void*, node*, func_compare);
node* insert_tree(void*, node*, func_compare, func_free);
node* delete_tree(void*, node*, func_compare, func_free);
int for_each_node(node*, func_each, void*);
void dump_tree(node*, func_each, void*);
void free_tree(node*, func_free);
int get_node_cnt(node*);

#endif
