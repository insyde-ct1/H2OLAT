/*****************************************************************************/
/* The development of this program is partly supported by IPA                */
/* (Information-Technology Promotion Agency, Japan).                         */
/*****************************************************************************/

/*****************************************************************************/
/*  chk_repeat.h - check repeat header                                       */
/*  Copyright: Copyright (c) Hitachi, Ltd. 2005-2006,2010                    */
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

#ifndef __CHK_REPEAT_H__
#define __CHK_REPEAT_H__

#include "bt.h"
#include "bt_utils.h"

#define MAX_ELEMENT_NUM	256 //128

struct chk_repeat_funcs {
	bool_t (*cmp)(const void*, const void*);
	void (*free)(const void*);
	void (*print_data)(FILE *, int, const void*, unsigned long, unsigned short);
	void (*print_start_repeat)(FILE *, int, unsigned long);
	void (*print_end_repeat)(FILE *, int);
};

void chk_repeat_start(struct chk_repeat_funcs *__funcs);
void chk_repeat_each(FILE *f, const void* data, unsigned short isTo);
void chk_repeat_end(FILE *f);

#endif /*__CHK_REPEAT_H__*/
