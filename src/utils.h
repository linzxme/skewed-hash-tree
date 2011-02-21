/*
 * Skewed Hash Tree Library
 * Copyright (C) 2009-2011 - University at Campinas (UNICAMP) - Brazil
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of
 * the BSD license.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 *  Author: Walter Wong <wong@dca.fee.unicamp.br>
 *
 */

#include <math.h>
#include <openssl/evp.h>

#ifndef __UTILS__
#define __UTILS__
#include "merkle.h"
#endif

void dump_MT_context(MT_context *);
void dump_stack_node(stack_node *);
void dump_stack(stack_pt, int);
void dump_md(md_t *);
void dump_list(md_t *, int);
FILE *openfile(char *);
int get_filesize(char *);
int check_null(void *);
int skewed_offset(MT_context *);
int get_mt_balanced_height(MT_context *);
int get_max_bheight(long);
int get_num_skewed_leaves(MT_context *);
int get_num_balanced_leaves(int);
int get_total_num_leaves(MT_context *);
void leafcalc(u_char *, size_t, u_char *, const EVP_MD *);
void leafcalc2(u_char *, size_t, u_char *, size_t, u_char *, const EVP_MD *);
int check_top2_equal(stack_node *, stack_node *);
int skewed_slope(MT_context *, int, int);
void dealloc_ap(AP_context **);
