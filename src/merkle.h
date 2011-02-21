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

#include <openssl/evp.h>
#include <sys/types.h>

#ifndef __MERKLE__
#define __MERKLE__

#define MD5_DIGEST_LEN      16
#define SHA1_DIGEST_LEN     20
#define SHA256_DIGEST_LEN   32
#define DIGEST_TYPE         SHA256_DIGEST_LEN

typedef int bool_t;
#define TRUE  ((bool_t)1)
#define FALSE ((bool_t)0)

typedef struct {
  unsigned char d[DIGEST_TYPE];
} md_t, *md_pt;

typedef struct {
  md_t md;
  int height;
} stack_node, *stack_pt;

typedef struct {
  int leaf_index;               /* Current index in the AP computation */
  int skewed_index;             /* Current skewed leaf count in the AP computation */
  int skewed_leaves;            /* Number of skewed leaves */
  int balanced_leaves;          /* Number of balanced leaves */
  int max_height;               /* Maximum tree height */
  md_pt s_list;                 /* Pointer to the S vector for the AP computation  */
  md_pt ap_list;                /* Pointer to the AP vector for the AP computation */
  stack_pt tmp_stack;           /* Temporary stack for data manipulation */
  u_char *buf;                  /* Temporary buffer to avoid re/deallocing */
} AP_context, *AP_ctx_pt;

typedef struct {
  FILE* fp;                     /* File pointer */
  int data_len;                 /* Length of the referenced data */
  const EVP_MD *hash_function;  /* Hash function to be used in the Merkle Tree */
  int block_size;               /* Size of the partitioned data blocks */
  md_t root_hash;               /* Computed Root Hash */
  AP_ctx_pt ap_ctx;             /* AP computation context */
} MT_context, *MT_pt;

#endif

int treehash(MT_context *);
int AP(MT_context *, md_t *, int *);
int verify(u_char *, int, int, md_t *, const EVP_MD *, md_t *, int);

