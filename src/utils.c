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

#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "utils.h"

FILE *openfile(char *filename){
  FILE *fp;

  if ((fp = fopen(filename, "r")) < 0){
    perror("fopen");
    return NULL;
  }
  
  return fp;
}

int get_filesize(char *filename){
  struct stat result;
  
  if (filename != NULL){
    if (stat(filename, &result) != -1){
      return result.st_size;      
    }
    else {
      perror("stat");
      return -1;
    }
  }
  
  perror("filename NULL");
  return -1;
}

void dump_md(md_t *md){
  int i;
  for (i = 0; i < DIGEST_TYPE; i++){
    printf("%02X", md->d[i]);
  }
  printf("\n");
}

void dump_list(md_t *list, int len){
  int i;
  for (i = 0; i < len; i++){
    dump_md((list + i));
  }  
}

void dump_stack_node(stack_node *node){
  if (node != NULL){
    printf("height = %d\n", node->height);
  }
}

void dump_stack(stack_pt vet, int len){
  int i;
  for (i = 0; i < len; i++){
    dump_md(&(vet + i)->md);
  }  
}

void dump_MT_context(MT_context *mtctx){

  if (mtctx != NULL){
    printf("Data length: %d\n", mtctx->data_len);
    printf("Block Size: %d\n", mtctx->block_size);
    printf("Root Hash:");
    dump_md(&mtctx->root_hash);
  }
  else {
    printf("MT Context NULL!\n");
  }  
}


int check_null(void *pt){
  if (pt == NULL){
    printf("NULL!\n");
    return 1;
  }
  
  return 0;
}

/* Return total number of leaves in the Skewed Merkle Tree */
int get_total_num_leaves (MT_context *ctx){
  return ceil(ctx->data_len / (double) ctx->block_size);  
}

int skewed_offset(MT_context *ctx){
  return ((get_num_skewed_leaves(ctx) != 0) ? 1 : 0);
}


/* Return the height of the balanced tree inside the Skewed Hash Tree */
int get_mt_balanced_height(MT_context *ctx){
  int nblocks;
  int pow2 = 1;
  int height = -1;
  
  nblocks = get_total_num_leaves(ctx);
  while (pow2 <= nblocks) {
    height++;
    pow2 <<= 1;
  }
  
  return height;
}

/* Return the maximum balanced tree that fits in the 
   amount of memory */
int get_max_bheight(long nblocks){
  int pow2 = 1;
  int height = -1;
  
  while (pow2 <= nblocks) {
    height++;
    pow2 <<= 1;
  }
  
  return height;
}

/* Computes the number of skewed leaves in the Merkle Tree*/
int get_num_skewed_leaves(MT_context *ctx){
  int nblocks;
  int pow2 = 1;
  
  nblocks = get_total_num_leaves(ctx);
  while (pow2 <= nblocks) pow2 <<= 1;
  return ((nblocks - (pow2 >> 1)) << 1);
}

/* Return total number of balanced tree leaves */
int get_num_balanced_leaves(int height){
  int count = 0;
  int leaves = 1;
  
  while (count++ < height)
    leaves <<= 1;
      
  return leaves;
}


void leafcalc(u_char *data, size_t len, u_char *digest, const EVP_MD *type){
  
  EVP_MD_CTX mdctx;
  EVP_MD_CTX_init(&mdctx);
  
  /*
   * arg1 - sets up the message digest context
   * arg2 - type of the message digest (e.g, EVP_sha1())
   * arg3 - implementation version of the message digest type. Default is used when NULL
   */
  EVP_DigestInit_ex(&mdctx, type, NULL);
  EVP_DigestUpdate(&mdctx, data, len);
  EVP_DigestFinal_ex(&mdctx, digest, NULL);
  EVP_MD_CTX_cleanup(&mdctx);
}

void leafcalc2(u_char *data, size_t len, 
	      u_char *data2, size_t len2, 
	      u_char *digest, const EVP_MD *type){

  EVP_MD_CTX mdctx;
  EVP_MD_CTX_init(&mdctx);
  EVP_DigestInit_ex(&mdctx, type, NULL);
  EVP_DigestUpdate(&mdctx, data, len);
  EVP_DigestUpdate(&mdctx, data2, len2);
  EVP_DigestFinal_ex(&mdctx, digest, NULL);
  EVP_MD_CTX_cleanup(&mdctx);
}


int check_top2_equal(stack_node *vet, stack_node *npt){
  if (vet != NULL && npt != NULL && npt - vet > 1){
    return ((npt - 2)->height == (npt - 1)->height);
  }
  
  return 0;
}

/* Check whether the algorithm will encounter a tree slope*/
int skewed_slope(MT_context *ctx, int index, int height){
  
  int tmp = index + (height ? 2 << (height - 1): 1) - 1;
  if ((index < ctx->ap_ctx->skewed_leaves) && (tmp >= ctx->ap_ctx->skewed_leaves)){
    return TRUE;
  }
  
  return FALSE;
}

void dealloc_ap(AP_ctx_pt *ap_ctx){

  if (*ap_ctx != NULL){
    if ((*ap_ctx)->s_list != NULL)
      free((*ap_ctx)->s_list);
    if ((*ap_ctx)->ap_list != NULL)
      free((*ap_ctx)->ap_list);
    if ((*ap_ctx)->tmp_stack != NULL)
      free((*ap_ctx)->tmp_stack);
    if ((*ap_ctx)->buf != NULL)
      free((*ap_ctx)->buf);
    free(*ap_ctx);
    *ap_ctx = NULL;
  }
}
