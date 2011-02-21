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
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>
#include <openssl/evp.h>

#include "merkle.h"
#include "utils.h"

int treehash(MT_context *ctx){
  static int skewed_count, height, bytes_read, max_height, num_skewed_leaves;
  skewed_count      = 0;
  height            = 0;
  max_height        = get_mt_balanced_height(ctx);
  num_skewed_leaves = get_num_skewed_leaves(ctx);
  u_char buf[ctx->block_size];
  stack_node vet[max_height + 2];
  stack_pt npt    = vet;
  
  printf("Total number of leaves: %d\n", get_total_num_leaves(ctx));

  while (height < max_height){
    if (check_top2_equal(vet, npt)){
      npt -= 2;
      //dump_md(&npt->md);
      //dump_md(&(npt + 1)->md);
      leafcalc2(npt->md.d, DIGEST_TYPE, (npt + 1)->md.d, DIGEST_TYPE,
		npt->md.d, ctx->hash_function);
      npt->height = (npt + 1)->height + 1;
      npt++;
    }
    else {
      if ((bytes_read = fread(buf, 1, ctx->block_size, ctx->fp)) > 0){
	leafcalc(buf, bytes_read, npt->md.d, ctx->hash_function);
	//dump_md(&npt->md);
	if (skewed_count < num_skewed_leaves){
	  //printf("skewed leaf\n");
	  npt->height = -1;
	  skewed_count++;
	}
	else {
	  //printf("normal leaf\n");
	  npt->height = 0;
	}
	npt++;
      }
    }
    height = vet->height;
  }
  ctx->root_hash = vet->md;

  return 0;
}

/* Initialize the S and AP vectors */
static void init_vectors(MT_context *ctx, md_t *s, md_t *ap){
  static int skewed_count, height, bytes_read, max_height, num_skewed_leaves, pos;
  skewed_count      = 0;
  height            = 0;
  max_height        = get_mt_balanced_height(ctx);
  num_skewed_leaves = get_num_skewed_leaves(ctx);
  pos               = (num_skewed_leaves > 0 ? -1 : 0);
  stack_pt vet      = ctx->ap_ctx->tmp_stack;
  stack_pt npt      = vet;
  
  while (height < max_height){
    if (check_top2_equal(vet, npt)){
      npt -= 2;
      if (pos == (npt + 1)->height){
	*s = npt->md;
	*ap = ((npt + 1)->md);
	ap++;
	s++;
	pos++;
      }
      leafcalc2(npt->md.d, DIGEST_TYPE,
		(npt + 1)->md.d, DIGEST_TYPE,
		npt->md.d, ctx->hash_function);
      npt->height = (npt + 1)->height + 1;
      npt++;
    }
    else {
      if ((bytes_read = fread(ctx->ap_ctx->buf, 1, ctx->block_size, ctx->fp)) > 0){
	leafcalc(ctx->ap_ctx->buf, bytes_read, npt->md.d, ctx->hash_function);
	if (skewed_count < num_skewed_leaves){
	  npt->height = -1;
	  skewed_count++;
	}
	else {
	  npt->height = 0;
	}
	npt++;	
      }
    }
    height = vet->height;
  }
}


/* Computes the sub root hash of a tree */
int skewed_treehash(MT_context *ctx, int startnode, int height, md_t **ret){
  static int offset, c_height, bytes_read, leaf_index, slope;
  long int state    = ftell(ctx->fp);
  offset            = startnode * ctx->block_size;
  c_height          = 0;
  leaf_index        = startnode;
  slope             = skewed_slope(ctx, startnode, height);
  stack_pt vet      = ctx->ap_ctx->tmp_stack;
  stack_pt npt      = vet;

  //printf("Skewed_treehash, startnode: %d total_leaves: %d height=%d\n", startnode, 
  // get_total_num_leaves(ctx), height);
  
  if (startnode < get_total_num_leaves(ctx)){
    fseek(ctx->fp, offset, SEEK_SET);
    
    do{
      if (check_top2_equal(vet, npt)){
	npt -= 2;
	leafcalc2(npt->md.d, DIGEST_TYPE, (npt + 1)->md.d, DIGEST_TYPE,
		  npt->md.d, ctx->hash_function);
	npt->height = (npt + 1)->height + 1;
	npt++;
      }
      else {
	if ((bytes_read = fread(ctx->ap_ctx->buf, 1, ctx->block_size, ctx->fp)) > 0){
	  leafcalc(ctx->ap_ctx->buf, bytes_read, npt->md.d, ctx->hash_function);
	  if (ctx->ap_ctx->skewed_leaves && slope){
	    if (leaf_index < ctx->ap_ctx->skewed_leaves){
	      npt->height = 0;
	      leaf_index++;
	    }
	    else{
	      npt->height = 1;
	    }
	  }
	  else{
	    npt->height = 0;
	  }
	  npt++;
	}
      }
      c_height = vet->height;
    } while (c_height < height);
    
    fseek(ctx->fp, state, SEEK_SET); //Previous state
    **ret = vet->md;
  }
  
  return 0;
}

/* It will store the amount of 'memory size' bytes of hash values
   in order to reduce the AP computation time. It will return it
   in the ap_vector.
*/
void alloc_ap_vector(MT_context *ctx, long memory, md_pt *ap_vector){
  
  long num_blocks = memory / DIGEST_TYPE;
  int tree_height = get_max_bheight(num_blocks);

  ap_vector = (md_pt *) calloc(get_num_balanced_leaves(tree_height), sizeof(md_t));
  
}

/* This function will return the AP hash value from the ap_vector
   located in the 'index' position 
*/
void get_ap(long index, md_pt ap_vector, md_pt *ap_val){

  
}

int AP(MT_context *ctx, md_t *ap, int *ap_len){
  static int h, power, startnode;
  md_t *apt, *spt, *tmp;  
  h                        = 0;
  power                    = 0;
  startnode                = 0;
  AP_ctx_pt *ap_ctx        = &ctx->ap_ctx;
  
  if (*ap_ctx == NULL){
    /* Start new AP computation instance */
    *ap_ctx                    = (AP_ctx_pt) calloc(1, sizeof(AP_context));
    (*ap_ctx)->max_height      = get_mt_balanced_height(ctx);
    (*ap_ctx)->balanced_leaves = get_num_balanced_leaves((*ap_ctx)->max_height);
    (*ap_ctx)->skewed_leaves   = get_num_skewed_leaves(ctx);
    (*ap_ctx)->s_list          = (md_pt)calloc((*ap_ctx)->max_height + 1, sizeof(md_t));
    (*ap_ctx)->ap_list         = (md_pt)calloc((*ap_ctx)->max_height + 1, sizeof(md_t));
    (*ap_ctx)->tmp_stack       = (stack_pt)calloc((*ap_ctx)->max_height + 2, 
						  sizeof(stack_node));
    (*ap_ctx)->buf             = (u_char *)calloc(ctx->block_size + 1, sizeof(char));
    
    /* Rewind the FP (it might have been used by previous instances) */
    rewind(ctx->fp);
    /* Initialize S and AP vectors */
    init_vectors(ctx, (*ap_ctx)->s_list, (*ap_ctx)->ap_list);
  }

  if ((*ap_ctx)->skewed_leaves){
    apt = (*ap_ctx)->ap_list + 1;
    spt = (*ap_ctx)->s_list + 1;
  }
  else{
    apt = (*ap_ctx)->ap_list;
    spt = (*ap_ctx)->s_list;
  }
  
  if ((*ap_ctx)->leaf_index < (*ap_ctx)->balanced_leaves){
    if ((*ap_ctx)->skewed_index < (*ap_ctx)->skewed_leaves){
      //printf("Skewed leaf\n");
      skewed_treehash(ctx, ((*ap_ctx)->skewed_index ^ 1), 0, &ap);
      ap++;
      (*ap_ctx)->skewed_index++;
      *ap_len = (*ap_ctx)->max_height + 1;
    }
    else{
      *ap_len = (*ap_ctx)->max_height;
    }

    for (h = 0; h < (*ap_ctx)->max_height; h++){
      *(ap + h) = *(apt + h);
    }

    if ((((*ap_ctx)->skewed_index ^ 1) % 2 != 0) || // Check if it is right side node
	(*ap_ctx)->skewed_index >= (*ap_ctx)->skewed_leaves){ // Check if it is balanced
      
      for (h = 0; h < (*ap_ctx)->max_height; h++){
	//power = (int) pow(2, h);
	power = (h ? 2 << (h - 1): 1);
	if ((((*ap_ctx)->leaf_index + 1) % power) == 0){
	  *(apt + h) = *(spt + h);
	  tmp = &spt[h];
	  startnode = ((*ap_ctx)->leaf_index + 1 + power) ^ power;
	  //skewed_treehash(ctx, startnode, h, &tmp);
	  if (startnode < ((*ap_ctx)->skewed_leaves >> 1)){
	    //printf("Skewed case\n");
	    skewed_treehash(ctx, startnode << 1, h + 1, &tmp);
	  }
	  else {
	    //printf("Balanced case\n");
	    skewed_treehash(ctx, ((*ap_ctx)->skewed_leaves >> 1) + startnode, h, &tmp);
	  }
	}
      }
      
      (*ap_ctx)->leaf_index++;
    }
    
    return 0;
  }
  
  printf("WARNING: Leaf index overflow!!!\n");
  return -1;
}

int verify(u_char *data, int data_len, int index, md_t *root_hash, 
	   const EVP_MD *hash_func, md_t *ap, int ap_len){

  static int i;
  static md_t tmp;
  
  if (data != NULL && root_hash != NULL && ap != NULL){
    leafcalc(data, data_len, tmp.d, hash_func);

    for(i = 0; i < ap_len; i++){

      if ((index % 2) == 0){
	//dump_md(&tmp);
	//dump_md(ap + i);
	leafcalc2(tmp.d, DIGEST_TYPE,
		  (ap + i)->d, DIGEST_TYPE,
		  tmp.d, hash_func);
      }
      else {
	//dump_md(ap + i);
	//dump_md(&tmp);
	leafcalc2((ap + i)->d, DIGEST_TYPE,
		  tmp.d, DIGEST_TYPE,		  
		  tmp.d, hash_func);
      }
      index /= 2;
    }
    return memcmp(&tmp.d, root_hash, sizeof(md_t));
  }
  
  return -1;
}

