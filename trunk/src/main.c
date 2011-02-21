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
#include <string.h>
#include <errno.h>
#include <openssl/evp.h>
#include <sys/time.h>
#include <sys/types.h>

#include "merkle.h"
#include "utils.h"

int main(int argc, char *argv[]){
  
  MT_pt mt_pt = (MT_context *) calloc(1, sizeof(MT_context));
  FILE *fp, *nfp;
  int data_len;
  int i;
  int ret;
  int bytes_read;
  int index;
  struct timeval tim;
  double t_start, t1, t2, t3;
  
  if (argc < 3){
    printf("Usage: ./merkle filename blocksize\n");
    exit(-1);
  }

  if ((fp = openfile(argv[1])) == NULL){
    perror("openfile");
    return -1;
  }
  
  if ((data_len = get_filesize(argv[1])) == -1){
    perror("get_filesize");
    return -1;
  }

  mt_pt->fp = fp;
  mt_pt->data_len = data_len;
  mt_pt->hash_function = EVP_sha256(); // ATTENTION: NEED TO CHANGE THE MERKLE.H WITH THE
  mt_pt->block_size = atoi(argv[2]);    // LENGTH OF THE DATA STRUCTURE;

  if (mt_pt->data_len < mt_pt->block_size){
    fprintf(stderr, "Error: number of blocks insufficient!\n");
    exit(-1);
  }

  int total_leaves = get_total_num_leaves(mt_pt);
  printf("Total # of blocks = %d\n", total_leaves);
  
  gettimeofday(&tim, NULL);
  t_start = tim.tv_sec + (tim.tv_usec/1000000.0);
  
  treehash(mt_pt);
  printf("Root Hash: ");
  dump_md(&mt_pt->root_hash);
  
  gettimeofday(&tim, NULL);
  t1 = tim.tv_sec + (tim.tv_usec/1000000.0);
  printf("Root hash computation time:\t\t %.3lf\n", (t1 - t_start));  // In seconds
  
  int mt_balanced_height = get_mt_balanced_height(mt_pt);
  u_char buf[mt_pt->block_size];
  md_t **ap_mat = (md_t **) calloc(total_leaves, sizeof(md_t *));
  int ap_len;
  for (i = 0; i < total_leaves; i++){
    ap_mat[i] = (md_t *) calloc(mt_balanced_height + 1, sizeof(md_t));
  }
  
  if ((nfp = openfile(argv[1])) == NULL){
    perror("openfile");
    return -1;
  }
  
  gettimeofday(&tim, NULL);
  t1 = tim.tv_sec + (tim.tv_usec/1000000.0);
  
  for (i = 0; i < total_leaves; i++){
    AP(mt_pt, ap_mat[i], &ap_len);
    //printf("ap_vet[%d]\n", i);
    //dump_list(ap_vet[i], 3);
  }
  
  gettimeofday(&tim, NULL);
  t2 = tim.tv_sec + (tim.tv_usec/1000000.0);
  printf("Authentication Path computation time:\t %.3lf\n", (t2 - t1));


  for (i = 0; i < total_leaves; i++){
    if (i < mt_pt->ap_ctx->skewed_leaves){
      index = i;
      ap_len = mt_balanced_height + 1;
    }
    else {
      index = i - (mt_pt->ap_ctx->skewed_leaves >> 1);
      ap_len = mt_balanced_height;
    }
    
    if ((bytes_read = fread(buf, 1, mt_pt->block_size, nfp)) > 0){
      ret = verify(buf, bytes_read, index, &mt_pt->root_hash, 
		   mt_pt->hash_function, ap_mat[i], ap_len);
      if (ret){
	printf("Error on AP leaf %d\n", i);
      }
    }
  }

  gettimeofday(&tim, NULL);
  t3 = tim.tv_sec + (tim.tv_usec/1000000.0); 
  printf("Authentication Path verification time:\t %.3lf\n", (t3 - t2));

  fclose(mt_pt->fp);
  fclose(nfp);

  for (i = 0; i < total_leaves; i++){
    free(ap_mat[i]);
  }
  free(ap_mat);

  dealloc_ap(&mt_pt->ap_ctx);
  free(mt_pt);

  return 0;
}
