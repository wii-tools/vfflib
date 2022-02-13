// SPDX-License-Identifier: BSD-2-Clause
// Copyright Spotlight 2022.
//
// This file includes source code from the Limine bootloader.
// Copyright 2019, 2020, 2021, 2022 mintsuki and contributors.

#ifndef __FAT_H__
#define __FAT_H__

#include "volume.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

// Adopted from common/lib/blib.h within Limine.
#define DIV_ROUNDUP(a, b) (((a) + ((b)-1)) / (b))
#define SIZEOF_ARRAY(array) (sizeof(array) / sizeof(array[0]))

struct fat32_context {
  struct volume *part;
  int type;
  uint16_t bytes_per_sector;
  uint8_t sectors_per_cluster;
  uint16_t reserved_sectors;
  uint8_t number_of_fats;
  uint32_t hidden_sectors;
  uint32_t sectors_per_fat;
  uint32_t fat_start_lba;
  uint32_t data_start_lba;
  uint32_t root_directory_cluster;
  uint16_t root_entries;
  uint32_t root_start;
  uint32_t root_size;
};

struct fat32_file_handle {
  struct fat32_context context;
  uint32_t first_cluster;
  uint32_t size_bytes;
  uint32_t size_clusters;
  uint32_t *cluster_chain;
  size_t chain_len;
};

int fat32_check_signature(struct volume *part);

bool fat32_open(struct fat32_file_handle *ret, struct volume *part,
                const char *path);
void fat32_read(struct fat32_file_handle *file, void *buf, uint64_t loc,
                uint64_t count);
void fat32_close(struct fat32_file_handle *file);

#endif