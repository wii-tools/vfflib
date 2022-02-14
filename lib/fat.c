// SPDX-License-Identifier: BSD-2-Clause
// Copyright Spotlight 2022.
//
// This file includes source code from the Limine bootloader.
// Copyright 2019, 2020, 2021, 2022 mintsuki and contributors.

#include <vfflib/fat.h>
#include <vfflib/volume.h>

#include <ctype.h>
#include <stdbool.h>
#include <string.h>

#include "local_endian.h"

#define FAT32_LFN_MAX_ENTRIES 20
#define FAT32_LFN_MAX_FILENAME_LENGTH (FAT32_LFN_MAX_ENTRIES * 13 + 1)

#define VFF_MAGIC "VFF "
#define VFF_BOM_BE 0xFEFF0100
#define VFF_BOM_LE 0xFFEF0100
#define VFF_HEADER_SIZE 0x20
#define FAT12_VALID_SYSTEM_IDENTIFIER "FAT12   "
#define FAT32_ATTRIBUTE_SUBDIRECTORY 0x10
#define FAT32_LFN_ATTRIBUTE 0x0F

#pragma pack(push, 1)
struct vff_header {
  char magic[4];
  uint32_t byte_order_marker;
  uint32_t volume_size;
  uint16_t cluster_size;
  uint16_t padding;
  // Set to 0x0 or 0x1 based on unknown factors.
  uint8_t unknown;
  uint8_t reserved[15];
};

struct fat32_directory_entry {
  char file_name_and_ext[8 + 3];
  uint8_t attribute;
  uint8_t file_data_1[8];
  uint16_t cluster_num_high;
  uint8_t file_data_2[4];
  uint16_t cluster_num_low;
  uint32_t file_size_bytes;
};

struct fat32_lfn_entry {
  uint8_t sequence_number;
  char name1[10];
  uint8_t attribute;
  uint8_t type;
  uint8_t dos_checksum;
  char name2[12];
  uint16_t first_cluster;
  char name3[4];
};
#pragma pack(pop)

static int fat32_init_context(struct fat32_context *context,
                              struct volume *part) {
  context->part = part;

  struct vff_header header;
  volume_read(context->part, &header, 0, sizeof(struct vff_header));

  // Validate magic
  if (strncmp(header.magic, VFF_MAGIC, 4) != 0) {
    return 1;
  }

  // Somewhat ironically, we cannot depend on the upper byte order marker.
  // For server-side VFFs, the header's cluster size will be in little endian.
  // Endianness is hard :)
  // However, we can depend on the lower value being 0x0100.
  uint32_t bom = be32toh(header.byte_order_marker);
  if (bom == VFF_BOM_BE) {
    context->is_big_endian = true;
  } else if (bom == VFF_BOM_LE) {
    context->is_big_endian = false;
  } else {
    return 1;
  }

  // For an unknown reason, the cluster size must be multiplied by 16.
  // (It should always be 512, but we support variable sizes just in case.)
  if (context->is_big_endian == true) {
    context->cluster_size = be16toh(header.cluster_size) * 16;
  } else {
    context->cluster_size = le16toh(header.cluster_size) * 16;
  }

  uint32_t volume_size = be32toh(header.volume_size);

  // Determine the cluster count based on from cluster size
  // and volume size. This size is not given to us otherwise.
  uint32_t cluster_count = volume_size / context->cluster_size;

  // We now determine the FAT type.
  // 32, 16 or 12 are possible.
  if (cluster_count >= 0xFFF5) {
    context->type = 32;
  } else if (cluster_count >= 0xFF5) {
    context->type = 16;
  } else {
    context->type = 12;
  }

  // We must have two FATs per VFF.
  context->number_of_fats = 2;

  context->root_directory_cluster = 0;
  context->root_entries = cluster_count * 2;
  context->root_start = context->number_of_fats * context->cluster_size;

  context->root_size = context->cluster_size * 2;
  context->root_size = (context->root_size + context->cluster_size - 1) &
                       ~(context->cluster_size - 1);

  switch (context->type) {
  case 12:
  case 16:
    context->data_start_lba = context->root_start + context->root_size;
    break;
  case 32:
    context->data_start_lba = context->root_start;
    break;
  default:
    // This should not occur.
    return 1;
  }

  return 0;
}

static int read_cluster_from_map(struct fat32_context *context,
                                 uint32_t cluster, uint32_t *out) {
  switch (context->type) {
  case 12: {
    *out = 0;
    uint16_t tmp = 0;
    volume_read(context->part, &tmp, (cluster + cluster / 2), sizeof(uint16_t));
    if (cluster % 2 == 0) {
      *out = tmp & 0xfff;
    } else {
      *out = tmp >> 4;
    }
    break;
  }
  case 16:
    *out = 0;
    volume_read(context->part, out, cluster * sizeof(uint16_t),
                sizeof(uint16_t));
    break;
  case 32:
    volume_read(context->part, out, cluster * sizeof(uint32_t),
                sizeof(uint32_t));
    *out &= 0x0fffffff;
    break;
  default:
    return 1;
  }

  return 0;
}

static uint32_t *cache_cluster_chain(struct fat32_context *context,
                                     uint32_t initial_cluster,
                                     size_t *_chain_length) {
  uint32_t cluster_limit = (context->type == 12 ? 0xfef : 0) |
                           (context->type == 16 ? 0xffef : 0) |
                           (context->type == 32 ? 0xfffffef : 0);
  if (initial_cluster < 0x2 || initial_cluster > cluster_limit)
    return NULL;
  uint32_t cluster = initial_cluster;
  size_t chain_length;
  for (chain_length = 1;; chain_length++) {
    read_cluster_from_map(context, cluster, &cluster);
    if (cluster < 0x2 || cluster > cluster_limit)
      break;
  }
  uint32_t *cluster_chain = malloc(chain_length * sizeof(uint32_t));
  cluster = initial_cluster;
  for (size_t i = 0; i < chain_length; i++) {
    cluster_chain[i] = cluster;
    read_cluster_from_map(context, cluster, &cluster);
  }
  *_chain_length = chain_length;
  return cluster_chain;
}

static bool read_cluster_chain(struct fat32_context *context,
                               uint32_t *cluster_chain, void *buf, uint64_t loc,
                               uint64_t count) {
  size_t block_size = context->cluster_size;
  for (uint64_t progress = 0; progress < count;) {
    uint64_t block = (loc + progress) / block_size;

    uint64_t chunk = count - progress;
    uint64_t offset = (loc + progress) % block_size;
    if (chunk > block_size - offset)
      chunk = block_size - offset;

    uint64_t base =
        ((uint64_t)context->data_start_lba + (cluster_chain[block] - 2)) *
        context->cluster_size;
    volume_read(context->part, buf + progress, base + offset, chunk);

    progress += chunk;
  }

  return true;
}

// Copy ucs-2 characters to char*
static void fat32_lfncpy(char *destination, const void *source,
                         unsigned int size) {
  for (unsigned int i = 0; i < size; i++) {
    // ignore high bytes
    *(((uint8_t *)destination) + i) = *(((uint8_t *)source) + (i * 2));
  }
}

static bool fat32_filename_to_8_3(char *dest, const char *src) {
  int i = 0, j = 0;
  bool ext = false;

  for (size_t k = 0; k < 8 + 3; k++)
    dest[k] = ' ';

  while (src[i]) {
    if (src[i] == '.') {
      if (ext) {
        // This is a double extension here, just give up.
        return false;
      }
      ext = true;
      j = 8;
      i++;
      continue;
    }
    if (j >= 8 + 3 || (j >= 8 && !ext)) {
      // Filename too long, give up.
      return false;
    }
    dest[j++] = toupper(src[i++]);
  }

  return true;
}

static int fat32_open_in(struct fat32_context *context,
                         struct fat32_directory_entry *directory,
                         struct fat32_directory_entry *file, const char *name) {
  size_t block_size = context->cluster_size;
  char current_lfn[FAT32_LFN_MAX_FILENAME_LENGTH] = {0};

  size_t dir_chain_len;
  struct fat32_directory_entry *directory_entries;

  if (directory != NULL) {
    uint32_t current_cluster_number = directory->cluster_num_low;
    if (context->type == 32)
      current_cluster_number |= (uint32_t)directory->cluster_num_high << 16;

    uint32_t *directory_cluster_chain =
        cache_cluster_chain(context, current_cluster_number, &dir_chain_len);

    if (directory_cluster_chain == NULL)
      return -1;

    directory_entries = malloc(dir_chain_len * block_size);

    read_cluster_chain(context, directory_cluster_chain, directory_entries, 0,
                       dir_chain_len * block_size);

    free(directory_cluster_chain);
  } else {
    dir_chain_len = DIV_ROUNDUP(context->root_entries *
                                    sizeof(struct fat32_directory_entry),
                                block_size);

    directory_entries = malloc(dir_chain_len * block_size);

    volume_read(context->part, directory_entries,
                context->root_start * context->cluster_size,
                context->root_entries * sizeof(struct fat32_directory_entry));
  }

  int ret;

  for (size_t i = 0;
       i < (dir_chain_len * block_size) / sizeof(struct fat32_directory_entry);
       i++) {
    if (directory_entries[i].file_name_and_ext[0] == 0x00) {
      // no more entries here
      break;
    }

    if (directory_entries[i].attribute == FAT32_LFN_ATTRIBUTE) {
      struct fat32_lfn_entry *lfn =
          (struct fat32_lfn_entry *)&directory_entries[i];

      if (lfn->sequence_number & 0b01000000) {
        // this lfn is the first entry in the table, clear the lfn buffer
        memset(current_lfn, ' ', sizeof(current_lfn));
      }

      const unsigned int lfn_index =
          ((lfn->sequence_number & 0b00011111) - 1U) * 13U;
      if (lfn_index >= FAT32_LFN_MAX_ENTRIES * 13) {
        continue;
      }

      fat32_lfncpy(current_lfn + lfn_index + 00, lfn->name1, 5);
      fat32_lfncpy(current_lfn + lfn_index + 05, lfn->name2, 6);
      fat32_lfncpy(current_lfn + lfn_index + 11, lfn->name3, 2);

      if (lfn_index != 0)
        continue;

      // remove trailing spaces
      for (int j = SIZEOF_ARRAY(current_lfn) - 2; j >= -1; j--) {
        if (j == -1 || current_lfn[j] != ' ') {
          current_lfn[j + 1] = 0;
          break;
        }
      }

      if (!strcmp(current_lfn, name)) {
        *file = directory_entries[i + 1];
        ret = 0;
        goto out;
      }
    }

    if (directory_entries[i].attribute & (1 << 3)) {
      // It is a volume label, skip
      continue;
    }
    // SFN
    char fn[8 + 3];
    if (!fat32_filename_to_8_3(fn, name)) {
      continue;
    }
    if (!strncmp(directory_entries[i].file_name_and_ext, fn, 8 + 3)) {
      *file = directory_entries[i];
      ret = 0;
      goto out;
    }
  }

  // file not found
  ret = -1;

out:
  free(directory_entries);
  return ret;
}

int fat32_check_signature(struct volume *part) {
  struct fat32_context context;
  return fat32_init_context(&context, part) == 0;
}

bool fat32_open(struct fat32_file_handle *ret, struct volume *part,
                const char *path) {
  struct fat32_context context;
  int r = fat32_init_context(&context, part);

  if (r) {
    return false;
  }

  struct fat32_directory_entry _current_directory;
  struct fat32_directory_entry *current_directory;
  struct fat32_directory_entry current_file;
  unsigned int current_index = 0;
  char current_part[FAT32_LFN_MAX_FILENAME_LENGTH];

  // skip trailing slashes
  while (path[current_index] == '/') {
    current_index++;
  }

  // walk down the directory tree
  switch (context.type) {
  case 12:
  case 16:
    current_directory = NULL;
    break;
  case 32:
    _current_directory.cluster_num_low =
        context.root_directory_cluster & 0xFFFF;
    _current_directory.cluster_num_high = context.root_directory_cluster >> 16;
    current_directory = &_current_directory;
    break;
  default:
    return false;
  }

  for (;;) {
    bool expect_directory = false;

    for (unsigned int i = 0; i < SIZEOF_ARRAY(current_part); i++) {
      if (path[i + current_index] == 0) {
        memcpy(current_part, path + current_index, i);
        current_part[i] = 0;
        expect_directory = false;
        break;
      }

      if (path[i + current_index] == '/') {
        memcpy(current_part, path + current_index, i);
        current_part[i] = 0;
        current_index += i + 1;
        expect_directory = true;
        break;
      }
    }

    if ((r = fat32_open_in(&context, current_directory, &current_file,
                           current_part)) != 0) {
      return false;
    }

    if (expect_directory) {
      _current_directory = current_file;
      current_directory = &_current_directory;
    } else {
      ret->context = context;
      ret->first_cluster = current_file.cluster_num_low;
      if (context.type == 32)
        ret->first_cluster |= (uint64_t)current_file.cluster_num_high << 16;
      ret->size_clusters =
          DIV_ROUNDUP(current_file.file_size_bytes, context.cluster_size);
      ret->size_bytes = current_file.file_size_bytes;
      ret->cluster_chain =
          cache_cluster_chain(&context, ret->first_cluster, &ret->chain_len);
      return true;
    }
  }
}

void fat32_read(struct fat32_file_handle *file, void *buf, uint64_t loc,
                uint64_t count) {
  read_cluster_chain(&file->context, file->cluster_chain, buf, loc, count);
}

void fat32_close(struct fat32_file_handle *file) {
  free(file->cluster_chain);
  free(file);
}
