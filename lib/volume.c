// SPDX-License-Identifier: BSD-2-Clause
// Copyright Spotlight 2022.

#include <vfflib/volume.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct volume *volume_open(char *filename) {
  FILE *vol_file = fopen(filename, "r+w");

  // Ensure our file opened successfully.
  if (vol_file == NULL) {
    return NULL;
  }

  struct volume *result = (struct volume *)malloc(sizeof(struct volume));
  result->vff = vol_file;
  return result;
}

bool volume_read(struct volume *volume, void *buffer, uint64_t loc,
                 uint64_t count) {
  // Seek to where we need, and read.
  fseek(volume->vff, loc, SEEK_SET);
  int result = fread(buffer, count, 1, volume->vff);

  // Return whether we read the amount we intended.
  return result == count;
}

bool volume_close(struct volume *volume) {
  // We cannot close a null volume.
  if (volume == NULL) {
    return false;
  }

  if (fclose(volume->vff) == 0) {
    return false;
  }

  free(volume);
  return true;
}