// SPDX-License-Identifier: BSD-2-Clause
// Copyright Spotlight 2022.

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <vfflib/fat.h>
#include <vfflib/volume.h>

int main(int argc, char *argv[]) {
  if (argc != 3) {
    printf("Usage: %s <vff path> <file>\n", argv[0]);
    return 1;
  }

  char *vff_path = argv[1];
  char *file_path = argv[2];
  struct volume *vol = volume_open(vff_path);

  // Validate opening volume
  int result = fat32_check_signature(vol);
  if (result != 1) {
    printf("The file %s is not a valid VFF.\n", vff_path);
    return 1;
  } else {
    printf("VFF opened successfully!\n");
  }

  // Open file
  struct fat32_file_handle *handle = malloc(sizeof(struct fat32_file_handle));
  bool test = fat32_open(handle, vol, file_path);
  printf("%d\n", test == true);
  fat32_close(handle);

  return 0;
}
