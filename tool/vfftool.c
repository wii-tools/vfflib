// SPDX-License-Identifier: BSD-2-Clause
// Copyright Spotlight 2022.

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <vfflib/fat.h>
#include <vfflib/volume.h>

int main(int argc, char *argv[]) {
  if (argc != 2) {
    printf("Usage: %s <file path>\n", argv[0]);
    return 1;
  }

  char *filepath = argv[1];
  struct volume *vol = volume_open(filepath);

  // Validate opening volume
  int result = fat32_check_signature(vol);
  if (result != 1) {
    printf("The file %s is not a valid VFF.\n", filepath);
    return 1;
  } else {
    printf("VFF opened successfully!\n");
  }

  return 0;
}