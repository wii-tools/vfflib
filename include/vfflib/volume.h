// SPDX-License-Identifier: BSD-2-Clause
// Copyright Spotlight 2022.

#ifndef __VOLUME_H__
#define __VOLUME_H__

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

struct volume {
  FILE *vff;
};

struct volume *volume_open(char *filename);

bool volume_read(struct volume *volume, void *buffer, uint64_t loc,
                 uint64_t count);

bool volume_close(struct volume *volume);

#endif