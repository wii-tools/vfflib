// SPDX-License-Identifier: BSD-2-Clause
// Copyright Spotlight 2022.
// This header is intended to only permit various endian
// values to be present on the host endian.

#ifndef __LOCAL_ENDIAN_H__
#define __LOCAL_ENDIAN_H__

#if defined(__linux__) || defined(__CYGWIN__)
#include <endian.h>
#elif defined(__APPLE__)
#include <libkern/OSByteOrder.h>

#define be16toh(x) OSSwapBigToHostInt16(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define be64toh(x) OSSwapBigToHostInt64(x)

#define le16toh(x) OSSwapLittleToHostInt16(x)

#endif

#endif
