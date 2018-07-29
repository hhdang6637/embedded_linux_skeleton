/*
 * Copyright (c) 2013, Google Inc.
 *
 * (C) Copyright 2008 Semihalf
 *
 * (C) Copyright 2000-2006
 * Wolfgang Denk, DENX Software Engineering, wd@denx.de.
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef APPLICATIONS_LIB_APP_LIBFDT_FDT_H_
#define APPLICATIONS_LIB_APP_LIBFDT_FDT_H_

#include <time.h>

#define uswap_32(x) \
    ((((x) & 0xff000000) >> 24) | \
     (((x) & 0x00ff0000) >>  8) | \
     (((x) & 0x0000ff00) <<  8) | \
     (((x) & 0x000000ff) << 24))

#if __BYTE_ORDER == __LITTLE_ENDIAN
# define be32_to_cpu(x)     uswap_32(x)
#else
# define be32_to_cpu(x)     (x)
#endif

#define uimage_to_cpu(x)        be32_to_cpu(x)
//#define cpu_to_uimage(x)        cpu_to_be32(x)

typedef __be32 fdt32_t;

struct fdt_header {
    fdt32_t magic;           /* magic word FDT_MAGIC */
    fdt32_t totalsize;       /* total size of DT block */
    fdt32_t off_dt_struct;       /* offset to structure */
    fdt32_t off_dt_strings;      /* offset to strings */
    fdt32_t off_mem_rsvmap;      /* offset to memory reserve map */
    fdt32_t version;         /* format version */
    fdt32_t last_comp_version;   /* last compatible version */

    /* version 2 fields below */
    fdt32_t boot_cpuid_phys;     /* Which physical CPU id we're
                        booting on */
    /* version 3 fields below */
    fdt32_t size_dt_strings;     /* size of the strings block */

    /* version 17 fields below */
    fdt32_t size_dt_struct;      /* size of the structure block */
};

struct fdt_property {
    fdt32_t tag;
    fdt32_t len;
    fdt32_t nameoff;
    char data[0];
};

int fit_get_desc(const fdt32_t *fit, int noffset, char **desc);
int fit_get_timestamp(const fdt32_t *fit, int noffset, time_t *timestamp);

#endif /* APPLICATIONS_LIB_APP_LIBFDT_FDT_H_ */
