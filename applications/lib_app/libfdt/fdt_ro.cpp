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

#include <stdio.h>
#include <string.h>
#include <linux/types.h>
#include <syslog.h>
#include <stdint.h>

#include "fdt.h"

#define FIT_TIMESTAMP_PROP  "timestamp"
#define FIT_DESC_PROP       "description"

#define fdt32_to_cpu(x) be32_to_cpu(x)

#define FDT_MAGIC                   0xd00dfeed  /* 4: version, 4: total size */
#define FDT_SW_MAGIC                (~FDT_MAGIC)
#define FDT_FIRST_SUPPORTED_VERSION 0x10
#define FDT_LAST_SUPPORTED_VERSION  0x11
#define FDT_TAGSIZE                 sizeof(fdt32_t)

#define FDT_BEGIN_NODE  0x1     /* Start node: full name */
#define FDT_END_NODE    0x2     /* End node */
#define FDT_PROP        0x3     /* Property: name off,
                                   size, content */
#define FDT_NOP     0x4     /* nop */
#define FDT_END     0x9

#define FDT_ERR_NOTFOUND    1
    /* FDT_ERR_NOTFOUND: The requested node or property does not exist */
#define FDT_ERR_EXISTS      2
    /* FDT_ERR_EXISTS: Attempted to create a node or property which
     * already exists */
#define FDT_ERR_BADOFFSET   4
    /* FDT_ERR_BADOFFSET: Function was passed a structure block
     * offset which is out-of-bounds, or which points to an
     * unsuitable part of the structure for the operation. */
#define FDT_ERR_BADSTATE        7
    /* FDT_ERR_BADSTATE: Function was passed an incomplete device
     * tree created by the sequential-write functions, which is
     * not sufficiently complete for the requested operation. */
#define FDT_ERR_TRUNCATED   8
    /* FDT_ERR_TRUNCATED: Structure block of the given device tree
     * ends without an FDT_END tag. */

#define FDT_ERR_BADMAGIC        9
    /* FDT_ERR_BADMAGIC: Given "device tree" appears not to be a
     * device tree at all - it is missing the flattened device
     * tree magic number. */
#define FDT_ERR_BADVERSION      10
    /* FDT_ERR_BADVERSION: Given device tree has a version which
     * can't be handled by the requested operation.  For
     * read-write functions, this may mean that fdt_open_into() is
     * required to convert the tree to the expected version. */
#define FDT_ERR_BADSTRUCTURE    11
    /* FDT_ERR_BADSTRUCTURE: Given device tree has a corrupt
     * structure block or other serious error (e.g. misnested
     * nodes, or subnodes preceding properties). */
#define FDT_ERR_INTERNAL    13
    /* FDT_ERR_INTERNAL: libfdt has failed an internal assertion.
     * Should never be returned, if it is, it indicates a bug in
     * libfdt itself. */

#define FDT_ALIGN(x, a)     (((x) + (a) - 1) & ~((a) - 1))
#define FDT_TAGALIGN(x)     (FDT_ALIGN((x), FDT_TAGSIZE))

/**********************************************************************/
/* General functions                                                  */
/**********************************************************************/
#define fdt_get_header(fdt, field) \
    (fdt32_to_cpu(((const struct fdt_header *)(fdt))->field))
#define fdt_magic(fdt)          (fdt_get_header(fdt, magic))
#define fdt_totalsize(fdt)      (fdt_get_header(fdt, totalsize))
#define fdt_off_dt_struct(fdt)      (fdt_get_header(fdt, off_dt_struct))
#define fdt_off_dt_strings(fdt)     (fdt_get_header(fdt, off_dt_strings))
#define fdt_off_mem_rsvmap(fdt)     (fdt_get_header(fdt, off_mem_rsvmap))
#define fdt_version(fdt)        (fdt_get_header(fdt, version))
#define fdt_last_comp_version(fdt)  (fdt_get_header(fdt, last_comp_version))
#define fdt_boot_cpuid_phys(fdt)    (fdt_get_header(fdt, boot_cpuid_phys))
#define fdt_size_dt_strings(fdt)    (fdt_get_header(fdt, size_dt_strings))
#define fdt_size_dt_struct(fdt)     (fdt_get_header(fdt, size_dt_struct))

const char *fdt_string(const void *fdt, int stroffset)
{
    return (const char *)fdt + fdt_off_dt_strings(fdt) + stroffset;
}

static int _fdt_string_eq(const void *fdt, int stroffset,
              const char *s, unsigned int len)
{
    const char *p = fdt_string(fdt, stroffset);

    return (strnlen(p, len + 1) == len) && (memcmp(p, s, len) == 0);
}

static inline const void *_fdt_offset_ptr(const fdt32_t *fdt, int offset)
{
    return (const char *)fdt + fdt_off_dt_struct(fdt) + offset;
}

static const void *fdt_offset_ptr(const fdt32_t *fdt, unsigned offset, unsigned int len)
{
    unsigned absoffset = offset + fdt_off_dt_struct(fdt);

    if ((absoffset < offset)
        || ((absoffset + len) < absoffset)
        || (absoffset + len) > fdt_totalsize(fdt))
        return NULL;

    if (fdt_version(fdt) >= 0x11)
        if (((offset + len) < offset)
            || ((offset + len) > fdt_size_dt_struct(fdt)))
            return NULL;

    return _fdt_offset_ptr(fdt, offset);
}

static uint32_t fdt_next_tag(const fdt32_t*fdt, int startoffset, int *nextoffset)
{
    const fdt32_t *tagp, *lenp;
    uint32_t tag;
    int offset = startoffset;
    const char *p;

    *nextoffset = -FDT_ERR_TRUNCATED;
    tagp = (const fdt32_t*)fdt_offset_ptr(fdt, offset, FDT_TAGSIZE);
    if (!tagp)
        return FDT_END; /* premature end */
    tag = fdt32_to_cpu(*tagp);
    offset += FDT_TAGSIZE;

    *nextoffset = -FDT_ERR_BADSTRUCTURE;
    switch (tag) {
    case FDT_BEGIN_NODE:
        /* skip name */
        do {
            p = (const char *)fdt_offset_ptr(fdt, offset++, 1);
        } while (p && (*p != '\0'));
        if (!p)
            return FDT_END; /* premature end */
        break;

    case FDT_PROP:
        lenp = (const fdt32_t*)fdt_offset_ptr(fdt, offset, sizeof(*lenp));
        if (!lenp)
            return FDT_END; /* premature end */
        /* skip-name offset, length and value */
        offset += sizeof(struct fdt_property) - FDT_TAGSIZE
            + fdt32_to_cpu(*lenp);
        break;

    case FDT_END:
    case FDT_END_NODE:
    case FDT_NOP:
        break;

    default:
        return FDT_END;
    }

    if (!fdt_offset_ptr(fdt, startoffset, offset - startoffset))
        return FDT_END; /* premature end */

    *nextoffset = FDT_TAGALIGN(offset);
    return tag;
}

static int _fdt_check_node_offset(const fdt32_t*fdt, int offset)
{
    if ((offset < 0) || (offset % FDT_TAGSIZE)
        || (fdt_next_tag(fdt, offset, &offset) != FDT_BEGIN_NODE))
        return -FDT_ERR_BADOFFSET;

    return offset;
}
static int _nextprop(const fdt32_t*fdt, int offset)
{
    uint32_t tag;
    int nextoffset;

    do {
        tag = fdt_next_tag(fdt, offset, &nextoffset);

        switch (tag) {
        case FDT_END:
            if (nextoffset >= 0)
                return -FDT_ERR_BADSTRUCTURE;
            else
                return nextoffset;

        case FDT_PROP:
            return offset;
        }
        offset = nextoffset;
    } while (tag == FDT_NOP);

    return -FDT_ERR_NOTFOUND;
}

int _fdt_check_prop_offset(const fdt32_t *fdt, int offset)
{
    if ((offset < 0) || (offset % FDT_TAGSIZE)
        || (fdt_next_tag(fdt, offset, &offset) != FDT_PROP))
        return -FDT_ERR_BADOFFSET;

    return offset;
}

static int fdt_first_property_offset(const fdt32_t*fdt, int nodeoffset)
{
    int offset;

    if ((offset = _fdt_check_node_offset(fdt, nodeoffset)) < 0)
        return offset;

    return _nextprop(fdt, offset);
}

int fdt_next_property_offset(const fdt32_t*fdt, int offset)
{
    if ((offset = _fdt_check_prop_offset(fdt, offset)) < 0)
        return offset;

    return _nextprop(fdt, offset);
}

const struct fdt_property *fdt_get_property_by_offset(const fdt32_t *fdt,
                              int offset,
                              int *lenp)
{
    int err;
    const struct fdt_property *prop;

    if ((err = _fdt_check_prop_offset(fdt, offset)) < 0) {
        if (lenp)
            *lenp = err;
        return NULL;
    }

    prop = (struct fdt_property *)_fdt_offset_ptr(fdt, offset);

    if (lenp)
        *lenp = fdt32_to_cpu(prop->len);

    return prop;
}

static const struct fdt_property *fdt_get_property_namelen(const fdt32_t*fdt,
                            int offset,
                            const char *name,
                            int namelen, int *lenp)
{
    for (offset = fdt_first_property_offset(fdt, offset);
         (offset >= 0);
         (offset = fdt_next_property_offset(fdt, offset))) {
        const struct fdt_property *prop;

        if (!(prop = fdt_get_property_by_offset(fdt, offset, lenp))) {
            offset = -FDT_ERR_INTERNAL;
            break;
        }
        if (_fdt_string_eq(fdt, fdt32_to_cpu(prop->nameoff),
                   name, namelen))
            return prop;
    }

    if (lenp)
        *lenp = offset;
    return NULL;
}

static const void *fdt_getprop_namelen(const fdt32_t*fdt, int nodeoffset,
                const char *name, int namelen, int *lenp)
{
    const struct fdt_property *prop;

    prop = fdt_get_property_namelen(fdt, nodeoffset, name, namelen, lenp);
    if (! prop)
        return NULL;

    return prop->data;
}


static const void *fdt_getprop(const fdt32_t*fdt, int nodeoffset,
            const char *name, int *lenp)
{
    return fdt_getprop_namelen(fdt, nodeoffset, name, (int)strlen(name), lenp);
}

int fit_get_desc(const fdt32_t *fit, int noffset, char **desc)
{
    int len;

    *desc = (char *)fdt_getprop(fit, noffset, FIT_DESC_PROP, &len);
    if (*desc == NULL) {
        return -1;
    }

    return 0;
}

int fit_get_timestamp(const fdt32_t *fit, int noffset, time_t *timestamp)
{
    int len;
    const void *data;

    data = fdt_getprop(fit, noffset, FIT_TIMESTAMP_PROP, &len);
    if (data == NULL) {
        return -1;
    }
    if (len != sizeof(uint32_t)) {
        syslog(LOG_WARNING, "FIT timestamp with incorrect size of (%u)\n", len);
        return -2;
    }

    *timestamp = uimage_to_cpu(*((uint32_t *)data));
    return 0;
}

int fdt_check_header(const void *fdt)
{
    if (fdt_magic(fdt) == FDT_MAGIC) {
        /* Complete tree */
        if (fdt_version(fdt) < FDT_FIRST_SUPPORTED_VERSION)
            return -FDT_ERR_BADVERSION;
        if (fdt_last_comp_version(fdt) > FDT_LAST_SUPPORTED_VERSION)
            return -FDT_ERR_BADVERSION;
    } else if (fdt_magic(fdt) == FDT_SW_MAGIC) {
        /* Unfinished sequential-write blob */
        if (fdt_size_dt_struct(fdt) == 0)
            return -FDT_ERR_BADSTATE;
    } else {
        return -FDT_ERR_BADMAGIC;
    }

    return 0;
}

