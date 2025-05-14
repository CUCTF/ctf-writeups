
#ifndef VIRTI_VRING_H
#define VIRTI_VRING_H

#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/module.h>
#include <linux/list.h>

#include <linux/types.h>
#include <linux/virtio_types.h>
#include <linux/align.h>

/* Alignment requirements for vring elements.
 * When using pre-virtio 1.0 layout, these fall out naturally.
 */
#define VRING_AVAIL_ALIGN_SIZE 2
#define VRING_USED_ALIGN_SIZE 4
#define VRING_DESC_ALIGN_SIZE 16

struct vring_desc
{
    __virtio64 addr;
    __virtio32 len;
    __virtio16 flags;
    __virtio16 next;
};
struct vring_avail
{
    __virtio16 flags;
    __virtio16 idx;
    __virtio16 ring[];
};

/* u32 is used here for ids for padding reasons. */
struct vring_used_elem
{
    /* Index of start of used descriptor chain. */
    __virtio32 id;
    /* Total length of the descriptor chain which was used (written to) */
    __virtio32 len;
};

typedef struct vring_used_elem __attribute__((aligned(VRING_USED_ALIGN_SIZE)))
vring_used_elem_t;

struct vring_used
{
    __virtio16 flags;
    __virtio16 idx;
    vring_used_elem_t ring[];
};
/*
 * The ring element addresses are passed between components with different
 * alignments assumptions. Thus, we might need to decrease the compiler-selected
 * alignment, and so must use a typedef to make sure the aligned attribute
 * actually takes hold:
 *
 * https://gcc.gnu.org/onlinedocs//gcc/Common-Type-Attributes.html#Common-Type-Attributes
 *
 * When used on a struct, or struct member, the aligned attribute can only
 * increase the alignment; in order to decrease it, the packed attribute must
 * be specified as well. When used as part of a typedef, the aligned attribute
 * can both increase and decrease alignment, and specifying the packed
 * attribute generates a warning.
 */
typedef struct vring_desc __attribute__((aligned(VRING_DESC_ALIGN_SIZE)))
vring_desc_t;
typedef struct vring_avail __attribute__((aligned(VRING_AVAIL_ALIGN_SIZE)))
vring_avail_t;
typedef struct vring_used __attribute__((aligned(VRING_USED_ALIGN_SIZE)))
vring_used_t;

struct vring
{
    unsigned int num;

    vring_desc_t *desc;

    vring_avail_t *avail;

    vring_used_t *used;
};

/* The standard layout for the ring is a continuous chunk of memory which looks
 * like this.  We assume num is a power of 2.
 *
 * struct vring
 * {
 *	// The actual descriptors (16 bytes each)
 *	struct vring_desc desc[num];
 *
 *	// A ring of available descriptor heads with free-running index.
 *	__virtio16 avail_flags;
 *	__virtio16 avail_idx;
 *	__virtio16 available[num];
 *	__virtio16 used_event_idx;
 *
 *	// Padding to the next align boundary.
 *	char pad[];
 *
 *	// A ring of used descriptor heads with free-running index.
 *	__virtio16 used_flags;
 *	__virtio16 used_idx;
 *	struct vring_used_elem used[num];
 *	__virtio16 avail_event_idx;
 * };
 */

static inline uint64_t desc_size(unsigned int qsz)
{
    return ALIGN(sizeof(struct vring_desc) * qsz + sizeof(uint16_t) * (3 + qsz), PAGE_SIZE);
}

static inline uint64_t avail_size(unsigned int qsz)
{
    return ALIGN(sizeof(uint16_t) * 3 + sizeof(uint16_t) * qsz, PAGE_SIZE);
}

static inline uint64_t used_size(unsigned int qsz)
{
    return sizeof(uint16_t) * 3 + sizeof(struct vring_used_elem) * qsz;
}

static inline uint64_t virtq_size(unsigned int qsz)
{
    return desc_size(qsz) + avail_size(qsz) + used_size(qsz);
}

#endif // VIRTI_VRING_H