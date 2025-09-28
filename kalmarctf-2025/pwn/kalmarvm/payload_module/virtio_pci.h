#ifndef VIRTI_PCI_H
#define VIRTI_PCI_H

#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/module.h>
#include <linux/list.h>

#include <linux/types.h>
#include <linux/virtio_types.h>

#define KVM_32BIT_MAX_MEM_SIZE (1ULL << 32)
#define KVM_32BIT_GAP_SIZE (768 << 20)
#define KVM_32BIT_GAP_START (KVM_32BIT_MAX_MEM_SIZE - KVM_32BIT_GAP_SIZE)

#define KVM_MMIO_START KVM_32BIT_GAP_START

#define KVM_PCI_MMIO_AREA (KVM_MMIO_START + 0x2000000)
#define KVM_VIRTIO_MMIO_AREA (KVM_MMIO_START + 0x3000000)

/* Fields in VIRTIO_PCI_CAP_COMMON_CFG: */
struct virtio_pci_common_cfg
{
    /* About the whole device. */
    __le32 device_feature_select; /* read-write */
    __le32 device_feature;        /* read-only */
    __le32 guest_feature_select;  /* read-write */
    __le32 guest_feature;         /* read-write */
    __le16 msix_config;           /* read-write */
    __le16 num_queues;            /* read-only */
    __u8 device_status;           /* read-write */
    __u8 config_generation;       /* read-only */

    /* About a specific virtqueue. */
    __le16 queue_select;      /* read-write */
    __le16 queue_size;        /* read-write, power of 2. */
    __le16 queue_msix_vector; /* read-write */
    __le16 queue_enable;      /* read-write */
    __le16 queue_notify_off;  /* read-only */
    __le32 queue_desc_lo;     /* read-write */
    __le32 queue_desc_hi;     /* read-write */
    __le32 queue_avail_lo;    /* read-write */
    __le32 queue_avail_hi;    /* read-write */
    __le32 queue_used_lo;     /* read-write */
    __le32 queue_used_hi;     /* read-write */
};

// These are the offsets into the BAR that either configure or notify the virtio PCI device

#define VPCI_CFG_COMMON_SIZE sizeof(struct virtio_pci_common_cfg)
#define VPCI_CFG_COMMON_START 0
#define VPCI_CFG_COMMON_END (VPCI_CFG_COMMON_SIZE - 1)
/*
 * Use a naturally aligned 4-byte doorbell, in case we ever want to
 * implement VIRTIO_F_NOTIFICATION_DATA
 */
#define VPCI_CFG_NOTIFY_SIZE 4
#define VPCI_CFG_NOTIFY_START (VPCI_CFG_COMMON_END + 1)
#define VPCI_CFG_NOTIFY_END (VPCI_CFG_COMMON_END + VPCI_CFG_NOTIFY_SIZE)

static inline void printk_common_config(struct virtio_pci_common_cfg *cfg)
{
    printk(KERN_INFO "Virtio PCI Common Config:\n");
    printk(KERN_INFO "  device_feature_select: 0x%08x\n", cfg->device_feature_select);
    printk(KERN_INFO "  device_feature: 0x%08x\n", cfg->device_feature);
    printk(KERN_INFO "  guest_feature_select: 0x%08x\n", cfg->guest_feature_select);
    printk(KERN_INFO "  guest_feature: 0x%08x\n", cfg->guest_feature);
    printk(KERN_INFO "  msix_config: 0x%04x\n", cfg->msix_config);
    printk(KERN_INFO "  num_queues: 0x%04x\n", cfg->num_queues);
    printk(KERN_INFO "  device_status: 0x%02x\n", cfg->device_status);
    printk(KERN_INFO "  config_generation: 0x%02x\n", cfg->config_generation);
    printk(KERN_INFO " \nVQ Specific:\n");
    printk(KERN_INFO "  queue_select: 0x%04x\n", cfg->queue_select);
    printk(KERN_INFO "  queue_size: 0x%04x\n", cfg->queue_size);
    printk(KERN_INFO "  queue_msix_vector: 0x%04x\n", cfg->queue_msix_vector);
    printk(KERN_INFO "  queue_enable: 0x%04x\n", cfg->queue_enable);
    printk(KERN_INFO "  queue_notify_off: 0x%04x\n", cfg->queue_notify_off);
    printk(KERN_INFO "  queue_desc: 0x%08x%08x\n", cfg->queue_desc_hi, cfg->queue_desc_lo);
    printk(KERN_INFO "  queue_avail: 0x%08x%08x\n", cfg->queue_avail_hi, cfg->queue_avail_lo);
    printk(KERN_INFO "  queue_used: 0x%08x%08x\n", cfg->queue_used_hi, cfg->queue_used_lo);
}

#endif // VIRTI_PCI_H