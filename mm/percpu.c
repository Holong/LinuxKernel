/*
 * mm/percpu.c - percpu memory allocator
 *
 * Copyright (C) 2009		SUSE Linux Products GmbH
 * Copyright (C) 2009		Tejun Heo <tj@kernel.org>
 *
 * This file is released under the GPLv2.
 *
 * This is percpu allocator which can handle both static and dynamic
 * areas.  Percpu areas are allocated in chunks.  Each chunk is
 * consisted of boot-time determined number of units and the first
 * chunk is used for static percpu variables in the kernel image
 * (special boot time alloc/init handling necessary as these areas
 * need to be brought up before allocation services are running).
 * Unit grows as necessary and all units grow or shrink in unison.
 * When a chunk is filled up, another chunk is allocated.
 *
 *  c0                           c1                         c2
 *  -------------------          -------------------        ------------
 * | u0 | u1 | u2 | u3 |        | u0 | u1 | u2 | u3 |      | u0 | u1 | u
 *  -------------------  ......  -------------------  ....  ------------
 *
 * Allocation is done in offset-size areas of single unit space.  Ie,
 * an area of 512 bytes at 6k in c1 occupies 512 bytes at 6k of c1:u0,
 * c1:u1, c1:u2 and c1:u3.  On UMA, units corresponds directly to
 * cpus.  On NUMA, the mapping can be non-linear and even sparse.
 * Percpu access can be done by configuring percpu base registers
 * according to cpu to unit mapping and pcpu_unit_size.
 *
 * There are usually many small percpu allocations many of them being
 * as small as 4 bytes.  The allocator organizes chunks into lists
 * according to free size and tries to allocate from the fullest one.
 * Each chunk keeps the maximum contiguous area size hint which is
 * guaranteed to be equal to or larger than the maximum contiguous
 * area in the chunk.  This helps the allocator not to iterate the
 * chunk maps unnecessarily.
 *
 * Allocation state in each chunk is kept using an array of integers
 * on chunk->map.  A positive value in the map represents a free
 * region and negative allocated.  Allocation inside a chunk is done
 * by scanning this map sequentially and serving the first matching
 * entry.  This is mostly copied from the percpu_modalloc() allocator.
 * Chunks can be determined from the address using the index field
 * in the page struct. The index field contains a pointer to the chunk.
 *
 * To use this allocator, arch code should do the followings.
 *
 * - define __addr_to_pcpu_ptr() and __pcpu_ptr_to_addr() to translate
 *   regular address to percpu pointer and back if they need to be
 *   different from the default
 *
 * - use pcpu_setup_first_chunk() during percpu area initialization to
 *   setup the first chunk containing the kernel static percpu area
 */

#include <linux/bitmap.h>
#include <linux/bootmem.h>
#include <linux/err.h>
#include <linux/list.h>
#include <linux/log2.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/pfn.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/kmemleak.h>

#include <asm/cacheflush.h>
#include <asm/sections.h>
#include <asm/tlbflush.h>
#include <asm/io.h>

#define PCPU_SLOT_BASE_SHIFT		5	/* 1-31 shares the same slot */
#define PCPU_DFL_MAP_ALLOC		16	/* start a map with 16 ents */

#ifdef CONFIG_SMP
/* default addr <-> pcpu_ptr mapping, override in asm/percpu.h if necessary */
#ifndef __addr_to_pcpu_ptr
#define __addr_to_pcpu_ptr(addr)					\
	(void __percpu *)((unsigned long)(addr) -			\
			  (unsigned long)pcpu_base_addr	+		\
			  (unsigned long)__per_cpu_start)
#endif
#ifndef __pcpu_ptr_to_addr
#define __pcpu_ptr_to_addr(ptr)						\
	(void __force *)((unsigned long)(ptr) +				\
			 (unsigned long)pcpu_base_addr -		\
			 (unsigned long)__per_cpu_start)
#endif
#else	/* CONFIG_SMP */
/* on UP, it's always identity mapped */
#define __addr_to_pcpu_ptr(addr)	(void __percpu *)(addr)
#define __pcpu_ptr_to_addr(ptr)		(void __force *)(ptr)
#endif	/* CONFIG_SMP */

struct pcpu_chunk {
	struct list_head	list;		/* linked to pcpu_slot lists */
	int			free_size;	/* free bytes in the chunk */
	int			contig_hint;	/* max contiguous size hint */
	void			*base_addr;	/* base address of this chunk */
	int			map_used;	/* # of map entries used */
	int			map_alloc;	/* # of map entries allocated */
	int			*map;		/* allocation map */
	void			*data;		/* chunk data */
	bool			immutable;	/* no [de]population allowed */
	unsigned long		populated[];	/* populated bitmap */
};

static int pcpu_unit_pages __read_mostly;
static int pcpu_unit_size __read_mostly;
static int pcpu_nr_units __read_mostly;
static int pcpu_atom_size __read_mostly;
static int pcpu_nr_slots __read_mostly;
static size_t pcpu_chunk_struct_size __read_mostly;

/* cpus with the lowest and highest unit addresses */
static unsigned int pcpu_low_unit_cpu __read_mostly;
static unsigned int pcpu_high_unit_cpu __read_mostly;

/* the address of the first chunk which starts with the kernel static area */
void *pcpu_base_addr __read_mostly;
EXPORT_SYMBOL_GPL(pcpu_base_addr);

static const int *pcpu_unit_map __read_mostly;		/* cpu -> unit */
const unsigned long *pcpu_unit_offsets __read_mostly;	/* cpu -> unit offset */

/* group information, used for vm allocation */
static int pcpu_nr_groups __read_mostly;
static const unsigned long *pcpu_group_offsets __read_mostly;
static const size_t *pcpu_group_sizes __read_mostly;

/*
 * The first chunk which always exists.  Note that unlike other
 * chunks, this one can be allocated and mapped in several different
 * ways and thus often doesn't live in the vmalloc area.
 */
static struct pcpu_chunk *pcpu_first_chunk;

/*
 * Optional reserved chunk.  This chunk reserves part of the first
 * chunk and serves it for reserved allocations.  The amount of
 * reserved offset is in pcpu_reserved_chunk_limit.  When reserved
 * area doesn't exist, the following variables contain NULL and 0
 * respectively.
 */
static struct pcpu_chunk *pcpu_reserved_chunk;
static int pcpu_reserved_chunk_limit;

/*
 * Synchronization rules.
 *
 * There are two locks - pcpu_alloc_mutex and pcpu_lock.  The former
 * protects allocation/reclaim paths, chunks, populated bitmap and
 * vmalloc mapping.  The latter is a spinlock and protects the index
 * data structures - chunk slots, chunks and area maps in chunks.
 *
 * During allocation, pcpu_alloc_mutex is kept locked all the time and
 * pcpu_lock is grabbed and released as necessary.  All actual memory
 * allocations are done using GFP_KERNEL with pcpu_lock released.  In
 * general, percpu memory can't be allocated with irq off but
 * irqsave/restore are still used in alloc path so that it can be used
 * from early init path - sched_init() specifically.
 *
 * Free path accesses and alters only the index data structures, so it
 * can be safely called from atomic context.  When memory needs to be
 * returned to the system, free path schedules reclaim_work which
 * grabs both pcpu_alloc_mutex and pcpu_lock, unlinks chunks to be
 * reclaimed, release both locks and frees the chunks.  Note that it's
 * necessary to grab both locks to remove a chunk from circulation as
 * allocation path might be referencing the chunk with only
 * pcpu_alloc_mutex locked.
 */
static DEFINE_MUTEX(pcpu_alloc_mutex);	/* protects whole alloc and reclaim */
static DEFINE_SPINLOCK(pcpu_lock);	/* protects index data structures */

static struct list_head *pcpu_slot __read_mostly; /* chunk list slots */

/* reclaim work to release fully free chunks, scheduled from free path */
static void pcpu_reclaim(struct work_struct *work);
static DECLARE_WORK(pcpu_reclaim_work, pcpu_reclaim);

static bool pcpu_addr_in_first_chunk(void *addr)
{
	void *first_start = pcpu_first_chunk->base_addr;

	return addr >= first_start && addr < first_start + pcpu_unit_size;
}

static bool pcpu_addr_in_reserved_chunk(void *addr)
{
	void *first_start = pcpu_first_chunk->base_addr;

	return addr >= first_start &&
		addr < first_start + pcpu_reserved_chunk_limit;
}

// size : unit_size
static int __pcpu_size_to_slot(int size)
{
	int highbit = fls(size);	/* size is in bytes */
	// highbit : 14
	
	return max(highbit - PCPU_SLOT_BASE_SHIFT + 2, 1);
}

// size : 0x3000
static int pcpu_size_to_slot(int size)
{
	if (size == pcpu_unit_size)
		return pcpu_nr_slots - 1;
	return __pcpu_size_to_slot(size);
	// 11 반환
}

// chunk : dchunk
static int pcpu_chunk_slot(const struct pcpu_chunk *chunk)
{
	// chunk->free_size : 0x3000, chunk->contig_hint : 0x3000
	if (chunk->free_size < sizeof(int) || chunk->contig_hint < sizeof(int))
		return 0;

	// chunk->free_size : 0x3000
	return pcpu_size_to_slot(chunk->free_size);
}

/* set the pointer to a chunk in a page struct */
static void pcpu_set_page_chunk(struct page *page, struct pcpu_chunk *pcpu)
{
	page->index = (unsigned long)pcpu;
}

/* obtain pointer to a chunk from a page struct */
static struct pcpu_chunk *pcpu_get_page_chunk(struct page *page)
{
	return (struct pcpu_chunk *)page->index;
}

static int __maybe_unused pcpu_page_idx(unsigned int cpu, int page_idx)
{
	return pcpu_unit_map[cpu] * pcpu_unit_pages + page_idx;
}

// chunk : pcpu_slot[11]의 chunk, cpu : 0, page_idx : 0
static unsigned long pcpu_chunk_addr(struct pcpu_chunk *chunk,
				     unsigned int cpu, int page_idx)
{
	return (unsigned long)chunk->base_addr + pcpu_unit_offsets[cpu] +
		(page_idx << PAGE_SHIFT);
}

static void __maybe_unused pcpu_next_unpop(struct pcpu_chunk *chunk,
					   int *rs, int *re, int end)
{
	*rs = find_next_zero_bit(chunk->populated, end, *rs);
	*re = find_next_bit(chunk->populated, end, *rs + 1);
}

// chunk : pcpu_slot[11]에 걸린 chunk, rs, re, end : 4
static void __maybe_unused pcpu_next_pop(struct pcpu_chunk *chunk,
					 int *rs, int *re, int end)
{
	// *rs = 3, chunk->populated : 0xFF
	*rs = find_next_bit(chunk->populated, end, *rs);
	// *rs : 0x4

	*re = find_next_zero_bit(chunk->populated, end, *rs + 1);
	// *re : 0x4
}

/*
 * (Un)populated page region iterators.  Iterate over (un)populated
 * page regions between @start and @end in @chunk.  @rs and @re should
 * be integer variables and will be set to start and end page index of
 * the current region.
 */
#define pcpu_for_each_unpop_region(chunk, rs, re, start, end)		    \
	for ((rs) = (start), pcpu_next_unpop((chunk), &(rs), &(re), (end)); \
	     (rs) < (re);						    \
	     (rs) = (re) + 1, pcpu_next_unpop((chunk), &(rs), &(re), (end)))

#define pcpu_for_each_pop_region(chunk, rs, re, start, end)		    \
	for ((rs) = (start), pcpu_next_pop((chunk), &(rs), &(re), (end));   \
	     (rs) < (re);						    \
	     (rs) = (re) + 1, pcpu_next_pop((chunk), &(rs), &(re), (end)))

/**
 * pcpu_mem_zalloc - allocate memory
 * @size: bytes to allocate
 *
 * Allocate @size bytes.  If @size is smaller than PAGE_SIZE,
 * kzalloc() is used; otherwise, vzalloc() is used.  The returned
 * memory is always zeroed.
 *
 * CONTEXT:
 * Does GFP_KERNEL allocation.
 *
 * RETURNS:
 * Pointer to the allocated area on success, NULL on failure.
 */
// size : 128
// size : 512
static void *pcpu_mem_zalloc(size_t size)
{
	// slab_is_available() : 0
	if (WARN_ON_ONCE(!slab_is_available()))
		return NULL; // NULL 반환

	// size : 512, PAGE_SIZE : 4KB
	if (size <= PAGE_SIZE)
		// 이 쪽으로 들어옴
		return kzalloc(size, GFP_KERNEL);
		// slab 할당자를 이용해 512크기의 오브젝트를 생성해 반환함
		// kmem_cache#6-o1이 반환됨
	else
		return vzalloc(size);
}

/**
 * pcpu_mem_free - free memory
 * @ptr: memory to free
 * @size: size of the area
 *
 * Free @ptr.  @ptr should have been allocated using pcpu_mem_zalloc().
 */
static void pcpu_mem_free(void *ptr, size_t size)
{
	if (size <= PAGE_SIZE)
		kfree(ptr);
	else
		vfree(ptr);
}

/**
 * pcpu_chunk_relocate - put chunk in the appropriate chunk slot
 * @chunk: chunk of interest
 * @oslot: the previous slot it was on
 *
 * This function is called after an allocation or free changed @chunk.
 * New slot according to the changed state is determined and @chunk is
 * moved to the slot.  Note that the reserved chunk is never put on
 * chunk slots.
 *
 * CONTEXT:
 * pcpu_lock.
 */
// chunk : dchunk, oslot : -1
static void pcpu_chunk_relocate(struct pcpu_chunk *chunk, int oslot)
{
	int nslot = pcpu_chunk_slot(chunk);
	// nslot : 11
	// chunk->free_size 값을 이용해 계산함

	// pcpu_reserved_chunk : schunk, oslot : -1, nslot : 11
	if (chunk != pcpu_reserved_chunk && oslot != nslot) {
		if (oslot < nslot)
			list_move(&chunk->list, &pcpu_slot[nslot]);
			// dchunk->list를 pcpu_slot[11]에 연결시킴
		else
			list_move_tail(&chunk->list, &pcpu_slot[nslot]);
	}
}

/**
 * pcpu_need_to_extend - determine whether chunk area map needs to be extended
 * @chunk: chunk of interest
 *
 * Determine whether area map of @chunk needs to be extended to
 * accommodate a new allocation.
 *
 * CONTEXT:
 * pcpu_lock.
 *
 * RETURNS:
 * New target map allocation length if extension is necessary, 0
 * otherwise.
 */
static int pcpu_need_to_extend(struct pcpu_chunk *chunk)
{
	int new_alloc;

	// chunk->map_alloc : 128, chunk->map_used : 2
	if (chunk->map_alloc >= chunk->map_used + 2)
		return 0;

	new_alloc = PCPU_DFL_MAP_ALLOC;
	while (new_alloc < chunk->map_used + 2)
		new_alloc *= 2;

	return new_alloc;
}

/**
 * pcpu_extend_area_map - extend area map of a chunk
 * @chunk: chunk of interest
 * @new_alloc: new target allocation length of the area map
 *
 * Extend area map of @chunk to have @new_alloc entries.
 *
 * CONTEXT:
 * Does GFP_KERNEL allocation.  Grabs and releases pcpu_lock.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
static int pcpu_extend_area_map(struct pcpu_chunk *chunk, int new_alloc)
{
	int *old = NULL, *new = NULL;
	size_t old_size = 0, new_size = new_alloc * sizeof(new[0]);
	unsigned long flags;

	new = pcpu_mem_zalloc(new_size);
	if (!new)
		return -ENOMEM;

	/* acquire pcpu_lock and switch to new area map */
	spin_lock_irqsave(&pcpu_lock, flags);

	if (new_alloc <= chunk->map_alloc)
		goto out_unlock;

	old_size = chunk->map_alloc * sizeof(chunk->map[0]);
	old = chunk->map;

	memcpy(new, old, old_size);

	chunk->map_alloc = new_alloc;
	chunk->map = new;
	new = NULL;

out_unlock:
	spin_unlock_irqrestore(&pcpu_lock, flags);

	/*
	 * pcpu_mem_free() might end up calling vfree() which uses
	 * IRQ-unsafe lock and thus can't be called under pcpu_lock.
	 */
	pcpu_mem_free(old, old_size);
	pcpu_mem_free(new, new_size);

	return 0;
}

/**
 * pcpu_split_block - split a map block
 * @chunk: chunk of interest
 * @i: index of map block to split
 * @head: head size in bytes (can be 0)
 * @tail: tail size in bytes (can be 0)
 *
 * Split the @i'th map block into two or three blocks.  If @head is
 * non-zero, @head bytes block is inserted before block @i moving it
 * to @i+1 and reducing its size by @head bytes.
 *
 * If @tail is non-zero, the target block, which can be @i or @i+1
 * depending on @head, is reduced by @tail bytes and @tail byte block
 * is inserted after the target block.
 *
 * @chunk->map must have enough free slots to accommodate the split.
 *
 * CONTEXT:
 * pcpu_lock.
 */
static void pcpu_split_block(struct pcpu_chunk *chunk, int i,
			     int head, int tail)
{
	int nr_extra = !!head + !!tail;

	BUG_ON(chunk->map_alloc < chunk->map_used + nr_extra);

	/* insert new subblocks */
	memmove(&chunk->map[i + nr_extra], &chunk->map[i],
		sizeof(chunk->map[0]) * (chunk->map_used - i));
	chunk->map_used += nr_extra;

	if (head) {
		chunk->map[i + 1] = chunk->map[i] - head;
		chunk->map[i++] = head;
	}
	if (tail) {
		chunk->map[i++] -= tail;
		chunk->map[i] = tail;
	}
}

/**
 * pcpu_alloc_area - allocate area from a pcpu_chunk
 * @chunk: chunk of interest
 * @size: wanted size in bytes
 * @align: wanted align
 *
 * Try to allocate @size bytes area aligned at @align from @chunk.
 * Note that this function only allocates the offset.  It doesn't
 * populate or map the area.
 *
 * @chunk->map must have at least two free slots.
 *
 * CONTEXT:
 * pcpu_lock.
 *
 * RETURNS:
 * Allocated offset in @chunk on success, -1 if no matching area is
 * found.
 */
// chunk : 이전에 만들어 둔 dchunk, size : 16, align : 8
static int pcpu_alloc_area(struct pcpu_chunk *chunk, int size, int align)
{
	int oslot = pcpu_chunk_slot(chunk);
	// oslot : 11
	// pcpu_slot 11번 리스트에 묶어두었음
	int max_contig = 0;
	int i, off;

	// chunk->map_used : 2
	// abs(chunk->map[0]) : -(__per_cpu 실제 할당한 size + 0x2000)
	for (i = 0, off = 0; i < chunk->map_used; off += abs(chunk->map[i++])) {
		bool is_last = i + 1 == chunk->map_used;
		// chunk->map_used : 2
		// is_last = 0
		int head, tail;

		/* extra for alignment requirement */
		head = ALIGN(off, align) - off;
		// head : 0
		BUG_ON(i == 0 && head != 0);

		// chunk->map[0] : -(0x1D00 + 0x2000)
		if (chunk->map[i] < 0)
			continue; // 첫 번째 루프에서는 걸림

		// [2] i : 1, chunk->map[1] : 0x3000, head : 0, size : 16
		if (chunk->map[i] < head + size) {
			max_contig = max(chunk->map[i], max_contig);
			continue;
		}

		/*
		 * If head is small or the previous block is free,
		 * merge'em.  Note that 'small' is defined as smaller
		 * than sizeof(int), which is very small but isn't too
		 * uncommon for percpu allocations.
		 */
		// [2] i : 1, chunk->map[0] : -(0x1D00 + 0x2000), head : 0, size : 16
		if (head && (head < sizeof(int) || chunk->map[i - 1] > 0)) {
			if (chunk->map[i - 1] > 0)
				chunk->map[i - 1] += head;
			else {
				chunk->map[i - 1] -= head;
				chunk->free_size -= head;
			}
			chunk->map[i] -= head;
			off += head;
			head = 0;
		}

		/* if tail is small, just keep it around */
		tail = chunk->map[i] - head - size;
		// tail : 0x2FF0

		if (tail < sizeof(int))
			tail = 0;

		// head : 0, tail : 0x2FF0
		/* split if warranted */
		if (head || tail) {
			pcpu_split_block(chunk, i, head, tail);
			if (head) {
				i++;
				off += head;
				max_contig = max(chunk->map[i - 1], max_contig);
			}
			if (tail)
				max_contig = max(chunk->map[i + 1], max_contig);
		}

		/* update hint and mark allocated */
		if (is_last)
			chunk->contig_hint = max_contig; /* fully scanned */
		else
			chunk->contig_hint = max(chunk->contig_hint,
						 max_contig);

		chunk->free_size -= chunk->map[i];
		chunk->map[i] = -chunk->map[i];

		pcpu_chunk_relocate(chunk, oslot);
		return off;
	}

	chunk->contig_hint = max_contig;	/* fully scanned */
	pcpu_chunk_relocate(chunk, oslot);

	/* tell the upper layer that this chunk has no matching area */
	return -1;
}

/**
 * pcpu_free_area - free area to a pcpu_chunk
 * @chunk: chunk of interest
 * @freeme: offset of area to free
 *
 * Free area starting from @freeme to @chunk.  Note that this function
 * only modifies the allocation map.  It doesn't depopulate or unmap
 * the area.
 *
 * CONTEXT:
 * pcpu_lock.
 */
static void pcpu_free_area(struct pcpu_chunk *chunk, int freeme)
{
	int oslot = pcpu_chunk_slot(chunk);
	int i, off;

	for (i = 0, off = 0; i < chunk->map_used; off += abs(chunk->map[i++]))
		if (off == freeme)
			break;
	BUG_ON(off != freeme);
	BUG_ON(chunk->map[i] > 0);

	chunk->map[i] = -chunk->map[i];
	chunk->free_size += chunk->map[i];

	/* merge with previous? */
	if (i > 0 && chunk->map[i - 1] >= 0) {
		chunk->map[i - 1] += chunk->map[i];
		chunk->map_used--;
		memmove(&chunk->map[i], &chunk->map[i + 1],
			(chunk->map_used - i) * sizeof(chunk->map[0]));
		i--;
	}
	/* merge with next? */
	if (i + 1 < chunk->map_used && chunk->map[i + 1] >= 0) {
		chunk->map[i] += chunk->map[i + 1];
		chunk->map_used--;
		memmove(&chunk->map[i + 1], &chunk->map[i + 2],
			(chunk->map_used - (i + 1)) * sizeof(chunk->map[0]));
	}

	chunk->contig_hint = max(chunk->map[i], chunk->contig_hint);
	pcpu_chunk_relocate(chunk, oslot);
}

static struct pcpu_chunk *pcpu_alloc_chunk(void)
{
	struct pcpu_chunk *chunk;

	chunk = pcpu_mem_zalloc(pcpu_chunk_struct_size);
	if (!chunk)
		return NULL;

	chunk->map = pcpu_mem_zalloc(PCPU_DFL_MAP_ALLOC *
						sizeof(chunk->map[0]));
	if (!chunk->map) {
		kfree(chunk);
		return NULL;
	}

	chunk->map_alloc = PCPU_DFL_MAP_ALLOC;
	chunk->map[chunk->map_used++] = pcpu_unit_size;

	INIT_LIST_HEAD(&chunk->list);
	chunk->free_size = pcpu_unit_size;
	chunk->contig_hint = pcpu_unit_size;

	return chunk;
}

static void pcpu_free_chunk(struct pcpu_chunk *chunk)
{
	if (!chunk)
		return;
	pcpu_mem_free(chunk->map, chunk->map_alloc * sizeof(chunk->map[0]));
	pcpu_mem_free(chunk, pcpu_chunk_struct_size);
}

/*
 * Chunk management implementation.
 *
 * To allow different implementations, chunk alloc/free and
 * [de]population are implemented in a separate file which is pulled
 * into this file and compiled together.  The following functions
 * should be implemented.
 *
 * pcpu_populate_chunk		- populate the specified range of a chunk
 * pcpu_depopulate_chunk	- depopulate the specified range of a chunk
 * pcpu_create_chunk		- create a new chunk
 * pcpu_destroy_chunk		- destroy a chunk, always preceded by full depop
 * pcpu_addr_to_page		- translate address to physical address
 * pcpu_verify_alloc_info	- check alloc_info is acceptable during init
 */
static int pcpu_populate_chunk(struct pcpu_chunk *chunk, int off, int size);
static void pcpu_depopulate_chunk(struct pcpu_chunk *chunk, int off, int size);
static struct pcpu_chunk *pcpu_create_chunk(void);
static void pcpu_destroy_chunk(struct pcpu_chunk *chunk);
static struct page *pcpu_addr_to_page(void *addr);
static int __init pcpu_verify_alloc_info(const struct pcpu_alloc_info *ai);

#ifdef CONFIG_NEED_PER_CPU_KM
#include "percpu-km.c"
#else
#include "percpu-vm.c"
#endif

/**
 * pcpu_chunk_addr_search - determine chunk containing specified address
 * @addr: address for which the chunk needs to be determined.
 *
 * RETURNS:
 * The address of the found chunk.
 */
static struct pcpu_chunk *pcpu_chunk_addr_search(void *addr)
{
	/* is it in the first chunk? */
	if (pcpu_addr_in_first_chunk(addr)) {
		/* is it in the reserved area? */
		if (pcpu_addr_in_reserved_chunk(addr))
			return pcpu_reserved_chunk;
		return pcpu_first_chunk;
	}

	/*
	 * The address is relative to unit0 which might be unused and
	 * thus unmapped.  Offset the address to the unit space of the
	 * current processor before looking it up in the vmalloc
	 * space.  Note that any possible cpu id can be used here, so
	 * there's no need to worry about preemption or cpu hotplug.
	 */
	addr += pcpu_unit_offsets[raw_smp_processor_id()];
	return pcpu_get_page_chunk(pcpu_addr_to_page(addr));
}

/**
 * pcpu_alloc - the percpu allocator
 * @size: size of area to allocate in bytes
 * @align: alignment of area (max PAGE_SIZE)
 * @reserved: allocate from the reserved chunk if available
 *
 * Allocate percpu area of @size bytes aligned at @align.
 *
 * CONTEXT:
 * Does GFP_KERNEL allocation.
 *
 * RETURNS:
 * Percpu pointer to the allocated area on success, NULL on failure.
 */
// size : 16, align : 8, reserved : false
static void __percpu *pcpu_alloc(size_t size, size_t align, bool reserved)
{
	static int warn_limit = 10;
	struct pcpu_chunk *chunk;
	const char *err;
	int slot, off, new_alloc;
	unsigned long flags;
	void __percpu *ptr;

	if (unlikely(!size || size > PCPU_MIN_UNIT_SIZE || align > PAGE_SIZE)) {
		WARN(true, "illegal size (%zu) or align (%zu) for "
		     "percpu allocation\n", size, align);
		return NULL;
	}

	mutex_lock(&pcpu_alloc_mutex);
	// mutex 락을 걸음

	spin_lock_irqsave(&pcpu_lock, flags);
	// spin 락을 검

	/* serve reserved allocations from the reserved chunk if available */
	// reserved : false
	if (reserved && pcpu_reserved_chunk) {
		chunk = pcpu_reserved_chunk;

		if (size > chunk->contig_hint) {
			err = "alloc from reserved chunk failed";
			goto fail_unlock;
		}

		while ((new_alloc = pcpu_need_to_extend(chunk))) {
			spin_unlock_irqrestore(&pcpu_lock, flags);
			if (pcpu_extend_area_map(chunk, new_alloc) < 0) {
				err = "failed to extend area map of reserved chunk";
				goto fail_unlock_mutex;
			}
			spin_lock_irqsave(&pcpu_lock, flags);
		}

		off = pcpu_alloc_area(chunk, size, align);
		if (off >= 0)
			goto area_found;

		err = "alloc from reserved chunk failed";
		goto fail_unlock;
	}

restart:
	/* search through normal chunks */
	// size : 16 (kmem_cache_cpu의 크기), pcpu_nr_slots : 15
	// pcpu_size_to_slot(16) : 1
	for (slot = pcpu_size_to_slot(size); slot < pcpu_nr_slots; slot++) {

		// slot 11일 때 아래로 들어옴
		list_for_each_entry(chunk, &pcpu_slot[slot], list) {

			// chunk->contig_hint : 0x3000
			if (size > chunk->contig_hint)
				continue;
			// contig_hint에는 현재 chunk의 남은 공간이 저장되어 있음
			// 이것보다 size가 크면 현재 chunk에는 저장이 불가능하다는 뜻이 되므로
			// 다음 chunk를 찾도록 함

			new_alloc = pcpu_need_to_extend(chunk);
			// new_alloc : 0

			if (new_alloc) {
				spin_unlock_irqrestore(&pcpu_lock, flags);
				if (pcpu_extend_area_map(chunk,
							 new_alloc) < 0) {
					err = "failed to extend area map";
					goto fail_unlock_mutex;
				}
				spin_lock_irqsave(&pcpu_lock, flags);
				/*
				 * pcpu_lock has been dropped, need to
				 * restart cpu_slot list walking.
				 */
				goto restart;
			}

			// chunk : 이전에 만들어 둔 것, size : 16, align : 8
			off = pcpu_alloc_area(chunk, size, align);
			// chunk에서 size 만큼의 공간을 확보한 뒤 offset을 반환함

			if (off >= 0)
				goto area_found;
		}
	}

	/* hmmm... no space left, create a new chunk */
	spin_unlock_irqrestore(&pcpu_lock, flags);

	chunk = pcpu_create_chunk();
	if (!chunk) {
		err = "failed to allocate new chunk";
		goto fail_unlock_mutex;
	}

	spin_lock_irqsave(&pcpu_lock, flags);
	pcpu_chunk_relocate(chunk, -1);
	goto restart;

area_found:
	spin_unlock_irqrestore(&pcpu_lock, flags);
	// spin lock 해제

	/* populate, map and clear the area */
	// chunk : dchunk, off : kmem_cache_cpu를 넣을 위치의 offset, size : 16(kmem_cache_cpu의 크기)
	if (pcpu_populate_chunk(chunk, off, size)) {
		// chunk가 담당하는 공간의 cpu0부터 cpu3번까지 dynamic 영역 중에
		// kmem_cache_cpu를 넣을 공간을 0 으로 초기화
		spin_lock_irqsave(&pcpu_lock, flags);
		pcpu_free_area(chunk, off);
		err = "failed to populate";
		goto fail_unlock;
	}

	mutex_unlock(&pcpu_alloc_mutex);
	// mutex 해제

	/* return address relative to base address */
	ptr = __addr_to_pcpu_ptr(chunk->base_addr + off);
	// ptr : chunk->base_addr + off - pcpu_base_addr + __per_cpu_start
	// 결국 ptr은 off + __per_cpu_start가 됨
	kmemleak_alloc_percpu(ptr, size);
	// NULL 함수

	return ptr;

fail_unlock:
	spin_unlock_irqrestore(&pcpu_lock, flags);
fail_unlock_mutex:
	mutex_unlock(&pcpu_alloc_mutex);
	if (warn_limit) {
		pr_warning("PERCPU: allocation failed, size=%zu align=%zu, "
			   "%s\n", size, align, err);
		dump_stack();
		if (!--warn_limit)
			pr_info("PERCPU: limit reached, disable warning\n");
	}
	return NULL;
}

/**
 * __alloc_percpu - allocate dynamic percpu area
 * @size: size of area to allocate in bytes
 * @align: alignment of area (max PAGE_SIZE)
 *
 * Allocate zero-filled percpu area of @size bytes aligned at @align.
 * Might sleep.  Might trigger writeouts.
 *
 * CONTEXT:
 * Does GFP_KERNEL allocation.
 *
 * RETURNS:
 * Percpu pointer to the allocated area on success, NULL on failure.
 */
// size : 16, align : 8
// size : 4, align : 4
void __percpu *__alloc_percpu(size_t size, size_t align)
{
	return pcpu_alloc(size, align, false);
}
EXPORT_SYMBOL_GPL(__alloc_percpu);

/**
 * __alloc_reserved_percpu - allocate reserved percpu area
 * @size: size of area to allocate in bytes
 * @align: alignment of area (max PAGE_SIZE)
 *
 * Allocate zero-filled percpu area of @size bytes aligned at @align
 * from reserved percpu area if arch has set it up; otherwise,
 * allocation is served from the same dynamic area.  Might sleep.
 * Might trigger writeouts.
 *
 * CONTEXT:
 * Does GFP_KERNEL allocation.
 *
 * RETURNS:
 * Percpu pointer to the allocated area on success, NULL on failure.
 */
void __percpu *__alloc_reserved_percpu(size_t size, size_t align)
{
	return pcpu_alloc(size, align, true);
}

/**
 * pcpu_reclaim - reclaim fully free chunks, workqueue function
 * @work: unused
 *
 * Reclaim all fully free chunks except for the first one.
 *
 * CONTEXT:
 * workqueue context.
 */
static void pcpu_reclaim(struct work_struct *work)
{
	LIST_HEAD(todo);
	struct list_head *head = &pcpu_slot[pcpu_nr_slots - 1];
	struct pcpu_chunk *chunk, *next;

	mutex_lock(&pcpu_alloc_mutex);
	spin_lock_irq(&pcpu_lock);

	list_for_each_entry_safe(chunk, next, head, list) {
		WARN_ON(chunk->immutable);

		/* spare the first one */
		if (chunk == list_first_entry(head, struct pcpu_chunk, list))
			continue;

		list_move(&chunk->list, &todo);
	}

	spin_unlock_irq(&pcpu_lock);

	list_for_each_entry_safe(chunk, next, &todo, list) {
		pcpu_depopulate_chunk(chunk, 0, pcpu_unit_size);
		pcpu_destroy_chunk(chunk);
	}

	mutex_unlock(&pcpu_alloc_mutex);
}

/**
 * free_percpu - free percpu area
 * @ptr: pointer to area to free
 *
 * Free percpu area @ptr.
 *
 * CONTEXT:
 * Can be called from atomic context.
 */
void free_percpu(void __percpu *ptr)
{
	void *addr;
	struct pcpu_chunk *chunk;
	unsigned long flags;
	int off;

	if (!ptr)
		return;

	kmemleak_free_percpu(ptr);

	addr = __pcpu_ptr_to_addr(ptr);

	spin_lock_irqsave(&pcpu_lock, flags);

	chunk = pcpu_chunk_addr_search(addr);
	off = addr - chunk->base_addr;

	pcpu_free_area(chunk, off);

	/* if there are more than one fully free chunks, wake up grim reaper */
	if (chunk->free_size == pcpu_unit_size) {
		struct pcpu_chunk *pos;

		list_for_each_entry(pos, &pcpu_slot[pcpu_nr_slots - 1], list)
			if (pos != chunk) {
				schedule_work(&pcpu_reclaim_work);
				break;
			}
	}

	spin_unlock_irqrestore(&pcpu_lock, flags);
}
EXPORT_SYMBOL_GPL(free_percpu);

/**
 * is_kernel_percpu_address - test whether address is from static percpu area
 * @addr: address to test
 *
 * Test whether @addr belongs to in-kernel static percpu area.  Module
 * static percpu areas are not considered.  For those, use
 * is_module_percpu_address().
 *
 * RETURNS:
 * %true if @addr is from in-kernel static percpu area, %false otherwise.
 */
bool is_kernel_percpu_address(unsigned long addr)
{
#ifdef CONFIG_SMP
	const size_t static_size = __per_cpu_end - __per_cpu_start;
	void __percpu *base = __addr_to_pcpu_ptr(pcpu_base_addr);
	unsigned int cpu;

	for_each_possible_cpu(cpu) {
		void *start = per_cpu_ptr(base, cpu);

		if ((void *)addr >= start && (void *)addr < start + static_size)
			return true;
        }
#endif
	/* on UP, can't distinguish from other static vars, always false */
	return false;
}

/**
 * per_cpu_ptr_to_phys - convert translated percpu address to physical address
 * @addr: the address to be converted to physical address
 *
 * Given @addr which is dereferenceable address obtained via one of
 * percpu access macros, this function translates it into its physical
 * address.  The caller is responsible for ensuring @addr stays valid
 * until this function finishes.
 *
 * percpu allocator has special setup for the first chunk, which currently
 * supports either embedding in linear address space or vmalloc mapping,
 * and, from the second one, the backing allocator (currently either vm or
 * km) provides translation.
 *
 * The addr can be tranlated simply without checking if it falls into the
 * first chunk. But the current code reflects better how percpu allocator
 * actually works, and the verification can discover both bugs in percpu
 * allocator itself and per_cpu_ptr_to_phys() callers. So we keep current
 * code.
 *
 * RETURNS:
 * The physical address for @addr.
 */
phys_addr_t per_cpu_ptr_to_phys(void *addr)
{
	void __percpu *base = __addr_to_pcpu_ptr(pcpu_base_addr);
	bool in_first_chunk = false;
	unsigned long first_low, first_high;
	unsigned int cpu;

	/*
	 * The following test on unit_low/high isn't strictly
	 * necessary but will speed up lookups of addresses which
	 * aren't in the first chunk.
	 */
	first_low = pcpu_chunk_addr(pcpu_first_chunk, pcpu_low_unit_cpu, 0);
	first_high = pcpu_chunk_addr(pcpu_first_chunk, pcpu_high_unit_cpu,
				     pcpu_unit_pages);
	if ((unsigned long)addr >= first_low &&
	    (unsigned long)addr < first_high) {
		for_each_possible_cpu(cpu) {
			void *start = per_cpu_ptr(base, cpu);

			if (addr >= start && addr < start + pcpu_unit_size) {
				in_first_chunk = true;
				break;
			}
		}
	}

	if (in_first_chunk) {
		if (!is_vmalloc_addr(addr))
			return __pa(addr);
		else
			return page_to_phys(vmalloc_to_page(addr)) +
			       offset_in_page(addr);
	} else
		return page_to_phys(pcpu_addr_to_page(addr)) +
		       offset_in_page(addr);
}

/**
 * pcpu_alloc_alloc_info - allocate percpu allocation info
 * @nr_groups: the number of groups
 * @nr_units: the number of units
 *
 * Allocate ai which is large enough for @nr_groups groups containing
 * @nr_units units.  The returned ai's groups[0].cpu_map points to the
 * cpu_map array which is long enough for @nr_units and filled with
 * NR_CPUS.  It's the caller's responsibility to initialize cpu_map
 * pointer of other groups.
 *
 * RETURNS:
 * Pointer to the allocated pcpu_alloc_info on success, NULL on
 * failure.
 */
// nr_groups : 1, nr_units : 4
struct pcpu_alloc_info * __init pcpu_alloc_alloc_info(int nr_groups,
						      int nr_units)
{
	struct pcpu_alloc_info *ai;
	size_t base_size, ai_size;
	void *ptr;
	int unit;

	// sizeof(*ai) : 32, nr_groups : 1, sizeof(ai->groups[0]) : 12
	base_size = ALIGN(sizeof(*ai) + nr_groups * sizeof(ai->groups[0]),
			  __alignof__(ai->groups[0].cpu_map[0]));
	// base_size : 44

	ai_size = base_size + nr_units * sizeof(ai->groups[0].cpu_map[0]);
	// ai_size : 60
	// pcpu_alloc_info에 현재 타깃의 cpu 그룹, cpu 정보를 저장해야함.
	// 이 정보들은 groups 멤버와 cpu_map 멤버에 저장됨.
	// 필요한 크기는 타깃마다 달라짐
	// 60 = struct pcpu_alloc_info + struct pcpu_group_info * 1 + int * 4
	//	전체 관리용		그룹 관리용 1개			cpu 관리용 4개

	ptr = alloc_bootmem_nopanic(PFN_ALIGN(ai_size));
	// 그 크기만큼 할당받음

	if (!ptr)
		return NULL;

	ai = ptr;
	// ai : 할당 받은 시작 위치

	ptr += base_size;
	// struct pcpu_alloc_info + struct pcpu_group_info 크기만큼 띄운 위치를 ptr에 저장

	ai->groups[0].cpu_map = ptr;
	// 연달아 있는 주소를 cpu_map에 저장

	// 할당 받은 공간이 struct pcpu_alloc_info >> struct pcpu_group_info 1개 >> int 4개

	for (unit = 0; unit < nr_units; unit++)
		ai->groups[0].cpu_map[unit] = NR_CPUS;
	// ai->groups[0].cpu_map[0] : 4
	// ai->groups[0].cpu_map[1] : 4
	// ai->groups[0].cpu_map[2] : 4
	// ai->groups[0].cpu_map[3] : 4

	ai->nr_groups = nr_groups;
	// ai->nr_groups : 1
	ai->__ai_size = PFN_ALIGN(ai_size);
	// ai->__ai_size : 0x1000

	return ai;
}

/**
 * pcpu_free_alloc_info - free percpu allocation info
 * @ai: pcpu_alloc_info to free
 *
 * Free @ai which was allocated by pcpu_alloc_alloc_info().
 */
void __init pcpu_free_alloc_info(struct pcpu_alloc_info *ai)
{
	free_bootmem(__pa(ai), ai->__ai_size);
}

/**
 * pcpu_dump_alloc_info - print out information about pcpu_alloc_info
 * @lvl: loglevel
 * @ai: allocation info to dump
 *
 * Print out information about @ai using loglevel @lvl.
 */
static void pcpu_dump_alloc_info(const char *lvl,
				 const struct pcpu_alloc_info *ai)
{
	int group_width = 1, cpu_width = 1, width;
	char empty_str[] = "--------";
	int alloc = 0, alloc_end = 0;
	int group, v;
	int upa, apl;	/* units per alloc, allocs per line */

	v = ai->nr_groups;
	while (v /= 10)
		group_width++;

	v = num_possible_cpus();
	while (v /= 10)
		cpu_width++;
	empty_str[min_t(int, cpu_width, sizeof(empty_str) - 1)] = '\0';

	upa = ai->alloc_size / ai->unit_size;
	width = upa * (cpu_width + 1) + group_width + 3;
	apl = rounddown_pow_of_two(max(60 / width, 1));

	printk("%spcpu-alloc: s%zu r%zu d%zu u%zu alloc=%zu*%zu",
	       lvl, ai->static_size, ai->reserved_size, ai->dyn_size,
	       ai->unit_size, ai->alloc_size / ai->atom_size, ai->atom_size);

	for (group = 0; group < ai->nr_groups; group++) {
		const struct pcpu_group_info *gi = &ai->groups[group];
		int unit = 0, unit_end = 0;

		BUG_ON(gi->nr_units % upa);
		for (alloc_end += gi->nr_units / upa;
		     alloc < alloc_end; alloc++) {
			if (!(alloc % apl)) {
				printk(KERN_CONT "\n");
				printk("%spcpu-alloc: ", lvl);
			}
			printk(KERN_CONT "[%0*d] ", group_width, group);

			for (unit_end += upa; unit < unit_end; unit++)
				if (gi->cpu_map[unit] != NR_CPUS)
					printk(KERN_CONT "%0*d ", cpu_width,
					       gi->cpu_map[unit]);
				else
					printk(KERN_CONT "%s ", empty_str);
		}
	}
	printk(KERN_CONT "\n");
}

/**
 * pcpu_setup_first_chunk - initialize the first percpu chunk
 * @ai: pcpu_alloc_info describing how to percpu area is shaped
 * @base_addr: mapped address
 *
 * Initialize the first percpu chunk which contains the kernel static
 * perpcu area.  This function is to be called from arch percpu area
 * setup path.
 *
 * @ai contains all information necessary to initialize the first
 * chunk and prime the dynamic percpu allocator.
 *
 * @ai->static_size is the size of static percpu area.
 *
 * @ai->reserved_size, if non-zero, specifies the amount of bytes to
 * reserve after the static area in the first chunk.  This reserves
 * the first chunk such that it's available only through reserved
 * percpu allocation.  This is primarily used to serve module percpu
 * static areas on architectures where the addressing model has
 * limited offset range for symbol relocations to guarantee module
 * percpu symbols fall inside the relocatable range.
 *
 * @ai->dyn_size determines the number of bytes available for dynamic
 * allocation in the first chunk.  The area between @ai->static_size +
 * @ai->reserved_size + @ai->dyn_size and @ai->unit_size is unused.
 *
 * @ai->unit_size specifies unit size and must be aligned to PAGE_SIZE
 * and equal to or larger than @ai->static_size + @ai->reserved_size +
 * @ai->dyn_size.
 *
 * @ai->atom_size is the allocation atom size and used as alignment
 * for vm areas.
 *
 * @ai->alloc_size is the allocation size and always multiple of
 * @ai->atom_size.  This is larger than @ai->atom_size if
 * @ai->unit_size is larger than @ai->atom_size.
 *
 * @ai->nr_groups and @ai->groups describe virtual memory layout of
 * percpu areas.  Units which should be colocated are put into the
 * same group.  Dynamic VM areas will be allocated according to these
 * groupings.  If @ai->nr_groups is zero, a single group containing
 * all units is assumed.
 *
 * The caller should have mapped the first chunk at @base_addr and
 * copied static data to each unit.
 *
 * If the first chunk ends up with both reserved and dynamic areas, it
 * is served by two chunks - one to serve the core static and reserved
 * areas and the other for the dynamic area.  They share the same vm
 * and page map but uses different area allocation map to stay away
 * from each other.  The latter chunk is circulated in the chunk slots
 * and available for dynamic allocation like any other chunks.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
// ai : struct pcpu_alloc_info*
// base_addr : cpu들을 위한 static + dynamic + reserved 영역들의 시작 주소
int __init pcpu_setup_first_chunk(const struct pcpu_alloc_info *ai,
				  void *base_addr)
{
	static char cpus_buf[4096] __initdata;
	// PERCPU_DYNAMIC_EARLY_SLOTS : 128
	static int smap[PERCPU_DYNAMIC_EARLY_SLOTS] __initdata;
	static int dmap[PERCPU_DYNAMIC_EARLY_SLOTS] __initdata;
	size_t dyn_size = ai->dyn_size;
	// dyn_size : 0x3000
	size_t size_sum = ai->static_size + ai->reserved_size + dyn_size;
	// size_sum : static + dynamic + reserved
	struct pcpu_chunk *schunk, *dchunk = NULL;
	unsigned long *group_offsets;
	size_t *group_sizes;
	unsigned long *unit_off;
	unsigned int cpu;
	int *unit_map;
	int group, unit, i;

	// sizeof(cpus_buf) : 4096, cpu_possible_mask : 0b1111
	cpumask_scnprintf(cpus_buf, sizeof(cpus_buf), cpu_possible_mask);
	// cpus_buf : "f" 문자열이 들어감 (cpu_possible_mask를 문자열로 바꾼 것)

#define PCPU_SETUP_BUG_ON(cond)	do {					\
	if (unlikely(cond)) {						\
		pr_emerg("PERCPU: failed to initialize, %s", #cond);	\
		pr_emerg("PERCPU: cpu_possible_mask=%s\n", cpus_buf);	\
		pcpu_dump_alloc_info(KERN_EMERG, ai);			\
		BUG();							\
	}								\
} while (0)

	/* sanity checks */
	PCPU_SETUP_BUG_ON(ai->nr_groups <= 0);
#ifdef CONFIG_SMP
	PCPU_SETUP_BUG_ON(!ai->static_size);
	PCPU_SETUP_BUG_ON((unsigned long)__per_cpu_start & ~PAGE_MASK);
#endif
	PCPU_SETUP_BUG_ON(!base_addr);
	PCPU_SETUP_BUG_ON((unsigned long)base_addr & ~PAGE_MASK);
	PCPU_SETUP_BUG_ON(ai->unit_size < size_sum);
	PCPU_SETUP_BUG_ON(ai->unit_size & ~PAGE_MASK);
	PCPU_SETUP_BUG_ON(ai->unit_size < PCPU_MIN_UNIT_SIZE);
	PCPU_SETUP_BUG_ON(ai->dyn_size < PERCPU_DYNAMIC_EARLY_SIZE);
	PCPU_SETUP_BUG_ON(pcpu_verify_alloc_info(ai) < 0);
	// bug 존재 확인

	/* process group information and build config tables accordingly */
	group_offsets = alloc_bootmem(ai->nr_groups * sizeof(group_offsets[0]));
	group_sizes = alloc_bootmem(ai->nr_groups * sizeof(group_sizes[0]));
	unit_map = alloc_bootmem(nr_cpu_ids * sizeof(unit_map[0]));
	unit_off = alloc_bootmem(nr_cpu_ids * sizeof(unit_off[0]));
	// 각 변수에 새로 할당받은 공간의 주소를 저장

	for (cpu = 0; cpu < nr_cpu_ids; cpu++)
		unit_map[cpu] = UINT_MAX;
	// unit_map[0] : UINT_MAX
	// unit_map[1] : UINT_MAX
	// unit_map[2] : UINT_MAX
	// unit_map[3] : UINT_MAX

	pcpu_low_unit_cpu = NR_CPUS;
	pcpu_high_unit_cpu = NR_CPUS;
	// pcpu_low_unit_cpu : 4
	// pcpu_high_unit_cpu : 4

	// ai->nr_groups : 1
	for (group = 0, unit = 0; group < ai->nr_groups; group++, unit += i) {
		const struct pcpu_group_info *gi = &ai->groups[group];

		group_offsets[group] = gi->base_offset;
		// group_offsets[0] : 0

		group_sizes[group] = gi->nr_units * ai->unit_size;
		// groups_sizes[0] : 4 * unit_size

		// gi->nr_units : 4
		for (i = 0; i < gi->nr_units; i++) {
			cpu = gi->cpu_map[i];
			// [0] cpu : 0
			// [1] cpu : 1

			if (cpu == NR_CPUS)
				continue;

			PCPU_SETUP_BUG_ON(cpu > nr_cpu_ids);
			PCPU_SETUP_BUG_ON(!cpu_possible(cpu));
			PCPU_SETUP_BUG_ON(unit_map[cpu] != UINT_MAX);

			unit_map[cpu] = unit + i;
			// unit_map[0] : 0
			// unit_map[1] : 1
			// unit_map[2] : 2
			// unit_map[3] : 3

			unit_off[cpu] = gi->base_offset + i * ai->unit_size;
			// unit_off[0] : 0
			// unit_off[1] : 1 * unit_size
			// unit_off[2] : 2 * unit_size
			// unit_off[3] : 3 * unit_size
			// 
			// 각 cpu별로 static + reserve + dynamic의 offset 값이 저장

			/* determine low/high unit_cpu */
			if (pcpu_low_unit_cpu == NR_CPUS ||
			    unit_off[cpu] < unit_off[pcpu_low_unit_cpu])
				pcpu_low_unit_cpu = cpu;
			if (pcpu_high_unit_cpu == NR_CPUS ||
			    unit_off[cpu] > unit_off[pcpu_high_unit_cpu])
				pcpu_high_unit_cpu = cpu;
			
			// pcpu_low_unit_cpu : 0	cpu 번호 중 가장 작은 값
			// pcpu_high_unit_cpu : 3	cpu 번호 중 가장 큰 값
		}
	}
	pcpu_nr_units = unit;
	// pcpu_nr_units : 4	총 cpu 갯수

	for_each_possible_cpu(cpu)
		PCPU_SETUP_BUG_ON(unit_map[cpu] == UINT_MAX);

	/* we're done parsing the input, undefine BUG macro and dump config */
#undef PCPU_SETUP_BUG_ON
	pcpu_dump_alloc_info(KERN_DEBUG, ai);
	// DEBUG 정보 출력

	pcpu_nr_groups = ai->nr_groups;		// group 개수
	pcpu_group_offsets = group_offsets;	// 각 group의 area 내의 오프셋
	pcpu_group_sizes = group_sizes;		// 각 group내의 cpu들을 위한 static + dynamic + reserved 공간 합
	pcpu_unit_map = unit_map;		// cpu 번호
	pcpu_unit_offsets = unit_off;		// 각 cpu의 전용 공간 시작 오프셋
	// 모든 오프셋의 베이스 값은 base_addr
	// 전역 변수에 위에서 할당받은 공간을 차례대로 저장
	// 나중에 사용할 것으로 생각됨

	/* determine basic parameters */
	pcpu_unit_pages = ai->unit_size >> PAGE_SHIFT;
	// pcpu_unit_pages : unit_size의 페이지 개수 저장

	pcpu_unit_size = pcpu_unit_pages << PAGE_SHIFT;
	// pcpu_unit_size : unit_size 저장

	pcpu_atom_size = ai->atom_size;
	// pcpu_atom_size : 할당 최소 단위인 4KB 저장

	pcpu_chunk_struct_size = sizeof(struct pcpu_chunk) +
		BITS_TO_LONGS(pcpu_unit_pages) * sizeof(unsigned long);
	// pcpu_chunk_struct_size : struct pcpu_chunk용 공간의 크기를 저장

	/*
	 * Allocate chunk slots.  The additional last slot is for
	 * empty chunks.
	 */
	// pcup_unit_size : unit_size
	pcpu_nr_slots = __pcpu_size_to_slot(pcpu_unit_size) + 2;
	// pcpu_nr_slots : 15

	pcpu_slot = alloc_bootmem(pcpu_nr_slots * sizeof(pcpu_slot[0]));
	// pcpu_slot : slot 개수만큼 list_head를 만듬
	//	       이를 위한 공간을 할당 받고 시작 주소를 pcpu_slot에 저장함
	for (i = 0; i < pcpu_nr_slots; i++)
		INIT_LIST_HEAD(&pcpu_slot[i]);
	// 위에서 만든 list 초기화

	/*
	 * Initialize static chunk.  If reserved_size is zero, the
	 * static chunk covers static area + dynamic allocation area
	 * in the first chunk.  If reserved_size is not zero, it
	 * covers static area + reserved area (mostly used for module
	 * static percpu allocation).
	 */
	schunk = alloc_bootmem(pcpu_chunk_struct_size);
	// schunk : struct pcpu_chunk를 저장하기 위한 공간 할당 받음
	INIT_LIST_HEAD(&schunk->list);
	// schunk내의 list 초기화
	schunk->base_addr = base_addr;
	// schunk->base_addr : static + dynamic + reserved를 위해 할당받은 공간의 시작 주소
	schunk->map = smap;
	// schunk->map : smap 위치 저장
	schunk->map_alloc = ARRAY_SIZE(smap);
	// schunk->map_alloc : smap의 크기 저장
	schunk->immutable = true;
	// schunk->immutable : true

	// pcpu_unit_pages
	bitmap_fill(schunk->populated, pcpu_unit_pages);
	// schunk->populated[0] : 0xFF

	// ai->reserved_size : 8KB
	if (ai->reserved_size) {
		schunk->free_size = ai->reserved_size;
		// schunk->free_size : 8KB

		pcpu_reserved_chunk = schunk;
		// pcpu_reserved_chunk : schunk 대입
		// 			 나중에 접근 시 사용할 것 같음

		pcpu_reserved_chunk_limit = ai->static_size + ai->reserved_size;
	} else {
		schunk->free_size = dyn_size;
		dyn_size = 0;			/* dynamic area covered */
	}
	schunk->contig_hint = schunk->free_size;
	// schunk->contig_hint : 8KB

	// schunk->map_used : 0
	schunk->map[schunk->map_used++] = -ai->static_size;
	// schunk->map[0] = -static_size

	// schunk->free_size : 0x2000
	if (schunk->free_size)
		schunk->map[schunk->map_used++] = schunk->free_size;
		// schunk->map[1] : 0x2000

	/* init dynamic chunk if necessary */
	if (dyn_size) {
		dchunk = alloc_bootmem(pcpu_chunk_struct_size);
		// dynamic용 chunk를 저장하기 위한 공간을 할당받음

		INIT_LIST_HEAD(&dchunk->list);
		// dchunk->list 초기화

		dchunk->base_addr = base_addr;
		// dchunk->base_addr : CPU 갯수만큼 할당받은 reserved + static + dynamic 공간

		dchunk->map = dmap;
		// dchunk->map : dmap[PERCPU_DYNAMIC_EARLY_SLOTS]

		// ARRAY_SIZE(dmap) : 128
		dchunk->map_alloc = ARRAY_SIZE(dmap);
		// dchunk->map_alloc : 128

		dchunk->immutable = true;

		// pcpu_unit_pages : 0x08
		bitmap_fill(dchunk->populated, pcpu_unit_pages);
		// dchunk->populated[0] : 0xFF

		dchunk->contig_hint = dchunk->free_size = dyn_size;
		// dchunk->contig_hint : 0x3000

		dchunk->map[dchunk->map_used++] = -pcpu_reserved_chunk_limit;
		// dchunk->map[0] : -(static + reserved 크기)

		dchunk->map[dchunk->map_used++] = dchunk->free_size;
		// dchunk->map[1] : 0x3000
		// dchunk 값 초기화
	}

	/* link the first chunk in */
	pcpu_first_chunk = dchunk ?: schunk;
	// pcpu_first_chunk : dchunk
	pcpu_chunk_relocate(pcpu_first_chunk, -1);

	/* we're done */
	pcpu_base_addr = base_addr;
	return 0;
}

#ifdef CONFIG_SMP

const char * const pcpu_fc_names[PCPU_FC_NR] __initconst = {
	[PCPU_FC_AUTO]	= "auto",
	[PCPU_FC_EMBED]	= "embed",
	[PCPU_FC_PAGE]	= "page",
};

enum pcpu_fc pcpu_chosen_fc __initdata = PCPU_FC_AUTO;

static int __init percpu_alloc_setup(char *str)
{
	if (!str)
		return -EINVAL;

	if (0)
		/* nada */;
#ifdef CONFIG_NEED_PER_CPU_EMBED_FIRST_CHUNK
	else if (!strcmp(str, "embed"))
		pcpu_chosen_fc = PCPU_FC_EMBED;
#endif
#ifdef CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK
	else if (!strcmp(str, "page"))
		pcpu_chosen_fc = PCPU_FC_PAGE;
#endif
	else
		pr_warning("PERCPU: unknown allocator %s specified\n", str);

	return 0;
}
early_param("percpu_alloc", percpu_alloc_setup);

/*
 * pcpu_embed_first_chunk() is used by the generic percpu setup.
 * Build it if needed by the arch config or the generic setup is going
 * to be used.
 */
#if defined(CONFIG_NEED_PER_CPU_EMBED_FIRST_CHUNK) || \
	!defined(CONFIG_HAVE_SETUP_PER_CPU_AREA)
#define BUILD_EMBED_FIRST_CHUNK
#endif

/* build pcpu_page_first_chunk() iff needed by the arch config */
#if defined(CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK)
#define BUILD_PAGE_FIRST_CHUNK
#endif

/* pcpu_build_alloc_info() is used by both embed and page first chunk */
#if defined(BUILD_EMBED_FIRST_CHUNK) || defined(BUILD_PAGE_FIRST_CHUNK)
/**
 * pcpu_build_alloc_info - build alloc_info considering distances between CPUs
 * @reserved_size: the size of reserved percpu area in bytes
 * @dyn_size: minimum free size for dynamic allocation in bytes
 * @atom_size: allocation atom size
 * @cpu_distance_fn: callback to determine distance between cpus, optional
 *
 * This function determines grouping of units, their mappings to cpus
 * and other parameters considering needed percpu size, allocation
 * atom size and distances between CPUs.
 *
 * Groups are always mutliples of atom size and CPUs which are of
 * LOCAL_DISTANCE both ways are grouped together and share space for
 * units in the same group.  The returned configuration is guaranteed
 * to have CPUs on different nodes on different groups and >=75% usage
 * of allocated virtual address space.
 *
 * RETURNS:
 * On success, pointer to the new allocation_info is returned.  On
 * failure, ERR_PTR value is returned.
 */
// reserved_size : 0x2000, dyn_size : 0x3000, atom_size : 0x1000, cpu_distance_fn : NULL
static struct pcpu_alloc_info * __init pcpu_build_alloc_info(
				size_t reserved_size, size_t dyn_size,
				size_t atom_size,
				pcpu_fc_cpu_distance_fn_t cpu_distance_fn)
{
	static int group_map[NR_CPUS] __initdata;
	static int group_cnt[NR_CPUS] __initdata;
	const size_t static_size = __per_cpu_end - __per_cpu_start;
	int nr_groups = 1, nr_units = 0;
	size_t size_sum, min_unit_size, alloc_size;
	int upa, max_upa, uninitialized_var(best_upa);	/* units_per_alloc */
	int last_allocs, group, unit;
	unsigned int cpu, tcpu;
	struct pcpu_alloc_info *ai;
	unsigned int *cpu_map;

	/* this function may be called multiple times */
	memset(group_map, 0, sizeof(group_map));
	memset(group_cnt, 0, sizeof(group_cnt));
	// group_map, group_cnt 초기화

	/* calculate size_sum and ensure dyn_size is enough for early alloc */
	// static_size : ?, reserved_size : 0x2000, dyn_size : 0x3000, PERCPU_DYNAMIC_EARLY_SIZE : 0x3000
	size_sum = PFN_ALIGN(static_size + reserved_size +
			    max_t(size_t, dyn_size, PERCPU_DYNAMIC_EARLY_SIZE));
	// size_sum : static_size + reserved_size + dyn_size를 페이지 크기로 정렬한 것

	dyn_size = size_sum - static_size - reserved_size;
	// dyn_size : 페이지 정렬로 인해 늘어난 값으로 변경

	/*
	 * Determine min_unit_size, alloc_size and max_upa such that
	 * alloc_size is multiple of atom_size and is the smallest
	 * which can accommodate 4k aligned segments which are equal to
	 * or larger than min_unit_size.
	 */

	// size_sum : ?, PCPU_MIN_UNIT_SIZE : 32K
	min_unit_size = max_t(size_t, size_sum, PCPU_MIN_UNIT_SIZE);
	// min_unit_size : 둘 중 큰 값

	alloc_size = roundup(min_unit_size, atom_size);
	// 4K로 align해서 alloc_size로 저장

	upa = alloc_size / min_unit_size;
	// upa : 1

	while (alloc_size % upa || ((alloc_size / upa) & ~PAGE_MASK))
		upa--;

	max_upa = upa;
	// max_upa : 1

	/* group cpus according to their proximity */
	for_each_possible_cpu(cpu) {
	// for (cpu = -1; cpu = cpumask_next(cpu, cpu_possible_bits), cpu < nr_cpu_ids; )
		group = 0;
	next_group:
		for_each_possible_cpu(tcpu) {
		// for (tcpu = -1; tcpu = cpumask_next(tcpu, cpu_possible_bits), tcpu < nr_cpu_ids; )
			if (cpu == tcpu)
				break;
			if (group_map[tcpu] == group && cpu_distance_fn &&
			    (cpu_distance_fn(cpu, tcpu) > LOCAL_DISTANCE ||
			     cpu_distance_fn(tcpu, cpu) > LOCAL_DISTANCE)) {
				group++;
				nr_groups = max(nr_groups, group + 1);
				goto next_group;
			}
		}
		group_map[cpu] = group;
		group_cnt[group]++;
	}
	// group_map[0] = 0
	// group_map[1] = 0
	// group_map[2] = 0
	// group_map[3] = 0
	// 각 cpu가 어느 그룹에 속하는 지 저장함
	//
	// group_cnt[0] = 4
	// 0번 그룹에 속한 cpu의 갯수
	// cpu_distance_fn이 null이기 때문에 모든 cpu가 그룹 0번에 속하게 됨

	/*
	 * Expand unit size until address space usage goes over 75%
	 * and then as much as possible without using more address
	 * space.
	 */
	last_allocs = INT_MAX;
	// max_upa : 1
	for (upa = max_upa; upa; upa--) {
		int allocs = 0, wasted = 0;
		
		// upa : 1
		if (alloc_size % upa || ((alloc_size / upa) & ~PAGE_MASK))
			continue;

		// nr_groups : 1
		for (group = 0; group < nr_groups; group++) {
			// group_cnt[group] : 4, upa : 1
			int this_allocs = DIV_ROUND_UP(group_cnt[group], upa);
			// this_allocs : 4
			
			allocs += this_allocs;
			// allocs : 4

			wasted += this_allocs * upa - group_cnt[group];
			// wasted : 0
		}

		/*
		 * Don't accept if wastage is over 1/3.  The
		 * greater-than comparison ensures upa==1 always
		 * passes the following check.
		 */
		// num_possible_cpus() : 4
		if (wasted > num_possible_cpus() / 3)
			continue;

		/* and then don't consume more memory */
		// allocs : 4, last_allocs : INT_MAX
		if (allocs > last_allocs)
			break;
		last_allocs = allocs;
		// last_allocs : 4

		best_upa = upa;
		// best_upa : 1
	}
	upa = best_upa;
	// upa : 1

	/* allocate and fill alloc_info */
	// nr_groups : 1
	for (group = 0; group < nr_groups; group++)
		nr_units += roundup(group_cnt[group], upa);
	// nr_units : 4
	// 모든 cpu를 위한 unit의 갯수

	// nr_groups : 1, nr_units : 4
	ai = pcpu_alloc_alloc_info(nr_groups, nr_units);
	// struct pcpu_alloc_info + struct pcpu_group_info * nr_groups + int * nr_units 만큼 공간 할당
	// 할당 받은 공간은 차례대로  struct pcpu_alloc_info >> struct pcpu_group_info 1개 >> int 4개로 사용됨
	// ai->groups[0].cpu_map[0] : 4
	// ai->groups[0].cpu_map[1] : 4
	// ai->groups[0].cpu_map[2] : 4
	// ai->groups[0].cpu_map[3] : 4
	// ai->nr_groups : 1
	// ai->__ai_size : 0x1000

	if (!ai)
		return ERR_PTR(-ENOMEM);
	cpu_map = ai->groups[0].cpu_map;
	// cpu_map : 위에서 할당 받은 cpu_map 배열의 시작 주소

	// nr_groups : 1
	for (group = 0; group < nr_groups; group++) {
		ai->groups[group].cpu_map = cpu_map;
		// ai->groups[x].cpu_map에 각 그룹의 cpu_map 시작 주소를 대입
		cpu_map += roundup(group_cnt[group], upa);
	}

	ai->static_size = static_size;
	// ai->static_size :  __per_cpu_end - __per_cpu_start;
	ai->reserved_size = reserved_size;
	// ai->reserved_size : 0x2000
	ai->dyn_size = dyn_size;
	// ai->dyn_size : 0x3000
	ai->unit_size = alloc_size / upa;
	// ai->unit_size : min_unit_size
	ai->atom_size = atom_size;
	// ai->atom_size : 0x1000
	ai->alloc_size = alloc_size;
	// alloc_size : min_unit_size

	// group_cnt[0] : 4
	for (group = 0, unit = 0; group_cnt[group]; group++) {
		struct pcpu_group_info *gi = &ai->groups[group];
		// gi : &groups[0]

		/*
		 * Initialize base_offset as if all groups are located
		 * back-to-back.  The caller should update this to
		 * reflect actual allocation.
		 */
		gi->base_offset = unit * ai->unit_size;
		// ai->groups[0].base_offset : 0

		for_each_possible_cpu(cpu)		// cpu : 0 ~ 3
			if (group_map[cpu] == group)
				gi->cpu_map[gi->nr_units++] = cpu;
				// ai->groups[0].cpu_map[0] : 0
				// ai->groups[0].cpu_map[1] : 1
				// ai->groups[0].cpu_map[2] : 2
				// ai->groups[0].cpu_map[3] : 3
		gi->nr_units = roundup(gi->nr_units, upa);
		// ai->groups[0].nr_units : 4
		unit += gi->nr_units;
		// unit : 4
	}
	BUG_ON(unit != nr_units);

	// ai->nr_groups : 1
	// ai->__ai_size : 0x1000
	// ai->static_size :  __per_cpu_end - __per_cpu_start;
	// ai->reserved_size : 0x2000
	// ai->dyn_size : 0x3000
	// ai->unit_size : min_unit_size
	// ai->atom_size : 0x1000
	// ai->alloc_size : min_unit_size
	// ai->groups[0].cpu_map[0] : 0
	// ai->groups[0].cpu_map[1] : 1
	// ai->groups[0].cpu_map[2] : 2
	// ai->groups[0].cpu_map[3] : 3
	// ai->groups[0].nr_units : 4
	// ai->groups[0].base_offset : 0

	return ai;
}
#endif /* BUILD_EMBED_FIRST_CHUNK || BUILD_PAGE_FIRST_CHUNK */

#if defined(BUILD_EMBED_FIRST_CHUNK)
/**
 * pcpu_embed_first_chunk - embed the first percpu chunk into bootmem
 * @reserved_size: the size of reserved percpu area in bytes
 * @dyn_size: minimum free size for dynamic allocation in bytes
 * @atom_size: allocation atom size
 * @cpu_distance_fn: callback to determine distance between cpus, optional
 * @alloc_fn: function to allocate percpu page
 * @free_fn: function to free percpu page
 *
 * This is a helper to ease setting up embedded first percpu chunk and
 * can be called where pcpu_setup_first_chunk() is expected.
 *
 * If this function is used to setup the first chunk, it is allocated
 * by calling @alloc_fn and used as-is without being mapped into
 * vmalloc area.  Allocations are always whole multiples of @atom_size
 * aligned to @atom_size.
 *
 * This enables the first chunk to piggy back on the linear physical
 * mapping which often uses larger page size.  Please note that this
 * can result in very sparse cpu->unit mapping on NUMA machines thus
 * requiring large vmalloc address space.  Don't use this allocator if
 * vmalloc space is not orders of magnitude larger than distances
 * between node memory addresses (ie. 32bit NUMA machines).
 *
 * @dyn_size specifies the minimum dynamic area size.
 *
 * If the needed size is smaller than the minimum or specified unit
 * size, the leftover is returned using @free_fn.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
// reserved_size : 0x2000, dyn_size : 0x3000, atom_size : 0x1000, cpu_distance_fn : NULL
// alloc_fn : pcpu_dfl_fc_alloc, free_fn : pcpu_dfl_fc_free
int __init pcpu_embed_first_chunk(size_t reserved_size, size_t dyn_size,
				  size_t atom_size,
				  pcpu_fc_cpu_distance_fn_t cpu_distance_fn,
				  pcpu_fc_alloc_fn_t alloc_fn,
				  pcpu_fc_free_fn_t free_fn)
{
	void *base = (void *)ULONG_MAX;
	void **areas = NULL;
	struct pcpu_alloc_info *ai;
	size_t size_sum, areas_size, max_distance;
	int group, i, rc;

	// reserved_size : 0x2000, dyn_size : 0x3000, atom_size : 0x1000, cpu_distance_fn : NULL
	ai = pcpu_build_alloc_info(reserved_size, dyn_size, atom_size,
				   cpu_distance_fn);
	// struct pcpu_alloc_info, struct pcpu_group_info 1개, int 4개 할당 받은 후
	// 내부 멤버 값을 설정

	if (IS_ERR(ai))
		return PTR_ERR(ai);

	size_sum = ai->static_size + ai->reserved_size + ai->dyn_size;
	// size_sum : 할당 받을 크기 인 듯
	
	// ai->nr_groups : 1
	areas_size = PFN_ALIGN(ai->nr_groups * sizeof(void *));
	// areas_size : 4K

	areas = alloc_bootmem_nopanic(areas_size);
	// areas : 4K 할당 받음 (그룹 당 void* 한 개씩)
	if (!areas) {
		rc = -ENOMEM;
		goto out_free;
	}

	/* allocate, copy and determine base address */
	for (group = 0; group < ai->nr_groups; group++) {
		struct pcpu_group_info *gi = &ai->groups[group];
		// gi : &ai->groups[0]
		unsigned int cpu = NR_CPUS;
		// cpu : 4
		void *ptr;

		// gi->nr_units : 4
		for (i = 0; i < gi->nr_units && cpu == NR_CPUS; i++)
			cpu = gi->cpu_map[i];
		// cpu : 0
		BUG_ON(cpu == NR_CPUS);

		/* allocate space for the whole group */
		// cpu : 0, gi->nr_units : 4, ai->unit_size : ?, atom_size : 0x1000, alloc_fn : pcpu_dfl_fc_alloc
		ptr = alloc_fn(cpu, gi->nr_units * ai->unit_size, atom_size);
		// cpu마다 static + dynamic + reserved를 하나 씩 확보
		// 4개 공간을 할당 받아 ptr에 저장

		if (!ptr) {
			rc = -ENOMEM;
			goto out_free_areas;
		}
		/* kmemleak tracks the percpu allocations separately */
		kmemleak_free(ptr);
		// NULL 함수

		areas[group] = ptr;
		// areas[0] : 그룹에 해당하는 cpu를 위한 static + dynamic + reserved 영역들의 시작 주소

		base = min(ptr, base);
		// base : areas[0]
	}

	/*
	 * Copy data and free unused parts.  This should happen after all
	 * allocations are complete; otherwise, we may end up with
	 * overlapping groups.
	 */
	for (group = 0; group < ai->nr_groups; group++) {
		struct pcpu_group_info *gi = &ai->groups[group];
		void *ptr = areas[group];
		// ptr : areas[0]

		// gi->nr_units : 4, ai->unit_size : static + dynamic + reserved
		for (i = 0; i < gi->nr_units; i++, ptr += ai->unit_size) {
			if (gi->cpu_map[i] == NR_CPUS) {
				/* unused unit, free whole */
				free_fn(ptr, ai->unit_size);
				continue;
			}
			/* copy and return the unused part */
			// 각 cpu의 static 영역에 __per_cpu_load 값을 저장
			memcpy(ptr, __per_cpu_load, ai->static_size);
			// free_fn : pcpu_dfl_fc_free
			free_fn(ptr + size_sum, ai->unit_size - size_sum);
			// min_unit_size에서 static + reserved + dyn 크기를 빼면
			// 쓰지 않는 빈 공간 크기가 나옴
			// 이를 해제함
		}
	}

	/* base address is now known, determine group base offsets */
	max_distance = 0;
	
	// ai->nr_groups : 1
	for (group = 0; group < ai->nr_groups; group++) {
		// base : areas[0]
		ai->groups[group].base_offset = areas[group] - base;
		// ai->groups[0].base_offset : 0

		max_distance = max_t(size_t, max_distance,
				     ai->groups[group].base_offset);
		// max_distance : 0
	}
	max_distance += ai->unit_size;
	// max_distance : ai->unit_size

	/* warn if maximum distance is further than 75% of vmalloc space */
	if (max_distance > (VMALLOC_END - VMALLOC_START) * 3 / 4) {
		pr_warning("PERCPU: max_distance=0x%zx too large for vmalloc "
			   "space 0x%lx\n", max_distance,
			   (unsigned long)(VMALLOC_END - VMALLOC_START));
#ifdef CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK
		/* and fail if we have fallback */
		rc = -EINVAL;
		goto out_free;
#endif
	}

	pr_info("PERCPU: Embedded %zu pages/cpu @%p s%zu r%zu d%zu u%zu\n",
		PFN_DOWN(size_sum), base, ai->static_size, ai->reserved_size,
		ai->dyn_size, ai->unit_size);

	// ai : struct pcpu_alloc_info*
	// base : cpu들을 위한 static + dynamic + reserved 영역들의 시작 주소
	rc = pcpu_setup_first_chunk(ai, base);
	goto out_free;

out_free_areas:
	for (group = 0; group < ai->nr_groups; group++)
		if (areas[group])
			free_fn(areas[group],
				ai->groups[group].nr_units * ai->unit_size);
out_free:
	pcpu_free_alloc_info(ai);
	// ai : struct pcpu_alloc_info 구조체를 해제함
	if (areas)
		free_bootmem(__pa(areas), areas_size);
		// areas 전부 해제
	return rc;
}
#endif /* BUILD_EMBED_FIRST_CHUNK */

#ifdef BUILD_PAGE_FIRST_CHUNK
/**
 * pcpu_page_first_chunk - map the first chunk using PAGE_SIZE pages
 * @reserved_size: the size of reserved percpu area in bytes
 * @alloc_fn: function to allocate percpu page, always called with PAGE_SIZE
 * @free_fn: function to free percpu page, always called with PAGE_SIZE
 * @populate_pte_fn: function to populate pte
 *
 * This is a helper to ease setting up page-remapped first percpu
 * chunk and can be called where pcpu_setup_first_chunk() is expected.
 *
 * This is the basic allocator.  Static percpu area is allocated
 * page-by-page into vmalloc area.
 *
 * RETURNS:
 * 0 on success, -errno on failure.
 */
int __init pcpu_page_first_chunk(size_t reserved_size,
				 pcpu_fc_alloc_fn_t alloc_fn,
				 pcpu_fc_free_fn_t free_fn,
				 pcpu_fc_populate_pte_fn_t populate_pte_fn)
{
	static struct vm_struct vm;
	struct pcpu_alloc_info *ai;
	char psize_str[16];
	int unit_pages;
	size_t pages_size;
	struct page **pages;
	int unit, i, j, rc;

	snprintf(psize_str, sizeof(psize_str), "%luK", PAGE_SIZE >> 10);

	ai = pcpu_build_alloc_info(reserved_size, 0, PAGE_SIZE, NULL);
	if (IS_ERR(ai))
		return PTR_ERR(ai);
	BUG_ON(ai->nr_groups != 1);
	BUG_ON(ai->groups[0].nr_units != num_possible_cpus());

	unit_pages = ai->unit_size >> PAGE_SHIFT;

	/* unaligned allocations can't be freed, round up to page size */
	pages_size = PFN_ALIGN(unit_pages * num_possible_cpus() *
			       sizeof(pages[0]));
	pages = alloc_bootmem(pages_size);

	/* allocate pages */
	j = 0;
	for (unit = 0; unit < num_possible_cpus(); unit++)
		for (i = 0; i < unit_pages; i++) {
			unsigned int cpu = ai->groups[0].cpu_map[unit];
			void *ptr;

			ptr = alloc_fn(cpu, PAGE_SIZE, PAGE_SIZE);
			if (!ptr) {
				pr_warning("PERCPU: failed to allocate %s page "
					   "for cpu%u\n", psize_str, cpu);
				goto enomem;
			}
			/* kmemleak tracks the percpu allocations separately */
			kmemleak_free(ptr);
			pages[j++] = virt_to_page(ptr);
		}

	/* allocate vm area, map the pages and copy static data */
	vm.flags = VM_ALLOC;
	vm.size = num_possible_cpus() * ai->unit_size;
	vm_area_register_early(&vm, PAGE_SIZE);

	for (unit = 0; unit < num_possible_cpus(); unit++) {
		unsigned long unit_addr =
			(unsigned long)vm.addr + unit * ai->unit_size;

		for (i = 0; i < unit_pages; i++)
			populate_pte_fn(unit_addr + (i << PAGE_SHIFT));

		/* pte already populated, the following shouldn't fail */
		rc = __pcpu_map_pages(unit_addr, &pages[unit * unit_pages],
				      unit_pages);
		if (rc < 0)
			panic("failed to map percpu area, err=%d\n", rc);

		/*
		 * FIXME: Archs with virtual cache should flush local
		 * cache for the linear mapping here - something
		 * equivalent to flush_cache_vmap() on the local cpu.
		 * flush_cache_vmap() can't be used as most supporting
		 * data structures are not set up yet.
		 */

		/* copy static data */
		memcpy((void *)unit_addr, __per_cpu_load, ai->static_size);
	}

	/* we're ready, commit */
	pr_info("PERCPU: %d %s pages/cpu @%p s%zu r%zu d%zu\n",
		unit_pages, psize_str, vm.addr, ai->static_size,
		ai->reserved_size, ai->dyn_size);

	rc = pcpu_setup_first_chunk(ai, vm.addr);
	goto out_free_ar;

enomem:
	while (--j >= 0)
		free_fn(page_address(pages[j]), PAGE_SIZE);
	rc = -ENOMEM;
out_free_ar:
	free_bootmem(__pa(pages), pages_size);
	pcpu_free_alloc_info(ai);
	return rc;
}
#endif /* BUILD_PAGE_FIRST_CHUNK */

#ifndef	CONFIG_HAVE_SETUP_PER_CPU_AREA
/*
 * Generic SMP percpu area setup.
 *
 * The embedding helper is used because its behavior closely resembles
 * the original non-dynamic generic percpu area setup.  This is
 * important because many archs have addressing restrictions and might
 * fail if the percpu area is located far away from the previous
 * location.  As an added bonus, in non-NUMA cases, embedding is
 * generally a good idea TLB-wise because percpu area can piggy back
 * on the physical linear memory mapping which uses large page
 * mappings on applicable archs.
 */
unsigned long __per_cpu_offset[NR_CPUS] __read_mostly;
EXPORT_SYMBOL(__per_cpu_offset);

// cpu : 0, size : gi->nr_units(4) * ai->unit_size, align : 0x1000
static void * __init pcpu_dfl_fc_alloc(unsigned int cpu, size_t size,
				       size_t align)
{
	// size : gi->nr_units(4) * ai->unit_size, align : 0x1000
	return __alloc_bootmem_nopanic(size, align, __pa(MAX_DMA_ADDRESS));
}

static void __init pcpu_dfl_fc_free(void *ptr, size_t size)
{
	free_bootmem(__pa(ptr), size);
}

void __init setup_per_cpu_areas(void)
{
	unsigned long delta;
	unsigned int cpu;
	int rc;

	/*
	 * Always reserve area for module percpu variables.  That's
	 * what the legacy allocator did.
	 */
	// PERCPU_MODULE_RESERVE : 0x2000, PERCPU_DYNAMIC_RESERVE : 0x3000, PAGE_SIZE : 0x1000
	rc = pcpu_embed_first_chunk(PERCPU_MODULE_RESERVE,
				    PERCPU_DYNAMIC_RESERVE, PAGE_SIZE, NULL,
				    pcpu_dfl_fc_alloc, pcpu_dfl_fc_free);
	// cpu마다 static + dynamic + reserved를 하나 씩 확보하고
	// pcpu 관련 전역 변수 값을 설정해 줌.

	if (rc < 0)
		panic("Failed to initialize percpu areas.");

	delta = (unsigned long)pcpu_base_addr - (unsigned long)__per_cpu_start;
	for_each_possible_cpu(cpu)
		__per_cpu_offset[cpu] = delta + pcpu_unit_offsets[cpu];
	// __per_cpu_offset[0] = 첫 번째 코어가 사용할 static + dynamic + reserved 의 오프셋
	// __per_cpu_offset[1] = 두 번째 코어가 사용할 static + dynamic + reserved 의 오프셋
	// __per_cpu_offset[2] = 세 번째 코어가 사용할 static + dynamic + reserved 의 오프셋
	// __per_cpu_offset[3] = 네 번째 코어가 사용할 static + dynamic + reserved 의 오프셋
	// 베이스 주소는 __per_cpu_start가 됨
	// __per_cpu_start와 __per_cpu_offset을 이용하면 각 코어가 사용하는 공간의 가상 주소를 얻을 수 있음
}
#endif	/* CONFIG_HAVE_SETUP_PER_CPU_AREA */

#else	/* CONFIG_SMP */

/*
 * UP percpu area setup.
 *
 * UP always uses km-based percpu allocator with identity mapping.
 * Static percpu variables are indistinguishable from the usual static
 * variables and don't require any special preparation.
 */
void __init setup_per_cpu_areas(void)
{
	const size_t unit_size =
		roundup_pow_of_two(max_t(size_t, PCPU_MIN_UNIT_SIZE,
					 PERCPU_DYNAMIC_RESERVE));
	struct pcpu_alloc_info *ai;
	void *fc;

	ai = pcpu_alloc_alloc_info(1, 1);
	fc = __alloc_bootmem(unit_size, PAGE_SIZE, __pa(MAX_DMA_ADDRESS));
	if (!ai || !fc)
		panic("Failed to allocate memory for percpu areas.");
	/* kmemleak tracks the percpu allocations separately */
	kmemleak_free(fc);

	ai->dyn_size = unit_size;
	ai->unit_size = unit_size;
	ai->atom_size = unit_size;
	ai->alloc_size = unit_size;
	ai->groups[0].nr_units = 1;
	ai->groups[0].cpu_map[0] = 0;

	if (pcpu_setup_first_chunk(ai, fc) < 0)
		panic("Failed to initialize percpu areas.");
}

#endif	/* CONFIG_SMP */

/*
 * First and reserved chunks are initialized with temporary allocation
 * map in initdata so that they can be used before slab is online.
 * This function is called after slab is brought up and replaces those
 * with properly allocated maps.
 */
void __init percpu_init_late(void)
{
	struct pcpu_chunk *target_chunks[] =
		{ pcpu_first_chunk, pcpu_reserved_chunk, NULL };
	// pcpu_first_chunk : pcpu_setup_first_chunk() 함수에서 할당한 dchunk
	// pcpu_reserved_chunk : pcpu_setup_first_chunk() 함수에서 할당한 schunk

	struct pcpu_chunk *chunk;
	unsigned long flags;
	int i;

	for (i = 0; (chunk = target_chunks[i]); i++) {
		int *map;

		// PERCPU_DYNAMIC_EARLY_SLOTS : 128
		const size_t size = PERCPU_DYNAMIC_EARLY_SLOTS * sizeof(map[0]);
		// size : 128 * 4
		// 	  512

		BUILD_BUG_ON(size > PAGE_SIZE);

		// size : 512
		map = pcpu_mem_zalloc(size);
		// slab 할당자를 이용해 512크기의 오브젝트를 생성해 반환함
		// kmem_cache#6-o1이 반환됨
		
		BUG_ON(!map);

		spin_lock_irqsave(&pcpu_lock, flags);
		memcpy(map, chunk->map, size);
		// chunk->map의 정보를 kmem_cache#6-o1에 전부 복사
		// 이전에 만든 kmem_cache_cpu 정보들을 전부 슬랩 공간으로 복사함

		chunk->map = map;
		// 이제부터 percpu_alloc이 걸리면 슬랩 공간에서 가져다 씀(?)

		spin_unlock_irqrestore(&pcpu_lock, flags);
	}
}
