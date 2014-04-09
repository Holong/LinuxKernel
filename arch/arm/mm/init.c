/*
 *  linux/arch/arm/mm/init.c
 *
 *  Copyright (C) 1995-2005 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/swap.h>
#include <linux/init.h>
#include <linux/bootmem.h>
#include <linux/mman.h>
#include <linux/export.h>
#include <linux/nodemask.h>
#include <linux/initrd.h>
#include <linux/of_fdt.h>
#include <linux/highmem.h>
#include <linux/gfp.h>
#include <linux/memblock.h>
#include <linux/dma-contiguous.h>
#include <linux/sizes.h>

#include <asm/mach-types.h>
#include <asm/memblock.h>
#include <asm/prom.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <asm/tlb.h>
#include <asm/fixmap.h>

#include <asm/mach/arch.h>
#include <asm/mach/map.h>

#include "mm.h"

static phys_addr_t phys_initrd_start __initdata = 0;
static unsigned long phys_initrd_size __initdata = 0;

static int __init early_initrd(char *p)
{
	phys_addr_t start;
	unsigned long size;
	char *endp;

	start = memparse(p, &endp);
	if (*endp == ',') {
		size = memparse(endp + 1, NULL);

		phys_initrd_start = start;
		phys_initrd_size = size;
	}
	return 0;
}
early_param("initrd", early_initrd);

static int __init parse_tag_initrd(const struct tag *tag)
{
	printk(KERN_WARNING "ATAG_INITRD is deprecated; "
		"please update your bootloader.\n");
	phys_initrd_start = __virt_to_phys(tag->u.initrd.start);
	phys_initrd_size = tag->u.initrd.size;
	return 0;
}

__tagtable(ATAG_INITRD, parse_tag_initrd);

static int __init parse_tag_initrd2(const struct tag *tag)
{
	phys_initrd_start = tag->u.initrd.start;
	phys_initrd_size = tag->u.initrd.size;
	return 0;
}

__tagtable(ATAG_INITRD2, parse_tag_initrd2);

#ifdef CONFIG_OF_FLATTREE
void __init early_init_dt_setup_initrd_arch(unsigned long start, unsigned long end)
{
	phys_initrd_start = start;
	phys_initrd_size = end - start;
}
#endif /* CONFIG_OF_FLATTREE */

/*
 * This keeps memory configuration data used by a couple memory
 * initialization functions, as well as show_mem() for the skipping
 * of holes in the memory map.  It is populated by arm_add_memory().
 */
struct meminfo meminfo;

void show_mem(unsigned int filter)
{
	int free = 0, total = 0, reserved = 0;
	int shared = 0, cached = 0, slab = 0, i;
	struct meminfo * mi = &meminfo;

	printk("Mem-info:\n");
	show_free_areas(filter);

	if (filter & SHOW_MEM_FILTER_PAGE_COUNT)
		return;

	for_each_bank (i, mi) {
		struct membank *bank = &mi->bank[i];
		unsigned int pfn1, pfn2;
		struct page *page, *end;

		pfn1 = bank_pfn_start(bank);
		pfn2 = bank_pfn_end(bank);

		page = pfn_to_page(pfn1);
		end  = pfn_to_page(pfn2 - 1) + 1;

		do {
			total++;
			if (PageReserved(page))
				reserved++;
			else if (PageSwapCache(page))
				cached++;
			else if (PageSlab(page))
				slab++;
			else if (!page_count(page))
				free++;
			else
				shared += page_count(page) - 1;
			page++;
		} while (page < end);
	}

	printk("%d pages of RAM\n", total);
	printk("%d free pages\n", free);
	printk("%d reserved pages\n", reserved);
	printk("%d slab pages\n", slab);
	printk("%d pages shared\n", shared);
	printk("%d pages swap cached\n", cached);
}

// *min : ??, *max_low : 0, *max_high : 0
static void __init find_limits(unsigned long *min, unsigned long *max_low,
			       unsigned long *max_high)
{
	struct meminfo *mi = &meminfo;
	// 이전에 meminfo에 bank0, bank1 정보를 저장해 두었음
	int i;

	/* This assumes the meminfo array is properly sorted */
	*min = bank_pfn_start(&mi->bank[0]);
	// 이전에 만들었던 뱅크 0 시작 주소의 물리 프레임 번호를 가져옴
	// *min : 0x20000
	for_each_bank (i, mi)
	// for (i = 0; i < (mi)->nr_banks; i++)	, mi->nr_banks : 2, mi->bank[1].highmem = 1
		if (mi->bank[i].highmem)
				break;
	*max_low = bank_pfn_end(&mi->bank[i - 1]);
	// 뱅크 0의 마지막 주소의 물리 small page 번호를 가져옴 
	// max_low : 0x4F800
	*max_high = bank_pfn_end(&mi->bank[mi->nr_banks - 1]);
	// 뱅크 1의 마지막 주소의 물리 small page 번호를 가져옴
	// max_high : 0xA0000
}

// start_pfn : 뱅크 0 시작 주소의 물리 small page 번호		(0x20000)
// end_pfn   : 뱅크 0의 마지막 주소의 물리 small page 번호	(0x4f800)
static void __init arm_bootmem_init(unsigned long start_pfn,
	unsigned long end_pfn)
{
	struct memblock_region *reg;
	unsigned int boot_pages;
	phys_addr_t bitmap;
	pg_data_t *pgdat;
	// pg_data_t : struct pglist_data

	/*
	 * Allocate the bootmem bitmap page.  This must be in a region
	 * of memory which has already been mapped.
	 */
	boot_pages = bootmem_bootmap_pages(end_pfn - start_pfn);
	// boot_pages : 6
	// start_pfn ~ end_pfn 까지를 bitmap으로 바꿨을 때 총 프레임의 갯수가 반환됨.
	
	// boot_pages << PAGE_SHIFT : 0x6000, L1_CACHE_BYTES : 64, _pfn_to_phys(end_pfn) : 0x4F800000
	bitmap = memblock_alloc_base(boot_pages << PAGE_SHIFT, L1_CACHE_BYTES,
				__pfn_to_phys(end_pfn));
	// non-reserved 영역에서 비트맵용 영역을 만들어 가져옴
	// 영역의 시작 주소가 반환됨(물리)

	/*
	 * Initialise the bootmem allocator, handing the
	 * memory banks over to bootmem.
	 */
	node_set_online(0);	// 비어 있는 함수임
	pgdat = NODE_DATA(0);
	//*pgdat = contig_page_data
	//
	//	.bdata = &bootmem_node_data[0]
	//			 현재는 0으로 되어 있는 값임
	//
	init_bootmem_node(pgdat, __phys_to_pfn(bitmap), start_pfn, end_pfn);
	// bdata_list 에 등록
	// bitmap 값을 0xFF로 초기화

	/* Free the lowmem regions from memblock into bootmem. */
	for_each_memblock(memory, reg) {
	// for (reg = memblock.memory.regions; reg < (memblock.memory.regions + memblock.memory.cnt), reg++)
		unsigned long start = memblock_region_memory_base_pfn(reg);
		unsigned long end = memblock_region_memory_end_pfn(reg);
		// start : 0x20000
		// end   : 0xA0000

		if (end >= end_pfn)
			end = end_pfn;
		if (start >= end)
			break;
		
		// start : 0x20000000, (end - start) << PAGE_SHIFT : 0x2F800000
		free_bootmem(__pfn_to_phys(start), (end - start) << PAGE_SHIFT);
		// start부터 end에 해당하는 bitmap을 전부 0으로 설정
		// 일단 전부 FREE로 만듬
	}

	/* Reserve the lowmem memblock reserved regions in bootmem. */
	for_each_memblock(reserved, reg) {
	// for (reg = memblock.reserved.regions; reg < (memblock.reserved.regions + memblock.reserved.cnt), reg++)
		unsigned long start = memblock_region_reserved_base_pfn(reg);
		unsigned long end = memblock_region_reserved_end_pfn(reg);

		if (end >= end_pfn)
			end = end_pfn;
		if (start >= end)
			break;

		// start : 0x20000000, (end - start) << PAGE_SHIFT : 0x2F800000
		reserve_bootmem(__pfn_to_phys(start),
			        (end - start) << PAGE_SHIFT, BOOTMEM_DEFAULT);
		// start부터 end에 해당하는 bitmap 중 reserved 영역을 1로 설정
	}
}

#ifdef CONFIG_ZONE_DMA

unsigned long arm_dma_zone_size __read_mostly;
EXPORT_SYMBOL(arm_dma_zone_size);

/*
 * The DMA mask corresponding to the maximum bus address allocatable
 * using GFP_DMA.  The default here places no restriction on DMA
 * allocations.  This must be the smallest DMA mask in the system,
 * so a successful GFP_DMA allocation will always satisfy this.
 */
phys_addr_t arm_dma_limit;

static void __init arm_adjust_dma_zone(unsigned long *size, unsigned long *hole,
	unsigned long dma_size)
{
	if (size[0] <= dma_size)
		return;

	size[ZONE_NORMAL] = size[0] - dma_size;
	size[ZONE_DMA] = dma_size;
	hole[ZONE_NORMAL] = hole[0];
	hole[ZONE_DMA] = 0;
}
#endif

void __init setup_dma_zone(struct machine_desc *mdesc)
{
#ifdef CONFIG_ZONE_DMA
	if (mdesc->dma_zone_size) {
		arm_dma_zone_size = mdesc->dma_zone_size;
		arm_dma_limit = PHYS_OFFSET + arm_dma_zone_size - 1;
	} else
		arm_dma_limit = 0xffffffff;
#endif
}

// min      : 뱅크 0 시작 주소의 물리 small page 번호		(0x20000)
// max_low  : 뱅크 0의 마지막 주소의 물리 small page 번호	(0x4f800)
// max_high : 뱅크 1의 마지막 주소의 물리 small page 번호	(0xA0000)
static void __init arm_bootmem_free(unsigned long min, unsigned long max_low,
	unsigned long max_high)
{
	unsigned long zone_size[MAX_NR_ZONES], zhole_size[MAX_NR_ZONES];
	// MAX_NR_ZONES : 3
	struct memblock_region *reg;

	/*
	 * initialise the zones.
	 */
	memset(zone_size, 0, sizeof(zone_size));
	// zone_size를 0으로 초기화

	/*
	 * The memory size has already been determined.  If we need
	 * to do anything fancy with the allocation of this memory
	 * to the zones, now is the time to do it.
	 */
	zone_size[0] = max_low - min;
	// zone_size[0] : 0x2F800
#ifdef CONFIG_HIGHMEM
	zone_size[ZONE_HIGHMEM] = max_high - max_low;
	// zone_size[1] = : 0x50800
#endif

	/*
	 * Calculate the size of the holes.
	 *  holes = node_size - sum(bank_sizes)
	 */
	memcpy(zhole_size, zone_size, sizeof(zhole_size));
	// zone_size 값을 zhole_size 로 모두 복사
	for_each_memblock(memory, reg) {
		unsigned long start = memblock_region_memory_base_pfn(reg);
		unsigned long end = memblock_region_memory_end_pfn(reg);
		// start : 0x20000
		// end : 0xA0000

		// max_low : 0x4F800
		if (start < max_low) {
			unsigned long low_end = min(end, max_low);
			// low_end : 0x4F800
			// 중간에 끊어져 있는 경우 end 값이 max_low 값보다 더 작을 수 있음
			zhole_size[0] -= low_end - start;
			// zhole_size[0] : 0
			// 중간이 끊긴 경우 hole이 아닌 곳의 크기가 low_end - start 가 됨
		}
#ifdef CONFIG_HIGHMEM
		if (end > max_low) {
			// end > max_low 이면 hole이 high mem 중간 어딘가에 있다는 뜻이므로
			// 이를 처리해 주어야 함.
			unsigned long high_start = max(start, max_low);
			// high mem의 시작 주소를 저장
			zhole_size[ZONE_HIGHMEM] -= end - high_start;
			// hole이 아닌 곳의 크기가 end - high_start가 됨
		}
#endif
	}
	// hole 크기를 계산하는 동작을 수행함
	// 현재는 모든 메모리가 연속적이기 때문에 hole 값이 0임

#ifdef CONFIG_ZONE_DMA
	/*
	 * Adjust the sizes according to any special requirements for
	 * this machine type.
	 */
	if (arm_dma_zone_size)
		arm_adjust_dma_zone(zone_size, zhole_size,
			arm_dma_zone_size >> PAGE_SHIFT);
#endif
	// min : 0x20000
	// zone_size[0] = 0x2F800, zone_size[1] = 0x50800
	// zhole_size[0] = 0, zhole_size[1] = 0
	free_area_init_node(0, zone_size, min, zhole_size);
}

#ifdef CONFIG_HAVE_ARCH_PFN_VALID
int pfn_valid(unsigned long pfn)
{
	return memblock_is_memory(__pfn_to_phys(pfn));
}
EXPORT_SYMBOL(pfn_valid);
#endif

#ifndef CONFIG_SPARSEMEM
static void __init arm_memory_present(void)
{
}
#else
static void __init arm_memory_present(void)
{
	struct memblock_region *reg;

	for_each_memblock(memory, reg)
	// for (reg = memblock.memory.regions; reg < (memblock.memory.regions + memblock.memory.cnt), reg++)
		memory_present(0, memblock_region_memory_base_pfn(reg),		// base : 0x20000, end : 0xA0000
			       memblock_region_memory_end_pfn(reg));
}
#endif

static bool arm_memblock_steal_permitted = true;

phys_addr_t __init arm_memblock_steal(phys_addr_t size, phys_addr_t align)
{
	phys_addr_t phys;

	BUG_ON(!arm_memblock_steal_permitted);

	phys = memblock_alloc_base(size, align, MEMBLOCK_ALLOC_ANYWHERE);
	memblock_free(phys, size);
	memblock_remove(phys, size);

	return phys;
}

// mdesc :  __mach_desc_EXYNOS5_DT_name		, mi : &meminfo
// 	    mach-exynos5-dt.c에 선언되어 있음
void __init arm_memblock_init(struct meminfo *mi, struct machine_desc *mdesc)
{
	int i;

	for (i = 0; i < mi->nr_banks; i++)
		memblock_add(mi->bank[i].start, mi->bank[i].size);

	/* Register the kernel text, kernel data and initrd with memblock. */
#ifdef CONFIG_XIP_KERNEL
	memblock_reserve(__pa(_sdata), _end - _sdata);
#else
	memblock_reserve(__pa(_stext), _end - _stext);
#endif
#ifdef CONFIG_BLK_DEV_INITRD
	if (phys_initrd_size &&
	    !memblock_is_region_memory(phys_initrd_start, phys_initrd_size)) {
		pr_err("INITRD: 0x%08llx+0x%08lx is not a memory region - disabling initrd\n",
		       (u64)phys_initrd_start, phys_initrd_size);
		phys_initrd_start = phys_initrd_size = 0;
	}
	if (phys_initrd_size &&
	    memblock_is_region_reserved(phys_initrd_start, phys_initrd_size)) {
		pr_err("INITRD: 0x%08llx+0x%08lx overlaps in-use memory region - disabling initrd\n",
		       (u64)phys_initrd_start, phys_initrd_size);
		phys_initrd_start = phys_initrd_size = 0;
	}
	if (phys_initrd_size) {
		memblock_reserve(phys_initrd_start, phys_initrd_size);

		/* Now convert initrd to virtual addresses */
		initrd_start = __phys_to_virt(phys_initrd_start);
		initrd_end = initrd_start + phys_initrd_size;
	}
#endif

	arm_mm_memblock_reserve();
	arm_dt_memblock_reserve();

	/* reserve any platform specific memblock areas */
	if (mdesc->reserve)
		mdesc->reserve();

	/*
	 * reserve memory for DMA contigouos allocations,
	 * must come from DMA area inside low memory
	 */
	dma_contiguous_reserve(min(arm_dma_limit, arm_lowmem_limit));

	arm_memblock_steal_permitted = false;
	memblock_allow_resize();
	memblock_dump_all();
}

void __init bootmem_init(void)
{
	unsigned long min, max_low, max_high;

	max_low = max_high = 0;

	find_limits(&min, &max_low, &max_high);
	// min      : 뱅크 0 시작 주소의 물리 small page 번호		(0x20000)
	// max_low  : 뱅크 0의 마지막 주소의 물리 small page 번호	(0x4f800)
	// max_high : 뱅크 1의 마지막 주소의 물리 small page 번호	(0xA0000)
	
	arm_bootmem_init(min, max_low);
	// bitmap에 reserve 된 것은 1로 세팅하고
	// reserve 안 된 곳은 0으로 만듬
	// 그리고 그 bitmap은 bdata_list에 등록함

	/*
	 * Sparsemem tries to allocate bootmem in memory_present(),
	 * so must be done after the fixed reservations
	 */
	arm_memory_present();
	// &mem_section[0][2] ~ &mem_section[0][10] 까지 section_mem_map 멤버에 1을 저장함

	/*
	 * sparse_init() needs the bootmem allocator up and running.
	 */
	sparse_init();
	// &mem_section[0][2] ~ &mem_section[0][10] 까지 
	// section_mem_map 멤버에 struct page용 공간의 위치를 저장 및 플래그 설정
	// page_block_bitmap 멤버에 0x40 크기의 할당받은 메모리 시작 주소 저장

	/*
	 * Now free the memory - free_area_init_node needs
	 * the sparse mem_map arrays initialized by sparse_init()
	 * for memmap_init_zone(), otherwise all PFNs are invalid.
	 */
	arm_bootmem_free(min, max_low, max_high);
	// contig_page_data 내부 값과 내부 멤버  node_zones[ZONE_NORMAL], node_zones[ZONE_HIGHMEM], node_zones[ZONE_MOVABLE] 값을
	// 설정하였음
	// 
		/*
		이 함수 내부에서 초기화 되는 값들
		struct pglist_data contig_page_data {
			struct zone node_zones[MAX_NR_ZONES];
				// node_zones[ZONE_NORMAL]
				// 	.spanned_pages : 0x2F800 (zone에 해당하는 4KB 페이지 갯수)
				//	.present_pages : 0x2F800 (hole을 제외한 4KB 페이지 갯수)
				//	.managed_pages : 0x2EFD6 (struct page용 공간을 제외한 갯수)
				//	.name : "Normal"
				//	.lock : 초기화됨
				//	.lru_lock : 초기화됨
				//	.zone_pgdat : &contig_page_data (현재 pglist_data 구조체의 시작 주소)
				//	.pageset : &boot_pageset (전역변수)
				//	.lruvec : lruvec.lists[0] ~ lruvec.lists[4] 리스트를 전부 초기화됨
				//	.wait_table_hash_nr_entries : 0x400 (hash 테이블의 pivot 칸 수)
				//	.wait_table_bits : 10	(1 << wait_table_bits 하면 hash의 pivot 칸 수를 뽑아낼 수 있음)
				//	.wait_table : hash의 pivot을 할당 받은 뒤, 시작 주소가 저장됨
						      현재는 1024개의 wait_queue_head_t를 저장할 수 있는 공간이 할당되며
						      초기화 작업까지 수행되었음
				//	.zone_start_pfn : 0x20000 (normal zone의 시작 프레임 번호)
				//	.free_area[0] ~ .free_area[MAX_ORDER] 까지 11개 배열에 대해 내부의
				//		.free_list[0] ~ .free_list[MIGRATE_TYPES] 리스트가 초기화되고, .nr_free 값은 전부 0으로 초기화
				
				// node_zones[ZONE_HIGHMEM]
				// 	.spanned_pages : 0x50800 (zone에 해당하는 4KB 페이지 갯수)
				//	.present_pages : 0x50800 (hole을 제외한 4KB 페이지 갯수)
				//	.managed_pages : 0x50800 (struct page용 공간을 제외한 갯수)
				//	.name : "HighMem"
				//	.lock : 초기화됨
				//	.lru_lock : 초기화됨
				//	.zone_pgdat : &contig_page_data (현재 pglist_data 구조체의 시작 주소)
				//	.pageset : &boot_pageset (전역변수)
				//	.lruvec : lruvec.lists[0] ~ lruvec.lists[4] 리스트를 전부 초기화됨
				//	.wait_table_hash_nr_entries : 0x800 (hash 테이블의 pivot 칸 수)
				//	.wait_table_bits : 11	(1 << wait_table_bits 하면 hash의 pivot 칸 수를 뽑아낼 수 있음)
				//	.wait_table : hash의 pivot을 할당 받은 뒤, 시작 주소가 저장됨
						      현재는 2048개의 wait_queue_head_t를 저장할 수 있는 공간이 할당되며
						      초기화 작업까지 수행되었음
				//	.zone_start_pfn : 0x4F8000 (HighMem zone의 시작 프레임 번호)
				//	.free_area[0] ~ .free_area[MAX_ORDER] 까지 11개 배열에 대해 내부의
				//		.free_list[0] ~ .free_list[MIGRATE_TYPES] 리스트가 초기화되고, .nr_free 값은 전부 0으로 초기화
									
			struct zonelist node_zonelists[MAX_ZONELISTS];	
			int nr_zones;					// 2 : 현재 몇 번째 node_zones 배열까지 처리했는지 기록됨(시작 인덱스가 1)
			struct bootmem_data *bdata;			// 현재 bootmem 정보가 들어 있음
			unsigned long node_start_pfn;			// 0x20000 : 시작 4KB 페이지 번호
			unsigned long node_present_pages; 		// 0x80000 : 모든 zone에 포함되는 4KB 페이지 갯수
			unsigned long node_spanned_pages; 		// 0x80000 : hole을 제외한 4KB 페이지 갯수
			int node_id;					// 0 : NUMA 구조에서만 사용됨
			nodemask_t reclaim_nodes;
			wait_queue_head_t kswapd_wait;			// 리스트 1개 연결
			wait_queue_head_t pfmemalloc_wait;		// 리스트 1개 연결
			struct task_struct *kswapd;
			int kswapd_max_order;
			enum zone_type classzone_idx;
		} pg_data_t;
		*/

	/*
	 * This doesn't seem to be used by the Linux memory manager any
	 * more, but is used by ll_rw_block.  If we can get rid of it, we
	 * also get rid of some of the stuff above as well.
	 *
	 * Note: max_low_pfn and max_pfn reflect the number of _pages_ in
	 * the system, not the maximum PFN.
	 */

	max_low_pfn = max_low - PHYS_PFN_OFFSET;
	// max_low : 0x4F800, PHYS_PFN_OFFSET : 0x20000
	// max_low_pfn : 0x2F800
	max_pfn = max_high - PHYS_PFN_OFFSET;
	// max_high : 0xA0000, PHYS_PFN_OFFSET : 0x20000
	// max_pfn : 0x80000
}

/*
 * Poison init memory with an undefined instruction (ARM) or a branch to an
 * undefined instruction (Thumb).
 */
static inline void poison_init_mem(void *s, size_t count)
{
	u32 *p = (u32 *)s;
	for (; count != 0; count -= 4)
		*p++ = 0xe7fddef0;
}

static inline void
free_memmap(unsigned long start_pfn, unsigned long end_pfn)
{
	struct page *start_pg, *end_pg;
	phys_addr_t pg, pgend;

	/*
	 * Convert start_pfn/end_pfn to a struct page pointer.
	 */
	start_pg = pfn_to_page(start_pfn - 1) + 1;
	end_pg = pfn_to_page(end_pfn - 1) + 1;

	/*
	 * Convert to physical addresses, and
	 * round start upwards and end downwards.
	 */
	pg = PAGE_ALIGN(__pa(start_pg));
	pgend = __pa(end_pg) & PAGE_MASK;

	/*
	 * If there are free pages between these,
	 * free the section of the memmap array.
	 */
	if (pg < pgend)
		free_bootmem(pg, pgend - pg);
}

/*
 * The mem_map array can get very big.  Free the unused area of the memory map.
 */
// mi : bank 정보가 들어가 있는 공간
static void __init free_unused_memmap(struct meminfo *mi)
{
	unsigned long bank_start, prev_bank_end = 0;
	unsigned int i;

	/*
	 * This relies on each bank being in address order.
	 * The banks are sorted previously in bootmem_init().
	 */
	for_each_bank(i, mi) {
		struct membank *bank = &mi->bank[i];
		// [0] bank : lowmem 정보가 연결됨
		// [1] bank : highmem 정보가 연결됨

		bank_start = bank_pfn_start(bank);
		// [0] bank_start : lowmem의 시작 주소 프레임 번호
		// 		    0x20000
		// [1] bank_start : highmem의 시작 주소 프레임 번호
		// 		    0x4F800

#ifdef CONFIG_SPARSEMEM
		/*
		 * Take care not to free memmap entries that don't exist
		 * due to SPARSEMEM sections which aren't present.
		 */
		bank_start = min(bank_start,
				 ALIGN(prev_bank_end, PAGES_PER_SECTION));
		// [0] bank_start : 0
		// [1] bank_start : 0x4F800
#else
		/*
		 * Align down here since the VM subsystem insists that the
		 * memmap entries are valid from the bank start aligned to
		 * MAX_ORDER_NR_PAGES.
		 */
		// 통과
		bank_start = round_down(bank_start, MAX_ORDER_NR_PAGES);
#endif
		/*
		 * If we had a previous bank, and there is a space
		 * between the current bank and the previous, free it.
		 */
		// [0] prev_bank_end : 0, bank_start : 0
		// [1] prev_bank_end : 0x4F800, bank_start : 0x4F800
		if (prev_bank_end && prev_bank_end < bank_start)
			free_memmap(prev_bank_end, bank_start);		// 통과됨
		// if문에 걸리는 경우는 이전 뱅크와 현재 뱅크 사이에 공간이 존재하는 경우임

		/*
		 * Align up here since the VM subsystem insists that the
		 * memmap entries are valid from the bank end aligned to
		 * MAX_ORDER_NR_PAGES.
		 */
		// [0] bank_pfn_end(bank) : 0x4F800, MAX_ORDER_NR_PAGES : 1K
		// [0] bank_pfn_end(bank) : 0xA0000, MAX_ORDER_NR_PAGES : 1K
		prev_bank_end = ALIGN(bank_pfn_end(bank), MAX_ORDER_NR_PAGES);
		// [0] prev_bank_end : 0x4F800
		// [1] prev_bank_end : 0xA0000
	}

#ifdef CONFIG_SPARSEMEM
	if (!IS_ALIGNED(prev_bank_end, PAGES_PER_SECTION))		// 통과
		free_memmap(prev_bank_end,
			    ALIGN(prev_bank_end, PAGES_PER_SECTION));
#endif
}

#ifdef CONFIG_HIGHMEM
static inline void free_area_high(unsigned long pfn, unsigned long end)
{
	for (; pfn < end; pfn++)
		free_highmem_page(pfn_to_page(pfn));
}
#endif

static void __init free_highpages(void)
{
#ifdef CONFIG_HIGHMEM
	unsigned long max_low = max_low_pfn + PHYS_PFN_OFFSET;
	struct memblock_region *mem, *res;

	/* set highmem page free */
	for_each_memblock(memory, mem) {
		unsigned long start = memblock_region_memory_base_pfn(mem);
		unsigned long end = memblock_region_memory_end_pfn(mem);

		/* Ignore complete lowmem entries */
		if (end <= max_low)
			continue;

		/* Truncate partial highmem entries */
		if (start < max_low)
			start = max_low;

		/* Find and exclude any reserved regions */
		for_each_memblock(reserved, res) {
			unsigned long res_start, res_end;

			res_start = memblock_region_reserved_base_pfn(res);
			res_end = memblock_region_reserved_end_pfn(res);

			if (res_end < start)
				continue;
			if (res_start < start)
				res_start = start;
			if (res_start > end)
				res_start = end;
			if (res_end > end)
				res_end = end;
			if (res_start != start)
				free_area_high(start, res_start);
			start = res_end;
			if (start == end)
				break;
		}

		/* And now free anything which remains */
		if (start < end)
			free_area_high(start, end);
	}
#endif
}

/*
 * mem_init() marks the free areas in the mem_map and tells us how much
 * memory is free.  This is done after various parts of the system have
 * claimed their memory after the kernel image.
 */
void __init mem_init(void)
{
#ifdef CONFIG_HAVE_TCM			// N
	/* These pointers are filled in on TCM detection */
	extern u32 dtcm_end;
	extern u32 itcm_end;
#endif

	// max_pfn : 0x80000, PHYS_PFN_OFFSET : 0x20000, mem_map : NULL
	// mem_map이 NULL인 이유는 NUMA 구조가 아니기 때문임
	max_mapnr   = pfn_to_page(max_pfn + PHYS_PFN_OFFSET) - mem_map;
	// 0xA0000을 담당하는 struct page 공간의 시작 주소

	/* this will put all unused low memory onto the freelists */
	// meminfo : 뱅크 정보가 들어가 있는 공간
	// 		region 1개에 lowmem, highmem 으로 뱅크가 두 개 존재
	free_unused_memmap(&meminfo);
	// bank 사이에 빈 공간이 존재하거나, 64K로 정렬이 되어 있지 않은 부분을 free 해 줌

	free_all_bootmem();

#ifdef CONFIG_SA1111
	/* now that our DMA memory is actually so designated, we can free it */
	free_reserved_area(__va(PHYS_OFFSET), swapper_pg_dir, -1, NULL);
#endif

	free_highpages();

	mem_init_print_info(NULL);

#define MLK(b, t) b, t, ((t) - (b)) >> 10
#define MLM(b, t) b, t, ((t) - (b)) >> 20
#define MLK_ROUNDUP(b, t) b, t, DIV_ROUND_UP(((t) - (b)), SZ_1K)

	printk(KERN_NOTICE "Virtual kernel memory layout:\n"
			"    vector  : 0x%08lx - 0x%08lx   (%4ld kB)\n"
#ifdef CONFIG_HAVE_TCM
			"    DTCM    : 0x%08lx - 0x%08lx   (%4ld kB)\n"
			"    ITCM    : 0x%08lx - 0x%08lx   (%4ld kB)\n"
#endif
			"    fixmap  : 0x%08lx - 0x%08lx   (%4ld kB)\n"
			"    vmalloc : 0x%08lx - 0x%08lx   (%4ld MB)\n"
			"    lowmem  : 0x%08lx - 0x%08lx   (%4ld MB)\n"
#ifdef CONFIG_HIGHMEM
			"    pkmap   : 0x%08lx - 0x%08lx   (%4ld MB)\n"
#endif
#ifdef CONFIG_MODULES
			"    modules : 0x%08lx - 0x%08lx   (%4ld MB)\n"
#endif
			"      .text : 0x%p" " - 0x%p" "   (%4d kB)\n"
			"      .init : 0x%p" " - 0x%p" "   (%4d kB)\n"
			"      .data : 0x%p" " - 0x%p" "   (%4d kB)\n"
			"       .bss : 0x%p" " - 0x%p" "   (%4d kB)\n",

			MLK(UL(CONFIG_VECTORS_BASE), UL(CONFIG_VECTORS_BASE) +
				(PAGE_SIZE)),
#ifdef CONFIG_HAVE_TCM
			MLK(DTCM_OFFSET, (unsigned long) dtcm_end),
			MLK(ITCM_OFFSET, (unsigned long) itcm_end),
#endif
			MLK(FIXADDR_START, FIXADDR_TOP),
			MLM(VMALLOC_START, VMALLOC_END),
			MLM(PAGE_OFFSET, (unsigned long)high_memory),
#ifdef CONFIG_HIGHMEM
			MLM(PKMAP_BASE, (PKMAP_BASE) + (LAST_PKMAP) *
				(PAGE_SIZE)),
#endif
#ifdef CONFIG_MODULES
			MLM(MODULES_VADDR, MODULES_END),
#endif

			MLK_ROUNDUP(_text, _etext),
			MLK_ROUNDUP(__init_begin, __init_end),
			MLK_ROUNDUP(_sdata, _edata),
			MLK_ROUNDUP(__bss_start, __bss_stop));

#undef MLK
#undef MLM
#undef MLK_ROUNDUP

	/*
	 * Check boundaries twice: Some fundamental inconsistencies can
	 * be detected at build time already.
	 */
#ifdef CONFIG_MMU
	BUILD_BUG_ON(TASK_SIZE				> MODULES_VADDR);
	BUG_ON(TASK_SIZE 				> MODULES_VADDR);
#endif

#ifdef CONFIG_HIGHMEM
	BUILD_BUG_ON(PKMAP_BASE + LAST_PKMAP * PAGE_SIZE > PAGE_OFFSET);
	BUG_ON(PKMAP_BASE + LAST_PKMAP * PAGE_SIZE	> PAGE_OFFSET);
#endif

	if (PAGE_SIZE >= 16384 && get_num_physpages() <= 128) {
		extern int sysctl_overcommit_memory;
		/*
		 * On a machine this small we won't get
		 * anywhere without overcommit, so turn
		 * it on by default.
		 */
		sysctl_overcommit_memory = OVERCOMMIT_ALWAYS;
	}
}

void free_initmem(void)
{
#ifdef CONFIG_HAVE_TCM
	extern char __tcm_start, __tcm_end;

	poison_init_mem(&__tcm_start, &__tcm_end - &__tcm_start);
	free_reserved_area(&__tcm_start, &__tcm_end, -1, "TCM link");
#endif

	poison_init_mem(__init_begin, __init_end - __init_begin);
	if (!machine_is_integrator() && !machine_is_cintegrator())
		free_initmem_default(-1);
}

#ifdef CONFIG_BLK_DEV_INITRD

static int keep_initrd;

void free_initrd_mem(unsigned long start, unsigned long end)
{
	if (!keep_initrd) {
		poison_init_mem((void *)start, PAGE_ALIGN(end) - start);
		free_reserved_area((void *)start, (void *)end, -1, "initrd");
	}
}

static int __init keepinitrd_setup(char *__unused)
{
	keep_initrd = 1;
	return 1;
}

__setup("keepinitrd", keepinitrd_setup);
#endif
