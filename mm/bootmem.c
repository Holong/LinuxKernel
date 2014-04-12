/*
 *  bootmem - A boot-time physical memory allocator and configurator
 *
 *  Copyright (C) 1999 Ingo Molnar
 *                1999 Kanoj Sarcar, SGI
 *                2008 Johannes Weiner
 *
 * Access to this subsystem has to be serialized externally (which is true
 * for the boot process anyway).
 */
#include <linux/init.h>
#include <linux/pfn.h>
#include <linux/slab.h>
#include <linux/bootmem.h>
#include <linux/export.h>
#include <linux/kmemleak.h>
#include <linux/range.h>
#include <linux/memblock.h>

#include <asm/bug.h>
#include <asm/io.h>
#include <asm/processor.h>

#include "internal.h"

#ifndef CONFIG_NEED_MULTIPLE_NODES
struct pglist_data __refdata contig_page_data = {
	.bdata = &bootmem_node_data[0]
};
EXPORT_SYMBOL(contig_page_data);
#endif

unsigned long max_low_pfn;
unsigned long min_low_pfn;
unsigned long max_pfn;
// MAX_NUMNODSE : 1
bootmem_data_t bootmem_node_data[MAX_NUMNODES] __initdata;

static struct list_head bdata_list __initdata = LIST_HEAD_INIT(bdata_list);

static int bootmem_debug;

static int __init bootmem_debug_setup(char *buf)
{
	bootmem_debug = 1;
	return 0;
}
early_param("bootmem_debug", bootmem_debug_setup);

#define bdebug(fmt, args...) ({				\
	if (unlikely(bootmem_debug))			\
		printk(KERN_INFO			\
			"bootmem::%s " fmt,		\
			__func__, ## args);		\
})

static unsigned long __init bootmap_bytes(unsigned long pages)
{
	unsigned long bytes = DIV_ROUND_UP(pages, 8);

	return ALIGN(bytes, sizeof(long));
}

/**
 * bootmem_bootmap_pages - calculate bitmap size in pages
 * @pages: number of pages the bitmap has to represent
 */
// pages : 0x2F800 (end - start)
unsigned long __init bootmem_bootmap_pages(unsigned long pages)
{
	unsigned long bytes = bootmap_bytes(pages);
	// bytes : small page 하나당 비트 한개씩 할당할 경우
	// 	   총 계산된 바이트들
	// 	   그러므로 pages는 small page 갯수임
	// bytes : 0x5F00
	// PAGE_ALIGN(bytes) : 0x6000
	return PAGE_ALIGN(bytes) >> PAGE_SHIFT;
}

/*
 * link bdata in order
 */
static void __init link_bootmem(bootmem_data_t *bdata)
{
	bootmem_data_t *ent;

	list_for_each_entry(ent, &bdata_list, list) {
		if (bdata->node_min_pfn < ent->node_min_pfn) {
			list_add_tail(&bdata->list, &ent->list);
			return;
		}
	}

	list_add_tail(&bdata->list, &bdata_list);
}

/*
 * Called once to set up the allocator itself.
 */

// bdata : &bootmem_node_data, mapstart : bitmap의 프레임 번호, start : 0x20000, end : 0x4F800
static unsigned long __init init_bootmem_core(bootmem_data_t *bdata,
	unsigned long mapstart, unsigned long start, unsigned long end)
{
	unsigned long mapsize;

	mminit_validate_memmodel_limits(&start, &end);
	// 문제 없음 (뭔 문제??)
	// 32bit 물리 주소 범위를 넘는 것인지 확인함
	bdata->node_bootmem_map = phys_to_virt(PFN_PHYS(mapstart));
	// bitmap의 가상 주소가 저장됨
	bdata->node_min_pfn = start;
	bdata->node_low_pfn = end;
	link_bootmem(bdata);
	// bdata_list 에 위에서 만든 구조체를 연결
	// 일단은 bdata_list에 한 개 밖에 없음

	/*
	 * Initially all pages are reserved - setup_arch() has to
	 * register free RAM areas explicitly.
	 */
	mapsize = bootmap_bytes(end - start);
	// mapsize : 0x5F00
	memset(bdata->node_bootmem_map, 0xff, mapsize);
	// bitmap을 전부 0xFF로 초기화
	// 초기화를 전부 reserved 영역으로 표시하는 걸로 수행하였음

	bdebug("nid=%td start=%lx map=%lx end=%lx mapsize=%lx\n",
		bdata - bootmem_node_data, start, mapstart, end, mapsize);

	return mapsize;
}

/**
 * init_bootmem_node - register a node as boot memory
 * @pgdat: node to register
 * @freepfn: pfn where the bitmap for this node is to be placed
 * @startpfn: first pfn on the node
 * @endpfn: first pfn after the node
 *
 * Returns the number of bytes needed to hold the bitmap for this node.
 */
//pgdat : &contig_page_data, freepfn : bitmap의 프레임 번호, startpfn : 0x20000, end_pfn : 0x4F800
unsigned long __init init_bootmem_node(pg_data_t *pgdat, unsigned long freepfn,
				unsigned long startpfn, unsigned long endpfn)
{
	return init_bootmem_core(pgdat->bdata, freepfn, startpfn, endpfn);
}

/**
 * init_bootmem - register boot memory
 * @start: pfn where the bitmap is to be placed
 * @pages: number of available physical pages
 *
 * Returns the number of bytes needed to hold the bitmap.
 */
unsigned long __init init_bootmem(unsigned long start, unsigned long pages)
{
	max_low_pfn = pages;
	min_low_pfn = start;
	return init_bootmem_core(NODE_DATA(0)->bdata, start, 0, pages);
}

/*
 * free_bootmem_late - free bootmem pages directly to page allocator
 * @addr: starting physical address of the range
 * @size: size of the range in bytes
 *
 * This is only useful when the bootmem allocator has already been torn
 * down, but we are still initializing the system.  Pages are given directly
 * to the page allocator, no bootmem metadata is updated because it is gone.
 */
void __init free_bootmem_late(unsigned long physaddr, unsigned long size)
{
	unsigned long cursor, end;

	kmemleak_free_part(__va(physaddr), size);

	cursor = PFN_UP(physaddr);
	end = PFN_DOWN(physaddr + size);

	for (; cursor < end; cursor++) {
		__free_pages_bootmem(pfn_to_page(cursor), 0);
		totalram_pages++;
	}
}

// bdata : bdata_list의 첫 번째 entry
static unsigned long __init free_all_bootmem_core(bootmem_data_t *bdata)
{
	struct page *page;
	unsigned long start, end, pages, count = 0;

	// bdata->node_bootmem_map : 있음
	if (!bdata->node_bootmem_map)
		return 0;

	start = bdata->node_min_pfn;
	// start : 0x20000
	end = bdata->node_low_pfn;
	// end : 0x4F800

	bdebug("nid=%td start=%lx end=%lx\n",
		bdata - bootmem_node_data, start, end);

	while (start < end) {
		unsigned long *map, idx, vec;
		unsigned shift;

		map = bdata->node_bootmem_map;
		// map : bitmap의 주소

		idx = start - bdata->node_min_pfn;
		// idx : 0x20000 - 0x20000 : 0

		shift = idx & (BITS_PER_LONG - 1);
		// shift : 0

		/*
		 * vec holds at most BITS_PER_LONG map bits,
		 * bit 0 corresponds to start.
		 */
		vec = ~map[idx / BITS_PER_LONG];
		// vec = ~map[0];
		// 비트 맵의 첫 번째 4바이트를 vec에 저장
		// 즉 32개의 페이지 프레임 정보가 vec에 저장됨

		// shift : 0
		if (shift) {
			vec >>= shift;
			// idx 번째 페이지 프레임의 할당 정보를 담당하는 비트가
			// vec의 0번째 비트가 되게 만듬

			if (end - start >= BITS_PER_LONG)
				vec |= ~map[idx / BITS_PER_LONG + 1] <<
					(BITS_PER_LONG - shift);
		}
		/*
		 * If we have a properly aligned and fully unreserved
		 * BITS_PER_LONG block of pages in front of us, free
		 * it in one go.
		 */

		// start : 0x20000
		// 0x20000 - 0x2001F까지 32개의 struct page가 free 상태라고 가정)
		if (IS_ALIGNED(start, BITS_PER_LONG) && vec == ~0UL) {
			int order = ilog2(BITS_PER_LONG);
			// order : 5

			// start : 0x20000, order : 5
			__free_pages_bootmem(pfn_to_page(start), order);
			// 0x20000에서 0x2001F까지의 페이지가 free 상태임을
			// 적절한 전역 변수와 플래그에 반영시켜 줌

			count += BITS_PER_LONG;
			// count : 32
			start += BITS_PER_LONG;
			// start : 0x20020
		} else {
			// start : 0x20000, vec : 0xFFFFFF0F (할당 정보 비트)
			// 즉, 중간에 reserve되어 있는 page가 끼어 있는 상황임
			unsigned long cur = start;

			start = ALIGN(start + 1, BITS_PER_LONG);
			// start : 0x20020

			while (vec && cur != start) {
				if (vec & 1) {
					page = pfn_to_page(cur);
					// page : 0x20000을 담당하는 struct page

					__free_pages_bootmem(page, 0);
					// 0x20000 페이지가 free 상태임을
					// 적절한 전역 변수와 플래그에 반영시켜 줌
					count++;
					// count 증가
				}
				vec >>= 1;
				++cur;
			}
			// vec 정보를 이용해서 free 상태인 page를 전역 변수들에게 반영시킴
		}
	}
	// bootmem 할당자에 의해 관리되왔던 정보들이 전부 buddy 정보로 변경되 저장됨
	// contig_page_data.node_zones[ZONE_NORMAL].free_area[order].free_list[MIGRATE_MOVABLE] 에
	// 각 공간의 선두 struct page를 연결
	// contig_page_data.node_zones[ZONE_NORMAL].free_area[order].nr_free
	// 에 해당 order 인 free 공간 갯수를 저장
	// CPU0의 percpu 변수인 vm_event_states.event[PGFREE]에 전체 struct page 개수 설정
	// contig_page_data.node_zones[ZONE_NORMAL].vm_stat[NR_FREE_PAGES]에도 전체 struct page 개수 설정
	// vm_stat[NR_FREE_PAGES]에 전체 struct page 개수 설정
	// 모든 struct page의 index 멤버에 migratetype(0x2)을 저장함
	// 각 공간의 선두 struct page의 _mapcount는 -128이 되고, private 멤버는 order 값이 됨

	page = virt_to_page(bdata->node_bootmem_map);
	// bootmem 할당자의 비트를 가지고 있던 공간을 담당하던 struct page 값 반환

	pages = bdata->node_low_pfn - bdata->node_min_pfn;
	// pages : 0x2F800

	pages = bootmem_bootmap_pages(pages);
	// pages : 0x6
	// 비트맵 공간이 몇 개의 페이지에 걸쳐서 존재 했는지 계산

	count += pages;
	// count에 비트맵 공간 개수를 추가
	// 이제부터 비트맵은 필요 없어짐

	while (pages--)
		__free_pages_bootmem(page++, 0);
		// 필요 없는 비트맵을 해제해서 buddy에 등록시킴

	bdebug("nid=%td released=%lx\n", bdata - bootmem_node_data, count);

	return count;
}

static int reset_managed_pages_done __initdata;

// pgdat : &contig_page_data
static inline void __init reset_node_managed_pages(pg_data_t *pgdat)
{
	struct zone *z;

	// reset_managed_pages_done : 0
	if (reset_managed_pages_done)
		return;		// 통과

	for (z = pgdat->node_zones; z < pgdat->node_zones + MAX_NR_ZONES; z++)
		z->managed_pages = 0;
	
	// contig_page_data에 존재하는 node_zones 구조체의 멤버인 managed_pages를 0으로 만듬
	// managed_pages 멤버는 그 zone에서 관리하는 struct page의 개수임
}

void __init reset_all_zones_managed_pages(void)
{
	struct pglist_data *pgdat;

	for_each_online_pgdat(pgdat)
		// pgdat : contig_page_data
		reset_node_managed_pages(pgdat);
		// node_zones의 managed_pages를 전부 초기화
	reset_managed_pages_done = 1;
}

/**
 * free_all_bootmem - release free pages to the buddy allocator
 *
 * Returns the number of pages actually released.
 */
unsigned long __init free_all_bootmem(void)
{
	unsigned long total_pages = 0;
	bootmem_data_t *bdata;

	reset_all_zones_managed_pages();
	// contig_page_data에 존재하는 node_zones의 managed_pages를 전부 초기화

	list_for_each_entry(bdata, &bdata_list, list)
	// for (bdata = list_entry((&bdata_list)->next, typeof(*bdata), list); &bdata->list != &bdata_list; bdata = list_entry(bdata->list.next, typeof(*bdata), list))
		total_pages += free_all_bootmem_core(bdata);
		// bootmem 할당자에서 관리하는 정보를 이용해
		// buddy로 전부 새로 등록하고 bootmem 비트맵을 전부 제거
		// contig_page_data.node_zones[ZONE_NORMAL].free_area[order]에 전부 등록됨

	totalram_pages += total_pages;

	return total_pages;
}

// sidx : 0, eidx : 0x2F800
static void __init __free(bootmem_data_t *bdata,
			unsigned long sidx, unsigned long eidx)
{
	unsigned long idx;

	bdebug("nid=%td start=%lx end=%lx\n", bdata - bootmem_node_data,
		sidx + bdata->node_min_pfn,
		eidx + bdata->node_min_pfn);

	if (bdata->hint_idx > sidx)
		bdata->hint_idx = sidx;

	// bitmap 내용을 변경
	// sidx : 0, eidx : 0x2F800
	for (idx = sidx; idx < eidx; idx++)
		if (!test_and_clear_bit(idx, bdata->node_bootmem_map))
			// 비트가 0이면 에러를 뽑음
			// 이미 초기화시 0xFF로 되어 있기 때문에 BUG는 절대 수행 안됨
			BUG();
}

static int __init __reserve(bootmem_data_t *bdata, unsigned long sidx,
			unsigned long eidx, int flags)
{
	unsigned long idx;
	int exclusive = flags & BOOTMEM_EXCLUSIVE;

	bdebug("nid=%td start=%lx end=%lx flags=%x\n",
		bdata - bootmem_node_data,
		sidx + bdata->node_min_pfn,
		eidx + bdata->node_min_pfn,
		flags);

	for (idx = sidx; idx < eidx; idx++)
		if (test_and_set_bit(idx, bdata->node_bootmem_map)) {
			// 리턴이 1이면 reserve인데 다시 reserve 하려고 시도한 것임
			if (exclusive) {
				__free(bdata, sidx, idx);
				return -EBUSY;
			}
			bdebug("silent double reserve of PFN %lx\n",
				idx + bdata->node_min_pfn);
		}
	return 0;
}

// start : 0x20000, end : 0x4F800, reserve : 0, flags : 0
static int __init mark_bootmem_node(bootmem_data_t *bdata,
				unsigned long start, unsigned long end,
				int reserve, int flags)
{
	unsigned long sidx, eidx;

	bdebug("nid=%td start=%lx end=%lx reserve=%d flags=%x\n",
		bdata - bootmem_node_data, start, end, reserve, flags);

	BUG_ON(start < bdata->node_min_pfn);
	BUG_ON(end > bdata->node_low_pfn);

	sidx = start - bdata->node_min_pfn;
	// sidx : 0
	eidx = end - bdata->node_min_pfn;
	// eidx : 0x2F800

	if (reserve)			// 넘어온 reserve가 1일 경우
		return __reserve(bdata, sidx, eidx, flags);
	else
		__free(bdata, sidx, eidx);
	return 0;
}

// start : 0x20000, end : 0x4F800, reserve : 0, flags : 0
static int __init mark_bootmem(unsigned long start, unsigned long end,
				int reserve, int flags)
{
	unsigned long pos;
	bootmem_data_t *bdata;

	pos = start;
	// pos : 0x20000 
	
	list_for_each_entry(bdata, &bdata_list, list) {
		int err;
		unsigned long max;

		// node_min_pfn : 0x20000, node_low_pfn : 0x4F800
		if (pos < bdata->node_min_pfn ||
		    pos >= bdata->node_low_pfn) {
			BUG_ON(pos != start);
			continue;
		}
		// 위 조건문을 통해 start가 등록되어 있는 bitmap이 저장된 bdata를 찾아냄

		max = min(bdata->node_low_pfn, end);
		// max : 0x4F800
		
		// pos : 0x20000, max : 0x4F800
		err = mark_bootmem_node(bdata, pos, max, reserve, flags);
		// reserve 값에 맞게 비트맵을 설정해 줌
		// 전부 FREE로 설정됨
		// 0이 반환
		if (reserve && err) {
			mark_bootmem(start, pos, 0, 0);
			return err;
		}

		if (max == end)
			return 0;
		pos = bdata->node_low_pfn;
	}
	// bitmap 영역이 여러 bdata에 나뉘어 있는 경우 루프가 여러번 돌아감
	BUG();
}

/**
 * free_bootmem_node - mark a page range as usable
 * @pgdat: node the range resides on
 * @physaddr: starting address of the range
 * @size: size of the range in bytes
 *
 * Partial pages will be considered reserved and left as they are.
 *
 * The range must reside completely on the specified node.
 */
void __init free_bootmem_node(pg_data_t *pgdat, unsigned long physaddr,
			      unsigned long size)
{
	unsigned long start, end;

	kmemleak_free_part(__va(physaddr), size);

	start = PFN_UP(physaddr);
	end = PFN_DOWN(physaddr + size);

	mark_bootmem_node(pgdat->bdata, start, end, 0, 0);
}

/**
 * free_bootmem - mark a page range as usable
 * @addr: starting physical address of the range
 * @size: size of the range in bytes
 *
 * Partial pages will be considered reserved and left as they are.
 *
 * The range must be contiguous but may span node boundaries.
 */
// physaddr : 0x20000000, size : 0x2F800000
void __init free_bootmem(unsigned long physaddr, unsigned long size)
{
	unsigned long start, end;

	// 0xC0000000, 0x2F800000
	kmemleak_free_part(__va(physaddr), size);	// 아무 것도 안함

	start = PFN_UP(physaddr);
	// start : 0x20000
	end = PFN_DOWN(physaddr + size);
	// end : 0x4F800

	// start : 0x20000, end : 0x4F800
	mark_bootmem(start, end, 0, 0);
}

/**
 * reserve_bootmem_node - mark a page range as reserved
 * @pgdat: node the range resides on
 * @physaddr: starting address of the range
 * @size: size of the range in bytes
 * @flags: reservation flags (see linux/bootmem.h)
 *
 * Partial pages will be reserved.
 *
 * The range must reside completely on the specified node.
 */
int __init reserve_bootmem_node(pg_data_t *pgdat, unsigned long physaddr,
				 unsigned long size, int flags)
{
	unsigned long start, end;

	start = PFN_DOWN(physaddr);
	end = PFN_UP(physaddr + size);

	return mark_bootmem_node(pgdat->bdata, start, end, 1, flags);
}

/**
 * reserve_bootmem - mark a page range as reserved
 * @addr: starting address of the range
 * @size: size of the range in bytes
 * @flags: reservation flags (see linux/bootmem.h)
 *
 * Partial pages will be reserved.
 *
 * The range must be contiguous but may span node boundaries.
 */
int __init reserve_bootmem(unsigned long addr, unsigned long size,
			    int flags)
{
	unsigned long start, end;

	start = PFN_DOWN(addr);
	end = PFN_UP(addr + size);

	return mark_bootmem(start, end, 1, flags);
}
// *bdata : &bootmem_node_data[0], idx : 첫번째 FREE 프레임 인덱스 번호, step : 1
static unsigned long __init align_idx(struct bootmem_data *bdata,
				      unsigned long idx, unsigned long step)
{
	unsigned long base = bdata->node_min_pfn;
	// base : 0x20000 (lowmem 시작 주소)
	
	/*
	 * Align the index with respect to the node start so that the
	 * combination of both satisfies the requested alignment.
	 */

	return ALIGN(base + idx, step) - base;
	// step이 1이므로 idx를 그냥 리턴
}

static unsigned long __init align_off(struct bootmem_data *bdata,
				      unsigned long off, unsigned long align)
{
	unsigned long base = PFN_PHYS(bdata->node_min_pfn);

	/* Same as align_idx for byte offsets */

	return ALIGN(base + off, align) - base;
}

// bdata : &bootmem_node_data[0], size : 0x1000, align : 64, goal : 0x5FFFFFFF, limit : 0
// align : SMP_DCACHE_SIZE, goal : __pa(0xFFFFFFFF)
// bdata : &bootmem_node_data[0], size : 4 * 16, align : 64, goal : 0x0, limit : 0
static void * __init alloc_bootmem_bdata(struct bootmem_data *bdata,
					unsigned long size, unsigned long align,
					unsigned long goal, unsigned long limit)
{
	unsigned long fallback = 0;
	unsigned long min, max, start, sidx, midx, step;

	bdebug("nid=%td size=%lx [%lu pages] align=%lx goal=%lx limit=%lx\n",
		bdata - bootmem_node_data, size, PAGE_ALIGN(size) >> PAGE_SHIFT,
		align, goal, limit);

	BUG_ON(!size);
	BUG_ON(align & (align - 1));
	BUG_ON(limit && goal + size > limit);

	if (!bdata->node_bootmem_map)		// bitmap 주소가 들어 있으므로 통과됨
		return NULL;
  
	min = bdata->node_min_pfn;		// lowmem 시작 주소
						// 0x20000
	max = bdata->node_low_pfn;		// lowmem 끝 주소
						// 0x4F800

	goal >>= PAGE_SHIFT;			// goal : 0x5FFFF
	limit >>= PAGE_SHIFT;			// limit : 0

	if (limit && max > limit)		// 둘 다 통과
		max = limit;
	if (max <= min)
		return NULL;

	step = max(align >> PAGE_SHIFT, 1UL);
	// step : 1

	if (goal && min < goal && goal < max)
		start = ALIGN(goal, step);
	else
		start = ALIGN(min, step);
	// goal이 min과 max 사이에 있으면 그 값을 start로 지정
	// 아니면 min을 start로 지정. 지금은 max 보다 goal이 큰 상태임

	sidx = start - bdata->node_min_pfn;
	midx = max - bdata->node_min_pfn;
	// sidx : 0, midx : 0x2F800

	if (bdata->hint_idx > sidx) {		// 통과
		/*
		 * Handle the valid case of sidx being zero and still
		 * catch the fallback below.
		 */
		fallback = sidx + 1;
		sidx = align_idx(bdata, bdata->hint_idx, step);
	}

	while (1) {
		int merge;
		void *region;
		unsigned long eidx, i, start_off, end_off;
find_block:
		// sidx : 0, midx : 0x2F800
		sidx = find_next_zero_bit(bdata->node_bootmem_map, midx, sidx);
		// _find_next_zero_bit_le(bdata->node_bootmem_map, midx, sidx)
		// FREE 페이지 번호
		sidx = align_idx(bdata, sidx, step);
		// step으로 sidx를 align
		// 그냥 sidx는 변화없이 나옴
		eidx = sidx + PFN_UP(size);
		// eidx = sidx + 1
		// sidx는 정확히 모름

		if (sidx >= midx || eidx > midx)
			break;
		// sidx나 eidx가 midx 보다 큰 경우는 문제가 생긴 것임.

		for (i = sidx; i < eidx; i++)
			if (test_bit(i, bdata->node_bootmem_map)) {
				sidx = align_idx(bdata, i, step);
				// i 값이 sidx로 대입됨
				if (sidx == i)
					sidx += step;
				goto find_block;
			}
		// size가 4KB 여러 개가 필요한 경우 연달아 0인 곳을 찾아내기 위한 루프임
		// First Fit 알고리즘

		if (bdata->last_end_off & (PAGE_SIZE - 1) &&
				PFN_DOWN(bdata->last_end_off) + 1 == sidx)
			start_off = align_off(bdata, bdata->last_end_off, align);
		else
			start_off = PFN_PHYS(sidx);	// start offset이 계산됨(물리)

		merge = PFN_DOWN(start_off) < sidx;	// merge : 0
		end_off = start_off + size;		// end offset이 계산됨

		bdata->last_end_off = end_off;		// last_end_off : 현재 end offset이 저장됨
							// 마지막으로 할당해 준 offset 값이 저장됨
		bdata->hint_idx = PFN_UP(end_off);

		/*
		 * Reserve the area now:
		 */
		if (__reserve(bdata, PFN_DOWN(start_off) + merge,
				PFN_UP(end_off), BOOTMEM_EXCLUSIVE))
			BUG();
		// 현재 0 비트로 되어 있는 것을 1 비트로 바꿈.
		// reserve 된 것을 표시함

		region = phys_to_virt(PFN_PHYS(bdata->node_min_pfn) +
				start_off);
		// 0x20000000 + start_off >> 실제 확보된 영역의 첫 번째 주소
		// region : 확보된 영역 시작의 가상 주소
		memset(region, 0, size);
		// 그 영역을 0으로 초기화

		/*
		 * The min_count is set to 0 so that bootmem allocated blocks
		 * are never reported as leaks.
		 */
		// size : 0x1000
		kmemleak_alloc(region, size, 0, 0);
		// config 상 null 함수임
		// 아무 것도 하지 않음
		return region;
	}

	if (fallback) {
		sidx = align_idx(bdata, fallback - 1, step);
		fallback = 0;
		goto find_block;
	}

	return NULL;
}

// size : 4 * 16, align : 64, goal : 0x5FFFFFFF, limit : 0
// size : 4 * 16, align : 64, goal : 0x0, limit : 0
static void * __init alloc_bootmem_core(unsigned long size,
					unsigned long align,
					unsigned long goal,
					unsigned long limit)
{
	bootmem_data_t *bdata;
	void *region;

	if (WARN_ON_ONCE(slab_is_available()))
		return kzalloc(size, GFP_NOWAIT);

	list_for_each_entry(bdata, &bdata_list, list) {
		if (goal && bdata->node_low_pfn <= PFN_DOWN(goal))
			continue;
		if (limit && bdata->node_min_pfn >= PFN_DOWN(limit))
			break;

		// size : 4 * 16, align : 64, goal : 0x0, limit : 0
		region = alloc_bootmem_bdata(bdata, size, align, goal, limit);
		// 4KB 빈 공간을 할당 받아 시작 가상 주소를 받아옴
		if (region)
			return region;
	}

	return NULL;
}

// size : 4 * 16, align : 64, goal : 0x5FFFFFFF, limit : 0
// size : 28, align : 64, goal : 0, limit : 0xFFFFFFFF
static void * __init ___alloc_bootmem_nopanic(unsigned long size,
					      unsigned long align,
					      unsigned long goal,
					      unsigned long limit)
{
	void *ptr;

restart:
	ptr = alloc_bootmem_core(size, align, goal, limit);
	if (ptr)
		return ptr;
	if (goal) {
		goal = 0;
		goto restart;
	}

	return NULL;
}

/**
 * __alloc_bootmem_nopanic - allocate boot memory without panicking
 * @size: size of the request in bytes
 * @align: alignment of the region
 * @goal: preferred starting address of the region
 *
 * The goal is dropped if it can not be satisfied and the allocation will
 * fall back to memory below @goal.
 *
 * Allocation may happen on any node in the system.
 *
 * Returns NULL on failure.
 */
void * __init __alloc_bootmem_nopanic(unsigned long size, unsigned long align,
					unsigned long goal)
{
	unsigned long limit = 0;

	return ___alloc_bootmem_nopanic(size, align, goal, limit);
}

// size : 4 * 16, align : 64, goal : 0x5FFFFFFF, limit : 0
// size : 28, align : 64, goal : 0, limit : 0xFFFFFFFF
static void * __init ___alloc_bootmem(unsigned long size, unsigned long align,
					unsigned long goal, unsigned long limit)
{
	void *mem = ___alloc_bootmem_nopanic(size, align, goal, limit);

	if (mem)
		return mem;
	/*
	 * Whoops, we cannot satisfy the allocation request.
	 */
	printk(KERN_ALERT "bootmem alloc of %lu bytes failed!\n", size);
	panic("Out of memory");
	return NULL;
}

/**
 * __alloc_bootmem - allocate boot memory
 * @size: size of the request in bytes
 * @align: alignment of the region
 * @goal: preferred starting address of the region
 *
 * The goal is dropped if it can not be satisfied and the allocation will
 * fall back to memory below @goal.
 *
 * Allocation may happen on any node in the system.
 *
 * The function panics if the request can not be satisfied.
 */
// size : 4 * 16, align : 64, goal : 0x5FFFFFFF
void * __init __alloc_bootmem(unsigned long size, unsigned long align,
			      unsigned long goal)
{
	unsigned long limit = 0;

	return ___alloc_bootmem(size, align, goal, limit);
}

// pgdat : &contig_page_data, size : 0x1000, align : 64, goal : 0x5FFFFFFF, limit : 0
// pgdat : &contig_page_data, size : 0x800, align : 64, goal : 0x5FFFFFFF, limit : 0
void * __init ___alloc_bootmem_node_nopanic(pg_data_t *pgdat,
				unsigned long size, unsigned long align,
				unsigned long goal, unsigned long limit)
{
	void *ptr;

	if (WARN_ON_ONCE(slab_is_available()))		// slab 초기화가 안되어 있으므로 통과
		return kzalloc(size, GFP_NOWAIT);
again:

	/* do not panic in alloc_bootmem_bdata() */
	if (limit && goal + size > limit)
		limit = 0;

	// pgdat : &contig_page_data, size : 0x1000, align : 64, goal : 0x5FFFFFFF, limit : 0
	ptr = alloc_bootmem_bdata(pgdat->bdata, size, align, goal, limit);
	// ptr : size 크기 만큼 영역을 first fit으로 찾아낸 뒤, 그에 대한 bitmap을 설정해 준 후
	// 	 그 영역의 시작 가상 주소를 반환함
	
	if (ptr)			// 이 쪽으로 들어감
		return ptr;		// 반환

	ptr = alloc_bootmem_core(size, align, goal, limit);
	if (ptr)
		return ptr;

	if (goal) {
		goal = 0;
		goto again;
	}

	return NULL;
}

void * __init __alloc_bootmem_node_nopanic(pg_data_t *pgdat, unsigned long size,
				   unsigned long align, unsigned long goal)
{
	if (WARN_ON_ONCE(slab_is_available()))
		return kzalloc_node(size, GFP_NOWAIT, pgdat->node_id);

	return ___alloc_bootmem_node_nopanic(pgdat, size, align, goal, 0);
}

// pgdat : &contig_page_data, size : 0x1000, align : 64, goal : 0x5FFFFFFF, limit : 0
void * __init ___alloc_bootmem_node(pg_data_t *pgdat, unsigned long size,
				    unsigned long align, unsigned long goal,
				    unsigned long limit)
{
	void *ptr;

	ptr = ___alloc_bootmem_node_nopanic(pgdat, size, align, goal, 0);
	if (ptr)
		return ptr;

	printk(KERN_ALERT "bootmem alloc of %lu bytes failed!\n", size);
	panic("Out of memory");
	return NULL;
}

/**
 * __alloc_bootmem_node - allocate boot memory from a specific node
 * @pgdat: node to allocate from
 * @size: size of the request in bytes
 * @align: alignment of the region
 * @goal: preferred starting address of the region
 *
 * The goal is dropped if it can not be satisfied and the allocation will
 * fall back to memory below @goal.
 *
 * Allocation may fall back to any node in the system if the specified node
 * can not hold the requested memory.
 *
 * The function panics if the request can not be satisfied.
 */
// pgdat : &contig_page_data, size : 0x1000, align : 64, goal : 0x5FFFFFFF
void * __init __alloc_bootmem_node(pg_data_t *pgdat, unsigned long size,
				   unsigned long align, unsigned long goal)
{
	if (WARN_ON_ONCE(slab_is_available()))		// 통과
		return kzalloc_node(size, GFP_NOWAIT, pgdat->node_id);

	return  ___alloc_bootmem_node(pgdat, size, align, goal, 0);
}

// pgdat : &contig_page_data, size : 0x2C0000, align : 0x1000, goal : 0x5FFFFFFF	
void * __init __alloc_bootmem_node_high(pg_data_t *pgdat, unsigned long size,
				   unsigned long align, unsigned long goal)
{
#ifdef MAX_DMA32_PFN
	unsigned long end_pfn;

	if (WARN_ON_ONCE(slab_is_available()))
		return kzalloc_node(size, GFP_NOWAIT, pgdat->node_id);

	/* update goal according ...MAX_DMA32_PFN */
	end_pfn = pgdat->node_start_pfn + pgdat->node_spanned_pages;

	if (end_pfn > MAX_DMA32_PFN + (128 >> (20 - PAGE_SHIFT)) &&
	    (goal >> PAGE_SHIFT) < MAX_DMA32_PFN) {
		void *ptr;
		unsigned long new_goal;

		new_goal = MAX_DMA32_PFN << PAGE_SHIFT;
		ptr = alloc_bootmem_bdata(pgdat->bdata, size, align,
						 new_goal, 0);
		if (ptr)
			return ptr;
	}
#endif

	// pgdat : &contig_page_data, size : 0x2C0000, align : 0x1000, goal : 0x5FFFFFFF	
	return __alloc_bootmem_node(pgdat, size, align, goal);
	// 2816K 만큼 공간을 할당 받아 리턴함

}

#ifndef ARCH_LOW_ADDRESS_LIMIT
#define ARCH_LOW_ADDRESS_LIMIT	0xffffffffUL
#endif

/**
 * __alloc_bootmem_low - allocate low boot memory
 * @size: size of the request in bytes
 * @align: alignment of the region
 * @goal: preferred starting address of the region
 *
 * The goal is dropped if it can not be satisfied and the allocation will
 * fall back to memory below @goal.
 *
 * Allocation may happen on any node in the system.
 *
 * The function panics if the request can not be satisfied.
 */
// size : 28, align : 64, goal : 0
void * __init __alloc_bootmem_low(unsigned long size, unsigned long align,
				  unsigned long goal)
{
	// size : 28, align : 64, goal : 0, ARCH_LOW_ADDRESS_LIMIT : 0xFFFFFFFF
	return ___alloc_bootmem(size, align, goal, ARCH_LOW_ADDRESS_LIMIT);
}

void * __init __alloc_bootmem_low_nopanic(unsigned long size,
					  unsigned long align,
					  unsigned long goal)
{
	return ___alloc_bootmem_nopanic(size, align, goal,
					ARCH_LOW_ADDRESS_LIMIT);
}

/**
 * __alloc_bootmem_low_node - allocate low boot memory from a specific node
 * @pgdat: node to allocate from
 * @size: size of the request in bytes
 * @align: alignment of the region
 * @goal: preferred starting address of the region
 *
 * The goal is dropped if it can not be satisfied and the allocation will
 * fall back to memory below @goal.
 *
 * Allocation may fall back to any node in the system if the specified node
 * can not hold the requested memory.
 *
 * The function panics if the request can not be satisfied.
 */
void * __init __alloc_bootmem_low_node(pg_data_t *pgdat, unsigned long size,
				       unsigned long align, unsigned long goal)
{
	if (WARN_ON_ONCE(slab_is_available()))
		return kzalloc_node(size, GFP_NOWAIT, pgdat->node_id);

	return ___alloc_bootmem_node(pgdat, size, align,
				     goal, ARCH_LOW_ADDRESS_LIMIT);
}
