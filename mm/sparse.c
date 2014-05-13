/*
 * sparse memory mappings.
 */
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/mmzone.h>
#include <linux/bootmem.h>
#include <linux/highmem.h>
#include <linux/export.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include "internal.h"
#include <asm/dma.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>

/*
 * Permanent SPARSEMEM data:
 *
 * 1) mem_section	- memory sections, mem_map's for valid memory
 */
#ifdef CONFIG_SPARSEMEM_EXTREME
// NR_SECTION_ROOTS : 1
struct mem_section *mem_section[NR_SECTION_ROOTS]
	____cacheline_internodealigned_in_smp;
	//__attribute__((__aligned__(1 << (INTERNODE_CACHE_SHIFT))))
	// 구조체를 정렬
#else
struct mem_section mem_section[NR_SECTION_ROOTS][SECTIONS_PER_ROOT]
	____cacheline_internodealigned_in_smp;
#endif
EXPORT_SYMBOL(mem_section);

#ifdef NODE_NOT_IN_PAGE_FLAGS
/*
 * If we did not store the node number in the page then we have to
 * do a lookup in the section_to_node_table in order to find which
 * node the page belongs to.
 */
#if MAX_NUMNODES <= 256
static u8 section_to_node_table[NR_MEM_SECTIONS] __cacheline_aligned;
#else
static u16 section_to_node_table[NR_MEM_SECTIONS] __cacheline_aligned;
#endif

int page_to_nid(const struct page *page)
{
	return section_to_node_table[page_to_section(page)];
}
EXPORT_SYMBOL(page_to_nid);

static void set_section_nid(unsigned long section_nr, int nid)
{
	section_to_node_table[section_nr] = nid;
}
#else /* !NODE_NOT_IN_PAGE_FLAGS */
static inline void set_section_nid(unsigned long section_nr, int nid)
{
}
#endif

#ifdef CONFIG_SPARSEMEM_EXTREME
// nid : 0
static struct mem_section noinline __init_refok *sparse_index_alloc(int nid)
{
	struct mem_section *section = NULL;
	unsigned long array_size = SECTIONS_PER_ROOT *
				   sizeof(struct mem_section);
	// SECTIONS_PER_ROOT : 0x200
	// sizeof(struct mem_section) : 8
	// array_size : 0x1000 (4KB : PAGE_SIZE)

	if (slab_is_available()) {			// 현재는 slab_state가 DOWN 임
							// 한 번도 조작한 적이 없음, 그러므로 통과
		if (node_state(nid, N_HIGH_MEMORY))
			section = kzalloc_node(array_size, GFP_KERNEL, nid);
		else
			section = kzalloc(array_size, GFP_KERNEL);
	} else {
		section = alloc_bootmem_node(NODE_DATA(nid), array_size);
		// __alloc_bootmem_node(pgdat, x, SMP_CACHE_BYTES, BOOTMEM_LOW_LIMIT)
		// pgdat : &contig_page_data, array_size : 0x1000, SMP_CACHE_BYTES : 64, BOOTMEM_LOW_LIMIT : 0x5FFFFFFF
		// lowmem에서 FREE 영역 중에 array_size 만큼 영역을 찾아 낸 뒤 그 가상 주소를 반환함.
		// First fit으로 찾아내며 그 영역에 대한 비트맵 값을 bdata_list에 반영하는 것까지 처리
	}

	return section;
}

// section_nr : 0x2, nid : 0
static int __meminit sparse_index_init(unsigned long section_nr, int nid)
{
	unsigned long root = SECTION_NR_TO_ROOT(section_nr);
	// section_nr / 0x200
	// root : 0
	struct mem_section *section;

	if (mem_section[root])
		return -EEXIST;
	// mem_section은 전역인데 이번에 처음 건드리므로 0으로 초기화 되어 있음
	
	section = sparse_index_alloc(nid);
	// lowmem에서 FREE 영역 중에 4KB 만큼 찾아낸 뒤 그 가상 주소를 반환
	if (!section)
		return -ENOMEM;

	mem_section[root] = section;
	// mem_section[0]에 확보한 영역 주소 값을 저장함

	return 0;
}
#else /* !SPARSEMEM_EXTREME */
static inline int sparse_index_init(unsigned long section_nr, int nid)
{
	return 0;
}
#endif

/*
 * Although written for the SPARSEMEM_EXTREME case, this happens
 * to also work for the flat array case because
 * NR_SECTION_ROOTS==NR_MEM_SECTIONS.
 */
int __section_nr(struct mem_section* ms)
{
	unsigned long root_nr;
	struct mem_section* root;

	for (root_nr = 0; root_nr < NR_SECTION_ROOTS; root_nr++) {
		root = __nr_to_section(root_nr * SECTIONS_PER_ROOT);
		if (!root)
			continue;

		if ((ms >= root) && (ms < (root + SECTIONS_PER_ROOT)))
		     break;
	}

	VM_BUG_ON(root_nr == NR_SECTION_ROOTS);

	return (root_nr * SECTIONS_PER_ROOT) + (ms - root);
}

/*
 * During early boot, before section_mem_map is used for an actual
 * mem_map, we use section_mem_map to store the section's NUMA
 * node.  This keeps us from having to use another data structure.  The
 * node information is cleared just before we store the real mem_map.
 */
static inline unsigned long sparse_encode_early_nid(int nid)
{
	return (nid << SECTION_NID_SHIFT);
}

static inline int sparse_early_nid(struct mem_section *section)
{
	return (section->section_mem_map >> SECTION_NID_SHIFT);
}

/* Validate the physical addressing limitations of the model */
// startpfn : 0x20000, endpfn : 0x4F800
void __meminit mminit_validate_memmodel_limits(unsigned long *start_pfn,
						unsigned long *end_pfn)
{
	unsigned long max_sparsemem_pfn = 1UL << (MAX_PHYSMEM_BITS-PAGE_SHIFT);
	// max_sparsemem_pfn : 0x100000
	//
	/*
	 * Sanity checks - do not allow an architecture to pass
	 * in larger pfns than the maximum scope of sparsemem:
	 */
	// 둘 다 그냥 통과됨
	if (*start_pfn > max_sparsemem_pfn) {
		mminit_dprintk(MMINIT_WARNING, "pfnvalidation",
			"Start of range %lu -> %lu exceeds SPARSEMEM max %lu\n",
			*start_pfn, *end_pfn, max_sparsemem_pfn);
		WARN_ON_ONCE(1);
		*start_pfn = max_sparsemem_pfn;
		*end_pfn = max_sparsemem_pfn;
	} else if (*end_pfn > max_sparsemem_pfn) {
		mminit_dprintk(MMINIT_WARNING, "pfnvalidation",
			"End of range %lu -> %lu exceeds SPARSEMEM max %lu\n",
			*start_pfn, *end_pfn, max_sparsemem_pfn);
		WARN_ON_ONCE(1);
		*end_pfn = max_sparsemem_pfn;
	}
}

/* Record a memory area against a node. */
// nid : 0, start : 0x20000, end : 0xA0000
void __init memory_present(int nid, unsigned long start, unsigned long end)
{
	// section : 256MB
	// 기존의 section과는 다른 것임
	unsigned long pfn;

	start &= PAGE_SECTION_MASK;
	// PAGE_SECTION_MASK : 0xFFFF0000
	// start : 0x20000
	// 256MB로 정렬
	mminit_validate_memmodel_limits(&start, &end);
	// 32비트 주소 내에 들어가는 지 확인

	// start : 0x20000, end : 0xA0000, PAGES_PER_SECTION : 0x10000
	for (pfn = start; pfn < end; pfn += PAGES_PER_SECTION) {
		unsigned long section = pfn_to_section_nr(pfn);		
		// 하위 16비트를 날림
		// 256MB 정렬
		// section : 0x2
		struct mem_section *ms;

		sparse_index_init(section, nid);
		// section : 0x2, nid : 0	으로 호출
		// mem_section[0]에 확보한 4KB 영역 주소 값을 저장함
		set_section_nid(section, nid);
		// section : 0x2, nid : 0
		// 아무 것도 하지 않음

		// section : 0x2
		ms = __nr_to_section(section);
		// &mem_section[0][2] 가 반환됨
		// 위에서 확보한 4KB 중 struct mem_section을 200개 넣을 수 있는데
		// 그 중에 2번째 주소 값을 가져옴
		if (!ms->section_mem_map)
			ms->section_mem_map = sparse_encode_early_nid(nid) |
							SECTION_MARKED_PRESENT;
			// 1 값이 저장됨
	}
	// &mem_section[0][2] ~ &mem_section[0][10] 까지 section_mem_map 에 1을 저장함
}

/*
 * Only used by the i386 NUMA architecures, but relatively
 * generic code.
 */
unsigned long __init node_memmap_size_bytes(int nid, unsigned long start_pfn,
						     unsigned long end_pfn)
{
	unsigned long pfn;
	unsigned long nr_pages = 0;

	mminit_validate_memmodel_limits(&start_pfn, &end_pfn);
	for (pfn = start_pfn; pfn < end_pfn; pfn += PAGES_PER_SECTION) {
		if (nid != early_pfn_to_nid(pfn))
			continue;

		if (pfn_present(pfn))
			nr_pages += PAGES_PER_SECTION;
	}

	return nr_pages * sizeof(struct page);
}

/*
 * Subtle, we encode the real pfn into the mem_map such that
 * the identity pfn - section_mem_map will return the actual
 * physical page frame number.
 */
// mem_map : 2816K 주소, pnum : 2 
static unsigned long sparse_encode_mem_map(struct page *mem_map, unsigned long pnum)
{

	// section_nr_to_pfn(2) : 0x20000
	return (unsigned long)(mem_map - (section_nr_to_pfn(pnum)));
	// 주소 값을 인코딩 한 뒤 반환함
}

/*
 * Decode mem_map from the coded memmap
 */
struct page *sparse_decode_mem_map(unsigned long coded_mem_map, unsigned long pnum)
{
	/* mask off the extra low bits of information */
	coded_mem_map &= SECTION_MAP_MASK;
	return ((struct page *)coded_mem_map) + section_nr_to_pfn(pnum);
}

// ms : &mem_section[0][2], pnum : 2, mem_map : 2816K 주소, pageblock_bitmap : usemap_map[2]
static int __meminit sparse_init_one_section(struct mem_section *ms,
		unsigned long pnum, struct page *mem_map,
		unsigned long *pageblock_bitmap)
{
	if (!present_section(ms)) // 통과
		return -EINVAL;

	ms->section_mem_map &= ~SECTION_MAP_MASK;
	// ms->section_mem_map : 0x1
	ms->section_mem_map |= sparse_encode_mem_map(mem_map, pnum) |
							SECTION_HAS_MEM_MAP;
	// ms->section_mem_map 에 들어간 정보
	// 1bit : 할당 됬음
	// 2bit : struct page용 공간이 할당됬음.
	//
	// 3~4bit : nid값
	// 나머지 : struct page용 공간의 시작 주소를 encoding해서 저장
	
	ms->pageblock_flags = pageblock_bitmap;
	// ms->pageblock_flags : usemap_map[2]
	
	return 1;
}

unsigned long usemap_size(void)
{
	unsigned long size_bytes;
	size_bytes = roundup(SECTION_BLOCKFLAGS_BITS, 8) / 8;
	size_bytes = roundup(size_bytes, sizeof(unsigned long));
	return size_bytes;
}

#ifdef CONFIG_MEMORY_HOTPLUG
static unsigned long *__kmalloc_section_usemap(void)
{
	return kmalloc(usemap_size(), GFP_KERNEL);
}
#endif /* CONFIG_MEMORY_HOTPLUG */

#ifdef CONFIG_MEMORY_HOTREMOVE
static unsigned long * __init
sparse_early_usemaps_alloc_pgdat_section(struct pglist_data *pgdat,
					 unsigned long size)
{
	unsigned long goal, limit;
	unsigned long *p;
	int nid;
	/*
	 * A page may contain usemaps for other sections preventing the
	 * page being freed and making a section unremovable while
	 * other sections referencing the usemap retmain active. Similarly,
	 * a pgdat can prevent a section being removed. If section A
	 * contains a pgdat and section B contains the usemap, both
	 * sections become inter-dependent. This allocates usemaps
	 * from the same section as the pgdat where possible to avoid
	 * this problem.
	 */
	goal = __pa(pgdat) & (PAGE_SECTION_MASK << PAGE_SHIFT);
	limit = goal + (1UL << PA_SECTION_SHIFT);
	nid = early_pfn_to_nid(goal >> PAGE_SHIFT);
again:
	p = ___alloc_bootmem_node_nopanic(NODE_DATA(nid), size,
					  SMP_CACHE_BYTES, goal, limit);
	if (!p && limit) {
		limit = 0;
		goto again;
	}
	return p;
}

static void __init check_usemap_section_nr(int nid, unsigned long *usemap)
{
	unsigned long usemap_snr, pgdat_snr;
	static unsigned long old_usemap_snr = NR_MEM_SECTIONS;
	static unsigned long old_pgdat_snr = NR_MEM_SECTIONS;
	struct pglist_data *pgdat = NODE_DATA(nid);
	int usemap_nid;

	usemap_snr = pfn_to_section_nr(__pa(usemap) >> PAGE_SHIFT);
	pgdat_snr = pfn_to_section_nr(__pa(pgdat) >> PAGE_SHIFT);
	if (usemap_snr == pgdat_snr)
		return;

	if (old_usemap_snr == usemap_snr && old_pgdat_snr == pgdat_snr)
		/* skip redundant message */
		return;

	old_usemap_snr = usemap_snr;
	old_pgdat_snr = pgdat_snr;

	usemap_nid = sparse_early_nid(__nr_to_section(usemap_snr));
	if (usemap_nid != nid) {
		printk(KERN_INFO
		       "node %d must be removed before remove section %ld\n",
		       nid, usemap_snr);
		return;
	}
	/*
	 * There is a circular dependency.
	 * Some platforms allow un-removable section because they will just
	 * gather other removable sections for dynamic partitioning.
	 * Just notify un-removable section's number here.
	 */
	printk(KERN_INFO "Section %ld and %ld (node %d)", usemap_snr,
	       pgdat_snr, nid);
	printk(KERN_CONT
	       " have a circular dependency on usemap and pgdat allocations\n");
}
#else
// pgdat : &contig_page_data, size : 0x800
static unsigned long * __init
sparse_early_usemaps_alloc_pgdat_section(struct pglist_data *pgdat,
					 unsigned long size)
{
	return alloc_bootmem_node_nopanic(pgdat, size);
	// __alloc_bootmem_node_nopanic(pgdat, size, 64, 0x5FFFFFFF)
}

static void __init check_usemap_section_nr(int nid, unsigned long *usemap)
{
}
#endif /* CONFIG_MEMORY_HOTREMOVE */

// data : 4KB 할당 받은 주소, pnum_begin : 2, pnum_end : 16, usemap_count : 8, nodeid : 0
static void __init sparse_early_usemaps_alloc_node(void *data,
				 unsigned long pnum_begin,
				 unsigned long pnum_end,
				 unsigned long usemap_count, int nodeid)
{
	void *usemap;
	unsigned long pnum;
	unsigned long **usemap_map = (unsigned long **)data;
	// usemap_map : 4KB 할당 받은 주소
	int size = usemap_size();
	// size : 0x40

	// NODE_DATA(nodeid) : &contig_page_data, usemap_count : 0x20, size : 0x40
	usemap = sparse_early_usemaps_alloc_pgdat_section(NODE_DATA(nodeid),
							  size * usemap_count);
	if (!usemap) {
		printk(KERN_WARNING "%s: allocation failed\n", __func__);
		return;
	}

	// pnum_begin : 2, pnum_end : 0x10
	for (pnum = pnum_begin; pnum < pnum_end; pnum++) {
		if (!present_section_nr(pnum)) // pnum : 0 ~ 1, 11 ~ 16까지 걸림
			continue;

		// pnum : 2 ~ 10 까지만 수행됨
		usemap_map[pnum] = usemap;
		usemap += size;
		check_usemap_section_nr(nodeid, usemap_map[pnum]);
		// null 함수 
	}
	// usemap_map[2] ~ usemap_map[10] 에 이전에 할당 받았던 4KB 주소 + offset 값이 저장됨
}

#ifndef CONFIG_SPARSEMEM_VMEMMAP

// pnum : 2, nid : 0
struct page __init *sparse_mem_map_populate(unsigned long pnum, int nid)
{
	struct page *map;
	unsigned long size;

	// nid : 0, sizeof(struct page) : 44, PAGES_PER_SECTION: 0x10000
	// nid : 0, sizeof(struct page) * PAGES_PER_SECTION : 0x2C0000
	map = alloc_remap(nid, sizeof(struct page) * PAGES_PER_SECTION);
	// null 함수
	
	if (map)
		return map;
	
	// size : 0x2C0000
	size = PAGE_ALIGN(sizeof(struct page) * PAGES_PER_SECTION);

	// NODE_DATA(nid) : &contig_page_data, size : 0x2C0000, PAGE_SIZE : 0x1000, __pa : 0x5FFFFFFF	
	map = __alloc_bootmem_node_high(NODE_DATA(nid), size,
					 PAGE_SIZE, __pa(MAX_DMA_ADDRESS));
	// 2816K 만큼 공간을 할당 받아 리턴함
	return map;
}
void __init sparse_mem_maps_populate_node(struct page **map_map,
					  unsigned long pnum_begin,
					  unsigned long pnum_end,
					  unsigned long map_count, int nodeid)
{
	void *map;
	unsigned long pnum;
	unsigned long size = sizeof(struct page) * PAGES_PER_SECTION;

	map = alloc_remap(nodeid, size * map_count);
	if (map) {
		for (pnum = pnum_begin; pnum < pnum_end; pnum++) {
			if (!present_section_nr(pnum))
				continue;
			map_map[pnum] = map;
			map += size;
		}
		return;
	}

	size = PAGE_ALIGN(size);
	map = __alloc_bootmem_node_high(NODE_DATA(nodeid), size * map_count,
					 PAGE_SIZE, __pa(MAX_DMA_ADDRESS));
	if (map) {
		for (pnum = pnum_begin; pnum < pnum_end; pnum++) {
			if (!present_section_nr(pnum))
				continue;
			map_map[pnum] = map;
			map += size;
		}
		return;
	}

	/* fallback */
	for (pnum = pnum_begin; pnum < pnum_end; pnum++) {
		struct mem_section *ms;

		if (!present_section_nr(pnum))
			continue;
		map_map[pnum] = sparse_mem_map_populate(pnum, nodeid);
		if (map_map[pnum])
			continue;
		ms = __nr_to_section(pnum);
		printk(KERN_ERR "%s: sparsemem memory map backing failed "
			"some memory will not be available.\n", __func__);
		ms->section_mem_map = 0;
	}
}
#endif /* !CONFIG_SPARSEMEM_VMEMMAP */

#ifdef CONFIG_SPARSEMEM_ALLOC_MEM_MAP_TOGETHER
static void __init sparse_early_mem_maps_alloc_node(void *data,
				 unsigned long pnum_begin,
				 unsigned long pnum_end,
				 unsigned long map_count, int nodeid)
{
	struct page **map_map = (struct page **)data;
	sparse_mem_maps_populate_node(map_map, pnum_begin, pnum_end,
					 map_count, nodeid);
}
#else

// pnum : 2
static struct page __init *sparse_early_mem_map_alloc(unsigned long pnum)
{
	struct page *map;
	struct mem_section *ms = __nr_to_section(pnum);
	// ms : &mem_section[0][2]
	int nid = sparse_early_nid(ms);
	// nid : 0

	// pnum : 2, nid : 0
	map = sparse_mem_map_populate(pnum, nid);
	// 2816K 만큼 공간을 할당 받아 리턴함
	if (map)
		return map;

	printk(KERN_ERR "%s: sparsemem memory map backing failed "
			"some memory will not be available.\n", __func__);
	ms->section_mem_map = 0;
	return NULL;
}
#endif

void __attribute__((weak)) __meminit vmemmap_populate_print_last(void)
{
}

/**
 *  alloc_usemap_and_memmap - memory alloction for pageblock flags and vmemmap
 *  @map: usemap_map for pageblock flags or mmap_map for vmemmap
 */
static void __init alloc_usemap_and_memmap(void (*alloc_func)
					(void *, unsigned long, unsigned long,
					unsigned long, int), void *data)
{
	unsigned long pnum;
	unsigned long map_count;
	int nodeid_begin = 0;
	unsigned long pnum_begin = 0;

	for (pnum = 0; pnum < NR_MEM_SECTIONS; pnum++) {
		// NR_MEM_SECTIONS : 16
		struct mem_section *ms;

		if (!present_section_nr(pnum))
			continue;	// nr : 0, 1일때 걸림
		ms = __nr_to_section(pnum);
		// ms : &mem_section[0][pnum] 
		nodeid_begin = sparse_early_nid(ms);
		// nodeid_begin : 0
		// 이전에 저장해 둔 nid 값을 다시 뽑아냄
		pnum_begin = pnum;
		// pnum_begin : 2 일때 탈출
		break;
	}
	map_count = 1;

	// nodeid_begin : 0, pnum_begin : 2, NR_MEM_SECTIONS : 16
	for (pnum = pnum_begin + 1; pnum < NR_MEM_SECTIONS; pnum++) {
		struct mem_section *ms;
		int nodeid;

		if (!present_section_nr(pnum))
			continue;
		ms = __nr_to_section(pnum);
		// ms : &mem_section[0][3]

		nodeid = sparse_early_nid(ms);
		// nodeid : 0

		if (nodeid == nodeid_begin) {
			map_count++;
			continue;
		}
		// 즉 mem_section[0][pnum].section_mem_map에서 nodeid를 뽑아낸 뒤 그 값이 nodeid_begin과 동일한 갯수를 셈
		// usemap_count : 8
		/* ok, we need to take cake of from pnum_begin to pnum - 1*/
		alloc_func(data, pnum_begin, pnum,
						map_count, nodeid_begin);
		/* new start, update count etc*/
		nodeid_begin = nodeid;
		pnum_begin = pnum;
		map_count = 1;
	}
	/* ok, last chunk */
	// usemap_map : 4KB 할당 받은 주소(4*16 요청), pnum_begin : 2, NR_MEM_SECTIONS : 16, usemap_count : 8, nodeid_begin : 0
	alloc_func(data, pnum_begin, NR_MEM_SECTIONS,
						map_count, nodeid_begin);
	// usemap_map[2] ~ usemap_map[10] : 할당받은 주소 + offset가 저장됨
}

/*
 * Allocate the accumulated non-linear sections, allocate a mem_map
 * for each and record the physical to section mapping.
 */
void __init sparse_init(void)
{
	unsigned long pnum;
	struct page *map;
	unsigned long *usemap;
	unsigned long **usemap_map;
	int size;
#ifdef CONFIG_SPARSEMEM_ALLOC_MEM_MAP_TOGETHER
	int size2;
	struct page **map_map;
#endif

	/* see include/linux/mmzone.h 'struct mem_section' definition */
	BUILD_BUG_ON(!is_power_of_2(sizeof(struct mem_section)));
	// struct mem_section : 8 byte

	/* Setup pageblock_order for HUGETLB_PAGE_SIZE_VARIABLE */
	set_pageblock_order();
	// null 함수이므로 그냥 통과

	/*
	 * map is using big page (aka 2M in x86 64 bit)
	 * usemap is less one page (aka 24 bytes)
	 * so alloc 2M (with 2M align) and 24 bytes in turn will
	 * make next 2M slip to one more 2M later.
	 * then in big system, the memory will have a lot of holes...
	 * here try to allocate 2M pages continuously.
	 *
	 * powerpc need to call sparse_init_one_section right after each
	 * sparse_early_mem_map_alloc, so allocate usemap_map at first.
	 */
	size = sizeof(unsigned long *) * NR_MEM_SECTIONS;
	// NR_MEM_SECTION : 0x10
	// size : 4 * 16개(256MB가 16개 있으면 4GB)
	usemap_map = alloc_bootmem(size);
	// __alloc_bootmem(size, SMP_CACHE_BYTES, BOOTMEM_LOW_LIMIT)
	// size : 4 * 16, SMP_CACHE_BYTES : 64, BOOTMEM_LOW_LIMIT : 0x5FFFFFFF
	// 4KB 만큼 공간을 할당 받고 시작 가상 주소를 usemap_map에 저장
	
	if (!usemap_map)
		panic("can not allocate usemap_map\n");

	alloc_usemap_and_memmap(sparse_early_usemaps_alloc_node,
							(void *)usemap_map);

#ifdef CONFIG_SPARSEMEM_ALLOC_MEM_MAP_TOGETHER
	size2 = sizeof(struct page *) * NR_MEM_SECTIONS;
	map_map = alloc_bootmem(size2);
	if (!map_map)
		panic("can not allocate map_map\n");
	alloc_usemap_and_memmap(sparse_early_mem_maps_alloc_node,
							(void *)map_map);
#endif
	// NR_MEM_SECTIONS : 0x10
	for (pnum = 0; pnum < NR_MEM_SECTIONS; pnum++) {
		if (!present_section_nr(pnum)) // pnum : 0 ~ 1, 11 ~ 16 까지 통과
			continue;

		usemap = usemap_map[pnum];
		
		if (!usemap)
			continue;

#ifdef CONFIG_SPARSEMEM_ALLOC_MEM_MAP_TOGETHER
		map = map_map[pnum];
#else
		// pnum : 2
		map = sparse_early_mem_map_alloc(pnum);
		// 2816K 만큼 공간을 할당 받아옴
		// 2816K : 256MB를 관리하기 위한 struct page용 공간(64K개)
#endif
		if (!map)
			continue;

		// __nr_to_section(pum) : &mem_section[0][2], pnum : 2, map : 2816K, usemap : usemap_map[2]
		sparse_init_one_section(__nr_to_section(pnum), pnum, map,
								usemap);
	}

	vmemmap_populate_print_last();
	// null 함수

#ifdef CONFIG_SPARSEMEM_ALLOC_MEM_MAP_TOGETHER
	free_bootmem(__pa(map_map), size2);
#endif
	// usemap_map : ?(가상), size : 0x40
	free_bootmem(__pa(usemap_map), size);
	// usemap_map은 사용이 끝났으므로 free 해서 돌려줌
	// usemap_map의 값들은 mem_section 내부의 page_block_bitmap 멤버에 저장되었음
}

#ifdef CONFIG_MEMORY_HOTPLUG
#ifdef CONFIG_SPARSEMEM_VMEMMAP
static inline struct page *kmalloc_section_memmap(unsigned long pnum, int nid)
{
	/* This will make the necessary allocations eventually. */
	return sparse_mem_map_populate(pnum, nid);
}
static void __kfree_section_memmap(struct page *memmap)
{
	unsigned long start = (unsigned long)memmap;
	unsigned long end = (unsigned long)(memmap + PAGES_PER_SECTION);

	vmemmap_free(start, end);
}
#ifdef CONFIG_MEMORY_HOTREMOVE
static void free_map_bootmem(struct page *memmap)
{
	unsigned long start = (unsigned long)memmap;
	unsigned long end = (unsigned long)(memmap + PAGES_PER_SECTION);

	vmemmap_free(start, end);
}
#endif /* CONFIG_MEMORY_HOTREMOVE */
#else
static struct page *__kmalloc_section_memmap(void)
{
	struct page *page, *ret;
	unsigned long memmap_size = sizeof(struct page) * PAGES_PER_SECTION;

	page = alloc_pages(GFP_KERNEL|__GFP_NOWARN, get_order(memmap_size));
	if (page)
		goto got_map_page;

	ret = vmalloc(memmap_size);
	if (ret)
		goto got_map_ptr;

	return NULL;
got_map_page:
	ret = (struct page *)pfn_to_kaddr(page_to_pfn(page));
got_map_ptr:

	return ret;
}

static inline struct page *kmalloc_section_memmap(unsigned long pnum, int nid)
{
	return __kmalloc_section_memmap();
}

static void __kfree_section_memmap(struct page *memmap)
{
	if (is_vmalloc_addr(memmap))
		vfree(memmap);
	else
		free_pages((unsigned long)memmap,
			   get_order(sizeof(struct page) * PAGES_PER_SECTION));
}

#ifdef CONFIG_MEMORY_HOTREMOVE
static void free_map_bootmem(struct page *memmap)
{
	unsigned long maps_section_nr, removing_section_nr, i;
	unsigned long magic, nr_pages;
	struct page *page = virt_to_page(memmap);

	nr_pages = PAGE_ALIGN(PAGES_PER_SECTION * sizeof(struct page))
		>> PAGE_SHIFT;

	for (i = 0; i < nr_pages; i++, page++) {
		magic = (unsigned long) page->lru.next;

		BUG_ON(magic == NODE_INFO);

		maps_section_nr = pfn_to_section_nr(page_to_pfn(page));
		removing_section_nr = page->private;

		/*
		 * When this function is called, the removing section is
		 * logical offlined state. This means all pages are isolated
		 * from page allocator. If removing section's memmap is placed
		 * on the same section, it must not be freed.
		 * If it is freed, page allocator may allocate it which will
		 * be removed physically soon.
		 */
		if (maps_section_nr != removing_section_nr)
			put_page_bootmem(page);
	}
}
#endif /* CONFIG_MEMORY_HOTREMOVE */
#endif /* CONFIG_SPARSEMEM_VMEMMAP */

/*
 * returns the number of sections whose mem_maps were properly
 * set.  If this is <=0, then that means that the passed-in
 * map was not consumed and must be freed.
 */
int __meminit sparse_add_one_section(struct zone *zone, unsigned long start_pfn)
{
	unsigned long section_nr = pfn_to_section_nr(start_pfn);
	struct pglist_data *pgdat = zone->zone_pgdat;
	struct mem_section *ms;
	struct page *memmap;
	unsigned long *usemap;
	unsigned long flags;
	int ret;

	/*
	 * no locking for this, because it does its own
	 * plus, it does a kmalloc
	 */
	ret = sparse_index_init(section_nr, pgdat->node_id);
	if (ret < 0 && ret != -EEXIST)
		return ret;
	memmap = kmalloc_section_memmap(section_nr, pgdat->node_id);
	if (!memmap)
		return -ENOMEM;
	usemap = __kmalloc_section_usemap();
	if (!usemap) {
		__kfree_section_memmap(memmap);
		return -ENOMEM;
	}

	pgdat_resize_lock(pgdat, &flags);

	ms = __pfn_to_section(start_pfn);
	if (ms->section_mem_map & SECTION_MARKED_PRESENT) {
		ret = -EEXIST;
		goto out;
	}

	memset(memmap, 0, sizeof(struct page) * PAGES_PER_SECTION);

	ms->section_mem_map |= SECTION_MARKED_PRESENT;

	ret = sparse_init_one_section(ms, section_nr, memmap, usemap);

out:
	pgdat_resize_unlock(pgdat, &flags);
	if (ret <= 0) {
		kfree(usemap);
		__kfree_section_memmap(memmap);
	}
	return ret;
}

#ifdef CONFIG_MEMORY_HOTREMOVE
#ifdef CONFIG_MEMORY_FAILURE
static void clear_hwpoisoned_pages(struct page *memmap, int nr_pages)
{
	int i;

	if (!memmap)
		return;

	for (i = 0; i < PAGES_PER_SECTION; i++) {
		if (PageHWPoison(&memmap[i])) {
			atomic_long_sub(1, &num_poisoned_pages);
			ClearPageHWPoison(&memmap[i]);
		}
	}
}
#else
static inline void clear_hwpoisoned_pages(struct page *memmap, int nr_pages)
{
}
#endif

static void free_section_usemap(struct page *memmap, unsigned long *usemap)
{
	struct page *usemap_page;

	if (!usemap)
		return;

	usemap_page = virt_to_page(usemap);
	/*
	 * Check to see if allocation came from hot-plug-add
	 */
	if (PageSlab(usemap_page) || PageCompound(usemap_page)) {
		kfree(usemap);
		if (memmap)
			__kfree_section_memmap(memmap);
		return;
	}

	/*
	 * The usemap came from bootmem. This is packed with other usemaps
	 * on the section which has pgdat at boot time. Just keep it as is now.
	 */

	if (memmap)
		free_map_bootmem(memmap);
}

void sparse_remove_one_section(struct zone *zone, struct mem_section *ms)
{
	struct page *memmap = NULL;
	unsigned long *usemap = NULL, flags;
	struct pglist_data *pgdat = zone->zone_pgdat;

	pgdat_resize_lock(pgdat, &flags);
	if (ms->section_mem_map) {
		usemap = ms->pageblock_flags;
		memmap = sparse_decode_mem_map(ms->section_mem_map,
						__section_nr(ms));
		ms->section_mem_map = 0;
		ms->pageblock_flags = NULL;
	}
	pgdat_resize_unlock(pgdat, &flags);

	clear_hwpoisoned_pages(memmap, PAGES_PER_SECTION);
	free_section_usemap(memmap, usemap);
}
#endif /* CONFIG_MEMORY_HOTREMOVE */
#endif /* CONFIG_MEMORY_HOTPLUG */
