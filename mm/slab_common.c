/*
 * Slab allocator functions that are independent of the allocator strategy
 *
 * (C) 2012 Christoph Lameter <cl@linux.com>
 */
#include <linux/slab.h>

#include <linux/mm.h>
#include <linux/poison.h>
#include <linux/interrupt.h>
#include <linux/memory.h>
#include <linux/compiler.h>
#include <linux/module.h>
#include <linux/cpu.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/page.h>
#include <linux/memcontrol.h>
#include <trace/events/kmem.h>

#include "slab.h"

enum slab_state slab_state;
LIST_HEAD(slab_caches);
DEFINE_MUTEX(slab_mutex);
struct kmem_cache *kmem_cache;

#ifdef CONFIG_DEBUG_VM	// N
static int kmem_cache_sanity_check(struct mem_cgroup *memcg, const char *name,
				   size_t size)
{
	struct kmem_cache *s = NULL;

	if (!name || in_interrupt() || size < sizeof(void *) ||
		size > KMALLOC_MAX_SIZE) {
		pr_err("kmem_cache_create(%s) integrity check failed\n", name);
		return -EINVAL;
	}

	list_for_each_entry(s, &slab_caches, list) {
		char tmp;
		int res;

		/*
		 * This happens when the module gets unloaded and doesn't
		 * destroy its slab cache and no-one else reuses the vmalloc
		 * area of the module.  Print a warning.
		 */
		res = probe_kernel_address(s->name, tmp);
		if (res) {
			pr_err("Slab cache with size %d has lost its name\n",
			       s->object_size);
			continue;
		}

#if !defined(CONFIG_SLUB) || !defined(CONFIG_SLUB_DEBUG_ON)
		/*
		 * For simplicity, we won't check this in the list of memcg
		 * caches. We have control over memcg naming, and if there
		 * aren't duplicates in the global list, there won't be any
		 * duplicates in the memcg lists as well.
		 */
		if (!memcg && !strcmp(s->name, name)) {
			pr_err("%s (%s): Cache name already exists.\n",
			       __func__, name);
			dump_stack();
			s = NULL;
			return -EINVAL;
		}
#endif
	}

	WARN_ON(strchr(name, ' '));	/* It confuses parsers */
	return 0;
}
#else
static inline int kmem_cache_sanity_check(struct mem_cgroup *memcg,
					  const char *name, size_t size)
{
	return 0;
}
#endif

#ifdef CONFIG_MEMCG_KMEM
int memcg_update_all_caches(int num_memcgs)
{
	struct kmem_cache *s;
	int ret = 0;
	mutex_lock(&slab_mutex);

	list_for_each_entry(s, &slab_caches, list) {
		if (!is_root_cache(s))
			continue;

		ret = memcg_update_cache_size(s, num_memcgs);
		/*
		 * See comment in memcontrol.c, memcg_update_cache_size:
		 * Instead of freeing the memory, we'll just leave the caches
		 * up to this point in an updated state.
		 */
		if (ret)
			goto out;
	}

	memcg_update_array_size(num_memcgs);
out:
	mutex_unlock(&slab_mutex);
	return ret;
}
#endif

/*
 * Figure out what the alignment of the objects will be given a set of
 * flags, a user specified alignment and the size of the objects.
 */
// [D] flags : SLAB_HWCACHE_ALIGN(0x2000), align : ARCH_KMALLOC_MINALIGN(64), size : 44
// [P] flags : 0x2000, ARCH_KMALLOC_MINALIGN : 64(L1 cache 크기), size : 132
unsigned long calculate_alignment(unsigned long flags,
		unsigned long align, unsigned long size)
{
	/*
	 * If the user wants hardware cache aligned objects then follow that
	 * suggestion if the object is sufficiently large.
	 *
	 * The hardware cache alignment cannot override the specified
	 * alignment though. If that is greater then use it.
	 */
	if (flags & SLAB_HWCACHE_ALIGN) {
		unsigned long ralign = cache_line_size();
		// ralign : 64

		while (size <= ralign / 2)
			ralign /= 2;
		// 반복문은 통과됨

		align = max(align, ralign);
		// align : 64
	}

	// ARCH_SLAB_MINALIGN : 8
	if (align < ARCH_SLAB_MINALIGN)
		align = ARCH_SLAB_MINALIGN;

	return ALIGN(align, sizeof(void *));
	// align : 64
}


/*
 * kmem_cache_create - Create a cache.
 * @name: A string which is used in /proc/slabinfo to identify this cache.
 * @size: The size of objects to be created in this cache.
 * @align: The required alignment for the objects.
 * @flags: SLAB flags
 * @ctor: A constructor for the objects.
 *
 * Returns a ptr to the cache on success, NULL on failure.
 * Cannot be called within a interrupt, but can be interrupted.
 * The @ctor is run when new pages are allocated by the cache.
 *
 * The flags are
 *
 * %SLAB_POISON - Poison the slab with a known test pattern (a5a5a5a5)
 * to catch references to uninitialised memory.
 *
 * %SLAB_RED_ZONE - Insert `Red' zones around the allocated memory to check
 * for buffer overruns.
 *
 * %SLAB_HWCACHE_ALIGN - Align the objects in this cache to a hardware
 * cacheline.  This can be beneficial if you're counting cycles as closely
 * as davem.
 */

// memcg : NULL, name : "idr_layer_cache", size : sizeof(struct idr_layer),
// align : 0, flags : SLAB_PANIC, ctor : NULL, parent_cache : NULL
struct kmem_cache *
kmem_cache_create_memcg(struct mem_cgroup *memcg, const char *name, size_t size,
			size_t align, unsigned long flags, void (*ctor)(void *),
			struct kmem_cache *parent_cache)
{
	struct kmem_cache *s = NULL;
	int err = 0;

	get_online_cpus();
	// cpu_hotplug.refcount : 1로 증가
	
	mutex_lock(&slab_mutex);
	// mutex 락 획득

	// kmem_cache_sanity_check() : 무조건 0 반환
	if (!kmem_cache_sanity_check(memcg, name, size) == 0)
		goto out_locked;

	/*
	 * Some allocators will constraint the set of valid flags to a subset
	 * of all flags. We expect them to define CACHE_CREATE_MASK in this
	 * case, and we'll just provide them with a sanitized version of the
	 * passed flags.
	 */

	// flags : SLAB_PANIC(0x00040000), CACHE_CREATE_MASK : 0xAF6D00
	flags &= CACHE_CREATE_MASK;
	// flags : SLAB_PANIC(0x00040000)

	// memcg : NULL, name : "idr_layer_cache", size : sizeof(struct idr_layer),
	// align : 0, flags : SLAB_PANIC, ctor : NULL
	s = __kmem_cache_alias(memcg, name, size, align, flags, ctor);
	// s : NULL 반환
	
	// s : NULL
	if (s)
		goto out_locked;
	// 통과 

	s = kmem_cache_zalloc(kmem_cache, GFP_KERNEL);
	// 이전에 만들어 둔 kmem_cache용 page에서 사용하지 않는 오브젝트의 주소를 반환
	// s : kmem_cache#21
	// 21번째 오브젝트가 비어 있었음
	
	// s : kmem_cache#21
	if (s) {
		s->object_size = s->size = size;
		// kmem_cache#21.object_size : 1076
		// kmem_cache#21.size : 1076

		s->align = calculate_alignment(flags, align, size);
		// kmem_cache#21.align : 8
		
		s->ctor = ctor;
		// kmem_cache#21.ctor : NULL

		// memcg_register_cache : 항상 NULL 반환
		if (memcg_register_cache(memcg, s, parent_cache)) {
			kmem_cache_free(kmem_cache, s);
			err = -ENOMEM;
			goto out_locked;
		}
		// 통과

		s->name = kstrdup(name, GFP_KERNEL);
		// slub을 이용해 name을 저장할 공간을 확보한 뒤,
		// 문자열을 옮겨두고 그 주소를 s->name에 저장함
		
		if (!s->name) {
			kmem_cache_free(kmem_cache, s);
			err = -ENOMEM;
			goto out_locked;
		}

		// s : kmem_cache#21, flags : SLAB_PANIC
		err = __kmem_cache_create(s, flags);
		// kmem_cache 내부의 node 구조체 및 자료를 설정해줌
		// size 값을 이용해 주로 계산함
		// err : 0

		if (!err) {
			s->refcount = 1;
			list_add(&s->list, &slab_caches);
			memcg_cache_list_add(memcg, s);
			// refcount를 1로 바꿔주고
			// 이전과 마찬가지로 slab_caches에 등록해 줌
		} else {
			kfree(s->name);
			kmem_cache_free(kmem_cache, s);
		}
	} else
		err = -ENOMEM;

out_locked:
	mutex_unlock(&slab_mutex);
	// 락 해제
	
	put_online_cpus();
	// cpu_hotplug.refcount : 0 으로 변경

	if (err) {

		if (flags & SLAB_PANIC)
			panic("kmem_cache_create: Failed to create slab '%s'. Error %d\n",
				name, err);
		else {
			printk(KERN_WARNING "kmem_cache_create(%s) failed with error %d",
				name, err);
			dump_stack();
		}

		return NULL;
	}

	return s;
	// 설정을 완료한 kmem_cache 구조체 반환
}

// name : "idr_layer_cache", size : sizeof(struct idr_layer), align : 0, flags : SLAB_PANIC, ctor : NULL
// name : "radix_tree_node", size : sizeof(struct radix_tree_node),
// align : 0, flags : SLAB_PANIC | SLAB_RECLAIM_ACCOUNT, ctor : radix_tree_node_ctor
struct kmem_cache *
kmem_cache_create(const char *name, size_t size, size_t align,
		  unsigned long flags, void (*ctor)(void *))
{
	// NULL,  name : "idr_layer_cache", size : sizeof(struct idr_layer), align : 0, flags : SLAB_PANIC, ctor : NULL, NULL
	return kmem_cache_create_memcg(NULL, name, size, align, flags, ctor, NULL);
}
EXPORT_SYMBOL(kmem_cache_create);

void kmem_cache_destroy(struct kmem_cache *s)
{
	/* Destroy all the children caches if we aren't a memcg cache */
	kmem_cache_destroy_memcg_children(s);

	get_online_cpus();
	mutex_lock(&slab_mutex);
	s->refcount--;
	if (!s->refcount) {
		list_del(&s->list);

		if (!__kmem_cache_shutdown(s)) {
			mutex_unlock(&slab_mutex);
			if (s->flags & SLAB_DESTROY_BY_RCU)
				rcu_barrier();

			memcg_release_cache(s);
			kfree(s->name);
			kmem_cache_free(kmem_cache, s);
		} else {
			list_add(&s->list, &slab_caches);
			mutex_unlock(&slab_mutex);
			printk(KERN_ERR "kmem_cache_destroy %s: Slab cache still has objects\n",
				s->name);
			dump_stack();
		}
	} else {
		mutex_unlock(&slab_mutex);
	}
	put_online_cpus();
}
EXPORT_SYMBOL(kmem_cache_destroy);

int slab_is_available(void)
{
	return slab_state >= UP;
}

#ifndef CONFIG_SLOB		// N
/* Create a cache during boot when no slab services are available yet */
// [D] s : &boot_kmem_cache_node, name : "kmem_cache_node", size : 44byte, flags : SLAB_HWCACHE_ALIGN(0x2000)
// [P] s : &boot_kmem_cache, name : "kmem_cache", size : 132byte, flags : SLAB_HWCACHE_ALIGN(0x2000)
// [P] size : offsetof(struct kmem_cache, node) + nr_node_ids * sizeof(struct kmem_cache_node *)
// s : kmem_cache#2, name : NULL, size : 64, flags : 0
void __init create_boot_cache(struct kmem_cache *s, const char *name, size_t size,
		unsigned long flags)
{
	int err;

	s->name = name;
	// [D] boot_kmem_cache_node.name : "kmem_cache_node"
	// [P] boot_kmem_cache.name : "kmem_cache"

	s->size = s->object_size = size;
	// [D] boot_kmem_cache_node.size : 44;
	// [D] boot_kmem_cache_node.object_size : 44;
	// [P] boot_kmem_cache.size : 132;
	// [P] boot_kmem_cache.object_size : 132;

	// [D] flags : 0x2000, ARCH_KMALLOC_MINALIGN : 64(L1 cache 크기), size : 44
	// [P] flags : 0x2000, ARCH_KMALLOC_MINALIGN : 64(L1 cache 크기), size : 132
	s->align = calculate_alignment(flags, ARCH_KMALLOC_MINALIGN, size);
	// [D] boot_kmem_cache_node.align : 64
	// [P] boot_kmem_cache.align : 64
	
	err = __kmem_cache_create(s, flags);
	// boot_kmem_cache_node를 설정함
	// 확보한 kmem_cache_node object는 boot_kmem_cache_node.node에 연결해둠
	// object가 존재하는 page는 object의 partial 리스트에 달아둠
	// percpu dynamic 공간에서 kmem_cache_cpu용 공간을 확보하고 그 곳의 tid 멤버에
	// init_tid(cpu) : cpu와 동일한 값을 저장함

	// 두 번째 호출 시에는 boot_kmem_cache를 설정
	// 이전에 확보한 kmem_cache_node용 page는 boot_kmem_cache_node의 partial 리스트에 연결되어 있었는데, 
	// 그 page의 쓰지 않은 object 중 첫 번째 것을 빼와 boot_kmem_cache의 node[0] 멤버에 저장
	if (err)
		panic("Creation of kmalloc slab %s size=%zu failed. Reason %d\n",
					name, size, err);

	s->refcount = -1;	/* Exempt from merging for now */
	// refcount 설정
}

// name : NULL, size : 64, flags : 0
struct kmem_cache *__init create_kmalloc_cache(const char *name, size_t size,
				unsigned long flags)
{
	// kmem_cache : boot_kmem_cache를 복사한 것(object)
	struct kmem_cache *s = kmem_cache_zalloc(kmem_cache, GFP_NOWAIT);
	// s : kmem_cache#2
	//     kmem_cache#1  : kmem_cache 용
	//     kmem_cache#32 : kmem_cache_node 용

	if (!s)
		panic("Out of memory when creating slab %s\n", name);

	// s : kmem_cache#2, name : NULL, size : 64, flags : 0
	create_boot_cache(s, name, size, flags);
	// kmem_cache#2를 위한 kmem_cache_node를 확보하고, kmem_cache_cpu도 확보함
	// 이 두 값을 kmem_cache#2의 node 멤버와 cpu_slab 멤버에 저장함
	
	list_add(&s->list, &slab_caches);
	// kmem_cache#2를 slab_caches 리스트에 추가함
	
	s->refcount = 1;
	// kmem_cache#2의 refcount를 1로 설정함
	return s;
}

struct kmem_cache *kmalloc_caches[KMALLOC_SHIFT_HIGH + 1];
EXPORT_SYMBOL(kmalloc_caches);

#ifdef CONFIG_ZONE_DMA
struct kmem_cache *kmalloc_dma_caches[KMALLOC_SHIFT_HIGH + 1];
EXPORT_SYMBOL(kmalloc_dma_caches);
#endif

/*
 * Conversion table for small slabs sizes / 8 to the index in the
 * kmalloc array. This is necessary for slabs < 192 since we have non power
 * of two cache sizes there. The size of larger slabs can be determined using
 * fls.
 */
static s8 size_index[24] = {
	3,	/* 8 */		// 6
	4,	/* 16 */	// 6
	5,	/* 24 */	// 6
	5,	/* 32 */	// 6
	6,	/* 40 */	// 6
	6,	/* 48 */	// 6
	6,	/* 56 */	// 6
	6,	/* 64 */
	1,	/* 72 */
	1,	/* 80 */
	1,	/* 88 */
	1,	/* 96 */
	7,	/* 104 */
	7,	/* 112 */
	7,	/* 120 */
	7,	/* 128 */
	2,	/* 136 */
	2,	/* 144 */
	2,	/* 152 */
	2,	/* 160 */
	2,	/* 168 */
	2,	/* 176 */
	2,	/* 184 */
	2	/* 192 */
};

// bytes : 8
static inline int size_index_elem(size_t bytes)
{
	return (bytes - 1) / 8;
}

/*
 * Find the kmem_cache structure that serves a given size of
 * allocation
 */
// size : 12, gfpflags : GFP_NOWAIT
struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags)
{
	int index;

	// size : 12, KMALLOC_MAX_SIZE : 1G
	if (unlikely(size > KMALLOC_MAX_SIZE)) {
		WARN_ON_ONCE(!(flags & __GFP_NOWARN));
		return NULL;
	}
	
	// size : 12
	if (size <= 192) {
		if (!size)
			return ZERO_SIZE_PTR;

		// size_index_elem(12) : 2
		index = size_index[size_index_elem(size)];
		// size_index[2] : KMALLOC_SHIFT_LOW(6)이 저장되어 있음
		// index : 6이 됨
		
	} else
		index = fls(size - 1);

#ifdef CONFIG_ZONE_DMA // N
	if (unlikely((flags & GFP_DMA)))
		return kmalloc_dma_caches[index];

#endif
	return kmalloc_caches[index];
	// kmalloc_caches[6]이 반환됨
	// 즉, kmem_cache#2가 반환됨
}

/*
 * Create the kmalloc array. Some of the regular kmalloc arrays
 * may already have been created because they were needed to
 * enable allocations for slab creation.
 */
// flags : 0
void __init create_kmalloc_caches(unsigned long flags)
{
	int i;

	/*
	 * Patch up the size_index table if we have strange large alignment
	 * requirements for the kmalloc array. This is only the case for
	 * MIPS it seems. The standard arches will not generate any code here.
	 *
	 * Largest permitted alignment is 256 bytes due to the way we
	 * handle the index determination for the smaller caches.
	 *
	 * Make sure that nothing crazy happens if someone starts tinkering
	 * around with ARCH_KMALLOC_MINALIGN
	 */
	// KMALLOC_MIN_SIZE : 64
	BUILD_BUG_ON(KMALLOC_MIN_SIZE > 256 ||
		(KMALLOC_MIN_SIZE & (KMALLOC_MIN_SIZE - 1)));

	// KMALLOC_MIN_SIZE : 64
	for (i = 8; i < KMALLOC_MIN_SIZE; i += 8) {
		// i : 8
		int elem = size_index_elem(i);
		// elem : 0
		// i번째 비트가 몇 번째 바이트에 들어가는 지 계산함

		// elem : 0, size_index : 전역변수, ARRAY_SIZE(size_index) : 24
		if (elem >= ARRAY_SIZE(size_index))
			break;

		// size_index에 KMALLOC_SHIFT_LOW(log2(64) = 6)을 저장
		size_index[elem] = KMALLOC_SHIFT_LOW;
	}
	// size_index[0] ~ size_index[6]을 KMALLOC_SHIFT_LOW(6)로 변경함
	
	// KMALLOC_MIN_SIZE : 64
	if (KMALLOC_MIN_SIZE >= 64) {
		/*
		 * The 96 byte size cache is not used if the alignment
		 * is 64 byte.
		 */
		for (i = 64 + 8; i <= 96; i += 8)
			size_index[size_index_elem(i)] = 7;
		// size_index[8] ~ size_index[11] : 7로 변경

	}

	// KMALLOC_MIN_SIZE : 64
	if (KMALLOC_MIN_SIZE >= 128) {		// 통과
		/*
		 * The 192 byte sized cache is not used if the alignment
		 * is 128 byte. Redirect kmalloc to use the 256 byte cache
		 * instead.
		 */
		for (i = 128 + 8; i <= 192; i += 8)
			size_index[size_index_elem(i)] = 8;
	}

	// KMALLOC_SHIFT_LOW : 6, KMALLOC_SHIFT_HIGH : 13
	for (i = KMALLOC_SHIFT_LOW; i <= KMALLOC_SHIFT_HIGH; i++) {
		// kmalloc_caches : struct kmem_cache* 배열임 14칸
		// kmalloc_caches[6] : NULL
		if (!kmalloc_caches[i]) {
			// i : 6, flags : 0
			kmalloc_caches[i] = create_kmalloc_cache(NULL,
							1 << i, flags);
			// 관리하는 오브젝트의 크기가 64인 kmem_cache 구조체를 하나 생성하고,
			// 이를 위한 kmem_cache_node, kmem_cache_cpu를 새로 할당받아 설정함
			// 그리고 이 새로운 구조체의 주소를 kmalloc_caches[6]에 저장함
			// 결국 kmalloc_caches[6]의 값은 kmem_cache#2가 됨
		}

		/*
		 * Caches that are not of the two-to-the-power-of size.
		 * These have to be created immediately after the
		 * earlier power of two caches
		 */
		if (KMALLOC_MIN_SIZE <= 32 && !kmalloc_caches[1] && i == 6)
			kmalloc_caches[1] = create_kmalloc_cache(NULL, 96, flags);

		if (KMALLOC_MIN_SIZE <= 64 && !kmalloc_caches[2] && i == 7)
			kmalloc_caches[2] = create_kmalloc_cache(NULL, 192, flags);
	}

	/* Kmalloc array is now usable */
	slab_state = UP;

	// KMALLOC_SHIFT_HIGH : 13
	for (i = 0; i <= KMALLOC_SHIFT_HIGH; i++) {
		struct kmem_cache *s = kmalloc_caches[i];
		char *n;

		if (s) {
			// kmalloc_size(2) : 192
			n = kasprintf(GFP_NOWAIT, "kmalloc-%d", kmalloc_size(i));
			// kmem_cache#2-o1 오브젝트를 받아오고, 그 공간에 위에서 만든
			// 문자열을 만들어 저장함
			// 즉, 앞에서 만든 슬랩 할당자를 이용해 메모리를 확보하고
			// 그 공간에 문자열을 저장

			BUG_ON(!n);
			s->name = n;
		}
	}
	// 위에서 만든 각 kmem_cache의 name 멤버에 각각 크기를 이용해 이름을 만들어 연결해 줌

#ifdef CONFIG_ZONE_DMA	// N
	for (i = 0; i <= KMALLOC_SHIFT_HIGH; i++) {
		struct kmem_cache *s = kmalloc_caches[i];

		if (s) {
			int size = kmalloc_size(i);
			char *n = kasprintf(GFP_NOWAIT,
				 "dma-kmalloc-%d", size);

			BUG_ON(!n);
			kmalloc_dma_caches[i] = create_kmalloc_cache(n,
				size, SLAB_CACHE_DMA | flags);
		}
	}
#endif
}
#endif /* !CONFIG_SLOB */

#ifdef CONFIG_TRACING
void *kmalloc_order_trace(size_t size, gfp_t flags, unsigned int order)
{
	void *ret = kmalloc_order(size, flags, order);
	trace_kmalloc(_RET_IP_, ret, size, PAGE_SIZE << order, flags);
	return ret;
}
EXPORT_SYMBOL(kmalloc_order_trace);
#endif

#ifdef CONFIG_SLABINFO

#ifdef CONFIG_SLAB
#define SLABINFO_RIGHTS (S_IWUSR | S_IRUSR)
#else
#define SLABINFO_RIGHTS S_IRUSR
#endif

void print_slabinfo_header(struct seq_file *m)
{
	/*
	 * Output format version, so at least we can change it
	 * without _too_ many complaints.
	 */
#ifdef CONFIG_DEBUG_SLAB
	seq_puts(m, "slabinfo - version: 2.1 (statistics)\n");
#else
	seq_puts(m, "slabinfo - version: 2.1\n");
#endif
	seq_puts(m, "# name            <active_objs> <num_objs> <objsize> "
		 "<objperslab> <pagesperslab>");
	seq_puts(m, " : tunables <limit> <batchcount> <sharedfactor>");
	seq_puts(m, " : slabdata <active_slabs> <num_slabs> <sharedavail>");
#ifdef CONFIG_DEBUG_SLAB
	seq_puts(m, " : globalstat <listallocs> <maxobjs> <grown> <reaped> "
		 "<error> <maxfreeable> <nodeallocs> <remotefrees> <alienoverflow>");
	seq_puts(m, " : cpustat <allochit> <allocmiss> <freehit> <freemiss>");
#endif
	seq_putc(m, '\n');
}

static void *s_start(struct seq_file *m, loff_t *pos)
{
	loff_t n = *pos;

	mutex_lock(&slab_mutex);
	if (!n)
		print_slabinfo_header(m);

	return seq_list_start(&slab_caches, *pos);
}

void *slab_next(struct seq_file *m, void *p, loff_t *pos)
{
	return seq_list_next(p, &slab_caches, pos);
}

void slab_stop(struct seq_file *m, void *p)
{
	mutex_unlock(&slab_mutex);
}

static void
memcg_accumulate_slabinfo(struct kmem_cache *s, struct slabinfo *info)
{
	struct kmem_cache *c;
	struct slabinfo sinfo;
	int i;

	if (!is_root_cache(s))
		return;

	for_each_memcg_cache_index(i) {
		c = cache_from_memcg_idx(s, i);
		if (!c)
			continue;

		memset(&sinfo, 0, sizeof(sinfo));
		get_slabinfo(c, &sinfo);

		info->active_slabs += sinfo.active_slabs;
		info->num_slabs += sinfo.num_slabs;
		info->shared_avail += sinfo.shared_avail;
		info->active_objs += sinfo.active_objs;
		info->num_objs += sinfo.num_objs;
	}
}

int cache_show(struct kmem_cache *s, struct seq_file *m)
{
	struct slabinfo sinfo;

	memset(&sinfo, 0, sizeof(sinfo));
	get_slabinfo(s, &sinfo);

	memcg_accumulate_slabinfo(s, &sinfo);

	seq_printf(m, "%-17s %6lu %6lu %6u %4u %4d",
		   cache_name(s), sinfo.active_objs, sinfo.num_objs, s->size,
		   sinfo.objects_per_slab, (1 << sinfo.cache_order));

	seq_printf(m, " : tunables %4u %4u %4u",
		   sinfo.limit, sinfo.batchcount, sinfo.shared);
	seq_printf(m, " : slabdata %6lu %6lu %6lu",
		   sinfo.active_slabs, sinfo.num_slabs, sinfo.shared_avail);
	slabinfo_show_stats(m, s);
	seq_putc(m, '\n');
	return 0;
}

static int s_show(struct seq_file *m, void *p)
{
	struct kmem_cache *s = list_entry(p, struct kmem_cache, list);

	if (!is_root_cache(s))
		return 0;
	return cache_show(s, m);
}

/*
 * slabinfo_op - iterator that generates /proc/slabinfo
 *
 * Output layout:
 * cache-name
 * num-active-objs
 * total-objs
 * object size
 * num-active-slabs
 * total-slabs
 * num-pages-per-slab
 * + further values on SMP and with statistics enabled
 */
static const struct seq_operations slabinfo_op = {
	.start = s_start,
	.next = slab_next,
	.stop = slab_stop,
	.show = s_show,
};

static int slabinfo_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &slabinfo_op);
}

static const struct file_operations proc_slabinfo_operations = {
	.open		= slabinfo_open,
	.read		= seq_read,
	.write          = slabinfo_write,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init slab_proc_init(void)
{
	proc_create("slabinfo", SLABINFO_RIGHTS, NULL,
						&proc_slabinfo_operations);
	return 0;
}
module_init(slab_proc_init);
#endif /* CONFIG_SLABINFO */
