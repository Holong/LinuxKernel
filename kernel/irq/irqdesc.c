/*
 * Copyright (C) 1992, 1998-2006 Linus Torvalds, Ingo Molnar
 * Copyright (C) 2005-2006, Thomas Gleixner, Russell King
 *
 * This file contains the interrupt descriptor management code
 *
 * Detailed information is available in Documentation/DocBook/genericirq
 *
 */
#include <linux/irq.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/radix-tree.h>
#include <linux/bitmap.h>

#include "internals.h"

/*
 * lockdep: we want to handle all irq_desc locks as a single lock-class:
 */
static struct lock_class_key irq_desc_lock_class;

#if defined(CONFIG_SMP)	// Y
static void __init init_irq_default_affinity(void)
{
	// irq_default_affinity : cpumask_var_t형 전역변수
	alloc_cpumask_var(&irq_default_affinity, GFP_NOWAIT);
	// 하는 일 없음
	
	cpumask_setall(irq_default_affinity);
	// irq_default_affinity->bits[0] : 0xF
	// CPU 개수만큼 비트가 설정됨
}
#else
static void __init init_irq_default_affinity(void)
{
}
#endif

#ifdef CONFIG_SMP
// desc : kmem_cache#28-o0, gfp : GFP_KERNEL, node : 0
static int alloc_masks(struct irq_desc *desc, gfp_t gfp, int node)
{
	// desc->irq_data.affinity : kmem_cache#28-o0.irq_data.affinity
	// gfp : GFP_KERNEL, node : 0
	if (!zalloc_cpumask_var_node(&desc->irq_data.affinity, gfp, node))
		return -ENOMEM;

#ifdef CONFIG_GENERIC_PENDING_IRQ	// N
	if (!zalloc_cpumask_var_node(&desc->pending_mask, gfp, node)) {
		free_cpumask_var(desc->irq_data.affinity);
		return -ENOMEM;
	}
#endif
	return 0;
}

// desc : 할당받은 irq_desc, node : 0
static void desc_smp_init(struct irq_desc *desc, int node)
{
	// node : 0
	desc->irq_data.node = node;
	// 멤버 값 초기화
	
	// irq_default_affinity.bits[0] : 4
	cpumask_copy(desc->irq_data.affinity, irq_default_affinity);
	// desc->irq_data.affinity : irq_default_affinity 값을 대입
	
#ifdef CONFIG_GENERIC_PENDING_IRQ	// N
	cpumask_clear(desc->pending_mask);
#endif
}

static inline int desc_node(struct irq_desc *desc)
{
	return desc->irq_data.node;
}

#else
static inline int
alloc_masks(struct irq_desc *desc, gfp_t gfp, int node) { return 0; }
static inline void desc_smp_init(struct irq_desc *desc, int node) { }
static inline int desc_node(struct irq_desc *desc) { return 0; }
#endif

// irq : 0, desc : 할당받은 irq_desc 구조체의 주소, node : 0, owner : NULL
static void desc_set_defaults(unsigned int irq, struct irq_desc *desc, int node,
		struct module *owner)
{
	int cpu;

	// irq : 0 
	desc->irq_data.irq = irq;
	// 인터럽트 번호
	
	// no_irq_chip : 미리 준비되어 있는 초기화 값
	desc->irq_data.chip = &no_irq_chip;
	desc->irq_data.chip_data = NULL;
	desc->irq_data.handler_data = NULL;
	desc->irq_data.msi_desc = NULL;
	// desc->irq_data 값을 초기화 해 줌
	
	// desc : 할당받은 irq_desc, ~0, _IRQ_DEFAULT_INIT_FLAGS : 0xC00
	irq_settings_clr_and_set(desc, ~0, _IRQ_DEFAULT_INIT_FLAGS);
	// desc->status_use_accessors : 0xC00로 설정됨
	
	// desc->irq_data, IRQD_IRQ_DISABLED
	irqd_set(&desc->irq_data, IRQD_IRQ_DISABLED);
	// desc->irq_data.status_use_accessors : IRQD_IRQ_DISABLED
	
	desc->handle_irq = handle_bad_irq;
	// desc->handle_irq : handle_bad_irq 함수 포인터 저장
	
	desc->depth = 1;
	desc->irq_count = 0;
	desc->irqs_unhandled = 0;
	desc->name = NULL;
	
	// owner : NULL
	desc->owner = owner;
	// desc 멤버들 초기화
	
	for_each_possible_cpu(cpu)
		*per_cpu_ptr(desc->kstat_irqs, cpu) = 0;
	// 이전에 할당받아 kstat_irqs에 연결해둔 int percpu 변수를 전부 0으로 초기화
	
	// desc : 할당받은 irq_desc, node : 0
	desc_smp_init(desc, node);
	// desc->irq_data.node 멤버 값 초기화
	// desc->irq_data.affinity : 0xF로 초기화
}

int nr_irqs = NR_IRQS;
EXPORT_SYMBOL_GPL(nr_irqs);

static DEFINE_MUTEX(sparse_irq_lock);
// IRQ_BITMAP_BITS : 8212
static DECLARE_BITMAP(allocated_irqs, IRQ_BITMAP_BITS);
// long 257개짜리 배열 생성

#ifdef CONFIG_SPARSE_IRQ

static RADIX_TREE(irq_desc_tree, GFP_KERNEL);
// struct radix_tree_root irq_desc_tree = {
// 	.height = 0,
//	.gfp_mask = GFP_KERNEL,
//	.rnode = NULL
// }

// irq : 0, desc : 할당받은 irq_desc 주소
// irq : 16, desc : 할당받은 irq_desc 주소
static void irq_insert_desc(unsigned int irq, struct irq_desc *desc)
{
	// &irq_desc_tree, irq : 0, desc : 할당받은 irq_desc 주소
	// &irq_desc_tree, irq : 1, desc : 할당받은 irq_desc 주소
	// &irq_desc_tree, irq : 16, desc : 할당받은 irq_desc 주소
	radix_tree_insert(&irq_desc_tree, irq, desc);
}

// irq : 16
struct irq_desc *irq_to_desc(unsigned int irq)
{
	// irq_desc_tree : irq_desc가 등록되어 있는 radix tree
	// irq : 16
	return radix_tree_lookup(&irq_desc_tree, irq);
	// 16 index에 해당하는 irq_desc 16이 반환됨
}
EXPORT_SYMBOL(irq_to_desc);

static void delete_irq_desc(unsigned int irq)
{
	radix_tree_delete(&irq_desc_tree, irq);
}

#ifdef CONFIG_SMP
static void free_masks(struct irq_desc *desc)
{
#ifdef CONFIG_GENERIC_PENDING_IRQ
	free_cpumask_var(desc->pending_mask);
#endif
	free_cpumask_var(desc->irq_data.affinity);
}
#else
static inline void free_masks(struct irq_desc *desc) { }
#endif

// irq : 0, node : 0, owner : NULL
// irq : 16, node : 0, owner : NULL
static struct irq_desc *alloc_desc(int irq, int node, struct module *owner)
{
	struct irq_desc *desc;
	gfp_t gfp = GFP_KERNEL;

	// sizeof(*desc) : 156, gfp : GFP_KERNEL, node : 0
	desc = kzalloc_node(sizeof(*desc), gfp, node);
	// desc : kmalloc_caches[2].node[0]에서 관리하는 partial에서 가져온 object
	// struct irq_desc의 크기를 이용해서 kmalloc_caches 중에 적절한 곳을 찾은 뒤
	// 그 곳에 연결되어 있는 free object 중에 하나를 할당받아옴
	
	if (!desc)
		return NULL;

	/* allocate based on nr_cpu_ids */
	desc->kstat_irqs = alloc_percpu(unsigned int);
	// percpu 공간에서 int를 새로 할당한 뒤, 그 주소를 반환
	// 그 값을 desc->kstat_irqs에 저장함
	
	if (!desc->kstat_irqs)
		goto err_desc;

	// desc, gfp : GFP_KERNEL, node : 0
	if (alloc_masks(desc, gfp, node))
	// alloc_masks() :
	// kmem_cache#28-o0.irq_data.affinity의 하위 4비트를 0으로 클리어
	// 0을 반환함
		goto err_kstat;

	raw_spin_lock_init(&desc->lock);
	// 스핀락 초기화
	
	lockdep_set_class(&desc->lock, &irq_desc_lock_class);
	// NULL 함수

	// irq : 0, desc : 할당받은 irq_desc 구조체의 주소, node : 0, owner : NULL
	desc_set_defaults(irq, desc, node, owner);
	// irq_desc 구조체 내부 초기화 작업 수행

	return desc;

err_kstat:
	free_percpu(desc->kstat_irqs);
err_desc:
	kfree(desc);
	return NULL;
}

static void free_desc(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);

	unregister_irq_proc(irq, desc);

	mutex_lock(&sparse_irq_lock);
	delete_irq_desc(irq);
	mutex_unlock(&sparse_irq_lock);

	free_masks(desc);
	free_percpu(desc->kstat_irqs);
	kfree(desc);
}

// start : 16, cnt : 144, node : 0, owner : NULL
static int alloc_descs(unsigned int start, unsigned int cnt, int node,
		       struct module *owner)
{
	struct irq_desc *desc;
	int i;

	// cnt : 144
	for (i = 0; i < cnt; i++) {
		// start : 16, i : 0, node : 0, owner : NULL
		desc = alloc_desc(start + i, node, owner);
		// irq_desc를 할당받고 초기화 작업 수행 후
		// 그 주소를 desc로 반환함

		if (!desc)
			goto err;

		mutex_lock(&sparse_irq_lock);
		// 뮤텍스 락 설정

		// start + i : 16, desc : 위에서 할당 받은 것
		irq_insert_desc(start + i, desc);
		// &irq_desc_tree 트리에 삽입

		mutex_unlock(&sparse_irq_lock);
		// 뮤텍스 락 해제
	}
	return start;
	// 16 반환

err:
	for (i--; i >= 0; i--)
		free_desc(start + i);

	mutex_lock(&sparse_irq_lock);
	bitmap_clear(allocated_irqs, start, cnt);
	mutex_unlock(&sparse_irq_lock);
	return -ENOMEM;
}

// nr : 160
static int irq_expand_nr_irqs(unsigned int nr)
{
	// IRQ_BITMAP_BITS : 8212
	if (nr > IRQ_BITMAP_BITS)
		return -ENOMEM;
	nr_irqs = nr;
	// nr_irqs : 160
	return 0;
}

int __init early_irq_init(void)
{
	// first_online_node : 0
	int i, initcnt, node = first_online_node;
	// node : 0
	
	struct irq_desc *desc;

	init_irq_default_affinity();
	// irq_default_affinity->bits[0] : 0xF
	// 로 설정됨

	/* Let arch update nr_irqs and return the nr of preallocated irqs */
	initcnt = arch_probe_nr_irqs();
	// initcnt : 16
	// machine_desc에 설정되어 있는 값이 있는지 확인한 뒤, 적절한 값을 반환함
	// 현재 타겟용 machine_desc에는 설정된 값이 없었기 때문에 NR_IRQS의 값을 가져옴
	
	printk(KERN_INFO "NR_IRQS:%d nr_irqs:%d %d\n", NR_IRQS, nr_irqs, initcnt);
	// "NR_IRQS:16 nr_irqs:16 16"

	// nr_irqs : 16, IRQ_BITMAP_BITS : 8212
	if (WARN_ON(nr_irqs > IRQ_BITMAP_BITS))
		nr_irqs = IRQ_BITMAP_BITS;
	// 통과

	// initcnt : 16, IRQ_BITMAP_BITS : 8212
	if (WARN_ON(initcnt > IRQ_BITMAP_BITS))
		initcnt = IRQ_BITMAP_BITS;
	// 통과

	// initcnt : 16, nr_irqs : 16
	if (initcnt > nr_irqs)
		nr_irqs = initcnt;
	// 통과

	// initcnt : 16
	for (i = 0; i < initcnt; i++) {
		// i : 0, node : 0
		desc = alloc_desc(i, node, NULL);
		// 새로운 irq_desc를 슬랩에서 할당 받은 뒤,
		// 내부 초기화 작업 수행하고 그 주소를 반환함
		
		set_bit(i, allocated_irqs);
		// allocated_irqs의 0번째 비트를 1로 설정

		// i : 0, desc : 할당받은 irq_desc
		irq_insert_desc(i, desc);
		// irq_desc_tree에 desc를 삽입함
	}
	// 위 동작을 irq 0 ~ irq 15에 대해 수행
	
	return arch_early_irq_init();
	// 항상 0 반환
	// 수행 하는 동작 없음
}

#else /* !CONFIG_SPARSE_IRQ */

struct irq_desc irq_desc[NR_IRQS] __cacheline_aligned_in_smp = {
	[0 ... NR_IRQS-1] = {
		.handle_irq	= handle_bad_irq,
		.depth		= 1,
		.lock		= __RAW_SPIN_LOCK_UNLOCKED(irq_desc->lock),
	}
};

int __init early_irq_init(void)
{
	int count, i, node = first_online_node;
	struct irq_desc *desc;

	init_irq_default_affinity();

	printk(KERN_INFO "NR_IRQS:%d\n", NR_IRQS);

	desc = irq_desc;
	count = ARRAY_SIZE(irq_desc);

	for (i = 0; i < count; i++) {
		desc[i].kstat_irqs = alloc_percpu(unsigned int);
		alloc_masks(&desc[i], GFP_KERNEL, node);
		raw_spin_lock_init(&desc[i].lock);
		lockdep_set_class(&desc[i].lock, &irq_desc_lock_class);
		desc_set_defaults(i, &desc[i], node, NULL);
	}
	return arch_early_irq_init();
}

struct irq_desc *irq_to_desc(unsigned int irq)
{
	return (irq < NR_IRQS) ? irq_desc + irq : NULL;
}
EXPORT_SYMBOL(irq_to_desc);

static void free_desc(unsigned int irq)
{
	dynamic_irq_cleanup(irq);
}

static inline int alloc_descs(unsigned int start, unsigned int cnt, int node,
			      struct module *owner)
{
	u32 i;

	for (i = 0; i < cnt; i++) {
		struct irq_desc *desc = irq_to_desc(start + i);

		desc->owner = owner;
	}
	return start;
}

static int irq_expand_nr_irqs(unsigned int nr)
{
	return -ENOMEM;
}

#endif /* !CONFIG_SPARSE_IRQ */

/**
 * generic_handle_irq - Invoke the handler for a particular irq
 * @irq:	The irq number to handle
 *
 */
int generic_handle_irq(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);

	if (!desc)
		return -EINVAL;
	generic_handle_irq_desc(irq, desc);
	return 0;
}
EXPORT_SYMBOL_GPL(generic_handle_irq);

/* Dynamic interrupt handling */

/**
 * irq_free_descs - free irq descriptors
 * @from:	Start of descriptor range
 * @cnt:	Number of consecutive irqs to free
 */
void irq_free_descs(unsigned int from, unsigned int cnt)
{
	int i;

	if (from >= nr_irqs || (from + cnt) > nr_irqs)
		return;

	for (i = 0; i < cnt; i++)
		free_desc(from + i);

	mutex_lock(&sparse_irq_lock);
	bitmap_clear(allocated_irqs, from, cnt);
	mutex_unlock(&sparse_irq_lock);
}
EXPORT_SYMBOL_GPL(irq_free_descs);

/**
 * irq_alloc_descs - allocate and initialize a range of irq descriptors
 * @irq:	Allocate for specific irq number if irq >= 0
 * @from:	Start the search from this irq number
 * @cnt:	Number of consecutive irqs to allocate.
 * @node:	Preferred node on which the irq descriptor should be allocated
 * @owner:	Owning module (can be NULL)
 *
 * Returns the first irq number or error code
 */
// irq : -1, from : 16, cnt : 144, node : 0, owner : NULL
int __ref
__irq_alloc_descs(int irq, unsigned int from, unsigned int cnt, int node,
		  struct module *owner)
{
	int start, ret;

	// cnt : 144
	if (!cnt)
		return -EINVAL;

	// irq : -1
	if (irq >= 0) {
		if (from > irq)
			return -EINVAL;
		from = irq;
	}

	mutex_lock(&sparse_irq_lock);
	// mutex lock 획득

	// allocated_irqs : 전역 배열, IRQ_BITMAP_BITS : 8212, from : 16, cnt : 144, 0
	start = bitmap_find_next_zero_area(allocated_irqs, IRQ_BITMAP_BITS,
					   from, cnt, 0);
	// allocated_irqs에서 0이 연속으로 설정되어 있는 공간 중 연속 비트 길이가 144가 되는
	// 존재하는 공간을 찾아내 그 곳의 시작 인덱스를 반환함
	// 현재 allocated_irqs는 0~15까지만 1로 설정되어 있으므로 16이 반환됨
	
	ret = -EEXIST;
	// ret : -EEXIST

	// irq : -1, start : 16
	if (irq >=0 && start != irq)
		goto err;

	// start : 16, cnt : 144, nr_irqs : 16
	if (start + cnt > nr_irqs) {
		// start + cnt : 160
		ret = irq_expand_nr_irqs(start + cnt);
		// 전역 변수  nr_irqs 값을 160으로 설정
		// ret : 0
		
		if (ret)
			goto err;
	}

	// start : 16, cnt : 144
	bitmap_set(allocated_irqs, start, cnt);
	// allocated_irqs의 16 ~ 160비트까지 전부 1로 설정
	// 결국 allocated_irqs는 0 ~ 160비트까지 1로 설정된 상태가 됨
	
	mutex_unlock(&sparse_irq_lock);
	// 락 해제
	
	// start : 16, cnt : 144, node : 0, owner : NULL
	return alloc_descs(start, cnt, node, owner);
	// 16부터 144까지 struct irq_desc를 할당받고
	// &irq_desc_tree 트리에 삽입
	// radix_tree 구조로 되어 있음
	// 
	// 16 반환

err:
	mutex_unlock(&sparse_irq_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(__irq_alloc_descs);

/**
 * irq_reserve_irqs - mark irqs allocated
 * @from:	mark from irq number
 * @cnt:	number of irqs to mark
 *
 * Returns 0 on success or an appropriate error code
 */
// from : 16, cnt : 1
int irq_reserve_irqs(unsigned int from, unsigned int cnt)
{
	unsigned int start;
	int ret = 0;

	// nr_irqs : 160
	if (!cnt || (from + cnt) > nr_irqs)
		return -EINVAL;
	// 통과

	mutex_lock(&sparse_irq_lock);
	// 뮤텍스 락 획득
	
	// allocated_irqs : allocate 여부를 기록해 둔 배열,
	// nr_irqs : 160, from : 16, cnt : 1, 0
	start = bitmap_find_next_zero_area(allocated_irqs, nr_irqs, from, cnt, 0);
	// start : 161
	
	// start : 161, from : 16
	if (start == from)
		bitmap_set(allocated_irqs, start, cnt);
	else
		ret = -EEXIST;
		// ret : -EEXIST

	mutex_unlock(&sparse_irq_lock);
	// 뮤텍스 락 해제
	
	return ret;
	// ret : -EEXIST
}

/**
 * irq_get_next_irq - get next allocated irq number
 * @offset:	where to start the search
 *
 * Returns next irq number after offset or nr_irqs if none is found.
 */
unsigned int irq_get_next_irq(unsigned int offset)
{
	return find_next_bit(allocated_irqs, nr_irqs, offset);
}

// [0] irq : 16, flags : &flags, bus : false, check : 0
// [1] irq : 16, flags : &flags, bus : true, check : 0
struct irq_desc *
__irq_get_desc_lock(unsigned int irq, unsigned long *flags, bool bus,
		    unsigned int check)
{
	// [0] irq : 16
	// [1] irq : 16
	struct irq_desc *desc = irq_to_desc(irq);
	// [0] desc : irq_desc(16)
	// [1] desc : irq_desc(16)

	// [0] desc : irq_desc(16)
	// [1] desc : irq_desc(16)
	if (desc) {
		// [0] check : 0, _IRQ_DESC_CHECK : 1
		// [1] check : 0, _IRQ_DESC_CHECK : 1
		if (check & _IRQ_DESC_CHECK) {
			if ((check & _IRQ_DESC_PERCPU) &&
			    !irq_settings_is_per_cpu_devid(desc))
				return NULL;

			if (!(check & _IRQ_DESC_PERCPU) &&
			    irq_settings_is_per_cpu_devid(desc))
				return NULL;
		}
		// [0] 통과
		// [1] 통과

		// [0] bus : false
		// [1] bus : true
		if (bus)
			// [1] desc : irq_desc(16)
			chip_bus_lock(desc);
			// [1] irq_desc.irq_data.chip->irq_bus_lock : NULL
			// [1] 이므로 따로 하는 것이 없음
		// [0] 통과

		raw_spin_lock_irqsave(&desc->lock, *flags);
		// [0] 락 획득
		// [0] cpsr 값이 flags로 저장됨
		// [1] 락 획득
		// [1] cpsr 값이 flags로 저장됨
	}
	return desc;
}

void __irq_put_desc_unlock(struct irq_desc *desc, unsigned long flags, bool bus)
{
	raw_spin_unlock_irqrestore(&desc->lock, flags);
	if (bus)
		chip_bus_sync_unlock(desc);
}

// irq : 16
int irq_set_percpu_devid(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);
	// desc : irq_desc(16)

	if (!desc)
		return -EINVAL;

	if (desc->percpu_enabled)
		return -EINVAL;

	desc->percpu_enabled = kzalloc(sizeof(*desc->percpu_enabled), GFP_KERNEL);
	// desc->percpu_enabled : 4byte 공간을 할당받아 저장
	// 4byte인 이유는 CPU 4개를 위해 4bit가 필요하기 때문임

	if (!desc->percpu_enabled)
		return -ENOMEM;

	// irq : 16
	irq_set_percpu_devid_flags(irq);
	// irq_desc(16).status_use_accessors 값을 set으로 설정
	// irq_desc(16).irq_data.status_use_accessors 값을
	// irq_desc(16).status_use_accessors 값을 이용해 설정해 줌
	return 0;
}

/**
 * dynamic_irq_cleanup - cleanup a dynamically allocated irq
 * @irq:	irq number to initialize
 */
void dynamic_irq_cleanup(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);
	unsigned long flags;

	raw_spin_lock_irqsave(&desc->lock, flags);
	desc_set_defaults(irq, desc, desc_node(desc), NULL);
	raw_spin_unlock_irqrestore(&desc->lock, flags);
}

unsigned int kstat_irqs_cpu(unsigned int irq, int cpu)
{
	struct irq_desc *desc = irq_to_desc(irq);

	return desc && desc->kstat_irqs ?
			*per_cpu_ptr(desc->kstat_irqs, cpu) : 0;
}

unsigned int kstat_irqs(unsigned int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);
	int cpu;
	int sum = 0;

	if (!desc || !desc->kstat_irqs)
		return 0;
	for_each_possible_cpu(cpu)
		sum += *per_cpu_ptr(desc->kstat_irqs, cpu);
	return sum;
}
