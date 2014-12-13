/*
 * Copyright (c) 2010-2011 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * Combiner irqchip for EXYNOS
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/err.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/irqdomain.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <asm/mach/irq.h>

#include "irqchip.h"

#define COMBINER_ENABLE_SET	0x0
#define COMBINER_ENABLE_CLEAR	0x4
#define COMBINER_INT_STATUS	0xC

#define IRQ_IN_COMBINER		8

static DEFINE_SPINLOCK(irq_controller_lock);

struct combiner_chip_data {
	unsigned int hwirq_offset;
	unsigned int irq_mask;
	void __iomem *base;
	unsigned int parent_irq;
};

static struct irq_domain *combiner_irq_domain;

static inline void __iomem *combiner_base(struct irq_data *data)
{
	struct combiner_chip_data *combiner_data =
		irq_data_get_irq_chip_data(data);

	return combiner_data->base;
}

static void combiner_mask_irq(struct irq_data *data)
{
	u32 mask = 1 << (data->hwirq % 32);

	__raw_writel(mask, combiner_base(data) + COMBINER_ENABLE_CLEAR);
}

static void combiner_unmask_irq(struct irq_data *data)
{
	u32 mask = 1 << (data->hwirq % 32);

	__raw_writel(mask, combiner_base(data) + COMBINER_ENABLE_SET);
}

static void combiner_handle_cascade_irq(unsigned int irq, struct irq_desc *desc)
{
	struct combiner_chip_data *chip_data = irq_get_handler_data(irq);
	struct irq_chip *chip = irq_get_chip(irq);
	unsigned int cascade_irq, combiner_irq;
	unsigned long status;

	chained_irq_enter(chip, desc);

	spin_lock(&irq_controller_lock);
	status = __raw_readl(chip_data->base + COMBINER_INT_STATUS);
	spin_unlock(&irq_controller_lock);
	status &= chip_data->irq_mask;

	if (status == 0)
		goto out;

	combiner_irq = chip_data->hwirq_offset + __ffs(status);
	cascade_irq = irq_find_mapping(combiner_irq_domain, combiner_irq);

	if (unlikely(!cascade_irq))
		do_bad_IRQ(irq, desc);
	else
		generic_handle_irq(cascade_irq);

 out:
	chained_irq_exit(chip, desc);
}

#ifdef CONFIG_SMP
static int combiner_set_affinity(struct irq_data *d,
				 const struct cpumask *mask_val, bool force)
{
	struct combiner_chip_data *chip_data = irq_data_get_irq_chip_data(d);
	struct irq_chip *chip = irq_get_chip(chip_data->parent_irq);
	struct irq_data *data = irq_get_irq_data(chip_data->parent_irq);

	if (chip && chip->irq_set_affinity)
		return chip->irq_set_affinity(data, mask_val, force);
	else
		return -EINVAL;
}
#endif

static struct irq_chip combiner_chip = {
	.name			= "COMBINER",
	.irq_mask		= combiner_mask_irq,
	.irq_unmask		= combiner_unmask_irq,
#ifdef CONFIG_SMP
	.irq_set_affinity	= combiner_set_affinity,
#endif
};

static void __init combiner_cascade_irq(struct combiner_chip_data *combiner_data,
					unsigned int irq)
{
	if (irq_set_handler_data(irq, combiner_data) != 0)
		BUG();
	irq_set_chained_handler(irq, combiner_handle_cascade_irq);
}

// combiner_data : combiner_chip_data[0], combiner_nr : 0,
// base : 0xF0004000, irq : 32
static void __init combiner_init_one(struct combiner_chip_data *combiner_data,
				     unsigned int combiner_nr,
				     void __iomem *base, unsigned int irq)
{
	combiner_data->base = base;
	// combiner_chip_data[0].base : 0xF0004000
	
	// combiner_nr : 0, IRQ_IN_COMBINER : 8
	combiner_data->hwirq_offset = (combiner_nr & ~3) * IRQ_IN_COMBINER;
	// combiner_chip_data[0].hwirq_offset : 0
	
	// combiner_nr : 0
	combiner_data->irq_mask = 0xff << ((combiner_nr % 4) << 3);
	// combiner_chip_data[0].irq_mask : 0xFF
	
	// irq : 32
	combiner_data->parent_irq = irq;
	// combiner_chip_data[0].parent_irq : 32

	/* Disable all interrupts */
	// combiner_chip_data[0].irq_mask : 0xFF, base : 0xF0004000
	// COMBINER_ENABLE_CLEAR : 0x4
	__raw_writel(combiner_data->irq_mask, base + COMBINER_ENABLE_CLEAR);
}

static int combiner_irq_domain_xlate(struct irq_domain *d,
				     struct device_node *controller,
				     const u32 *intspec, unsigned int intsize,
				     unsigned long *out_hwirq,
				     unsigned int *out_type)
{
	if (d->of_node != controller)
		return -EINVAL;

	if (intsize < 2)
		return -EINVAL;

	*out_hwirq = intspec[0] * IRQ_IN_COMBINER + intspec[1];
	*out_type = 0;

	return 0;
}

// d : combiner용 domain 주소, irq : 160, hw : 0
static int combiner_irq_domain_map(struct irq_domain *d, unsigned int irq,
				   irq_hw_number_t hw)
{
	struct combiner_chip_data *combiner_data = d->host_data;
	// combiner_data : 할당받은 combiner_chip_data용 공간의 시작 주소

	// irq : 160, combiner_chip : 전역 변수 주소, handle_level_irq : 함수 포인터
	irq_set_chip_and_handler(irq, &combiner_chip, handle_level_irq);
	// irq_desc(160).irq_data.chip : &combiner_chip 로 설정
	// irq_desc(160).handle_irq : handle_level_irq
	// irq_desc(160).name : NULL
	
	// irq : 160, &combiner_chip_data[0]
	irq_set_chip_data(irq, &combiner_data[hw >> 3]);
	// irq_desc(160).chip_data : &combiner_chip_data[0] 로 설정
	
	// irq : 160, IRQF_VALID | IRQF_PROBE
	set_irq_flags(irq, IRQF_VALID | IRQF_PROBE);
	// irq_desc(160).status_use_accessors을 설정하고, 그 값을 이용해
	// irq_desc(160).irq_data.status_use_accessors 값을 설정

	return 0;
}

static struct irq_domain_ops combiner_irq_domain_ops = {
	.xlate	= combiner_irq_domain_xlate,
	.map	= combiner_irq_domain_map,
};

// combiner_base : 0xF0004000, np : combiner 노드의 주소
// max_nr : 32, irq_base : 160
static void __init combiner_init(void __iomem *combiner_base,
				 struct device_node *np,
				 unsigned int max_nr,
				 int irq_base)
{
	int i, irq;
	unsigned int nr_irq;
	struct combiner_chip_data *combiner_data;

	// max_nr : 32, IRQ_IN_COMBINER : 8
	nr_irq = max_nr * IRQ_IN_COMBINER;
	// nr_irq : 256

	// max_nr : 32, sizeof(combiner_chip_data) : 16, GFP_KERNEL
	combiner_data = kcalloc(max_nr, sizeof (*combiner_data), GFP_KERNEL);
	// combiner_data : 512짜리 object를 새로 할당받음
	// 		   즉, combiner_chip_data가 32개 들어가는 배열 공간이 됨
	
	// combiner_data : 할당받은 공간
	if (!combiner_data) {
		pr_warning("%s: could not allocate combiner data\n", __func__);
		return;
	}
	// 통과

	// np : combiner 노드의 주소, nr_irq : 256, irq_base : 160
	// &combiner_irq_domain_ops, combiner_data : combiner_chip_data용 공간
	combiner_irq_domain = irq_domain_add_simple(np, nr_irq, irq_base,
				&combiner_irq_domain_ops, combiner_data);
	// irq_domain, irq_desc 공간을 만들고 내부 값을 설정하는 작업 수행
	// 만들어진 irq_domain의 주소가 반환됨
	
	if (WARN_ON(!combiner_irq_domain)) {
		pr_warning("%s: irq domain init failed\n", __func__);
		return;
	}

	// max_nr : 32
	for (i = 0; i < max_nr; i++) {
		// np : combiner 노드 주소, i : 0
		irq = irq_of_parse_and_map(np, i);
		// combiner의 interrupts 속성의 i번째 값을 확인한 후
		// 그에 맞는 인터럽트 번호를 반환함
		// irq : 32

		// combiner_data[0], i : 0, combiner_base : 0xF0004000, irq : 32
		combiner_init_one(&combiner_data[i], i,
				  combiner_base + (i >> 2) * 0x10, irq);
		combiner_cascade_irq(&combiner_data[i], irq);
	}
}

// np : combiner 노드의 주소, parent : gic 노드 주소
static int __init combiner_of_init(struct device_node *np,
				   struct device_node *parent)
{
	void __iomem *combiner_base;
	unsigned int max_nr = 20;
	int irq_base = -1;

	// np : combiner 노드의 주소
	combiner_base = of_iomap(np, 0);
 	// free_vmap_cache에 새 정보 삽입(rb_tree)
	// vmap_area_list에 새 정보 연결(list)
	// 가상주소와 물리주소 연결을 위한 페이지 테이블 생성
	// 물리 주소 0x10440000 ~ 0x10440000을
	// 가상 주소 0xF0004000 ~ 0xF0004FFF로 연결
	// combiner_base : 0xF0004000
	//
	// 두 번째 인자에 의해 디바이스 트리 내부의 0번 reg 정보를 이용하게 됨
	
	if (!combiner_base) {
		pr_err("%s: failed to map combiner registers\n", __func__);
		return -ENXIO;
	}

	// np : combiner 노드의 주소, "samsung,combiner-nr", &max_nr
	if (of_property_read_u32(np, "samsung,combiner-nr", &max_nr)) {
		pr_info("%s: number of combiners not specified, "
			"setting default as %d.\n",
			__func__, max_nr);
	}
	// max_nr : 32
	// 디바이스 트리의 combiner 노드에서 samsung,combiner-nr 속성의 값을 가져옴

	/* 
	 * FIXME: This is a hardwired COMBINER_IRQ(0,0). Once all devices
	 * get their IRQ from DT, remove this in order to get dynamic
	 * allocation.
	 */
	irq_base = 160;
	// irq_base : 160

	// combiner_base : 0xF0004000, np : combiner 노드의 주소
	// max_nr : 32, irq_base : 160
	combiner_init(combiner_base, np, max_nr, irq_base);

	return 0;
}
IRQCHIP_DECLARE(exynos4210_combiner, "samsung,exynos4210-combiner",
		combiner_of_init);
