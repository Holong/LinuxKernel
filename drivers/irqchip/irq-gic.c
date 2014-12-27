/*
 *  linux/arch/arm/common/gic.c
 *
 *  Copyright (C) 2002 ARM Limited, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Interrupt architecture for the GIC:
 *
 * o There is one Interrupt Distributor, which receives interrupts
 *   from system devices and sends them to the Interrupt Controllers.
 *
 * o There is one CPU Interface per CPU, which sends interrupts sent
 *   by the Distributor, and interrupts generated locally, to the
 *   associated CPU. The base address of the CPU interface is usually
 *   aliased so that the same address points to different chips depending
 *   on the CPU it is accessed from.
 *
 * Note that IRQs 0-31 are special - they are local to each CPU.
 * As such, the enable set/clear, pending set/clear and active bit
 * registers are banked per-cpu for these sources.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/smp.h>
#include <linux/cpu.h>
#include <linux/cpu_pm.h>
#include <linux/cpumask.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/irqdomain.h>
#include <linux/interrupt.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/irqchip/arm-gic.h>

#include <asm/irq.h>
#include <asm/exception.h>
#include <asm/smp_plat.h>

#include "irqchip.h"

union gic_base {
	void __iomem *common_base;
	void __percpu __iomem **percpu_base;
};

struct gic_chip_data {
	union gic_base dist_base;
	union gic_base cpu_base;
#ifdef CONFIG_CPU_PM		// Y
	u32 saved_spi_enable[DIV_ROUND_UP(1020, 32)];
	u32 saved_spi_conf[DIV_ROUND_UP(1020, 16)];
	u32 saved_spi_target[DIV_ROUND_UP(1020, 4)];
	u32 __percpu *saved_ppi_enable;
	u32 __percpu *saved_ppi_conf;
#endif
	struct irq_domain *domain;
	unsigned int gic_irqs;
#ifdef CONFIG_GIC_NON_BANKED	// N
	void __iomem *(*get_base)(union gic_base *);
#endif
};

static DEFINE_RAW_SPINLOCK(irq_controller_lock);

/*
 * The GIC mapping of CPU interfaces does not necessarily match
 * the logical CPU numbering.  Let's use a mapping as returned
 * by the GIC itself.
 */
#define NR_GIC_CPU_IF 8
static u8 gic_cpu_map[NR_GIC_CPU_IF] __read_mostly;

/*
 * Supported arch specific GIC irq extension.
 * Default make them NULL.
 */
struct irq_chip gic_arch_extn = {
	.irq_eoi	= NULL,
	.irq_mask	= NULL,
	.irq_unmask	= NULL,
	.irq_retrigger	= NULL,
	.irq_set_type	= NULL,
	.irq_set_wake	= NULL,
};

#ifndef MAX_GIC_NR
#define MAX_GIC_NR	1
#endif

static struct gic_chip_data gic_data[MAX_GIC_NR] __read_mostly;

#ifdef CONFIG_GIC_NON_BANKED
static void __iomem *gic_get_percpu_base(union gic_base *base)
{
	return *__this_cpu_ptr(base->percpu_base);
}

static void __iomem *gic_get_common_base(union gic_base *base)
{
	return base->common_base;
}

static inline void __iomem *gic_data_dist_base(struct gic_chip_data *data)
{
	return data->get_base(&data->dist_base);
}

static inline void __iomem *gic_data_cpu_base(struct gic_chip_data *data)
{
	return data->get_base(&data->cpu_base);
}

static inline void gic_set_base_accessor(struct gic_chip_data *data,
					 void __iomem *(*f)(union gic_base *))
{
	data->get_base = f;
}
#else
#define gic_data_dist_base(d)	((d)->dist_base.common_base)
#define gic_data_cpu_base(d)	((d)->cpu_base.common_base)
#define gic_set_base_accessor(d, f)
#endif

static inline void __iomem *gic_dist_base(struct irq_data *d)
{
	struct gic_chip_data *gic_data = irq_data_get_irq_chip_data(d);
	return gic_data_dist_base(gic_data);
}

static inline void __iomem *gic_cpu_base(struct irq_data *d)
{
	struct gic_chip_data *gic_data = irq_data_get_irq_chip_data(d);
	return gic_data_cpu_base(gic_data);
}

// d : &irq_desc(32).irq_data
static inline unsigned int gic_irq(struct irq_data *d)
{
	return d->hwirq;
	// irq_desc(32).irq_data.hwirq : 32
}

/*
 * Routines to acknowledge, disable and enable interrupts
 */
static void gic_mask_irq(struct irq_data *d)
{
	u32 mask = 1 << (gic_irq(d) % 32);

	raw_spin_lock(&irq_controller_lock);
	writel_relaxed(mask, gic_dist_base(d) + GIC_DIST_ENABLE_CLEAR + (gic_irq(d) / 32) * 4);
	if (gic_arch_extn.irq_mask)
		gic_arch_extn.irq_mask(d);
	raw_spin_unlock(&irq_controller_lock);
}

// d : &irq_desc(32).irq_data
static void gic_unmask_irq(struct irq_data *d)
{
	// d : &irq_desc(32).irq_data
	// gic_irq(d) : 32
	u32 mask = 1 << (gic_irq(d) % 32);
	// mask : 1

	raw_spin_lock(&irq_controller_lock);
	// 스핀락 획득

	// gic_arch_extn.irq_unmask : NULL
	if (gic_arch_extn.irq_unmask)
		gic_arch_extn.irq_unmask(d);

	// gic_dist_base(d) : 0xF0000000
	// gic_dist_base(d) + GIC_DIST_ENABLE_SET : 0xF0000100
	// gic_dist_base(d) + GIC_DIST_ENABLE_SET + (gic_irq(d) / 32) * 4 : 0xF0000104
	writel_relaxed(mask, gic_dist_base(d) + GIC_DIST_ENABLE_SET + (gic_irq(d) / 32) * 4);
	// 32번 인터럽트 활성화
	
	raw_spin_unlock(&irq_controller_lock);
	// 스핀락 해제
}

static void gic_eoi_irq(struct irq_data *d)
{
	if (gic_arch_extn.irq_eoi) {
		raw_spin_lock(&irq_controller_lock);
		gic_arch_extn.irq_eoi(d);
		raw_spin_unlock(&irq_controller_lock);
	}

	writel_relaxed(gic_irq(d), gic_cpu_base(d) + GIC_CPU_EOI);
}

static int gic_set_type(struct irq_data *d, unsigned int type)
{
	void __iomem *base = gic_dist_base(d);
	unsigned int gicirq = gic_irq(d);
	u32 enablemask = 1 << (gicirq % 32);
	u32 enableoff = (gicirq / 32) * 4;
	u32 confmask = 0x2 << ((gicirq % 16) * 2);
	u32 confoff = (gicirq / 16) * 4;
	bool enabled = false;
	u32 val;

	/* Interrupt configuration for SGIs can't be changed */
	if (gicirq < 16)
		return -EINVAL;

	if (type != IRQ_TYPE_LEVEL_HIGH && type != IRQ_TYPE_EDGE_RISING)
		return -EINVAL;

	raw_spin_lock(&irq_controller_lock);

	if (gic_arch_extn.irq_set_type)
		gic_arch_extn.irq_set_type(d, type);

	val = readl_relaxed(base + GIC_DIST_CONFIG + confoff);
	if (type == IRQ_TYPE_LEVEL_HIGH)
		val &= ~confmask;
	else if (type == IRQ_TYPE_EDGE_RISING)
		val |= confmask;

	/*
	 * As recommended by the spec, disable the interrupt before changing
	 * the configuration
	 */
	if (readl_relaxed(base + GIC_DIST_ENABLE_SET + enableoff) & enablemask) {
		writel_relaxed(enablemask, base + GIC_DIST_ENABLE_CLEAR + enableoff);
		enabled = true;
	}

	writel_relaxed(val, base + GIC_DIST_CONFIG + confoff);

	if (enabled)
		writel_relaxed(enablemask, base + GIC_DIST_ENABLE_SET + enableoff);

	raw_spin_unlock(&irq_controller_lock);

	return 0;
}

static int gic_retrigger(struct irq_data *d)
{
	if (gic_arch_extn.irq_retrigger)
		return gic_arch_extn.irq_retrigger(d);

	/* the genirq layer expects 0 if we can't retrigger in hardware */
	return 0;
}

#ifdef CONFIG_SMP
static int gic_set_affinity(struct irq_data *d, const struct cpumask *mask_val,
			    bool force)
{
	void __iomem *reg = gic_dist_base(d) + GIC_DIST_TARGET + (gic_irq(d) & ~3);
	unsigned int shift = (gic_irq(d) % 4) * 8;
	unsigned int cpu = cpumask_any_and(mask_val, cpu_online_mask);
	u32 val, mask, bit;

	if (cpu >= NR_GIC_CPU_IF || cpu >= nr_cpu_ids)
		return -EINVAL;

	raw_spin_lock(&irq_controller_lock);
	mask = 0xff << shift;
	bit = gic_cpu_map[cpu] << shift;
	val = readl_relaxed(reg) & ~mask;
	writel_relaxed(val | bit, reg);
	raw_spin_unlock(&irq_controller_lock);

	return IRQ_SET_MASK_OK;
}
#endif

#ifdef CONFIG_PM
static int gic_set_wake(struct irq_data *d, unsigned int on)
{
	int ret = -ENXIO;

	if (gic_arch_extn.irq_set_wake)
		ret = gic_arch_extn.irq_set_wake(d, on);

	return ret;
}

#else
#define gic_set_wake	NULL
#endif

// regs.r0 : 인터럽트 발생 할 때의 r0
// regs.r1 : 인터럽트 발생 할 때의 r1
// ...
// regs.r12 : 인터럽트 발생 할 때의 r12
// regs.r13 : sp_svc
// regs.r14 : 인터럽트 발생 할 때의 lr
// regs.r15 : 인터럽트 처리 후 복귀할 주소
// regs.cpsr : 인터럽트 발생 할 때의 cpsr
// regs.orig_r0 : -1
// EINT[15] 때문에 발생한 인터럽트로 가정
static asmlinkage void __exception_irq_entry gic_handle_irq(struct pt_regs *regs)
{
	u32 irqstat, irqnr;
	struct gic_chip_data *gic = &gic_data[0];
	// gic : &gic_data[0]
	void __iomem *cpu_base = gic_data_cpu_base(gic);
	// cpu_base : 0xF0002000

	do {
		irqstat = readl_relaxed(cpu_base + GIC_CPU_INTACK);
		// irqstat : GICC_IAR 값이 저장됨
		
		irqnr = irqstat & ~0x1c00;
		// irqnr : 63
		// EINT[15]의 경우 combiner를 통해 63번 인터럽트로 gic에게 전달됨

		if (likely(irqnr > 15 && irqnr < 1021)) {
			// gic->domain : gic용 irq_domain 주소, irqnr : 63
			irqnr = irq_find_mapping(gic->domain, irqnr);
			// irqnr : 63

			// irqnr : 63, regs : &pt_regs
			handle_IRQ(irqnr, regs);
			continue;
		}
		if (irqnr < 16) {
			writel_relaxed(irqstat, cpu_base + GIC_CPU_EOI);
#ifdef CONFIG_SMP
			handle_IPI(irqnr, regs);
#endif
			continue;
		}
		break;
	} while (1);
}

static void gic_handle_cascade_irq(unsigned int irq, struct irq_desc *desc)
{
	struct gic_chip_data *chip_data = irq_get_handler_data(irq);
	struct irq_chip *chip = irq_get_chip(irq);
	unsigned int cascade_irq, gic_irq;
	unsigned long status;

	chained_irq_enter(chip, desc);

	raw_spin_lock(&irq_controller_lock);
	status = readl_relaxed(gic_data_cpu_base(chip_data) + GIC_CPU_INTACK);
	raw_spin_unlock(&irq_controller_lock);

	gic_irq = (status & 0x3ff);
	if (gic_irq == 1023)
		goto out;

	cascade_irq = irq_find_mapping(chip_data->domain, gic_irq);
	if (unlikely(gic_irq < 32 || gic_irq > 1020))
		handle_bad_irq(cascade_irq, desc);
	else
		generic_handle_irq(cascade_irq);

 out:
	chained_irq_exit(chip, desc);
}

static struct irq_chip gic_chip = {
	.name			= "GIC",
	.irq_mask		= gic_mask_irq,
	.irq_unmask		= gic_unmask_irq,
	.irq_eoi		= gic_eoi_irq,
	.irq_set_type		= gic_set_type,
	.irq_retrigger		= gic_retrigger,
#ifdef CONFIG_SMP
	.irq_set_affinity	= gic_set_affinity,
#endif
	.irq_set_wake		= gic_set_wake,
};

void __init gic_cascade_irq(unsigned int gic_nr, unsigned int irq)
{
	if (gic_nr >= MAX_GIC_NR)
		BUG();
	if (irq_set_handler_data(irq, &gic_data[gic_nr]) != 0)
		BUG();
	irq_set_chained_handler(irq, gic_handle_cascade_irq);
}

// gic : gic_data[0]
static u8 gic_get_cpumask(struct gic_chip_data *gic)
{
	void __iomem *base = gic_data_dist_base(gic);
	// base : 0xF0000000
	
	u32 mask, i;

	for (i = mask = 0; i < 32; i += 4) {
		// GIC_DIST_TARGET : 0x800
		mask = readl_relaxed(base + GIC_DIST_TARGET + i);
		// GICD_ITARGETSR 에서 4바이트를 읽어옴
		// mask : 0x01010101
		// CPU target, byte offset 0 ~ 4까지의 interrupt target을
		// "CPU interface 0"으로 설정

		mask |= mask >> 16;
		// mask : 0x01010101
		mask |= mask >> 8;
		// mask : 0x01010101
		if (mask)
			break;
	}

	// mask : 0x01010101
	if (!mask)
		pr_crit("GIC CPU mask not found - kernel will fail to boot.\n");

	return mask;
}

// gic : &gic_data[0]
static void __init gic_dist_init(struct gic_chip_data *gic)
{
	unsigned int i;
	u32 cpumask;

	// gic->gic_irqs : 160
	unsigned int gic_irqs = gic->gic_irqs;
	// gic_irqs : 160
	
	void __iomem *base = gic_data_dist_base(gic);
	// gic_data[0].dist_base 멤버를 반환함
	// base : 0xF0000000

	// GIC_DIST_CTRL : 0
	writel_relaxed(0, base + GIC_DIST_CTRL);
	// 0을 0xF0000000에 씀
	// GICD_CTLR : 0 으로 초기화

	/*
	 * Set all global interrupts to be level triggered, active low.
	 */
	// gic_irqs : 160
	for (i = 32; i < gic_irqs; i += 16)
		// GIC_DIST_CONFIG : 0xC00
		writel_relaxed(0, base + GIC_DIST_CONFIG + i * 4 / 16);
		// irq 32 ~ irq 159 까지 level-sensitive로 변경

	/*
	 * Set all global interrupts to this CPU only.
	 */
	// gic : gic_data[0]
	cpumask = gic_get_cpumask(gic);
	// cpumask : 0x01010101
	cpumask |= cpumask << 8;
	cpumask |= cpumask << 16;
	// cpumask : 0x01010101
	
	for (i = 32; i < gic_irqs; i += 4)
		writel_relaxed(cpumask, base + GIC_DIST_TARGET + i * 4 / 4);
	// irq 32 ~ 160 까지 GICD_ITARGETSR을 전부 0x01010101로 설정
	// 즉, 모든 irq를 받는 CPU가 0 번 CPU가 되게 됨

	/*
	 * Set priority on all global interrupts.
	 */
	for (i = 32; i < gic_irqs; i += 4)
		writel_relaxed(0xa0a0a0a0, base + GIC_DIST_PRI + i * 4 / 4);
	// irq 32 ~ 160 까지 동일한 priority를 설정해줌

	/*
	 * Disable all interrupts.  Leave the PPI and SGIs alone
	 * as these enables are banked registers.
	 */
	for (i = 32; i < gic_irqs; i += 32)
		writel_relaxed(0xffffffff, base + GIC_DIST_ENABLE_CLEAR + i * 4 / 32);
	// irq 32 ~ 160 까지 전부 disable 시킴

	writel_relaxed(1, base + GIC_DIST_CTRL);
	// gic를 동작하게 만듬
}

// gic : &gic_data[0]
static void gic_cpu_init(struct gic_chip_data *gic)
{
	void __iomem *dist_base = gic_data_dist_base(gic);
	// dist_base : 0xF0000000
	// gic_data.dist_base를 가져옴
	
	void __iomem *base = gic_data_cpu_base(gic);
	// base : 0xF0002000
	// gic_data.cpu_base를 가져옴
	
	unsigned int cpu_mask, cpu = smp_processor_id();
	// cpu : 0
	int i;

	/*
	 * Get what the GIC says our CPU mask is.
	 */
	// NR_GIC_CPU_IF : 8, cpu : 0
	BUG_ON(cpu >= NR_GIC_CPU_IF);
	cpu_mask = gic_get_cpumask(gic);
	// cpu_mask : 0x01010101
	
	// cpu_mask : 0x01010101
	gic_cpu_map[cpu] = cpu_mask;
	// gic_cpu_map[0] : 0x01010101

	/*
	 * Clear our mask from the other map entries in case they're
	 * still undefined.
	 */
	// NR_GIC_CPU_IF : 8
	for (i = 0; i < NR_GIC_CPU_IF; i++)
		if (i != cpu)
			// gic_cpu_map[1] : 0xFF
			gic_cpu_map[i] &= ~cpu_mask;
			// gic_cpu_map[1] : 0xFE
	// gic_cpu_map[1 ~ 7] : 0xFE

	/*
	 * Deal with the banked PPI and SGI interrupts - disable all
	 * PPI interrupts, ensure all SGI interrupts are enabled.
	 */
	
	writel_relaxed(0xffff0000, dist_base + GIC_DIST_ENABLE_CLEAR);
	// irq 16 ~ 31까지 disable
	writel_relaxed(0x0000ffff, dist_base + GIC_DIST_ENABLE_SET);
	// irq 0 ~ 15까지 enable
	
	/*
	 * Set priority on PPI and SGI interrupts
	 */
	for (i = 0; i < 32; i += 4)
		writel_relaxed(0xa0a0a0a0, dist_base + GIC_DIST_PRI + i * 4 / 4);
		// irq 0 ~ irq 31 까지 동일한 priority로 설정

	// base : 0xF0002000
	writel_relaxed(0xf0, base + GIC_CPU_PRIMASK);
	// GIC_PMR을 0xF0으로 설정
	// priority가 0xF0보다 큰 인터럽트만 처리 됨
	writel_relaxed(1, base + GIC_CPU_CTRL);
	// GICC_CTLR을 1로 설정
}

void gic_cpu_if_down(void)
{
	void __iomem *cpu_base = gic_data_cpu_base(&gic_data[0]);
	writel_relaxed(0, cpu_base + GIC_CPU_CTRL);
}

#ifdef CONFIG_CPU_PM	// Y
/*
 * Saves the GIC distributor registers during suspend or idle.  Must be called
 * with interrupts disabled but before powering down the GIC.  After calling
 * this function, no interrupts will be delivered by the GIC, and another
 * platform-specific wakeup source must be enabled.
 */
static void gic_dist_save(unsigned int gic_nr)
{
	unsigned int gic_irqs;
	void __iomem *dist_base;
	int i;

	if (gic_nr >= MAX_GIC_NR)
		BUG();

	gic_irqs = gic_data[gic_nr].gic_irqs;
	dist_base = gic_data_dist_base(&gic_data[gic_nr]);

	if (!dist_base)
		return;

	for (i = 0; i < DIV_ROUND_UP(gic_irqs, 16); i++)
		gic_data[gic_nr].saved_spi_conf[i] =
			readl_relaxed(dist_base + GIC_DIST_CONFIG + i * 4);

	for (i = 0; i < DIV_ROUND_UP(gic_irqs, 4); i++)
		gic_data[gic_nr].saved_spi_target[i] =
			readl_relaxed(dist_base + GIC_DIST_TARGET + i * 4);

	for (i = 0; i < DIV_ROUND_UP(gic_irqs, 32); i++)
		gic_data[gic_nr].saved_spi_enable[i] =
			readl_relaxed(dist_base + GIC_DIST_ENABLE_SET + i * 4);
}

/*
 * Restores the GIC distributor registers during resume or when coming out of
 * idle.  Must be called before enabling interrupts.  If a level interrupt
 * that occured while the GIC was suspended is still present, it will be
 * handled normally, but any edge interrupts that occured will not be seen by
 * the GIC and need to be handled by the platform-specific wakeup source.
 */
static void gic_dist_restore(unsigned int gic_nr)
{
	unsigned int gic_irqs;
	unsigned int i;
	void __iomem *dist_base;

	if (gic_nr >= MAX_GIC_NR)
		BUG();

	gic_irqs = gic_data[gic_nr].gic_irqs;
	dist_base = gic_data_dist_base(&gic_data[gic_nr]);

	if (!dist_base)
		return;

	writel_relaxed(0, dist_base + GIC_DIST_CTRL);

	for (i = 0; i < DIV_ROUND_UP(gic_irqs, 16); i++)
		writel_relaxed(gic_data[gic_nr].saved_spi_conf[i],
			dist_base + GIC_DIST_CONFIG + i * 4);

	for (i = 0; i < DIV_ROUND_UP(gic_irqs, 4); i++)
		writel_relaxed(0xa0a0a0a0,
			dist_base + GIC_DIST_PRI + i * 4);

	for (i = 0; i < DIV_ROUND_UP(gic_irqs, 4); i++)
		writel_relaxed(gic_data[gic_nr].saved_spi_target[i],
			dist_base + GIC_DIST_TARGET + i * 4);

	for (i = 0; i < DIV_ROUND_UP(gic_irqs, 32); i++)
		writel_relaxed(gic_data[gic_nr].saved_spi_enable[i],
			dist_base + GIC_DIST_ENABLE_SET + i * 4);

	writel_relaxed(1, dist_base + GIC_DIST_CTRL);
}

static void gic_cpu_save(unsigned int gic_nr)
{
	int i;
	u32 *ptr;
	void __iomem *dist_base;
	void __iomem *cpu_base;

	if (gic_nr >= MAX_GIC_NR)
		BUG();

	dist_base = gic_data_dist_base(&gic_data[gic_nr]);
	cpu_base = gic_data_cpu_base(&gic_data[gic_nr]);

	if (!dist_base || !cpu_base)
		return;

	ptr = __this_cpu_ptr(gic_data[gic_nr].saved_ppi_enable);
	for (i = 0; i < DIV_ROUND_UP(32, 32); i++)
		ptr[i] = readl_relaxed(dist_base + GIC_DIST_ENABLE_SET + i * 4);

	ptr = __this_cpu_ptr(gic_data[gic_nr].saved_ppi_conf);
	for (i = 0; i < DIV_ROUND_UP(32, 16); i++)
		ptr[i] = readl_relaxed(dist_base + GIC_DIST_CONFIG + i * 4);

}

static void gic_cpu_restore(unsigned int gic_nr)
{
	int i;
	u32 *ptr;
	void __iomem *dist_base;
	void __iomem *cpu_base;

	if (gic_nr >= MAX_GIC_NR)
		BUG();

	dist_base = gic_data_dist_base(&gic_data[gic_nr]);
	cpu_base = gic_data_cpu_base(&gic_data[gic_nr]);

	if (!dist_base || !cpu_base)
		return;

	ptr = __this_cpu_ptr(gic_data[gic_nr].saved_ppi_enable);
	for (i = 0; i < DIV_ROUND_UP(32, 32); i++)
		writel_relaxed(ptr[i], dist_base + GIC_DIST_ENABLE_SET + i * 4);

	ptr = __this_cpu_ptr(gic_data[gic_nr].saved_ppi_conf);
	for (i = 0; i < DIV_ROUND_UP(32, 16); i++)
		writel_relaxed(ptr[i], dist_base + GIC_DIST_CONFIG + i * 4);

	for (i = 0; i < DIV_ROUND_UP(32, 4); i++)
		writel_relaxed(0xa0a0a0a0, dist_base + GIC_DIST_PRI + i * 4);

	writel_relaxed(0xf0, cpu_base + GIC_CPU_PRIMASK);
	writel_relaxed(1, cpu_base + GIC_CPU_CTRL);
}

static int gic_notifier(struct notifier_block *self, unsigned long cmd,	void *v)
{
	int i;

	for (i = 0; i < MAX_GIC_NR; i++) {
#ifdef CONFIG_GIC_NON_BANKED
		/* Skip over unused GICs */
		if (!gic_data[i].get_base)
			continue;
#endif
		switch (cmd) {
		case CPU_PM_ENTER:
			gic_cpu_save(i);
			break;
		case CPU_PM_ENTER_FAILED:
		case CPU_PM_EXIT:
			gic_cpu_restore(i);
			break;
		case CPU_CLUSTER_PM_ENTER:
			gic_dist_save(i);
			break;
		case CPU_CLUSTER_PM_ENTER_FAILED:
		case CPU_CLUSTER_PM_EXIT:
			gic_dist_restore(i);
			break;
		}
	}

	return NOTIFY_OK;
}

static struct notifier_block gic_notifier_block = {
	.notifier_call = gic_notifier,
};

// gic : &gic_data[0]
static void __init gic_pm_init(struct gic_chip_data *gic)
{
	gic->saved_ppi_enable = __alloc_percpu(DIV_ROUND_UP(32, 32) * 4,
		sizeof(u32));
	// gic->saved_ppi_enable : percpu 4byte를 할당받고 그 시작 주소가 저장됨
	BUG_ON(!gic->saved_ppi_enable);

	gic->saved_ppi_conf = __alloc_percpu(DIV_ROUND_UP(32, 16) * 4,
		sizeof(u32));
	// gic->saved_ppi_enable : percpu 8byte를 할당받고 그 시작 주소가 저장됨
	BUG_ON(!gic->saved_ppi_conf);

	// gic : &gic_data[0]
	if (gic == &gic_data[0])
		cpu_pm_register_notifier(&gic_notifier_block);
		// gic_notifier_block을 cpu_pm_notifier_chain에 등록함
}
#else
static void __init gic_pm_init(struct gic_chip_data *gic)
{
}
#endif

#ifdef CONFIG_SMP
void gic_raise_softirq(const struct cpumask *mask, unsigned int irq)
{
	int cpu;
	unsigned long flags, map = 0;

	raw_spin_lock_irqsave(&irq_controller_lock, flags);

	/* Convert our logical CPU mask into a physical one. */
	for_each_cpu(cpu, mask)
		map |= gic_cpu_map[cpu];

	/*
	 * Ensure that stores to Normal memory are visible to the
	 * other CPUs before issuing the IPI.
	 */
	dsb();

	/* this always happens on GIC0 */
	writel_relaxed(map << 16 | irq, gic_data_dist_base(&gic_data[0]) + GIC_DIST_SOFTINT);

	raw_spin_unlock_irqrestore(&irq_controller_lock, flags);
}
#endif

#ifdef CONFIG_BL_SWITCHER
/*
 * gic_send_sgi - send a SGI directly to given CPU interface number
 *
 * cpu_id: the ID for the destination CPU interface
 * irq: the IPI number to send a SGI for
 */
void gic_send_sgi(unsigned int cpu_id, unsigned int irq)
{
	BUG_ON(cpu_id >= NR_GIC_CPU_IF);
	cpu_id = 1 << cpu_id;
	/* this always happens on GIC0 */
	writel_relaxed((cpu_id << 16) | irq, gic_data_dist_base(&gic_data[0]) + GIC_DIST_SOFTINT);
}

/*
 * gic_get_cpu_id - get the CPU interface ID for the specified CPU
 *
 * @cpu: the logical CPU number to get the GIC ID for.
 *
 * Return the CPU interface ID for the given logical CPU number,
 * or -1 if the CPU number is too large or the interface ID is
 * unknown (more than one bit set).
 */
int gic_get_cpu_id(unsigned int cpu)
{
	unsigned int cpu_bit;

	if (cpu >= NR_GIC_CPU_IF)
		return -1;
	cpu_bit = gic_cpu_map[cpu];
	if (cpu_bit & (cpu_bit - 1))
		return -1;
	return __ffs(cpu_bit);
}

/*
 * gic_migrate_target - migrate IRQs to another CPU interface
 *
 * @new_cpu_id: the CPU target ID to migrate IRQs to
 *
 * Migrate all peripheral interrupts with a target matching the current CPU
 * to the interface corresponding to @new_cpu_id.  The CPU interface mapping
 * is also updated.  Targets to other CPU interfaces are unchanged.
 * This must be called with IRQs locally disabled.
 */
void gic_migrate_target(unsigned int new_cpu_id)
{
	unsigned int cur_cpu_id, gic_irqs, gic_nr = 0;
	void __iomem *dist_base;
	int i, ror_val, cpu = smp_processor_id();
	u32 val, cur_target_mask, active_mask;

	if (gic_nr >= MAX_GIC_NR)
		BUG();

	dist_base = gic_data_dist_base(&gic_data[gic_nr]);
	if (!dist_base)
		return;
	gic_irqs = gic_data[gic_nr].gic_irqs;

	cur_cpu_id = __ffs(gic_cpu_map[cpu]);
	cur_target_mask = 0x01010101 << cur_cpu_id;
	ror_val = (cur_cpu_id - new_cpu_id) & 31;

	raw_spin_lock(&irq_controller_lock);

	/* Update the target interface for this logical CPU */
	gic_cpu_map[cpu] = 1 << new_cpu_id;

	/*
	 * Find all the peripheral interrupts targetting the current
	 * CPU interface and migrate them to the new CPU interface.
	 * We skip DIST_TARGET 0 to 7 as they are read-only.
	 */
	for (i = 8; i < DIV_ROUND_UP(gic_irqs, 4); i++) {
		val = readl_relaxed(dist_base + GIC_DIST_TARGET + i * 4);
		active_mask = val & cur_target_mask;
		if (active_mask) {
			val &= ~active_mask;
			val |= ror32(active_mask, ror_val);
			writel_relaxed(val, dist_base + GIC_DIST_TARGET + i*4);
		}
	}

	raw_spin_unlock(&irq_controller_lock);

	/*
	 * Now let's migrate and clear any potential SGIs that might be
	 * pending for us (cur_cpu_id).  Since GIC_DIST_SGI_PENDING_SET
	 * is a banked register, we can only forward the SGI using
	 * GIC_DIST_SOFTINT.  The original SGI source is lost but Linux
	 * doesn't use that information anyway.
	 *
	 * For the same reason we do not adjust SGI source information
	 * for previously sent SGIs by us to other CPUs either.
	 */
	for (i = 0; i < 16; i += 4) {
		int j;
		val = readl_relaxed(dist_base + GIC_DIST_SGI_PENDING_SET + i);
		if (!val)
			continue;
		writel_relaxed(val, dist_base + GIC_DIST_SGI_PENDING_CLEAR + i);
		for (j = i; j < i + 4; j++) {
			if (val & 0xff)
				writel_relaxed((1 << (new_cpu_id + 16)) | j,
						dist_base + GIC_DIST_SOFTINT);
			val >>= 8;
		}
	}
}

/*
 * gic_get_sgir_physaddr - get the physical address for the SGI register
 *
 * REturn the physical address of the SGI register to be used
 * by some early assembly code when the kernel is not yet available.
 */
static unsigned long gic_dist_physaddr;

unsigned long gic_get_sgir_physaddr(void)
{
	if (!gic_dist_physaddr)
		return 0;
	return gic_dist_physaddr + GIC_DIST_SOFTINT;
}

void __init gic_init_physaddr(struct device_node *node)
{
	struct resource res;
	if (of_address_to_resource(node, 0, &res) == 0) {
		gic_dist_physaddr = res.start;
		pr_info("GIC physical location is %#lx\n", gic_dist_physaddr);
	}
}

#else
#define gic_init_physaddr(node)  do { } while (0)
#endif

// d : 이전에 할당받은 domain 주소, irq : 16, hw : 16
static int gic_irq_domain_map(struct irq_domain *d, unsigned int irq,
				irq_hw_number_t hw)
{
	// hw : 16
	if (hw < 32) {
		// irq : 16
		irq_set_percpu_devid(irq);
		// irq 16을 위한 percpu_enabled 공간을 확보
		// irq_desc(16).status_use_accessors 값을
		// IRQ_NOAUTOEN | IRQ_PER_CPU | IRQ_NOTHREAD | IRQ_NOPROBE | IRQ_PER_CPU_DEVID 로 설정
		// irq_desc(16).irq_data.status_use_accessors 값을
		// irq_desc(16).status_use_accessors 값을 이용해 설정해 줌

		// irq : 16, &gic_chip, handle_percpu_devid_irq
		irq_set_chip_and_handler(irq, &gic_chip,
					 handle_percpu_devid_irq);
		// irq_desc(16).irq_data.chip : &gic_chip 로 설정
		// irq_desc(16).handle_irq : handle_percpu_devid_irq
		// irq_desc(16).name : NULL
		
		// irq : 16, IRQF_VALID | IRQF_NOAUTOEN
		set_irq_flags(irq, IRQF_VALID | IRQF_NOAUTOEN);
		// 내부 flag 값 설정
	} else {
		irq_set_chip_and_handler(irq, &gic_chip,
					 handle_fasteoi_irq);
		set_irq_flags(irq, IRQF_VALID | IRQF_PROBE);
	}
	
	// irq : 16, d->host_data : &gic_data[0]
	irq_set_chip_data(irq, d->host_data);
	// irq_desc(16).chip_data : &gic_data[0] 로 설정
	
	return 0;
	// 0 반환
}

// irq_domain : gic용 irq_domain, controller : gic용 노드 주소
// intspec : oirq.args, intsize : 3, out_hwirq : &hwirq, out_type : &type
static int gic_irq_domain_xlate(struct irq_domain *d,
				struct device_node *controller,
				const u32 *intspec, unsigned int intsize,
				unsigned long *out_hwirq, unsigned int *out_type)
{
	// d->of_node : gic용 노드의 주소
	if (d->of_node != controller)
		return -EINVAL;
	// 통과
	
	// intsize : 3
	if (intsize < 3)
		return -EINVAL;
	// 통과

	/* Get the interrupt number and add 16 to skip over SGIs */
	*out_hwirq = intspec[1] + 16;
	// out_hwirq : 16

	/* For SPIs, we need to add 16 more to get the GIC irq ID number */
	// intspec[0] : 0
	if (!intspec[0])
		*out_hwirq += 16;
		// out_hwirq : 32

	// intspec[2] : 0, IRQ_TYPE_SENSE_MASK : 0x0000000f
	*out_type = intspec[2] & IRQ_TYPE_SENSE_MASK;
	// out_type : IRQ_TYPE_NONE

	return 0;
}

#ifdef CONFIG_SMP
static int gic_secondary_init(struct notifier_block *nfb, unsigned long action,
			      void *hcpu)
{
	if (action == CPU_STARTING || action == CPU_STARTING_FROZEN)
		gic_cpu_init(&gic_data[0]);
	return NOTIFY_OK;
}

/*
 * Notifier for enabling the GIC CPU interface. Set an arbitrarily high
 * priority because the GIC needs to be up before the ARM generic timers.
 */
static struct notifier_block gic_cpu_notifier = {
	.notifier_call = gic_secondary_init,
	.priority = 100,
};
#endif

const struct irq_domain_ops gic_irq_domain_ops = {
	.map = gic_irq_domain_map,
	.xlate = gic_irq_domain_xlate,
};

// gic_nr : 0, irq_start : -1, dist_base : 0xF0000000, cpu_base : 0xF0002000
// percpu_offset : 0, node : gic 노드 주소
void __init gic_init_bases(unsigned int gic_nr, int irq_start,
			   void __iomem *dist_base, void __iomem *cpu_base,
			   u32 percpu_offset, struct device_node *node)
{
	irq_hw_number_t hwirq_base;
	// unsigned long 형
	struct gic_chip_data *gic;
	int gic_irqs, irq_base, i;

	// gic_nr : 0, MAX_GIC_NR : 1
	BUG_ON(gic_nr >= MAX_GIC_NR);
	// 통과

	gic = &gic_data[gic_nr];
	// gic : &gic_data[0]
	
#ifdef CONFIG_GIC_NON_BANKED	// N
	if (percpu_offset) { /* Frankein-GIC without banked registers... */
		unsigned int cpu;

		gic->dist_base.percpu_base = alloc_percpu(void __iomem *);
		gic->cpu_base.percpu_base = alloc_percpu(void __iomem *);
		if (WARN_ON(!gic->dist_base.percpu_base ||
			    !gic->cpu_base.percpu_base)) {
			free_percpu(gic->dist_base.percpu_base);
			free_percpu(gic->cpu_base.percpu_base);
			return;
		}

		for_each_possible_cpu(cpu) {
			unsigned long offset = percpu_offset * cpu_logical_map(cpu);
			*per_cpu_ptr(gic->dist_base.percpu_base, cpu) = dist_base + offset;
			*per_cpu_ptr(gic->cpu_base.percpu_base, cpu) = cpu_base + offset;
		}

		gic_set_base_accessor(gic, gic_get_percpu_base);
	} else
#endif	
	{			/* Normal, sane GIC... */
		WARN(percpu_offset,
		     "GIC_NON_BANKED not enabled, ignoring %08x offset!",
		     percpu_offset);
		// 출력 없음

		// gic : &gic_data[0], dist_base : 0xF0000000
		gic->dist_base.common_base = dist_base;
		// gic->dist_base.common_base : 0xF0000000
		
		// gic : &gic_data[0], cpu_base : 0xF0002000
		gic->cpu_base.common_base = cpu_base;
		// gic->cpu_base.common_base : 0xF0002000

		// gic : &gic_data[0], gic_get_common_base : 함수 포인터
		gic_set_base_accessor(gic, gic_get_common_base);
		// NULL 함수
	}

	/*
	 * Initialize the CPU interface map to all CPUs.
	 * It will be refined as each CPU probes its ID.
	 */
	// NR_GIC_CPU_IF : 8 
	for (i = 0; i < NR_GIC_CPU_IF; i++)
		gic_cpu_map[i] = 0xff;
	// gic_cpu_map[0 ~ 7] : 0xFF 로 초기화

	/*
	 * For primary GICs, skip over SGIs.
	 * For secondary GICs, skip over PPIs, too.
	*/
	// gic_nr : 0, irq_start : -1
	// irq_start & 31 : 0x1F
	if (gic_nr == 0 && (irq_start & 31) > 0) {
		hwirq_base = 16;
		// hwirq_base : 16
		
		// irq_start : -1
		if (irq_start != -1)
			irq_start = (irq_start & ~31) + 16;
		// 통과

	} else {
		hwirq_base = 32;
	}

	/*
	 * Find out how many interrupts are supported.
	 * The GIC only supports up to 1020 interrupt sources.
	 */
	// gic : &gic_data[0], gic_data_dist_base(gic) : gic->dist_base.common_base => 0xF0000000,
	// GIC_DIST_CTR : 0x004
	gic_irqs = readl_relaxed(gic_data_dist_base(gic) + GIC_DIST_CTR) & 0x1f;
	// readl_relaxed(0xF0000004) : 0xF0000004에서 값을 읽음
	// 물리 메모리 0x104810004 에서 값을 읽게 됨
	// 0x0000FC24의 하위 5비트가 gic_irqs에 들어가게 됨
	// Up to 160 interrupts, 128 external interrupt lines 
	//
	// gic_irqs : 0x4
	
	// gic_irqs : 4
	gic_irqs = (gic_irqs + 1) * 32;
	// gic_irqs : 160
	// gic가 지원 가능한 인터럽트의 개수
	// 결국 하드웨어에 설정되어 있던 gic가 지원 가능한 인터럽트의 개수를
	// 얻을 수 있게 됨
	
	// gic_irqs : 1020
	if (gic_irqs > 1020)
		gic_irqs = 1020;
	// gic_irqs 가 1020보다 적기 때문에 변경 없음
	
	// gic : &gic_data[0]
	gic->gic_irqs = gic_irqs;
	// gic_data[0].gic_irqs : 160
	// 필드 값 설정

	// hwirq_base = 16
	gic_irqs -= hwirq_base; /* calculate # of irqs to allocate */
	// gic_irqs : 144
	
	// irq_start : -1, 16, gic_irqs : 144, numa_node_id() : 0
	irq_base = irq_alloc_descs(irq_start, 16, gic_irqs, numa_node_id());
	// 16부터 144개의 struct irq_desc를 할당받고
	// &irq_desc_tree 트리에 삽입
	// 추가된 irq 중 첫 번째 번호가 반환됨
	// irq_base : 16 
	
	/*
	 * (&irq_desc_tree)->rnode --> +-----------------------+
	 *                             |    radix_tree_node    |
	 *                             |   (kmem_cache#20-o1)  |
	 *                             +-----------------------+
	 *                             | height: 2 | count: 3  |
	 *                             +-----------------------+
	 *                             | radix_tree_node 0 ~ 2 |
	 *                             +-----------------------+
	 *                            /            |             \
	 *    slot: 0                /   slot: 1   |              \ slot: 2
	 *    +-----------------------+  +-----------------------+  +-----------------------+
	 *    |    radix_tree_node    |  |    radix_tree_node    |  |    radix_tree_node    |
	 *    |   (kmem_cache#20-o0)  |  |   (kmem_cache#20-o2)  |  |   (kmem_cache#20-o3)  |
	 *    +-----------------------+  +-----------------------+  +-----------------------+
	 *    | height: 1 | count: 64 |  | height: 1 | count: 64 |  | height: 1 | count: 32 |
	 *    +-----------------------+  +-----------------------+  +-----------------------+
	 *    |    irq  0 ~ 63        |  |    irq 64 ~ 127       |  |    irq 128 ~ 160      |
	 *    +-----------------------+  +-----------------------+  +-----------------------+
	 */
	

	// irq_base : 16
	if (IS_ERR_VALUE(irq_base)) {
		WARN(1, "Cannot allocate irq_descs @ IRQ%d, assuming pre-allocated\n",
		     irq_start);
		irq_base = irq_start;
	}
	// 통과
	
	// node : gic 노드, gic_irqs : 144, irq_base : 16, hwirq_base : 16
	// gic_irq_domain_ops : 전역 구조체, gic : &gic_data[0]
	gic->domain = irq_domain_add_legacy(node, gic_irqs, irq_base,
				    hwirq_base, &gic_irq_domain_ops, gic);
	// irq 16 ~ 144를 위한 struct irq_domain 을 할당받고 
	// irq_desc(16 ~ 144) 내부 정보를 초기화해 줌
	// 할당받은 irq_domain의 주소가 반환 됨
	
	if (WARN_ON(!gic->domain))
		return;

	// gic_nr : 0
	if (gic_nr == 0) {
#ifdef CONFIG_SMP
		// gic_raise_softirq : 함수 포인터
		set_smp_cross_call(gic_raise_softirq);
		// smp_cross_call : gic_raise_softirq
		// 전역 함수 포인터에 gic_raise_softirq를 대입
		register_cpu_notifier(&gic_cpu_notifier);
		// gic_cpu_notifier 등록
#endif
		// gic_handle_irq : 함수 포인터
		set_handle_irq(gic_handle_irq);
	}

	// gic_arch_extn.flags : 0
	gic_chip.flags |= gic_arch_extn.flags;
	// gic_chip.flags : 0
	
	// gic : &gic_data[0]
	gic_dist_init(gic);
	// irq 32 ~ irq 160 까지 level-sensitive로 변경
	// 모든 irq를 받는 CPU가 0 번 CPU가 되게 됨
	// irq 32 ~ 160 까지 동일한 priority를 설정해줌
	// irq 32 ~ 160 까지 전부 disable 시킴
	// gic를 동작하게 만듬
	
	// gic : &gic_data[0]
	gic_cpu_init(gic);
	// gic_cpu_map[1 ~ 7] : 0xFE
	// irq 16 ~ 31까지 disable
	// irq 0 ~ 15까지 enable
	// irq 0 ~ irq 31 까지 동일한 priority로 설정
	// GIC_PMR을 0xF0로 설정
	// priority가 0xF0보다 큰 인터럽트만 처리 됨
	// GICC_CTLR을 1로 설정
	
	// gic : &gic_data[0]
	gic_pm_init(gic);
	// percpu 공간 할당받음
}

#ifdef CONFIG_OF
static int gic_cnt __initdata;

// node : gic 노드의 주소, parent : NULL
int __init gic_of_init(struct device_node *node, struct device_node *parent)
{
	void __iomem *cpu_base;
	void __iomem *dist_base;
	u32 percpu_offset;
	int irq;

	if (WARN_ON(!node))
		return -ENODEV;
	// 통과

	// node : gic 노드의 주소, 0
	dist_base = of_iomap(node, 0);
	// free_vmap_cache에 새 정보 삽입(rb_tree)
	// vmap_area_list에 새 정보 연결(list)
	// 가상주소와 물리주소 연결을 위한 페이지 테이블 생성
	// 물리 주소 0x10481000 ~ 0x10481FFF을
	// 가상 주소 0xF0000000 ~ 0xF0000FFF로 연결
	// dist_base : 0xF0000000
	// 두 번째 인자에 의해 디바이스 트리 내부의 0번 reg 정보를 이용하게 됨
	
	WARN(!dist_base, "unable to map gic dist registers\n");

	// node : gic 노드의 주소, 1
	cpu_base = of_iomap(node, 1);
	// 가상주소와 물리주소 연결을 위한 페이지 테이블 생성
	// 물리 주소 0x10482000 ~ 0x10482FFF을
	// 가상 주소 0xF0002000 ~ 0xF0002FFF로 연결
	// cpu_base : 0xF0002000
	// 
	// 두 번째 인자에 의해 디바이스 트리 내부의 1번 reg 정보를 이용하게 됨
	
	WARN(!cpu_base, "unable to map gic cpu registers\n");

	if (of_property_read_u32(node, "cpu-offset", &percpu_offset))
		// 디바이스 트리의 gic 노드에 cpu-offset 속성 값을 가져옴
		// 현재는 cpu-offset 속성이 없기 때문에 true가 반환됨
		percpu_offset = 0;
	// percpu_offset : 0

	// gic_cnt : 0, -1, dist_base : 0xF0000000, cpu_base : 0xF0002000
	// percpu_offset : 0, node : gic 노드 주소
	gic_init_bases(gic_cnt, -1, dist_base, cpu_base, percpu_offset, node);
	// gic 하드웨어 초기화 값을 읽은 뒤,
	// 하드웨어에 맞게 struct irq_domain, struct irq_desc들을 만들고 초기화함.
	// 그 뒤, gic 레지스터에 초기화 값을 넣어줌
	// 
	// 현재는 irq 0 ~ 15 enable, 16 ~ 31 disable, 32 ~ 160 disable 상태임
	// priority는 전부 동일함
	// 현재 cpu는 interrupt disable 상태이기 때문에 실제로 처리 되지는 않음

	// gic_cnt : 0
	if (!gic_cnt)
		// node : gic node 주소
		gic_init_physaddr(node);
		// NULL 함수

	// parent : NULL
	if (parent) {
		irq = irq_of_parse_and_map(node, 0);
		gic_cascade_irq(gic_cnt, irq);
	}

	// gic_cnt : 0
	gic_cnt++;
	// gic_cnt : 1
	return 0;
}
IRQCHIP_DECLARE(cortex_a15_gic, "arm,cortex-a15-gic", gic_of_init);
IRQCHIP_DECLARE(cortex_a9_gic, "arm,cortex-a9-gic", gic_of_init);
IRQCHIP_DECLARE(msm_8660_qgic, "qcom,msm-8660-qgic", gic_of_init);
IRQCHIP_DECLARE(msm_qgic2, "qcom,msm-qgic2", gic_of_init);

#endif
