/*
 *  linux/arch/arm/kernel/irq.c
 *
 *  Copyright (C) 1992 Linus Torvalds
 *  Modifications for ARM processor Copyright (C) 1995-2000 Russell King.
 *
 *  Support for Dynamic Tick Timer Copyright (C) 2004-2005 Nokia Corporation.
 *  Dynamic Tick Timer written by Tony Lindgren <tony@atomide.com> and
 *  Tuukka Tikkanen <tuukka.tikkanen@elektrobit.com>.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *  This file contains the code used by various IRQ handling routines:
 *  asking for different IRQ's should be done through these routines
 *  instead of just grabbing them. Thus setups with different IRQ numbers
 *  shouldn't result in any weird surprises, and installing new handlers
 *  should be easier.
 *
 *  IRQ's are in fact implemented a bit like signal handlers for the kernel.
 *  Naturally it's not a 1:1 relation, but there are similarities.
 */
#include <linux/kernel_stat.h>
#include <linux/signal.h>
#include <linux/ioport.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqchip.h>
#include <linux/random.h>
#include <linux/smp.h>
#include <linux/init.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/kallsyms.h>
#include <linux/proc_fs.h>
#include <linux/export.h>

#include <asm/exception.h>
#include <asm/mach/arch.h>
#include <asm/mach/irq.h>
#include <asm/mach/time.h>

unsigned long irq_err_count;

int arch_show_interrupts(struct seq_file *p, int prec)
{
#ifdef CONFIG_FIQ
	show_fiq_list(p, prec);
#endif
#ifdef CONFIG_SMP
	show_ipi_list(p, prec);
#endif
	seq_printf(p, "%*s: %10lu\n", prec, "Err", irq_err_count);
	return 0;
}

/*
 * handle_IRQ handles all hardware IRQ's.  Decoded IRQs should
 * not come via this function.  Instead, they should provide their
 * own 'handler'.  Used by platform code implementing C-based 1st
 * level decoding.
 */
void handle_IRQ(unsigned int irq, struct pt_regs *regs)
{
	struct pt_regs *old_regs = set_irq_regs(regs);

	irq_enter();

	/*
	 * Some hardware gives randomly wrong interrupts.  Rather
	 * than crashing, do something sensible.
	 */
	if (unlikely(irq >= nr_irqs)) {
		if (printk_ratelimit())
			printk(KERN_WARNING "Bad IRQ%u\n", irq);
		ack_bad_irq(irq);
	} else {
		generic_handle_irq(irq);
	}

	irq_exit();
	set_irq_regs(old_regs);
}

/*
 * asm_do_IRQ is the interface to be used from assembly code.
 */
asmlinkage void __exception_irq_entry
asm_do_IRQ(unsigned int irq, struct pt_regs *regs)
{
	handle_IRQ(irq, regs);
}

// [1] irq : 16, iflags : IRQF_VALID | IRQF_NOAUTOEN
// [2] irq : 160, iflags : IRQF_VALID | IRQF_PROBE
void set_irq_flags(unsigned int irq, unsigned int iflags)
{
	unsigned long clr = 0, set = IRQ_NOREQUEST | IRQ_NOPROBE | IRQ_NOAUTOEN;

	// [1] nr_irqs : 160
	// [2] nr_irqs : 416
	if (irq >= nr_irqs) {
		printk(KERN_ERR "Trying to set irq flags for IRQ%d\n", irq);
		return;
	}
	// 통과

	// [1] iflags : IRQF_VALID | IRQF_NOAUTOEN
	// [2] iflags : IRQF_VALID | IRQF_PROBE
	if (iflags & IRQF_VALID)
		clr |= IRQ_NOREQUEST;
	if (iflags & IRQF_PROBE)
		clr |= IRQ_NOPROBE;
	if (!(iflags & IRQF_NOAUTOEN))
		clr |= IRQ_NOAUTOEN;
	// [1] clr : IRQ_NOREQUEST 로 설정됨
	// [2] clr : IRQ_NOREQUEST | IRQ_NOPROBE | IRQ_NOAUTOEN 로 설정됨
	
	/* Order is clear bits in "clr" then set bits in "set" */
	// [1] clr : IRQ_NOREQUEST
	//     set : IRQ_NOREQUEST | IRQ_NOPROBE | IRQ_NOAUTOEN
	// [2] clr : IRQ_NOREQUEST | IRQ_NOPROBE | IRQ_NOAUTOEN
	//     set : IRQ_NOREQUEST | IRQ_NOPROBE | IRQ_NOAUTOEN
	irq_modify_status(irq, clr, set & ~clr);

}
EXPORT_SYMBOL_GPL(set_irq_flags);

void __init init_IRQ(void)
{
	// CONFIG_OF : Y
	// machine_desc : mach-exynos5-dt.c에 선언되어 있음
	// machine_desc->init_irq : NULl
	if (IS_ENABLED(CONFIG_OF) && !machine_desc->init_irq)
		irqchip_init();
		// irq 관련 init 수행
		// gic_of_init, combiner_of_init이 수행됨
	else
		machine_desc->init_irq();
}

#ifdef CONFIG_MULTI_IRQ_HANDLER	// Y
// handle_irq : gic_handle_irq
void __init set_handle_irq(void (*handle_irq)(struct pt_regs *))
{
	if (handle_arch_irq)
		return;

	handle_arch_irq = handle_irq;
}
#endif

#ifdef CONFIG_SPARSE_IRQ
int __init arch_probe_nr_irqs(void)
{
	// machine_desc : mach-exynos5-dt.c에 선언되어 있음
	// machine_desc->nr_irqs는 NULL 상태로 되어 있음
	nr_irqs = machine_desc->nr_irqs ? machine_desc->nr_irqs : NR_IRQS;
	// nr_irqs : 16
	
	return nr_irqs;
}
#endif

#ifdef CONFIG_HOTPLUG_CPU

static bool migrate_one_irq(struct irq_desc *desc)
{
	struct irq_data *d = irq_desc_get_irq_data(desc);
	const struct cpumask *affinity = d->affinity;
	struct irq_chip *c;
	bool ret = false;

	/*
	 * If this is a per-CPU interrupt, or the affinity does not
	 * include this CPU, then we have nothing to do.
	 */
	if (irqd_is_per_cpu(d) || !cpumask_test_cpu(smp_processor_id(), affinity))
		return false;

	if (cpumask_any_and(affinity, cpu_online_mask) >= nr_cpu_ids) {
		affinity = cpu_online_mask;
		ret = true;
	}

	c = irq_data_get_irq_chip(d);
	if (!c->irq_set_affinity)
		pr_debug("IRQ%u: unable to set affinity\n", d->irq);
	else if (c->irq_set_affinity(d, affinity, true) == IRQ_SET_MASK_OK && ret)
		cpumask_copy(d->affinity, affinity);

	return ret;
}

/*
 * The current CPU has been marked offline.  Migrate IRQs off this CPU.
 * If the affinity settings do not allow other CPUs, force them onto any
 * available CPU.
 *
 * Note: we must iterate over all IRQs, whether they have an attached
 * action structure or not, as we need to get chained interrupts too.
 */
void migrate_irqs(void)
{
	unsigned int i;
	struct irq_desc *desc;
	unsigned long flags;

	local_irq_save(flags);

	for_each_irq_desc(i, desc) {
		bool affinity_broken;

		raw_spin_lock(&desc->lock);
		affinity_broken = migrate_one_irq(desc);
		raw_spin_unlock(&desc->lock);

		if (affinity_broken && printk_ratelimit())
			pr_warning("IRQ%u no longer affine to CPU%u\n", i,
				smp_processor_id());
	}

	local_irq_restore(flags);
}
#endif /* CONFIG_HOTPLUG_CPU */
