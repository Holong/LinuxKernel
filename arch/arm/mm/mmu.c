/*
 *  linux/arch/arm/mm/mmu.c
 *
 *  Copyright (C) 1995-2005 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/mman.h>
#include <linux/nodemask.h>
#include <linux/memblock.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/sizes.h>

#include <asm/cp15.h>
#include <asm/cputype.h>
#include <asm/sections.h>
#include <asm/cachetype.h>
#include <asm/setup.h>
#include <asm/smp_plat.h>
#include <asm/tlb.h>
#include <asm/highmem.h>
#include <asm/system_info.h>
#include <asm/traps.h>

#include <asm/mach/arch.h>
#include <asm/mach/map.h>
#include <asm/mach/pci.h>

#include "mm.h"
#include "tcm.h"

/*
 * empty_zero_page is a special page that is used for
 * zero-initialized data and COW.
 */
struct page *empty_zero_page;
EXPORT_SYMBOL(empty_zero_page);

/*
 * The pmd table for the upper-most set of pages.
 */
pmd_t *top_pmd;

#define CPOLICY_UNCACHED	0
#define CPOLICY_BUFFERED	1
#define CPOLICY_WRITETHROUGH	2
#define CPOLICY_WRITEBACK	3
#define CPOLICY_WRITEALLOC	4

static unsigned int cachepolicy __initdata = CPOLICY_WRITEBACK;
static unsigned int ecc_mask __initdata = 0;
pgprot_t pgprot_user;
pgprot_t pgprot_kernel;
pgprot_t pgprot_hyp_device;
pgprot_t pgprot_s2;
pgprot_t pgprot_s2_device;

EXPORT_SYMBOL(pgprot_user);
EXPORT_SYMBOL(pgprot_kernel);

struct cachepolicy {
	const char	policy[16];
	unsigned int	cr_mask;
	pmdval_t	pmd;
	pteval_t	pte;
	pteval_t	pte_s2;
};

#ifdef CONFIG_ARM_LPAE
#define s2_policy(policy)	policy
#else
#define s2_policy(policy)	0
#endif

static struct cachepolicy cache_policies[] __initdata = {
	{
		.policy		= "uncached",
		.cr_mask	= CR_W|CR_C,
		.pmd		= PMD_SECT_UNCACHED,
		.pte		= L_PTE_MT_UNCACHED,
		.pte_s2		= s2_policy(L_PTE_S2_MT_UNCACHED),
	}, {
		.policy		= "buffered",
		.cr_mask	= CR_C,
		.pmd		= PMD_SECT_BUFFERED,
		.pte		= L_PTE_MT_BUFFERABLE,
		.pte_s2		= s2_policy(L_PTE_S2_MT_UNCACHED),
	}, {
		.policy		= "writethrough",
		.cr_mask	= 0,
		.pmd		= PMD_SECT_WT,
		.pte		= L_PTE_MT_WRITETHROUGH,
		.pte_s2		= s2_policy(L_PTE_S2_MT_WRITETHROUGH),
	}, {
		.policy		= "writeback",
		.cr_mask	= 0,
		.pmd		= PMD_SECT_WB,
		.pte		= L_PTE_MT_WRITEBACK,
		.pte_s2		= s2_policy(L_PTE_S2_MT_WRITEBACK),
	}, {
		.policy		= "writealloc",
		.cr_mask	= 0,
		.pmd		= PMD_SECT_WBWA,
		.pte		= L_PTE_MT_WRITEALLOC,
		.pte_s2		= s2_policy(L_PTE_S2_MT_WRITEBACK),
	}
};

#ifdef CONFIG_CPU_CP15
/*
 * These are useful for identifying cache coherency
 * problems by allowing the cache or the cache and
 * writebuffer to be turned off.  (Note: the write
 * buffer should not be on and the cache off).
 */
static int __init early_cachepolicy(char *p)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(cache_policies); i++) {
		int len = strlen(cache_policies[i].policy);

		if (memcmp(p, cache_policies[i].policy, len) == 0) {
			cachepolicy = i;
			cr_alignment &= ~cache_policies[i].cr_mask;
			cr_no_alignment &= ~cache_policies[i].cr_mask;
			break;
		}
	}
	if (i == ARRAY_SIZE(cache_policies))
		printk(KERN_ERR "ERROR: unknown or unsupported cache policy\n");
	/*
	 * This restriction is partly to do with the way we boot; it is
	 * unpredictable to have memory mapped using two different sets of
	 * memory attributes (shared, type, and cache attribs).  We can not
	 * change these attributes once the initial assembly has setup the
	 * page tables.
	 */
	if (cpu_architecture() >= CPU_ARCH_ARMv6) {
		printk(KERN_WARNING "Only cachepolicy=writeback supported on ARMv6 and later\n");
		cachepolicy = CPOLICY_WRITEBACK;
	}
	flush_cache_all();
	set_cr(cr_alignment);
	return 0;
}
early_param("cachepolicy", early_cachepolicy);

static int __init early_nocache(char *__unused)
{
	char *p = "buffered";
	printk(KERN_WARNING "nocache is deprecated; use cachepolicy=%s\n", p);
	early_cachepolicy(p);
	return 0;
}
early_param("nocache", early_nocache);

static int __init early_nowrite(char *__unused)
{
	char *p = "uncached";
	printk(KERN_WARNING "nowb is deprecated; use cachepolicy=%s\n", p);
	early_cachepolicy(p);
	return 0;
}
early_param("nowb", early_nowrite);

#ifndef CONFIG_ARM_LPAE
static int __init early_ecc(char *p)
{
	if (memcmp(p, "on", 2) == 0)
		ecc_mask = PMD_PROTECTION;
	else if (memcmp(p, "off", 3) == 0)
		ecc_mask = 0;
	return 0;
}
early_param("ecc", early_ecc);
#endif

static int __init noalign_setup(char *__unused)
{
	cr_alignment &= ~CR_A;
	cr_no_alignment &= ~CR_A;
	set_cr(cr_alignment);
	return 1;
}
__setup("noalign", noalign_setup);

#ifndef CONFIG_SMP
void adjust_cr(unsigned long mask, unsigned long set)
{
	unsigned long flags;

	mask &= ~CR_A;

	set &= mask;

	local_irq_save(flags);

	cr_no_alignment = (cr_no_alignment & ~mask) | set;
	cr_alignment = (cr_alignment & ~mask) | set;

	set_cr((get_cr() & ~mask) | set);

	local_irq_restore(flags);
}
#endif

#else /* ifdef CONFIG_CPU_CP15 */

static int __init early_cachepolicy(char *p)
{
	pr_warning("cachepolicy kernel parameter not supported without cp15\n");
}
early_param("cachepolicy", early_cachepolicy);

static int __init noalign_setup(char *__unused)
{
	pr_warning("noalign kernel parameter not supported without cp15\n");
}
__setup("noalign", noalign_setup);

#endif /* ifdef CONFIG_CPU_CP15 / else */

#define PROT_PTE_DEVICE		L_PTE_PRESENT|L_PTE_YOUNG|L_PTE_DIRTY|L_PTE_XN
#define PROT_SECT_DEVICE	PMD_TYPE_SECT|PMD_SECT_AP_WRITE

static struct mem_type mem_types[] = {
	[MT_DEVICE] = {		  /* Strongly ordered / ARMv6 shared device */
		.prot_pte	= PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED |
				  L_PTE_SHARED,
		.prot_l1	= PMD_TYPE_TABLE,
		.prot_sect	= PROT_SECT_DEVICE | PMD_SECT_S,
		.domain		= DOMAIN_IO,
	},
	[MT_DEVICE_NONSHARED] = { /* ARMv6 non-shared device */
		.prot_pte	= PROT_PTE_DEVICE | L_PTE_MT_DEV_NONSHARED,
		.prot_l1	= PMD_TYPE_TABLE,
		.prot_sect	= PROT_SECT_DEVICE,
		.domain		= DOMAIN_IO,
	},
	[MT_DEVICE_CACHED] = {	  /* ioremap_cached */
		.prot_pte	= PROT_PTE_DEVICE | L_PTE_MT_DEV_CACHED,
		.prot_l1	= PMD_TYPE_TABLE,
		.prot_sect	= PROT_SECT_DEVICE | PMD_SECT_WB,
		.domain		= DOMAIN_IO,
	},
	[MT_DEVICE_WC] = {	/* ioremap_wc */
		.prot_pte	= PROT_PTE_DEVICE | L_PTE_MT_DEV_WC,
		.prot_l1	= PMD_TYPE_TABLE,
		.prot_sect	= PROT_SECT_DEVICE,
		.domain		= DOMAIN_IO,
	},
	[MT_UNCACHED] = {
		.prot_pte	= PROT_PTE_DEVICE,
		.prot_l1	= PMD_TYPE_TABLE,
		.prot_sect	= PMD_TYPE_SECT | PMD_SECT_XN,
		.domain		= DOMAIN_IO,
	},
	[MT_CACHECLEAN] = {
		.prot_sect = PMD_TYPE_SECT | PMD_SECT_XN,
		.domain    = DOMAIN_KERNEL,
	},
#ifndef CONFIG_ARM_LPAE
	[MT_MINICLEAN] = {
		.prot_sect = PMD_TYPE_SECT | PMD_SECT_XN | PMD_SECT_MINICACHE,
		.domain    = DOMAIN_KERNEL,
	},
#endif
	[MT_LOW_VECTORS] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY |
				L_PTE_RDONLY,
		.prot_l1   = PMD_TYPE_TABLE,
		.domain    = DOMAIN_USER,
	},
	[MT_HIGH_VECTORS] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY |
				L_PTE_USER | L_PTE_RDONLY,
		.prot_l1   = PMD_TYPE_TABLE,
		.domain    = DOMAIN_USER,
	},
	[MT_MEMORY] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY,
		.prot_l1   = PMD_TYPE_TABLE,
		.prot_sect = PMD_TYPE_SECT | PMD_SECT_AP_WRITE,
		.domain    = DOMAIN_KERNEL,
	},
	[MT_ROM] = {
		.prot_sect = PMD_TYPE_SECT,
		.domain    = DOMAIN_KERNEL,
	},
	[MT_MEMORY_NONCACHED] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY |
				L_PTE_MT_BUFFERABLE,
		.prot_l1   = PMD_TYPE_TABLE,
		.prot_sect = PMD_TYPE_SECT | PMD_SECT_AP_WRITE,
		.domain    = DOMAIN_KERNEL,
	},
	[MT_MEMORY_DTCM] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY |
				L_PTE_XN,
		.prot_l1   = PMD_TYPE_TABLE,
		.prot_sect = PMD_TYPE_SECT | PMD_SECT_XN,
		.domain    = DOMAIN_KERNEL,
	},
	[MT_MEMORY_ITCM] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY,
		.prot_l1   = PMD_TYPE_TABLE,
		.domain    = DOMAIN_KERNEL,
	},
	[MT_MEMORY_SO] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY |
				L_PTE_MT_UNCACHED | L_PTE_XN,
		.prot_l1   = PMD_TYPE_TABLE,
		.prot_sect = PMD_TYPE_SECT | PMD_SECT_AP_WRITE | PMD_SECT_S |
				PMD_SECT_UNCACHED | PMD_SECT_XN,
		.domain    = DOMAIN_KERNEL,
	},
	[MT_MEMORY_DMA_READY] = {
		.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY,
		.prot_l1   = PMD_TYPE_TABLE,
		.domain    = DOMAIN_KERNEL,
	},
};

const struct mem_type *get_mem_type(unsigned int type)
{
	return type < ARRAY_SIZE(mem_types) ? &mem_types[type] : NULL;
}
EXPORT_SYMBOL(get_mem_type);

/*
 * Adjust the PMD section entries according to the CPU in use.
 */
static void __init build_mem_type_table(void)
{
	struct cachepolicy *cp;
	unsigned int cr = get_cr();
	pteval_t user_pgprot, kern_pgprot, vecs_pgprot;
	pteval_t hyp_device_pgprot, s2_pgprot, s2_device_pgprot;
	int cpu_arch = cpu_architecture();
	int i;

	if (cpu_arch < CPU_ARCH_ARMv6) {
#if defined(CONFIG_CPU_DCACHE_DISABLE)
		if (cachepolicy > CPOLICY_BUFFERED)
			cachepolicy = CPOLICY_BUFFERED;
#elif defined(CONFIG_CPU_DCACHE_WRITETHROUGH)
		if (cachepolicy > CPOLICY_WRITETHROUGH)
			cachepolicy = CPOLICY_WRITETHROUGH;
#endif
	}
	if (cpu_arch < CPU_ARCH_ARMv5) {
		if (cachepolicy >= CPOLICY_WRITEALLOC)
			cachepolicy = CPOLICY_WRITEBACK;
		ecc_mask = 0;
	}
	if (is_smp())
		cachepolicy = CPOLICY_WRITEALLOC;

	/*
	 * Strip out features not present on earlier architectures.
	 * Pre-ARMv5 CPUs don't have TEX bits.  Pre-ARMv6 CPUs or those
	 * without extended page tables don't have the 'Shared' bit.
	 */
	if (cpu_arch < CPU_ARCH_ARMv5)
		for (i = 0; i < ARRAY_SIZE(mem_types); i++)
			mem_types[i].prot_sect &= ~PMD_SECT_TEX(7);
	if ((cpu_arch < CPU_ARCH_ARMv6 || !(cr & CR_XP)) && !cpu_is_xsc3())
		for (i = 0; i < ARRAY_SIZE(mem_types); i++)
			mem_types[i].prot_sect &= ~PMD_SECT_S;

	/*
	 * ARMv5 and lower, bit 4 must be set for page tables (was: cache
	 * "update-able on write" bit on ARM610).  However, Xscale and
	 * Xscale3 require this bit to be cleared.
	 */
	if (cpu_is_xscale() || cpu_is_xsc3()) {
		for (i = 0; i < ARRAY_SIZE(mem_types); i++) {
			mem_types[i].prot_sect &= ~PMD_BIT4;
			mem_types[i].prot_l1 &= ~PMD_BIT4;
		}
	} else if (cpu_arch < CPU_ARCH_ARMv6) {
		for (i = 0; i < ARRAY_SIZE(mem_types); i++) {
			if (mem_types[i].prot_l1)
				mem_types[i].prot_l1 |= PMD_BIT4;
			if (mem_types[i].prot_sect)
				mem_types[i].prot_sect |= PMD_BIT4;
		}
	}

	/*
	 * Mark the device areas according to the CPU/architecture.
	 */
	if (cpu_is_xsc3() || (cpu_arch >= CPU_ARCH_ARMv6 && (cr & CR_XP))) {
		if (!cpu_is_xsc3()) {
			/*
			 * Mark device regions on ARMv6+ as execute-never
			 * to prevent speculative instruction fetches.
			 */
			mem_types[MT_DEVICE].prot_sect |= PMD_SECT_XN;
			mem_types[MT_DEVICE_NONSHARED].prot_sect |= PMD_SECT_XN;
			mem_types[MT_DEVICE_CACHED].prot_sect |= PMD_SECT_XN;
			mem_types[MT_DEVICE_WC].prot_sect |= PMD_SECT_XN;
		}
		if (cpu_arch >= CPU_ARCH_ARMv7 && (cr & CR_TRE)) {
			/*
			 * For ARMv7 with TEX remapping,
			 * - shared device is SXCB=1100
			 * - nonshared device is SXCB=0100
			 * - write combine device mem is SXCB=0001
			 * (Uncached Normal memory)
			 */
			mem_types[MT_DEVICE].prot_sect |= PMD_SECT_TEX(1);
			mem_types[MT_DEVICE_NONSHARED].prot_sect |= PMD_SECT_TEX(1);
			mem_types[MT_DEVICE_WC].prot_sect |= PMD_SECT_BUFFERABLE;
		} else if (cpu_is_xsc3()) {
			/*
			 * For Xscale3,
			 * - shared device is TEXCB=00101
			 * - nonshared device is TEXCB=01000
			 * - write combine device mem is TEXCB=00100
			 * (Inner/Outer Uncacheable in xsc3 parlance)
			 */
			mem_types[MT_DEVICE].prot_sect |= PMD_SECT_TEX(1) | PMD_SECT_BUFFERED;
			mem_types[MT_DEVICE_NONSHARED].prot_sect |= PMD_SECT_TEX(2);
			mem_types[MT_DEVICE_WC].prot_sect |= PMD_SECT_TEX(1);
		} else {
			/*
			 * For ARMv6 and ARMv7 without TEX remapping,
			 * - shared device is TEXCB=00001
			 * - nonshared device is TEXCB=01000
			 * - write combine device mem is TEXCB=00100
			 * (Uncached Normal in ARMv6 parlance).
			 */
			mem_types[MT_DEVICE].prot_sect |= PMD_SECT_BUFFERED;
			mem_types[MT_DEVICE_NONSHARED].prot_sect |= PMD_SECT_TEX(2);
			mem_types[MT_DEVICE_WC].prot_sect |= PMD_SECT_TEX(1);
		}
	} else {
		/*
		 * On others, write combining is "Uncached/Buffered"
		 */
		mem_types[MT_DEVICE_WC].prot_sect |= PMD_SECT_BUFFERABLE;
	}

	/*
	 * Now deal with the memory-type mappings
	 */
	cp = &cache_policies[cachepolicy];
	vecs_pgprot = kern_pgprot = user_pgprot = cp->pte;
	s2_pgprot = cp->pte_s2;
	hyp_device_pgprot = s2_device_pgprot = mem_types[MT_DEVICE].prot_pte;

	/*
	 * ARMv6 and above have extended page tables.
	 */
	if (cpu_arch >= CPU_ARCH_ARMv6 && (cr & CR_XP)) {
#ifndef CONFIG_ARM_LPAE
		/*
		 * Mark cache clean areas and XIP ROM read only
		 * from SVC mode and no access from userspace.
		 */
		mem_types[MT_ROM].prot_sect |= PMD_SECT_APX|PMD_SECT_AP_WRITE;
		mem_types[MT_MINICLEAN].prot_sect |= PMD_SECT_APX|PMD_SECT_AP_WRITE;
		mem_types[MT_CACHECLEAN].prot_sect |= PMD_SECT_APX|PMD_SECT_AP_WRITE;
#endif

		if (is_smp()) {
			/*
			 * Mark memory with the "shared" attribute
			 * for SMP systems
			 */
			user_pgprot |= L_PTE_SHARED;
			kern_pgprot |= L_PTE_SHARED;
			vecs_pgprot |= L_PTE_SHARED;
			s2_pgprot |= L_PTE_SHARED;
			mem_types[MT_DEVICE_WC].prot_sect |= PMD_SECT_S;
			mem_types[MT_DEVICE_WC].prot_pte |= L_PTE_SHARED;
			mem_types[MT_DEVICE_CACHED].prot_sect |= PMD_SECT_S;
			mem_types[MT_DEVICE_CACHED].prot_pte |= L_PTE_SHARED;
			mem_types[MT_MEMORY].prot_sect |= PMD_SECT_S;
			mem_types[MT_MEMORY].prot_pte |= L_PTE_SHARED;
			mem_types[MT_MEMORY_DMA_READY].prot_pte |= L_PTE_SHARED;
			mem_types[MT_MEMORY_NONCACHED].prot_sect |= PMD_SECT_S;
			mem_types[MT_MEMORY_NONCACHED].prot_pte |= L_PTE_SHARED;
		}
	}

	/*
	 * Non-cacheable Normal - intended for memory areas that must
	 * not cause dirty cache line writebacks when used
	 */
	if (cpu_arch >= CPU_ARCH_ARMv6) {
		if (cpu_arch >= CPU_ARCH_ARMv7 && (cr & CR_TRE)) {
			/* Non-cacheable Normal is XCB = 001 */
			mem_types[MT_MEMORY_NONCACHED].prot_sect |=
				PMD_SECT_BUFFERED;
		} else {
			/* For both ARMv6 and non-TEX-remapping ARMv7 */
			mem_types[MT_MEMORY_NONCACHED].prot_sect |=
				PMD_SECT_TEX(1);
		}
	} else {
		mem_types[MT_MEMORY_NONCACHED].prot_sect |= PMD_SECT_BUFFERABLE;
	}

#ifdef CONFIG_ARM_LPAE
	/*
	 * Do not generate access flag faults for the kernel mappings.
	 */
	for (i = 0; i < ARRAY_SIZE(mem_types); i++) {
		mem_types[i].prot_pte |= PTE_EXT_AF;
		if (mem_types[i].prot_sect)
			mem_types[i].prot_sect |= PMD_SECT_AF;
	}
	kern_pgprot |= PTE_EXT_AF;
	vecs_pgprot |= PTE_EXT_AF;
#endif

	for (i = 0; i < 16; i++) {
		pteval_t v = pgprot_val(protection_map[i]);
		protection_map[i] = __pgprot(v | user_pgprot);
	}

	mem_types[MT_LOW_VECTORS].prot_pte |= vecs_pgprot;
	mem_types[MT_HIGH_VECTORS].prot_pte |= vecs_pgprot;

	// pgprot_user >> u32 전역변수
	// user_pgprot |= L_PTE_SHARED 로 위에서 세팅 됨.
	// #define __pgprot(x)	(x) 로 정의 되어 있음.
	pgprot_user   = __pgprot(L_PTE_PRESENT | L_PTE_YOUNG | user_pgprot);

	// pgprot_kernel >> u32 전역변수
	// kern_pgprot = cp->pte | L_PTE_SHARED   (cp->pte : L_PTE_MT_WRITEALLOC)
	pgprot_kernel = __pgprot(L_PTE_PRESENT | L_PTE_YOUNG |
				 L_PTE_DIRTY | kern_pgprot);

	// pgprot_s2 >> u32 전역변수
	// s2_pgprot = L_PTE_SHARED
	pgprot_s2  = __pgprot(L_PTE_PRESENT | L_PTE_YOUNG | s2_pgprot);

	// s2_device_pgprot = PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED
	pgprot_s2_device  = __pgprot(s2_device_pgprot);
	// hyp_device_pgprot = PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED
	pgprot_hyp_device  = __pgprot(hyp_device_pgprot);

	// ecc_mask >> unsigned static int 이며 0 으로 되어 있음.
	// 그러므로 prot_l1 값은 그대로 유지됨.
	// .prot_l1   = PMD_TYPE_TABLE
	mem_types[MT_LOW_VECTORS].prot_l1 |= ecc_mask;
	mem_types[MT_HIGH_VECTORS].prot_l1 |= ecc_mask;

	// cp : struct cachepolicy *
	// cp = &cache_policies[cachepolicy];
	// cp->pmd : PMD_SECT_WBWA
	// PMD_SECT_WBWA : (PMD_SECT_TEX(1) | PMD_SECT_CACHEABLE | PMD_SECT_BUFFERABLE)
	mem_types[MT_MEMORY].prot_sect |= ecc_mask | cp->pmd;

	// kern_pgprot = cp->pte | L_PTE_SHARED   (cp->pte : L_PTE_MT_WRITEALLOC)
	mem_types[MT_MEMORY].prot_pte |= kern_pgprot;

	// kern_pgprot = cp->pte | L_PTE_SHARED   (cp->pte : L_PTE_MT_WRITEALLOC)
	mem_types[MT_MEMORY_DMA_READY].prot_pte |= kern_pgprot;
	mem_types[MT_MEMORY_NONCACHED].prot_sect |= ecc_mask;
	mem_types[MT_ROM].prot_sect |= cp->pmd;

	// 위에서 저장해 주는 값은 각 메모리 영역의 특성을 지정해 주는 방법임.
	// 위의 방법은 아키텍쳐 구조에 따라 달라지며 현재는 ARMv7 Cortex A-15에 해당하는 값임.
	// 아키텍쳐의 구조에 따라 바뀔 수 있으며 차후 하드웨어 지원이나 기술 발전에 따라 달라 질 수 있음.
	// 그러므로 여기서 중요한 점은 메모리 별로 특성을 달리 주는 부분이 필요한다는 것을 이해하는 것임.

	// cp->pmd : PMD_SECT_WBWA
	switch (cp->pmd) {
	case PMD_SECT_WT:
		mem_types[MT_CACHECLEAN].prot_sect |= PMD_SECT_WT;
		break;
	case PMD_SECT_WB:
	case PMD_SECT_WBWA: // 이 쪽으로 들어감.
		mem_types[MT_CACHECLEAN].prot_sect |= PMD_SECT_WB;
		break;
	}
	printk("Memory policy: ECC %sabled, Data cache %s\n",
		ecc_mask ? "en" : "dis", cp->policy);
	// cp->policy= "writealloc"
	// 출력되는 값
	// "Memory policy: ECC disabled, Data cache writealloc"
	
	for (i = 0; i < ARRAY_SIZE(mem_types); i++) {
		struct mem_type *t = &mem_types[i];
		if (t->prot_l1)
			t->prot_l1 |= PMD_DOMAIN(t->domain);
		if (t->prot_sect)
			t->prot_sect |= PMD_DOMAIN(t->domain);
	}	

	// ARRAY_SIZE(mem_types) : 15 개
	//
	// 각 메모리 타입의 prot_l1, prot_sect 에 PMD_DOMAIN(t->domain) OR 연산을 통해 저장함.
	// ARM 아키텍쳐의 도메인 특성에 대한 설정을 해 주는 것으로 생각됨.
	// page table 메모리 구조의 DOMAIN 영역은 [8:5] 비트임.
	// PMD_DOMAIN을 통해 5비트 쉬프트를 시킴으로써 이 영역의 값을 저장해 줌.
	//
	//	#define DOMAIN_KERNEL	0
	//	#define DOMAIN_TABLE	0
	//	#define DOMAIN_USER	1
	//	#define DOMAIN_IO	2
	//
	// 위의 값을 밀어 넣음
	
}

#ifdef CONFIG_ARM_DMA_MEM_BUFFERABLE
pgprot_t phys_mem_access_prot(struct file *file, unsigned long pfn,
			      unsigned long size, pgprot_t vma_prot)
{
	if (!pfn_valid(pfn))
		return pgprot_noncached(vma_prot);
	else if (file->f_flags & O_SYNC)
		return pgprot_writecombine(vma_prot);
	return vma_prot;
}
EXPORT_SYMBOL(phys_mem_access_prot);
#endif

#define vectors_base()	(vectors_high() ? 0xffff0000 : 0)
// 각 값 둘 다 8K
static void __init *early_alloc_aligned(unsigned long sz, unsigned long align)
{
	void *ptr = __va(memblock_alloc(sz, align));
	// size 만큼의 reserve 되지 않은 영역에 대한 주소를 가져 옴.
	memset(ptr, 0, sz);
	// 전부 0으로 초기화
	return ptr;
}

static void __init *early_alloc(unsigned long sz)
{
	return early_alloc_aligned(sz, sz);
}

// pmd: 0xC0007FF9, addr: 0xffff0000, prot : type->prot_l1
// pmd :            addr : 0xBFE00000, prot: 0x11
static pte_t * __init early_pte_alloc(pmd_t *pmd, unsigned long addr, unsigned long prot)
{
	if (pmd_none(*pmd)) {	// pmd가 가리키는 장소 : page table을 저장할 곳
				// 그 곳에 이전에 만들어 둔 자료 구조가 있으면 수행 안됨
				// 즉, 이전에 이 곳을 위한 2차 페이지 테이블을 만들어 두었으면 다시 잡을 필요가 없다는 뜻임.
				// 만약 이전에 만들어 둔 구조가 없다면 2차 페이지 테이블도 없다는 뜻이므로
				// 이를 위한 공간을 lowmem 영역에 만들어야 함.
		pte_t *pte = early_alloc(PTE_HWTABLE_OFF + PTE_HWTABLE_SIZE);
		// PTE_HWTABLE_OFF: 2048, PTE_HWTABLE_SIZE: 2048
		// pte: 0xEF7FD000
		// 4KB 만큼 reserved 공간을 확보
		// 4KB인 이유는 Section 2개로 짝을 만들어 메모리 관리를 하기 때문임.
		// 즉 pte 테이블 2개를 만들고 있음
		__pmd_populate(pmd, __pa(pte), prot);
		// page table 에 pte 테이블 시작 주소와 속성을 설정해 줌.
	}
	BUG_ON(pmd_bad(*pmd));
	// 버그 존재 여부 확인
	return pte_offset_kernel(pmd, addr);
	// small page의 위치 주소를 뽑아냄 (2차 테이블 내의 자료 주소 값)
}

// pmd: 0xc0007FF8, addr: 0xffff0000, next: 0xffff1000, __phys_to_pfn(phys): 0x6F7FE
static void __init alloc_init_pte(pmd_t *pmd, unsigned long addr,
				  unsigned long end, unsigned long pfn,
				  const struct mem_type *type)
{
	// pmd : page table을 저장할 위치
	// addr : 매핑할 가상 메모리 주소
	// end : 가상 메모리 주소의 마지막
	// pfn : 물리 페이지 프레임 번호 (즉 물리 주소를 뽑을 수 있음)
	pte_t *pte = early_pte_alloc(pmd, addr, type->prot_l1);
	do {
		set_pte_ext(pte, pfn_pte(pfn, __pgprot(type->prot_pte)), 0);
		pfn++;
	} while (pte++, addr += PAGE_SIZE, addr != end);
}

// pmd : 0xC0007000, addr : 0xC0000000, end : 0xC0200000, phys : 0x40000000
static void __init __map_init_section(pmd_t *pmd, unsigned long addr,
			unsigned long end, phys_addr_t phys,
			const struct mem_type *type)
{
	pmd_t *p = pmd;

#ifndef CONFIG_ARM_LPAE
	/*
	 * In classic MMU format, puds and pmds are folded in to
	 * the pgds. pmd_offset gives the PGD entry. PGDs refer to a
	 * group of L1 entries making up one logical pointer to
	 * an L2 table (2MB), where as PMDs refer to the individual
	 * L1 entries (1MB). Hence increment to get the correct
	 * offset for odd 1MB sections.
	 * (See arch/arm/include/asm/pgtable-2level.h)
	 */
	if (addr & SECTION_SIZE)		// 만약 홀수 1MB를 할당하려고 하면 현재 pmd는 건너뛰고 다음 pmd를 설정
		pmd++;
#endif
	do {
		// pmd : 0xC0007000 >> section entry 주소
		// phys : 0x40000000, type->prot_sect : 메모리 타입의 속성
		*pmd = __pmd(phys | type->prot_sect);
		// section entry에 적합한 데이터를 만들어 줌
		phys += SECTION_SIZE; // phys 를 1MB씩 올림
	} while (pmd++, addr += SECTION_SIZE, addr != end); // 2번 돔

	flush_pmd_entry(p);
}

static void __init alloc_init_pmd(pud_t *pud, unsigned long addr,
				      unsigned long end, phys_addr_t phys,
				      const struct mem_type *type)
{
	pmd_t *pmd = pmd_offset(pud, addr);
	// pud를 그대로 pmd에 대입
	// pmd : 4byte형 포인터
	unsigned long next;

	do {
		/*
		 * With LPAE, we must loop over to map
		 * all the pmds for the given range.
		 */
		next = pmd_addr_end(addr, end);
		// addr을 그대로 next로 대입

		/*
		 * Try a section mapping - addr, next and phys must all be
		 * aligned to a section boundary.
		 */
		if (type->prot_sect &&
				((addr | next | phys) & ~SECTION_MASK) == 0) {
			// 위 조건에서는 addr, next, phys 하위 1MB 부분에 어떤 값이 쓰여 있는지 확인하고 있음.
			// 만약 어떤 값이 쓰여 있으면 pte로 뛰고 아니면 section으로 감.
			__map_init_section(pmd, addr, next, phys, type);
		} else {
			// pmd: 0xc0007FF8, addr: 0xffff0000, next: 0xffff1000, __phys_to_pfn(phys): 0x6F7FE
			alloc_init_pte(pmd, addr, next,
						__phys_to_pfn(phys), type);
			// 하위 1MB 부분에 값이 있다면 1MB 이하의 크기로 메모리 관리를 하겠다는 뜻임.
			// 그러므로 section이 아닌 small page를 이용하여 관리하여야 함 (2-Level trans)
			// 그러므로 page table 값과 small page용 구조를 따로 만들어야 함.
			// small page는 4KB씩 관리할 수 있음
		}
		phys += next - addr;
		// next : 0xC0200000
		// addr : 0xC0000000
		// phys += 2MB
		// 바로 탈출
	} while (pmd++, addr = next, addr != end);
}

static void __init alloc_init_pud(pgd_t *pgd, unsigned long addr,
				  unsigned long end, phys_addr_t phys,
				  const struct mem_type *type)
{
	pud_t *pud = pud_offset(pgd, addr);
	// 아무 것도 하지 않음
	unsigned long next;

	do {
		next = pud_addr_end(addr, end);
		// pgd, addr, end, phys, type 으로 그대로 들어감
		alloc_init_pmd(pud, addr, next, phys, type);
		phys += next - addr;
	} while (pud++, addr = next, addr != end);

	// 결국 이 함수는 pgd >> pud, end >> next로 그대로 대입한 뒤
	// alloc_init_pmd를 호출하고 끝냄.
	// 내부 do while문은 아무 역할도 하지 않음
	// 아마 LPAE 방식을 쓸 때 사용할 것으로 생각됨
}

#ifndef CONFIG_ARM_LPAE
static void __init create_36bit_mapping(struct map_desc *md,
					const struct mem_type *type)
{
	unsigned long addr, length, end;
	phys_addr_t phys;
	pgd_t *pgd;

	addr = md->virtual;
	phys = __pfn_to_phys(md->pfn);
	length = PAGE_ALIGN(md->length);

	if (!(cpu_architecture() >= CPU_ARCH_ARMv6 || cpu_is_xsc3())) {
		printk(KERN_ERR "MM: CPU does not support supersection "
		       "mapping for 0x%08llx at 0x%08lx\n",
		       (long long)__pfn_to_phys((u64)md->pfn), addr);
		return;
	}

	/* N.B.	ARMv6 supersections are only defined to work with domain 0.
	 *	Since domain assignments can in fact be arbitrary, the
	 *	'domain == 0' check below is required to insure that ARMv6
	 *	supersections are only allocated for domain 0 regardless
	 *	of the actual domain assignments in use.
	 */
	if (type->domain) {
		printk(KERN_ERR "MM: invalid domain in supersection "
		       "mapping for 0x%08llx at 0x%08lx\n",
		       (long long)__pfn_to_phys((u64)md->pfn), addr);
		return;
	}

	if ((addr | length | __pfn_to_phys(md->pfn)) & ~SUPERSECTION_MASK) {
		printk(KERN_ERR "MM: cannot create mapping for 0x%08llx"
		       " at 0x%08lx invalid alignment\n",
		       (long long)__pfn_to_phys((u64)md->pfn), addr);
		return;
	}

	/*
	 * Shift bits [35:32] of address into bits [23:20] of PMD
	 * (See ARMv6 spec).
	 */
	phys |= (((md->pfn >> (32 - PAGE_SHIFT)) & 0xF) << 20);

	pgd = pgd_offset_k(addr);
	end = addr + length;
	do {
		pud_t *pud = pud_offset(pgd, addr);
		pmd_t *pmd = pmd_offset(pud, addr);
		int i;

		for (i = 0; i < 16; i++)
			*pmd++ = __pmd(phys | type->prot_sect | PMD_SECT_SUPER);

		addr += SUPERSECTION_SIZE;
		phys += SUPERSECTION_SIZE;
		pgd += SUPERSECTION_SIZE >> PGDIR_SHIFT;
	} while (addr != end);
}
#endif	/* !CONFIG_ARM_LPAE */

/*
 * Create the page directory entries and any necessary
 * page tables for the mapping specified by `md'.  We
 * are able to cope here with varying sizes and address
 * offsets, and we take full advantage of sections and
 * supersections.
 */
// 2MB 할당으로 넘어온 경우
// map.pfn: 0x40000
// map.virtual: 0xC0000000
// map.length: 0x2f800000
// map.type: MT_MEMORY

// 4KB 할당으로 넘어온 경우(vector)
// map.pfn: 0x6F7FE
// map.virtual: 0xffff0000;
// map.length: 0x1000, PAGE_SIZE: 0x1000
// map.type = MT_HIGH_VECTORS;
static void __init create_mapping(struct map_desc *md)
{
	unsigned long addr, length, end;	// addr : 매핑할 가상 메모리 주소
						// length : 가상 메모리 길이 (물리 메모리 길이와 동일)
						// end : 가상 메모리 마지막 주소
	phys_addr_t phys;			// phys : 매핑할 물리 주소의 시작
	const struct mem_type *type;		// type : 메모리의 옵션값
	pgd_t *pgd;				// pgd(section)의 주소 위치

	// md->virtual = 0xC0000000 vectors_base : 0xffff0000 , TASK_SIZE : 0xBF000000
	// lowmem을 매핑할 가상 메모리의 시작 주소가 USER SPACE를 침범하는 지 확인
	if (md->virtual != vectors_base() && md->virtual < TASK_SIZE) {
		printk(KERN_WARNING "BUG: not creating mapping for 0x%08llx"
		       " at 0x%08lx in user region\n",
		       (long long)__pfn_to_phys((u64)md->pfn), md->virtual);
		return;
	}
	
	// md->type : MD_MEMORY
	if ((md->type == MT_DEVICE || md->type == MT_ROM) &&
	    md->virtual >= PAGE_OFFSET &&
	    (md->virtual < VMALLOC_START || md->virtual >= VMALLOC_END)) {
		printk(KERN_WARNING "BUG: mapping for 0x%08llx"
		       " at 0x%08lx out of vmalloc space\n",
		       (long long)__pfn_to_phys((u64)md->pfn), md->virtual);
	}

	type = &mem_types[md->type];
	
	//[MT_MEMORY] = {
	//	.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY,
	//	.prot_l1   = PMD_TYPE_TABLE,
	//	.prot_sect = PMD_TYPE_SECT | PMD_SECT_AP_WRITE,
	//	.domain    = DOMAIN_KERNEL,
	//}
#ifndef CONFIG_ARM_LPAE
	/*
	 * Catch 36-bit addresses
	 */

	// md->pfn : 0x40000
	if (md->pfn >= 0x100000) {
		create_36bit_mapping(md, type);
		return;
	}
#endif

	addr = md->virtual & PAGE_MASK;
	// md->virtual : 0xC0000000, PAGE_MASK : 0xFFFFF000, addr : 0xC0000000
	// md.virtual: 0xffff0000, PAGE_MASK: 0xFFFFF000, addr: 0xffff0000
	phys = __pfn_to_phys(md->pfn);
	// md->pfn: 0x40000, phys: 0x40000000
	// md->pfn: 0x6F7FE, phys: 0x6F7FE000
	length = PAGE_ALIGN(md->length + (md->virtual & ~PAGE_MASK));
	// md.length: 0x2f800000, length: 0x2f800000
	// md.length: 0x1000, length: 0x1000
	if (type->prot_l1 == 0 && ((addr | phys | length) & ~SECTION_MASK)) {
		printk(KERN_WARNING "BUG: map for 0x%08llx at 0x%08lx can not "
		       "be mapped using pages, ignoring.\n",
		       (long long)__pfn_to_phys(md->pfn), addr);
		return;
	}

	pgd = pgd_offset_k(addr);
	// addr: 0xC0000000, pgd: 0xc0004000 + 0x600 * 8
	// addr: 0xffff0000, pgd: 0xc0004000 + 0x7FF * 8
	// 가상 주소를 넣었을 때 찾아가는 pgd 테이블의 주소를 찾아냄
	end = addr + length;
	// end: 0xC0000000 + 0x2f800000: 0xef800000
	// end: 0xffff0000 + 0x1000: 0xffff1000
	// 매핑할 가상 주소의 마지막 값
	do {
		unsigned long next = pgd_addr_end(addr, end);
		// addr: 0xC0000000, end: 0xef800000, next: 0xC0200000
		// addr: 0xffff0000, end: 0xffff1000, next: 0xffff1000
		// 2MB씩 자르거나 그것보다 end가 적으면 end를 next로 설정

		// pgd: 0xC0007000, addr: 0xC0000000, next: 0xC0200000, phys: 0x40000000
		// pgd: 0xC0007FF8, addr: 0xFFFF0000, next: 0xFFFF1000, phys: 0x6F7FE000
		alloc_init_pud(pgd, addr, next, phys, type);

		phys += next - addr;
		// 매핑할 물리 주소값을 2MB 만큼 추가함
		addr = next;
		// 다음 매핑할 가상 주소도 2MB 만큼 추가함
	} while (pgd++, addr != end);
	// pgd 위치를 하나 올리고 가상 주소 끝까지 수행 했는지 확인
	// 2칸씩 뛰어 올라감 (pgd >> 8byte형 포인터)
	// alloc_init_pud 내부에서 2번 돌았기 때문에 2칸 올라가야 하는 것이 맞음
}

/*
 * Create the architecture specific mappings
 */
// cpuid 뽑아내기 호출 시
// io_desc.pfn : 0x10000
// io_desc.length : 0xFF
// io_desc.virtual : 0xF8000000
// io_desc.type : MT_DEVICE
//
// exynos 그 외 인자 호출 시 exynos5_iodesc 값이 쭉 들어감
// nr = 7
void __init iotable_init(struct map_desc *io_desc, int nr)
{
	struct map_desc *md;
	struct vm_struct *vm;
	struct static_vm *svm;
	// static_vm : vm_struct를 리스트로 묶어둔 것.

	if (!nr)	// nr = 1
		return;

	svm = early_alloc_aligned(sizeof(*svm) * nr, __alignof__(*svm));
	// lowmem 영역에서 reserved 되지 않은 영역 중 struct_vm 크기만큼
	// 위에서부터 찾아냄

	for (md = io_desc; nr; md++, nr--) {
		create_mapping(md);
		// IO 영역에 대한 내용을 매핑함

		vm = &svm->vm;
		// reserved 된 영역 내의 vm_struct를 가리키게 됨
		vm->addr = (void *)(md->virtual & PAGE_MASK);
		// 매핑된 가상 주소 정보를 저장해 둠.
		vm->size = PAGE_ALIGN(md->length + (md->virtual & ~PAGE_MASK));
		// 매핑된 길이를 저장 (만약 length가 5K >> 8KB로 바꿔서 저장)
		vm->phys_addr = __pfn_to_phys(md->pfn);
		// 매핑된 물리 프레임 번호를 물리 주소로 바꾼 뒤 저장
		vm->flags = VM_IOREMAP | VM_ARM_STATIC_MAPPING;
		vm->flags |= VM_ARM_MTYPE(md->type);
		// flag 정보를 만들어 저장
		vm->caller = iotable_init;
		// svm->vm에 위의 정보를 넣어 구조체를 만들어 줌
		// vm->addr : 0xF8000000
		// vm->size : 0x1000
		// vm->phys_addr : 0x10000000
		// vm->flags : 0x40000001
		add_static_vm_early(svm++);
	}
}

void __init vm_reserve_area_early(unsigned long addr, unsigned long size,
				  void *caller)
{
	struct vm_struct *vm;
	struct static_vm *svm;

	svm = early_alloc_aligned(sizeof(*svm), __alignof__(*svm));

	vm = &svm->vm;
	vm->addr = (void *)addr;
	vm->size = size;
	vm->flags = VM_IOREMAP | VM_ARM_EMPTY_MAPPING;
	vm->caller = caller;
	add_static_vm_early(svm);
}

#ifndef CONFIG_ARM_LPAE

/*
 * The Linux PMD is made of two consecutive section entries covering 2MB
 * (see definition in include/asm/pgtable-2level.h).  However a call to
 * create_mapping() may optimize static mappings by using individual
 * 1MB section mappings.  This leaves the actual PMD potentially half
 * initialized if the top or bottom section entry isn't used, leaving it
 * open to problems if a subsequent ioremap() or vmalloc() tries to use
 * the virtual space left free by that unused section entry.
 *
 * Let's avoid the issue by inserting dummy vm entries covering the unused
 * PMD halves once the static mappings are in place.
 */

static void __init pmd_empty_section_gap(unsigned long addr)
{
	vm_reserve_area_early(addr, SECTION_SIZE, pmd_empty_section_gap);
}

static void __init fill_pmd_gaps(void)
{
	struct static_vm *svm;
	struct vm_struct *vm;
	unsigned long addr, next = 0;
	pmd_t *pmd;

	list_for_each_entry(svm, &static_vmlist, list) {
		vm = &svm->vm;
		addr = (unsigned long)vm->addr;
		// 가장 먼저 0xF6100000 가 addr로 들어감
		if (addr < next) // 일단 통과
			continue;

		/*
		 * Check if this vm starts on an odd section boundary.
		 * If so and the first section entry for this PMD is free
		 * then we block the corresponding virtual address.
		 */

		// io 매핑되는 가상 주소가 홀수 1MB에서 시작 했을 경우 section pair 중 앞 쪽이 안맞음
		// 1MB 이하 크기면 alloc_pte에서 알아서 처리해줌
		// 1MB 이상이면 alloc_pmd에서는 해당되는 것만 처리하기 때문에 문제가 발생됨
		// 이 때 쓰지 않은 section도 무조건 쓰는 것으로 바꿈
		if ((addr & ~PMD_MASK) == SECTION_SIZE) {
			pmd = pmd_off_k(addr);
			// pgd offset이 계산되어 나옴 (section의 가상 메모리 주소)
			if (pmd_none(*pmd))
				pmd_empty_section_gap(addr & PMD_MASK);
		}

		/*
		 * Then check if this vm ends on an odd section boundary.
		 * If so and the second section entry for this PMD is empty
		 * then we block the corresponding virtual address.
		 */
		// io 매핑되는 가상 주소가 홀수 1MB에서 끝날 경우 section pair 중 뒤 쪽이 안맞음
		// 이 때 쓰지 않은 section도 무조건 쓰는 것으로 바꿈
		addr += vm->size;
		if ((addr & ~PMD_MASK) == SECTION_SIZE) {
			pmd = pmd_off_k(addr) + 1;
			if (pmd_none(*pmd))
				pmd_empty_section_gap(addr);
		}

		/* no need to look at any vm entry until we hit the next PMD */
		next = (addr + PMD_SIZE - 1) & PMD_MASK;
	}
}

#else
#define fill_pmd_gaps() do { } while (0)
#endif

#if defined(CONFIG_PCI) && !defined(CONFIG_NEED_MACH_IO_H)
static void __init pci_reserve_io(void)
{
	struct static_vm *svm;

	svm = find_static_vm_vaddr((void *)PCI_IO_VIRT_BASE);
	if (svm)
		return;

	vm_reserve_area_early(PCI_IO_VIRT_BASE, SZ_2M, pci_reserve_io);
}
#else
#define pci_reserve_io() do { } while (0)
#endif

#ifdef CONFIG_DEBUG_LL
void __init debug_ll_io_init(void)
{
	struct map_desc map;

	debug_ll_addr(&map.pfn, &map.virtual);
	if (!map.pfn || !map.virtual)
		return;
	map.pfn = __phys_to_pfn(map.pfn);
	map.virtual &= PAGE_MASK;
	map.length = PAGE_SIZE;
	map.type = MT_DEVICE;
	iotable_init(&map, 1);
}
#endif

static void * __initdata vmalloc_min =
	(void *)(VMALLOC_END - (240 << 20) - VMALLOC_OFFSET);

/*
 * vmalloc=size forces the vmalloc area to be exactly 'size'
 * bytes. This can be used to increase (or decrease) the vmalloc
 * area - the default is 240m.
 */
static int __init early_vmalloc(char *arg)
{
	unsigned long vmalloc_reserve = memparse(arg, NULL);

	if (vmalloc_reserve < SZ_16M) {
		vmalloc_reserve = SZ_16M;
		printk(KERN_WARNING
			"vmalloc area too small, limiting to %luMB\n",
			vmalloc_reserve >> 20);
	}

	if (vmalloc_reserve > VMALLOC_END - (PAGE_OFFSET + SZ_32M)) {
		vmalloc_reserve = VMALLOC_END - (PAGE_OFFSET + SZ_32M);
		printk(KERN_WARNING
			"vmalloc area is too big, limiting to %luMB\n",
			vmalloc_reserve >> 20);
	}

	vmalloc_min = (void *)(VMALLOC_END - vmalloc_reserve);
	return 0;
}
early_param("vmalloc", early_vmalloc);

phys_addr_t arm_lowmem_limit __initdata = 0;

void __init sanity_check_meminfo(void)
{
	phys_addr_t memblock_limit = 0;
	int i, j, highmem = 0;

	// vmalloc_min : 0xEF800000
	phys_addr_t vmalloc_limit = __pa(vmalloc_min - 1) + 1;
	// vmalloc_limit : 0x4F80000

	// meminfo.nr_banks : 1
	for (i = 0, j = 0; i < meminfo.nr_banks; i++) {
		struct membank *bank = &meminfo.bank[j];
		// bank : meminfo.bank[0]
		// meminfo.bank[0].start : 0x20000000
		// meminfo.bank[0].size : 0x80000000 가 저장되어 있음

		phys_addr_t size_limit;

		*bank = meminfo.bank[i];
		// meminfo.bank[0]에  meminfo.bank[0] 를 대입

		size_limit = bank->size;
		// size_limit : 0x80000000

		// bank->start : 0x20000000, vmalloc_limit : 0x4F800000
		if (bank->start >= vmalloc_limit)
			highmem = 1;
		else
			size_limit = vmalloc_limit - bank->start;
			// size_limit : 0x2F800000

		bank->highmem = highmem;
		// bank->highmem : 0

#ifdef CONFIG_HIGHMEM
		/*
		 * Split those memory banks which are partially overlapping
		 * the vmalloc area greatly simplifying things later.
		 */
		if (!highmem && bank->size > size_limit) {		
			// 현재 뱅크가 lowmem인데, 뱅크 크기가 lowmem 제한 크기보다 클 경우를 찾아내는 조건임
			// lowmem 크기 제한은 760MB이기 때문에 현재 뱅크를 적당히 쪼개야 함
			if (meminfo.nr_banks >= NR_BANKS) {
				printk(KERN_CRIT "NR_BANKS too low, "
						 "ignoring high memory\n");
			} else {
				memmove(bank + 1, bank,
					(meminfo.nr_banks - i) * sizeof(*bank));
				// meminfo.bank[1]에 meminfo.bank[0] 대입
				// 뱅크가 여러 개일 경우 여러 칸이 이동 됨

				meminfo.nr_banks++;
				// meminfo.nr_banks : 2
				i++;
				bank[1].size -= size_limit;
				// bank[1].size : 0x5080000

				bank[1].start = vmalloc_limit;
				// bank[1].start : 0x4F800000

				bank[1].highmem = highmem = 1;
				// bank[1].highmem : 1
				j++;
			}
			bank->size = size_limit;
			// bank[0].size : 0x2F800000
		}
		// 뱅크가 2개로 분리 됨
		// meminfo.nr_banks : 2
		// meminfo.bank[0].start : 0x20000000
		// meminfo.bank[0].size : 0x2F800000
		// meminfo.bank[0].highmem : 0
		//
		// meminfo.bank[1].start : 0x4F800000
		// meminfo.bank[1].size : 0x50800000
		// meminfo.bank[1].highmem : 1
#else
		/*
		 * Highmem banks not allowed with !CONFIG_HIGHMEM.
		 */
		if (highmem) {
			printk(KERN_NOTICE "Ignoring RAM at %.8llx-%.8llx "
			       "(!CONFIG_HIGHMEM).\n",
			       (unsigned long long)bank->start,
			       (unsigned long long)bank->start + bank->size - 1);
			continue;
		}

		/*
		 * Check whether this memory bank would partially overlap
		 * the vmalloc area.
		 */
		if (bank->size > size_limit) {
			printk(KERN_NOTICE "Truncating RAM at %.8llx-%.8llx "
			       "to -%.8llx (vmalloc region overlap).\n",
			       (unsigned long long)bank->start,
			       (unsigned long long)bank->start + bank->size - 1,
			       (unsigned long long)bank->start + size_limit - 1);
			bank->size = size_limit;
		}
#endif
		// bank : meminfo.bank[0]
		// bank->highmem : 0
		if (!bank->highmem) {
			phys_addr_t bank_end = bank->start + bank->size;
			// bank_end : 0x4F800000, lowmem의 마지막 주소임

			// arm_lowmem_limit : 0
			if (bank_end > arm_lowmem_limit)
				arm_lowmem_limit = bank_end;
				// arm_lowmem_limit : 0x4F800000

			/*
			 * Find the first non-section-aligned page, and point
			 * memblock_limit at it. This relies on rounding the
			 * limit down to be section-aligned, which happens at
			 * the end of this function.
			 *
			 * With this algorithm, the start or end of almost any
			 * bank can be non-section-aligned. The only exception
			 * is that the start of the bank 0 must be section-
			 * aligned, since otherwise memory would need to be
			 * allocated when mapping the start of bank 0, which
			 * occurs before any free memory is mapped.
			 */
			// memblock_limit : 0
			if (!memblock_limit) {
				if (!IS_ALIGNED(bank->start, SECTION_SIZE))
					memblock_limit = bank->start;
				else if (!IS_ALIGNED(bank_end, SECTION_SIZE))
					memblock_limit = bank_end;
				// bank->start, bank_end 둘 다 1MB에 대해 정렬되어 있으므로
				// 둘 다 수행되지 않음
				// memblock_limit : 0
			}
		}
		j++;
	}
#ifdef CONFIG_HIGHMEM		// y

	if (highmem) {
		const char *reason = NULL;

		if (cache_is_vipt_aliasing()) {
			/*
			 * Interactions between kmap and other mappings
			 * make highmem support with aliasing VIPT caches
			 * rather difficult.
			 */
			reason = "with VIPT aliasing cache";
		}
		if (reason) {
			printk(KERN_CRIT "HIGHMEM is not supported %s, ignoring high memory\n",
				reason);
			while (j > 0 && meminfo.bank[j - 1].highmem)
				j--;
		}
	}
#endif

	meminfo.nr_banks = j;
	// meminfo.nr_banks : 2

	// arm_lowmem_limit : 0x4F800000
	high_memory = __va(arm_lowmem_limit - 1) + 1;
	// high_memory : 0xEF800000

	/*
	 * Round the memblock limit down to a section size.  This
	 * helps to ensure that we will allocate memory from the
	 * last full section, which should be mapped.
	 */
	if (memblock_limit)
		memblock_limit = round_down(memblock_limit, SECTION_SIZE);
	if (!memblock_limit)
		memblock_limit = arm_lowmem_limit;
	// memblock_limit : 0x4F800000

	memblock_set_current_limit(memblock_limit);
	// 전역 변수인 memblock.current_limit가 0x4F800000 으로 설정됨
}

// 인라인 함수!?
static inline void prepare_page_table(void)
{
	unsigned long addr;
	phys_addr_t end;

	/*
	 * Clear out all the mappings below the kernel image.
	 */

	// MODULES_VADDR : PAGE_OFFSET - SZ_16M
	// PAGE_OFFSET : 0xC0000000
	// SZ_16M : 0x01000000 (16MB)
	// MODULES_VADDR : 0xbf000000
	// PMD_SIZE : 0x00200000 (2MB) 
	for (addr = 0; addr < MODULES_VADDR; addr += PMD_SIZE)
		pmd_clear(pmd_off_k(addr));
		// return pmd_offset(pud_offset(pgd_offset_k(virt), virt), virt);
		// #define pud_offset(pgd, start)		(pgd)
		// #define pgd_offset_k(addr)	pgd_offset(&init_mm, addr)
		// #define pgd_offset(mm, addr)	((mm)->pgd + pgd_index(addr))
		// #define pgd_index(addr)		((addr) >> PGDIR_SHIFT)
		//
		// mm->pgd : 0xc0004000
		// pgd_offset_k(virt) >> pgd table 상에서 virt 주소에 해당하는 것의 위치를 가져옴.
		// pud는 쓰지 않음. 그냥 pgd offset이 pmd_offset(~, ~)로 들어감.
		// pmd도 쓰지 않으므로, pgd offset이 얻어 짐.
		// ARM 에서는 PGD >> PTE >> 인덱스 구조만 사용 됨.
		// pmd_off_k(addr)은 결국 addr에 해당하는 pgd 위치의 주소가 됨.
		//
		// 매크로 중첩이 심한데 컴파일러를 통해 전부 처리된 상태를 확인할 수 도 있음.
		//
		// 인덱스 값이 2MB 당 1씩 증가한 이유는 (mm)->pgd 가 8byte형 포인터이기 때문이다.
		// 그러므로 1씩 증가시켜야 pgd 2개가 올라가게 된다.
		
	// 위 반복문을 통해 하는 작업은 USER 영역인 0x00000000 ~ 0xbf000000 에 대한
	// PGD 테이블을 Data Cache Clean >> TLB를 날림.

#ifdef CONFIG_XIP_KERNEL
	/* The XIP kernel is mapped in the module area -- skip over it */
	addr = ((unsigned long)_etext + PMD_SIZE - 1) & PMD_MASK;
#endif
	for ( ; addr < PAGE_OFFSET; addr += PMD_SIZE)
		pmd_clear(pmd_off_k(addr));
	// 0xbf000000 ~ 0xc0000000 에 대한
	// PGD 테이블을 Data Cache Clean
	
	/*
	 * Find the end of the first block of lowmem.
	 */
	end = memblock.memory.regions[0].base + memblock.memory.regions[0].size;
	// end = 0x20000000 + 0x80000000
	//   >> 0xA0000000  (2GB)
	
	if (end >= arm_lowmem_limit)
		end = arm_lowmem_limit;
	// arm_lowmem_limit : 0x6f800000
	// 그러므로 end 값이 arm_lowmem_limit가 됨
	// bank 0 의 마지막 주소임
	
	/*
	 * Clear out all the kernel space mappings, except for the first
	 * memory bank, up to the vmalloc region.
	 */

	// adddr : 0xef800000, VMALLOC_START : 0xF0000000 임 
	for (addr = __phys_to_virt(end); addr < VMALLOC_START; addr += PMD_SIZE)
		pmd_clear(pmd_off_k(addr));

	// 그러므로 buffer 8MB 에 대한 PGD 테이블을 Data Cache Clean
}

#ifdef CONFIG_ARM_LPAE
/* the first page is reserved for pgd */
#define SWAPPER_PG_DIR_SIZE	(PAGE_SIZE + \
				 PTRS_PER_PGD * PTRS_PER_PMD * sizeof(pmd_t))
#else
#define SWAPPER_PG_DIR_SIZE	(PTRS_PER_PGD * sizeof(pgd_t))
#endif

/*
 * Reserve the special regions of memory
 */
void __init arm_mm_memblock_reserve(void)
{
	/*
	 * Reserve the page tables.  These are already in use,
	 * and can only be in node 0.
	 */
	// swapper_pd_dir : 0xC0004000, SWAPPER_PG_DIR_SIZE : 16K
	memblock_reserve(__pa(swapper_pg_dir), SWAPPER_PG_DIR_SIZE);
	// 페이지 테이블 공간을 reserve 영역에 등록
	// 물리 주소 0x20004000 - 0x20008000이 등록됨

#ifdef CONFIG_SA1111	// N
	/*
	 * Because of the SA1111 DMA bug, we want to preserve our
	 * precious DMA-able memory...
	 */
	memblock_reserve(PHYS_OFFSET, __pa(swapper_pg_dir) - PHYS_OFFSET);
#endif
}

/*
 * Set up the device mappings.  Since we clear out the page tables for all
 * mappings above VMALLOC_START, we will remove any debug device mappings.
 * This means you have to be careful how you debug this function, or any
 * called function.  This means you can't use any function or debugging
 * method which may touch any device, otherwise the kernel _will_ crash.
 */
static void __init devicemaps_init(struct machine_desc *mdesc)
{
	struct map_desc map;
	unsigned long addr;
	void *vectors;

	/*
	 * Allocate the vector page early.
	 */
	vectors = early_alloc(PAGE_SIZE * 2);
	// PAGE_SIZE * 2 : 8K
	// 8KB 크기인 reserved 되지 않은 영역을 가져옴.
	// lowmem 상위에서부터 탐색하며 가장 먼저 발견되는 8KB 영역을 가져온다.
	// vectors는 찾아낸 영역의 시작 주소가 됨
	
	early_trap_init(vectors);
	// vector, stub, kuser_help를 lowmem 영역에 만든 뒤 cache를 전부 메모리에 반영시켜 
	// 확실하게 메모리에 올라오게 함.
	
	// VMALLOC_START : 0xF0000000, PMD_SIZE : 0x00200000(2MB)
	for (addr = VMALLOC_START; addr; addr += PMD_SIZE)
		pmd_clear(pmd_off_k(addr));
	// 0xF0000000 ~ 0xFFFFFFFF 에 해당하는 section에 대한 data cache를 전부 클리어

	/*
	 * Map the kernel if it is XIP.
	 * It is always first in the modulearea.
	 */
#ifdef CONFIG_XIP_KERNEL	// 통과
	map.pfn = __phys_to_pfn(CONFIG_XIP_PHYS_ADDR & SECTION_MASK);
	map.virtual = MODULES_VADDR;
	map.length = ((unsigned long)_etext - map.virtual + ~SECTION_MASK) & SECTION_MASK;
	map.type = MT_ROM;
	create_mapping(&map);
#endif

	/*
	 * Map the cache flushing regions.
	 */
#ifdef FLUSH_BASE		// 통과
	map.pfn = __phys_to_pfn(FLUSH_BASE_PHYS);
	map.virtual = FLUSH_BASE;
	map.length = SZ_1M;
	map.type = MT_CACHECLEAN;
	create_mapping(&map);
#endif
#ifdef FLUSH_BASE_MINICACHE	// 통과
	map.pfn = __phys_to_pfn(FLUSH_BASE_PHYS + SZ_1M);
	map.virtual = FLUSH_BASE_MINICACHE;
	map.length = SZ_1M;
	map.type = MT_MINICLEAN;
	create_mapping(&map);
#endif

	/*
	 * Create a mapping for the machine vectors at the high-vectors
	 * location (0xffff0000).  If we aren't using high-vectors, also
	 * create a mapping at the low-vectors virtual address.
	 */
	map.pfn = __phys_to_pfn(virt_to_phys(vectors));
	// map.pfn: 0x6F7FE
	map.virtual = 0xffff0000;
	map.length = PAGE_SIZE;
	// map.length = 0x1000
#ifdef CONFIG_KUSER_HELPERS	// 여기
	map.type = MT_HIGH_VECTORS;
#else
	map.type = MT_LOW_VECTORS;
#endif
	create_mapping(&map);
	// 새로 만든 영역의 하위 4KB를 0xffff0000으로 매핑
	// 특성은 MT_HIGH_VECTORS
	//	[MT_HIGH_VECTORS] = {
	//	.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY |
	//			L_PTE_USER | L_PTE_RDONLY,
	//	.prot_l1   = PMD_TYPE_TABLE,
	//	.domain    = DOMAIN_USER,
	// },
	if (!vectors_high()) {				// 안들어감
		map.virtual = 0;
		map.length = PAGE_SIZE * 2;
		map.type = MT_LOW_VECTORS;
		create_mapping(&map);
	}
	
	/* Now create a kernel read-only mapping */
	map.pfn += 1;
	map.virtual = 0xffff0000 + PAGE_SIZE;
	map.length = PAGE_SIZE;
	map.type = MT_LOW_VECTORS;
	create_mapping(&map);
	// 새로 만든 영역의 상위 4KB를 0xffff1000으로 매핑
	//[ MT_LOW_VECTORS] = {
	//	.prot_pte  = L_PTE_PRESENT | L_PTE_YOUNG | L_PTE_DIRTY |
	//			L_PTE_RDONLY,
	//	.prot_l1   = PMD_TYPE_TABLE,
	//	.domain    = DOMAIN_USER,
	// },

	/*
	 * Ask the machine support to map in the statically mapped devices.
	 */
	if (mdesc->map_io)
		mdesc->map_io();
		// exynos_init_io 호출
		// exynos io의 실제 메모리 주소를 가상 메모리 주소에 매핑하고
		// vmlist와 static_vmlist에 등록시킴
	else
		debug_ll_io_init();
	fill_pmd_gaps();
	// section 단위로 io 맵 할당 시 사용하는 section의 갯수가 홀수개일 경우 reserve 처리함

	/* Reserve fixed i/o space in VMALLOC region */
	pci_reserve_io();
	// 그냥 통과

	/*
	 * Finally flush the caches and tlb to ensure that we're in a
	 * consistent state wrt the writebuffer.  This also ensures that
	 * any write-allocated cache lines in the vector page are written
	 * back.  After this point, we can start to touch devices again.
	 */
	local_flush_tlb_all();
	flush_cache_all(); // v7_flush_kern_cache_all
	// tlb, cache 전부 flush 처리
}

static void __init kmap_init(void)
{
#ifdef CONFIG_HIGHMEM
	// PKMAP_BASE : 0xBFE00000, _PAGE_KERNEL_TABLE : 0x11
	pkmap_page_table = early_pte_alloc(pmd_off_k(PKMAP_BASE),
		PKMAP_BASE, _PAGE_KERNEL_TABLE);
#endif
}

static void __init map_lowmem(void)
{
	struct memblock_region *reg;
	// struct memblock_region : base, size 값이 저장됨

	/* Map all the lowmem memory banks. */
	// lowmem 영역을 매핑
	// lowmem은 커널 영역의 아랫 부분이며
	// 물리 메모리 위치 : 0x40000000 ~ 0x6f800000 (760MB)
	// 가상 메모리 위치 : 0xC0000000 ~ 0xEF800000 (760MB)

	// for (reg = memblock.memory.regions; reg < memblock.memory.regions + memblock.memory.cnt; reg++)
	for_each_memblock(memory, reg) {
		phys_addr_t start = reg->base;
		phys_addr_t end = start + reg->size;
		struct map_desc map;
		
		// end : 0xC0000000 , arm_lowmem_limit : 0x6f800000
		if (end > arm_lowmem_limit)
			end = arm_lowmem_limit;

		// start : 0x40000000, end : 0x6f800000
		if (start >= end)
			break;
		// 위 2개의 if 문은 start, end의 위치를 lowmem 영역에 맞추는 작업임
		
		
		map.pfn = __phys_to_pfn(start);
		// 프레임 번호를 긁어 옴 (4KB 단위 크기 프레임)
		// map.pfn : 0x40000
		map.virtual = __phys_to_virt(start);
		// map.virtual : 0xC0000000  (가상 메모리 시작 주소)
		map.length = end - start;
		// map.length : 0x2f800000 (760MB)
		map.type = MT_MEMORY;

		create_mapping(&map);
		// map 정보에 맞게 mmu를 위한 section 자료 구조를 생성함.
		// map의 각 인자 값이 의미 하는 것은?
		// virtual : 가상 주소의 시작값
		// pfn : 물리 주소의 시작 프레임 번호 (내부에서 물리 주소의 시작 주소로 변경)
		// length : 매핑할 크기.
		// type : section 설정 필드에 넣어줄 설정값들
	}
}

/*
 * paging_init() sets up the page tables, initialises the zone memory
 * maps, and sets up the zero page, bad page and bad page tables.
 */
void __init paging_init(struct machine_desc *mdesc)
{
	void *zero_page;
	
	build_mem_type_table();
	// 아키텍쳐 설정에 따라 mem_type 배열을 세팅 하였음.

	prepare_page_table();
	// PGD 테이블 초기화 (User 영역, Module 영역, Buffer 8MB 영역)
	
	map_lowmem();
	// lowmem 영역에 대하여
	// First-level Table에 Section들을 만들어 줌.
	// Read/write & No access Access only at PL1 or higher 권한 설정
	// 대응하는 Physical 위치 설정
	// 나머지는 0으로 밀어버림
	
	dma_contiguous_remap();
	// 그냥 통과
	devicemaps_init(mdesc);
	// vectors, io memory map 설정
	kmap_init();
	// pkmap_page_table 을 설정해 줌
	// 가상 주소 0xBFE00000 에 해당하는 page table과 small page table만 만듬
	// small page table 내부 값은 설정하지 않음
	tcm_init();
	// 그냥 통과 됨.

	top_pmd = pmd_off_k(0xffff0000);

	/* allocate the zero page. */
	zero_page = early_alloc(PAGE_SIZE);
	// zero_page에 reserved 되지 않았던 4KB 영역 할당(가상 주소 반환)
	
	bootmem_init();
	// contig_page_data 자료 값 설정 및 struct page 값들 초기화
	
	empty_zero_page = virt_to_page(zero_page);
	// zero_page에 해당하는 struct page 주소를 empty_zero_page에 저장
	__flush_dcache_page(NULL, empty_zero_page);
	// zero_page에 해당하는 D 캐쉬를 클리어
}
