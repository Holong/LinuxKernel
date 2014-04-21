/*
 *  linux/arch/arm/kernel/setup.c
 *
 *  Copyright (C) 1995-2001 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/ioport.h>
#include <linux/delay.h>
#include <linux/utsname.h>
#include <linux/initrd.h>
#include <linux/console.h>
#include <linux/bootmem.h>
#include <linux/seq_file.h>
#include <linux/screen_info.h>
#include <linux/of_platform.h>
#include <linux/init.h>
#include <linux/kexec.h>
#include <linux/of_fdt.h>
#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/smp.h>
#include <linux/proc_fs.h>
#include <linux/memblock.h>
#include <linux/bug.h>
#include <linux/compiler.h>
#include <linux/sort.h>

#include <asm/unified.h>
#include <asm/cp15.h>
#include <asm/cpu.h>
#include <asm/cputype.h>
#include <asm/elf.h>
#include <asm/procinfo.h>
#include <asm/psci.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <asm/smp_plat.h>
#include <asm/mach-types.h>
#include <asm/cacheflush.h>
#include <asm/cachetype.h>
#include <asm/tlbflush.h>

#include <asm/prom.h>
#include <asm/mach/arch.h>
#include <asm/mach/irq.h>
#include <asm/mach/time.h>
#include <asm/system_info.h>
#include <asm/system_misc.h>
#include <asm/traps.h>
#include <asm/unwind.h>
#include <asm/memblock.h>
#include <asm/virt.h>

#include "atags.h"


#if defined(CONFIG_FPE_NWFPE) || defined(CONFIG_FPE_FASTFPE)
char fpe_type[8];

static int __init fpe_setup(char *line)
{
	memcpy(fpe_type, line, 8);
	return 1;
}

__setup("fpe=", fpe_setup);
#endif

extern void paging_init(struct machine_desc *desc);
extern void sanity_check_meminfo(void);
extern enum reboot_mode reboot_mode;
extern void setup_dma_zone(struct machine_desc *desc);

unsigned int processor_id;
EXPORT_SYMBOL(processor_id);
unsigned int __machine_arch_type __read_mostly;
EXPORT_SYMBOL(__machine_arch_type);
unsigned int cacheid __read_mostly;
EXPORT_SYMBOL(cacheid);

unsigned int __atags_pointer __initdata;

unsigned int system_rev;
EXPORT_SYMBOL(system_rev);

unsigned int system_serial_low;
EXPORT_SYMBOL(system_serial_low);

unsigned int system_serial_high;
EXPORT_SYMBOL(system_serial_high);

unsigned int elf_hwcap __read_mostly;
EXPORT_SYMBOL(elf_hwcap);


#ifdef MULTI_CPU
struct processor processor __read_mostly;
#endif
#ifdef MULTI_TLB
struct cpu_tlb_fns cpu_tlb __read_mostly;
#endif
#ifdef MULTI_USER
struct cpu_user_fns cpu_user __read_mostly;
#endif
#ifdef MULTI_CACHE
struct cpu_cache_fns cpu_cache __read_mostly;
#endif
#ifdef CONFIG_OUTER_CACHE
struct outer_cache_fns outer_cache __read_mostly;
EXPORT_SYMBOL(outer_cache);
#endif

/*
 * Cached cpu_architecture() result for use by assembler code.
 * C code should use the cpu_architecture() function instead of accessing this
 * variable directly.
 */
int __cpu_architecture __read_mostly = CPU_ARCH_UNKNOWN;

struct stack {
	u32 irq[3];
	u32 abt[3];
	u32 und[3];
} ____cacheline_aligned;

#ifndef CONFIG_CPU_V7M
static struct stack stacks[NR_CPUS];
#endif

char elf_platform[ELF_PLATFORM_SIZE];
EXPORT_SYMBOL(elf_platform);

static const char *cpu_name;
static const char *machine_name;
static char __initdata cmd_line[COMMAND_LINE_SIZE];
struct machine_desc *machine_desc __initdata;

static union { char c[4]; unsigned long l; } endian_test __initdata = { { 'l', '?', '?', 'b' } };
#define ENDIANNESS ((char)endian_test.l)

DEFINE_PER_CPU(struct cpuinfo_arm, cpu_data);

/*
 * Standard memory resources
 */
static struct resource mem_res[] = {
	{
		.name = "Video RAM",
		.start = 0,
		.end = 0,
		.flags = IORESOURCE_MEM
	},
	{
		.name = "Kernel code",
		.start = 0,
		.end = 0,
		.flags = IORESOURCE_MEM
	},
	{
		.name = "Kernel data",
		.start = 0,
		.end = 0,
		.flags = IORESOURCE_MEM
	}
};

#define video_ram   mem_res[0]
#define kernel_code mem_res[1]
#define kernel_data mem_res[2]

static struct resource io_res[] = {
	{
		.name = "reserved",
		.start = 0x3bc,
		.end = 0x3be,
		.flags = IORESOURCE_IO | IORESOURCE_BUSY
	},
	{
		.name = "reserved",
		.start = 0x378,
		.end = 0x37f,
		.flags = IORESOURCE_IO | IORESOURCE_BUSY
	},
	{
		.name = "reserved",
		.start = 0x278,
		.end = 0x27f,
		.flags = IORESOURCE_IO | IORESOURCE_BUSY
	}
};

#define lp0 io_res[0]
#define lp1 io_res[1]
#define lp2 io_res[2]

static const char *proc_arch[] = {
	"undefined/unknown",
	"3",
	"4",
	"4T",
	"5",
	"5T",
	"5TE",
	"5TEJ",
	"6TEJ",
	"7",
	"7M",
	"?(12)",
	"?(13)",
	"?(14)",
	"?(15)",
	"?(16)",
	"?(17)",
};

#ifdef CONFIG_CPU_V7M	// n
static int __get_cpu_architecture(void)
{
	return CPU_ARCH_ARMv7M;
}
#else	// y
static int __get_cpu_architecture(void)
{
	int cpu_arch;

	if ((read_cpuid_id() & 0x0008f000) == 0) {
		cpu_arch = CPU_ARCH_UNKNOWN;
	} else if ((read_cpuid_id() & 0x0008f000) == 0x00007000) {
		cpu_arch = (read_cpuid_id() & (1 << 23)) ? CPU_ARCH_ARMv4T : CPU_ARCH_ARMv3;
	} else if ((read_cpuid_id() & 0x00080000) == 0x00000000) {
		cpu_arch = (read_cpuid_id() >> 16) & 7;
		if (cpu_arch)
			cpu_arch += CPU_ARCH_ARMv3;
	} else if ((read_cpuid_id() & 0x000f0000) == 0x000f0000) {
		unsigned int mmfr0;

		/* Revised CPUID format. Read the Memory Model Feature
		 * Register 0 and check for VMSAv7 or PMSAv7 */
		asm("mrc	p15, 0, %0, c0, c1, 4"
		    : "=r" (mmfr0));
		if ((mmfr0 & 0x0000000f) >= 0x00000003 ||
		    (mmfr0 & 0x000000f0) >= 0x00000030)
			cpu_arch = CPU_ARCH_ARMv7;
		else if ((mmfr0 & 0x0000000f) == 0x00000002 ||
			 (mmfr0 & 0x000000f0) == 0x00000020)
			cpu_arch = CPU_ARCH_ARMv6;
		else
			cpu_arch = CPU_ARCH_UNKNOWN;
	} else
		cpu_arch = CPU_ARCH_UNKNOWN;

	return cpu_arch;
}
#endif

int __pure cpu_architecture(void)
{
	// __cpu_architecture = CPU_ARCH_ARMv7
	BUG_ON(__cpu_architecture == CPU_ARCH_UNKNOWN);

	return __cpu_architecture;
}

static int cpu_has_aliasing_icache(unsigned int arch)
{
	int aliasing_icache;
	unsigned int id_reg, num_sets, line_size;

	/* PIPT caches never alias. */
	if (icache_is_pipt())	// 여기로 진입
		return 0;

	/* arch specifies the register format */
	switch (arch) {
	case CPU_ARCH_ARMv7:
		asm("mcr	p15, 2, %0, c0, c0, 0 @ set CSSELR"
		    : /* No output operands */
		    : "r" (1));
		isb();
		asm("mrc	p15, 1, %0, c0, c0, 0 @ read CCSIDR"
		    : "=r" (id_reg));
		line_size = 4 << ((id_reg & 0x7) + 2);
		num_sets = ((id_reg >> 13) & 0x7fff) + 1;
		aliasing_icache = (line_size * num_sets) > PAGE_SIZE;
		break;
	case CPU_ARCH_ARMv6:
		aliasing_icache = read_cpuid_cachetype() & (1 << 11);
		break;
	default:
		/* I-cache aliases will be handled by D-cache aliasing code */
		aliasing_icache = 0;
	}

	return aliasing_icache;
}

static void __init cacheid_init(void)
{
	unsigned int arch = cpu_architecture();
	// arch = CPU_ARCH_ARMv7;

	if (arch == CPU_ARCH_ARMv7M) {
		cacheid = 0;
	} else if (arch >= CPU_ARCH_ARMv6) {		// 이쪽으로 진입
		unsigned int cachetype = read_cpuid_cachetype();
	// cachetype : CTR 레지스터 값이 저장됨
	// 	       0x8444C004
		if ((cachetype & (7 << 29)) == 4 << 29) {
			// CTR의 Format 비트가 0b100 인지 확인함.
			// 0b100이면 ARMv7 format이므로, 이쪽으로 진입

			/* ARMv7 register format */
			arch = CPU_ARCH_ARMv7;
			cacheid = CACHEID_VIPT_NONALIASING;
			// cacheid : 0x2
			switch (cachetype & (3 << 14)) { // L1Ip 비트를 확인 (L1 I-Cache Policy)
			case (1 << 14):
				cacheid |= CACHEID_ASID_TAGGED;
				break;
			case (3 << 14):	// 이쪽으로 들어옴
				cacheid |= CACHEID_PIPT;
				// cacheid : 0x22
				break;
			}
		} else {
			arch = CPU_ARCH_ARMv6;
			if (cachetype & (1 << 23))
				cacheid = CACHEID_VIPT_ALIASING;
			else
				cacheid = CACHEID_VIPT_NONALIASING;
		}
		if (cpu_has_aliasing_icache(arch))
			// cpu_has_aliasing_icache(arch) : 0
			cacheid |= CACHEID_VIPT_I_ALIASING;
	} else {
		cacheid = CACHEID_VIVT;
	}

	// cacheid : 0x22
	printk("CPU: %s data cache, %s instruction cache\n",
		cache_is_vivt() ? "VIVT" :
		cache_is_vipt_aliasing() ? "VIPT aliasing" :
		cache_is_vipt_nonaliasing() ? "PIPT / VIPT nonaliasing" : "unknown",
		cache_is_vivt() ? "VIVT" :
		icache_is_vivt_asid_tagged() ? "VIVT ASID tagged" :
		icache_is_vipt_aliasing() ? "VIPT aliasing" :
		icache_is_pipt() ? "PIPT" :
		cache_is_vipt_nonaliasing() ? "VIPT nonaliasing" : "unknown");
	// 출력값
	// CPU : PIPT / VIPT nonaliasing data cache, PIPT instruction cache
}

/*
 * These functions re-use the assembly code in head.S, which
 * already provide the required functionality.
 */
extern struct proc_info_list *lookup_processor_type(unsigned int);

void __init early_print(const char *str, ...)
{
	extern void printascii(const char *);
	char buf[256];
	va_list ap;

	va_start(ap, str);
	vsnprintf(buf, sizeof(buf), str, ap);
	va_end(ap);

#ifdef CONFIG_DEBUG_LL
	printascii(buf);
#endif
	printk("%s", buf);
}

static void __init cpuid_init_hwcaps(void)
{
	unsigned int divide_instrs, vmsa;

	if (cpu_architecture() < CPU_ARCH_ARMv7)
		// cpu_architecture() : CPU_ARCH_ARMv7
		return;

	divide_instrs = (read_cpuid_ext(CPUID_EXT_ISAR0) & 0x0f000000) >> 24;
	// read_cpuid_ext(CPUID_EXT_ISAR0) : ID_ISAR0 레지스터 반환
	// divide_instrs : ID_ISAR0 레지스터의 Divide_instrs 비트 값을 가지고 있음
	// 		   Cortex-A15는 0x2 값임
	//		   즉, SDIV, UDIV 연산 지원됨

	switch (divide_instrs) {
	case 2:
		elf_hwcap |= HWCAP_IDIVA;
	case 1:
		elf_hwcap |= HWCAP_IDIVT;
	}

	/* LPAE implies atomic ldrd/strd instructions */
	vmsa = (read_cpuid_ext(CPUID_EXT_MMFR0) & 0xf) >> 0;
	if (vmsa >= 5)
		elf_hwcap |= HWCAP_LPAE;
}

static void __init feat_v6_fixup(void)
{
	int id = read_cpuid_id();
	// id : 0x410FC0F0

	if ((id & 0xff0f0000) != 0x41070000)
		return;

	/*
	 * HWCAP_TLS is available only on 1136 r1p0 and later,
	 * see also kuser_get_tls_init.
	 */
	if ((((id >> 4) & 0xfff) == 0xb36) && (((id >> 20) & 3) == 0))
		elf_hwcap &= ~HWCAP_TLS;
}

/*
 * cpu_init - initialise one CPU.
 *
 * cpu_init sets up the per-CPU stacks.
 */
void notrace cpu_init(void)
{
#ifndef CONFIG_CPU_V7M
	unsigned int cpu = smp_processor_id();
	// cpu : 0

	struct stack *stk = &stacks[cpu];
	// stk = &stacks[0]
	// 36바이트

	if (cpu >= NR_CPUS) { // 통과
		printk(KERN_CRIT "CPU%u: bad primary CPU number\n", cpu);
		BUG();
	}

	/*
	 * This only works on resume and secondary cores. For booting on the
	 * boot cpu, smp_prepare_boot_cpu is called after percpu area setup.
	 */
	set_my_cpu_offset(per_cpu_offset(cpu));
	// set_my_cpu_offset(__per_cpu_offset[0])
	// TPIDRPRW 레지스터에 __per_cpu_offset[0] 값을 저장함
	// 그러므로 TPIDRPRW에는 0이 저장됨

	cpu_proc_init();
	// cpu_v7_proc_init을 호출
	// v7의 경우 그냥 빈 함수로 되어 있음

	/*
	 * Define the placement constraint for the inline asm directive below.
	 * In Thumb-2, msr with an immediate value is not allowed.
	 */
#ifdef CONFIG_THUMB2_KERNEL
#define PLC	"r"
#else
#define PLC	"I"	// 이쪽으로 진입
#endif

	/*
	 * setup stacks for re-entrant exception handlers
	 */
	__asm__ (
	"msr	cpsr_c, %1\n\t"
	"add	r14, %0, %2\n\t"
	"mov	sp, r14\n\t"
	"msr	cpsr_c, %3\n\t"
	"add	r14, %0, %4\n\t"
	"mov	sp, r14\n\t"
	"msr	cpsr_c, %5\n\t"
	"add	r14, %0, %6\n\t"
	"mov	sp, r14\n\t"
	"msr	cpsr_c, %7"
	    :
	    : "r" (stk),
	      PLC (PSR_F_BIT | PSR_I_BIT | IRQ_MODE),
	      "I" (offsetof(struct stack, irq[0])),
	      PLC (PSR_F_BIT | PSR_I_BIT | ABT_MODE),
	      "I" (offsetof(struct stack, abt[0])),
	      PLC (PSR_F_BIT | PSR_I_BIT | UND_MODE),
	      "I" (offsetof(struct stack, und[0])),
	      PLC (PSR_F_BIT | PSR_I_BIT | SVC_MODE)
	    : "r14");

		// IRQ, ABT, UND 모드의 sp 값을 초기화 및 IRQ, FIQ를 끔
		// IRQ, FIQ 끈 상태로 SVC 모드로 복귀함
		//	msr  cpsr_c, PSR_F_BIT | PSR_I_BIT | IRQ_MODE
		//	add  r14, stk, offsetof(struct stack, irq[0])   // r14: &(stk->irq[0])
		//	mov  sp, r14
		//	msr  cpsr_c, PSR_F_BIT | PSR_I_BIT | ABT_MODE
		//	add  r14, stk, offsetof(struct stack, abt[0])   // r14: &(stk->abt[0])
		//	mov  sp, r14
		//	msr  cpsr_c, PSR_F_BIT | PSR_I_BIT | UND_MODE
		//	add  r14, stk, offsetof(struct stack, und[0])   // r14: &(stk->und[0])
		//	mov  sp, r14
		//	msr  cpsr_c, PSR_F_BIT | PSR_I_BIT | SVC_MODE


#endif
}

u32 __cpu_logical_map[NR_CPUS] = { [0 ... NR_CPUS-1] = MPIDR_INVALID };

void __init smp_setup_processor_id(void)
{
	int i;
	u32 mpidr = is_smp() ? read_cpuid_mpidr() & MPIDR_HWID_BITMASK : 0;
	// 현재 실제 SMP 시스템인지 확인하는 동작임
	// config만 가지고 확인하지 않고 레지스터를 뜯어서 실제 SMP인지 확인함.
	// MPIDR의 MSB를 보면 확인할 수 있음
	// SMP이면 Aff2~Aff0까지 가져오고 아니면 0을 mpidr에 설정
	// Cortex-A15의 경우 AFF0는 CPUID, AFF1은 클러스터 ID 번호가 저장되어 있음

	u32 cpu = MPIDR_AFFINITY_LEVEL(mpidr, 0);
	// cpu에 현재 동작하는 코어의 Aff0 값을 저장함

	cpu_logical_map(0) = cpu;
	// __cpu_logical_map[0] 에 현재 동작하는 코어의 Aff0 값을 저장
	for (i = 1; i < nr_cpu_ids; ++i)
		cpu_logical_map(i) = i == cpu ? 0 : i;

	// if cpu=0
	//	__cpu_logical_map[0] = 0    // current
	//	__cpu_logical_map[1] = 1    // others
	//	__cpu_logical_map[2] = 2    // others
	//	__cpu_logical_map[3] = 3    // others
	// if cpu=1
	//	__cpu_logical_map[0] = 1    // current
	//	__cpu_logical_map[1] = 0    // others
	//	__cpu_logical_map[2] = 2    // others
	//	__cpu_logical_map[3] = 3    // others
	// 무조건 현재 동작하는 코어의 AFF0 값은 __cpu_logical_map[0] 번에 저장하게 되어 있음

	/*
	 * clear __my_cpu_offset on boot CPU to avoid hang caused by
	 * using percpu variable early, for example, lockdep will
	 * access percpu variable inside lock_release
	 */
	set_my_cpu_offset(0);
	// TPIDRPRW 레지스터에 0 값을 저장함.
	// Thread ID 값이라고 하는데 어디에 쓰는지는 아직 모름

	printk(KERN_INFO "Booting Linux on physical CPU 0x%x\n", mpidr);
}

struct mpidr_hash mpidr_hash;
#ifdef CONFIG_SMP
/**
 * smp_build_mpidr_hash - Pre-compute shifts required at each affinity
 *			  level in order to build a linear index from an
 *			  MPIDR value. Resulting algorithm is a collision
 *			  free hash carried out through shifting and ORing
 */
static void __init smp_build_mpidr_hash(void)
{
	u32 i, affinity;
	u32 fs[3], bits[3], ls, mask = 0;
	/*
	 * Pre-scan the list of MPIDRS and filter out bits that do
	 * not contribute to affinity levels, ie they never toggle.
	 */
	for_each_possible_cpu(i)
	// for (i = -1; i = cpumask_next(i, cpu_possible_mask), i < nr_cpu_ids; )
		// i = 0 부터 시작
		mask |= (cpu_logical_map(i) ^ cpu_logical_map(0));
	// mask : 0x3
	pr_debug("mask of set bits 0x%x\n", mask);

	/*
	 * Find and stash the last and first bit set at all affinity levels to
	 * check how many bits are required to represent them.
	 */
	for (i = 0; i < 3; i++) {
		affinity = MPIDR_AFFINITY_LEVEL(mask, i);
		// [0] affinity : mask의 하위 8비트가 저장됨

		/*
		 * Find the MSB bit and LSB bits position
		 * to determine how many bits are required
		 * to express the affinity level.
		 */
		ls = fls(affinity);
		// [0] ls : 2

		fs[i] = affinity ? ffs(affinity) - 1 : 0;
		// fls : MSB, ffs : LSB
		// [0] fs[0] : 0
		bits[i] = ls - fs[i];
		// [0] bits[0] : 2
	}
	// fs[0] : 0, fs[1] : 0, fs[2] : 0
	// bits[0] : 2, bits[1] : 0, bits[2] : 0

	/*
	 * An index can be created from the MPIDR by isolating the
	 * significant bits at each affinity level and by shifting
	 * them in order to compress the 24 bits values space to a
	 * compressed set of values. This is equivalent to hashing
	 * the MPIDR through shifting and ORing. It is a collision free
	 * hash though not minimal since some levels might contain a number
	 * of CPUs that is not an exact power of 2 and their bit
	 * representation might contain holes, eg MPIDR[7:0] = {0x2, 0x80}.
	 */
	mpidr_hash.shift_aff[0] = fs[0];
	// mpidr_hash.shift_aff[0] : 0
	mpidr_hash.shift_aff[1] = MPIDR_LEVEL_BITS + fs[1] - bits[0];
	// mpidr_hash.shift_aff[1] : 6
	mpidr_hash.shift_aff[2] = 2*MPIDR_LEVEL_BITS + fs[2] -
						(bits[1] + bits[0]);
	// mpidr_hash.shift_aff[2] : 14

	mpidr_hash.mask = mask;
	// mpidr_hash.mask : 0x3

	mpidr_hash.bits = bits[2] + bits[1] + bits[0];
	// mpidr_hash.bits : 2
	pr_debug("MPIDR hash: aff0[%u] aff1[%u] aff2[%u] mask[0x%x] bits[%u]\n",
				mpidr_hash.shift_aff[0],
				mpidr_hash.shift_aff[1],
				mpidr_hash.shift_aff[2],
				mpidr_hash.mask,
				mpidr_hash.bits);
	/*
	 * 4x is an arbitrary value used to warn on a hash table much bigger
	 * than expected on most systems.
	 */
	if (mpidr_hash_size() > 4 * num_possible_cpus())
		pr_warn("Large number of MPIDR hash buckets detected\n");
	sync_cache_w(&mpidr_hash);
	// __sync_cache_range_w(&mpidr_hash, sizeof(mpidr_hash))
	// mpidr_hash 내용을 cache flush 수행
}
#endif

static void __init setup_processor(void)
{
	struct proc_info_list *list;

	/*
	 * locate processor in the list of supported processor
	 * types.  The linker builds this table for us from the
	 * entries in arch/arm/mm/proc-*.S
	 */
	list = lookup_processor_type(read_cpuid_id());
	// read_cpuid_id() : MIDR 레지스터 값을 반환
	// list = &__v7_ca15mp_proc_info
	
	if (!list) {
		printk("CPU configuration botched (ID %08x), unable "
		       "to continue.\n", read_cpuid_id());
		while (1);
	}

	cpu_name = list->cpu_name;
	// cpu_name : "ARMv7 Processor"
	
	__cpu_architecture = __get_cpu_architecture();
	// __cpu_architecture = CPU_ARCH_ARMv7;

#ifdef MULTI_CPU	// not defined
	processor = *list->proc;
#endif
#ifdef MULTI_TLB
	cpu_tlb = *list->tlb;
	// cpu_tlb : define_tlb_functions 매크로를 이용해 설정함
#endif
#ifdef MULTI_USER
	cpu_user = *list->user;
	// cpu_user : v6_user_fns
#endif
#ifdef MULTI_CACHE
	cpu_cache = *list->cache;
	// cpu_cache : define_cache_functions 매크로를 이용해 설정함
#endif

	printk("CPU: %s [%08x] revision %d (ARMv%s), cr=%08lx\n",
	       cpu_name, read_cpuid_id(), read_cpuid_id() & 15,
	       proc_arch[cpu_architecture()], cr_alignment);

	snprintf(init_utsname()->machine, __NEW_UTS_LEN + 1, "%s%c",
		 list->arch_name, ENDIANNESS);
	snprintf(elf_platform, ELF_PLATFORM_SIZE, "%s%c",
		 list->elf_name, ENDIANNESS);
	elf_hwcap = list->elf_hwcap;
	// elf_hwcap : HWCAP_SWP | HWCAP_HALF | HWCAP_THUMB | HWCAP_FAST_MULT | HWCAP_EDSP | HWCAP_TLS

	cpuid_init_hwcaps();
	// elf_hwcap |= HWCAP_IDIVA | HWCAP_IDIVT | HWCAP_LPAE

#ifndef CONFIG_ARM_THUMB	// 아래 수행 안함
	elf_hwcap &= ~(HWCAP_THUMB | HWCAP_IDIVT);
#endif

	feat_v6_fixup();
	// MIDR 값 확인한 뒤, 따로 작업 없이 종료함

	cacheid_init();
	// cacheid 값을 설정해줌 (PIPT 구조)
	// CPU : PIPT / VIPT nonaliasing data cache, PIPT instruction cache
	// cacheid : 0x22

	cpu_init();
	// TPIDRPRW에 0 저장
	// IRQ, ABT, UND 모드의 sp 값을 설정 및 IRQ, FIQ를 끔
	// stacks[0]의 각 멤버를 sp 값으로 설정하였음
	// IRQ, FIQ 끈 상태로 SVC 모드로 복귀함
}

void __init dump_machine_table(void)
{
	struct machine_desc *p;

	early_print("Available machine support:\n\nID (hex)\tNAME\n");
	for_each_machine_desc(p)
		early_print("%08x\t%s\n", p->nr, p->name);

	early_print("\nPlease check your kernel config and/or bootloader.\n");

	while (true)
		/* can't use cpu_relax() here as it may require MMU setup */;
}

// base : 0x20000000, size : 0x80000000
int __init arm_add_memory(phys_addr_t start, phys_addr_t size)
{
	struct membank *bank = &meminfo.bank[meminfo.nr_banks];
	// meminfo.nr_banks : 0 (초기화만 되어 있음)
	// bank : &meminfo.bank[0]

	if (meminfo.nr_banks >= NR_BANKS) {
		printk(KERN_CRIT "NR_BANKS too low, "
			"ignoring memory at 0x%08llx\n", (long long)start);
		return -EINVAL;
	}

	/*
	 * Ensure that start/size are aligned to a page boundary.
	 * Size is appropriately rounded down, start is rounded up.
	 */
	size -= start & ~PAGE_MASK;
	// PAGE_MASK : 0xFFFFF000
	// size 정렬
	bank->start = PAGE_ALIGN(start);
	// start 정렬
	
	// 즉, start는 4KB 단위로 올리고, size는 내림

#ifndef CONFIG_ARM_LPAE
	if (bank->start + size < bank->start) {
		printk(KERN_CRIT "Truncating memory at 0x%08llx to fit in "
			"32-bit physical address space\n", (long long)start);
		/*
		 * To ensure bank->start + bank->size is representable in
		 * 32 bits, we use ULONG_MAX as the upper limit rather than 4GB.
		 * This means we lose a page after masking.
		 */
		size = ULONG_MAX - bank->start;
	}
	// 문제 발생 시에만 진입
#endif

	bank->size = size & ~(phys_addr_t)(PAGE_SIZE - 1);
	// 4KB 단위로 size도 정렬시킴

	/*
	 * Check whether this memory region has non-zero size or
	 * invalid node number.
	 */
	if (bank->size == 0)
		return -EINVAL;

	meminfo.nr_banks++;
	// meminfo.nr_banks : 1
	// meminfo.bank[0].start : 0x20000000
	// meminfo.bank[0].size : 0x80000000

	return 0;
}

/*
 * Pick out the memory size.  We look for mem=size@start,
 * where start and size are "size[KkMm]"
 */
static int __init early_mem(char *p)
{
	static int usermem __initdata = 0;
	phys_addr_t size;
	phys_addr_t start;
	char *endp;

	/*
	 * If the user specifies memory size, we
	 * blow away any automatically generated
	 * size.
	 */
	if (usermem == 0) {
		usermem = 1;
		meminfo.nr_banks = 0;
	}

	start = PHYS_OFFSET;
	size  = memparse(p, &endp);
	if (*endp == '@')
		start = memparse(endp + 1, NULL);

	arm_add_memory(start, size);

	return 0;
}
early_param("mem", early_mem);

static void __init request_standard_resources(struct machine_desc *mdesc)
{
	struct memblock_region *region;
	struct resource *res;

	// kernel_code : mem_res[1]
	// kernel_data : mem_res[2]
	// 전역변수임
	kernel_code.start   = virt_to_phys(_text);
	kernel_code.end     = virt_to_phys(_etext - 1);
	kernel_data.start   = virt_to_phys(_sdata);
	kernel_data.end     = virt_to_phys(_end - 1);
	// 커널의 text 영역과 data 영역에 대한 정보를
	// 전역 변수 멤버에 적절한 값을 저장함

	for_each_memblock(memory, region) {
		// sizeof(*res) : 28바이트
		res = alloc_bootmem_low(sizeof(*res));
		// res : 4KB 영역을 할당 받은 뒤 시작 주소를 반환
		res->name  = "System RAM";
		// name : "System RAM" 저장
		res->start = __pfn_to_phys(memblock_region_memory_base_pfn(region));
		// res->start : 0x20000000
		res->end = __pfn_to_phys(memblock_region_memory_end_pfn(region)) - 1;
		// res->end : 0x9FFFFFFF
		res->flags = IORESOURCE_MEM | IORESOURCE_BUSY;
		// IORESOURCE_MEM : 0x00000200
		// IORESOURCE_BUSY : 0x80000000

		request_resource(&iomem_resource, res);
		// iomem_resource를 root로 하는 트리에 res를 노드로 등록함

		// res->start : 0x20000000, res->end : 0x9FFFFFFF
		if (kernel_code.start >= res->start &&
		    kernel_code.end <= res->end)
			request_resource(res, &kernel_code);
			// res의 자식으로 kernel_code 노드를 등록
		if (kernel_data.start >= res->start &&
		    kernel_data.end <= res->end)
			request_resource(res, &kernel_data);
			// res의 자식으로 kernel_data 노드를 등록
			// 결론적으로 res의 자식 1번에 kernel_code가 들어가고
			// kernel_code의 sibiling에 kernel_data가 등록됨
			//
			/*
			              res
			       /      /          \
			   parent  child       parent
			    /      /               \
			   kernel_code  ------->  kernel_data ------> null
			                sibling
			*/
	}

	if (mdesc->video_start) {
		video_ram.start = mdesc->video_start;
		video_ram.end   = mdesc->video_end;
		request_resource(&iomem_resource, &video_ram);
	}
	// mdesc->video_start는 0임

	/*
	 * Some machines don't have the possibility of ever
	 * possessing lp0, lp1 or lp2
	 */
	if (mdesc->reserve_lp0)
		request_resource(&ioport_resource, &lp0);
	if (mdesc->reserve_lp1)
		request_resource(&ioport_resource, &lp1);
	if (mdesc->reserve_lp2)
		request_resource(&ioport_resource, &lp2);
}

#if defined(CONFIG_VGA_CONSOLE) || defined(CONFIG_DUMMY_CONSOLE)
struct screen_info screen_info = {
 .orig_video_lines	= 30,
 .orig_video_cols	= 80,
 .orig_video_mode	= 0,
 .orig_video_ega_bx	= 0,
 .orig_video_isVGA	= 1,
 .orig_video_points	= 8
};
#endif

static int __init customize_machine(void)
{
	/*
	 * customizes platform devices, or adds new ones
	 * On DT based machines, we fall back to populating the
	 * machine from the device tree, if no callback is provided,
	 * otherwise we would always need an init_machine callback.
	 */
	if (machine_desc->init_machine)
		machine_desc->init_machine();
#ifdef CONFIG_OF
	else
		of_platform_populate(NULL, of_default_bus_match_table,
					NULL, NULL);
#endif
	return 0;
}
arch_initcall(customize_machine);

static int __init init_machine_late(void)
{
	if (machine_desc->init_late)
		machine_desc->init_late();
	return 0;
}
late_initcall(init_machine_late);

#ifdef CONFIG_KEXEC
static inline unsigned long long get_total_mem(void)
{
	unsigned long total;

	total = max_low_pfn - min_low_pfn;
	return total << PAGE_SHIFT;
}

/**
 * reserve_crashkernel() - reserves memory are for crash kernel
 *
 * This function reserves memory area given in "crashkernel=" kernel command
 * line parameter. The memory reserved is used by a dump capture kernel when
 * primary kernel is crashing.
 */
static void __init reserve_crashkernel(void)
{
	unsigned long long crash_size, crash_base;
	unsigned long long total_mem;
	int ret;

	total_mem = get_total_mem();
	ret = parse_crashkernel(boot_command_line, total_mem,
				&crash_size, &crash_base);
	if (ret)
		return;

	ret = reserve_bootmem(crash_base, crash_size, BOOTMEM_EXCLUSIVE);
	if (ret < 0) {
		printk(KERN_WARNING "crashkernel reservation failed - "
		       "memory is in use (0x%lx)\n", (unsigned long)crash_base);
		return;
	}

	printk(KERN_INFO "Reserving %ldMB of memory at %ldMB "
	       "for crashkernel (System RAM: %ldMB)\n",
	       (unsigned long)(crash_size >> 20),
	       (unsigned long)(crash_base >> 20),
	       (unsigned long)(total_mem >> 20));

	crashk_res.start = crash_base;
	crashk_res.end = crash_base + crash_size - 1;
	insert_resource(&iomem_resource, &crashk_res);
}
#else
static inline void reserve_crashkernel(void) {}
#endif /* CONFIG_KEXEC */

static int __init meminfo_cmp(const void *_a, const void *_b)
{
	const struct membank *a = _a, *b = _b;
	long cmp = bank_pfn_start(a) - bank_pfn_start(b);
	return cmp < 0 ? -1 : cmp > 0 ? 1 : 0;
}

void __init hyp_mode_check(void)
{
#ifdef CONFIG_ARM_VIRT_EXT
	sync_boot_mode();

	if (is_hyp_mode_available()) {
		pr_info("CPU: All CPU(s) started in HYP mode.\n");
		pr_info("CPU: Virtualization extensions available.\n");
	} else if (is_hyp_mode_mismatched()) {
		pr_warn("CPU: WARNING: CPU(s) started in wrong/inconsistent modes (primary CPU mode 0x%x)\n",
			__boot_cpu_mode & MODE_MASK);
		pr_warn("CPU: This may indicate a broken bootloader or firmware.\n");
	} else
		pr_info("CPU: All CPU(s) started in SVC mode.\n");
#endif
}

void __init setup_arch(char **cmdline_p)
{
	// machine_desc는 core 관련 정보를 관리하는 구조체임.
	struct machine_desc *mdesc;

	setup_processor();
	// cpu_tlb, cpu_user, cpu_cache를 현재 아키텍쳐에 맞는 구조체로 설정해줌
	// cache_id 값을 설정함(PIPT), elf_hwcap 설정
	// IRQ, ABT, UND 모드의 FIQ, IRQ를 끄고, SP를 설정함.

	mdesc = setup_machine_fdt(__atags_pointer);
	// DTB에 저장되어 있는 보드 명과 가장 일치하는 machine_desc 정보를 찾아 mdesc에 저장
	// boot_coommand_line 정보 설정 및 메모리 뱅크 정보를 설정

	if (!mdesc)
		mdesc = setup_machine_tags(__atags_pointer, __machine_arch_type);
	machine_desc = mdesc;
	// machine_desc :  __mach_desc_EXYNOS5_DT_name
	// 		   mach-exynos5-dt.c에 선언되어 있음
	machine_name = mdesc->name;
	// machine_name : "SAMSUNG EXYNOS5 (Flattened Device Tree)"

	setup_dma_zone(mdesc);
	// NULL 함수

	if (mdesc->reboot_mode != REBOOT_HARD)
		reboot_mode = mdesc->reboot_mode;

	init_mm.start_code = (unsigned long) _text;
	init_mm.end_code   = (unsigned long) _etext;
	init_mm.end_data   = (unsigned long) _edata;
	init_mm.brk	   = (unsigned long) _end;

	/* populate cmd_line too for later use, preserving boot_command_line */
	// boot_command_line : "console=ttySAC2,115200 init=/linuxrc"
	strlcpy(cmd_line, boot_command_line, COMMAND_LINE_SIZE);
	// cmd_line : "console=ttySAC2,115200 init=/linuxrc"

	*cmdline_p = cmd_line;

	parse_early_param();
	// 부트 커맨드에서 파라미터와 해당 값을 뽑아 처리 함수를 호출
	// 처리 함수는 파라미터 이름을 가지고 찾아냄
	// 현재 처리되는 파라미터는 "console"과 "init"임
	// 그런데 해당하는 처리 함수가 등록되어 있지 않기 때문에 하는 일이 없음

	sort(&meminfo.bank, meminfo.nr_banks, sizeof(meminfo.bank[0]), meminfo_cmp, NULL);
	// heap sort를 이용해 정렬을 수행하게 됨
	// 현재 meminfo.bank에 저장되어 있는 정보는 
	// meminfo.nr_banks : 1
	// meminfo.bank[0].start : 0x20000000
	// meminfo.bank[0].size : 0x80000000
	// 이며 1개 밖에 존재하지 않기 때문에 정렬이 수행되지 않음

	sanity_check_meminfo();
	// 뱅크가 lowmem, highmem 2개로 분리 됨.
	// lowmem은 붙밖이로 쓰이고, highmem은 virtual memory 기법이 적용될 것으로 보임
	// meminfo.nr_banks : 2
	// meminfo.bank[0].start : 0x20000000
	// meminfo.bank[0].size : 0x2F800000
	// meminfo.bank[0].highmem : 0
	// meminfo.bank[1].start : 0x4F800000
	// meminfo.bank[1].size : 0x50800000
	// meminfo.bank[1].highmem : 1

	// mdesc :  __mach_desc_EXYNOS5_DT_name
	// 	   mach-exynos5-dt.c에 선언되어 있음
	arm_memblock_init(&meminfo, mdesc);
	// memblock 에 regions 정보를 설정하였음
	//
	// memblock.memory.cnt : 2
	// memblock.memory.max : 128
	// memblock.memory.total_size : 0x80000000
	// memblock.memory.regions[0].base : 0x20000000
	// memblock.memory.regions[0].size : 0x80000000
	//
	// memblock.reserved 에는 현재 사용하는 공간을 등록
	// 커널 공간, DTB 공간, initrd, 섹션 테이블 등록

	paging_init(mdesc);
	// mmu용 변환 테이블인 pgd, pte 설정
	// zone memory map 설정, zero_page 설정

	request_standard_resources(mdesc);
	/* iomem_resource를 root로 하는 트리에 res를 노드로 등록함
	              res
	       /      /          \
	   parent  child       parent
	    /      /               \
	   kernel_code  ------->  kernel_data ------> null
	                         sibling
	*/
	if (mdesc->restart)
		arm_pm_restart = mdesc->restart;

	unflatten_device_tree();
	// DTB를 struct device_node, struct property를 이용하여 실제 트리로 만듬
	// of_allnodes : DTB의 루트 노드
	// of_chosen : chosen 노드
	// of_aliases : aliases 노드
	// alias 특성은 전역 변수 aliases_lookup에 연결시킴

	arm_dt_init_cpu_maps();
	// DT에서 cpu 노드 정보를 가져와 현재 부팅 동작을 수행 중인 cpu와 값을 비교

	// __cpu_logical_map[0] : 0
	// __cpu_logical_map[1] : 1
	// __cpu_logical_map[2] : 2
	// __cpu_logical_map[3] : 3
	// cpu_possible_bits[0] 의 0번 비트를 1로 설정
	// cpu_possible_bits[0] 의 1번 비트를 1로 설정
	// cpu_possible_bits[0] 의 2번 비트를 1로 설정
	// cpu_possible_bits[0] 의 3번 비트를 1로 설정
	// __cpu_logical_map[0]에 무조건 부팅 cpu 번호가 들어감
	
	psci_init();
	// NULL 함수

#ifdef CONFIG_SMP
	if (is_smp()) {
		// mdesc->smp_init : NULL
		if (!mdesc->smp_init || !mdesc->smp_init()) {
			if (psci_smp_available())	// psci_smp_available() : false
				smp_set_ops(&psci_smp_ops);
			else if (mdesc->smp)		 // .smp = smp_ops(exynos_smp_ops)
				// mdesc->smp : &exynos_smp_ops
				smp_set_ops(mdesc->smp);
				// 전역 변수 smp_ops : &exynos_smp_ops
		}
		smp_init_cpus();	// exynos_smp_init_cpus() 호출
		// Cortex-A15에서는 따로 하는 일이 없음
		// cpu_possible_bits를 수정하는데, 이 작업은 arm_dt_init_cpu_maps()에서 수행하였음
		smp_build_mpidr_hash();
		// mpidr_hash 구조체 값을 설정함
	}
#endif

	if (!is_smp())
		hyp_mode_check();

	reserve_crashkernel();
	// Null 함수

#ifdef CONFIG_MULTI_IRQ_HANDLER
	handle_arch_irq = mdesc->handle_irq;
	// handle_arch_irq : NULL
#endif

#ifdef CONFIG_VT
#if defined(CONFIG_VGA_CONSOLE)		// 통과
	conswitchp = &vga_con;
#elif defined(CONFIG_DUMMY_CONSOLE)	// 이쪽으로 들어옴
	conswitchp = &dummy_con;
#endif
#endif

	if (mdesc->init_early)		// NULL
		mdesc->init_early();
}


static int __init topology_init(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct cpuinfo_arm *cpuinfo = &per_cpu(cpu_data, cpu);
		cpuinfo->cpu.hotpluggable = 1;
		register_cpu(&cpuinfo->cpu, cpu);
	}

	return 0;
}
subsys_initcall(topology_init);

#ifdef CONFIG_HAVE_PROC_CPU
static int __init proc_cpu_init(void)
{
	struct proc_dir_entry *res;

	res = proc_mkdir("cpu", NULL);
	if (!res)
		return -ENOMEM;
	return 0;
}
fs_initcall(proc_cpu_init);
#endif

static const char *hwcap_str[] = {
	"swp",
	"half",
	"thumb",
	"26bit",
	"fastmult",
	"fpa",
	"vfp",
	"edsp",
	"java",
	"iwmmxt",
	"crunch",
	"thumbee",
	"neon",
	"vfpv3",
	"vfpv3d16",
	"tls",
	"vfpv4",
	"idiva",
	"idivt",
	"vfpd32",
	"lpae",
	NULL
};

static int c_show(struct seq_file *m, void *v)
{
	int i, j;
	u32 cpuid;

	for_each_online_cpu(i) {
		/*
		 * glibc reads /proc/cpuinfo to determine the number of
		 * online processors, looking for lines beginning with
		 * "processor".  Give glibc what it expects.
		 */
		seq_printf(m, "processor\t: %d\n", i);
		cpuid = is_smp() ? per_cpu(cpu_data, i).cpuid : read_cpuid_id();
		seq_printf(m, "model name\t: %s rev %d (%s)\n",
			   cpu_name, cpuid & 15, elf_platform);

#if defined(CONFIG_SMP)
		seq_printf(m, "BogoMIPS\t: %lu.%02lu\n",
			   per_cpu(cpu_data, i).loops_per_jiffy / (500000UL/HZ),
			   (per_cpu(cpu_data, i).loops_per_jiffy / (5000UL/HZ)) % 100);
#else
		seq_printf(m, "BogoMIPS\t: %lu.%02lu\n",
			   loops_per_jiffy / (500000/HZ),
			   (loops_per_jiffy / (5000/HZ)) % 100);
#endif
		/* dump out the processor features */
		seq_puts(m, "Features\t: ");

		for (j = 0; hwcap_str[j]; j++)
			if (elf_hwcap & (1 << j))
				seq_printf(m, "%s ", hwcap_str[j]);

		seq_printf(m, "\nCPU implementer\t: 0x%02x\n", cpuid >> 24);
		seq_printf(m, "CPU architecture: %s\n",
			   proc_arch[cpu_architecture()]);

		if ((cpuid & 0x0008f000) == 0x00000000) {
			/* pre-ARM7 */
			seq_printf(m, "CPU part\t: %07x\n", cpuid >> 4);
		} else {
			if ((cpuid & 0x0008f000) == 0x00007000) {
				/* ARM7 */
				seq_printf(m, "CPU variant\t: 0x%02x\n",
					   (cpuid >> 16) & 127);
			} else {
				/* post-ARM7 */
				seq_printf(m, "CPU variant\t: 0x%x\n",
					   (cpuid >> 20) & 15);
			}
			seq_printf(m, "CPU part\t: 0x%03x\n",
				   (cpuid >> 4) & 0xfff);
		}
		seq_printf(m, "CPU revision\t: %d\n\n", cpuid & 15);
	}

	seq_printf(m, "Hardware\t: %s\n", machine_name);
	seq_printf(m, "Revision\t: %04x\n", system_rev);
	seq_printf(m, "Serial\t\t: %08x%08x\n",
		   system_serial_high, system_serial_low);

	return 0;
}

static void *c_start(struct seq_file *m, loff_t *pos)
{
	return *pos < 1 ? (void *)1 : NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return NULL;
}

static void c_stop(struct seq_file *m, void *v)
{
}

const struct seq_operations cpuinfo_op = {
	.start	= c_start,
	.next	= c_next,
	.stop	= c_stop,
	.show	= c_show
};
