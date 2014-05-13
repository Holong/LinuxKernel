/*
 *  linux/arch/arm/kernel/devtree.c
 *
 *  Copyright (C) 2009 Canonical Ltd. <jeremy.kerr@canonical.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/init.h>
#include <linux/export.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/bootmem.h>
#include <linux/memblock.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>

#include <asm/cputype.h>
#include <asm/setup.h>
#include <asm/page.h>
#include <asm/smp_plat.h>
#include <asm/mach/arch.h>
#include <asm/mach-types.h>

void __init early_init_dt_add_memory_arch(u64 base, u64 size)
{
	arm_add_memory(base, size);
}

void * __init early_init_dt_alloc_memory_arch(u64 size, u64 align)
{
	return alloc_bootmem_align(size, align);
}

void __init arm_dt_memblock_reserve(void)
{
	u64 *reserve_map, base, size;

	// initial_boot_params : DTB가 저장된 공간의 주소
	if (!initial_boot_params)
		return;

	/* Reserve the dtb region */
	memblock_reserve(virt_to_phys(initial_boot_params),
			 be32_to_cpu(initial_boot_params->totalsize));
	// DTB가 저장된 공간을 reserved 영역에 등록함

	/*
	 * Process the reserve map.  This will probably overlap the initrd
	 * and dtb locations which are already reserved, but overlaping
	 * doesn't hurt anything
	 */
	reserve_map = ((void*)initial_boot_params) +
			be32_to_cpu(initial_boot_params->off_mem_rsvmap);
	// DTB 내부의 memory reserv map 부분의 시작 주소가 저장됨

	while (1) {
		base = be64_to_cpup(reserve_map++);
		size = be64_to_cpup(reserve_map++);
		if (!size)
			break;
		memblock_reserve(base, size);
		// DTB 내부의 memory reserve map 영역에 저장되어 있는
		// 시작 주소와 사이즈 조합을 이용해
		// reserve 영역에 등록함
		// 현재 DTB에는 없음
	}
}

/*
 * arm_dt_init_cpu_maps - Function retrieves cpu nodes from the device tree
 * and builds the cpu logical map array containing MPIDR values related to
 * logical cpus
 *
 * Updates the cpu possible mask with the number of parsed cpu nodes
 */
void __init arm_dt_init_cpu_maps(void)
{
	/*
	 * Temp logical map is initialized with UINT_MAX values that are
	 * considered invalid logical map entries since the logical map must
	 * contain a list of MPIDR[23:0] values where MPIDR[31:24] must
	 * read as 0.
	 */
	struct device_node *cpu, *cpus;
	u32 i, j, cpuidx = 1;
	u32 mpidr = is_smp() ? read_cpuid_mpidr() & MPIDR_HWID_BITMASK : 0;
	// mpidr : MPIDR의 AFF0, AFF1, AFF2 값을 가져옴

	// NR_CPUS : 4
	// MPIDR_INVALID : 0xFF000000
	u32 tmp_map[NR_CPUS] = { [0 ... NR_CPUS-1] = MPIDR_INVALID };
	bool bootcpu_valid = false;
	cpus = of_find_node_by_path("/cpus");
	// cpus : cpus 노드의 struct device_node 주소

	if (!cpus)
		return;

	for_each_child_of_node(cpus, cpu) {
	// for (cpu = of_get_next_child(cpus, NULL); cpu != NULL; cpu = of_get_next_child(cpus, cpu))
		// cpu : cpu@0 노드의 struct device_node 주소
		u32 hwid;

		// cpu->type : "cpu"
		if (of_node_cmp(cpu->type, "cpu"))
			continue;

		pr_debug(" * %s...\n", cpu->full_name);
		/*
		 * A device tree containing CPU nodes with missing "reg"
		 * properties is considered invalid to build the
		 * cpu_logical_map.
		 */
		if (of_property_read_u32(cpu, "reg", &hwid)) {  // hwid : 0x0
			pr_debug(" * %s missing reg property\n",
				     cpu->full_name);
			return;
		}

		/*
		 * 8 MSBs must be set to 0 in the DT since the reg property
		 * defines the MPIDR[23:0].
		 */
		if (hwid & ~MPIDR_HWID_BITMASK)	// 통과
			return;

		/*
		 * Duplicate MPIDRs are a recipe for disaster.
		 * Scan all initialized entries and check for
		 * duplicates. If any is found just bail out.
		 * temp values were initialized to UINT_MAX
		 * to avoid matching valid MPIDR[23:0] values.
		 */

		// cpuidx : 1
		for (j = 0; j < cpuidx; j++)
			// tmp_map[0] : 0xFF000000
			if (WARN(tmp_map[j] == hwid, "Duplicate /cpu reg "
						     "properties in the DT\n"))
				return;

		/*
		 * Build a stashed array of MPIDR values. Numbering scheme
		 * requires that if detected the boot CPU must be assigned
		 * logical id 0. Other CPUs get sequential indexes starting
		 * from 1. If a CPU node with a reg property matching the
		 * boot CPU MPIDR is detected, this is recorded so that the
		 * logical map built from DT is validated and can be used
		 * to override the map created in smp_setup_processor_id().
		 */
		if (hwid == mpidr) {
			i = 0;
			bootcpu_valid = true;
		} else {
			i = cpuidx++;
		}

		if (WARN(cpuidx > nr_cpu_ids, "DT /cpu %u nodes greater than "
					       "max cores %u, capping them\n",
					       cpuidx, nr_cpu_ids)) {
			cpuidx = nr_cpu_ids;
			break;
		}

		tmp_map[i] = hwid;

		// bootcpu의 CPUID가 0인 경우
		// tmp_map[0] : 0
		// tmp_map[1] : 1
		// tmp_map[2] : 2
		// tmp_map[3] : 3

		// bootcpu의 CPUID가 1인 경우
		// tmp_map[0] : 1
		// tmp_map[1] : 0
		// tmp_map[2] : 2
		// tmp_map[3] : 3
	}

	if (!bootcpu_valid) {
		pr_warn("DT missing boot CPU MPIDR[23:0], fall back to default cpu_logical_map\n");
		return;
	}

	/*
	 * Since the boot CPU node contains proper data, and all nodes have
	 * a reg property, the DT CPU list can be considered valid and the
	 * logical map created in smp_setup_processor_id() can be overridden
	 */
	for (i = 0; i < cpuidx; i++) {
		set_cpu_possible(i, true);
		cpu_logical_map(i) = tmp_map[i];
		pr_debug("cpu logical map 0x%x\n", cpu_logical_map(i));
	}
	// __cpu_logical_map[0] : 0
	// __cpu_logical_map[1] : 1
	// __cpu_logical_map[2] : 2
	// __cpu_logical_map[3] : 3

	// cpu_possible_bits[0] 의 0번 비트를 1로 설정
	// cpu_possible_bits[0] 의 1번 비트를 1로 설정
	// cpu_possible_bits[0] 의 2번 비트를 1로 설정
	// cpu_possible_bits[0] 의 3번 비트를 1로 설정
	
	// __cpu_logical_map[0]에 무조건 부팅 cpu 번호가 들어감
}

bool arch_match_cpu_phys_id(int cpu, u64 phys_id)
{
	return phys_id == cpu_logical_map(cpu);
}

static const void * __init arch_get_next_mach(const char *const **match)
{
	static const struct machine_desc *mdesc = __arch_info_begin;
	const struct machine_desc *m = mdesc;

	if (m >= __arch_info_end)
		return NULL;

	mdesc++;
	*match = m->dt_compat;
	return m;
}

/**
 * setup_machine_fdt - Machine setup when an dtb was passed to the kernel
 * @dt_phys: physical address of dt blob
 *
 * If a dtb was passed to the kernel in r2, then use it to choose the
 * correct machine_desc and to setup the system.
 */
// dt_phys : DTB가 위치한 시작 주소
const struct machine_desc * __init setup_machine_fdt(unsigned int dt_phys)
{
	const struct machine_desc *mdesc, *mdesc_best = NULL;

#ifdef CONFIG_ARCH_MULTIPLATFORM	// N
	DT_MACHINE_START(GENERIC_DT, "Generic DT based system")
	MACHINE_END

	mdesc_best = &__mach_desc_GENERIC_DT;
#endif

	if (!dt_phys || !early_init_dt_scan(phys_to_virt(dt_phys)))
		return NULL;

	mdesc = of_flat_dt_match_machine(mdesc_best, arch_get_next_mach);

	if (!mdesc) {			// 호환 가능한 dtb를 찾지 못한 경우
		const char *prop;
		long size;
		unsigned long dt_root;

		early_print("\nError: unrecognized/unsupported "
			    "device tree compatible list:\n[ ");

		dt_root = of_get_flat_dt_root();
		prop = of_get_flat_dt_prop(dt_root, "compatible", &size);
		while (size > 0) {
			early_print("'%s' ", prop);
			size -= strlen(prop) + 1;
			prop += strlen(prop) + 1;
		}
		early_print("]\n\n");

		dump_machine_table(); /* does not return */
	}

	/* Change machine number to match the mdesc we're using */
	__machine_arch_type = mdesc->nr;
	// __machine_arch_type : 0xFFFFFFFF 으로 저장됨

	// mdesc_best : mach-exynos5-dt.c 에 선언되어 있음 
	return mdesc;
}
