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
<<<<<<< HEAD

		// cpuidx : 1
		for (j = 0; j < cpuidx; j++)
			// tmp_map[0] : 0xFF000000
=======
		for (j = 0; j < cpuidx; j++)
>>>>>>> 3.11.1
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

/**
 * setup_machine_fdt - Machine setup when an dtb was passed to the kernel
 * @dt_phys: physical address of dt blob
 *
 * If a dtb was passed to the kernel in r2, then use it to choose the
 * correct machine_desc and to setup the system.
 */
// dt_phys : DTB가 위치한 시작 주소
struct machine_desc * __init setup_machine_fdt(unsigned int dt_phys)
{
	struct boot_param_header *devtree;
	struct machine_desc *mdesc, *mdesc_best = NULL;
	unsigned int score, mdesc_score = ~1;
	unsigned long dt_root;
	const char *model;

#ifdef CONFIG_ARCH_MULTIPLATFORM	// N
	DT_MACHINE_START(GENERIC_DT, "Generic DT based system")
	MACHINE_END

	mdesc_best = (struct machine_desc *)&__mach_desc_GENERIC_DT;
#endif

	if (!dt_phys)		// DTB가 넘어왔으므로 통과됨
		return NULL;

	devtree = phys_to_virt(dt_phys);
	// devtree : DTB의 가상 주소

	/* check device tree validity */
	if (be32_to_cpu(devtree->magic) != OF_DT_HEADER)
		// be32_to_cpu(number) : 빅 엔디안 형태인 number를 CPU에 맞게 바꿔줌
		// 			 여기서는 리틀 엔디안 형태로 변경됨
		// DTB의 매직 넘버는 빅 엔디안 형태로 저장되어 있기 때문에
		// 비교 연산을 수행하려면 리틀 엔디안 형태로 바꾼 뒤 비교해야함
		return NULL;

	/* Search the mdescs for the 'best' compatible value match */
	initial_boot_params = devtree;
	// DTB의 가상 주소를 대입

	dt_root = of_get_flat_dt_root();
	// root 노드의 첫 번째 property 시작 주소를 dt_root에 저장

	for_each_machine_desc(mdesc) {
	//for (p = __arch_info_begin; p < __arch_info_end; p++)
	// __arch_info_begin ~ __arch_info_end 에서는 컴파일시 만들어진 machine_desc들이 전부 모여있음.
	// arch/arm/mach-* 폴더 내부에 각 제조사별 machine_desc를 생성하는 코드들이 들어 있음.
	// 각 machine_desc를 하나하나 방문하면서 아래 코드들이 수행됨
		score = of_flat_dt_match(dt_root, mdesc->dt_compat);
		// DTB의 compatible property를 이용해 현재 mdesc와 일치 정도를 비교한 뒤 반환
		// score : 1 (일치)
		// score : 1 이상 (호환 가능)
		// score : 0 (호환 불가)
		if (score > 0 && score < mdesc_score) {
			mdesc_best = mdesc;
			mdesc_score = score;
			// 호환 가능한 것을 찾은 경우 이 값을 저장해 둠.
			// 스코어 점수를 기록해서 가장 일치하는 machine_desc를 찾아야 함.
		}
	}
	// 모든 machine_desc를 비교 대상으로 삼아 DTB에 저장된 보드와 가장 일치하는 machine_desc를 찾아냄
	// 즉, score가 최대한 1에 가까운 것으로 찾음
	// 전체 machine_desc를 가지고 전부 비교해 봄

	if (!mdesc_best) {		// 호환 가능한 machine_desc를 찾지 못한 경우
		const char *prop;
		long size;

		early_print("\nError: unrecognized/unsupported "
			    "device tree compatible list:\n[ ");

		prop = of_get_flat_dt_prop(dt_root, "compatible", &size);
		while (size > 0) {
			early_print("'%s' ", prop);
			size -= strlen(prop) + 1;
			prop += strlen(prop) + 1;
		}
		early_print("]\n\n");

		dump_machine_table(); /* does not return */
	}

	model = of_get_flat_dt_prop(dt_root, "model", NULL);
	// model property의 데이터 시작 주소를 model에 저장

	if (!model)
		model = of_get_flat_dt_prop(dt_root, "compatible", NULL);
		// model property를 못 찾은 경우
		// compatible property의 데이터 시작 주소를 model에 저장

	if (!model)
		model = "<unknown>";
		// 그 것도 못 찾은 경우

	pr_info("Machine: %s, model: %s\n", mdesc_best->name, model);
	// Machine과 model 정보를 출력

	/* Retrieve various information from the /chosen node */
	of_scan_flat_dt(early_init_dt_scan_chosen, boot_command_line);
	// DTB chosen 노드의 bootargs property에서 데이터를 뽑아와 boot_command_line에 저장
	// of_scan_flat_dt : DTB의 노드마다 첫 번째 인자로 주어진 함수를 호출함.
	//		     그 함수가 1을 반환할 때까지 노드를 계속 바꾸면서 호출
	// early_init_dt_scan_chosen : 노드가 chosen 노드인지 확인한 후
	//			       맞으면 bootargs property의 데이터를 가져와 boot_command_line에 저장
	// boot_command_line : "console=ttySAC2,115200 init=/linuxrc"

	/* Initialize {size,address}-cells info */
	of_scan_flat_dt(early_init_dt_scan_root, NULL);
	// early_init_dt_scan_root : 노드가 root 노드인지 확인한 후
	//			     맞으면 #size-cells, #address-cells 값을 뽑아와
	//			     dt_root_size_cells, dt_root_addr_cells 변수에 각각 저장

	/* Setup memory, calling early_init_dt_add_memory_arch */
	of_scan_flat_dt(early_init_dt_scan_memory, NULL);
	// early_init_dt_scan_memory : 노드가 memory 정보인지 확인한 후
	// 맞는 경우 base와 size 정보를 뽑아와 아래 구조체를 초기화함.
	// meminfo.nr_banks : 1
	// meminfo.bank[0].start : 0x20000000
	// meminfo.bank[0].size : 0x80000000
	// 정보를 뽑을 때 위에서 처리한 dt_root_size_cells, dt_root_addr_cells를 이용함

	/* Change machine number to match the mdesc we're using */
	__machine_arch_type = mdesc_best->nr;
	// __machine_arch_type : 0xFFFFFFFF 으로 저장됨

	// mdesc_best : mach-exynos5-dt.c 에 선언되어 있음 
	return mdesc_best;
}
