/*
 * Copyright (c) 2013 Samsung Electronics Co., Ltd.
 * Copyright (c) 2013 Linaro Ltd.
 * Author: Thomas Abraham <thomas.ab@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This file includes utility functions to register clocks to common
 * clock framework for Samsung platforms.
*/

#include <linux/syscore_ops.h>
#include "clk.h"

static DEFINE_SPINLOCK(lock);
static struct clk **clk_table;
static void __iomem *reg_base;
#ifdef CONFIG_OF
static struct clk_onecell_data clk_data;
#endif

#ifdef CONFIG_PM_SLEEP
static struct samsung_clk_reg_dump *reg_dump;
static unsigned long nr_reg_dump;

static int samsung_clk_suspend(void)
{
	struct samsung_clk_reg_dump *rd = reg_dump;
	unsigned long i;

	for (i = 0; i < nr_reg_dump; i++, rd++)
		rd->value = __raw_readl(reg_base + rd->offset);

	return 0;
}

static void samsung_clk_resume(void)
{
	struct samsung_clk_reg_dump *rd = reg_dump;
	unsigned long i;

	for (i = 0; i < nr_reg_dump; i++, rd++)
		__raw_writel(rd->value, reg_base + rd->offset);
}

static struct syscore_ops samsung_clk_syscore_ops = {
	.suspend	= samsung_clk_suspend,
	.resume		= samsung_clk_resume,
};
#endif /* CONFIG_PM_SLEEP */

/* setup the essentials required to support clock lookup using ccf */
// np : clock-controller의 노드 주소, base : 0xF0040000, nr_clks : 769
// rdump : exynos5420_clk_regs, nr_rdump : 59, soc_rdump :  NULL, nr_soc_rdump : 0
void __init samsung_clk_init(struct device_node *np, void __iomem *base,
		unsigned long nr_clks, unsigned long *rdump,
		unsigned long nr_rdump, unsigned long *soc_rdump,
		unsigned long nr_soc_rdump)
{
	// base : 0xF0040000 (clk-controller의 가상 메모리 매핑 주소)
	reg_base = base;
	// reg_base : 0xF0040000

#ifdef CONFIG_PM_SLEEP	// Y
	// rdump : exynos5420_clk_regs, nr_rdump : 59
	if (rdump && nr_rdump) {
		unsigned int idx;

		// sizeof(struct samsung_clk_reg_dump) : 8, nr_rdump : 59, nr_soc_rdump : 0, GFP_KERNEL
		// kzalloc(8 * 59 , GFP_KERNEL)로 call이 됨
		reg_dump = kzalloc(sizeof(struct samsung_clk_reg_dump)
				* (nr_rdump + nr_soc_rdump), GFP_KERNEL);
		// 59개의 struct samsung_clk_reg_dump 공간을 슬랩에서 할당받고
		// 시작 주소를 반환함

		// reg_dump : samsung_clk_reg_dump[]
		if (!reg_dump) {
			pr_err("%s: memory alloc for register dump failed\n",
					__func__);
			return;
		}

		// nr_rdump : 59
		for (idx = 0; idx < nr_rdump; idx++)
			reg_dump[idx].offset = rdump[idx];
		// reg_dump[0 ... 58]의 offset 멤버 값을 exynos5420_clk_regs의 값으로 초기화함

		// nr_soc_rdump : 0
		for (idx = 0; idx < nr_soc_rdump; idx++)
			reg_dump[nr_rdump + idx].offset = soc_rdump[idx];
		// 통과

		// nr_rdump : 59, nr_soc_rdump : 0
		nr_reg_dump = nr_rdump + nr_soc_rdump;
		// nr_reg_dump : 59
		
		// samsung_clk_syscore_ops : 전역 구조체
		register_syscore_ops(&samsung_clk_syscore_ops);
		// syscore_ops_list에 samsung_clk_syscore_ops를 연결해둠
	}
#endif

	// sizeof(struct clk *) : 4, nr_clks : 769, GFP_KERNEL
	// kzalloc(4 * 769, GFP_KERNEL)이 call
	clk_table = kzalloc(sizeof(struct clk *) * nr_clks, GFP_KERNEL);
	// 크기가 769인 struct clk용 포인터 배열을 할당받고 시작 주소를 반환
	// clk_table : 배열의 시작 주소
	
	// clk_table : 할당받은 배열
	if (!clk_table)
		panic("could not allocate clock lookup table\n");

	// np : clock-controller의 노드 주소
	if (!np)
		return;
	// 통과

#ifdef CONFIG_OF	// Y
	clk_data.clks = clk_table;
	clk_data.clk_num = nr_clks;
	// clk_data라는 전역 구조체에 clk_table과 nr_clks 값을 저장해둠
	
	// np : clock-controller의 노드 주소, of_clk_src_onecell_get : 함수 포인터
	// clk_data : 전역 구조체
	of_clk_add_provider(np, of_clk_src_onecell_get, &clk_data);
	// struct of_clk_provider를 새로 할당받고 내부 값을 초기화
	// of_clk_provider.node : clock-controller 노드의 시작 주소
	// of_clk_provider.data : &clk_data
	// of_clk_provider.get : clk_src_get
	// 이 구조체를 of_clk_providers 리스트에 연결함
#endif
}

/* add a clock instance to the clock lookup table used for dt based lookup */
// clk : 할당받은 struct clk 공간, id : fin_pll
void samsung_clk_add_lookup(struct clk *clk, unsigned int id)
{
	// clk_table : 이전에 만든 struct clk용 포인터 배열
	// id : fin_pll (1)
	if (clk_table && id)
		clk_table[id] = clk;
		// clk_table[fin_pll] : clk
}

/* register a list of aliases */
void __init samsung_clk_register_alias(struct samsung_clock_alias *list,
					unsigned int nr_clk)
{
	struct clk *clk;
	unsigned int idx, ret;

	if (!clk_table) {
		pr_err("%s: clock table missing\n", __func__);
		return;
	}

	for (idx = 0; idx < nr_clk; idx++, list++) {
		if (!list->id) {
			pr_err("%s: clock id missing for index %d\n", __func__,
				idx);
			continue;
		}

		clk = clk_table[list->id];
		if (!clk) {
			pr_err("%s: failed to find clock %d\n", __func__,
				list->id);
			continue;
		}

		ret = clk_register_clkdev(clk, list->alias, list->dev_name);
		if (ret)
			pr_err("%s: failed to register lookup %s\n",
					__func__, list->alias);
	}
}

/* register a list of fixed clocks */
// list: exynos5420_fixed_rate_ext_clks, nr_clk : 1
void __init samsung_clk_register_fixed_rate(
		struct samsung_fixed_rate_clock *list, unsigned int nr_clk)
{
	struct clk *clk;
	unsigned int idx, ret;

	// nr_clk : 1, list : exynos5420_fixed_rate_ext_clks[0]
	for (idx = 0; idx < nr_clk; idx++, list++) {

		// NULL, list->name : "fin_pll", list->parent_name : NULL,
		// list->flags : CLK_IS_ROOT, list->fixed_rate : 24000000
		clk = clk_register_fixed_rate(NULL, list->name,
			list->parent_name, list->flags, list->fixed_rate);
		// struct clk_fixed_rate 공간을 할당받고 초기화한 뒤,
		// 이 구조체의 hw 멤버 주소를 struct clk의 hw 멤버에 저장 시켜둠
		// struct clk 공간을 할당받고, 인자로 넘어가는 값을 이용해
		// 내부를 초기화 해줌
		// 결국 clk를 통해 struct clk_fixed_rate를 찾을 수 있음
		//
		// clk : 할당받은 struct clk 공간

		if (IS_ERR(clk)) {
			pr_err("%s: failed to register clock %s\n", __func__,
				list->name);
			continue;
		}

		// clk : 할당받은 struct clk 공간, list->id : fin_pll
		samsung_clk_add_lookup(clk, list->id);
		// 이전에 만들어 둔 clk_table의 fin_pll에
		// 직전에 만든 struct clk의 주소를 저장함
		//
		// clk_table[fin_pll] : clk

		/*
		 * Unconditionally add a clock lookup for the fixed rate clocks.
		 * There are not many of these on any of Samsung platforms.
		 */
		// clk : 할당받은 struct clk 공간
		// list->name : "fin_pll", NULL
		ret = clk_register_clkdev(clk, list->name, NULL);
		// struct clk_lookup_alloc을 할당받고, 내부 초기화
		// 할당받은 구조체 내부에 존재하는 clk_lookup 구조체를 clocks 리스트에 연결
		
		// ret : 0
		if (ret)
			pr_err("%s: failed to register clock lookup for %s",
				__func__, list->name);
	}
}

/* register a list of fixed factor clocks */
void __init samsung_clk_register_fixed_factor(
		struct samsung_fixed_factor_clock *list, unsigned int nr_clk)
{
	struct clk *clk;
	unsigned int idx;

	for (idx = 0; idx < nr_clk; idx++, list++) {
		clk = clk_register_fixed_factor(NULL, list->name,
			list->parent_name, list->flags, list->mult, list->div);
		if (IS_ERR(clk)) {
			pr_err("%s: failed to register clock %s\n", __func__,
				list->name);
			continue;
		}

		samsung_clk_add_lookup(clk, list->id);
	}
}

/* register a list of mux clocks */
void __init samsung_clk_register_mux(struct samsung_mux_clock *list,
					unsigned int nr_clk)
{
	struct clk *clk;
	unsigned int idx, ret;

	for (idx = 0; idx < nr_clk; idx++, list++) {
		clk = clk_register_mux(NULL, list->name, list->parent_names,
			list->num_parents, list->flags, reg_base + list->offset,
			list->shift, list->width, list->mux_flags, &lock);
		if (IS_ERR(clk)) {
			pr_err("%s: failed to register clock %s\n", __func__,
				list->name);
			continue;
		}

		samsung_clk_add_lookup(clk, list->id);

		/* register a clock lookup only if a clock alias is specified */
		if (list->alias) {
			ret = clk_register_clkdev(clk, list->alias,
						list->dev_name);
			if (ret)
				pr_err("%s: failed to register lookup %s\n",
						__func__, list->alias);
		}
	}
}

/* register a list of div clocks */
void __init samsung_clk_register_div(struct samsung_div_clock *list,
					unsigned int nr_clk)
{
	struct clk *clk;
	unsigned int idx, ret;

	for (idx = 0; idx < nr_clk; idx++, list++) {
		if (list->table)
			clk = clk_register_divider_table(NULL, list->name,
					list->parent_name, list->flags,
					reg_base + list->offset, list->shift,
					list->width, list->div_flags,
					list->table, &lock);
		else
			clk = clk_register_divider(NULL, list->name,
					list->parent_name, list->flags,
					reg_base + list->offset, list->shift,
					list->width, list->div_flags, &lock);
		if (IS_ERR(clk)) {
			pr_err("%s: failed to register clock %s\n", __func__,
				list->name);
			continue;
		}

		samsung_clk_add_lookup(clk, list->id);

		/* register a clock lookup only if a clock alias is specified */
		if (list->alias) {
			ret = clk_register_clkdev(clk, list->alias,
						list->dev_name);
			if (ret)
				pr_err("%s: failed to register lookup %s\n",
						__func__, list->alias);
		}
	}
}

/* register a list of gate clocks */
void __init samsung_clk_register_gate(struct samsung_gate_clock *list,
						unsigned int nr_clk)
{
	struct clk *clk;
	unsigned int idx, ret;

	for (idx = 0; idx < nr_clk; idx++, list++) {
		clk = clk_register_gate(NULL, list->name, list->parent_name,
				list->flags, reg_base + list->offset,
				list->bit_idx, list->gate_flags, &lock);
		if (IS_ERR(clk)) {
			pr_err("%s: failed to register clock %s\n", __func__,
				list->name);
			continue;
		}

		/* register a clock lookup only if a clock alias is specified */
		if (list->alias) {
			ret = clk_register_clkdev(clk, list->alias,
							list->dev_name);
			if (ret)
				pr_err("%s: failed to register lookup %s\n",
					__func__, list->alias);
		}

		samsung_clk_add_lookup(clk, list->id);
	}
}

/*
 * obtain the clock speed of all external fixed clock sources from device
 * tree and register it
 */
#ifdef CONFIG_OF
// fixed_rate_clk : exynos5420_fixed_rate_ext_clks
// nr_fixed_rate_clk : 1
// clk_matches : ext_clk_match
void __init samsung_clk_of_register_fixed_ext(
			struct samsung_fixed_rate_clock *fixed_rate_clk,
			unsigned int nr_fixed_rate_clk,
			struct of_device_id *clk_matches)
{
	const struct of_device_id *match;
	struct device_node *np;
	u32 freq;

	for_each_matching_node_and_match(np, clk_matches, &match) {
	// for (np = of_find_matching_node_and_match(NULL, clk_matches, &match);
	// 	dn; dn = of_find_matching_node_and_match(np, clk_matches, &match))
	// 이 매크로를 사용하면 clk_matches에 존재하는 compatible 정보들을 이용해 디바이스 트리에서
	// 알맞는 노드를 뽑아내 np에 넣고 반복문 내부를 수행한다.
	// 다음 반복문에서는 다음에 일치하는 노드를 찾아낸다.
	// match는 현재 np가 clk_matches 내부의 어떤 것과 일치하는지를 가리키게 된다.
	//
	// 일치하는 노드는 oscclk 이다.
	// np : oscclk 노드 주소
		if (of_property_read_u32(np, "clock-frequency", &freq))
			// oscclk 노드에서 clock-frequency 속성이 존재하는 지 찾고
			// 존재하면 freq에 그 값을 저장
			// freq : 24000000
			// 읽어오면 0을 반환함
			continue;

		// match->data : 0, freq : 24000000
		fixed_rate_clk[(u32)match->data].fixed_rate = freq;
		// exynos5420_fixed_rate_ext_clk[0].fixed_rate : 24000000
	}

	// fixed_rate_clk : exynos5420_fixed_rate_ext_clks, nr_fixed_rate_clk : 1
	samsung_clk_register_fixed_rate(fixed_rate_clk, nr_fixed_rate_clk);
	// struct clk_fixed_rate 공간을 할당받고 초기화
	// struct clk 공간을 할당받고 초기화 수행
	// 이전에 만들어 둔 clk_table의 fin_pll 위치에 할당받은 struct clk를 저장함
	// struct clk_lookup_alloc을 할당받고, 내부 초기화
	// 할당받은 구조체 내부에 존재하는 clk_lookup 구조체를 clocks 리스트에 연결
	// 결국 생성한 구조체는 clk_fixed_rate, clk, clk_lookup_alloc이 됨
}
#endif

/* utility function to get the rate of a specified clock */
unsigned long _get_rate(const char *clk_name)
{
	struct clk *clk;

	clk = __clk_lookup(clk_name);
	if (!clk) {
		pr_err("%s: could not find clock %s\n", __func__, clk_name);
		return 0;
	}

	return clk_get_rate(clk);
}
