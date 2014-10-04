/*
 * Copyright (C) 2012 Thomas Petazzoni
 *
 * Thomas Petazzoni <thomas.petazzoni@free-electrons.com>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/init.h>
#include <linux/of_irq.h>

#include "irqchip.h"

/*
 * This special of_device_id is the sentinel at the end of the
 * of_device_id[] array of all irqchips. It is automatically placed at
 * the end of the array by the linker, thanks to being part of a
 * special section.
 */
static const struct of_device_id
irqchip_of_match_end __used __section(__irqchip_of_end);

extern struct of_device_id __irqchip_begin[];

void __init irqchip_init(void)
{
	// __irqchip_begin : 섹션을 이용해 만들어진 배열임
	// 배열에는 원소가 하나 밖에 없음
	// IRQCHIP_DECLARE(exynos4210_combiner, "samsung,exynos4210-combiner", combiner_of_init)으로 만들어진 것
	// static const struct of_device_id irqchip_of_match_exynos4210_combiner __used __section(__irqchip_of_table) = {
	// 	.compatible = "samsung,exynos4210-combiner",
	// 	.data = combiner_of_init
	// }
	of_irq_init(__irqchip_begin);
}
