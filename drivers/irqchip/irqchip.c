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
	// __irqchip_begin : 섹션을 이용해 만들어진 배열이며 IRQCHIP_DECLARE로 만들어짐
	// IRQCHIP_DECLARE(exynos4210_combiner, "samsung,exynos4210-combiner", combiner_of_init)으로 만들어진 것
	// static const struct of_device_id irqchip_of_match_exynos4210_combiner __used __section(__irqchip_of_table) = {
	// 	.compatible = "samsung,exynos4210-combiner",
	// 	.data = combiner_of_init
	// }
	// IRQCHIP_DECLARE(cortex_a15_gic, "arm,cortex-a15-gic", gic_of_init);
	// static const struct of_device_id irqchip_of_match_cortex_a15_gic __used __section(__irqchip_of_table) = {
	// 	.compatible = "arm,cortex-a15-gic",
	// 	.data = gic_of_init
	// }
	// IRQCHIP_DECLARE(cortex_a9_gic, "arm,cortex-a9-gic", gic_of_init);
	// static const struct of_device_id irqchip_of_match_cortex_a9_gic __used __section(__irqchip_of_table) = {
	// 	.compatible = "arm,cortex-a9-gic",
	// 	.data = gic_of_init
	// }
	// IRQCHIP_DECLARE(msm_8660_qgic, "qcom,msm-8660-qgic", gic_of_init);
	// static const struct of_device_id irqchip_of_match_msm_8660_qgic __used __section(__irqchip_of_table) = {
	// 	.compatible = "qcom,msm-8660-qgic",
	// 	.data = gic_of_init
	// }
	// IRQCHIP_DECLARE(msm_qgic2, "qcom,msm-qgic2", gic_of_init);
	// static const struct of_device_id irqchip_of_match_msm_qgic2 __used __section(__irqchip_of_table) = {
	// 	.compatible = "qcom,msm-qgic2",
	// 	.data = gic_of_init
	// }
	of_irq_init(__irqchip_begin);
	// irq 관련 init 수행
	// gic_of_init, combiner_of_init이 수행됨
	// gic 메모리를 가상 메모리 위로 올려주고,
	// gic 하드웨어 초기화 및 struct irq_desc와 struct irq_domain을
	// 설정해줌
	// combiner 메모리를 가상 메모리 위로 올려주고,
	// combiner 하드웨어 초기화 및 struct irq_desc와 struct irq_domain을
	// 설정해줌
	// irq_desc(160 ~ 415), irq_domain을 할당하고 설정
	// combiner_chip_data 구조체를 만들어주고
	// irq_desc(32 ~ 63)에 combiner_chip_data를 연결해줌
	// 그 뒤, gic의 32 ~ 63번 인터럽트 enable 수행
	// 즉, gic 0 ~ 15, 32 ~ 63만 인터럽트 enable 상태임
}
