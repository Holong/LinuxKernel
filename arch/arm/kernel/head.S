/*
 *  linux/arch/arm/kernel/head.S
 *
 *  Copyright (C) 1994-2002 Russell King
 *  Copyright (c) 2003 ARM Limited
 *  All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *  Kernel startup code for all 32-bit CPUs
 */
#include <linux/linkage.h>
#include <linux/init.h>

#include <asm/assembler.h>
#include <asm/cp15.h>
#include <asm/domain.h>
#include <asm/ptrace.h>
#include <asm/asm-offsets.h>
#include <asm/memory.h>
#include <asm/thread_info.h>
#include <asm/pgtable.h>

#if defined(CONFIG_DEBUG_LL) && !defined(CONFIG_DEBUG_SEMIHOSTING)
#include CONFIG_DEBUG_LL_INCLUDE
#endif

/*
 * swapper_pg_dir is the virtual address of the initial page table.
 * We place the page tables 16K below KERNEL_RAM_VADDR.  Therefore, we must
 * make sure that KERNEL_RAM_VADDR is correctly set.  Currently, we expect
 * the least significant 16 bits to be 0x8000, but we could probably
 * relax this restriction to KERNEL_RAM_VADDR >= PAGE_OFFSET + 0x4000.
 */
#define KERNEL_RAM_VADDR	(PAGE_OFFSET + TEXT_OFFSET)
#if (KERNEL_RAM_VADDR & 0xffff) != 0x8000
#error KERNEL_RAM_VADDR must start at 0xXXXX8000
#endif

#ifdef CONFIG_ARM_LPAE
	/* LPAE requires an additional page for the PGD */
#define PG_DIR_SIZE	0x5000
#define PMD_ORDER	3
#else
#define PG_DIR_SIZE	0x4000
#define PMD_ORDER	2
#endif

	.globl	swapper_pg_dir
	.equ	swapper_pg_dir, KERNEL_RAM_VADDR - PG_DIR_SIZE

	.macro	pgtbl, rd, phys
	add	\rd, \phys, #TEXT_OFFSET - PG_DIR_SIZE
	.endm

/*
 * Kernel startup entry point.
 * ---------------------------
 *
 * This is normally called from the decompressor code.  The requirements
 * are: MMU = off, D-cache = off, I-cache = dont care, r0 = 0,
 * r1 = machine nr, r2 = atags or dtb pointer.
 *
 * This code is mostly position independent, so if you link the kernel at
 * 0xc0008000, you call this at __pa(0xc0008000).
 *
 * See linux/arch/arm/tools/mach-types for the complete list of machine
 * numbers for r1.
 *
 * We're trying to keep crap to a minimum; DO NOT add any machine specific
 * crap here - that's what the boot loader (or in extreme, well justified
 * circumstances, zImage) is for.
 */
	.arm

	__HEAD				// #define __HEAD		.section	".head.text","ax"
					// 그러므로 아래부터는 .head.text 섹션으로 들어가며
					// vmlinux.lds.S 에서 이 섹션이 가장 첫 섹션이 됨
					// 그러므로 압축 푼 커널의 가장 처음 부분임
ENTRY(stext)

 THUMB(	adr	r9, BSYM(1f)	)	@ Kernel is always entered in ARM.
 THUMB(	bx	r9		)	@ If this is a Thumb-2 kernel,
 THUMB(	.thumb			)	@ switch to Thumb now.
 THUMB(1:			)

#ifdef CONFIG_ARM_VIRT_EXT
	bl	__hyp_stub_install	// 하이퍼바이저 통과
#endif
	@ ensure svc mode and all interrupts masked
	safe_svcmode_maskall r9

	mrc	p15, 0, r9, c0, c0		@ get processor id
						// MIDR를 r9에 저장
	bl	__lookup_processor_type		@ r5=procinfo r9=cpuid
						// r5 : __v7_ca15mp_proc_info의 주소가 저장
						// r9 : MIDR
	movs	r10, r5				@ invalid processor (r5=0)?
						// r5가 0인지 확인 + r10에 proc_info 저장
						// 0이면 적합한 아키텍쳐를 찾지 못한 것임
 THUMB( it	eq )		@ force fixup-able long branch encoding
	beq	__error_p			@ yes, error 'p'

#ifdef CONFIG_ARM_LPAE				// 통과
	mrc	p15, 0, r3, c0, c1, 4		@ read ID_MMFR0
	and	r3, r3, #0xf			@ extract VMSA support
	cmp	r3, #5				@ long-descriptor translation table format?
 THUMB( it	lo )				@ force fixup-able long branch encoding
	blo	__error_p			@ only classic page table format
#endif

#ifndef CONFIG_XIP_KERNEL
	adr	r3, 2f				// 2번 레이블의 런타임 주소 저장
	ldmia	r3, {r4, r8}			// r4 : 2번 레이블의 컴파일 타임 주소 저장
						// r8 : PAGE_OFFSET 값 저장 (0xC0000000) (가상 시작 주소)
	sub	r4, r3, r4			@ (PHYS_OFFSET - PAGE_OFFSET)
						// 런타임과 컴파일 타임 사이의 델타 값 계산
	add	r8, r8, r4			@ PHYS_OFFSET
						// 물리 시작 주소 계산해 r8에 저장
#else
	ldr	r8, =PHYS_OFFSET		@ always constant in this case
#endif

	/*
	 * r1 = machine no, r2 = atags or dtb,
	 * r8 = phys_offset, r9 = cpuid, r10 = procinfo
	 */
	bl	__vet_atags			// r2에 ATAG/DTB가 들어 있는지 확인
#ifdef CONFIG_SMP_ON_UP
	bl	__fixup_smp			// 멀티 코어 시스템인지 확인함
						// 멀티 코어이면 따로 처리 없이 복귀
						// 싱글 코어이면 SMP 관련 부분을 UP에서도 돌아갈 수 있도록 처리
#endif
#ifdef CONFIG_ARM_PATCH_PHYS_VIRT
	bl	__fixup_pv_table		// __phys_to_virt, __virt_to_phys 에서 사용된 명령의
						// imm8 값을 현재 델타 값에 맞게 변경시킴
#endif
	bl	__create_page_tables		// 컴파일 타임의 주소를 물리 주소에 매핑하기 위한 section을 설정하였음
						// section table에 저장됨

	/*
	 * The following calls CPU specific code in a position independent
	 * manner.  See arch/arm/mm/proc-*.S for details.  r10 = base of
	 * xxx_proc_info structure selected by __lookup_processor_type
	 * above.  On return, the CPU will be ready for the MMU to be
	 * turned on, and r0 will hold the CPU control register value.
	 */
	ldr	r13, =__mmap_switched		@ address to jump to after
						@ mmu has been enabled
	adr	lr, BSYM(1f)			@ return (PIC) address
	mov	r8, r4				@ set TTBR1 to swapper_pg_dir
						// section table의 시작 주소를 r8로 저장
 ARM(	add	pc, r10, #PROCINFO_INITFUNC	)
						// PROCINFO_INITFUNC : offsetof(struct proc_info_list, __cpu_flush)
						// __v7_ca15mp_setup 함수로 이동
 THUMB(	add	r12, r10, #PROCINFO_INITFUNC	)
 THUMB(	mov	pc, r12				)
1:	b	__enable_mmu
ENDPROC(stext)
	.ltorg
#ifndef CONFIG_XIP_KERNEL
2:	.long	.
	.long	PAGE_OFFSET
#endif

/*
 * Setup the initial page tables.  We only setup the barest
 * amount which are required to get the kernel running, which
 * generally means mapping in the kernel code.
 *
 * r8 = phys_offset, r9 = cpuid, r10 = procinfo
 *
 * Returns:
 *  r0, r3, r5-r7 corrupted
 *  r4 = page table (see ARCH_PGD_SHIFT in asm/memory.h)
 */
__create_page_tables:
	pgtbl	r4, r8				@ page table address
	// add	r4, r8, #TEXT_OFFSET - PG_DIR_SIZE  로 변환됨
	// TEXT_OFFSET : 0x00008000, PG_DIR_SIZE : 0x00004000
	// r8 = PHYS_OFFSET : 0x40000000
	// 그러므로 r4 : 0x40004000 이며 page table의 시작 주소가 됨 

	/*
	 * Clear the swapper page table
	 */
	mov	r0, r4				// r0 : page table 시작 주소
	mov	r3, #0				// r3 : 0 저장
	add	r6, r0, #PG_DIR_SIZE		// r6 : r0 + 0x4000
						// r6 : 0x40008000
						// 커널의 시작 주소가 됨
1:	str	r3, [r0], #4
	str	r3, [r0], #4
	str	r3, [r0], #4
	str	r3, [r0], #4
	teq	r0, r6
	bne	1b				// 이전에 만들었던 모든 페이지 테이블 모두 초기화

#ifdef CONFIG_ARM_LPAE				// 통과
	/*
	 * Build the PGD table (first level) to point to the PMD table. A PGD
	 * entry is 64-bit wide.
	 */
	mov	r0, r4
	add	r3, r4, #0x1000			@ first PMD table address
	orr	r3, r3, #3			@ PGD block type
	mov	r6, #4				@ PTRS_PER_PGD
	mov	r7, #1 << (55 - 32)		@ L_PGD_SWAPPER
1:
#ifdef CONFIG_CPU_ENDIAN_BE8			
	str	r7, [r0], #4			@ set top PGD entry bits
	str	r3, [r0], #4			@ set bottom PGD entry bits
#else
	str	r3, [r0], #4			@ set bottom PGD entry bits
	str	r7, [r0], #4			@ set top PGD entry bits
#endif
	add	r3, r3, #0x1000			@ next PMD table
	subs	r6, r6, #1
	bne	1b

	add	r4, r4, #0x1000			@ point to the PMD tables
#ifdef CONFIG_CPU_ENDIAN_BE8
	add	r4, r4, #4			@ we only write the bottom word
#endif
#endif						// 여기까지 통과됨

	ldr	r7, [r10, #PROCINFO_MM_MMUFLAGS] @ mm_mmuflags
	// r10 : proc_info
	// r7 : PMD_TYPE_SECT | PMD_SECT_AP_WRITE | PMD_SECT_AP_READ | PMD_SECT_AF | PMD_FLAGS_SMP
	//	PMD_TYPE_SECT : 0b0010, section 형식이라는 것을 알려줌
	//	PMD_SECT_AP_WRITE : AP[0] 건드림, Access Permission 설정
	// 	PMD_SECT_AP_READ  : AP[1] 건드림, Access Permission 설정, 결국 Full Access 설정됨.
	//	PMD_SECT_AF : 하는 것 없음
	//	PMD_FLAGS_SMP : TEX[2:0], C, B 건드림, Write Back, Write Allocate 정책 설정
	//			0b00111
	//			추가로 S 비트를 1로 설정함

	/*
	 * Create identity mapping to cater for __enable_mmu.
	 * This identity mapping will be removed by paging_init().
	 */
	adr	r0, __turn_mmu_on_loc		// r0에 런타임 주소 값 저장
	ldmia	r0, {r3, r5, r6}		// r3에 컴파일 타임 주소값 저장
						// r5 : __turn_mmu_on 주소
						// r6 : __turn_mmu_on_end 주소
	sub	r0, r0, r3			@ virt->phys offset
						// 델타값 계산
	add	r5, r5, r0			@ phys __turn_mmu_on
	add	r6, r6, r0			@ phys __turn_mmu_on_end
						// 전부 실제 물리 주소로 변환
	mov	r5, r5, lsr #SECTION_SHIFT	// 20비트 오른쪽으로 밀기
	mov	r6, r6, lsr #SECTION_SHIFT	// 1MB 단위로 몇 번째인지 확인, 즉 section 번호 계산

1:	orr	r3, r7, r5, lsl #SECTION_SHIFT	@ flags + kernel base
						// 위에서 만든 플래그와 section 주소를 합침
	str	r3, [r4, r5, lsl #PMD_ORDER]	@ identity mapping
						// 만든 section을 section table 내부에 저장
	cmp	r5, r6				// end까지 도달했는지 확인
	addlo	r5, r5, #1			@ next section
						// 도달 못했으면 section 한 개가 더 필요한 상황임
	blo	1b				// 추가 section에 대해 매핑을 함

	/*
	 * Map our RAM from the start to the end of the kernel .bss section.
	 */
	add	r0, r4, #PAGE_OFFSET >> (SECTION_SHIFT - PMD_ORDER)
						// 가상 시작 주소가 몇 번째 section인지 계산 한 뒤
						// 이를 r4에 더해 section table 내의 위치를 찾아냄
	ldr	r6, =(_end - 1)			// r6 : 마지막 주소 값
	orr	r3, r8, r7			// 물리 시작 주소 & 플래그 >> r3 에 section 값이 저장됨
	add	r6, r4, r6, lsr #(SECTION_SHIFT - PMD_ORDER)
						// 커널의 마지막 위치가 몇 번째 section인지 계산 한 뒤
						// 이를 r4에 더해 section table 내의 위치를 찾아냄
1:	str	r3, [r0], #1 << PMD_ORDER	// 해당하는 section table에 section 값 저장
	add	r3, r3, #1 << SECTION_SHIFT	// section 값의 address base를 1만큼 증가
	cmp	r0, r6				// 커널에 해당하는 section들에 대해 수행 했는지 확인
	bls	1b				// 아니면 계속 수행해 모든 section들 값을 변경

#ifdef CONFIG_XIP_KERNEL			// 통과
	/*
	 * Map the kernel image separately as it is not located in RAM.
	 */
#define XIP_START XIP_VIRT_ADDR(CONFIG_XIP_PHYS_ADDR)
	mov	r3, pc
	mov	r3, r3, lsr #SECTION_SHIFT
	orr	r3, r7, r3, lsl #SECTION_SHIFT
	add	r0, r4,  #(XIP_START & 0xff000000) >> (SECTION_SHIFT - PMD_ORDER)
	str	r3, [r0, #((XIP_START & 0x00f00000) >> SECTION_SHIFT) << PMD_ORDER]!
	ldr	r6, =(_edata_loc - 1)
	add	r0, r0, #1 << PMD_ORDER
	add	r6, r4, r6, lsr #(SECTION_SHIFT - PMD_ORDER)
1:	cmp	r0, r6
	add	r3, r3, #1 << SECTION_SHIFT
	strls	r3, [r0], #1 << PMD_ORDER
	bls	1b
#endif

	/*
	 * Then map boot params address in r2 if specified.
	 * We map 2 sections in case the ATAGs/DTB crosses a section boundary.
	 */
	mov	r0, r2, lsr #SECTION_SHIFT	// DTB 시작 주소의 섹션 번호를 알아냄
	movs	r0, r0, lsl #SECTION_SHIFT	// 다시 원래대로 위치시킴(하위 비트 삭제)
	subne	r3, r0, r8			// 물리 시작 섹션 번호를 빼서 r3에 넣음
	addne	r3, r3, #PAGE_OFFSET		// 다시 복구
	addne	r3, r4, r3, lsr #(SECTION_SHIFT - PMD_ORDER)
						// 해당 섹션의 섹션 테이블 상 위치를 알아냄
	orrne	r6, r7, r0			// r6에 섹션 값을 만듬
	strne	r6, [r3], #1 << PMD_ORDER	// 만든 섹션 값을 해당 위치에 저장
	addne	r6, r6, #1 << SECTION_SHIFT	// 섹션 값 내의 address base를 하나 증가
	strne	r6, [r3]			// 해당 위치에 저장

#if defined(CONFIG_ARM_LPAE) && defined(CONFIG_CPU_ENDIAN_BE8)		// 통과
	sub	r4, r4, #4			@ Fixup page table pointer
						@ for 64-bit descriptors
#endif

#ifdef CONFIG_DEBUG_LL
#if !defined(CONFIG_DEBUG_ICEDCC) && !defined(CONFIG_DEBUG_SEMIHOSTING)
	/*
	 * Map in IO space for serial debugging.
	 * This allows debug messages to be output
	 * via a serial console before paging_init.
	 */
	addruart r7, r3, r0
	// .macro addruart, rp, rv, tmp
	// mrc		p15, 0, r0, c0, c0, 0
	// and		r0, r0, #0xf0
	// teq		r0, #0xf0		@@ A15
	// ldreq	r7, =EXYNOS5_PA_UART
	// movne	r7, #EXYNOS4_PA_UART	@@ EXYNOS4
	// ldr		r3, =S3C_VA_UART
	// 여기서는 위의 명령으로 치환된다.

	mov	r3, r3, lsr #SECTION_SHIFT
	mov	r3, r3, lsl #PMD_ORDER

	add	r0, r4, r3
	mov	r3, r7, lsr #SECTION_SHIFT
	ldr	r7, [r10, #PROCINFO_IO_MMUFLAGS] @ io_mmuflags
	orr	r3, r7, r3, lsl #SECTION_SHIFT

#ifdef CONFIG_ARM_LPAE				// 통과
	mov	r7, #1 << (54 - 32)		@ XN
#ifdef CONFIG_CPU_ENDIAN_BE8
	str	r7, [r0], #4
	str	r3, [r0], #4
#else
	str	r3, [r0], #4
	str	r7, [r0], #4
#endif
#else						// 여기까지
	orr	r3, r3, #PMD_SECT_XN
	str	r3, [r0], #4			// UART용 메모리 위치에 대한 섹션 설정을 수행함
#endif

#else /* CONFIG_DEBUG_ICEDCC || CONFIG_DEBUG_SEMIHOSTING */
	/* we don't need any serial debugging mappings */
	ldr	r7, [r10, #PROCINFO_IO_MMUFLAGS] @ io_mmuflags
#endif

#if defined(CONFIG_ARCH_NETWINDER) || defined(CONFIG_ARCH_CATS)
	/*
	 * If we're using the NetWinder or CATS, we also need to map
	 * in the 16550-type serial port for the debug messages
	 */
	add	r0, r4, #0xff000000 >> (SECTION_SHIFT - PMD_ORDER)
	orr	r3, r7, #0x7c000000
	str	r3, [r0]
#endif
#ifdef CONFIG_ARCH_RPC
	/*
	 * Map in screen at 0x02000000 & SCREEN2_BASE
	 * Similar reasons here - for debug.  This is
	 * only for Acorn RiscPC architectures.
	 */
	add	r0, r4, #0x02000000 >> (SECTION_SHIFT - PMD_ORDER)
	orr	r3, r7, #0x02000000
	str	r3, [r0]
	add	r0, r4, #0xd8000000 >> (SECTION_SHIFT - PMD_ORDER)
	str	r3, [r0]
#endif
#endif
#ifdef CONFIG_ARM_LPAE
	sub	r4, r4, #0x1000		@ point to the PGD table
	mov	r4, r4, lsr #ARCH_PGD_SHIFT
#endif
	mov	pc, lr			// 복귀
ENDPROC(__create_page_tables)
	.ltorg
	.align
__turn_mmu_on_loc:
	.long	.
	.long	__turn_mmu_on
	.long	__turn_mmu_on_end

#if defined(CONFIG_SMP)
	.text
ENTRY(secondary_startup)
	/*
	 * Common entry point for secondary CPUs.
	 *
	 * Ensure that we're in SVC mode, and IRQs are disabled.  Lookup
	 * the processor type - there is no need to check the machine type
	 * as it has already been validated by the primary processor.
	 */
#ifdef CONFIG_ARM_VIRT_EXT
	bl	__hyp_stub_install_secondary
#endif
	safe_svcmode_maskall r9

	mrc	p15, 0, r9, c0, c0		@ get processor id
	bl	__lookup_processor_type
	movs	r10, r5				@ invalid processor?
	moveq	r0, #'p'			@ yes, error 'p'
 THUMB( it	eq )		@ force fixup-able long branch encoding
	beq	__error_p

	/*
	 * Use the page tables supplied from  __cpu_up.
	 */
	adr	r4, __secondary_data
	ldmia	r4, {r5, r7, r12}		@ address to jump to after
	sub	lr, r4, r5			@ mmu has been enabled
	ldr	r4, [r7, lr]			@ get secondary_data.pgdir
	add	r7, r7, #4
	ldr	r8, [r7, lr]			@ get secondary_data.swapper_pg_dir
	adr	lr, BSYM(__enable_mmu)		@ return address
	mov	r13, r12			@ __secondary_switched address
 ARM(	add	pc, r10, #PROCINFO_INITFUNC	) @ initialise processor
						  @ (return control reg)
 THUMB(	add	r12, r10, #PROCINFO_INITFUNC	)
 THUMB(	mov	pc, r12				)
ENDPROC(secondary_startup)

	/*
	 * r6  = &secondary_data
	 */
ENTRY(__secondary_switched)
	ldr	sp, [r7, #4]			@ get secondary_data.stack
	mov	fp, #0
	b	secondary_start_kernel
ENDPROC(__secondary_switched)

	.align

	.type	__secondary_data, %object
__secondary_data:
	.long	.
	.long	secondary_data
	.long	__secondary_switched
#endif /* defined(CONFIG_SMP) */



/*
 * Setup common bits before finally enabling the MMU.  Essentially
 * this is just loading the page table pointer and domain access
 * registers.
 *
 *  r0  = cp#15 control register
 *  r1  = machine ID
 *  r2  = atags or dtb pointer
 *  r4  = page table (see ARCH_PGD_SHIFT in asm/memory.h)
 *  r9  = processor ID
 *  r13 = *virtual* address to jump to upon completion
 */
__enable_mmu:
#if defined(CONFIG_ALIGNMENT_TRAP) && __LINUX_ARM_ARCH__ < 6
	orr	r0, r0, #CR_A
#else
	bic	r0, r0, #CR_A		// A 비트를 0으로 설정
#endif
#ifdef CONFIG_CPU_DCACHE_DISABLE
	bic	r0, r0, #CR_C
#endif
#ifdef CONFIG_CPU_BPREDICT_DISABLE
	bic	r0, r0, #CR_Z
#endif
#ifdef CONFIG_CPU_ICACHE_DISABLE
	bic	r0, r0, #CR_I
#endif
#ifndef CONFIG_ARM_LPAE
	mov	r5, #(domain_val(DOMAIN_USER, DOMAIN_MANAGER) | \
		      domain_val(DOMAIN_KERNEL, DOMAIN_MANAGER) | \
		      domain_val(DOMAIN_TABLE, DOMAIN_MANAGER) | \
		      domain_val(DOMAIN_IO, DOMAIN_CLIENT))
						// r5 : 1 << 2 | 1 << 0 | 1 << 0 | 1 << 4
	mcr	p15, 0, r5, c3, c0, 0		@ load domain access register
						// Domain 0, 1, 2에서 접근 권한은 page table 내용에 있는 AP 비트에 따라감
	mcr	p15, 0, r4, c2, c0, 0		@ load page table pointer
						// TTBR0 반영
#endif
	b	__turn_mmu_on
ENDPROC(__enable_mmu)

/*
 * Enable the MMU.  This completely changes the structure of the visible
 * memory space.  You will not be able to trace execution through this.
 * If you have an enquiry about this, *please* check the linux-arm-kernel
 * mailing list archives BEFORE sending another post to the list.
 *
 *  r0  = cp#15 control register
 *  r1  = machine ID
 *  r2  = atags or dtb pointer
 *  r9  = processor ID
 *  r13 = *virtual* address to jump to upon completion
 *
 * other registers depend on the function called upon completion
 */
	.align	5
	.pushsection	.idmap.text, "ax"
ENTRY(__turn_mmu_on)
	mov	r0, r0
	instr_sync				// ISB
	mcr	p15, 0, r0, c1, c0, 0		@ write control reg

						//   AT
						//  TFR   EV X F   I D LR    S
						// .EEE ..EE PUI. .T.T 4RVI ZWRS BLDP WCAM
						// rxxx rrxx xxx0 0101 xxxx xxxx x111 xxxx < forced
						//   01    0 110       0011 1000 .111 1101 < we want
						
						// 위의 값으로 SCTLR 반영
						// MMU 켜짐
	mrc	p15, 0, r3, c0, c0, 0		@ read id reg
						// MIDR 을 r3에 저장
	instr_sync				// ISB
	mov	r3, r3
	mov	r3, r13
	mov	pc, r3				// __mmap_switched 로 점프
__turn_mmu_on_end:
ENDPROC(__turn_mmu_on)
	.popsection


#ifdef CONFIG_SMP_ON_UP
	__INIT				// #define __INIT    .section	".init.text","ax"
__fixup_smp:
	and	r3, r9, #0x000f0000	@ architecture version
					// r3에 아키텍쳐 버전을 저장
					// Cortex-A15는 0x000F0000가 저장됨
	teq	r3, #0x000f0000		@ CPU ID supported?
					// CPUID 레지스터들이 지원되는 경우(ARMv7)
	bne	__fixup_smp_on_up	@ no, assume UP
					// ARMv7은 점프 하지 않음

	bic	r3, r9, #0x00ff0000	
	bic	r3, r3, #0x0000000f	@ mask 0xff00fff0
					// r9 & 0xFF00FFF0 값을 r3에 저장
					// Implementer와 Primary Part Number 값만 남음
	mov	r4, #0x41000000		// r4에 0x41000000 저장
	orr	r4, r4, #0x0000b000
	orr	r4, r4, #0x00000020	@ val 0x4100b020
					// r4 : 0x4100B020
	teq	r3, r4			@ ARM 11MPCore?
	moveq	pc, lr			@ yes, assume SMP
					// ARM 11MPCore 인지 확인

	mrc	p15, 0, r0, c0, c0, 5	@ read MPIDR
					// r0에 MPIDR 저장
					// 멀티 코어 관련 레지스터임
	and	r0, r0, #0xc0000000	@ multiprocessing extensions and
	teq	r0, #0x80000000		@ not part of a uniprocessor system?
					// MPIDR의 MSB가 1이면 멀티프로세서 시스템임
	moveq	pc, lr			@ yes, assume SMP
					// 멀티 프로세서이면 복귀
					// Cortex-A15이면 무조건 1임

__fixup_smp_on_up:
	adr	r0, 1f
	ldmia	r0, {r3 - r5}
	sub	r3, r0, r3
	add	r4, r4, r3
	add	r5, r5, r3
	b	__do_fixup_smp_on_up
ENDPROC(__fixup_smp)

	.align
1:	.word	.
	.word	__smpalt_begin
	.word	__smpalt_end

	.pushsection .data
	.globl	smp_on_up
smp_on_up:
	ALT_SMP(.long	1)
	ALT_UP(.long	0)
	.popsection
#endif

	.text
__do_fixup_smp_on_up:
	cmp	r4, r5
	movhs	pc, lr
	ldmia	r4!, {r0, r6}
 ARM(	str	r6, [r0, r3]	)
 THUMB(	add	r0, r0, r3	)
#ifdef __ARMEB__
 THUMB(	mov	r6, r6, ror #16	)	@ Convert word order for big-endian.
#endif
 THUMB(	strh	r6, [r0], #2	)	@ For Thumb-2, store as two halfwords
 THUMB(	mov	r6, r6, lsr #16	)	@ to be robust against misaligned r3.
 THUMB(	strh	r6, [r0]	)
	b	__do_fixup_smp_on_up
ENDPROC(__do_fixup_smp_on_up)

ENTRY(fixup_smp)
	stmfd	sp!, {r4 - r6, lr}
	mov	r4, r0
	add	r5, r0, r1
	mov	r3, #0
	bl	__do_fixup_smp_on_up
	ldmfd	sp!, {r4 - r6, pc}
ENDPROC(fixup_smp)

#ifdef CONFIG_ARM_PATCH_PHYS_VIRT

/* __fixup_pv_table - patch the stub instructions with the delta between
 * PHYS_OFFSET and PAGE_OFFSET, which is assumed to be 16MiB aligned and
 * can be expressed by an immediate shifter operand. The stub instruction
 * has a form of '(add|sub) rd, rn, #imm'.
 */
	__HEAD
__fixup_pv_table:
	adr	r0, 1f		// 1 레이블의 런타임 주소가 저장됨
	ldmia	r0, {r3-r5, r7}	// r3 : 1 레이블의 컴파일 타임 주소
				// r4 : __pv_table_begin
				// r5 : __pv_table_end
				// r7 : __pv_phys_offset
	sub	r3, r0, r3	@ PHYS_OFFSET - PAGE_OFFSET
				// r3 : 런타임 - 컴파일 타임
				// 물리 주소 - 가상 주소 : 델타 = r3
	add	r4, r4, r3	@ adjust table start address
	add	r5, r5, r3	@ adjust table end address
	add	r7, r7, r3	@ adjust __pv_phys_offset address
				// 위에서 저장한 주소 값을 런타임으로 변경
	str	r8, [r7]	@ save computed PHYS_OFFSET to __pv_phys_offset
				// PHYS_OFFSET을 __pv_phys_offset이 가리키는 공간에 저장
	mov	r6, r3, lsr #24	@ constant for add/sub instructions
	teq	r3, r6, lsl #24 @ must be 16MiB aligned
THUMB(	it	ne		@ cross section branch )
	bne	__error
	str	r6, [r7, #4]	@ save to __pv_offset
	b	__fixup_a_pv_table
ENDPROC(__fixup_pv_table)

	.align
1:	.long	.
	.long	__pv_table_begin
	.long	__pv_table_end
2:	.long	__pv_phys_offset

	.text
__fixup_a_pv_table:
#ifdef CONFIG_THUMB2_KERNEL
	lsls	r6, #24
	beq	2f
	clz	r7, r6
	lsr	r6, #24
	lsl	r6, r7
	bic	r6, #0x0080
	lsrs	r7, #1
	orrcs	r6, #0x0080
	orr	r6, r6, r7, lsl #12
	orr	r6, #0x4000
	b	2f
1:	add     r7, r3
	ldrh	ip, [r7, #2]
	and	ip, 0x8f00
	orr	ip, r6		@ mask in offset bits 31-24
	strh	ip, [r7, #2]
2:	cmp	r4, r5
	ldrcc	r7, [r4], #4	@ use branch for delay slot
	bcc	1b
	bx	lr
#else
	b	2f

1:	ldr	ip, [r7, r3]	// 주소에 델타를 더한 후 거기 존재하는 데이터를 r12로 저장
				// r12에는 명령들이 들어감
				// __phys_to_virt, __virt_to_phys 들이 존재
	bic	ip, ip, #0x000000ff
				// 명령어의 하위 8비트를 날림
	orr	ip, ip, r6	@ mask in offset bits 31-24
				// imm8을 반영시킴
	str	ip, [r7, r3]	// 변경한 명령을 다시 원래 자리에 복구함
2:	cmp	r4, r5		// r4 : __pv_table_begin
				// r5 : __pv_table_end
	ldrcc	r7, [r4], #4	@ use branch for delay slot
				// r4 < r5면 r7에 r4가 가리키는 데이터 값을 저장
				// r7은 명령어가 저장되어 있는 주소임
				// r4 += 4
	bcc	1b		// r4 < r5면 1 레이블로 점프
	mov	pc, lr
#endif
ENDPROC(__fixup_a_pv_table)

ENTRY(fixup_pv_table)
	stmfd	sp!, {r4 - r7, lr}
	ldr	r2, 2f			@ get address of __pv_phys_offset
	mov	r3, #0			@ no offset
	mov	r4, r0			@ r0 = table start
	add	r5, r0, r1		@ r1 = table size
	ldr	r6, [r2, #4]		@ get __pv_offset
	bl	__fixup_a_pv_table
	ldmfd	sp!, {r4 - r7, pc}
ENDPROC(fixup_pv_table)

	.align
2:	.long	__pv_phys_offset

	.data
	.globl	__pv_phys_offset
	.type	__pv_phys_offset, %object
__pv_phys_offset:
	.long	0
	.size	__pv_phys_offset, . - __pv_phys_offset
__pv_offset:
	.long	0
#endif

#include "head-common.S"
