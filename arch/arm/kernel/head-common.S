/*
 *  linux/arch/arm/kernel/head-common.S
 *
 *  Copyright (C) 1994-2002 Russell King
 *  Copyright (c) 2003 ARM Limited
 *  All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#define ATAG_CORE 0x54410001
#define ATAG_CORE_SIZE ((2*4 + 3*4) >> 2)
#define ATAG_CORE_SIZE_EMPTY ((2*4) >> 2)

#ifdef CONFIG_CPU_BIG_ENDIAN
#define OF_DT_MAGIC 0xd00dfeed
#else
#define OF_DT_MAGIC 0xedfe0dd0 /* 0xd00dfeed in big-endian */
#endif

/*
 * Exception handling.  Something went wrong and we can't proceed.  We
 * ought to tell the user, but since we don't have any guarantee that
 * we're even running on the right architecture, we do virtually nothing.
 *
 * If CONFIG_DEBUG_LL is set we try to print out something about the error
 * and hope for the best (useful if bootloader fails to pass a proper
 * machine ID for example).
 */
	__HEAD

/* Determine validity of the r2 atags pointer.  The heuristic requires
 * that the pointer be aligned, in the first 16k of physical RAM and
 * that the ATAG_CORE marker is first and present.  If CONFIG_OF_FLATTREE
 * is selected, then it will also accept a dtb pointer.  Future revisions
 * of this function may be more lenient with the physical address and
 * may also be able to move the ATAGS block if necessary.
 *
 * Returns:
 *  r2 either valid atags pointer, valid dtb pointer, or zero
 *  r5, r6 corrupted
 */
__vet_atags:
	tst	r2, #0x3			@ aligned?
						// atag 포인터가 4바이트 정렬 되어 있는 지 확인
	bne	1f

	ldr	r5, [r2, #0]			// atag의 시작 4바이트를 r5에 저장
#ifdef CONFIG_OF_FLATTREE
	ldr	r6, =OF_DT_MAGIC		@ is it a DTB?
						// DTB 매직 넘버를 r6에 저장
	cmp	r5, r6				// 비교
	beq	2f				// 일치하면 DTB가 존재하는 것임
#endif						
						// DTB가 아니면 atag 인지 확인
						// 2번째 word에 매직 넘버가 저장되어 있음
						// 이를 불러와 비교해서 확인함.
	cmp	r5, #ATAG_CORE_SIZE		@ is first tag ATAG_CORE?
	cmpne	r5, #ATAG_CORE_SIZE_EMPTY
	bne	1f
	ldr	r5, [r2, #4]
	ldr	r6, =ATAG_CORE
	cmp	r5, r6
	bne	1f

2:	mov	pc, lr				@ atag/dtb pointer is ok

1:	mov	r2, #0
	mov	pc, lr
ENDPROC(__vet_atags)

/*
 * The following fragment of code is executed with the MMU on in MMU mode,
 * and uses absolute addresses; this is not position independent.
 *
 *  r0  = cp#15 control register
 *  r1  = machine ID
 *  r2  = atags/dtb pointer
 *  r9  = processor ID
 */
	__INIT
__mmap_switched:
	adr	r3, __mmap_switched_data

	ldmia	r3!, {r4, r5, r6, r7}
	cmp	r4, r5				@ Copy data segment if needed
						// XIP가 켜져 있을때 필요함
1:	cmpne	r5, r6
	ldrne	fp, [r4], #4
	strne	fp, [r5], #4
	bne	1b

	mov	fp, #0				@ Clear BSS (and zero fp)
1:	cmp	r6, r7				// bss 섹션 전부 0으로 만듬
	strcc	fp, [r6],#4
	bcc	1b

 ARM(	ldmia	r3, {r4, r5, r6, r7, sp})
 THUMB(	ldmia	r3, {r4, r5, r6, r7}	)
 THUMB(	ldr	sp, [r3, #16]		)
	str	r9, [r4]			@ Save processor ID
	str	r1, [r5]			@ Save machine type
	str	r2, [r6]			@ Save atags pointer
						// 지금까지 가져온 값들을 전역변수에 저장함.
	cmp	r7, #0
	bicne	r4, r0, #CR_A			@ Clear 'A' bit
	stmneia	r7, {r0, r4}			@ Save control register values
						// r0는 cr_alignment 변수에 저장
						// r4는 cr_no_alignment 변수에 저장
	b	start_kernel
ENDPROC(__mmap_switched)

	.align	2
	.type	__mmap_switched_data, %object
__mmap_switched_data:
	.long	__data_loc			@ r4
	.long	_sdata				@ r5
	.long	__bss_start			@ r6
	.long	_end				@ r7
	.long	processor_id			@ r4
	.long	__machine_arch_type		@ r5
	.long	__atags_pointer			@ r6
#ifdef CONFIG_CPU_CP15
	.long	cr_alignment			@ r7
#else
	.long	0				@ r7
#endif
	.long	init_thread_union + THREAD_START_SP @ sp
	.size	__mmap_switched_data, . - __mmap_switched_data

/*
 * This provides a C-API version of __lookup_processor_type
 */
ENTRY(lookup_processor_type)
	stmfd	sp!, {r4 - r6, r9, lr}
	mov	r9, r0
	bl	__lookup_processor_type
	mov	r0, r5
	ldmfd	sp!, {r4 - r6, r9, pc}
ENDPROC(lookup_processor_type)

	__FINIT
	.text

/*
 * Read processor ID register (CP#15, CR0), and look up in the linker-built
 * supported processor list.  Note that we can't use the absolute addresses
 * for the __proc_info lists since we aren't running with the MMU on
 * (and therefore, we are not in the correct address space).  We have to
 * calculate the offset.
 *
 *	r9 = cpuid
 * Returns:
 *	r3, r4, r6 corrupted
 *	r5 = proc_info pointer in physical address space
 *	r9 = cpuid (preserved)
 */
__lookup_processor_type:
	adr	r3, __lookup_processor_type_data
						// r3에 __lookup_processor_type_data 주소저장(런 타임)
	ldmia	r3, {r4 - r6}			// r4 : __lookup_processor_type_data 주소(컴파일 타임)
						// r5 : __proc_info_begin >> section .proc.info.init의 시작 주소
						// r6 : __proc_info_end >> section .proc.info.init의 마지막 주소
	sub	r3, r3, r4			@ get offset between virt&phys
						// r3 : 런타임 - 컴파일타임
	add	r5, r5, r3			@ convert virt addresses to
						// r5를 런타임 주소로 변경
	add	r6, r6, r3			@ physical address space
						// r6를 런타임 주소로 변경
1:	ldmia	r5, {r3, r4}			@ value, mask
						// .proc.info.init 섹션의 시작 4바이트 값을 r3로
						// 그 다음 k바이트 값을 r4로 저장
	and	r4, r4, r9			@ mask wanted bits
						// r9 : MIDR
						// r4와 and 연산
	teq	r3, r4				// 그 값이 r3와 동일한 지 확인
	beq	2f				// 동일하면 2로 점프
						// __v7_ca15mp_proc_info에서 
						// r3 : .long   0x410fc0f0
						// r4 : .long   0xff0ffff0
						// 일 때 2f로 이동됨
	add	r5, r5, #PROC_INFO_SZ		@ sizeof(proc_info_list)
						// 아니면 r5를 다음 아키텍쳐로 이동
	cmp	r5, r6				// 끝까지 왔는지 확인
	blo	1b				// 더 있으면 다음 아키텍쳐 검사 루틴 수행
	mov	r5, #0				@ unknown processor
						// 여기까지 오면 일치하는 아키텍쳐가 없는 것임
2:	mov	pc, lr				// r5에 proc_info의 시작 주소를 저장한 채로 돌아감  

ENDPROC(__lookup_processor_type)

/*
 * Look in <asm/procinfo.h> for information about the __proc_info structure.
 */
	.align	2
	.type	__lookup_processor_type_data, %object
__lookup_processor_type_data:
	.long	.
	.long	__proc_info_begin
	.long	__proc_info_end
	.size	__lookup_processor_type_data, . - __lookup_processor_type_data

__error_p:
#ifdef CONFIG_DEBUG_LL
	adr	r0, str_p1
	bl	printascii
	mov	r0, r9
	bl	printhex8
	adr	r0, str_p2
	bl	printascii
	b	__error
str_p1:	.asciz	"\nError: unrecognized/unsupported processor variant (0x"
str_p2:	.asciz	").\n"
	.align
#endif
ENDPROC(__error_p)

__error:
#ifdef CONFIG_ARCH_RPC
/*
 * Turn the screen red on a error - RiscPC only.
 */
	mov	r0, #0x02000000
	mov	r3, #0x11
	orr	r3, r3, r3, lsl #8
	orr	r3, r3, r3, lsl #16
	str	r3, [r0], #4
	str	r3, [r0], #4
	str	r3, [r0], #4
	str	r3, [r0], #4
#endif
1:	mov	r0, r0
	b	1b
ENDPROC(__error)
