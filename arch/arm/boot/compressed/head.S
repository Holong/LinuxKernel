/*
 *  linux/arch/arm/boot/compressed/head.S
 *
 *  Copyright (C) 1996-2002 Russell King
 *  Copyright (C) 2004 Hyok S. Choi (MPU support)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/linkage.h>
#include <asm/assembler.h>

	.arch	armv7-a
/*
 * Debugging stuff
 *
 * Note that these macros must not contain any code which is not
 * 100% relocatable.  Any attempt to do so will result in a crash.
 * Please select one of the following when turning on debugging.
 */
#ifdef DEBUG

#if defined(CONFIG_DEBUG_ICEDCC)

#if defined(CONFIG_CPU_V6) || defined(CONFIG_CPU_V6K) || defined(CONFIG_CPU_V7)
		.macro	loadsp, rb, tmp
		.endm
		.macro	writeb, ch, rb
		mcr	p14, 0, \ch, c0, c5, 0
		.endm
#elif defined(CONFIG_CPU_XSCALE)
		.macro	loadsp, rb, tmp
		.endm
		.macro	writeb, ch, rb
		mcr	p14, 0, \ch, c8, c0, 0
		.endm
#else
		.macro	loadsp, rb, tmp
		.endm
		.macro	writeb, ch, rb
		mcr	p14, 0, \ch, c1, c0, 0
		.endm
#endif

#else

#include CONFIG_DEBUG_LL_INCLUDE		// 이 부분 수행 됨.
		
		.macro	writeb,	ch, rb
		senduart \ch, \rb
		.endm

		// .macro 는 어셈블러에게 매크로를 제작하라는 명령임.
		// 뒤에서 writeb r1, r2 라고 명령을 주면
		// 자동으로 senduart r1, r2 라고 명령이 수행됨.

#if defined(CONFIG_ARCH_SA1100)
		.macro	loadsp, rb, tmp
		mov	\rb, #0x80000000	@ physical base address
#ifdef CONFIG_DEBUG_LL_SER3
		add	\rb, \rb, #0x00050000	@ Ser3
#else
		add	\rb, \rb, #0x00010000	@ Ser1
#endif
		.endm
#elif defined(CONFIG_ARCH_S3C24XX)
		.macro loadsp, rb, tmp
		mov	\rb, #0x50000000
		add	\rb, \rb, #0x4000 * CONFIG_S3C_LOWLEVEL_UART_PORT
		.endm
#else						// 여기가 수행됨.
		.macro	loadsp,	rb, tmp		// 매크로 제작
		addruart \rb, \tmp
		.endm
		
		// .macro addruart, rp, rv, tmp
		// mrc		p15, 0, \tmp, c0, c0, 0
		// and		\tmp, \tmp, #0xf0
		// teq		\tmp, #0xf0		@@ A15
		// ldreq	\rp, =EXYNOS5_PA_UART
		// movne	\rp, #EXYNOS4_PA_UART	@@ EXYNOS4
		// ldr		\rv, =S3C_VA_UART
		// 위의 #include 문
		// #include CONFIG_DEBUG_LL_INCLUDE 에 의해 적합한 매크로가 지정됨.
		// 여기서는 위의 명령으로 치환된다.
#endif
#endif
#endif
		// DEBUG 모드가 아니면 이 쪽으로 바로 옴.
		// DEBUG 모드 아닌 걸로 생각하고 수행하기로 함.

		.macro	kputc,val	// val을 uart로 출력하는 매크로
		mov	r0, \val	// r0 에 val 대입
		bl	putc
		.endm

		.macro	kphex,val,len	// val을 16 진수로 출력
		mov	r0, \val
		mov	r1, #\len
		bl	phex
		.endm

		.macro	debug_reloc_start
#ifdef DEBUG
		kputc	#'\n'
		kphex	r6, 8		/* processor id */
		kputc	#':'
		kphex	r7, 8		/* architecture id */
#ifdef CONFIG_CPU_CP15
		kputc	#':'
		mrc	p15, 0, r0, c1, c0
		kphex	r0, 8		/* control reg */
#endif
		kputc	#'\n'
		kphex	r5, 8		/* decompressed kernel start */
		kputc	#'-'
		kphex	r9, 8		/* decompressed kernel end  */
		kputc	#'>'
		kphex	r4, 8		/* kernel execution address */
		kputc	#'\n'
#endif
		.endm

		.macro	debug_reloc_end
#ifdef DEBUG
		kphex	r5, 8		/* end of kernel */
		kputc	#'\n'
		mov	r0, r4
		bl	memdump		/* dump 256 bytes at start of kernel */
#endif
		.endm

		.section ".start", #alloc, #execinstr  // 실질적인 코드 시작임.
/*
 * sort out different calling conventions
 */
// 아래 코드들을 .start section에 밀어 넣음.

		.align				// 4byte로 align이 됨.
						// 2의 n 배로 정렬이 되며 아무 값이 없을 때는 4byte 정렬임.
		.arm				@ Always enter in ARM state
						// 아래부터는 ARM 코드임
start:
		.type	start,#function		// start 레이블은 function 타입임.
						// 이 값은 symbol table의 속성에 기록이 되어
						// 디버그 할 때 사용됨.
		.rept	7			// .endr 까지 7번 반복
		mov	r0, r0			// 이 코드가 삽입된 이유는 특수 부트로더의 call 주소가
		.endr				// 0x20 인 것을 맞추기 위함임.
   ARM(		mov	r0, r0		)	// CONFIG_THUMB2_KERNEL 옵션이 켜져 있으면 ARM()은 삭제되고 THUMB()만 사용됨.
   ARM(		b	1f		)	// 반대의 경우는 ARM() 내부가 살아 남고 THUMB() 내부는 삭제됨.
 THUMB(		adr	r12, BSYM(1f)	)	// BSYM() 매크로는 1f에 1을 더한 뒤 bx를 호출하게 한다.
 THUMB(		bx	r12		)	// 이와 같은 수행이 필요한 이유는 THUMB 모드로 점프를 수행하기 위함이다.
						// bx 는 r12 & 1을 수행한 뒤 그 결과를 cpsr의 T 비트에 저장한다.
						// 이 때 T 값이 1이 되어야 THUMB 모드로 CPU가 동작하게 된다.

		.word	0x016f2818		@ Magic numbers to help the loader
		.word	start			@ absolute load/run zImage address
		.word	_edata			@ zImage end address
						// zImage의 끝 주소 (링커 스크립트에 기록되어 있음)
 THUMB(		.thumb			)
1:
 ARM_BE8(	setend	be )			@ go BE8 if compiled for BE8
		mrs	r9, cpsr		// cpsr을 r9에 저장

#ifdef CONFIG_ARM_VIRT_EXT
		bl	__hyp_stub_install	@ get into SVC mode, reversibly
#endif
		mov	r7, r1			@ save architecture ID
		mov	r8, r2			@ save atags pointer
						// r1, r2는 부트로더가 넘겨준 값임.

		/*
		 * Booting from Angel - need to enter SVC mode and disable
		 * FIQs/IRQs (numeric definitions from angel arm.h source).
		 * We only do this if we were in user mode on entry.
		 */
		mrs	r2, cpsr		@ get current mode
		tst	r2, #3			@ not user?
		bne	not_angel
		mov	r0, #0x17		@ angel_SWIreason_EnterSVC
 ARM(		swi	0x123456	)	@ angel_SWI_ARM
 THUMB(		svc	0xab		)	@ angel_SWI_THUMB
not_angel:
		safe_svcmode_maskall r0	
		// 다음과 같이 변경되어 삽입됨.

	//	mrs	r0 , cpsr			// r0 = cpsr
	//	eor	r0, r0, #HYP_MODE		// r0 모드가 HYP_MODE 이면 Z 플래그를 1로 설정
	//	tst	r0, #MODE_MASK			// r0 하위 5비트가 0이면 Z 플래그를 1로 설정
	//	bic	r0 , r0 , #MODE_MASK		// r0 하위 5비트를 전부 0으로 변경
	//	orr	r0 , r0 , #PSR_I_BIT | PSR_F_BIT | SVC_MODE	// IRQ, FIQ 끄고 SuperVisor 모드로 설정
	//	bne	1f				// 즉 HYP 모드가 아니었으면 그냥 cpsr만 변경.
							// HYP 모드였으면 아래의 추가 동작 수행
	//	orr	r0, r0, #PSR_A_BIT		
	//	adr	lr, BSYM(2f)
	//	msr	spsr_cxsf, r0
	//	__MSR_ELR_HYP(14)
	//	__ERET
	//1:	msr	cpsr_c, r0
	//2:
	//.endm

		msr	spsr_cxsf, r9		@ Save the CPU boot mode in
						@ SPSR
						// SPSR 에 bootloader 에서의 cpsr을 저장함.
						// CPSR을 건드려 모드를 바꾸었기 때문에 자동으로
						// 이전 CPSR이 SPSR에 저장되지 않기 때문에 수동 저장하는 것임.
		/*
		 * Note that some cache flushing and other stuff may
		 * be needed here - is there an Angel SWI call for this?
		 */

		/*
		 * some architecture specific code can be inserted
		 * by the linker here, but it should preserve r7, r8, and r9.
		 */

		.text

#ifdef CONFIG_AUTO_ZRELADDR
		@ determine final kernel image address
		mov	r4, pc
		and	r4, r4, #0xf8000000
		add	r4, r4, #TEXT_OFFSET
#else
		ldr	r4, =zreladdr		// zreladdr-y += 0x40008000
						// grep 으로 긁어보면
						// arch/arm/mach-exynos/Makefile.boot 내부에 zreladdr-y += 0x40008000 이 들어있음.
						// arch/arm/boot/Makefile:22:ZRELADDR    := $(zreladdr-y) 구문이 있으며
						// 최종적으로 zreladdr=$(ZRELADDR) 으로 인해 0x40008000 이 zreladdr이 됨.

#endif

		/*
		 * Set up a page table only if it won't overwrite ourself.
		 * That means r4 < pc && r4 - 16k page directory > &_end.
		 * Given that r4 > &_end is most unfrequent, we add a rough
		 * additional 1MB of room for a possible appended DTB.
		 */
		// 위에 주석에 의하면 page table을 위치할 공간에 현재 코드들이 도달하지
		// 못할 때 page table 을 set up 한다고 되어 있음.
		// (r4 < pc) && (r4 - 16k > &(_end))  == 1 일 때는 set up을 하면 안되며
		// 0 이면 set up을 해도 된다는 뜻임

		mov	r0, pc			// r0 = pc (program counter)
		cmp	r0, r4			// r0 와 zreladdr 비교 (0x40008000)
		// pc < r4 이면 아래 3개 명령 수행됨
		// ~cc : Carry Clear, unsigned low
		ldrcc	r0, LC0+32		// r0 = _end - restart + 16384 + 1024*1024 (16KB + 1MB)
		addcc	r0, r0, pc		// r0 += pc
						// 위 두 연산을 통해 r0에는 현재 코드들이 도달해 있는 위치 + page table 넣을 공간 + DTB 공간 이 계산되어 들어감
		cmpcc	r4, r0			// r4 < r0 인지 확인
						// 위 연산을 통해 zreladdr 아래 공간이 충분히 확보되어 있는지 확인.
		orrcc	r4, r4, #1		@ remember we skipped cache_on
						// page table 위치 시킬 공간이 부족하면 이 연산이 실행되며 아래의 cache_on 연산은 건너 뛰게 된다.
						// 즉 cache_on 함수를 수행 했는지 안했는지를 r4 하위 1비트에 기록해둠
		blcs	cache_on		// page table 위치 시킬 공간이 있을 때만 수행됨

		// I, D cache 켜지고, MMU도 켜져있음.

restart:	adr	r0, LC0			// LC0의 주소를 r0로 대입
						//		.align	2
						//		.type	LC0, #object
						//LC0:		.word	LC0			@ r1
						//		.word	__bss_start		@ r2
						//		.word	_end			@ r3
						//		.word	_edata			@ r6
						//		.word	input_data_end - 4	@ r10 (inflated size location)
						//		.word	_got_start		@ r11
						//		.word	_got_end		@ ip
						//		.word	.L_user_stack_end	@ sp
						//		.word	_end - restart + 16384 + 1024*1024
						//		.size	LC0, . - LC0

		ldmia	r0, {r1, r2, r3, r6, r10, r11, r12}	// increment after 연산
								// r0에 저장된 주소에 존재하는 데이터 값을 차례로 가져온다.
		ldr	sp, [r0, #28]				// .L_user_stack_end의 주소 값을 sp 레지스터에 저장함.
								// 
								//			.align
								//			.section ".stack", "aw", %nobits
								//.L_user_stack:	.space	4096
								//.L_user_stack_end:
								// 이므로 stack 섹션에서 4KB를 확보한 뒤 스택 영역으로 쓸 것으로 보임
								// .stack 섹션은 가장 마지막에 존재하는 섹션임.
		/*
		 * We might be running at a different address.  We need
		 * to fix up various pointers.
		 */
		sub	r0, r0, r1		@ calculate the delta offset
						// r0 : runtime의 LC0 주소
						// r1 : compile time의 LC0 주소
						// 왜???
						// r0 값은 adr 명령으로 생성 되었다는 점을 눈여겨 봐야함.
						// adr은 항상 PC + offset 값을 레지스터에 저장하는 형태임
						// 그러므로 항상 실행 기반 주소가 생성될 수 밖에 없음.
						// 반면 r1은 ldmia 명령으로 생성되었는데
						// 이것은 그냥 메모리 특정 위치에 존재하는 데이터를 긁어오는 것이며
						// 이 때 LC0에 해당하는 데이터는 컴파일 시 결정되게 되어 있음.
		add	r6, r6, r0		@ _edata
						// _edata에 델타 오프셋을 더해
						// 실제로 어느 위치에 _edata 레이블이 올라오는지 알아 낼 수 있음
						// _edata는 zImage의 마지막 주소 값이다.
		add	r10, r10, r0		@ inflated kernel size location
						// input_data_end - 4 에 델타 오프셋을 더해
						// 실제 메모리의 어느 위치가 압축 커널 이미지의 마지막인지 알아 낼 수 있음
						// input_data_end는 .piggydata 섹션의 마지막 주소이다.
						// 링커 스크립트를 까보면 .piggydata 섹션 다음에는 bss와 stack 섹션 밖에 없으며
						// .piggydata 섹션 내부에는 arch/arm/boot/compressed/piggy.gzip이 들어 있다.
						// 이는 압축된 커널 이미지이다.
						// 그런데 여기서 포인트는 - 4를 해준 점임.
						// 커널 빌드 시스템에서는 빌드시 이 위치에 리틀 엔디안 형태로
						// 압축이 풀렸을 때의 커널 사이즈를 저장한다.

		/*
		 * The kernel build system appends the size of the
		 * decompressed kernel at the end of the compressed data
		 * in little-endian form.
		 */
		ldrb	r9, [r10, #0]
		ldrb	lr, [r10, #1]
		orr	r9, r9, lr, lsl #8
		ldrb	lr, [r10, #2]
		ldrb	r10, [r10, #3]
		orr	r9, r9, lr, lsl #16
		orr	r9, r9, r10, lsl #24		// 결국 r9에는 압축이 풀린 커널의 크기가 저장됨

#ifndef CONFIG_ZBOOT_ROM				// ROM booting이 아니면 수행됨
		/* malloc space is above the relocated stack (64k max) */
		add	sp, sp, r0			// sp를 runtime 주소에 맞게 바꿈
		add	r10, sp, #0x10000		// sp 위에 64KB를 더해서 r10에 밀어 넣음
							// malloc 공간을 확보함
 							// r10 = end of this image, including  bss/stack/malloc space if non XIP
#else
		/*
		 * With ZBOOT_ROM the bss/stack is non relocatable,
		 * but someone could still run this code from RAM,
		 * in which case our reference is _edata.
		 */
		mov	r10, r6
#endif

		mov	r5, #0			@ init dtb size to 0
						// r5에 0 대입
#ifdef CONFIG_ARM_APPENDED_DTB			// config 파일에는 설정 안되어 있는데....
						// 여길 왜 했을까....
/*
 *   r0  = delta
 *   r2  = BSS start
 *   r3  = BSS end
 *   r4  = final kernel address (possibly with LSB set)
 *   r5  = appended dtb size (still unknown)
 *   r6  = _edata
 *   r7  = architecture ID
 *   r8  = atags/device tree pointer
 *   r9  = size of decompressed image
 *   r10 = end of this image, including  bss/stack/malloc space if non XIP
 *   r11 = GOT start
 *   r12 = GOT end
 *   sp  = stack pointer
 *
 * if there are device trees (dtb) appended to zImage, advance r10 so that the
 * dtb data will get relocated along with the kernel if necessary.
 */

		ldr	lr, [r6, #0]		// _edata에 저장되어 있는 값을 lr에 저장
#ifndef __ARMEB__
		ldr	r1, =0xedfe0dd0		@ sig is 0xd00dfeed big endian
#else
		ldr	r1, =0xd00dfeed		// r1에 0xD00DFEED 저장
						// DTB 용 Magic Number
#endif
		cmp	lr, r1			// 매직 넘버가 맞는지 비교하고 있음
		bne	dtb_check_done		@ not found
						// 틀리면 zImage에 DTB가 없는 것임
						// 맞으면 다음단계 진행

#ifdef CONFIG_ARM_ATAG_DTB_COMPAT		// 설정 안되어 있음
						// 일단 아래 내용은 통과됨
						// atag 형태로 appended dtb가 붙어 있는 경우
						// 이를 dtb 형태로 변경해야함.
		/*
		 * OK... Let's do some funky business here.
		 * If we do have a DTB appended to zImage, and we do have
		 * an ATAG list around, we want the later to be translated
		 * and folded into the former here.  To be on the safe side,
		 * let's temporarily move  the stack away into the malloc
		 * area.  No GOT fixup has occurred yet, but none of the
		 * code we're about to call uses any global variable.
		*/

		// 위 주석에 의하면 zImage 내에 atag 형태로 디바이스 관련 정보가 저장되어 있으면
		// 이를 DTB 형태로 바꾸려는 것임.
		// atgs_to_fdt 함수를 통해 이 동작이 수행됨

		add	sp, sp, #0x10000		// sp를 64KB 만큼 올림
							// 충분한 스택 영역 확보
		stmfd	sp!, {r0-r3, ip, lr}		// r0, r1, r2, r3, ip, lr을 스택에 저장
		mov	r0, r8				// r0에 dtb 포인터 저장 (파라미터 1번)
		mov	r1, r6				// r1에 _edata 저장 (파라미터 2번)
		sub	r2, sp, r6			// r2 = sp - _edata (파라미터 3번)
		bl	atags_to_fdt			// int atags_to_fdt(void *atag_list, void *fdt, int total_space)

		/*
		 * If returned value is 1, there is no ATAG at the location
		 * pointed by r8.  Try the typical 0x100 offset from start
		 * of RAM and hope for the best.
		 */
		cmp	r0, #1				// atags_to_fdt 의 리턴 값이 1이면 atag를 찾지 못한 것임.
							// 그럴 경우 RAM 시작 주소에 0x100를 더한 뒤 atag를 찾아봄
							// 관행적으로 이 위치에 넣어두는 변태적인 경우가 있음
		sub	r0, r4, #TEXT_OFFSET		// TEXT_OFFSET : 0x0008000
							// r4 : 0x40008000
							// r0 : 0x40000000	(RAM 시작 주소가 됨)
		bic	r0, r0, #1			// r0 : 0x40000000
							// 이전에 cache_on 수행 여부를 하위 1비트에 기록해 두었기 때문에
							// 이를 지워줘야 한다.
		add	r0, r0, #0x100			// r0 : 0x40000100
		mov	r1, r6
		sub	r2, sp, r6
		bleq	atags_to_fdt			// 이전 호출에서 리턴값이 1이었으면 r0를 위 값으로 바꾼 뒤 다시 수행

		ldmfd	sp!, {r0-r3, ip, lr}
		sub	sp, sp, #0x10000		// 스택과 레지스터 전부 복구
#endif

		mov	r8, r6			@ use the appended device tree
						// _edata를 atags 포인터를 가리키는 r8에 넣음
						// appended device tree를 쓰는 것임

		/*
		 * Make sure that the DTB doesn't end up in the final
		 * kernel's .bss area. To do so, we adjust the decompressed
		 * kernel size to compensate if that .bss size is larger
		 * than the relocated code.
		 */
		ldr	r5, =_kernel_bss_size	// vmlinux의 bss 사이즈를 r5에 저장함.
						// 즉 압축 풀린 커널의 bss 크기가 저장됨.
						// 이는 Makefile로 인해 저장됨.
						// arch/arm/boot/compressed/Makefile 내부에
						//KBSS_SZ = $(shell $(CROSS_COMPILE)size $(obj)/../../../../vmlinux | awk 'END{print $$3}')
						//LDFLAGS_vmlinux = --defsym _kernel_bss_size=$(KBSS_SZ)
						// 이 되어 있음.
						// KBSS_SZ는 size 명령과 awk 명령을 조합해서 size 명령의 3번째 결과를 값으로 뽑아냄
						// 이 값이 bss 임.
		adr	r1, wont_overwrite	// wont_overwrite 심볼이 위치한 주소를 r1에 저장
		sub	r1, r6, r1		// _edata - wont_overwrite 후 r1에 저장
		subs	r1, r5, r1		// bss 크기 - r1 후 r1에 저장
						// bss 크기와 r1 값 중 누가 큰 지 판단함
		addhi	r9, r9, r1		// 위 연산의 결과로 수행이 결정됨
						// bss 크기가 r1보다 크면 r9을 더 크게 만듬
						// r9  = size of decompressed image
		/* Get the dtb's size */
		ldr	r5, [r6, #4]		// dtb의 두 번째 워드 자리에는 항상 size 값이 저장되어 있는 것을 이용함.
						// 그런데 이게 항상 big_endian으로 되어 있음
#ifndef __ARMEB__				// 아래부터 이 값을 little_endian으로 변경함
		/* convert r5 (dtb size) to little endian */
		eor	r1, r5, r5, ror #16	// A xor B xor A = B 가 되는 성질을 이용해 변환하고 있음.
		bic	r1, r1, #0x00ff0000
		mov	r5, r5, ror #8
		eor	r5, r5, r1, lsr #8	// 결국 little_endian으로 변경됨
#endif

		/* preserve 64-bit alignment */	// 64 bit alignment를 한다는 뜻은 dtb 크기가 항상 64bit의 배수가 되게 한다는 뜻.
						// 즉 8byte 단위로 size 크기가 올라가게 함.
						// 하위 3비트를 0으로 만들면 됨.
		add	r5, r5, #7		// 위, 아래 연산을 통해 하위 3비트 값이 존재하면 4비트에서 올림을 수행하고
		bic	r5, r5, #7		// 하위 3비트를 0으로 날림

		/* relocate some pointers past the appended dtb */
		add	r6, r6, r5		// _edata = _edata + dtb 크기
						// 코드의 마지막 주소가 dtb 크기까지 포함되서 들어감
		add	r10, r10, r5		// r10 = end of this image, including  bss/stack/malloc space if non XIP
						// 위 수치에 dtb 크기를 더해줌
		add	sp, sp, r5		// stack pointer도 dtb 크기 만큼 더해 위로 올림
dtb_check_done:					// 여기까지 수행한 것은 다음과 같다.
						// dtb가 zImage 뒤에 붙어 있는 경우
						// _edata, zImage의 마지막 위치, sp를 dtb 크기만큼 더해 사이즈를 보정해줌
#endif

/*
 * Check to see if we will overwrite ourselves.
 *   r4  = final kernel address (possibly with LSB set)
 *   r9  = size of decompressed image
 *   r10 = end of this image, including  bss/stack/malloc space if non XIP
 * We basically want:
 *   r4 - 16k page directory >= r10 -> OK
 *   r4 + image length <= address of wont_overwrite -> OK
 * Note: the possible LSB in r4 is harmless here.
 */
		add	r10, r10, #16384	// zImage 마지막 주소에 section table의 크기를 더함
		cmp	r4, r10			// 이 값을 압축 풀 커널 위치와 비교
		bhs	wont_overwrite		// 압축 풀 커널 위치가 더 크면 wont_overwrite로 이동
						// 즉 커널 위치 - 16KB >= zImage 마지막 주소이면
						// 압축을 풀어도 코드가 겹쳐지지 않는다는 것을 확인
		add	r10, r4, r9		// 압축 풀 커널 위치 + 압축 푼 커널 크기를 r10에 저장
						// 즉 압축 푼 커널의 마지막 메모리 주소가 r10에 들어감
		adr	r9, wont_overwrite	// r9에 wont_overwrite 주소를 저장
		cmp	r10, r9			// 두 값을 비교
		bls	wont_overwrite		// 마지막 메모리 주소 < wont_overwrite 이면
						// 압축 풀기로 이동
						// 위의 2가지 경우를 통해 정상적인 경우가 처리됨
						// 만약 압축을 풀면서 코드가 겹치기가 생기는 경우
						// 현재 zImage의 코드 부분을 재배치시키고 압축을 풀어야 함.
/*
 * Relocate ourselves past the end of the decompressed kernel.
 *   r6  = _edata
 *   r10 = end of the decompressed kernel
 * Because we always copy ahead, we need to do it from the end and go
 * backward in case the source and destination overlap.
 */
		/*
		 * Bump to the next 256-byte boundary with the size of
		 * the relocation code added. This avoids overwriting
		 * ourself when the offset is small.
		 */
		add	r10, r10, #((reloc_code_end - restart + 256) & ~255)
						// reloc_code_end - restart 크기를 256 바이트 올림 후
						// 압축 푼 커널의 마지막 위치에 더함
		bic	r10, r10, #255		// 압축 푼 커널의 마지막 위치의 하위 256 주소를 날림
						// 두 코드의 수행을 통해 여유 공간을 확보 하게 됨

		/* Get start of code we want to copy and align it down. */
		adr	r5, restart		// restart의 주소 값을 r5에 저장
		bic	r5, r5, #31		// 32바이트 정렬
						// registor 8개를 써서 이동이 수행되기 때문에
						// 반드시 시작 주소가 32바이트에 정렬되어 있어야 들어 맞는다.

/* Relocate the hyp vector base if necessary */
#ifdef CONFIG_ARM_VIRT_EXT			// 여긴 뺍시다.

		mrs	r0, spsr
		and	r0, r0, #MODE_MASK
		cmp	r0, #HYP_MODE
		bne	1f

		bl	__hyp_get_vectors
		sub	r0, r0, r5
		add	r0, r0, r10
		bl	__hyp_set_vectors
1:
#endif

		sub	r9, r6, r5		@ size to copy
						// _edata - restart 한 뒤 r9 에 저장
		add	r9, r9, #31		@ rounded up to a multiple
		bic	r9, r9, #31		@ ... of 32 bytes
						// 이 크기를 32byte 단위에서 올림
						// 레지스터 8개를 써서 복사할 예정
		add	r6, r9, r5		// restart + 위에서 구한 복사할 size
						// 즉 복사 source의 마지막 주소임
		add	r9, r9, r10		// 복사할 size + 압축 풀 커널의 마지막 주소에 여유분 확보한 주소
						// 즉 복사 destination의 마지막 주소임

1:		ldmdb	r6!, {r0 - r3, r10 - r12, lr}	// decrement before 로드 수행
							// r6에 저장된 주소 값을 줄이면서 레지스터에 데이터 저장
		cmp	r6, r5				// 줄인 값이 복사 source의 시작까지 왔는지 확인
		stmdb	r9!, {r0 - r3, r10 - r12, lr}	// decrement before 스토어 수행
							// r9에 저장된 주소 값을 줄이면서 메모리에 데이터 저장
		bhi	1b				// 만약 복사 source의 시작까지 오지 않았으면 다시 수행
							// 이를 통해 복사 source가 destination으로 복사됨

							// 왜 뒤에서부터 복사하는가?
							// 만약 앞에서부터 복사하면 둘 사이의 offset이 복사 size보다 작을 경우
							// 데이터가 겹쳐 꼬이는 문제가 발생함

		/* Preserve offset to relocated code. */
		sub	r6, r9, r6			// 두 위치의 오프셋을 계산해 r6에 저장해둠
							// 나중에 쓰겠지

#ifndef CONFIG_ZBOOT_ROM
		/* cache_clean_flush may use the stack, so relocate it */
		add	sp, sp, r6			// sp 포인터 위치 변경
#endif

		tst	r4, #1				// 압축 풀 커널 위치와 1 and 연산 비교
							// 이전에 r4 하위 1비트에 cache_on 수행 여부를 기록해 두었음
		bleq	cache_clean_flush		// 수행을 한 경우에만 cache_clen_flush가 수행됨
							// L1, L2 캐쉬 전부 초기화시켰음

		adr	r0, BSYM(restart)		// restart의 주소를 r0로 대입
		add	r0, r0, r6			// r6을 더해 재배치한 restart로 설정
		mov	pc, r0				// restart로 점프
							
							// restart로 돌아가 레지스터 값 오프셋 처리를 다시 해준 후
							// wont_overwrite로 이동된다.
wont_overwrite:
/*
 * If delta is zero, we are running at the address we were linked at.
 *   r0  = delta
 *   r2  = BSS start
 *   r3  = BSS end
 *   r4  = kernel execution address (possibly with LSB set)
 *   r5  = appended dtb size (0 if not present)
 *   r7  = architecture ID
 *   r8  = atags pointer
 *   r11 = GOT start
 *   r12 = GOT end
 *   sp  = stack pointer
 */
		orrs	r1, r0, r5		// r0와 r5를 orr 연산 후 플래그에 저장
		beq	not_relocated		// r0나 r5에 어떤 값이 있으면 무조건 점프 안하는데??
						// r0나 r5에 어떤 값이 있으면 무조건 relocate 처리가 수행된다는 것인듯.
						// r0에 값이 존재하면 실행 타임과 컴파일 타임 사이에 주소값 차이가 존재하기 때문에
						// 링커 스크립트에서 가져온 변수 값을 바꿔줘야 함
						// r5에 값이 존재하면 dtb가 붙은 상황이기 때문에 역시 링커 스크립트에서 가져온 변수 값을 바꿔줘야 함.

		add	r11, r11, r0		// GOT start 조정
		add	r12, r12, r0		// GOT end 조정


#ifndef CONFIG_ZBOOT_ROM
		/*
		 * If we're running fully PIC === CONFIG_ZBOOT_ROM = n,
		 * we need to fix up pointers into the BSS region.
		 * Note that the stack pointer has already been fixed up.
		 */
		add	r2, r2, r0		// bss 시작 주소 보정
		add	r3, r3, r0		// bss 끝 주소 보정


		/*
		 * Relocate all entries in the GOT table.
		 * Bump bss entries to _edata + dtb size
		 */
1:		ldr	r1, [r11, #0]		@ relocate entries in the GOT
						// r1에 GOT 시작 값을 저장
		add	r1, r1, r0		@ This fixes up C references
						// GOT 시작 값에 델타 오프셋을 더함 : entry
		cmp	r1, r2			@ if entry >= bss_start &&
		cmphs	r3, r1			@       bss_end > entry
		addhi	r1, r1, r5		@    entry += dtb size
						// 위 3 연산을 통해 다음이 수행됨
						// bss_end > entry >= bss_start 이면
						// entry += dtb size
		str	r1, [r11], #4		@ next entry
						// 변경한 r1 값을 다시 GOT에 저장
		cmp	r11, r12
		blo	1b			// 모든 GOT에 대해 전부 수행

		/* bump our bss pointers too */
		add	r2, r2, r5		// dtb 크기만큼 bss 영역을 위로 올림
		add	r3, r3, r5

#else

		/*
		 * Relocate entries in the GOT table.  We only relocate
		 * the entries that are outside the (relocated) BSS region.
		 */
1:		ldr	r1, [r11, #0]		@ relocate entries in the GOT
		cmp	r1, r2			@ entry < bss_start ||
		cmphs	r3, r1			@ _end < entry
		addlo	r1, r1, r0		@ table.  This fixes up the
		str	r1, [r11], #4		@ C references.
		cmp	r11, r12
		blo	1b
#endif

not_relocated:	mov	r0, #0			// r0 에 0 대입
1:		str	r0, [r2], #4		@ clear bss
		str	r0, [r2], #4
		str	r0, [r2], #4
		str	r0, [r2], #4
		cmp	r2, r3
		blo	1b			// 모든 bss 영역을 0으로 초기화

		/*
		 * Did we skip the cache setup earlier?
		 * That is indicated by the LSB in r4.
		 * Do it now if so.
		 */
		tst	r4, #1			// cache_on을 수행하였는지 확인
		bic	r4, r4, #1		// 이제는 page_table 영역이 무조건 확보 된 상태이기 때문에
		blne	cache_on		// cache_on 수행을 할 수 있음

/*
 * The C runtime environment should now be setup sufficiently.
 * Set up some pointers, and start decompressing.
 *   r4  = kernel execution address
 *   r7  = architecture ID
 *   r8  = atags pointer
 */
		mov	r0, r4			// 압축 풀 커널 위치를 첫 번째 파라미터로
		mov	r1, sp			@ malloc space above stack
						// sp 위의 공간을 malloc 공간으로 사용하기 위해 두 번째 파라미터로
		add	r2, sp, #0x10000	@ 64k max
						// malloc 최대 공간을 세 번째 파라미터로
		mov	r3, r7			// 아키텍쳐 ID를 네 번째 파라미터로 저장 후 C 함수 콜
		bl	decompress_kernel
		bl	cache_clean_flush	// 캐쉬 초기화
		bl	cache_off		// 캐쉬 끔
						// MMU, 캐쉬, TLB, Branch 예측기 전부 초기화
		mov	r1, r7			@ restore architecture number
		mov	r2, r8			@ restore atags pointer
						// architecture number, atag pointer를 r1, r2로 이동시킴

#ifdef CONFIG_ARM_VIRT_EXT			// 패스
		mrs	r0, spsr		@ Get saved CPU boot mode
		and	r0, r0, #MODE_MASK
		cmp	r0, #HYP_MODE		@ if not booted in HYP mode...
		bne	__enter_kernel		@ boot kernel directly

		adr	r12, .L__hyp_reentry_vectors_offset
		ldr	r0, [r12]
		add	r0, r0, r12

		bl	__hyp_set_vectors
		__HVC(0)			@ otherwise bounce to hyp mode

		b	.			@ should never be reached

		.align	2
.L__hyp_reentry_vectors_offset:	.long	__hyp_reentry_vectors - .
#else
		b	__enter_kernel		// __enter_kernel로 점프
#endif

		.align	2
		.type	LC0, #object
LC0:		.word	LC0			@ r1
		.word	__bss_start		@ r2
		.word	_end			@ r3
		.word	_edata			@ r6
		.word	input_data_end - 4	@ r10 (inflated size location)
		.word	_got_start		@ r11
		.word	_got_end		@ ip
		.word	.L_user_stack_end	@ sp
		.word	_end - restart + 16384 + 1024*1024
		.size	LC0, . - LC0

#ifdef CONFIG_ARCH_RPC
		.globl	params
params:		ldr	r0, =0x10000100		@ params_phys for RPC
		mov	pc, lr
		.ltorg
		.align
#endif

/*
 * Turn on the cache.  We need to setup some page tables so that we
 * can have both the I and D caches on.
 *
 * We place the page tables 16k down from the kernel execution address,
 * and we hope that nothing else is using it.  If we're using it, we
 * will go pop!
 *
 * On entry,
 *  r4 = kernel execution address
 *  r7 = architecture number
 *  r8 = atags pointer
 * On exit,
 *  r0, r1, r2, r3, r9, r10, r12 corrupted
 * This routine must preserve:
 *  r4, r7, r8
 */
// 위 주석에 의하면 I, D cache를 켜기 위해선 page table이 필요하다고 함 ( 왜 ?? )
// 이를 위한 공간이 kernel execution address 아래 16KB가 필요하며 이는 앞에서
// 검사하고 넘어 왔음.
// 만약 공간이 부족하면 cache를 켜지 않고 초기화 코드를 수행하는 것으로 생각됨.

		.align	5			// 2^5 (32byte) 로 정렬
cache_on:	mov	r3, #8			@ cache_on function
		b	call_cache_fn

/*
 * Initialize the highest priority protection region, PR7
 * to cover all 32bit address and cacheable and bufferable.
 */
__armv4_mpu_cache_on:
		mov	r0, #0x3f		@ 4G, the whole
		mcr	p15, 0, r0, c6, c7, 0	@ PR7 Area Setting
		mcr 	p15, 0, r0, c6, c7, 1

		mov	r0, #0x80		@ PR7
		mcr	p15, 0, r0, c2, c0, 0	@ D-cache on
		mcr	p15, 0, r0, c2, c0, 1	@ I-cache on
		mcr	p15, 0, r0, c3, c0, 0	@ write-buffer on

		mov	r0, #0xc000
		mcr	p15, 0, r0, c5, c0, 1	@ I-access permission
		mcr	p15, 0, r0, c5, c0, 0	@ D-access permission

		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c7, c5, 0	@ flush(inval) I-Cache
		mcr	p15, 0, r0, c7, c6, 0	@ flush(inval) D-Cache
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
						@ ...I .... ..D. WC.M
		orr	r0, r0, #0x002d		@ .... .... ..1. 11.1
		orr	r0, r0, #0x1000		@ ...1 .... .... ....

		mcr	p15, 0, r0, c1, c0, 0	@ write control reg

		mov	r0, #0
		mcr	p15, 0, r0, c7, c5, 0	@ flush(inval) I-Cache
		mcr	p15, 0, r0, c7, c6, 0	@ flush(inval) D-Cache
		mov	pc, lr

__armv3_mpu_cache_on:
		mov	r0, #0x3f		@ 4G, the whole
		mcr	p15, 0, r0, c6, c7, 0	@ PR7 Area Setting

		mov	r0, #0x80		@ PR7
		mcr	p15, 0, r0, c2, c0, 0	@ cache on
		mcr	p15, 0, r0, c3, c0, 0	@ write-buffer on

		mov	r0, #0xc000
		mcr	p15, 0, r0, c5, c0, 0	@ access permission

		mov	r0, #0
		mcr	p15, 0, r0, c7, c0, 0	@ invalidate whole cache v3
		/*
		 * ?? ARMv3 MMU does not allow reading the control register,
		 * does this really work on ARMv3 MPU?
		 */
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
						@ .... .... .... WC.M
		orr	r0, r0, #0x000d		@ .... .... .... 11.1
		/* ?? this overwrites the value constructed above? */
		mov	r0, #0
		mcr	p15, 0, r0, c1, c0, 0	@ write control reg

		/* ?? invalidate for the second time? */
		mcr	p15, 0, r0, c7, c0, 0	@ invalidate whole cache v3
		mov	pc, lr

#ifdef CONFIG_CPU_DCACHE_WRITETHROUGH
#define CB_BITS 0x08
#else
#define CB_BITS 0x0c
#endif

// r4 : 0x40008000 - zreladdr 값임.
// 커널 압축이 풀릴 위치임

__setup_mmu:	sub	r3, r4, #16384		@ Page directory size
						// 커널 시작 위치에서 page directory 크기만큼 뺌
						// r3 = 0x40004000
		bic	r3, r3, #0xff		@ Align the pointer
		bic	r3, r3, #0x3f00		// bic r3, r3, #0x3fff 으로 하지 않은 이유
						// ARM은 immediate를 rot4 + imm8로 표현
						// 그러므로 0x3fff를 imm 로 한 번에 인코딩이 불가능함.
						// 그렇기 때문에 2개 명령으로 쪼개서 만듬.
						// 16KB로 내림 연산이 수행됨
/*				
 * Initialise the page tables, turning on the cacheable and bufferable
 * bits for the RAM area only.
 */
		mov	r0, r3			// r0 = 0x40004000
		mov	r9, r0, lsr #18		// r9 = 0x1000 (16KB)
		mov	r9, r9, lsl #18		@ start of RAM
						// r9 = 0x40000000 이 저장됨
						// 이는 RAM의 시작 주소가 된다.
						// 관례상 커널의 압축은 RAM 시작 주소에 0x8000을 더한 주소에
						// 압축을 풀도록 되어 있기(??)때문에 위 연산을 통해 RAM 시작 주소를
						// 뽑아낼 수 있다.
		add	r10, r9, #0x10000000	@ a reasonable RAM size
						// RAM 시작 주소 + 256MB
						// r10 = 0x50000000
		mov	r1, #0x12		@ XN|U + section mapping
						// r1 = 0b10010
						// Execute Never 비트를 r1에 만듬
		orr	r1, r1, #3 << 10	@ AP=11
						// AP[1:0] 비트를 11로 만들어 r1에 넣음
						// AP[2] 비트는 현재 0임
						// Full Access 권한을 설정함
						// r1 = 0xC12
		add	r2, r3, #16384		// r2 = 0x40008000 : 커널의 압축이 풀릴 장소

		// r1 : 가변, r9 : 0x40000000, r10 : 0x50000000
1:		cmp	r1, r9			@ if virt > start of RAM
		cmphs	r10, r1			@   && end of RAM > virt
		bic	r1, r1, #0x1c		@ clear XN|U + C + B
						// Execute  + Strongly-ordered, sharable 설정 
		orrlo	r1, r1, #0x10		@ Set XN|U for non-RAM
						// Execute Never 설정
		orrhs	r1, r1, r6		@ set RAM section settings
						// r6 = 0xE
						// Write Back Cache 설정
		str	r1, [r0], #4		@ 1:1 mapping
						// r0가 가리키는 주소에 r1을 저장하고 r0 += 4 수행
		add	r1, r1, #1048576	// 1MB씩 주소를 추가함
						// 즉 Section Base Address가 1씩 증가 됨
		teq	r0, r2
		bne	1b
		// 위의 루프문이 하는 역할
		// 0x00000000 ~ 0x3fffffff 까지는 Excute Never, Strongly-ordered 설정
		// 0x40000000 ~ 0x4fffffff 까지는 Excute, Write Back Cache 설정
		// 0x50000000 ~ 0xffffffff 까지는 Excute Never, Strongly-ordered 설정
		// 앞 부분의 Section Base Address 는 물리주소를 가상주소에 그대로 매핑한다.
		// 현재까지는 Section Table 만 제작함
/*
 * If ever we are running from Flash, then we surely want the cache
 * to be enabled also for our execution instance...  We map 2MB of it
 * so there is no map overlap problem for up to 1 MB compressed kernel.
 * If the execution is in RAM then we would only be duplicating the above.
 */
		orr	r1, r6, #0x04		@ ensure B is set for this
						// r1 = 0xE : Write Back Cache
		orr	r1, r1, #3 << 10	// r1 = 0xCE : Full Access
		mov	r2, pc			// r2 = ip
						// 현재 명령어의 주소를 넣음
		mov	r2, r2, lsr #20		// 현재 명령어의 section offset 을 알아냄
		orr	r1, r1, r2, lsl #20	// Section Base Address | Control Bit
						// 현재 명령이 실행되고 있는 메모리 영역을 
						// Excute, Write Back Cache, Full Access 로 Section을 만들어줌.
		add	r0, r3, r2, lsl #2	// page table 시작 주소 + pc에 해당하는 page offset
						// 결국 pc에 해당하는 page offset을 저장할 정확한 메모리 주소를 뽑아냄
						// lsl #2는 Section 1개당 4바이트를 사용하기 때문
		str	r1, [r0], #4		// 위에서 만든 section을 저장함.
		add	r1, r1, #1048576	// Section Base Address 에 1MB 추가
		str	r1, [r0]		// 다음 Section에도 권한 설정
						// 그러므로 현재 pc에 해당하는 섹션과 그 다음 섹션까지
						// 총 2MB를 권한 설정 걸어줌
						// Flash에서 코드를 수행 할 때만 의미가 있고 
						// 메모리에 복사한 뒤 수행하는 경우는 
						// 위의 루프에서 수행한 일을 중복 수행하는 것으로 볼 수 있음
		mov	pc, lr			
ENDPROC(__setup_mmu)

@ Enable unaligned access on v6, to allow better code generation
@ for the decompressor C code:
__armv6_mmu_cache_on:
		mrc	p15, 0, r0, c1, c0, 0	@ read SCTLR
		bic	r0, r0, #2		@ A (no unaligned access fault)
		orr	r0, r0, #1 << 22	@ U (v6 unaligned access model)
		mcr	p15, 0, r0, c1, c0, 0	@ write SCTLR
		b	__armv4_mmu_cache_on

__arm926ejs_mmu_cache_on:
#ifdef CONFIG_CPU_DCACHE_WRITETHROUGH
		mov	r0, #4			@ put dcache in WT mode
		mcr	p15, 7, r0, c15, c0, 0
#endif

__armv4_mmu_cache_on:
		mov	r12, lr
#ifdef CONFIG_MMU
		mov	r6, #CB_BITS | 0x12	@ U
		bl	__setup_mmu
		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c8, c7, 0	@ flush I,D TLBs
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
		orr	r0, r0, #0x5000		@ I-cache enable, RR cache replacement
		orr	r0, r0, #0x0030
 ARM_BE8(	orr	r0, r0, #1 << 25 )	@ big-endian page tables
		bl	__common_mmu_cache_on
		mov	r0, #0
		mcr	p15, 0, r0, c8, c7, 0	@ flush I,D TLBs
#endif
		mov	pc, r12

__armv7_mmu_cache_on:
		mov	r12, lr			// 현재 lr을 r12에 저장함.
						// 원래는 스택에 저장하는 스타일을 취해야 하지만
						// 현재는 스택이 없으므로 그냥 레지스터에 저장함.
#ifdef CONFIG_MMU
		mrc	p15, 0, r11, c0, c1, 4	@ read ID_MMFR0
						// MMFR0를 r11에 저장.
						// Memory Model Feature Register0
		// memory menagement 지원이 어느 기능까지 되는지 저장됨.
		tst	r11, #0xf		@ VMSA
						// MMFR0 하위 4비트에 VMSA값이 저장되어 있음
						// Cortex A-15 : 0x05
						// VMSA 지원여부를 확인함
		movne	r6, #CB_BITS | 0x02	@ !XN
						// VMSA를 지원하면 수행됨
						// 현재 D-Cache WriteBack이므로 CB_BITS = 0xC
						// r6 = 0xE
		blne	__setup_mmu		// VMSA를 지원하면 점프 Cortex A-15는 이리로 이동
						// 위 함수에서는 mmu를 위한 Section Page Table을 만들어줌.
						// 0x00000000 ~ 0x3fffffff : Strongly-Ordered, XN
						// 0x40000000 ~ 0x4fffffff : Write Back Cache, X
						// 0x50000000 ~ 0xffffffff : Strongly-Ordered, XN
						// 모두 Full Access 권한
						// 아직 mmu를 켠 것은 아님
		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
						// CP15DSB(Data Synchronization Barrier 레지스터)에 0을 저장
						// DSB 연산을 통해 write buffer에 있는 내용을 확실하게
						// 메모리에 저장시킴
						// MMU 켜기 전에 table 만든 내용을 확실하게 메모리에 올리기 위함
		tst	r11, #0xf		@ VMSA
		mcrne	p15, 0, r0, c8, c7, 0	@ flush I,D TLBs
						// VMSA 지원 여부 확인 후 지원하면
						// 모든 TLB 내용을 통채로 초기화
						// MMU 켜기 전에 반드시 수행해야 함
#endif
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
						// SCTLR을 r0에 저장
						// System Control Register
						// 전반적인 전체 시스템에 대한 옵션을 설정함
		bic	r0, r0, #1 << 28	@ clear SCTLR.TRE
						// TRE 비트를 0으로 변경
						// TRE 비트가 꺼지면  TEX[2:0], C, B 비트가 메모리 특성 설정에 사용됨
						// TRE 비트가 켜지면 TEX[2:1]은 OS에 의해 아무 용도로나 사용가능해지며
						// TEX[0], C, B, MMU 내부 레지스터에 의해 메모리 특성이 설정됨
						// Remap disabled
		orr	r0, r0, #0x5000		@ I-cache enable, RR cache replacement
						// I-Cache를 켜고 RR cache 교체 정책을 선택함
						// RR 비트는 cache replacement 정책을 선택하는 것인데 1로 선택하면
						// 좀 더 좋은 정책으로 결정된다.
						// 하지만 Cortex-A15는 이 비트가 RAZ/WI (Read as zero/Write Ignoreed)로 되어
						// 아무 영향도 미치지 않는다.
		orr	r0, r0, #0x003c		@ write buffer
						// CP15BEN 비트와 C 비트를 1로 변경
						// CP15BEN 비트는 cp15 barrier enable 비트이다.
						// 1로 설정되면 DMB, DSB, ISB barrier 명령들이 사용 가능해진다.
						// Cortex-A15의 경우 RAO/SBOP(Read as one/Should be one or preserved on write)
						// 이므로 항상 사용 가능한 상태이다.
						// C 비트는 캐쉬를 켜는 명령으로 Data or unified Cache를 켠다.
						// A15는 Split캐쉬 이므로 Data 캐쉬를 켜게 된다.
		bic	r0, r0, #2		@ A (no unaligned access fault)
						// Alignment Check를 끔
		orr	r0, r0, #1 << 22	@ U (v6 unaligned access model)
						@ (needed for ARM1176)
						// 하위 호환을 위한 기능 Cortex-A15에서는 그냥 1로 되어있다.
#ifdef CONFIG_MMU
 ARM_BE8(	orr	r0, r0, #1 << 25 )	@ big-endian page tables
 						// 그냥 통과
		mrcne   p15, 0, r6, c2, c0, 2   @ read ttb control reg
						// TTBCR 레지스터 값을 r6에 저장
						// TTBCR은 TTBR0와 TTBR1 중에 Translation table 로 쓸 것을 선택하는 것임.
						// 1-level 변환에서만 사용됨
		orrne	r0, r0, #1		@ MMU enabled
						// MMU 켜는 비트를 설정
						// 아직 r0에 있으므로 실제 켜진 것은 아님
		movne	r1, #0xfffffffd		@ domain 0 = client
						// r1에 상수값 저장
		bic     r6, r6, #1 << 31        @ 32-bit translation system
						// TTBCR의 31번 비트를 0으로 변경
						// 32bit translation system과 short descriptor 형태로 사용을 결정
		bic     r6, r6, #3 << 0         @ use only ttbr0
						// TTBR0에서 base 주소 길이를 얼마로 할지 지정함.
						// 0으로 세팅되므로 [31:14] 까지가 base 주소값이 됨.
						// 즉 16KB로 정렬된 table 자료가 필요해짐
		mcrne	p15, 0, r3, c2, c0, 0	@ load page table pointer
						// r3 : 0x40004000
						// TTBR0에 r3 값을 저장함
		mcrne	p15, 0, r1, c3, c0, 0	@ load domain access control
						// r1 : 0xFFFFFFFD 
						// DACR에 값을 저장함.
						// D15 ~ D1까지는 무조건 접근 가능이 되며
						// D0는 translation table의 권한 비트를 확인함.
						// 앞에서 Section 값을 만들 때 도메인 비트는 전부 0이었음.
						// 그러므로 모든 메모리 영역은 D0 설정을 따르며 항상 Section의 권한 비트를 확인함.
		mcrne   p15, 0, r6, c2, c0, 2   @ load ttb control
						// r6 : 위에서 만든 TTBCR 값
						// TTBCR 값을 저장함.
#endif
		mcr	p15, 0, r0, c7, c5, 4	@ ISB
						// Instruction Synchoronization Barrier 연산 수행
						// 파이프 라인을 전부 비우고 이전의 명령을 무조건 전부 수행한 뒤 
						// 다음 명령을 수행하게 함.
						// CP15의 레지스터 값을 바꾸면 반드시 수행해야함.
						// r0는 그냥 써준 값임. 연산에 아무 변경 없음
		mcr	p15, 0, r0, c1, c0, 0	@ load control register
						// SCTRL 레지스터를 업데이트
		mrc	p15, 0, r0, c1, c0, 0	@ and read it back
						// 다시 읽어들임.
		mov	r0, #0			// r0에 0 대입
		mcr	p15, 0, r0, c7, c5, 4	@ ISB
						// ISB 연산 수행해 SCTRL 레지스터를 확실하게 업데이트 함.
		mov	pc, r12			// cache_on 호출 장소로 복귀

__fa526_cache_on:
		mov	r12, lr
		mov	r6, #CB_BITS | 0x12	@ U
		bl	__setup_mmu
		mov	r0, #0
		mcr	p15, 0, r0, c7, c7, 0	@ Invalidate whole cache
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c8, c7, 0	@ flush UTLB
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
		orr	r0, r0, #0x1000		@ I-cache enable
		bl	__common_mmu_cache_on
		mov	r0, #0
		mcr	p15, 0, r0, c8, c7, 0	@ flush UTLB
		mov	pc, r12

__common_mmu_cache_on:
#ifndef CONFIG_THUMB2_KERNEL
#ifndef DEBUG
		orr	r0, r0, #0x000d		@ Write buffer, mmu
#endif
		mov	r1, #-1
		mcr	p15, 0, r3, c2, c0, 0	@ load page table pointer
		mcr	p15, 0, r1, c3, c0, 0	@ load domain access control
		b	1f
		.align	5			@ cache line aligned
1:		mcr	p15, 0, r0, c1, c0, 0	@ load control register
		mrc	p15, 0, r0, c1, c0, 0	@ and read it back to
		sub	pc, lr, r0, lsr #32	@ properly flush pipeline
#endif

#define PROC_ENTRY_SIZE (4*5)

/*
 * Here follow the relocatable cache support functions for the
 * various processors.  This is a generic hook for locating an
 * entry and jumping to an instruction at the specified offset
 * from the start of the block.  Please note this is all position
 * independent code.
 *
 *  r1  = corrupted
 *  r2  = corrupted
 *  r3  = block offset
 *  r9  = corrupted
 *  r12 = corrupted
 */
	// 현재 r3에 8 넣고 들어옴
call_cache_fn:	
		adr	r12, proc_types		// r12에 proc_types의 주소 넣음
#ifdef CONFIG_CPU_CP15
		mrc	p15, 0, r9, c0, c0	@ get processor ID
						// r9에 MIDR 레지스터를 저장
						// For an ARMv7 implementation by ARM, the MIDR is interpreted as:
						// Bits[31:24] Implementer code, must be 0x41.
						// Bits[23:20] Major revision number, rX.
						// Bits[19:16] Architecture code, must be 0xF.
						// Bits[15:4] ARM part number.
						// Bits[3:0] Minor revision number, pY.
#else
		ldr	r9, =CONFIG_PROCESSOR_ID	// 수행 안됨
#endif
1:		ldr	r1, [r12, #0]		@ get value
						// r1 = *(r12 + 0)
						// r1 = 0x41000000
		ldr	r2, [r12, #4]		@ get mask
						// r2 = *(r12 + 4)
						// r2 = 0xff00f000
		eor	r1, r1, r9		@ (real ^ match)
		tst	r1, r2			@       & mask
 ARM(		addeq	pc, r12, r3		) @ call cache function
						// 현재 동작하는 CPU와 proc_types이 일치하는 지 확인
						// 일치하면 r3에 저장한 값을 r12에 더한 뒤 pc에 넣음으로서
						// 현재 CPU에 일치하는 특정 cache 함수를 수행할 수 있음
 THUMB(		addeq	r12, r3			)
 THUMB(		moveq	pc, r12			) @ call cache function
		add	r12, r12, #PROC_ENTRY_SIZE
						// r12 += 20
						// CPU가 일치하지 않으면 다음 CPU로 이동
		b	1b			// 일치할 때까지 반복 수행
/*
 * Table for cache operations.  This is basically:
 *   - CPU ID match
 *   - CPU ID mask
 *   - 'cache on' method instruction
 *   - 'cache off' method instruction
 *   - 'cache flush' method instruction
 *
 * We match an entry using: ((real_id ^ match) & mask) == 0
 *
 * Writethrough caches generally only need 'on' and 'off'
 * methods.  Writeback caches _must_ have the flush method
 * defined.
 */
		.align	2
		.type	proc_types,#object
proc_types:
		.word	0x41000000		@ old ARM ID
		.word	0xff00f000
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		.word	0x41007000		@ ARM7/710
		.word	0xfff8fe00
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		.word	0x41807200		@ ARM720T (writethrough)
		.word	0xffffff00
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		mov	pc, lr
 THUMB(		nop				)

		.word	0x41007400		@ ARM74x
		.word	0xff00ff00
		W(b)	__armv3_mpu_cache_on
		W(b)	__armv3_mpu_cache_off
		W(b)	__armv3_mpu_cache_flush
		
		.word	0x41009400		@ ARM94x
		.word	0xff00ff00
		W(b)	__armv4_mpu_cache_on
		W(b)	__armv4_mpu_cache_off
		W(b)	__armv4_mpu_cache_flush

		.word	0x41069260		@ ARM926EJ-S (v5TEJ)
		.word	0xff0ffff0
		W(b)	__arm926ejs_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

		.word	0x00007000		@ ARM7 IDs
		.word	0x0000f000
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		@ Everything from here on will be the new ID system.

		.word	0x4401a100		@ sa110 / sa1100
		.word	0xffffffe0
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x6901b110		@ sa1110
		.word	0xfffffff0
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x56056900
		.word	0xffffff00		@ PXA9xx
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x56158000		@ PXA168
		.word	0xfffff000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

		.word	0x56050000		@ Feroceon
		.word	0xff0f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

#ifdef CONFIG_CPU_FEROCEON_OLD_ID
		/* this conflicts with the standard ARMv5TE entry */
		.long	0x41009260		@ Old Feroceon
		.long	0xff00fff0
		b	__armv4_mmu_cache_on
		b	__armv4_mmu_cache_off
		b	__armv5tej_mmu_cache_flush
#endif

		.word	0x66015261		@ FA526
		.word	0xff01fff1
		W(b)	__fa526_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__fa526_cache_flush

		@ These match on the architecture ID

		.word	0x00020000		@ ARMv4T
		.word	0x000f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x00050000		@ ARMv5TE
		.word	0x000f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x00060000		@ ARMv5TEJ
		.word	0x000f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

		.word	0x0007b000		@ ARMv6
		.word	0x000ff000
		W(b)	__armv6_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv6_mmu_cache_flush
		
		//
		// ARMv7 용 cache 관련 함수
		//
		.word	0x000f0000		@ new CPU Id
		.word	0x000f0000
		W(b)	__armv7_mmu_cache_on
		W(b)	__armv7_mmu_cache_off
		W(b)	__armv7_mmu_cache_flush

		.word	0			@ unrecognised type
		.word	0
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		.size	proc_types, . - proc_types

		/*
		 * If you get a "non-constant expression in ".if" statement"
		 * error from the assembler on this line, check that you have
		 * not accidentally written a "b" instruction where you should
		 * have written W(b).
		 */
		.if (. - proc_types) % PROC_ENTRY_SIZE != 0
		.error "The size of one or more proc_types entries is wrong."
		.endif

/*
 * Turn off the Cache and MMU.  ARMv3 does not support
 * reading the control register, but ARMv4 does.
 *
 * On exit,
 *  r0, r1, r2, r3, r9, r12 corrupted
 * This routine must preserve:
 *  r4, r7, r8
 */
		.align	5
cache_off:	mov	r3, #12			@ cache_off function
		b	call_cache_fn

__armv4_mpu_cache_off:
		mrc	p15, 0, r0, c1, c0
		bic	r0, r0, #0x000d
		mcr	p15, 0, r0, c1, c0	@ turn MPU and cache off
		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c7, c6, 0	@ flush D-Cache
		mcr	p15, 0, r0, c7, c5, 0	@ flush I-Cache
		mov	pc, lr

__armv3_mpu_cache_off:
		mrc	p15, 0, r0, c1, c0
		bic	r0, r0, #0x000d
		mcr	p15, 0, r0, c1, c0, 0	@ turn MPU and cache off
		mov	r0, #0
		mcr	p15, 0, r0, c7, c0, 0	@ invalidate whole cache v3
		mov	pc, lr

__armv4_mmu_cache_off:
#ifdef CONFIG_MMU
		mrc	p15, 0, r0, c1, c0
		bic	r0, r0, #0x000d
		mcr	p15, 0, r0, c1, c0	@ turn MMU and cache off
		mov	r0, #0
		mcr	p15, 0, r0, c7, c7	@ invalidate whole cache v4
		mcr	p15, 0, r0, c8, c7	@ invalidate whole TLB v4
#endif
		mov	pc, lr

__armv7_mmu_cache_off:
		mrc	p15, 0, r0, c1, c0	// SCTLR 레지스터 값을 r0로 저장
#ifdef CONFIG_MMU
		bic	r0, r0, #0x000d		// C, M 비트를 0으로 날림
#else
		bic	r0, r0, #0x000c
#endif
		mcr	p15, 0, r0, c1, c0	@ turn MMU and cache off
						// MMU와 캐쉬 꺼짐
		mov	r12, lr			// r12에 lr 값 저장
		bl	__armv7_mmu_cache_flush	// cache 전부 초기화
		mov	r0, #0			// r0에 0 대입
#ifdef CONFIG_MMU
		mcr	p15, 0, r0, c8, c7, 0	@ invalidate whole TLB
						// TLB 전부 초기화
#endif
		mcr	p15, 0, r0, c7, c5, 6	@ invalidate BTC
						// Brach 예측기 전부 초기화
		mcr	p15, 0, r0, c7, c10, 4	@ DSB
		mcr	p15, 0, r0, c7, c5, 4	@ ISB
						// Synch Barrier 연산을 통해 MMU 처리가 확실하게 되게 만듬
		mov	pc, r12

/*
 * Clean and flush the cache to maintain consistency.
 *
 * On exit,
 *  r1, r2, r3, r9, r10, r11, r12 corrupted
 * This routine must preserve:
 *  r4, r6, r7, r8
 */
		.align	5			// 32바이트 정렬
cache_clean_flush:
		mov	r3, #16			// 16을 넣음 즉, 5번째 것을 수행하겠다는 뜻임
		b	call_cache_fn

__armv4_mpu_cache_flush:
		mov	r2, #1
		mov	r3, #0
		mcr	p15, 0, ip, c7, c6, 0	@ invalidate D cache
		mov	r1, #7 << 5		@ 8 segments
1:		orr	r3, r1, #63 << 26	@ 64 entries
2:		mcr	p15, 0, r3, c7, c14, 2	@ clean & invalidate D index
		subs	r3, r3, #1 << 26
		bcs	2b			@ entries 63 to 0
		subs 	r1, r1, #1 << 5
		bcs	1b			@ segments 7 to 0

		teq	r2, #0
		mcrne	p15, 0, ip, c7, c5, 0	@ invalidate I cache
		mcr	p15, 0, ip, c7, c10, 4	@ drain WB
		mov	pc, lr
		
__fa526_cache_flush:
		mov	r1, #0
		mcr	p15, 0, r1, c7, c14, 0	@ clean and invalidate D cache
		mcr	p15, 0, r1, c7, c5, 0	@ flush I cache
		mcr	p15, 0, r1, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv6_mmu_cache_flush:
		mov	r1, #0
		mcr	p15, 0, r1, c7, c14, 0	@ clean+invalidate D
		mcr	p15, 0, r1, c7, c5, 0	@ invalidate I+BTB
		mcr	p15, 0, r1, c7, c15, 0	@ clean+invalidate unified
		mcr	p15, 0, r1, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv7_mmu_cache_flush:			// 이쪽으로 날아옴
		mrc	p15, 0, r10, c0, c1, 5	@ read ID_MMFR1
						// ID_MMFR1 값을 r10에 저장
						// Memory Model Feature로 캐쉬 구조에 대한 내용을 저장하고 있음
		tst	r10, #0xf << 16		@ hierarchical cache (ARMv7)
						// 23:16비트를 검사
						// 만약 전부 0이면 hierarchical cache로서 특수 연산이 더 필요함
		mov	r10, #0			// 0 대입
		beq	hierarchical		// exynos 5420은 ARMv7이므로 특수 처리가 필요

		mcr	p15, 0, r10, c7, c14, 0	@ clean+invalidate D
		b	iflush
hierarchical:
		mcr	p15, 0, r10, c7, c10, 5	@ DMB
						// Data Memory Barrier 연산이 수행됨
						// 이전의 Memory Access가 완전히 종료되게 만듬.
						// 캐쉬 조작을 하기 전에는 수행해야함.
		stmfd	sp!, {r0-r7, r9-r11}	// 스택에 사용할 레지스터를 저장해 둠.

		mrc	p15, 1, r0, c0, c0, 1	@ read clidr
						// CLIDR을 r0에 저장
						// 캐쉬의 계층 정보를 저장하고 있음
		ands	r3, r0, #0x7000000	@ extract loc from clidr
						// CLIDR의 26:24 비트를 r3에 저장
						// LOC 정보를 가져옴
						// Level Of Coherency
		mov	r3, r3, lsr #23		@ left align loc bit field
						// 23비트 오른쪽으로 밀어 LOC 정보를 하위 비트로 이동시킴
						// 완전히 하위는 아니고 하위 2번째 비트부터 LOC 정보가 됨
		beq	finished		@ if loc is 0, then no need to clean
						// ands 의 결과로 인해 이동이 결정됨
						// A15의 경우 L2 cache이므로 이 값이 0b10이다.
						// 즉 L1, L2 캐쉬를 날릴 필요가 있다는 뜻임
						// 그 다음은 메모리이므로 관리할 필요 없음
						// 그러므로 점프 안함
		mov	r10, #0			@ start clean at cache level 0
						// r10에 0 저장
loop1:
		add	r2, r10, r10, lsr #1	@ work out 3x current cache level
						// 첫 번째 루프 : r2 = 0
						// 두 번째 루프 : r2 = 3
		mov	r1, r0, lsr r2		@ extract cache type bits from clidr
						// r0 값을 r2 만큼 오른쪽으로 밀고 r1에 대입
						// r0 값은 CLDIR 값으로 Ctype 값을 뽑아냄
						// 첫 번째 루프에서는 L1 캐쉬의 형태를 뽑아내며
						// Cortex-A15에서는 0b011임 (I, D 캐쉬 분리형태)
						// 두 번째 루프에서는 L2 캐쉬의 형태를 뽑아내며
						// Cortex-A15에서는 0b100임 (I, D 캐쉬 통합형태)
		and	r1, r1, #7		@ mask of the bits for current cache only
						// Ctype 값만 남기고 클리어
						// Ctype 만 남기기 위함임.
		cmp	r1, #2			@ see what cache we have at this level
						// Ctype 값이 2 인지 확인 (D 캐쉬가 있는 형태)
		blt	skip			@ skip if no cache, or just i-cache
						// 2 보다 작은 값을 가지면 skip으로 점프함.
						// 0 : 캐쉬 없음
						// 1 : 명령 캐쉬만 존재
						// 캐쉬가 없거나 명령 캐쉬만 존재하면 skip으로 이동
		mcr	p15, 2, r10, c0, c0, 0	@ select current cache level in cssr
						// 첫 번째 루프 : r10 = 0 임
						// CSSELR 레지스터로 0 대입
						// CSIDR 레지스터 내용을 L1 캐쉬로 만들라는 뜻임
						// 두 번째 루프 : r10 = 2 임
						// CSSELR 레지스터로 2 대입
						// CSIDR 레지스터 내용을 L2 캐쉬로 만들라는 뜻임
		mcr	p15, 0, r10, c7, c5, 4	@ isb to sych the new cssr&csidr
						// ISB : Instruction Synchronization Barrier
						// 위 명령을 코프로세서에 확실하게 수행 시키라는 것임.
						// 이렇게 해야 정확하게 CCSIDR 값이 변경됨
		mrc	p15, 1, r1, c0, c0, 0	@ read the new csidr
						// 첫 번째 루프 : L1 캐쉬 내용이 r1에 저장됨
						// 두 번째 루프 : L2 캐쉬 내용이 r1에 저장됨
		and	r2, r1, #7		@ extract the length of the cache lines
						// CCSIDR 의 하위 3비트가 r2에 저장됨
		add	r2, r2, #4		@ add 4 (line length offset)
						// r2 + 4 >> 라인 길이가 저장됨(정확히는 아닌데?)
		ldr	r4, =0x3ff		// r4 = 0x3FF 가 저장됨
		ands	r4, r4, r1, lsr #3	@ find maximum number on the way size
						// Associativity가 r4에 저장됨
		clz	r5, r4			@ find bit position of way size increment
						// r4에서 가장 큰 자리수가 몇인지 확인
						// r4의 0이 아닌 최상위 비트와 MSB 사이에 0이 몇 개 있는지 셈
		ldr	r7, =0x7fff		// r7에 0x7FFF 대입
		ands	r7, r7, r1, lsr #13	@ extract max number of the index size
						// CSIDR을 13비트 오른쪽으로 밀고 r7과 and 연산
						// NumSet 값이 r7에 저장됨 (set의 갯수, index의 길이)
loop2:
		mov	r9, r4			@ create working copy of max way size
						// r4를 r9로 저장
						// 즉 Associativity가 r9에 저장
loop3:
 ARM(		orr	r11, r10, r9, lsl r5	) @ factor way and cache number into r11
 						// Associativity를 왼쪽으로 이동시킨 후 r10과 or연산
 						// 첫 번째 루프에서는 r10이 0이므로 Associativity 값이 r11로 들어감
 						// Level과 Way 값이 설정됨
 ARM(		orr	r11, r11, r7, lsl r2	) @ factor index number into r11
 						// Set 값이 설정됨

 THUMB(		lsl	r6, r9, r5		)
 THUMB(		orr	r11, r10, r6		) @ factor way and cache number into r11
 THUMB(		lsl	r6, r7, r2		)
 THUMB(		orr	r11, r11, r6		) @ factor index number into r11
		mcr	p15, 0, r11, c7, c14, 2	@ clean & invalidate by set/way
						// clean : 캐쉬 내용을 전부 메모리에 반영
						// invalidate : 캐쉬 내용을 무효화
						//		그러므로 hit은 발생하지 않음 무조건 다시 불러와야 함.
		subs	r9, r9, #1		@ decrement the way
						// r9을 하나 줄임
						// way를 줄이는 것임
		bge	loop3
		subs	r7, r7, #1		@ decrement the index
						// set을 하나 줄임 그러므로 인덱스 값이 줄어듬
		bge	loop2
skip:
		add	r10, r10, #2		@ increment cache number
		cmp	r3, r10			// 첫 번째 루프에서 r3 : 0b100, r10 : 0b010
		bgt	loop1			// L2 까지 돌고 종료
finished:
		ldmfd	sp!, {r0-r7, r9-r11}	// 스택 복구
		mov	r10, #0			@ swith back to cache level 0
						// r10에 0 대입
		mcr	p15, 2, r10, c0, c0, 0	@ select current cache level in cssr
						// CSSELR 레지스터에 0 대입
						// L1 캐쉬 선택
iflush:
		mcr	p15, 0, r10, c7, c10, 4	@ DSB
		mcr	p15, 0, r10, c7, c5, 0	@ invalidate I+BTB
						// I 캐쉬 무효화 >> hit는 안생기고 새로 불러 와야 함
		mcr	p15, 0, r10, c7, c10, 4	@ DSB
		mcr	p15, 0, r10, c7, c5, 4	@ ISB
		mov	pc, lr

__armv5tej_mmu_cache_flush:
1:		mrc	p15, 0, r15, c7, c14, 3	@ test,clean,invalidate D cache
		bne	1b
		mcr	p15, 0, r0, c7, c5, 0	@ flush I cache
		mcr	p15, 0, r0, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv4_mmu_cache_flush:
		mov	r2, #64*1024		@ default: 32K dcache size (*2)
		mov	r11, #32		@ default: 32 byte line size
		mrc	p15, 0, r3, c0, c0, 1	@ read cache type
		teq	r3, r9			@ cache ID register present?
		beq	no_cache_id
		mov	r1, r3, lsr #18
		and	r1, r1, #7
		mov	r2, #1024
		mov	r2, r2, lsl r1		@ base dcache size *2
		tst	r3, #1 << 14		@ test M bit
		addne	r2, r2, r2, lsr #1	@ +1/2 size if M == 1
		mov	r3, r3, lsr #12
		and	r3, r3, #3
		mov	r11, #8
		mov	r11, r11, lsl r3	@ cache line size in bytes
no_cache_id:
		mov	r1, pc
		bic	r1, r1, #63		@ align to longest cache line
		add	r2, r1, r2
1:
 ARM(		ldr	r3, [r1], r11		) @ s/w flush D cache
 THUMB(		ldr     r3, [r1]		) @ s/w flush D cache
 THUMB(		add     r1, r1, r11		)
		teq	r1, r2
		bne	1b

		mcr	p15, 0, r1, c7, c5, 0	@ flush I cache
		mcr	p15, 0, r1, c7, c6, 0	@ flush D cache
		mcr	p15, 0, r1, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv3_mmu_cache_flush:
__armv3_mpu_cache_flush:
		mov	r1, #0
		mcr	p15, 0, r1, c7, c0, 0	@ invalidate whole cache v3
		mov	pc, lr

/*
 * Various debugging routines for printing hex characters and
 * memory, which again must be relocatable.
 */
#ifdef DEBUG
		.align	2
		.type	phexbuf,#object
phexbuf:	.space	12
		.size	phexbuf, . - phexbuf

@ phex corrupts {r0, r1, r2, r3}
phex:		adr	r3, phexbuf	// 어셈블러 매크로 명령
					// phexbuf 주소가 r3에 들어감.
		mov	r2, #0		// r2 = 0
		strb	r2, [r3, r1]	// *(r3 + r1) = r2   1 byte가 이동 됨.
					// r3 += r1   
1:		subs	r1, r1, #1	// r1 -= 1, cpsr 고쳐짐.
		movmi	r0, r3		// 위 결과가 음수인 경우 수행
		bmi	puts		// 음수인 경우 puts을 수행

		and	r2, r0, #15
		mov	r0, r0, lsr #4
		cmp	r2, #10
		addge	r2, r2, #7
		add	r2, r2, #'0'
		strb	r2, [r3, r1]
		b	1b

@ puts corrupts {r0, r1, r2, r3}
puts:		loadsp	r3, r1
1:		ldrb	r2, [r0], #1	// r0 가 가리키는 곳에서 바이트 1개를 긁어옴.
		teq	r2, #0		// r2가 문자열 끝인지 확인
		moveq	pc, lr		// 끝이면 복귀 아니면 출력
2:		writeb	r2, r3		// uart 출력
		mov	r1, #0x00020000	// 
3:		subs	r1, r1, #1	// 대기 시간을 넣은 것으로 보임.
		bne	3b		// r1이 0이 될 때까지 반복 연산
		teq	r2, #'\n'	// '\n'과 r2 가 동일한 지 확인
		moveq	r2, #'\r'	// \n 이면 r2 = \r 대입
		beq	2b		// 그 뒤 2 레이블로 다시 점프
					// 즉 \n 을 \n\r로 변경하는 것임.
		teq	r0, #0		// r0 가 0 인지 확인.
		bne	1b		// 아니면 1로 점프
		mov	pc, lr		// 복귀
@ putc corrupts {r0, r1, r2, r3}
putc:					// 진입 시 r0에 값이 들어 있음.
		mov	r2, r0		// r2 = r0
		mov	r0, #0		// r0 = 0
		loadsp	r3, r1		// uart 설정인가??
		b	2b		// 2b로 그냥 점프

@ memdump corrupts {r0, r1, r2, r3, r10, r11, r12, lr}
memdump:	mov	r12, r0
		mov	r10, lr
		mov	r11, #0
2:		mov	r0, r11, lsl #2
		add	r0, r0, r12
		mov	r1, #8
		bl	phex
		mov	r0, #':'
		bl	putc
1:		mov	r0, #' '
		bl	putc
		ldr	r0, [r12, r11, lsl #2]
		mov	r1, #8
		bl	phex
		and	r0, r11, #7
		teq	r0, #3
		moveq	r0, #' '
		bleq	putc
		and	r0, r11, #7
		add	r11, r11, #1
		teq	r0, #7
		bne	1b
		mov	r0, #'\n'
		bl	putc
		cmp	r11, #64
		blt	2b
		mov	pc, r10
#endif

		.ltorg

#ifdef CONFIG_ARM_VIRT_EXT
.align 5
__hyp_reentry_vectors:
		W(b)	.			@ reset
		W(b)	.			@ undef
		W(b)	.			@ svc
		W(b)	.			@ pabort
		W(b)	.			@ dabort
		W(b)	__enter_kernel		@ hyp
		W(b)	.			@ irq
		W(b)	.			@ fiq
#endif /* CONFIG_ARM_VIRT_EXT */

__enter_kernel:
		mov	r0, #0			@ must be 0
						// r0는 0
 ARM(		mov	pc, r4	)		@ call kernel
 						// 압축 푼 커널의 시작으로 점프
 THUMB(		bx	r4	)		@ entry point is always ARM

reloc_code_end:

		.align
		.section ".stack", "aw", %nobits
.L_user_stack:	.space	4096
.L_user_stack_end:
