#include <asm/unwind.h>

#if __LINUX_ARM_ARCH__ >= 6
	.macro	bitop, name, instr
ENTRY(	\name		)
UNWIND(	.fnstart	)
	ands	ip, r1, #3		
	strneb	r1, [ip]		@ assert word-aligned
	mov	r2, #1			
	and	r3, r0, #31		@ Get bit offset
	mov	r0, r0, lsr #5		
	add	r1, r1, r0, lsl #2	@ Get word offset
#if __LINUX_ARM_ARCH__ >= 7 && defined(CONFIG_SMP)
	.arch_extension	mp
	ALT_SMP(W(pldw)	[r1])
	ALT_UP(W(nop))
#endif
	mov	r3, r2, lsl r3
1:	ldrex	r2, [r1]
	\instr	r2, r2, r3
	strex	r0, r2, [r1]
	cmp	r0, #0
	bne	1b
	bx	lr
UNWIND(	.fnend		)
ENDPROC(\name		)
	.endm

	.macro	testop, name, instr, store
					// r0 : idx
					// r1 : 비트맵 시작 주소
ENTRY(	\name		)
UNWIND(	.fnstart	)
	ands	ip, r1, #3		// ip : r12
					// ip : 비트맵 시작 주소의 하위 2비트
	strneb	r1, [ip]		// r1에 저장된 값이 4byte 정렬이 안되어 있을 경우 수행됨
					// DATA ABORT exception을 띄우기 위한 용도임
	mov	r2, #1                  
	and	r3, r0, #31		@ Get bit offset
					// 하위 5비트만 살려서 r3로 저장 (비트 오프셋 계산)
	mov	r0, r0, lsr #5  	// 상위 [31:5] 만 살림        	
	add	r1, r1, r0, lsl #2      @ Get word offset
					// r1 : 비트맵의 시작 주소
					// 시작 주소 + r0의 word 오프셋 * 4
					// 그러므로 해당 비트맵 word의 시작 주소
	mov	r3, r2, lsl r3		@ create mask
					// 비트 오프셋에 해당하는 비트를 설정한 후 r3에 저장
	smp_dmb       			// Data Memory Barrier
					// 이전에 존재하는 메모리 엑세스가 확실하게 수행됨
1:	ldrex	r2, [r1]		// 해당 비트맵 word의 값을 r2에 저장함
					// LDREX : 싱크용 명령
					// 
					// 	Monitor라는 하드웨어가 ARM 내부에 존재
					//
					// 	Process P1 에서 다음 수행시
					//	LDREX r1, [r2]  >> r2에서 r1 읽어오기
					//			>> 모니터 내부에 r2는 P1 이라는 것을 기록
					//
					//	~~~~ 명령들 ~~~~~
					//
					//	STREX r0, r1, [r2]  >> r1의 값을 r2에 쓰기
					//				수행 여부는 r0에 저장됨
					//				그러므로 r0 값을 이용해서 조건문을 만들어 둬야함.
					//
					//				수행 시 모니터 값을 확인하고
					//				r2는 P1 이라는 기록이 남아 있으면 수행 가능
					//
					//	만약 P2와 같은 다른 프로세스에서 [r2] 내용을 건드렸으면
					//	모니터 내부에서 r2는 P2라는 것을 기록해둠.
					//
					//	그렇기 때문에 STREX에서 모니터를 확인 할 시 P2라고 기록이 되어 있기 때문에
					//	저장 수행을 하지 않음
					//
	ands	r0, r2, r3		@ save old value of bit
	\instr	r2, r2, r3		@ toggle bit
					// reserve : 0 이면 bicne
					// reserve : 1 이면 orreq
	strex	ip, r2, [r1]		// r2 값을 r1이 가리키는 메모리에 저장
	cmp	ip, #0			
	bne	1b			// 저장 실패시 다시 시도
	smp_dmb
	cmp	r0, #0
	movne	r0, #1
2:	bx	lr
UNWIND(	.fnend		)
ENDPROC(\name		)
	.endm
#else
	.macro	bitop, name, instr
ENTRY(	\name		)
UNWIND(	.fnstart	)
	ands	ip, r1, #3
	strneb	r1, [ip]		@ assert word-aligned
	and	r2, r0, #31
	mov	r0, r0, lsr #5
	mov	r3, #1
	mov	r3, r3, lsl r2
	save_and_disable_irqs ip
	ldr	r2, [r1, r0, lsl #2]
	\instr	r2, r2, r3
	str	r2, [r1, r0, lsl #2]
	restore_irqs ip
	mov	pc, lr
UNWIND(	.fnend		)
ENDPROC(\name		)
	.endm

/**
 * testop - implement a test_and_xxx_bit operation.
 * @instr: operational instruction
 * @store: store instruction
 *
 * Note: we can trivially conditionalise the store instruction
 * to avoid dirtying the data cache.
 */
	.macro	testop, name, instr, store
ENTRY(	\name		)
UNWIND(	.fnstart	)
	ands	ip, r1, #3
	strneb	r1, [ip]		@ assert word-aligned
	and	r3, r0, #31
	mov	r0, r0, lsr #5
	save_and_disable_irqs ip
	ldr	r2, [r1, r0, lsl #2]!
	mov	r0, #1
	tst	r2, r0, lsl r3
	\instr	r2, r2, r0, lsl r3
	\store	r2, [r1]
	moveq	r0, #0
	restore_irqs ip
	mov	pc, lr
UNWIND(	.fnend		)
ENDPROC(\name		)
	.endm
#endif
