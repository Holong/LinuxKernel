/*
 * Re-map IO memory to kernel address space so that we can access it.
 * This is needed for high PCI addresses that aren't mapped in the
 * 640k-1MB IO memory area on PC's
 *
 * (C) Copyright 1995 1996 Linus Torvalds
 */
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/io.h>
#include <linux/export.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>

// pmd : 0xC0004780, addr : 0xF0000000, next : 0xF0001000, phys_addr : 0x10481000
// prot : PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED
static int ioremap_pte_range(pmd_t *pmd, unsigned long addr,
		unsigned long end, phys_addr_t phys_addr, pgprot_t prot)
{
	pte_t *pte;
	u64 pfn;

	// phys_addr : 0x10481000
	pfn = phys_addr >> PAGE_SHIFT;
	// pfn : 0x10481
	
	// pmd : 0xC0004780, addr : 0xF0000000
	pte = pte_alloc_kernel(pmd, addr);
	// ((unlikely(pmd_none(*(pmd))) && __pte_alloc_kernel(pmd, addr)) ? NULL : pte_offset_kernel(pmd, addr))
	// 로 변경되고 결국
	// __pte_alloc_kernel(pmd, addr) 이 호출됨
	// __pte_alloc_kernel 에서는 pte용 page를 할당받고 first-level table에
	// page table을 생성시켜 줌
	//
	// pte_offset_kernel(pmd, addr) : 생성한 second-level table에서 addr에 해당하는 곳의
	// 주소를 뽑아냄
	// pte : 해당 pte

	if (!pte)
		return -ENOMEM;
	// 통과
	
	do {
		BUG_ON(!pte_none(*pte));
		// pte에 값이 있는지 확인하는데, free 페이지를 받았으므로
		// 아무것도 없음
	
		// pfn : 0x10481, prot : PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED
		// pfn_pte(pfn, prot) : 물리 주소가 0x10481000이고 prot 속성을 가진 small page 데이터 반환
		// init_mm, addr : 0xF0000000, pte, 0x10481653
		set_pte_at(&init_mm, addr, pte, pfn_pte(pfn, prot));
		// second-level table에 적절한 값을 설정해 줌

		pfn++;
		// pfn : 0x10482

		// pte, addr : 0xF0000000, end : 0xF0001000
	} while (pte++, addr += PAGE_SIZE, addr != end);
	// 4KB 영역에 대해서만 small page를 만들어주고 빠져나옴
	
	return 0;
}

// pud : 0xC0004780, addr : 0xF0000000, end : 0xF0001000, phys_addr : 0x10481000
// prot : PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED
static inline int ioremap_pmd_range(pud_t *pud, unsigned long addr,
		unsigned long end, phys_addr_t phys_addr, pgprot_t prot)
{
	pmd_t *pmd;
	unsigned long next;

	phys_addr -= addr;
	// phys_addr : 0x20481000
	
	// init_mm, pud : 0xC0004780, addr : 0xF0000000
	pmd = pmd_alloc(&init_mm, pud, addr);
	// ((unlikely(pgd_none(*(pud))) && __pmd_alloc(&init_mm, pud, addr)) ? NULL : pmd_offset(pud, addr))
	// pmd : 0xC0004780
	// pud 값이 그냥 반환됨
	
	if (!pmd)
		return -ENOMEM;
	// 통과
	
	do {
		// addr : 0xF0000000, end : 0xF0001000
		next = pmd_addr_end(addr, end);
		// next : 0xF0001000
		// end 값이 그대로 반환됨

		// pmd : 0xC0004780, addr : 0xF0000000, next : 0xF0001000, phys_addr + addr : 0x10481000
		// prot : PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED
		if (ioremap_pte_range(pmd, addr, next, phys_addr + addr, prot))
		// page table과 이를 위한 page를 할당받고 적절한 small page를 설정해줌
			return -ENOMEM;
	
	} while (pmd++, addr = next, addr != end);
	// 바로 탈출
	
	return 0;
}

// pgd : 0xC0004780, addr : 0xF0000000, end : 0xF0001000
// phys_addr : 0x10481000, prot : PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED
static inline int ioremap_pud_range(pgd_t *pgd, unsigned long addr,
		unsigned long end, phys_addr_t phys_addr, pgprot_t prot)
{
	pud_t *pud;
	unsigned long next;

	// phys_addr : 0x10481000, addr : 0xF0000000
	phys_addr -= addr;
	// phys_addr : 0x20481000
	
	// init_mm : 전역 변수, pgd : 0xC0004780, addr : 0xF0000000
	pud = pud_alloc(&init_mm, pgd, addr);
	// pgd를 그냥 반환함
	// pud : 0xC0004780

	if (!pud)
		return -ENOMEM;
	// 통과
	
	do {
		// addr : 0xF0000000, end : 0xF0001000
		next = pud_addr_end(addr, end);
		// end가 그냥 반환됨
		// next : 0xF0001000

		// pud : 0xC0004780, addr : 0xF0000000, next : 0xF0001000, phys_addr + addr : 0x10481000
		// prot : PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED
		if (ioremap_pmd_range(pud, addr, next, phys_addr + addr, prot))
		// pte 생성
			return -ENOMEM;
	} while (pud++, addr = next, addr != end);
	// 바로 탈출
	
	return 0;
}

// addr : 0xF0000000, end : 0xF0001000, phys_addr : 0x10481000, 
// prot : mem_types[MT_DEVICE].prot_pte
int ioremap_page_range(unsigned long addr,
		       unsigned long end, phys_addr_t phys_addr, pgprot_t prot)
{
	pgd_t *pgd;
	unsigned long start;
	unsigned long next;
	int err;

	BUG_ON(addr >= end);

	start = addr;
	// start : 0xF0000000

	// addr : 0xF0000000
	phys_addr -= addr;
	// phys_addr : 0x20481000
	
	pgd = pgd_offset_k(addr);
	// pgd : 0xC0004780
	
	do {
		// addr : 0xF0000000, end : 0xF0001000
		next = pgd_addr_end(addr, end);
		// next : 0xF0001000

		// pgd : 0xC0004780, addr : 0xF0000000, next : 0xF0001000
		// phys_addr + addr : 0x10481000, prot : PROT_PTE_DEVICE | L_PTE_MT_DEV_SHARED | L_PTE_SHARED
		err = ioremap_pud_range(pgd, addr, next, phys_addr+addr, prot);
		// 적절한 페이지 테이블 생성
		// err : 0

		if (err)
			break;
	} while (pgd++, addr = next, addr != end);
	// 바로 탈출

	flush_cache_vmap(start, end);
	// 캐시를 flush 해줌

	return err;
	// return 0
}
EXPORT_SYMBOL_GPL(ioremap_page_range);
