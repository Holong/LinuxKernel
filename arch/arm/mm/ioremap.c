/*
 *  linux/arch/arm/mm/ioremap.c
 *
 * Re-map IO memory to kernel address space so that we can access it.
 *
 * (C) Copyright 1995 1996 Linus Torvalds
 *
 * Hacked for ARM by Phil Blundell <philb@gnu.org>
 * Hacked to allow all architectures to build, and various cleanups
 * by Russell King
 *
 * This allows a driver to remap an arbitrary region of bus memory into
 * virtual space.  One should *only* use readl, writel, memcpy_toio and
 * so on with such remapped areas.
 *
 * Because the ARM only has a 32-bit address space we can't address the
 * whole of the (physical) PCI space at once.  PCI huge-mode addressing
 * allows us to circumvent this restriction by splitting PCI space into
 * two 2GB chunks and mapping only one at a time into processor memory.
 * We use MMU protection domains to trap any attempt to access the bank
 * that is not currently mapped.  (This isn't fully implemented yet.)
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/io.h>
#include <linux/sizes.h>

#include <asm/cp15.h>
#include <asm/cputype.h>
#include <asm/cacheflush.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/system_info.h>

#include <asm/mach/map.h>
#include <asm/mach/pci.h>
#include "mm.h"


LIST_HEAD(static_vmlist);
// static_vmlist : iotable
// SYSC : 0xf6100000 +  64kB  PA:0x10050000
// TMR  : 0xf6300000 +  16kB  PA:0x12DD0000
// WDT  : 0xf6400000 +   4kB  PA:0x101D0000
// CHID : 0xf8000000 +   4kB  PA:0x10000000
// CMU  : 0xf8100000 + 144kB  PA:0x10010000
// PMU  : 0xf8180000 +  64kB  PA:0x10040000
// SRAM : 0xf8400000 +   4kB  PA:0x02020000
// ROMC : 0xf84c0000 +   4kB  PA:0x12250000

// paddr : 0x10481000, size : 0x1000, mtype : MT_DEVICE
static struct static_vm *find_static_vm_paddr(phys_addr_t paddr,
			size_t size, unsigned int mtype)
{
	struct static_vm *svm;
	struct vm_struct *vm;

	list_for_each_entry(svm, &static_vmlist, list) {
		// static_vmlist에 연결되어 있는 static_vm을 하나씩 뽑아옴

		// svm : SYSC의 svm
		vm = &svm->vm;
		// static_vm의 vm 추출
		// vm->address : 0xF6100000, vm->size : 0x10000, vm->phys_addr : 0x10050000
		// vm->flags : VM_IOREMAP | VM_ARM_STATIC_MAPPING

		if (!(vm->flags & VM_ARM_STATIC_MAPPING))
			continue;
		if ((vm->flags & VM_ARM_MTYPE_MASK) != VM_ARM_MTYPE(mtype))
			continue;
		// 둘 다 통과

		// vm->phys_addr : 0x10050000, paddr : 0x10481000, size : 0x1000
		// vm->size : 0x10000
		if (vm->phys_addr > paddr ||
			paddr + size - 1 > vm->phys_addr + vm->size - 1)
			continue;
		// vm이 관리하는 영역에 현재 paddr + size 영역이 포함될 때
		// continue로 빠지지 않음

		return svm;
	}
	// static_vmlist에 등록된 영역 중에 해당하는 영역이 없음

	return NULL;
}

struct static_vm *find_static_vm_vaddr(void *vaddr)
{
	struct static_vm *svm;
	struct vm_struct *vm;

	list_for_each_entry(svm, &static_vmlist, list) {
		vm = &svm->vm;

		/* static_vmlist is ascending order */
		if (vm->addr > vaddr)
			break;

		if (vm->addr <= vaddr && vm->addr + vm->size > vaddr)
			return svm;
	}

	return NULL;
}

// cpuid
// vm->addr : 0xF8000000
// vm->size : 0x1000
// vm->phys_addr : 0x10000000
// vm->flags : 0x40000001
//
// VA_SYS
// vm->addr : 0xF6100000
// vm->size : 0x10000
// vm->phys_addr : 0x10050000
// vm->flags : 0x40000001
void __init add_static_vm_early(struct static_vm *svm)
{
	struct static_vm *curr_svm;
	struct vm_struct *vm;
	void *vaddr;

	vm = &svm->vm;
	vm_area_add_early(vm);
	// vmlist에 vm을 삽임시킴, 오름차순
	vaddr = vm->addr;
	// 가상 주소

	list_for_each_entry(curr_svm, &static_vmlist, list) {
	// 매크로 변환됨
	// list_for_each_entry(pos, head, member)				
	// for (curr_svm = list_entry((&static_vmlist)->next, typeof(*curr_svm), list); &curr_svm->list != (&static_vmlist);
	// 						curr_svm = list_entry(curr_svm->list.next, typeof(*curr_svm), list))
	//
	// for (curr_svm = 리스트의 첫번째, curr_svm이 끝까지 왔는가, 다음 next를 가져와 대입)
	//
	// list_entry >> container_of 매크로로 변환 >> list를 가지고 있는 구조체 변수의 시작 위치를 가지고 옴
	// {
	//	const typeof( ((static_vm *)0)->list ) *__mptr = (&static_vmlist)->next;
	//	(static_vm *)( (char *)__mptr - offsetof(static_vm, list));
	// }
	//
	// {
	// 	const typeof( ((static_vm *)0)->list ) *__mptr = curr_svm->list.next;
	// 	(static_vm *)( (char *)__mptr - offsetof(static_vm, list));
	// }
	//
	//#define container_of(ptr, type, member) ({			
	// const typeof( ((type *)0)->member ) *__mptr = (ptr);	
	// (type *)( (char *)__mptr - offsetof(type,member) );})
	//
		vm = &curr_svm->vm;

		if (vm->addr > vaddr)
			break;
	}
	list_add_tail(&svm->list, &curr_svm->list);
	// static_vmlist에 svm 추가, 오름차순으로
}

int ioremap_page(unsigned long virt, unsigned long phys,
		 const struct mem_type *mtype)
{
	return ioremap_page_range(virt, virt + PAGE_SIZE, phys,
				  __pgprot(mtype->prot_pte));
}
EXPORT_SYMBOL(ioremap_page);

void __check_vmalloc_seq(struct mm_struct *mm)
{
	unsigned int seq;

	do {
		seq = init_mm.context.vmalloc_seq;
		memcpy(pgd_offset(mm, VMALLOC_START),
		       pgd_offset_k(VMALLOC_START),
		       sizeof(pgd_t) * (pgd_index(VMALLOC_END) -
					pgd_index(VMALLOC_START)));
		mm->context.vmalloc_seq = seq;
	} while (seq != init_mm.context.vmalloc_seq);
}

#if !defined(CONFIG_SMP) && !defined(CONFIG_ARM_LPAE)
/*
 * Section support is unsafe on SMP - If you iounmap and ioremap a region,
 * the other CPUs will not see this change until their next context switch.
 * Meanwhile, (eg) if an interrupt comes in on one of those other CPUs
 * which requires the new ioremap'd region to be referenced, the CPU will
 * reference the _old_ region.
 *
 * Note that get_vm_area_caller() allocates a guard 4K page, so we need to
 * mask the size back to 1MB aligned or we will overflow in the loop below.
 */
static void unmap_area_sections(unsigned long virt, unsigned long size)
{
	unsigned long addr = virt, end = virt + (size & ~(SZ_1M - 1));
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmdp;

	flush_cache_vunmap(addr, end);
	pgd = pgd_offset_k(addr);
	pud = pud_offset(pgd, addr);
	pmdp = pmd_offset(pud, addr);
	do {
		pmd_t pmd = *pmdp;

		if (!pmd_none(pmd)) {
			/*
			 * Clear the PMD from the page table, and
			 * increment the vmalloc sequence so others
			 * notice this change.
			 *
			 * Note: this is still racy on SMP machines.
			 */
			pmd_clear(pmdp);
			init_mm.context.vmalloc_seq++;

			/*
			 * Free the page table, if there was one.
			 */
			if ((pmd_val(pmd) & PMD_TYPE_MASK) == PMD_TYPE_TABLE)
				pte_free_kernel(&init_mm, pmd_page_vaddr(pmd));
		}

		addr += PMD_SIZE;
		pmdp += 2;
	} while (addr < end);

	/*
	 * Ensure that the active_mm is up to date - we want to
	 * catch any use-after-iounmap cases.
	 */
	if (current->active_mm->context.vmalloc_seq != init_mm.context.vmalloc_seq)
		__check_vmalloc_seq(current->active_mm);

	flush_tlb_kernel_range(virt, end);
}

static int
remap_area_sections(unsigned long virt, unsigned long pfn,
		    size_t size, const struct mem_type *type)
{
	unsigned long addr = virt, end = virt + size;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	/*
	 * Remove and free any PTE-based mapping, and
	 * sync the current kernel mapping.
	 */
	unmap_area_sections(virt, size);

	pgd = pgd_offset_k(addr);
	pud = pud_offset(pgd, addr);
	pmd = pmd_offset(pud, addr);
	do {
		pmd[0] = __pmd(__pfn_to_phys(pfn) | type->prot_sect);
		pfn += SZ_1M >> PAGE_SHIFT;
		pmd[1] = __pmd(__pfn_to_phys(pfn) | type->prot_sect);
		pfn += SZ_1M >> PAGE_SHIFT;
		flush_pmd_entry(pmd);

		addr += PMD_SIZE;
		pmd += 2;
	} while (addr < end);

	return 0;
}

static int
remap_area_supersections(unsigned long virt, unsigned long pfn,
			 size_t size, const struct mem_type *type)
{
	unsigned long addr = virt, end = virt + size;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;

	/*
	 * Remove and free any PTE-based mapping, and
	 * sync the current kernel mapping.
	 */
	unmap_area_sections(virt, size);

	pgd = pgd_offset_k(virt);
	pud = pud_offset(pgd, addr);
	pmd = pmd_offset(pud, addr);
	do {
		unsigned long super_pmd_val, i;

		super_pmd_val = __pfn_to_phys(pfn) | type->prot_sect |
				PMD_SECT_SUPER;
		super_pmd_val |= ((pfn >> (32 - PAGE_SHIFT)) & 0xf) << 20;

		for (i = 0; i < 8; i++) {
			pmd[0] = __pmd(super_pmd_val);
			pmd[1] = __pmd(super_pmd_val);
			flush_pmd_entry(pmd);

			addr += PMD_SIZE;
			pmd += 2;
		}

		pfn += SUPERSECTION_SIZE >> PAGE_SHIFT;
	} while (addr < end);

	return 0;
}
#endif

// pfn : 0x10481, offset : 0, size : 0x1000, mtype : MT_DEVICE, caller : 복귀 주소
void __iomem * __arm_ioremap_pfn_caller(unsigned long pfn,
	unsigned long offset, size_t size, unsigned int mtype, void *caller)
{
	const struct mem_type *type;
	int err;
	unsigned long addr;
	struct vm_struct *area;

	// pfn : 0x10481
	phys_addr_t paddr = __pfn_to_phys(pfn);
	// paddr : 0x10481000

#ifndef CONFIG_ARM_LPAE	// N
	/*
	 * High mappings must be supersection aligned
	 */
	// pfn : 0x10481
	// SUPERSECTION_MASK : 0xFF000000
	// ~SUPERSECTION_MASK : 0x00FFFFFF
	if (pfn >= 0x100000 && (paddr & ~SUPERSECTION_MASK))
		return NULL;
#endif

	// mtype : MT_DEVICE
	type = get_mem_type(mtype);
	// type : &mem_types[MT_DEVICE]
	if (!type)
		return NULL;

	/*
	 * Page align the mapping size, taking account of any offset.
	 */
	// offset : 0, size : 0x1000
	size = PAGE_ALIGN(offset + size);
	// size : 0x1000

	/*
	 * Try to reuse one of the static mapping whenever possible.
	 */
	// size : 0x1000, sizeof(phys_addr_t) : 4, pfn : 0x10481
	if (size && !(sizeof(phys_addr_t) == 4 && pfn >= 0x100000)) {
		struct static_vm *svm;

		// paddr : 0x10481000, size : 0x1000, mtype : MT_DEVICE
		svm = find_static_vm_paddr(paddr, size, mtype);
		// svm : NULL

		if (svm) {
			addr = (unsigned long)svm->vm.addr;
			addr += paddr - svm->vm.phys_addr;
			return (void __iomem *) (offset + addr);
		}
	}

	/*
	 * Don't allow RAM to be mapped - this causes problems with ARMv6+
	 */
	// pfn : 0x10481
	if (WARN_ON(pfn_valid(pfn)))
	// pfn_valid : 0 
	// 현재 pfn이 memory 영역에 들어가는 지 확인함
		return NULL;

	// size : 0x1000, VM_IOREMAP : 0x00000001, caller : 복귀 주소
	area = get_vm_area_caller(size, VM_IOREMAP, caller);
	// size 정보를 이용해 새로운 vmap_area를 생성하고
	// vmap_area_root 의 레드 블랙 트리에 새로 삽입함
	// 그 뒤, vm_struct를 생성하고 그 값을 설정해 준 뒤, 그 주소를 반환
	
 	if (!area)
 		return NULL;

	// area->addr : 0xF0000000
 	addr = (unsigned long)area->addr;
	// addr : 0xF0000000
	
	// paddr : 0x10481000
	area->phys_addr = paddr;
	// area->phys_addr : 0x10481000

#if !defined(CONFIG_SMP) && !defined(CONFIG_ARM_LPAE)	// 통과
	if (DOMAIN_IO == 0 &&
	    (((cpu_architecture() >= CPU_ARCH_ARMv6) && (get_cr() & CR_XP)) ||
	       cpu_is_xsc3()) && pfn >= 0x100000 &&
	       !((paddr | size | addr) & ~SUPERSECTION_MASK)) {
		area->flags |= VM_ARM_SECTION_MAPPING;
		err = remap_area_supersections(addr, pfn, size, type);
	} else if (!((paddr | size | addr) & ~PMD_MASK)) {
		area->flags |= VM_ARM_SECTION_MAPPING;
		err = remap_area_sections(addr, pfn, size, type);
	} else
#endif
		// 여기부터 수행
		// addr : 0xF0000000, addr+size : 0xF0001000,
		// paddr : 0x10481000, 
		// __pgprot(type->prot_pte) : mem_types[MT_DEVICE].prot_pte
		err = ioremap_page_range(addr, addr + size, paddr,
					 __pgprot(type->prot_pte));
		// 가상주소 0xF0000000 ~ 0xF0001000을 물리주소 0x10481000 ~ 0x10481FFF으로
		// 매핑시키기 위한 페이지 테이블 생성
		// err : 0
		
	if (err) {
 		vunmap((void *)addr);
 		return NULL;
 	}

	flush_cache_vmap(addr, addr + size);
	// 캐시 클린
	
	return (void __iomem *) (offset + addr);
	// return 0xF0000000
}

// phys_addr : 0x10481000, size : 0x1000, mtype : MT_DEVICE, caller : 복귀 주소
void __iomem *__arm_ioremap_caller(phys_addr_t phys_addr, size_t size,
	unsigned int mtype, void *caller)
{
	phys_addr_t last_addr;
	// PAGE_MASK : 0xFFFFF000
 	unsigned long offset = phys_addr & ~PAGE_MASK;
	// offset : 0
	
 	unsigned long pfn = __phys_to_pfn(phys_addr);
	// pfn : 0x10481

 	/*
 	 * Don't allow wraparound or zero size
	 */
	last_addr = phys_addr + size - 1;
	// last_addr : 0x10481FFF
	
	if (!size || last_addr < phys_addr)
		return NULL;
	// 통과

	// pfn : 0x10481, offset : 0, size : 0x1000, mtype : MT_DEVICE, caller : 복귀 주소
	return __arm_ioremap_pfn_caller(pfn, offset, size, mtype,
			caller);
	// 가상주소와 물리주소 연결을 위한 페이지 테이블 생성
	// return 0xF0000000
}

/*
 * Remap an arbitrary physical address space into the kernel virtual
 * address space. Needed when the kernel wants to access high addresses
 * directly.
 *
 * NOTE! We need to allow non-page-aligned mappings too: we will obviously
 * have to convert them into an offset in a page-aligned mapping, but the
 * caller shouldn't need to know that small detail.
 */
void __iomem *
__arm_ioremap_pfn(unsigned long pfn, unsigned long offset, size_t size,
		  unsigned int mtype)
{
	return __arm_ioremap_pfn_caller(pfn, offset, size, mtype,
			__builtin_return_address(0));
}
EXPORT_SYMBOL(__arm_ioremap_pfn);

void __iomem * (*arch_ioremap_caller)(phys_addr_t, size_t,
				      unsigned int, void *) =
	__arm_ioremap_caller;

// phys_addr : 0x10481000, size : 0x1000, mtype : MT_DEVICE
void __iomem *
__arm_ioremap(phys_addr_t phys_addr, size_t size, unsigned int mtype)
{
	// phys_addr : 0x10481000, size : 0x1000, mtype : MT_DEVICE, 복귀 주소
	return arch_ioremap_caller(phys_addr, size, mtype,
		__builtin_return_address(0));
	// __arm_ioremap_caller이 불림
	//
	// 가상주소와 물리주소 연결을 위한 페이지 테이블 생성
	// return 0xF0000000
}
EXPORT_SYMBOL(__arm_ioremap);

/*
 * Remap an arbitrary physical address space into the kernel virtual
 * address space as memory. Needed when the kernel wants to execute
 * code in external memory. This is needed for reprogramming source
 * clocks that would affect normal memory for example. Please see
 * CONFIG_GENERIC_ALLOCATOR for allocating external memory.
 */
void __iomem *
__arm_ioremap_exec(phys_addr_t phys_addr, size_t size, bool cached)
{
	unsigned int mtype;

	if (cached)
		mtype = MT_MEMORY;
	else
		mtype = MT_MEMORY_NONCACHED;

	return __arm_ioremap_caller(phys_addr, size, mtype,
			__builtin_return_address(0));
}

void __iounmap(volatile void __iomem *io_addr)
{
	void *addr = (void *)(PAGE_MASK & (unsigned long)io_addr);
	struct static_vm *svm;

	/* If this is a static mapping, we must leave it alone */
	svm = find_static_vm_vaddr(addr);
	if (svm)
		return;

#if !defined(CONFIG_SMP) && !defined(CONFIG_ARM_LPAE)
	{
		struct vm_struct *vm;

		vm = find_vm_area(addr);

		/*
		 * If this is a section based mapping we need to handle it
		 * specially as the VM subsystem does not know how to handle
		 * such a beast.
		 */
		if (vm && (vm->flags & VM_ARM_SECTION_MAPPING))
			unmap_area_sections((unsigned long)vm->addr, vm->size);
	}
#endif

	vunmap(addr);
}

void (*arch_iounmap)(volatile void __iomem *) = __iounmap;

void __arm_iounmap(volatile void __iomem *io_addr)
{
	arch_iounmap(io_addr);
}
EXPORT_SYMBOL(__arm_iounmap);

#ifdef CONFIG_PCI
int pci_ioremap_io(unsigned int offset, phys_addr_t phys_addr)
{
	BUG_ON(offset + SZ_64K > IO_SPACE_LIMIT);

	return ioremap_page_range(PCI_IO_VIRT_BASE + offset,
				  PCI_IO_VIRT_BASE + offset + SZ_64K,
				  phys_addr,
				  __pgprot(get_mem_type(MT_DEVICE)->prot_pte));
}
EXPORT_SYMBOL_GPL(pci_ioremap_io);
#endif
