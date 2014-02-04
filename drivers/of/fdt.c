/*
 * Functions for working with the Flattened Device Tree data format
 *
 * Copyright 2009 Benjamin Herrenschmidt, IBM Corp
 * benh@kernel.crashing.org
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/initrd.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>

#include <asm/setup.h>  /* for COMMAND_LINE_SIZE */
#ifdef CONFIG_PPC
#include <asm/machdep.h>
#endif /* CONFIG_PPC */

#include <asm/page.h>

char *of_fdt_get_string(struct boot_param_header *blob, u32 offset)
{
	return ((char *)blob) +
		be32_to_cpu(blob->off_dt_strings) + offset;
}

/**
 * of_fdt_get_property - Given a node in the given flat blob, return
 * the property ptr
 */
// blob : DTB 시작 주소, node : 루트 노드, name : "compatible", size : 저장할 공간
void *of_fdt_get_property(struct boot_param_header *blob,
		       unsigned long node, const char *name,
		       unsigned long *size)
{
	unsigned long p = node;
	// 탐색할 노드의 시작 주소를 p에 저장

	do {
		u32 tag = be32_to_cpup((__be32 *)p);
		// tag : p가 가리키는 주소에서 값을 빼옴
		u32 sz, noff;
		const char *nstr;

		p += 4;
		if (tag == OF_DT_NOP)
			continue;
		if (tag != OF_DT_PROP)
			return NULL;
		// 노드의 시작 주소에 OF_DT_PROP 값이 없으면 아예 property가 없는 것임

		sz = be32_to_cpup((__be32 *)p);
		// property 값의 길이를 sz에 저장
		// DTB 파일 포맷 상 OF_DT_PROP 다음에
		// property 데이터의 길이가 word 크기로 저장되어 있음

		noff = be32_to_cpup((__be32 *)(p + 4));
		// property 이름의 offset 값을 noff에 저장
		// DTB 파일 포맷 상 property 데이터의 길이 다음에
		// property 이름의 offset 값이 word 크기로 저장되어 있음
		// offset의 시작은 DTB string block의 시작 주소로, string block은
		// DTB 헤더에서 뽑아낼 수 있음

		p += 8;	// property 데이터가 저장된 부분으로 이동
		if (be32_to_cpu(blob->version) < 0x10)	// DTB 버전이 16보다 낮은 경우
			p = ALIGN(p, sz >= 8 ? 8 : 4);

		nstr = of_fdt_get_string(blob, noff);
		// property의 이름 string을 nstr이 가리키게 함

		if (nstr == NULL) {
			pr_warning("Can't find property index name !\n");
			return NULL;
		}
		if (strcmp(name, nstr) == 0) {	// compatible property에 도달했는지 확인
			// 현재 p가 가리키는 곳이 compatible property인 경우 진입함
			if (size)
				*size = sz;
				// size 변수에 property 데이터의 길이를 저장
			return (void *)p;
				// property 데이터의 시작 주소를 반환
		}
		p += sz;
		p = ALIGN(p, 4);
		// 다음 property로 이동
	} while (1);
}

/**
 * of_fdt_is_compatible - Return true if given node from the given blob has
 * compat in its compatible list
 * @blob: A device tree blob
 * @node: node to test
 * @compat: compatible string to compare with compatible list.
 *
 * On match, returns a non-zero value with smaller values returned for more
 * specific compatible values.
 */
// blob : DTB 시작 주소, node : 루트 노드, compat : 비교할 리스트
int of_fdt_is_compatible(struct boot_param_header *blob,
		      unsigned long node, const char *compat)
{
	const char *cp;
	unsigned long cplen, l, score = 0;

	cp = of_fdt_get_property(blob, node, "compatible", &cplen);
	// node에서 compatible property를 찾아낸다.
	// cp : 찾아낸 property의 데이터 부분이 저장된 시작 주소
	// cplen : 찾아낸 property의 데이터 길이를 담음.

	if (cp == NULL)
		return 0;	// 못 찾은 경우
	while (cplen > 0) {
		score++;
		if (of_compat_cmp(cp, compat, strlen(compat)) == 0)
			// cp와 compat이 동일한 경우
			// 즉 compatible property와 비교 문자열이 동일한 경우 진입
			return score;
		l = strlen(cp) + 1;
		cp += l;
		cplen -= l;
		// compatible property에 여러 값이 존재할 경우
		// 우선순위가 높은 값부터 검사하는데, 높은 값이 비교 문자열과 다를 경우
		// 스코어 값을 1씩 올리면서 다음 값과 비교하도록 만듬.
		// 그러므로 스코어가 1로 반환되면 일치
		// 1보다 큰 값이면 호환 가능한 보드라는 뜻임`
	}

	return 0;
}

/**
 * of_fdt_match - Return true if node matches a list of compatible values
 */
int of_fdt_match(struct boot_param_header *blob, unsigned long node,
                 const char *const *compat)
{
	unsigned int tmp, score = 0;

	if (!compat)
		return 0;

	while (*compat) {
		tmp = of_fdt_is_compatible(blob, node, *compat);
		if (tmp && (score == 0 || (tmp < score)))
			score = tmp;
		compat++;
	}

	return score;
}

static void *unflatten_dt_alloc(unsigned long *mem, unsigned long size,
				       unsigned long align)
{
	void *res;

	*mem = ALIGN(*mem, align);
	res = (void *)*mem;
	*mem += size;

	return res;
}

/**
 * unflatten_dt_node - Alloc and populate a device_node from the flat tree
 * @blob: The parent device tree blob
 * @mem: Memory chunk to use for allocating device nodes and properties
 * @p: pointer to node in flat tree
 * @dad: Parent struct device_node
 * @allnextpp: pointer to ->allnext from last allocated device_node
 * @fpsize: Size of the node path up at the current depth.
 */
static unsigned long unflatten_dt_node(struct boot_param_header *blob,
				unsigned long mem,
				unsigned long *p,
				struct device_node *dad,
				struct device_node ***allnextpp,
				unsigned long fpsize)
{
	struct device_node *np;
	struct property *pp, **prev_pp = NULL;
	char *pathp;
	u32 tag;
	unsigned int l, allocl;
	int has_name = 0;
	int new_format = 0;

	tag = be32_to_cpup((__be32 *)(*p));
	if (tag != OF_DT_BEGIN_NODE) {
		pr_err("Weird tag at start of node: %x\n", tag);
		return mem;
	}
	*p += 4;
	pathp = (char *)*p;
	l = allocl = strlen(pathp) + 1;
	*p = ALIGN(*p + l, 4);

	/* version 0x10 has a more compact unit name here instead of the full
	 * path. we accumulate the full path size using "fpsize", we'll rebuild
	 * it later. We detect this because the first character of the name is
	 * not '/'.
	 */
	if ((*pathp) != '/') {
		new_format = 1;
		if (fpsize == 0) {
			/* root node: special case. fpsize accounts for path
			 * plus terminating zero. root node only has '/', so
			 * fpsize should be 2, but we want to avoid the first
			 * level nodes to have two '/' so we use fpsize 1 here
			 */
			fpsize = 1;
			allocl = 2;
			l = 1;
			*pathp = '\0';
		} else {
			/* account for '/' and path size minus terminal 0
			 * already in 'l'
			 */
			fpsize += l;
			allocl = fpsize;
		}
	}

	np = unflatten_dt_alloc(&mem, sizeof(struct device_node) + allocl,
				__alignof__(struct device_node));
	if (allnextpp) {
		char *fn;
		memset(np, 0, sizeof(*np));
		np->full_name = fn = ((char *)np) + sizeof(*np);
		if (new_format) {
			/* rebuild full path for new format */
			if (dad && dad->parent) {
				strcpy(fn, dad->full_name);
#ifdef DEBUG
				if ((strlen(fn) + l + 1) != allocl) {
					pr_debug("%s: p: %d, l: %d, a: %d\n",
						pathp, (int)strlen(fn),
						l, allocl);
				}
#endif
				fn += strlen(fn);
			}
			*(fn++) = '/';
		}
		memcpy(fn, pathp, l);

		prev_pp = &np->properties;
		**allnextpp = np;
		*allnextpp = &np->allnext;
		if (dad != NULL) {
			np->parent = dad;
			/* we temporarily use the next field as `last_child'*/
			if (dad->next == NULL)
				dad->child = np;
			else
				dad->next->sibling = np;
			dad->next = np;
		}
		kref_init(&np->kref);
	}
	/* process properties */
	while (1) {
		u32 sz, noff;
		char *pname;

		tag = be32_to_cpup((__be32 *)(*p));
		if (tag == OF_DT_NOP) {
			*p += 4;
			continue;
		}
		if (tag != OF_DT_PROP)
			break;
		*p += 4;
		sz = be32_to_cpup((__be32 *)(*p));
		noff = be32_to_cpup((__be32 *)((*p) + 4));
		*p += 8;
		if (be32_to_cpu(blob->version) < 0x10)
			*p = ALIGN(*p, sz >= 8 ? 8 : 4);

		pname = of_fdt_get_string(blob, noff);
		if (pname == NULL) {
			pr_info("Can't find property name in list !\n");
			break;
		}
		if (strcmp(pname, "name") == 0)
			has_name = 1;
		l = strlen(pname) + 1;
		pp = unflatten_dt_alloc(&mem, sizeof(struct property),
					__alignof__(struct property));
		if (allnextpp) {
			/* We accept flattened tree phandles either in
			 * ePAPR-style "phandle" properties, or the
			 * legacy "linux,phandle" properties.  If both
			 * appear and have different values, things
			 * will get weird.  Don't do that. */
			if ((strcmp(pname, "phandle") == 0) ||
			    (strcmp(pname, "linux,phandle") == 0)) {
				if (np->phandle == 0)
					np->phandle = be32_to_cpup((__be32*)*p);
			}
			/* And we process the "ibm,phandle" property
			 * used in pSeries dynamic device tree
			 * stuff */
			if (strcmp(pname, "ibm,phandle") == 0)
				np->phandle = be32_to_cpup((__be32 *)*p);
			pp->name = pname;
			pp->length = sz;
			pp->value = (void *)*p;
			*prev_pp = pp;
			prev_pp = &pp->next;
		}
		*p = ALIGN((*p) + sz, 4);
	}
	/* with version 0x10 we may not have the name property, recreate
	 * it here from the unit name if absent
	 */
	if (!has_name) {
		char *p1 = pathp, *ps = pathp, *pa = NULL;
		int sz;

		while (*p1) {
			if ((*p1) == '@')
				pa = p1;
			if ((*p1) == '/')
				ps = p1 + 1;
			p1++;
		}
		if (pa < ps)
			pa = p1;
		sz = (pa - ps) + 1;
		pp = unflatten_dt_alloc(&mem, sizeof(struct property) + sz,
					__alignof__(struct property));
		if (allnextpp) {
			pp->name = "name";
			pp->length = sz;
			pp->value = pp + 1;
			*prev_pp = pp;
			prev_pp = &pp->next;
			memcpy(pp->value, ps, sz - 1);
			((char *)pp->value)[sz - 1] = 0;
			pr_debug("fixed up name for %s -> %s\n", pathp,
				(char *)pp->value);
		}
	}
	if (allnextpp) {
		*prev_pp = NULL;
		np->name = of_get_property(np, "name", NULL);
		np->type = of_get_property(np, "device_type", NULL);

		if (!np->name)
			np->name = "<NULL>";
		if (!np->type)
			np->type = "<NULL>";
	}
	while (tag == OF_DT_BEGIN_NODE || tag == OF_DT_NOP) {
		if (tag == OF_DT_NOP)
			*p += 4;
		else
			mem = unflatten_dt_node(blob, mem, p, np, allnextpp,
						fpsize);
		tag = be32_to_cpup((__be32 *)(*p));
	}
	if (tag != OF_DT_END_NODE) {
		pr_err("Weird tag at end of node: %x\n", tag);
		return mem;
	}
	*p += 4;
	return mem;
}

/**
 * __unflatten_device_tree - create tree of device_nodes from flat blob
 *
 * unflattens a device-tree, creating the
 * tree of struct device_node. It also fills the "name" and "type"
 * pointers of the nodes so the normal device-tree walking functions
 * can be used.
 * @blob: The blob to expand
 * @mynodes: The device_node tree created by the call
 * @dt_alloc: An allocator that provides a virtual address to memory
 * for the resulting tree
 */
static void __unflatten_device_tree(struct boot_param_header *blob,
			     struct device_node **mynodes,
			     void * (*dt_alloc)(u64 size, u64 align))
{
	unsigned long start, mem, size;
	struct device_node **allnextp = mynodes;

	pr_debug(" -> unflatten_device_tree()\n");

	if (!blob) {
		pr_debug("No device tree pointer\n");
		return;
	}

	pr_debug("Unflattening device tree:\n");
	pr_debug("magic: %08x\n", be32_to_cpu(blob->magic));
	pr_debug("size: %08x\n", be32_to_cpu(blob->totalsize));
	pr_debug("version: %08x\n", be32_to_cpu(blob->version));

	if (be32_to_cpu(blob->magic) != OF_DT_HEADER) {
		pr_err("Invalid device tree blob header\n");
		return;
	}

	/* First pass, scan for size */
	start = ((unsigned long)blob) +
		be32_to_cpu(blob->off_dt_struct);
	size = unflatten_dt_node(blob, 0, &start, NULL, NULL, 0);
	size = (size | 3) + 1;

	pr_debug("  size is %lx, allocating...\n", size);

	/* Allocate memory for the expanded device tree */
	mem = (unsigned long)
		dt_alloc(size + 4, __alignof__(struct device_node));

	memset((void *)mem, 0, size);

	((__be32 *)mem)[size / 4] = cpu_to_be32(0xdeadbeef);

	pr_debug("  unflattening %lx...\n", mem);

	/* Second pass, do actual unflattening */
	start = ((unsigned long)blob) +
		be32_to_cpu(blob->off_dt_struct);
	unflatten_dt_node(blob, mem, &start, NULL, &allnextp, 0);
	if (be32_to_cpup((__be32 *)start) != OF_DT_END)
		pr_warning("Weird tag at end of tree: %08x\n", *((u32 *)start));
	if (be32_to_cpu(((__be32 *)mem)[size / 4]) != 0xdeadbeef)
		pr_warning("End of tree marker overwritten: %08x\n",
			   be32_to_cpu(((__be32 *)mem)[size / 4]));
	*allnextp = NULL;

	pr_debug(" <- unflatten_device_tree()\n");
}

static void *kernel_tree_alloc(u64 size, u64 align)
{
	return kzalloc(size, GFP_KERNEL);
}

/**
 * of_fdt_unflatten_tree - create tree of device_nodes from flat blob
 *
 * unflattens the device-tree passed by the firmware, creating the
 * tree of struct device_node. It also fills the "name" and "type"
 * pointers of the nodes so the normal device-tree walking functions
 * can be used.
 */
void of_fdt_unflatten_tree(unsigned long *blob,
			struct device_node **mynodes)
{
	struct boot_param_header *device_tree =
		(struct boot_param_header *)blob;
	__unflatten_device_tree(device_tree, mynodes, &kernel_tree_alloc);
}
EXPORT_SYMBOL_GPL(of_fdt_unflatten_tree);

/* Everything below here references initial_boot_params directly. */
int __initdata dt_root_addr_cells;
int __initdata dt_root_size_cells;

struct boot_param_header *initial_boot_params;

#ifdef CONFIG_OF_EARLY_FLATTREE

/**
 * of_scan_flat_dt - scan flattened tree blob and call callback on each.
 * @it: callback function
 * @data: context data pointer
 *
 * This function is used to scan the flattened device-tree, it is
 * used to extract the memory information at boot before we can
 * unflatten the tree
 */
int __init of_scan_flat_dt(int (*it)(unsigned long node,
				     const char *uname, int depth,
				     void *data),
			   void *data)
{
	unsigned long p = ((unsigned long)initial_boot_params) +
		be32_to_cpu(initial_boot_params->off_dt_struct);
	// p에 로드해온 DTB의 structure block의 시작 주소를 저장

	int rc = 0;
	int depth = -1;

	do {
		u32 tag = be32_to_cpup((__be32 *)p);
		// property 단위로 계속 이동됨

		const char *pathp;

		p += 4;
		if (tag == OF_DT_END_NODE) {		// 노드 끝인지 확인
			depth--;			// 끝이면 depth를 하나 감소
			continue;
		}
		if (tag == OF_DT_NOP)			// NOP이면 계속 통과
			continue;
		if (tag == OF_DT_END)			// DTB 끝이면 탈출
			break;
		if (tag == OF_DT_PROP) {		// property가 걸릴 경우
			u32 sz = be32_to_cpup((__be32 *)p);
			// property 데이터 길이를 sz에 저장

			p += 8;
			// property 데이터 시작 위치로 p 이동

			if (be32_to_cpu(initial_boot_params->version) < 0x10)	// DTB 버전이 16보다 낮을 때
				p = ALIGN(p, sz >= 8 ? 8 : 4);

			p += sz;
			// property 데이터 종료 위치로 p 이동

			p = ALIGN(p, 4);
			// 4바이트 정렬

			continue;
		}

		// 여기까지 오는 경우는 tag가 새로운 NODE의 시작인 경우 밖에 없음
		if (tag != OF_DT_BEGIN_NODE) {
			pr_err("Invalid tag %x in flat device tree!\n", tag);
			return -EINVAL;
		}

		depth++;
		// 하위 노드가 존재하므로 depth를 하나 증가

		pathp = (char *)p;
		// 하위 노드의 이름 문자열 주소가 pathp에 저장

		p = ALIGN(p + strlen(pathp) + 1, 4);
		// 하위 노드의 이름을 건너 뛴 뒤, property 시작부로 p가 이동

		if (*pathp == '/')
			pathp = kbasename(pathp);
		// 경로 주소명은 전부 날리고, 마지막 실제 이름만 살림

		// p : property의 시작부, pathp : 노드의 이름
		// depth : 노드의 깊이, data : 정보를 저장해올 공간
		rc = it(p, pathp, depth, data);
		if (rc != 0)
			break;
	} while (1);

	return rc;
}

/**
 * of_get_flat_dt_root - find the root node in the flat blob
 */
unsigned long __init of_get_flat_dt_root(void)
{
	unsigned long p = ((unsigned long)initial_boot_params) +
		be32_to_cpu(initial_boot_params->off_dt_struct);
	// DTB 시작 주소에 struct offset을 더해
	// structure 블록의 시작 주소를 찾아 p에 저장

	while (be32_to_cpup((__be32 *)p) == OF_DT_NOP)
		p += 4;
	// structure 블록의 시작에서
	// OF_DT_NOP 이 발견되면 쭉 생략하게 됨

	BUG_ON(be32_to_cpup((__be32 *)p) != OF_DT_BEGIN_NODE);
	// OF_DT_NOP이 아닌 값이 나왔을 때, 그 값이 OF_DT_BEGIN_NODE가 아니면
	// 전달된 DTB에 문제가 있는 것임.
	p += 4;
	return ALIGN(p + strlen((char *)p) + 1, 4);
	// property 서술 시작 부분 위치를 반환
	// 노드 이름이 저장된 부분을 건너뜀
}

/**
 * of_get_flat_dt_prop - Given a node in the flat blob, return the property ptr
 *
 * This function can be used within scan_flattened_dt callback to get
 * access to properties
 */
void *__init of_get_flat_dt_prop(unsigned long node, const char *name,
				 unsigned long *size)
{
	return of_fdt_get_property(initial_boot_params, node, name, size);
}

/**
 * of_flat_dt_is_compatible - Return true if given node has compat in compatible list
 * @node: node to test
 * @compat: compatible string to compare with compatible list.
 */
// node : 테스트할 노드 (현재는 루트 노드), compat : 비교할 리스트
int __init of_flat_dt_is_compatible(unsigned long node, const char *compat)
{
	// initial_boot_params : 부팅 과정에 끌어온 DTB 시작 주소
	return of_fdt_is_compatible(initial_boot_params, node, compat);
}

/**
 * of_flat_dt_match - Return true if node matches a list of compatible values
 */
int __init of_flat_dt_match(unsigned long node, const char *const *compat)
{
	return of_fdt_match(initial_boot_params, node, compat);
}

#ifdef CONFIG_BLK_DEV_INITRD
/**
 * early_init_dt_check_for_initrd - Decode initrd location from flat tree
 * @node: reference to node containing initrd location ('chosen')
 */
void __init early_init_dt_check_for_initrd(unsigned long node)
{
	unsigned long start, end, len;
	__be32 *prop;

	pr_debug("Looking for initrd properties... ");

	prop = of_get_flat_dt_prop(node, "linux,initrd-start", &len);
	// prop : linux,initrd-start property의 데이터 시작 주소
	// len : property의 데이터 길이
	// 로 반환됨

	if (!prop)
		return;

	start = of_read_ulong(prop, len/4);

	prop = of_get_flat_dt_prop(node, "linux,initrd-end", &len);
	if (!prop)
		return;
	end = of_read_ulong(prop, len/4);

	early_init_dt_setup_initrd_arch(start, end);
	pr_debug("initrd_start=0x%lx  initrd_end=0x%lx\n", start, end);
}
#else
inline void early_init_dt_check_for_initrd(unsigned long node)
{
}
#endif /* CONFIG_BLK_DEV_INITRD */

/**
 * early_init_dt_scan_root - fetch the top level address and size cells
 */
// node : property의 시작부, uname : 노드의 이름
// depth : 노드의 깊이, data : 정보를 저장해올 공간
int __init early_init_dt_scan_root(unsigned long node, const char *uname,
				   int depth, void *data)
{
	__be32 *prop;

	if (depth != 0)
		return 0;	// root 노드가 아니면 0 반환

	dt_root_size_cells = OF_ROOT_NODE_SIZE_CELLS_DEFAULT;
	dt_root_addr_cells = OF_ROOT_NODE_ADDR_CELLS_DEFAULT;
	// #size-cells, #address-cells property가 없는 경우 1로 저장됨

	prop = of_get_flat_dt_prop(node, "#size-cells", NULL);
	// #size-cells property의 데이터 시작 주소를 prop에 저장

	if (prop)	// #size-cells property가 존재할 경우
		dt_root_size_cells = be32_to_cpup(prop);
		// property의 데이터를 변수에 저장함

	pr_debug("dt_root_size_cells = %x\n", dt_root_size_cells);

	prop = of_get_flat_dt_prop(node, "#address-cells", NULL);
	// #address-cells property의 데이터 시작 주소를 prop에 저장

	if (prop)	// #address-cells property가 존재하는 경우
		dt_root_addr_cells = be32_to_cpup(prop);
		// property의 데이터를 변수에 저장

	pr_debug("dt_root_addr_cells = %x\n", dt_root_addr_cells);

	/* break now */
	return 1;
}

u64 __init dt_mem_next_cell(int s, __be32 **cellp)
{
	__be32 *p = *cellp;

	*cellp = p + s;
	return of_read_number(p, s);
}

/**
 * early_init_dt_scan_memory - Look for an parse memory nodes
 */
// node : property의 시작부, uname : 노드의 이름
// depth : 노드의 깊이, data : 정보를 저장해올 공간
int __init early_init_dt_scan_memory(unsigned long node, const char *uname,
				     int depth, void *data)
{
	char *type = of_get_flat_dt_prop(node, "device_type", NULL);
	// device_type property가 존재하는지 확인하고 있으면 property의 데이터 시작 주소를
	// type에 저장.
	// 찾지 못한 경우 NULL을 저장함
	__be32 *reg, *endp;
	unsigned long l;

	/* We are scanning "memory" nodes only */
	if (type == NULL) {
		/*
		 * The longtrail doesn't have a device_type on the
		 * /memory node, so look for the node called /memory@0.
		 */
		if (depth != 1 || strcmp(uname, "memory@0") != 0)
			return 0;
	} else if (strcmp(type, "memory") != 0)
		return 0;
	// device_type이 memory가 아니거나 node 이름이 memory@0이 아니면 이 노드는
	// 무조건 메모리 관련 정보가 없는 것임

	// 이 노드에는 memory 관련 정보가 있는 경우만 여기까지 도달.
	// device_type property 가 memory 이거나 노드 이름 자체가 memory@0 인 경우
	reg = of_get_flat_dt_prop(node, "linux,usable-memory", &l);
	// linux,usable-memory property가 존재하면 property 데이터 시작 주소를 reg에 저장
	// 없는 경우 NULL 반환

	if (reg == NULL)
		reg = of_get_flat_dt_prop(node, "reg", &l);
		// reg property가 존재하면 데이터 시작 주소를 reg에 저장하고 데이터 길이를 l에 저장
		// 없으면 NULL 반환
	if (reg == NULL)
		return 0;	// reg 정보가 아예 없는 경우 실패

	endp = reg + (l / sizeof(__be32));
	// reg 정보의 마지막 주소 + 1을 endp에 저장

	pr_debug("memory scan node %s, reg size %ld, data: %x %x %x %x,\n",
	    uname, l, reg[0], reg[1], reg[2], reg[3]);

	while ((endp - reg) >= (dt_root_addr_cells + dt_root_size_cells)) {
		u64 base, size;

		base = dt_mem_next_cell(dt_root_addr_cells, &reg);
		// #address-cells 크기를 이용해 reg 값에서 주소 base 값을 뽑아냄
		// #address-cells 크기가 2이면 64바이트로 표현되며,
		// 1인 경우는 32바이트로 base 주소가 표현되게 됨.

		size = dt_mem_next_cell(dt_root_size_cells, &reg);
		// #size-cells를 위와 동일한 방법으로 뽑아냄

		if (size == 0)
			continue;
		pr_debug(" - %llx ,  %llx\n", (unsigned long long)base,
		    (unsigned long long)size);

		// base : 0x20000000, size : 0x80000000
		early_init_dt_add_memory_arch(base, size);
	}
	// while 문을 수행하지 않는 경우 #size-cells, #address-cells와 reg 정보 크기가 서로
	// 안 맞는 것임.
	// 그러므로 그냥 0 반환

	return 0;
}

// node : property의 시작부, uname : 노드의 이름
// depth : 노드의 깊이, data : 정보를 저장해올 공간
int __init early_init_dt_scan_chosen(unsigned long node, const char *uname,
				     int depth, void *data)
{
	unsigned long l;
	char *p;

	pr_debug("search \"chosen\", depth: %d, uname: %s\n", depth, uname);

	if (depth != 1 || !data ||
	    (strcmp(uname, "chosen") != 0 && strcmp(uname, "chosen@0") != 0))
		return 0;	// node 이름이 chosen이 아니면 무조건 0 반환

	// node 이름이 chosen, chosen@0이 되어야 이 쪽까지 도달 가능
	early_init_dt_check_for_initrd(node);
	// 만약 chosen 노드에 initrd 시작 주소와 마지막 주소에 대한 property가 존재하는 경우
	// 이를 전역 변수에 저장하고 돌아옴
	// 그러한 property가 없는 경우 그냥 복귀

	/* Retrieve command line */
	p = of_get_flat_dt_prop(node, "bootargs", &l);
	// p : bootargs property의 데이터 시작 주소
	// l : bootargs property의 데이터 길이

	if (p != NULL && l > 0)
		strlcpy(data, p, min((int)l, COMMAND_LINE_SIZE));
	// data에 찾아낸 property의 데이터를 복사함

	/*
	 * CONFIG_CMDLINE is meant to be a default in case nothing else
	 * managed to set the command line, unless CONFIG_CMDLINE_FORCE
	 * is set in which case we override whatever was found earlier.
	 */
#ifdef CONFIG_CMDLINE
#ifndef CONFIG_CMDLINE_FORCE
	if (!((char *)data)[0])
#endif
		strlcpy(data, CONFIG_CMDLINE, COMMAND_LINE_SIZE);
#endif /* CONFIG_CMDLINE */
	// DTB에서 뽑아온 cmdline 데이터가 없는 경우 미리 config에 지정해둔 값이 저장됨.
	// DTB에서 뽑아온 데이터가 존재하는 경우 이를 사용함

	pr_debug("Command line is: %s\n", (char*)data);

	/* break now */
	return 1;
}

/**
 * unflatten_device_tree - create tree of device_nodes from flat blob
 *
 * unflattens the device-tree passed by the firmware, creating the
 * tree of struct device_node. It also fills the "name" and "type"
 * pointers of the nodes so the normal device-tree walking functions
 * can be used.
 */
void __init unflatten_device_tree(void)
{
	__unflatten_device_tree(initial_boot_params, &of_allnodes,
				early_init_dt_alloc_memory_arch);

	/* Get pointer to "/chosen" and "/aliases" nodes for use everywhere */
	of_alias_scan(early_init_dt_alloc_memory_arch);
}

#endif /* CONFIG_OF_EARLY_FLATTREE */
