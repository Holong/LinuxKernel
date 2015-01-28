
#include <linux/device.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/pci_regs.h>
#include <linux/string.h>

/* Max address size we deal with */
#define OF_MAX_ADDR_CELLS	4
#define OF_CHECK_ADDR_COUNT(na)	((na) > 0 && (na) <= OF_MAX_ADDR_CELLS)
#define OF_CHECK_COUNTS(na, ns)	(OF_CHECK_ADDR_COUNT(na) && (ns) > 0)

static struct of_bus *of_match_bus(struct device_node *np);
static int __of_address_to_resource(struct device_node *dev,
		const __be32 *addrp, u64 size, unsigned int flags,
		const char *name, struct resource *r);

/* Debug utility */
#ifdef DEBUG
static void of_dump_addr(const char *s, const __be32 *addr, int na)
{
	printk(KERN_DEBUG "%s", s);
	while (na--)
		printk(" %08x", be32_to_cpu(*(addr++)));
	printk("\n");
}
#else
static void of_dump_addr(const char *s, const __be32 *addr, int na) { }
#endif

/* Callbacks for bus specific translators */
struct of_bus {
	const char	*name;
	const char	*addresses;
	int		(*match)(struct device_node *parent);
	void		(*count_cells)(struct device_node *child,
				       int *addrc, int *sizec);
	u64		(*map)(__be32 *addr, const __be32 *range,
				int na, int ns, int pna);
	int		(*translate)(__be32 *addr, u64 offset, int na);
	unsigned int	(*get_flags)(const __be32 *addr);
};

/*
 * Default translator (generic bus)
 */

// dev : gic 노드의 주소, addrc : &na, sizec : &ns
static void of_bus_default_count_cells(struct device_node *dev,
				       int *addrc, int *sizec)
{
	// addrc : &na
	if (addrc)
		// dev : gic 노드의 주소
		*addrc = of_n_addr_cells(dev);
		// gic 노드의 부모 노드 중에서 address-cells 속성을 갖고 있는지 찾고
		// 그 값을 반환
		// na값을 1로 변경

	// sizec : &ns
	if (sizec)
		// dev : gic 노드의 주소
		*sizec = of_n_size_cells(dev);
		// gic 노드의 부모 노드 중에서 size-cells 속성을 갖고 있는지 찾고
		// 그 값을 반환
		// ns값을 1로 변경
}

static u64 of_bus_default_map(__be32 *addr, const __be32 *range,
		int na, int ns, int pna)
{
	u64 cp, s, da;

	cp = of_read_number(range, na);
	s  = of_read_number(range + na + pna, ns);
	da = of_read_number(addr, na);

	pr_debug("OF: default map, cp=%llx, s=%llx, da=%llx\n",
		 (unsigned long long)cp, (unsigned long long)s,
		 (unsigned long long)da);

	if (da < cp || da >= (cp + s))
		return OF_BAD_ADDR;
	return da - cp;
}

static int of_bus_default_translate(__be32 *addr, u64 offset, int na)
{
	u64 a = of_read_number(addr, na);
	memset(addr, 0, na * 4);
	a += offset;
	if (na > 1)
		addr[na - 2] = cpu_to_be32(a >> 32);
	addr[na - 1] = cpu_to_be32(a & 0xffffffffu);

	return 0;
}

static unsigned int of_bus_default_get_flags(const __be32 *addr)
{
	return IORESOURCE_MEM;
}

#ifdef CONFIG_PCI
/*
 * PCI bus specific translator
 */

static int of_bus_pci_match(struct device_node *np)
{
	/*
 	 * "pciex" is PCI Express
	 * "vci" is for the /chaos bridge on 1st-gen PCI powermacs
	 * "ht" is hypertransport
	 */
	return !strcmp(np->type, "pci") || !strcmp(np->type, "pciex") ||
		!strcmp(np->type, "vci") || !strcmp(np->type, "ht");
}

static void of_bus_pci_count_cells(struct device_node *np,
				   int *addrc, int *sizec)
{
	if (addrc)
		*addrc = 3;
	if (sizec)
		*sizec = 2;
}

static unsigned int of_bus_pci_get_flags(const __be32 *addr)
{
	unsigned int flags = 0;
	u32 w = be32_to_cpup(addr);

	switch((w >> 24) & 0x03) {
	case 0x01:
		flags |= IORESOURCE_IO;
		break;
	case 0x02: /* 32 bits */
	case 0x03: /* 64 bits */
		flags |= IORESOURCE_MEM;
		break;
	}
	if (w & 0x40000000)
		flags |= IORESOURCE_PREFETCH;
	return flags;
}

static u64 of_bus_pci_map(__be32 *addr, const __be32 *range, int na, int ns,
		int pna)
{
	u64 cp, s, da;
	unsigned int af, rf;

	af = of_bus_pci_get_flags(addr);
	rf = of_bus_pci_get_flags(range);

	/* Check address type match */
	if ((af ^ rf) & (IORESOURCE_MEM | IORESOURCE_IO))
		return OF_BAD_ADDR;

	/* Read address values, skipping high cell */
	cp = of_read_number(range + 1, na - 1);
	s  = of_read_number(range + na + pna, ns);
	da = of_read_number(addr + 1, na - 1);

	pr_debug("OF: PCI map, cp=%llx, s=%llx, da=%llx\n",
		 (unsigned long long)cp, (unsigned long long)s,
		 (unsigned long long)da);

	if (da < cp || da >= (cp + s))
		return OF_BAD_ADDR;
	return da - cp;
}

static int of_bus_pci_translate(__be32 *addr, u64 offset, int na)
{
	return of_bus_default_translate(addr + 1, offset, na - 1);
}

const __be32 *of_get_pci_address(struct device_node *dev, int bar_no, u64 *size,
			unsigned int *flags)
{
	const __be32 *prop;
	unsigned int psize;
	struct device_node *parent;
	struct of_bus *bus;
	int onesize, i, na, ns;

	/* Get parent & match bus type */
	parent = of_get_parent(dev);
	if (parent == NULL)
		return NULL;
	bus = of_match_bus(parent);
	if (strcmp(bus->name, "pci")) {
		of_node_put(parent);
		return NULL;
	}
	bus->count_cells(dev, &na, &ns);
	of_node_put(parent);
	if (!OF_CHECK_ADDR_COUNT(na))
		return NULL;

	/* Get "reg" or "assigned-addresses" property */
	prop = of_get_property(dev, bus->addresses, &psize);
	if (prop == NULL)
		return NULL;
	psize /= 4;

	onesize = na + ns;
	for (i = 0; psize >= onesize; psize -= onesize, prop += onesize, i++) {
		u32 val = be32_to_cpu(prop[0]);
		if ((val & 0xff) == ((bar_no * 4) + PCI_BASE_ADDRESS_0)) {
			if (size)
				*size = of_read_number(prop + na, ns);
			if (flags)
				*flags = bus->get_flags(prop);
			return prop;
		}
	}
	return NULL;
}
EXPORT_SYMBOL(of_get_pci_address);

int of_pci_address_to_resource(struct device_node *dev, int bar,
			       struct resource *r)
{
	const __be32	*addrp;
	u64		size;
	unsigned int	flags;

	addrp = of_get_pci_address(dev, bar, &size, &flags);
	if (addrp == NULL)
		return -EINVAL;
	return __of_address_to_resource(dev, addrp, size, flags, NULL, r);
}
EXPORT_SYMBOL_GPL(of_pci_address_to_resource);

int of_pci_range_parser_init(struct of_pci_range_parser *parser,
				struct device_node *node)
{
	const int na = 3, ns = 2;
	int rlen;

	parser->node = node;
	parser->pna = of_n_addr_cells(node);
	parser->np = parser->pna + na + ns;

	parser->range = of_get_property(node, "ranges", &rlen);
	if (parser->range == NULL)
		return -ENOENT;

	parser->end = parser->range + rlen / sizeof(__be32);

	return 0;
}
EXPORT_SYMBOL_GPL(of_pci_range_parser_init);

struct of_pci_range *of_pci_range_parser_one(struct of_pci_range_parser *parser,
						struct of_pci_range *range)
{
	const int na = 3, ns = 2;

	if (!range)
		return NULL;

	if (!parser->range || parser->range + parser->np > parser->end)
		return NULL;

	range->pci_space = parser->range[0];
	range->flags = of_bus_pci_get_flags(parser->range);
	range->pci_addr = of_read_number(parser->range + 1, ns);
	range->cpu_addr = of_translate_address(parser->node,
				parser->range + na);
	range->size = of_read_number(parser->range + parser->pna + na, ns);

	parser->range += parser->np;

	/* Now consume following elements while they are contiguous */
	while (parser->range + parser->np <= parser->end) {
		u32 flags, pci_space;
		u64 pci_addr, cpu_addr, size;

		pci_space = be32_to_cpup(parser->range);
		flags = of_bus_pci_get_flags(parser->range);
		pci_addr = of_read_number(parser->range + 1, ns);
		cpu_addr = of_translate_address(parser->node,
				parser->range + na);
		size = of_read_number(parser->range + parser->pna + na, ns);

		if (flags != range->flags)
			break;
		if (pci_addr != range->pci_addr + range->size ||
		    cpu_addr != range->cpu_addr + range->size)
			break;

		range->size += size;
		parser->range += parser->np;
	}

	return range;
}
EXPORT_SYMBOL_GPL(of_pci_range_parser_one);

#endif /* CONFIG_PCI */

/*
 * ISA bus specific translator
 */
// np : root 노드의 주소
static int of_bus_isa_match(struct device_node *np)
{
	// np->name : root 노드의 이름 "/"
	return !strcmp(np->name, "isa");
	// return 0
}

static void of_bus_isa_count_cells(struct device_node *child,
				   int *addrc, int *sizec)
{
	if (addrc)
		*addrc = 2;
	if (sizec)
		*sizec = 1;
}

static u64 of_bus_isa_map(__be32 *addr, const __be32 *range, int na, int ns,
		int pna)
{
	u64 cp, s, da;

	/* Check address type match */
	if ((addr[0] ^ range[0]) & cpu_to_be32(1))
		return OF_BAD_ADDR;

	/* Read address values, skipping high cell */
	cp = of_read_number(range + 1, na - 1);
	s  = of_read_number(range + na + pna, ns);
	da = of_read_number(addr + 1, na - 1);

	pr_debug("OF: ISA map, cp=%llx, s=%llx, da=%llx\n",
		 (unsigned long long)cp, (unsigned long long)s,
		 (unsigned long long)da);

	if (da < cp || da >= (cp + s))
		return OF_BAD_ADDR;
	return da - cp;
}

static int of_bus_isa_translate(__be32 *addr, u64 offset, int na)
{
	return of_bus_default_translate(addr + 1, offset, na - 1);
}

static unsigned int of_bus_isa_get_flags(const __be32 *addr)
{
	unsigned int flags = 0;
	u32 w = be32_to_cpup(addr);

	if (w & 1)
		flags |= IORESOURCE_IO;
	else
		flags |= IORESOURCE_MEM;
	return flags;
}

/*
 * Array of bus specific translators
 */

static struct of_bus of_busses[] = {
#ifdef CONFIG_PCI	// N
	/* PCI */
	{
		.name = "pci",
		.addresses = "assigned-addresses",
		.match = of_bus_pci_match,
		.count_cells = of_bus_pci_count_cells,
		.map = of_bus_pci_map,
		.translate = of_bus_pci_translate,
		.get_flags = of_bus_pci_get_flags,
	},
#endif /* CONFIG_PCI */
	/* ISA */
	{
		.name = "isa",
		.addresses = "reg",
		.match = of_bus_isa_match,
		.count_cells = of_bus_isa_count_cells,
		.map = of_bus_isa_map,
		.translate = of_bus_isa_translate,
		.get_flags = of_bus_isa_get_flags,
	},
	/* Default */
	{
		.name = "default",
		.addresses = "reg",
		.match = NULL,
		.count_cells = of_bus_default_count_cells,
		.map = of_bus_default_map,
		.translate = of_bus_default_translate,
		.get_flags = of_bus_default_get_flags,
	},
};

// np : root 노드의 주소
static struct of_bus *of_match_bus(struct device_node *np)
{
	int i;

	// of_busses : 전역 배열
	// ARRAY_SIZE(of_busses) : 2
	for (i = 0; i < ARRAY_SIZE(of_busses); i++)
		// of_busses[0].match : of_bus_isa_match
		// of_busses[0].match(np) : of_bus_isa_match(np)
		// of_busses[1].match : NULL
		if (!of_busses[i].match || of_busses[i].match(np))
			return &of_busses[i];
			// return &of_busses[1]
	BUG();
	return NULL;
}

static int of_translate_one(struct device_node *parent, struct of_bus *bus,
			    struct of_bus *pbus, __be32 *addr,
			    int na, int ns, int pna, const char *rprop)
{
	const __be32 *ranges;
	unsigned int rlen;
	int rone;
	u64 offset = OF_BAD_ADDR;

	/* Normally, an absence of a "ranges" property means we are
	 * crossing a non-translatable boundary, and thus the addresses
	 * below the current not cannot be converted to CPU physical ones.
	 * Unfortunately, while this is very clear in the spec, it's not
	 * what Apple understood, and they do have things like /uni-n or
	 * /ht nodes with no "ranges" property and a lot of perfectly
	 * useable mapped devices below them. Thus we treat the absence of
	 * "ranges" as equivalent to an empty "ranges" property which means
	 * a 1:1 translation at that level. It's up to the caller not to try
	 * to translate addresses that aren't supposed to be translated in
	 * the first place. --BenH.
	 *
	 * As far as we know, this damage only exists on Apple machines, so
	 * This code is only enabled on powerpc. --gcl
	 */
	ranges = of_get_property(parent, rprop, &rlen);
#if !defined(CONFIG_PPC)
	if (ranges == NULL) {
		pr_err("OF: no ranges; cannot translate\n");
		return 1;
	}
#endif /* !defined(CONFIG_PPC) */
	if (ranges == NULL || rlen == 0) {
		offset = of_read_number(addr, na);
		memset(addr, 0, pna * 4);
		pr_debug("OF: empty ranges; 1:1 translation\n");
		goto finish;
	}

	pr_debug("OF: walking ranges...\n");

	/* Now walk through the ranges */
	rlen /= 4;
	rone = na + pna + ns;
	for (; rlen >= rone; rlen -= rone, ranges += rone) {
		offset = bus->map(addr, ranges, na, ns, pna);
		if (offset != OF_BAD_ADDR)
			break;
	}
	if (offset == OF_BAD_ADDR) {
		pr_debug("OF: not found !\n");
		return 1;
	}
	memcpy(addr, ranges + na, 4 * pna);

 finish:
	of_dump_addr("OF: parent translation for:", addr, pna);
	pr_debug("OF: with offset: %llx\n", (unsigned long long)offset);

	/* Translate it into parent bus space */
	return pbus->translate(addr, offset, pna);
}

/*
 * Translate an address from the device-tree into a CPU physical address,
 * this walks up the tree and applies the various bus mappings on the
 * way.
 *
 * Note: We consider that crossing any level with #size-cells == 0 to mean
 * that translation is impossible (that is we are not dealing with a value
 * that can be mapped to a cpu physical address). This is not really specified
 * that way, but this is traditionally the way IBM at least do things
 */
// dev : gic 노드의 주소, in_addr : gic 노드의 reg 속성 값 시작 주소
// rprop : "ranges"
static u64 __of_translate_address(struct device_node *dev,
				  const __be32 *in_addr, const char *rprop)
{
	struct device_node *parent = NULL;
	struct of_bus *bus, *pbus;
	// OF_MAX_ADDR_CELLS : 4
	__be32 addr[OF_MAX_ADDR_CELLS];
	int na, ns, pna, pns;
	// OF_BAD_ADDR : 0xFFFFFFFFFFFFFFFF;
	u64 result = OF_BAD_ADDR;
	// result : 0xFFFFFFFFFFFFFFFF;

	pr_debug("OF: ** translation for device %s **\n", of_node_full_name(dev));
	// of_node_full_name(dev) : "/interrupt-controller@10481000"

	/* Increase refcount at current level */
	of_node_get(dev);
	// 하는 것 없음

	/* Get parent & match bus type */
	parent = of_get_parent(dev);
	// parent : root 노드의 주소
	
	if (parent == NULL)
		goto bail;

	// parent : root 노드의 주소
	bus = of_match_bus(parent);
	// bus : &of_busses[1]
	
	/* Count address cells & copy address locally */
	// bus->count_cells : of_bus_default_count_cells
	bus->count_cells(dev, &na, &ns);
	// na : 1, ns : 1
	
	if (!OF_CHECK_COUNTS(na, ns)) {
		printk(KERN_ERR "prom_parse: Bad cell count for %s\n",
		       of_node_full_name(dev));
		goto bail;
	}
	// 통과
	
	// addr : 지역 변수 in_addr : gic 노드의 reg 속성 값 시작 주소
	// na : 1
	memcpy(addr, in_addr, na * 4);
	// addr[0] : 0x10481000

	pr_debug("OF: bus is %s (na=%d, ns=%d) on %s\n",
	    bus->name, na, ns, of_node_full_name(parent));
	// "OF: bus is defualt (na=1, ns=1) on /"
	of_dump_addr("OF: translating address:", addr, na);
	// NULL 함수

	/* Translate */
	for (;;) {
		/* Switch to parent bus */
		of_node_put(dev);
		// null 함수

		// parent : root 노드의 주소
		dev = parent;
		// dev : root 노드의 주소

		parent = of_get_parent(dev);
		// parent : NULL

		/* If root, we have finished */
		// parent : NULL
		if (parent == NULL) {
			pr_debug("OF: reached root node\n");
			result = of_read_number(addr, na);
			// result : 0x10481000
			break;
		}

		/* Get new parent bus and counts */
		pbus = of_match_bus(parent);
		pbus->count_cells(dev, &pna, &pns);
		if (!OF_CHECK_COUNTS(pna, pns)) {
			printk(KERN_ERR "prom_parse: Bad cell count for %s\n",
			       of_node_full_name(dev));
			break;
		}

		pr_debug("OF: parent bus is %s (na=%d, ns=%d) on %s\n",
		    pbus->name, pna, pns, of_node_full_name(parent));

		/* Apply bus translation */
		if (of_translate_one(dev, bus, pbus, addr, na, ns, pna, rprop))
			break;

		/* Complete the move up one level */
		na = pna;
		ns = pns;
		bus = pbus;

		of_dump_addr("OF: one level translation:", addr, na);
	}
 bail:
	of_node_put(parent);
	of_node_put(dev);
	// NULL 함수

	return result;
	// result : 0x10481000
}

// dev : gic 노드의 주소, addrp : gic 노드의 reg 속성 값 시작 주소
u64 of_translate_address(struct device_node *dev, const __be32 *in_addr)
{
	// dev : gic 노드의 주소, in_addr : gic 노드의 reg 속성 값 시작 주소
	return __of_translate_address(dev, in_addr, "ranges");
	// return : 0x10481000
}
EXPORT_SYMBOL(of_translate_address);

u64 of_translate_dma_address(struct device_node *dev, const __be32 *in_addr)
{
	return __of_translate_address(dev, in_addr, "dma-ranges");
}
EXPORT_SYMBOL(of_translate_dma_address);

bool of_can_translate_address(struct device_node *dev)
{
	struct device_node *parent;
	struct of_bus *bus;
	int na, ns;

	parent = of_get_parent(dev);
	if (parent == NULL)
		return false;

	bus = of_match_bus(parent);
	bus->count_cells(dev, &na, &ns);

	of_node_put(parent);

	return OF_CHECK_COUNTS(na, ns);
}
EXPORT_SYMBOL(of_can_translate_address);

// [0] dev : gic 노드의 주소, index : 0, size : 지역 변수 주소, flags : 지역 변수 주소
// [1] dev : gic 노드의 주소, index : 1, size : 지역 변수 주소, flags : 지역 변수 주소
const __be32 *of_get_address(struct device_node *dev, int index, u64 *size,
		    unsigned int *flags)
{
	const __be32 *prop;
	unsigned int psize;
	struct device_node *parent;
	struct of_bus *bus;
	int onesize, i, na, ns;

	/* Get parent & match bus type */
	// dev : gic 노드의 주소
	parent = of_get_parent(dev);
	// parent : root 노드의 주소
	// dev 노드의 부모 노드의 주소를 반환 함
	
	if (parent == NULL)
		return NULL;
	// 통과
	
	// parent : root 노드의 주소
	bus = of_match_bus(parent);
	// bus : &of_busses[1]

	// bus->count_cells : of_bus_default_count_cells
	// dev : gic 노드의 주소, na, ns
	bus->count_cells(dev, &na, &ns);
	// na : 1, ns : 1
	// address-cells, size-cells : 각각 1
	
	// parent : root 노드의 주소
	of_node_put(parent);
	// NULL 함수
	
	if (!OF_CHECK_ADDR_COUNT(na))
	// OF_CHECK_ADDR_COUNT(na)	((na) > 0 && (na) <= OF_MAX_ADDR_CELLS)
	// OF_MAX_ADDR_CELLS : 4
		return NULL;
	// address-cells 값이 1 ~ 4 인지 확인

	/* Get "reg" or "assigned-addresses" property */
	// dev : gic 노드의 주소, bus->addresses : "reg", psize
	prop = of_get_property(dev, bus->addresses, &psize);
	// prop : gic 노드의 reg 속성 값의 주소, psize : 32
	
	if (prop == NULL)
		return NULL;

	psize /= 4;
	// psize : 8

	// na : 1, ns : 1
	onesize = na + ns;
	// onesize : 2
	
	// psize : 8, onesize : 2, index : 0
	for (i = 0; psize >= onesize; psize -= onesize, prop += onesize, i++)
		if (i == index) {
			if (size)
				*size = of_read_number(prop + na, ns);
				// size : 0x1000
				// 이전 함수의 지역 변수에 저장됨
			if (flags)
				// bus->get_flags : of_bus_default_get_flags
				// prop : gic 노드의 reg 속성 값 주소
				*flags = bus->get_flags(prop);
				// flags : IORESOURCE_MEM(0x00000200)
				// 무조건 위의 값이 저장됨

			return prop;
			// return gic 노드의 reg 속성 값 시작 주소
		}
	return NULL;
}
EXPORT_SYMBOL(of_get_address);

unsigned long __weak pci_address_to_pio(phys_addr_t address)
{
	if (address > IO_SPACE_LIMIT)
		return (unsigned long)-1;

	return (unsigned long) address;
}

// dev : gic 노드의 주소, addrp : gic 노드의 reg 속성 값 시작 주소
// size : 0x1000, flags : IORESOURCE_MEM(0x00000200)
// name : NULL, r : res 주소
static int __of_address_to_resource(struct device_node *dev,
		const __be32 *addrp, u64 size, unsigned int flags,
		const char *name, struct resource *r)
{
	u64 taddr;

	// IORESOURCE_IO : 0x00000100, IORESOURCE_MEM : 0x00000200
	if ((flags & (IORESOURCE_IO | IORESOURCE_MEM)) == 0)
		return -EINVAL;
	// 통과
	
	// dev : gic 노드의 주소, addrp : gic 노드의 reg 속성 값 시작 주소
	taddr = of_translate_address(dev, addrp);
	// gic 노드의 reg 값 중에서 address 정보를 뽑아옴
	// taddr : 0x10481000
	
	if (taddr == OF_BAD_ADDR)
		return -EINVAL;
	// 통과
	
	memset(r, 0, sizeof(struct resource));
	// r 변수를 0으로 초기화
	
	// flags : IORESOURCE_MEM
	if (flags & IORESOURCE_IO) {
		unsigned long port;
		port = pci_address_to_pio(taddr);
		if (port == (unsigned long)-1)
			return -EINVAL;
		r->start = port;
		r->end = port + size - 1;
	} else {
		// 이쪽으로 진입
		r->start = taddr;
		// res->start : 0x10481000
		r->end = taddr + size - 1;
		// res->end : 0x10481FFF
	}
	r->flags = flags;
	// res->flags : IORESOURCE_MEM
	
	// name : NULL
	r->name = name ? name : dev->full_name;
	// res->name : "/interrupt-contoller@10481000"

	return 0;
}

/**
 * of_address_to_resource - Translate device tree address and return as resource
 *
 * Note that if your address is a PIO address, the conversion will fail if
 * the physical address can't be internally converted to an IO token with
 * pci_address_to_pio(), that is because it's either called to early or it
 * can't be matched to any host bridge IO space
 */
/*
 * of_address_to_resource - dev의 res 정보를 struct recource로 바꿔줌
 */
// [0] dev : gic 노드의 주소, index : 0, r : res 주소
// [1] dev : gic 노드의 주소, index : 1, r : res 주소
int of_address_to_resource(struct device_node *dev, int index,
			   struct resource *r)
{
	const __be32	*addrp;
	u64		size;
	unsigned int	flags;
	const char	*name = NULL;

	// [0] dev : gic 노드의 주소, index : 0
	// [1] dev : gic 노드의 주소, index : 1
	addrp = of_get_address(dev, index, &size, &flags);
	// addrp : gic 노드의 reg 속성 값 시작 주소
	// size : 0x1000
	// flags : IORESOURCE_MEM(0x00000200)
	
	// addrp : gic 노드의 reg 속성 값 시작 주소
	if (addrp == NULL)
		return -EINVAL;

	/* Get optional "reg-names" property to add a name to a resource */
	// dev : gic 노드의 주소, "reg-names", index : 0, name
	of_property_read_string_index(dev, "reg-names",	index, &name);
	// gic 노드에 reg-names 속성이 없기 때문에 하는 일 없음

	// dev : gic 노드의 주소, addrp : gic 노드의 reg 속성 값 시작 주소
	// size : 0x1000, flags : IORESOURCE_MEM(0x00000200)
	// name : NULL, r : res 주소
	return __of_address_to_resource(dev, addrp, size, flags, name, r);
	// return 0
	// dev 노드에서 address 값을 추출하고, size와 flags를 이용해
	// r이 가리키는 구조체를 초기화 해줌
	//
	// res->start : 0x10481000
	// res->end : 0x10481FFF
	// res->flags : IORESOURCE_MEM
	// res->name : "/interrupt-contoller@10481000"
}
EXPORT_SYMBOL_GPL(of_address_to_resource);

struct device_node *of_find_matching_node_by_address(struct device_node *from,
					const struct of_device_id *matches,
					u64 base_address)
{
	struct device_node *dn = of_find_matching_node(from, matches);
	struct resource res;

	while (dn) {
		if (of_address_to_resource(dn, 0, &res))
			continue;
		if (res.start == base_address)
			return dn;
		dn = of_find_matching_node(dn, matches);
	}

	return NULL;
}


/**
 * of_iomap - Maps the memory mapped IO for a given device_node
 * @device:	the device whose io range will be mapped
 * @index:	index of the io range
 *
 * Returns a pointer to the mapped memory
 */
// [0] np : gic 노드의 주소, index : 0
// [1] np : gic 노드의 주소, index : 1
// [2] np : combiner 노드의 주소
// [3] np : clock-controller의 노드 주소, index : 0
void __iomem *of_iomap(struct device_node *np, int index)
{
	struct resource res;

	// [0] np : gic 노드의 주소, index : 0, res : res 주소
	// [1] np : gic 노드의 주소, index : 1, res : res 주소
	// [2] np : combiner 노드의 주소, index : 0, res : res 주소
	// [3] np : clock-controller의 노드 주소, res : res 주소
	if (of_address_to_resource(np, index, &res))
		// of_address_to_resource : np의 reg 값을 해석해 resource 구조체로 변경
		//
		// [0] return 0
		// [0] res->start : 0x10481000
		// [0] res->end : 0x10481FFF
		// [0] res->flags : IORESOURCE_MEM
		// [0] res->name : "/interrupt-contoller@10481000"
		//
		// [2] return 0
		// [2] res->start : 0x10440000
		// [2] res->end : 0x10440FFF
		// [2] res->flags : IORESOURCE_MEM
		// [2] res->name : "/interrupt-contoller@10440000"
		return NULL;

	// [0] res.start : 0x10481000
	// [0] resource_size(&res) : 0x1000
	// [2] res.start : 0x10440000
	// [2] resource_size(&res) : 0x1000
	return ioremap(res.start, resource_size(&res));
	// [0] ioremap(0x10481000, 0x1000) 이
	// [0] __arm_ioremap(0x10481000, 0x1000, MT_DEVICE) 로 바뀜
	// [0] 가상주소와 물리주소 연결을 위한 페이지 테이블 생성
	// [0] return 0xF0000000
	//
	// [2] ioremap(0x10440000, 0x1000) 이
	// [2] __arm_ioremap(0x10440000, 0x1000, MT_DEVICE) 로 바뀜
	// [2] 가상주소와 물리주소 연결을 위한 페이지 테이블 생성
	//
}
EXPORT_SYMBOL(of_iomap);
