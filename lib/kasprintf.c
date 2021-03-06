/*
 *  linux/lib/kasprintf.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <stdarg.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/string.h>

/* Simplified asprintf. */
// gfp :: GFP_NOWAIT, fmt : "kmalloc-192", ap : 
char *kvasprintf(gfp_t gfp, const char *fmt, va_list ap)
{
	unsigned int len;
	char *p;
	va_list aq;

	va_copy(aq, ap);
	len = vsnprintf(NULL, 0, fmt, aq);
	va_end(aq);

	// len : 11, gfp : GFP_NOWAIT
	p = kmalloc_track_caller(len+1, gfp);
	// __kmalloc_track_caller(12, GFP_NOWAIT, _RET_IP_)가 호출됨
	// kmem_cache#2-o1 오브젝트를 받아 p에 저장
	
	if (!p)
		return NULL;

	vsnprintf(p, len+1, fmt, ap);

	return p;
}
EXPORT_SYMBOL(kvasprintf);

// gfp :: GFP_NOWAIT, fmt : "kmalloc-192"
char *kasprintf(gfp_t gfp, const char *fmt, ...)
{
	va_list ap;
	char *p;

	va_start(ap, fmt);
	p = kvasprintf(gfp, fmt, ap);
	va_end(ap);

	return p;
}
EXPORT_SYMBOL(kasprintf);
