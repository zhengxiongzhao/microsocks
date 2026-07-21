#include "sblist.h"
#include <string.h>

void sblist_delete(sblist* l, size_t item) {
	if (l->count && item < l->count) {
		memmove(sblist_item_from_index(l, item), sblist_item_from_index(l, item + 1), (sblist_getsize(l) - (item + 1)) * l->itemsize);
		l->count--;
	}
}

void sblist_delete_fast(sblist* l, size_t item) {
	if (l->count && item < l->count) {
		if (item != l->count - 1) {
			memcpy(sblist_item_from_index(l, item), sblist_item_from_index(l, l->count - 1), l->itemsize);
		}
		l->count--;
	}
}
