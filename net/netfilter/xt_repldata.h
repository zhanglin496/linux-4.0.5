/*
 * Today's hack: quantum tunneling in structs
 *
 * 'entries' and 'term' are never anywhere referenced by word in code. In fact,
 * they serve as the hanging-off data accessed through repl.data[].
 */

/* tbl has the following structure equivalent, but is C99 compliant:
 * struct {
 *	struct type##_replace repl;
 *	struct type##_standard entries[nhooks];
 *	struct type##_error term;
 * } *tbl;
 */

#if 0
//调用 xt_alloc_initial_table(ipt, IPT); 展开后如下

 unsigned int hook_mask = info->valid_hooks;
//计算hook_mask中bit为1的个数
 unsigned int nhooks = hweight32(hook_mask);
 unsigned int bytes = 0, hooknum = 0, i = 0;
 struct {
	   struct ipt_replace repl;
	   struct ipt_standard entries[];
 } *tbl;
 struct ipt_error *term;
 //计算term偏移，有多少个nhooks，就分配多少个ipt_standard
 size_t term_offset = (offsetof(typeof(*tbl), entries[nhooks]) + __alignof__(*term) - 1) & ~(__alignof__(*term) - 1);
 //分配表内存
 tbl = kzalloc(term_offset + sizeof(*term), GFP_KERNEL);
 if (tbl == NULL)
		 return NULL;
 term = (struct ipt_error *)&(((char *)tbl)[term_offset]);
 //拷贝表的名称，比如filter,nat,raw,mangle,
 strncpy(tbl->repl.name, info->name, sizeof(tbl->repl.name));
 //初始化ipt_error，ipt_error位于表的末尾
 *term = (struct ipt_error)IPT_ERROR_INIT;
 tbl->repl.valid_hooks = hook_mask;
 tbl->repl.num_entries = nhooks + 1;
 //size 不包括ipt_replace的大小，只包括规则的大小
 tbl->repl.size = nhooks * sizeof(struct ipt_standard) + sizeof(struct ipt_error);
 for (; hook_mask != 0; hook_mask >>= 1, ++hooknum) {
		 if (!(hook_mask & 1))
				 continue;
		 //hooknum 和 hook_mask是相对应的
		 //hook_mask bit0为1，则hooknum为0
		 //hook_mask bit1为1，则hooknum为1
		 //记录每个hook点的ipt_standard的偏移
		 tbl->repl.hook_entry[hooknum] = bytes;
		 tbl->repl.underflow[hooknum] = bytes;
		 //初始化ipt_standard, 默认都是NF_ACCEPT
		 tbl->entries[i++] = (struct ipt_standard) IPT_STANDARD_INIT(NF_ACCEPT);
		 bytes += sizeof(struct ipt_standard); 
 }
}
//tbl表的初始内存布局如下
----------------------------------------------------------
ipt_replace   | ipt_standard  | ipt_standard | ipt_error |
----------------------------------------------------------
#endif

#define xt_alloc_initial_table(type, typ2) ({ \
	unsigned int hook_mask = info->valid_hooks; \
	unsigned int nhooks = hweight32(hook_mask); \
	unsigned int bytes = 0, hooknum = 0, i = 0; \
	struct { \
		struct type##_replace repl; \
		struct type##_standard entries[]; \
	} *tbl; \
	struct type##_error *term; \
	size_t term_offset = (offsetof(typeof(*tbl), entries[nhooks]) + \
		__alignof__(*term) - 1) & ~(__alignof__(*term) - 1); \
	tbl = kzalloc(term_offset + sizeof(*term), GFP_KERNEL); \
	if (tbl == NULL) \
		return NULL; \
	term = (struct type##_error *)&(((char *)tbl)[term_offset]); \
	strncpy(tbl->repl.name, info->name, sizeof(tbl->repl.name)); \
	*term = (struct type##_error)typ2##_ERROR_INIT;  \
	tbl->repl.valid_hooks = hook_mask; \
	tbl->repl.num_entries = nhooks + 1; \
	tbl->repl.size = nhooks * sizeof(struct type##_standard) + \
			 sizeof(struct type##_error); \
	for (; hook_mask != 0; hook_mask >>= 1, ++hooknum) { \
		if (!(hook_mask & 1)) \
			continue; \
		tbl->repl.hook_entry[hooknum] = bytes; \
		tbl->repl.underflow[hooknum]  = bytes; \
		tbl->entries[i++] = (struct type##_standard) \
			typ2##_STANDARD_INIT(NF_ACCEPT); \
		bytes += sizeof(struct type##_standard); \
	} \
	tbl; \
})
