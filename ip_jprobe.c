#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

/* Proxy routine having the same arguments as actual _do_fork() routine */
static long j_do_fork(unsigned long clone_flags, unsigned long stack_start,
              unsigned long stack_size, int __user *parent_tidptr,
              int __user *child_tidptr, unsigned long tls)
{
        pr_info("jprobe: clone_flags = 0x%lx, stack_start = 0x%lx "
                "stack_size = 0x%lx\n", clone_flags, stack_start, stack_size);

        /* Always end with a call to jprobe_return(). */
        jprobe_return();
        return 0;
}

static struct jprobe my_jprobe = {
        .entry                  = j_do_fork,
        .kp = {
                .symbol_name    = "_do_fork",
        },
};

static int __init jprobe_init(void)
{
        int ret;

        ret = register_jprobe(&my_jprobe);
        if (ret < 0) {
                pr_err("register_jprobe failed, returned %d\n", ret);
                return -1;
        }
        pr_info("Planted jprobe at %p, handler addr %p\n",
               my_jprobe.kp.addr, my_jprobe.entry);
        return 0;
}

static void __exit jprobe_exit(void)
{
        unregister_jprobe(&my_jprobe);
        pr_info("jprobe at %p unregistered\n", my_jprobe.kp.addr);
}

module_init(jprobe_init)
module_exit(jprobe_exit)
MODULE_LICENSE("GPL");
