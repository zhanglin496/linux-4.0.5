#ifndef __LINUX_SPINLOCK_API_SMP_H
#define __LINUX_SPINLOCK_API_SMP_H

#ifndef __LINUX_SPINLOCK_H
# error "please don't include this file directly"
#endif

/*
 * include/linux/spinlock_api_smp.h
 *
 * spinlock API declarations on SMP (and debug)
 * (implemented in kernel/spinlock.c)
 *
 * portions Copyright 2005, Red Hat, Inc., Ingo Molnar
 * Released under the General Public License (GPL).
 */

int in_lock_functions(unsigned long addr);

#define assert_raw_spin_locked(x)	BUG_ON(!raw_spin_is_locked(x))

void __lockfunc _raw_spin_lock(raw_spinlock_t *lock)		__acquires(lock);
void __lockfunc _raw_spin_lock_nested(raw_spinlock_t *lock, int subclass)
								__acquires(lock);
void __lockfunc _raw_spin_lock_bh_nested(raw_spinlock_t *lock, int subclass)
								__acquires(lock);
void __lockfunc
_raw_spin_lock_nest_lock(raw_spinlock_t *lock, struct lockdep_map *map)
								__acquires(lock);
void __lockfunc _raw_spin_lock_bh(raw_spinlock_t *lock)		__acquires(lock);
void __lockfunc _raw_spin_lock_irq(raw_spinlock_t *lock)
								__acquires(lock);

unsigned long __lockfunc _raw_spin_lock_irqsave(raw_spinlock_t *lock)
								__acquires(lock);
unsigned long __lockfunc
_raw_spin_lock_irqsave_nested(raw_spinlock_t *lock, int subclass)
								__acquires(lock);
int __lockfunc _raw_spin_trylock(raw_spinlock_t *lock);
int __lockfunc _raw_spin_trylock_bh(raw_spinlock_t *lock);
void __lockfunc _raw_spin_unlock(raw_spinlock_t *lock)		__releases(lock);
void __lockfunc _raw_spin_unlock_bh(raw_spinlock_t *lock)	__releases(lock);
void __lockfunc _raw_spin_unlock_irq(raw_spinlock_t *lock)	__releases(lock);
void __lockfunc
_raw_spin_unlock_irqrestore(raw_spinlock_t *lock, unsigned long flags)
								__releases(lock);

#ifdef CONFIG_INLINE_SPIN_LOCK
#define _raw_spin_lock(lock) __raw_spin_lock(lock)
#endif

#ifdef CONFIG_INLINE_SPIN_LOCK_BH
#define _raw_spin_lock_bh(lock) __raw_spin_lock_bh(lock)
#endif

#ifdef CONFIG_INLINE_SPIN_LOCK_IRQ
#define _raw_spin_lock_irq(lock) __raw_spin_lock_irq(lock)
#endif

#ifdef CONFIG_INLINE_SPIN_LOCK_IRQSAVE
#define _raw_spin_lock_irqsave(lock) __raw_spin_lock_irqsave(lock)
#endif

#ifdef CONFIG_INLINE_SPIN_TRYLOCK
#define _raw_spin_trylock(lock) __raw_spin_trylock(lock)
#endif

#ifdef CONFIG_INLINE_SPIN_TRYLOCK_BH
#define _raw_spin_trylock_bh(lock) __raw_spin_trylock_bh(lock)
#endif

#ifndef CONFIG_UNINLINE_SPIN_UNLOCK
#define _raw_spin_unlock(lock) __raw_spin_unlock(lock)
#endif

#ifdef CONFIG_INLINE_SPIN_UNLOCK_BH
#define _raw_spin_unlock_bh(lock) __raw_spin_unlock_bh(lock)
#endif

#ifdef CONFIG_INLINE_SPIN_UNLOCK_IRQ
#define _raw_spin_unlock_irq(lock) __raw_spin_unlock_irq(lock)
#endif

#ifdef CONFIG_INLINE_SPIN_UNLOCK_IRQRESTORE
#define _raw_spin_unlock_irqrestore(lock, flags) __raw_spin_unlock_irqrestore(lock, flags)
#endif

static inline int __raw_spin_trylock(raw_spinlock_t *lock)
{
	preempt_disable();
	if (do_raw_spin_trylock(lock)) {
		spin_acquire(&lock->dep_map, 0, 1, _RET_IP_);
		return 1;
	}
	preempt_enable();
	return 0;
}

/*
 * If lockdep is enabled then we use the non-preemption spin-ops
 * even on CONFIG_PREEMPT, because lockdep assumes that interrupts are
 * not re-enabled during lock-acquire (which the preempt-spin-ops do):
 */
#if !defined(CONFIG_GENERIC_LOCKBREAK) || defined(CONFIG_DEBUG_LOCK_ALLOC)

static inline unsigned long __raw_spin_lock_irqsave(raw_spinlock_t *lock)
{
	unsigned long flags;

	local_irq_save(flags);
	preempt_disable();
	spin_acquire(&lock->dep_map, 0, 0, _RET_IP_);
	/*
	 * On lockdep we dont want the hand-coded irq-enable of
	 * do_raw_spin_lock_flags() code, because lockdep assumes
	 * that interrupts are not re-enabled during lock-acquire:
	 */
#ifdef CONFIG_LOCKDEP
	LOCK_CONTENDED(lock, do_raw_spin_trylock, do_raw_spin_lock);
#else
	do_raw_spin_lock_flags(lock, &flags);
#endif
	return flags;
}

//tip2：在关闭本地中断后是否有必要关闭抢占？
//    前阵子有网友发短消息问：“...在研究自旋锁的时候，
//发现在 spin_lock_irq函数，也就是在自旋锁中关闭中的这类
//函数中，既然已经关闭了本地中断，再禁止抢占有没有
//多余。也就是说，既然本地中断已经禁止了，在本处理
//器上是无法被打断的，本地调度器也无法运行，也就不
//可以被本地调度程序调度出去..."
//从spinlock设计原理看，使用它的时候，在临界区间是务必
//确保不会发生进程切换。现在的问题是，如果已经关闭
//了中断，在同一处理器上如果不关掉内核抢占的特性，
//会不会有进程调度的情况发生，如果没有，那我个人的
//理解是，在local_irq_disable之后再使用peempt_disable就多此一举了。
//这个在SMP系统上最好理解了，假设有A和B两个处理器，
//使用spin lock的进程(简称"焦点进程"好了)运行在处理器A上，
//一种很明显的情形就是如果有个进程（简称“睡眠进程”好了）
//先于焦点运行，但是因为等待网卡的一个数据包，它进入了sleep状态，
//然后焦点开始被调度运行，后者在spin lock获得锁后进入临界区，
//此时网卡收到了"睡眠进程“的数据包，因为焦点只是关闭了A上
//的中断，所以B还是会接收并处理该中断，然后唤醒“睡眠进程“，
//后者进入运行队列，此时出现一个调度点，如果”睡眠“的优先级高于”焦点“，
//那么就有进程切换发生了，但是如果焦点所使用的spin lock中关闭
//了内核抢占，那么就使得先前的进程切换成为不可能。
//     如果是在单处理器系统上，local_irq_disable实际上关闭了所有
//（其实就一个）处理器的中断，所有有中断引起的调度点
//都不可能存在，此时有无其他与中断无关的调度点出现呢？
//在2.4上，因为没有抢占，这种情形绝无可能，事实上，早期
//的内核很大程度上是依赖local_irq_disable来做资源保护，这个看
//看2.4的内核源码就很清楚了，里面有大量的对local_irq_disable
//函数的直接调用。 
//     2.6有了抢占的概念，local_irq_save等函数只是禁止了本地中断，
//即当前CPU上的中断。在单核CPU上，当然抢占就不可能发生了，
//但是在多核CPU上由于其他核上的中断并没有被禁止，
//是仍然可能发生抢占的，但本CPU内不会被抢占。UP下关闭中断，
//如前所述，实际上已经杜绝了内部因素导致的“就绪队列中
//加入一个进程”这个调度点的可能
///（内部因素实际上只剩下了一个处理器的异常，
//但是关中断的情形下，即便有异常也不会导致进程的切换），
//因此到这里我们可以这样说，在UP上关闭中断情形下，
//preempt_disable其实是多余的。但是我们知道，spin lock是一种内核API，
//不只是kernel的开发者在用，更多的内核模块
//(.ko，实际当中更多地表现形式是设备驱动程序)开发者也在使用。
//内核的设计者总是试图将其不能控的代码（所谓的外部因素了）
//可能给内核带来的损失降低至最小的程度，这个表现在内核
//对中断处理框架的设计时尤其明显，所以在UP系统下先后
//使用local_disable_irq和preempt_disable，只是尽量让你我可能在
//spin lock/unlock的临界区中某些混了头的代码不至于给系统带来灾难，
//因为难保某些人不会在spin lock的临界区中,比如去wake_up_interruptible（）
//一个进程，而被唤醒的进程在可抢占的系统里就是一个打开
//的潘多拉盒子。
static inline void __raw_spin_lock_irq(raw_spinlock_t *lock)
{
	local_irq_disable();
	preempt_disable();
	spin_acquire(&lock->dep_map, 0, 0, _RET_IP_);
	LOCK_CONTENDED(lock, do_raw_spin_trylock, do_raw_spin_lock);
}

static inline void __raw_spin_lock_bh(raw_spinlock_t *lock)
{
	__local_bh_disable_ip(_RET_IP_, SOFTIRQ_LOCK_OFFSET);
	spin_acquire(&lock->dep_map, 0, 0, _RET_IP_);
	LOCK_CONTENDED(lock, do_raw_spin_trylock, do_raw_spin_lock);
}

static inline void __raw_spin_lock(raw_spinlock_t *lock)
{
	preempt_disable();
	spin_acquire(&lock->dep_map, 0, 0, _RET_IP_);
	LOCK_CONTENDED(lock, do_raw_spin_trylock, do_raw_spin_lock);
}

#endif /* !CONFIG_GENERIC_LOCKBREAK || CONFIG_DEBUG_LOCK_ALLOC */

static inline void __raw_spin_unlock(raw_spinlock_t *lock)
{
	spin_release(&lock->dep_map, 1, _RET_IP_);
	do_raw_spin_unlock(lock);
	preempt_enable();
}

static inline void __raw_spin_unlock_irqrestore(raw_spinlock_t *lock,
					    unsigned long flags)
{
	spin_release(&lock->dep_map, 1, _RET_IP_);
	do_raw_spin_unlock(lock);
	local_irq_restore(flags);
	preempt_enable();
}

static inline void __raw_spin_unlock_irq(raw_spinlock_t *lock)
{
	spin_release(&lock->dep_map, 1, _RET_IP_);
	do_raw_spin_unlock(lock);
	local_irq_enable();
	preempt_enable();
}

static inline void __raw_spin_unlock_bh(raw_spinlock_t *lock)
{
	spin_release(&lock->dep_map, 1, _RET_IP_);
	do_raw_spin_unlock(lock);
	__local_bh_enable_ip(_RET_IP_, SOFTIRQ_LOCK_OFFSET);
}

static inline int __raw_spin_trylock_bh(raw_spinlock_t *lock)
{
	__local_bh_disable_ip(_RET_IP_, SOFTIRQ_LOCK_OFFSET);
	if (do_raw_spin_trylock(lock)) {
		spin_acquire(&lock->dep_map, 0, 1, _RET_IP_);
		return 1;
	}
	__local_bh_enable_ip(_RET_IP_, SOFTIRQ_LOCK_OFFSET);
	return 0;
}

#include <linux/rwlock_api_smp.h>

#endif /* __LINUX_SPINLOCK_API_SMP_H */
