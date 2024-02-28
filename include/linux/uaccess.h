#ifndef __LINUX_UACCESS_H__
#define __LINUX_UACCESS_H__

#include <linux/preempt.h>
#include <asm/uaccess.h>

/*
 * These routines enable/disable the pagefault handler in that
 * it will not take any locks and go straight to the fixup table.
 *
 * They have great resemblance to the preempt_disable/enable calls
 * and in fact they are identical; this is because currently there is
 * no other way to make the pagefault handlers do this. So we do
 * disable preemption but we don't necessarily care about that.
 */
static inline void pagefault_disable(void)
{
	preempt_count_inc();
	/*
	 * make sure to have issued the store before a pagefault
	 * can hit.
	 */
	barrier();
}

static inline void pagefault_enable(void)
{
#ifndef CONFIG_PREEMPT
	/*
	 * make sure to issue those last loads/stores before enabling
	 * the pagefault handler again.
	 */
	barrier();
	preempt_count_dec();
#else
	preempt_enable();
#endif
}

#ifndef ARCH_HAS_NOCACHE_UACCESS

static inline unsigned long __copy_from_user_inatomic_nocache(void *to,
				const void __user *from, unsigned long n)
{
	return __copy_from_user_inatomic(to, from, n);
}

static inline unsigned long __copy_from_user_nocache(void *to,
				const void __user *from, unsigned long n)
{
	return __copy_from_user(to, from, n);
}

#endif		/* ARCH_HAS_NOCACHE_UACCESS */

extern __must_check int check_zeroed_user(const void __user *from, size_t size);

/**
 * copy_struct_from_user: copy a struct from userspace
 * @dst:   Destination address, in kernel space. This buffer must be @ksize
 *         bytes long.
 * @ksize: Size of @dst struct.
 * @src:   Source address, in userspace.
 * @usize: (Alleged) size of @src struct.
 *
 * Copies a struct from userspace to kernel space, in a way that guarantees
 * backwards-compatibility for struct syscall arguments (as long as future
 * struct extensions are made such that all new fields are *appended* to the
 * old struct, and zeroed-out new fields have the same meaning as the old
 * struct).
 *
 * @ksize is just sizeof(*dst), and @usize should've been passed by userspace.
 * The recommended usage is something like the following:
 *
 *   SYSCALL_DEFINE2(foobar, const struct foo __user *, uarg, size_t, usize)
 *   {
 *      int err;
 *      struct foo karg = {};
 *
 *      if (usize > PAGE_SIZE)
 *        return -E2BIG;
 *      if (usize < FOO_SIZE_VER0)
 *        return -EINVAL;
 *
 *      err = copy_struct_from_user(&karg, sizeof(karg), uarg, usize);
 *      if (err)
 *        return err;
 *
 *      // ...
 *   }
 *
 * There are three cases to consider:
 *  * If @usize == @ksize, then it's copied verbatim.
 *  * If @usize < @ksize, then the userspace has passed an old struct to a
 *    newer kernel. The rest of the trailing bytes in @dst (@ksize - @usize)
 *    are to be zero-filled.
 *  * If @usize > @ksize, then the userspace has passed a new struct to an
 *    older kernel. The trailing bytes unknown to the kernel (@usize - @ksize)
 *    are checked to ensure they are zeroed, otherwise -E2BIG is returned.
 *
 * Returns (in all cases, some data may have been copied):
 *  * -E2BIG:  (@usize > @ksize) and there are non-zero trailing bytes in @src.
 *  * -EFAULT: access to userspace failed.
 */
static __always_inline __must_check int
copy_struct_from_user(void *dst, size_t ksize, const void __user *src,
		      size_t usize)
{
	size_t size = min(ksize, usize);
	size_t rest = max(ksize, usize) - size;

	/* Double check if ksize is larger than a known object size. */
	if (WARN_ON_ONCE(ksize > __builtin_object_size(dst, 1)))
		return -E2BIG;

	/* Deal with trailing bytes. */
	if (usize < ksize) {
		memset(dst + size, 0, rest);
	} else if (usize > ksize) {
		int ret = check_zeroed_user(src + size, rest);
		if (ret <= 0)
			return ret ?: -E2BIG;
	}
	/* Copy the interoperable parts of the struct. */
	if (copy_from_user(dst, src, size))
		return -EFAULT;
	return 0;
}

/**
 * probe_kernel_address(): safely attempt to read from a location
 * @addr: address to read from - its type is type typeof(retval)*
 * @retval: read into this variable
 *
 * Safely read from address @addr into variable @revtal.  If a kernel fault
 * happens, handle that and return -EFAULT.
 * We ensure that the __get_user() is executed in atomic context so that
 * do_page_fault() doesn't attempt to take mmap_sem.  This makes
 * probe_kernel_address() suitable for use within regions where the caller
 * already holds mmap_sem, or other locks which nest inside mmap_sem.
 * This must be a macro because __get_user() needs to know the types of the
 * args.
 *
 * We don't include enough header files to be able to do the set_fs().  We
 * require that the probe_kernel_address() caller will do that.
 */
#define probe_kernel_address(addr, retval)		\
	({						\
		long ret;				\
		mm_segment_t old_fs = get_fs();		\
							\
		set_fs(KERNEL_DS);			\
		pagefault_disable();			\
		ret = __copy_from_user_inatomic(&(retval), (__force typeof(retval) __user *)(addr), sizeof(retval));		\
		pagefault_enable();			\
		set_fs(old_fs);				\
		ret;					\
	})

/*
 * probe_kernel_read(): safely attempt to read from a location
 * @dst: pointer to the buffer that shall take the data
 * @src: address to read from
 * @size: size of the data chunk
 *
 * Safely read from address @src to the buffer at @dst.  If a kernel fault
 * happens, handle that and return -EFAULT.
 */
extern long probe_kernel_read(void *dst, const void *src, size_t size);
extern long __probe_kernel_read(void *dst, const void *src, size_t size);

/*
 * probe_kernel_write(): safely attempt to write to a location
 * @dst: address to write to
 * @src: pointer to the data that shall be written
 * @size: size of the data chunk
 *
 * Safely write to address @dst from the buffer at @src.  If a kernel fault
 * happens, handle that and return -EFAULT.
 */
extern long notrace probe_kernel_write(void *dst, const void *src, size_t size);
extern long notrace __probe_kernel_write(void *dst, const void *src, size_t size);

#ifndef user_access_begin
#define user_access_begin(type,ptr,len) access_ok(type,ptr, len)
#define user_access_end() do { } while (0)
#define unsafe_op_wrap(op, err) do { if (unlikely(op)) goto err; } while (0)
#define unsafe_get_user(x,p,e) unsafe_op_wrap(__get_user(x,p),e)
#define unsafe_put_user(x,p,e) unsafe_op_wrap(__put_user(x,p),e)
#define unsafe_copy_to_user(d,s,l,e) unsafe_op_wrap(__copy_to_user(d,s,l),e)
#define unsafe_copy_from_user(d,s,l,e) unsafe_op_wrap(__copy_from_user(d,s,l),e)
static inline unsigned long user_access_save(void) { return 0UL; }
static inline void user_access_restore(unsigned long flags) { }
#endif
#ifndef user_write_access_begin
#define user_write_access_begin user_access_begin
#define user_write_access_end user_access_end
#endif
#ifndef user_read_access_begin
#define user_read_access_begin user_access_begin
#define user_read_access_end user_access_end
#endif

#endif		/* __LINUX_UACCESS_H__ */
