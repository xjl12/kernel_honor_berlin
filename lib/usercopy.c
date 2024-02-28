#include <linux/bitops.h>
#include <linux/export.h>
#include <linux/bug.h>
#include <linux/uaccess.h>

void copy_from_user_overflow(void)
{
	WARN(1, "Buffer overflow detected!\n");
}
EXPORT_SYMBOL(copy_from_user_overflow);

/**
 * check_zeroed_user: check if a userspace buffer only contains zero bytes
 * @from: Source address, in userspace.
 * @size: Size of buffer.
 *
 * This is effectively shorthand for "memchr_inv(from, 0, size) == NULL" for
 * userspace addresses (and is more efficient because we don't care where the
 * first non-zero byte is).
 *
 * Returns:
 *  * 0: There were non-zero bytes present in the buffer.
 *  * 1: The buffer was full of zero bytes.
 *  * -EFAULT: access to userspace failed.
 */
int check_zeroed_user(const void __user *from, size_t size)
{
	unsigned long val;
	uintptr_t align = (uintptr_t) from % sizeof(unsigned long);

	if (unlikely(size == 0))
		return 1;

	from -= align;
	size += align;

	if (!user_read_access_begin(uintptr_t, from, size))
		return -EFAULT;

	unsafe_get_user(val, (unsigned long __user *) from, err_fault);
	if (align)
		val &= ~aligned_byte_mask(align);

	while (size > sizeof(unsigned long)) {
		if (unlikely(val))
			goto done;

		from += sizeof(unsigned long);
		size -= sizeof(unsigned long);

		unsafe_get_user(val, (unsigned long __user *) from, err_fault);
	}

	if (size < sizeof(unsigned long))
		val &= aligned_byte_mask(size);

done:
	user_read_access_end();
	return (val == 0);
err_fault:
	user_read_access_end();
	return -EFAULT;
}
EXPORT_SYMBOL(check_zeroed_user);
