#include <linux/kernel.h>
#include <linux/syscalls.h>

SYSCALL_DEFINE0(helloworld)
{
  printk("helloworld\n");
  return 0;
}
