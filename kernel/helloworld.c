#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/helloworld.h>

SYSCALL_DEFINE0(helloworld)
{
  printk("helloworld\n");
  return 0;
}
