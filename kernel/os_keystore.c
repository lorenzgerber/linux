
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lorenz Gerber");
MODULE_DESCRIPTION("A keystore module");

static int __init os_keystore_init(void){

  printk(KERN_INFO "I bear a charmed life.\n");
  return 0;

}

static void __exit os_keystore_exit(void){

  printk(KERN_INFO "Out, out, brief candle!\n");

}

module_init(os_keystore_init);
module_exit(os_keystore_exit);

