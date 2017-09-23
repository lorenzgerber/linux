/*
 * keystore.c 
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

/*
 * keystore_init - the init function, called when the module is loaded.
 * Returns zero if successfully loaded, nonzero otherwise.
 */
static int keystore_init(void){

  printk(KERN_ALERT "I bear a charmed life.\n");
  return 0;

}


/*
 * keystore_exit - the exit function, called when the module is removed.
 */
static void keystore_exit(void){

  printk(KERN_ALERT "Out, out, brief candle!\n");

}

module_init(hello_init);
module_init(hello_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lorenz Gerber");
MODULE_DESCRIPTION("A keystore module");
