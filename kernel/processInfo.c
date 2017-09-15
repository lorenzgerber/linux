#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/sched.h>
#include<linux/syscalls.h>
#include<linux/fdtable.h>
#include <linux/processInfo.h>
#include <linux/signal.h>

asmlinkage long sys_processInfo(void) {

    struct task_struct *proces;
    int processes = 0;
    int fd = 0;
    int pending = 0;
    int bitmask;

    printk("My user Id: %ld\n", sys_getuid());

    for_each_process(proces) {
 	
		if(__kuid_val(task_uid(proces)) == (uid_t)sys_getuid()){
			//pending = pending + proces->signal->sigcnt.counter;
			fd = fd + proces->files->count.counter;
			processes++;
			bitmask = *proces->pending.signal.sig;


			while (bitmask > 0) {           // until all bits are zero
				if ((bitmask & 1) == 1)     // check lower bit
					pending++;
				bitmask >>= 1;              // shift bits, removing lower bit
			}

		}

	}
	
    printk("\nThe current user has:\n%d processes running\n%d filedescriptors watched\n%d signals pendning\n", processes, fd, pending);
	   
  
   
  
  
  
  return 0;
}


/*unsigned int bitCount (unsigned long value) {
    unsigned int count = 0;
    while (value > 0) {           // until all bits are zero
        if ((value & 1) == 1)     // check lower bit
            count++;
        value >>= 1;              // shift bits, removing lower bit
    }
    return count;
}*/

