#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/sched.h>
#include<linux/syscalls.h>
#include<linux/fdtable.h>

#include "processInfo.h"

asmlinkage long sys_processInfo(void) {

    struct task_struct *proces;
    int processes = 0;
    int fd = 0;
    int pending = 0;

    for_each_process(proces) {
 	
	//if(proces->parent->uid == (unsigned short)sys_getuid()){
		pending = pending + proces->signal->sigcnt.counter;
		fd = fd + proces->files->count.counter;
		processes++;
		
	//}
	
	
	
    }
    printk("\nThe current user has:\n%d processes running\n%dfiledescriptors watched\n%dsignals pendning\n", processes, fd, pending);
	   
  
   
  
  
  
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

