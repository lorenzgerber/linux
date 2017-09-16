#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/fdtable.h>
#include <linux/processInfo.h>
#include <linux/signal.h>

SYSCALL_DEFINE2(processInfo, int*, buf, int, size) {

    struct task_struct *proces;
    int processes = 0;
    int fd = 0;
    int pending = 0;
    int bitmaskShared;
    int bitmaskPrivate;


    int buffers_in_kernel[size];
	//int *user_pointers[size];
	//int i;
	//unsigned long res;


    for_each_process(proces) {
 	
		if(__kuid_val(task_uid(proces)) == (uid_t)sys_getuid()){

			fd = fd + *proces->files->fdtab.open_fds;
			processes++;
			bitmaskShared = *proces->signal->shared_pending.signal.sig;
			bitmaskPrivate = *proces->pending.signal.sig;

			pending = pending + bitmaskSum(bitmaskShared);
			pending = pending + bitmaskSum(bitmaskPrivate);

		}

	}

    buffers_in_kernel[0] = processes;
    buffers_in_kernel[1] = fd;
    buffers_in_kernel[2] = pending;
    /*
    res = copy_from_user(user_pointers, buf, sizeof(user_pointers[size]));

	for (i = 0; i < size; i++) {
		 res = copy_to_user(user_pointers[i], &buffers_in_kernel[i], sizeof(int));
	}*/
	
    printk("\nThe current user has:\n%d processes running\n%d filedescriptors watched\n%d signals pendning\n", processes, fd, pending);
	   
  return 0;
}

int bitmaskSum(int bitmask){
	int sum = 0;

	while (bitmask > 0) {
		if ((bitmask & 1) == 1)
			sum++;
		bitmask >>= 1;
	}

	return sum;
}


