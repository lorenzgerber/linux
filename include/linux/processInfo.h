#ifndef _LINUX_PROCESSINFO_H
#define _LINUX_PROCESSINFO_H

asmlinkage long sys_processInfo(int* buf, int size);

int bitmaskSum(int bitmask);


#endif /* _LINUX_PROCESSINFO_H */
