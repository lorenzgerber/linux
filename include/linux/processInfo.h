#ifndef _LINUX_PROCESSINFO_H
#define _LINUX_PROCESSINFO_H


asmlinkage long sys_processInfo(int* procs, int* fds, int* sigpends);

int bitmaskSum(int bitmask);


#endif /* _LINUX_PROCESSINFO_H */
