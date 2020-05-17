#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include<netinet/in.h>
#include<netinet/ip.h>

#include"pkt_create.h"

void
print_ipv4Pkt(struct ip *iphdr){
    printf("========================================\n");

    printf("Header Len: %d\n", iphdr->ip_hl);
    printf("Version: %d\n", iphdr->ip_v);
    printf("TOS: %d\n", iphdr->ip_tos);
    printf("Pkt Len: %d\n", iphdr->ip_len);
    printf("ID: %d\n", iphdr->ip_id);
    printf("Offset: %d\n", iphdr->ip_off);
    printf("TTL: %d\n", iphdr->ip_ttl);
    printf("Protocol: %d\n", iphdr->ip_p);
    printf("Checksum: %d\n", iphdr->ip_sum);
    printf("Src Address: %d\n", iphdr->ip_src);
    printf("Dst Address: %d\n", iphdr->ip_dst);
    printf("Extra data: %s\n", (char *)&iphdr->ip_dst + sizeof(iphdr->ip_dst));

    printf("========================================\n");

}

static uint16_t
in_cksum(void *data, size_t len)
{
        uint16_t *buf = data;
        unsigned sum;

        for (sum = 0; len > 1; len -= 2)
                sum += *buf++;
        if (len)
                sum += *(uint8_t *)buf;

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);

        return ~sum;
}

int
pkt_create_ipv4(char *randBuf, int bufSize)
{
    union ipv4Pkt{
        char buf[bufSize];
        struct ip iphdr;
    } pkt;

    // Copy the random buffer to the pkt's buf
    memcpy(&pkt.buf, randBuf, bufSize);

    // Next modify the fields of ip header
    struct ip *iphdr = &pkt.iphdr;
    iphdr->ip_v = IPVERSION;

    int hlen = sizeof(struct ip); // Setting the hlen to baseline 20 bytes ip header size
    iphdr->ip_hl = hlen >> 2; // Setting the field as a 32bit word values

    iphdr->ip_len = bufSize; // In bytes
    iphdr->ip_sum = in_cksum(iphdr, hlen); // Calculate the correct checksum of IP Header

    // Print the packet structure
    print_ipv4Pkt(iphdr);

    // Copy back the modified pkt.buf to randBuf
    memcpy(randBuf, &pkt.buf, bufSize);

    return 0;
}

// int
// main()
// {
//     int bufSize = 30; // Bytes;
//     char randBuf[bufSize];
//     memcpy(&randBuf, "abcdefghijklmnopqrstuvwxyzabcd", bufSize);

//     pkt_create_ipv4(randBuf, bufSize);
// }