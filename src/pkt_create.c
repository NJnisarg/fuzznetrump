#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ip.h>

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
    printf("Src Address: %x\n", iphdr->ip_src);
    printf("Dst Address: %x\n", iphdr->ip_dst);
    printf("Extra data: %s\n", (char *)&iphdr->ip_dst + sizeof(iphdr->ip_dst));

    printf("========================================\n");

}

static uint16_t
in_cksum(const void *data, size_t len)
{
        const uint16_t *buf = data;
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
pkt_create_ipv4(void *randBuf, size_t bufLen)
{
    union ipv4Pkt{
        char buf[bufLen];
        struct ip iphdr;
    } pkt;

    // Copy the random buffer to the pkt's buf
    memcpy(&pkt.buf, randBuf, bufLen);

    // Next modify the fields of ip header
    struct ip *iphdr = &pkt.iphdr;
    iphdr->ip_v = IPVERSION;

    int hlen = sizeof(struct ip); // Setting the hlen to baseline 20 bytes ip header size
    iphdr->ip_hl = hlen >> 2; // Setting the field as a 32bit word values

    iphdr->ip_len = bufLen; // In bytes
    iphdr->ip_sum = in_cksum(iphdr, hlen); // Calculate the correct checksum of IP Header

    inet_pton(AF_INET, "192.168.0.1", &iphdr->ip_dst); // Setting localhost as dst address so that we dont get error in sendto

    // Print the packet structure
    print_ipv4Pkt(iphdr);

    // Copy back the modified pkt.buf to randBuf
    memcpy(randBuf, &pkt.buf, bufLen);

    return 0;
}

#if 0
int
main()
{
    int bufLen = 30; // Bytes;
    char randBuf[bufLen];
    memcpy(randBuf, "abcdefghijklmnopqrstuvwxyzabcd", bufLen);

    pkt_create_ipv4(randBuf, bufLen);
}
#endif