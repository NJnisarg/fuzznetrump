#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "extern.h"

#define IP_HDR_SIZE sizeof(struct ip)


static void
print_ipv4Pkt(const struct ip *iphdr){
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
    printf("Src Address: %#.8x\n", ntohl(iphdr->ip_src.s_addr));
    printf("Dst Address: %#.8x\n", ntohl(iphdr->ip_dst.s_addr));

    printf("Extra data: %s\n",
	(const char *)&iphdr->ip_dst + sizeof(iphdr->ip_dst));

    printf("========================================\n");

}

static void print_udpPkt(const struct udphdr *udp)
{
    printf("========================================\n");

    printf("Source Port: %d\n", udp->uh_sport);
    printf("Dest Port: %d\n", udp->uh_dport);
    printf("Len: %d\n", udp->uh_ulen);
    printf("Checksum: %d\n", udp->uh_sum);

    printf("Extra data: %s\n",
	(const char *)&udp->uh_sum + sizeof(udp->uh_sum));

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
                sum += *(const uint8_t *)buf;

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);

        return (uint16_t)~sum;
}

int
pkt_create_ipv4(void *buf, size_t buflen, const struct sockaddr_in *src,
    const struct sockaddr_in *dst)
{
	struct ip *iphdr = buf;
	if (buflen < sizeof(struct ip)) {
		errno = ENOSPC;
		return -1;
	}

	iphdr->ip_v = IPVERSION;

	// Setting the hlen to baseline 20 bytes ip header size
	size_t hlen = sizeof(struct ip);
	// Setting the field as a 32bit word values
	iphdr->ip_hl = (hlen >> 2) & 0xf;

	iphdr->ip_len = (uint16_t)buflen; // In bytes

	iphdr->ip_dst = dst->sin_addr;
	iphdr->ip_src = src->sin_addr;

    // Making things right
    iphdr->ip_tos = 0;
    iphdr->ip_p = 17;
    iphdr->ip_ttl = 64;
    iphdr->ip_off = 0;
    iphdr->ip_id = htons(0);

    // Calculate the correct checksum of IP Header
    iphdr->ip_sum = in_cksum(iphdr, sizeof(struct ip));

	// Print the packet structure
	print_ipv4Pkt(iphdr);

	return 0;
}

int
pkt_create_udp4(void *buf, size_t buflen, const struct sockaddr_in *src,
    const struct sockaddr_in *dst)
{
    int rv = pkt_create_ipv4(buf, buflen, src, dst);
    if(rv == -1)
    {
        errno = ENOSPC;
		return rv;
    }

    // We will set only the checksum to zero. Other fields we will let be random
    struct udphdr *udp = (struct udphdr *)(buf + IP_HDR_SIZE);
    udp->uh_sum = 0; // If we set this to zero the checksum is made optional and will be ignored

    print_udpPkt(udp);

    return 0;
}
