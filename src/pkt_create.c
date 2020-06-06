#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ip.h>

#include "extern.h"

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
	// Calculate the correct checksum of IP Header
	iphdr->ip_dst = dst->sin_addr;
	iphdr->ip_src = src->sin_addr;
	iphdr->ip_sum = in_cksum(iphdr, buflen);

	// Print the packet structure
	print_ipv4Pkt(iphdr);

	return 0;
}
