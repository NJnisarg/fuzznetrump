#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include "extern.h"

#define IP_HDR_SIZE sizeof(struct ip)

#define NUM_CODE_UNREACH 16
#define NUM_CODE_REDIRECT 4
#define NUM_CODE_ROUTERADVERT 2
#define NUM_CODE_TIMXCEED 2
#define NUM_CODE_PARAMPROB 3
#define NUM_CODE_PHOTURIS 6


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

    /* printf("Extra data: %s\n",
	(const char *)&iphdr->ip_dst + sizeof(iphdr->ip_dst)); */

    printf("========================================\n");

}

static void 
print_udpPkt(const struct udphdr *udp)
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

static void 
print_icmpPkt(const struct icmp *icp)
{
    printf("========================================\n");

    printf("ICMP Type: %d\n", icp->icmp_type);
    printf("ICMP Type: %d\n", icp->icmp_code);
    printf("ICMP Type: %d\n", icp->icmp_cksum);
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

uint8_t
getRandType(uint8_t type)
{
    // Return one of the ICMP types from 0 to 40
    return (type % ICMP_NTYPES);
}

uint8_t
getRandCode(uint8_t type, uint8_t code)
{
    uint8_t retCode = 0;
    switch(type){
        case ICMP_UNREACH:
            retCode = code % NUM_CODE_UNREACH;
            break;

        case ICMP_REDIRECT:
            retCode = code % NUM_CODE_REDIRECT;
            break;
        
        case ICMP_ROUTERADVERT:
            retCode = code % NUM_CODE_ROUTERADVERT;
            retCode *= 16; // 0 or 16 expected
            break;
        
        case ICMP_TIMXCEED:
            retCode = code % NUM_CODE_TIMXCEED;
            break;

        case ICMP_PARAMPROB:
            retCode = code % NUM_CODE_PARAMPROB;
            break;

        case ICMP_PHOTURIS:
            retCode = code % NUM_CODE_PHOTURIS;
            break;
        
        default:
            retCode = 0;
            break;
    }

    return retCode;
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
    iphdr->ip_sum = in_cksum(iphdr, IP_HDR_SIZE);

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

int 
pkt_create_icmp4(void *buf, size_t buflen, const struct sockaddr_in *src,
    const struct sockaddr_in *dst)
{
    int rv = pkt_create_ipv4(buf, buflen, src, dst);
    if(rv == -1)
    {
        errno = ENOSPC;
		return rv;
    }

    struct icmp *icp = (struct icmp *)(buf + IP_HDR_SIZE);
    icp->icmp_cksum = in_cksum(icp, buflen - IP_HDR_SIZE); // Checksum for the entire ICMP packet
    icp->icmp_type = getRandType(icp->icmp_type);
    icp->icmp_code = getRandCode(icp->icmp_type, icp->icmp_code);

    print_icmpPkt(icp);

    return 0;
}
