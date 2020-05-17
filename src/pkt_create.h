#include<netinet/in.h>
#include<netinet/ip.h>

// Debug function to print the packet
void print_ipv4Pkt(struct ip *iphdr);

// Checksum calculating algorithm
static uint16_t in_cksum(void *data, size_t len);

// Function to create an ipv4 packet from a rand data buffer
int pkt_create_ipv4(char *randBuf, int bufSize);