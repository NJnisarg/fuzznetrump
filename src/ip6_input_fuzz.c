/**
 * To compile this file:
 * gcc pkt_create.c net_config.c ip_input_fuzz.c -lrump -lrumpvfs -lrumpnet -lrumpnet_net -lrumpnet_netinet -lrumpnet_tun
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ip.h>

#include <rump/rump.h>
#include <rump/rump_syscalls.h>

#include "extern.h"

static const unsigned char randBuf[] = "abcdefghijklmnopqrstuvwxyzabcabcdefghijklmnopqrstuvwxyzabcabcdefghijklmnopqrstuvwxyzabcabcdefghijklmnopqrstuvwxyzabcabcdefghijklmnopqrstuvwxyzabcabcdefghijklmnopqrstuvwxyzabcabcdefghijklmnopqrstuvwxyzabcabcdefghijklmnopqrstuvwxyzabcabcdefghijklmnopqrstuvwxyzabcabcdefghijklmnopqrstuvwxyzabcabcdefghijklmnopqrstuvwxyzabc";

#define DEVICE "/dev/tun0"
#define CLIENT_ADDR "2001:db8::1234"
#define SERVER_ADDR "2001:db8::1235"
#define PREFIX_MASK "ffff:ffff:ffff:ffff:0000:0000:0000:0000"
int 
main(void)
{

	struct sockaddr_in6 client_addr, server_addr, prefix_mask;
	int rv = EXIT_FAILURE;
	unsigned char packet[sizeof(randBuf)];

	// Creating the packet here
	printf("Length of original Data: %ld\n", sizeof(randBuf));
	printf("Original Data:\n");
	int bufLen = sizeof(randBuf);
	for(int i=0;i<bufLen;i++)
		printf("%c", randBuf[i]);
	printf("\n");

	// We initialize rump
	rump_init();

	// Setting socket addresses for using with ip src and dest
	if (makeaddr6(&client_addr, CLIENT_ADDR) == -1)
		return rv;
	if (makeaddr6(&server_addr, SERVER_ADDR) == -1)
		return rv;
	if (makeaddr6(&prefix_mask, PREFIX_MASK) == -1)
		return rv;

	// Setting up the tun device
	int tunfd = netcfg_rump_if_tun6(DEVICE, &client_addr, &server_addr, &prefix_mask);
	if (tunfd == -1)
		return rv;
	
	memcpy(packet, randBuf, sizeof(randBuf));

	if (pkt_create_ipv6(packet, sizeof(packet), &server_addr,
	    &client_addr) == -1)
	{
		warn("Can't create packet");
		goto out;
	}

	ssize_t written = rump_sys_write(tunfd, randBuf, sizeof(randBuf));
	printf("Written: %ld\n", written);

	rv = EXIT_SUCCESS;

out:
	rump_sys_close(tunfd);
	return rv;
}
