/**
 * To compile this file:
 * 
 * ASAN_OPTIONS=detect_container_overflow=0 clang -fsanitize=address 
 * pkt_create.c net_config.c icmp_input_fuzz.c 
 * -lrump -lrumpvfs -lrumpvfs_nofifofs -lrumpnet -lrumpnet_net -lrumpnet_netinet -lrumpnet_tun -g
 * 
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

#include "../include/net_config.h"
#include "../include/pkt_create.h"

static const unsigned char randBuf[] = "abcdefghijklmnopqrstuvwxyzabcabcdefghijklmnopqrstuvwxyzabc";

#define CLIENT_ADDR "127.0.0.1"
#define SERVER_ADDR "127.0.0.1"
#define NETMASK "255.0.0.0"

int 
main(void)
{

	struct sockaddr_in client_addr, server_addr, netmask;
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
	if (makeaddr(&client_addr, CLIENT_ADDR) == -1)
		return rv;
	if (makeaddr(&server_addr, SERVER_ADDR) == -1)
		return rv;
	if (makeaddr(&netmask, NETMASK) == -1)
		return rv;
	
	memcpy(packet, randBuf, sizeof(randBuf));

	if (pkt_create_icmp4(packet, sizeof(packet), &server_addr,
	    &client_addr) == -1)
	{
		warn("Can't create packet");
		goto out;
	}

	// Call the fuzzer function inside rump
	rump_schedule();
    rumpns_fuzzrump_icmp_input((char *)packet, sizeof(packet));
	rump_unschedule();

	rv = EXIT_SUCCESS;
	return rv;
}
