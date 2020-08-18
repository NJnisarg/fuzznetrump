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

// #include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ip.h>

#include <rump/rump.h>
#include <rump/rump_syscalls.h>

#include "../include/net_config.h"
#include "../include/pkt_create.h"

static const unsigned char randBuf[] = "a";

#define DEVICE "/dev/tun0"
#define CLIENT_ADDR "192.168.0.5"
#define SERVER_ADDR "192.168.0.1"
#define NETMASK "255.255.255.0"

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

	// // Setting socket addresses for using with ip src and dest
	if (makeaddr(&client_addr, CLIENT_ADDR) == -1)
		return rv;
	if (makeaddr(&server_addr, SERVER_ADDR) == -1)
		return rv;
	if (makeaddr(&netmask, NETMASK) == -1)
		return rv;

	// // Setting up the tun device
	int tunfd = netcfg_rump_if_tun(DEVICE, &client_addr, &server_addr,
	    &netmask);
	if (tunfd == -1)
		return rv;
	
	memcpy(packet, randBuf, sizeof(randBuf));

	// if (pkt_create_ipv4(packet, sizeof(packet), &server_addr,
	//     &client_addr) == -1)
	// {
	// 	warn("Can't create packet");
	// 	goto out;
	// }

	packet[0] = (char)0x40;

	rump_schedule();
    rumpns_fuzzrump_ip_input((char *)packet, sizeof(packet));
	rump_unschedule();

	// ssize_t written = rump_sys_write(tunfd, randBuf, sizeof(randBuf));
	// printf("Written: %ld\n", written);

	rv = EXIT_SUCCESS;

out:
	// rump_sys_close(tunfd);
	return rv;
}
