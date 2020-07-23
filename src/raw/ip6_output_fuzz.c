/**
 * To compile this file:
 * gcc pkt_create.c net_config.c ip_output_fuzz.c -lrump -lrumpvfs -lrumpnet -lrumpnet_net -lrumpnet_netinet -lrumpnet_tun
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

static const unsigned char randBuf[] = "abcdefghijklmnopqrstuvwxyzabcd";

#define DEVICE "/dev/tun0"
#define CLIENT_ADDR "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
#define SERVER_ADDR "2001:0db8:85a3:0000:0000:8a2e:0370:7335"

int
main(void)
{
	int sock;
	struct sockaddr_in6 client_addr, server_addr;
	int rv = EXIT_FAILURE;
	unsigned char packet[sizeof(randBuf)];

	// We initialize rump
	rump_init();


	// Setting socket addresses for using with ip src and dest
	if (makeaddr(&client_addr, CLIENT_ADDR) == -1)
		return rv;
	if (makeaddr(&server_addr, SERVER_ADDR) == -1)
		return rv;

	// Setting up the tun device
	int tunfd = netcfg_rump_if_tun6(DEVICE, &client_addr, &server_addr);
	if (tunfd == -1)
		return rv;

	// Creating the socket
	if ((sock = rump_sys_socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)) == -1) {
		warn("Can't open raw socket");
		rump_sys_close(tunfd);
		return rv;
	}
	
      
	// Binding newly created socket to given IP and verification 
	if ((rump_sys_bind(sock, (const struct sockaddr *)&client_addr,
	    sizeof(client_addr))) == -1)
	{ 
		warn("Can't bind socket"); 
		goto out;
	}

	// packet holds the final packet
	// copy the payload
	memcpy(packet, randBuf, sizeof(randBuf));

	if (pkt_create_ipv6(packet, sizeof(packet), &client_addr,
	    &server_addr) == -1)
	{
		warn("Can't create packet");
		goto out;
	}

	// Setting the header included flag for RAW IP to not touch the
	// IP header
	int one = 1;
	if (rump_sys_setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one,
	    sizeof(one)) == -1)
	{
	    warn("Cannot set HDRINCL!");
	    goto out;
	}

	// Sending down the socket
	ssize_t written = rump_sys_sendto(sock, packet, sizeof(packet), 0, 
	    (struct sockaddr *) &server_addr, sizeof(server_addr));
	if (written == -1) {
		warn("sendto failed");
		goto out;
	}

	if ((size_t)written != sizeof(packet)) {
		warnx("Incomplete write: %zd != %zu", written, sizeof(packet));
		goto out;
	}

	printf("All data written\n");

	rv = EXIT_SUCCESS;
out:
	// Close and return
	rump_sys_close(tunfd);
	rump_sys_close(sock);
	return rv;
}
