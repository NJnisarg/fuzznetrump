/**
 * To compile this file:
 * gcc pkt_create.c net_config.c reader_writer_test.c -lrump -lrumpvfs -lrumpnet -lrumpnet_net -lrumpnet_netinet -lrumpnet_tun
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

static unsigned char randBuf[] = "abcdefghijklmnopqrstuvwxyzabc";

#define DEVICE "/dev/tun0"
#define CLIENT_ADDR "192.168.0.5"
#define SERVER_ADDR "192.168.0.1"
#define NETMASK "255.255.255.0"

int 
main(void)
{
    int sock;
	struct sockaddr_in client_addr, server_addr, netmask;
	int rv = EXIT_FAILURE;

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

	// Setting up the tun device
	int tunfd = netcfg_rump_if_tun(DEVICE, &client_addr, &server_addr,
	    &netmask);
	if (tunfd == -1)
		return rv;

	// Creating the socket
	if ((sock = rump_sys_socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
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

	// if (pkt_create_ipv4(randBuf, sizeof(randBuf), &server_addr,
	//     &client_addr) == -1)
	// {
	// 	warn("Can't create packet");
	// 	goto out;
	// }

	// Setting the header included flag for RAW IP to not touch the
	// IP header
	// int one = 1;
	// if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one,
	//     sizeof(one)) == -1)
	// {
	//     warn("Cannot set HDRINCL!");
	//     goto out;
	// }

	// Sending down the socket
	ssize_t written = rump_sys_sendto(sock, randBuf, sizeof(randBuf), 0, 
	    (struct sockaddr *) &server_addr, sizeof(server_addr));
	if (written == -1) {
		warn("sendto failed");
		goto out;
	}

	if ((size_t)written != sizeof(randBuf)) {
		warnx("Incomplete write: %zd != %zu", written, sizeof(randBuf));
		goto out;
	}

	printf("All data written\n");

	// Reading from the Data sent down the socket
	unsigned char readBuf[100];
	ssize_t red = rump_sys_read(tunfd, readBuf, 100); // Intentionally spelled as red for past tense of read.
	if(red == -1)
	{
		warn("read failed");
		goto out;
	}

	printf("Amount of data read:%ld\n", red);

	// Reading the IP packet
	struct ip *iphdr = (struct ip*)(readBuf);
	printf("IP Version: %d\n", iphdr->ip_v);

	// Swapping the IP Src and Dest before writing packet on the wire
	iphdr->ip_dst = client_addr.sin_addr;
	iphdr->ip_src = server_addr.sin_addr;

	// Writing the packet on the wire of tun Device
	written = rump_sys_write(tunfd, readBuf, (size_t)red);
	printf("Written: %ld\n", written);

	// Receiving from the socket
	memset(randBuf, 0, sizeof(randBuf));
	red = rump_sys_recvfrom(sock, randBuf, sizeof(randBuf), 0, NULL, NULL);
	if (red == -1) {
		warn("recvfrom failed");
		goto out;
	}
	printf("Amount of data read from socket: %ld\n", red);
	printf("Data read from socket:\n");
	for(int i=0;i<red;i++)
		printf("%c", randBuf[i]);
	printf("\n");

	rv = EXIT_SUCCESS;
out:
	// Close and return
	rump_sys_close(tunfd);
	rump_sys_close(sock);
	return rv;
}