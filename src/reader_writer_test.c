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

#define DEVICE "/dev/tun0"
#define CLIENT_ADDR "192.168.0.5"
#define SERVER_ADDR "192.168.0.1"
#define NETMASK "255.255.255.0"

static int
makeaddr(struct sockaddr_in *addr, const char *name)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	addr->sin_len = sizeof(*addr);
	if (inet_pton(AF_INET, name, &addr->sin_addr) < 0)  { 
		warnx("Invalid address/Address not supported"); 
		return -1;
	}
	return 0;
}


int main()
{
    int sock;
	struct sockaddr_in client_addr, server_addr, netmask;
	int rv = EXIT_FAILURE;

	// Creating the packet here
	int bufLen = 30; // Bytes;
    unsigned char randBuf[bufLen];
    memcpy(&randBuf, "abcdefghijklmnopqrstuvwxyzabcd", bufLen);
	printf("Length of original Data: %d\n", bufLen);
	printf("Original Data:\n");
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

	printf("Amount of data read:%d\n", red);

	// Reading the IP packet
	struct ip *iphdr = (struct ip*)(readBuf);
	printf("IP Version: %d\n", iphdr->ip_v);

	// Swapping the IP Src and Dest before writing packet on the wire
	iphdr->ip_dst = client_addr.sin_addr;
	iphdr->ip_src = server_addr.sin_addr;

	// Writing the packet on the wire of tun Device
	written = rump_sys_write(tunfd, readBuf, red);
	printf("Written: %d\n", written);

	// Receiving from the socket
	memset(randBuf, 0, bufLen);
	red = rump_sys_recvfrom(sock, randBuf, bufLen, 0, NULL, NULL);
	if (red == -1) {
		warn("recvfrom failed");
		goto out;
	}
	printf("Amount of data read from socket: %d\n", red);
	printf("Data read from socket:\n");
	for(int i=0;i<red;i++)
		printf("%c", randBuf[i]);

	rv = EXIT_SUCCESS;
out:
	// Close and return
	rump_sys_close(tunfd);
	rump_sys_close(sock);
	return rv;

    // After that we will read the echoed value sent as a reply from the socket
}