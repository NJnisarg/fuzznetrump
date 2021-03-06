/**
 * To compile this file:
 * 
 * ASAN_OPTIONS=detect_container_overflow=0 hfuzz-clang -fsanitize=address 
 * pkt_create.c net_config.c hfuzz_ip_output_fuzz.c 
 * -lrump -lrumpvfs -lrumpvfs_nofifofs -lrumpnet -lrumpnet_net -lrumpnet_netinet -lrumpnet_tun -g
 * 
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ip.h>

#include <rump/rump.h>
#include <rump/rump_syscalls.h>

#include "../include/net_config.h"
#include "../include/pkt_create.h"

#define DEVICE "/dev/tun0"
#define CLIENT_ADDR "192.168.0.5"
#define SERVER_ADDR "192.168.0.1"
#define NETMASK "255.255.255.0"

/* Global vars */
int tunfd, sock;
struct sockaddr_in client_addr, server_addr, netmask;

/* entry point for library fuzzers (libFuzzer/honggfuzz) */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);


static int
ip_output_fuzz(const uint8_t *randBuf, size_t bufLen)
{
    int rv = -1;
    // Preparing the IP packet
    unsigned char packet[bufLen];
    memcpy(packet, randBuf, bufLen);

	if (pkt_create_ipv4(packet, sizeof(packet), &client_addr,
	    &server_addr, 0, 0) == -1)
	{
		warn("Can't create packet");
		return rv;
	}

    // Sending down the socket
    ssize_t written = rump_sys_sendto(sock , packet , bufLen , 0, (struct sockaddr *) &server_addr, sizeof (server_addr));
    if (written == -1) {
		warn("sendto failed");
		return rv;
	}

	if ((size_t)written != sizeof(packet)) {
		warnx("Incomplete write: %zd != %zu", written, sizeof(packet));
		return rv;
	}

    rv = 0;
    return rv;
}

/* Initialize rumpkernel and network setup only once. */
static
void Initialize()
{
	// We initialize rump
    if(rump_init() == -1)
        __builtin_trap();

	// Setting socket addresses for using with ip src and dest
	if (makeaddr(&client_addr, CLIENT_ADDR) == -1)
		__builtin_trap();
	if (makeaddr(&server_addr, SERVER_ADDR) == -1)
		__builtin_trap();
	if (makeaddr(&netmask, NETMASK) == -1)
		__builtin_trap();

	// Setting up the tun device
	int tunfd = netcfg_rump_if_tun(DEVICE, &client_addr, &server_addr,
	    &netmask);
	if (tunfd == -1)
		__builtin_trap();

	// Creating the socket
	if ((sock = rump_sys_socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
		warn("Can't open raw socket");
		rump_sys_close(tunfd);
		__builtin_trap();
	}
	
	// Binding newly created socket to given IP and verification 
	if ((rump_sys_bind(sock, (const struct sockaddr *)&client_addr,
	    sizeof(client_addr))) == -1)
	{ 
		warn("Can't bind socket"); 
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

    return;

out:
    rump_sys_close(tunfd);
    rump_sys_close(sock);
    __builtin_trap();
}

int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	static bool Initialized;

	if (!Initialized) {
		Initialize();
		Initialized = true;
	}

	if (ip_output_fuzz(Data, Size)) {
		/**
		 * We shall return 0 on error paths as otherwise
		 * a fuzzer (honggfuzz) restarts the fuzzing process 
		 * and restarting the program costs time.
		 */
		return 0;
	}

	return 0;
}