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
#define CLIENT_ADDR "2001:db8::1234"
#define SERVER_ADDR "2001:db8::1235"
#define PREFIX_MASK "ffff:ffff:ffff:ffff:0000:0000:0000:0000"

/* Global vars */
int tunfd, sock;
struct sockaddr_in6 client_addr, server_addr, prefix;

/* entry point for library fuzzers (libFuzzer/honggfuzz) */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);


static int
ip6_input_fuzz(const uint8_t *randBuf, size_t bufLen)
{
    int rv = -1;
    // Preparing the IP packet
    unsigned char packet[bufLen];
    memcpy(packet, randBuf, bufLen);

	if (pkt_create_ipv6(packet, sizeof(packet), &server_addr,
	    &client_addr) == -1)
	{
		warn("Can't create packet");
		return rv;
	}

	ssize_t written = rump_sys_write(tunfd, randBuf, sizeof(randBuf));
	rv = 0;

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
	if (makeaddr6(&client_addr, CLIENT_ADDR) == -1)
		__builtin_trap();
	if (makeaddr6(&server_addr, SERVER_ADDR) == -1)
		__builtin_trap();
	if (makeaddr6(&prefix, PREFIX_MASK) == -1)
		__builtin_trap();

	// Setting up the tun device
	int tunfd = netcfg_rump_if_tun6(DEVICE, &client_addr, &server_addr,
	    &prefix);
	if (tunfd == -1)
		__builtin_trap();

	// Creating the socket
	if ((sock = rump_sys_socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)) == -1) {
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
	// int one = 1;
	// if (rump_sys_setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one,
	//     sizeof(one)) == -1)
	// {
	//     warn("Cannot set HDRINCL!");
	//     goto out;
	// }

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

	if (ip6_input_fuzz(Data, Size)) {
		/**
		 * We shall return 0 on error paths as otherwise
		 * a fuzzer (honggfuzz) restarts the fuzzing process 
		 * and restarting the program costs time.
		 */
		return 0;
	}

	return 0;
}

#ifdef MAIN

#endif