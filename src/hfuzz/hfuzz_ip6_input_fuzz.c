/**
 * To compile this file:
 * 
 * ASAN_OPTIONS=detect_container_overflow=0 hfuzz-clang -fsanitize=address 
 * pkt_create.c net_config.c hfuzz_ip6_input_fuzz.c 
 * -lrump -lrumpvfs -lrumpvfs_nofifofs -lrumpnet -lrumpnet_net -lrumpnet_netinet -lrumpnet_netinet6 -lrumpnet_tun -g
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

#define CLIENT_ADDR "::1"
#define SERVER_ADDR "::1"
#define PREFIX_MASK "ffff:ffff:ffff:ffff:0000:0000:0000:0000"

/* Global vars */
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

	// Call the fuzzer function inside rump
	rump_schedule();
    rumpns_fuzzrump_ip6_input((char *)packet, sizeof(packet));
	rump_unschedule();

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

    return;
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