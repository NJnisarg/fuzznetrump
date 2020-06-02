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

#include "../pkt_create.c"
#include "../net_config.c"

/* Global vars */
int tunfd;

/* entry point for library fuzzers (libFuzzer/honggfuzz) */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);


static int
ip_input_fuzz(const uint8_t *randBuf, size_t bufLen)
{
    // Preparing the IP packet
    int bufLen = 30; // Bytes;
    char randBuf[bufLen];
    memcpy(&randBuf, "abcdefghijklmnopqrstuvwxyzabcd", bufLen);

    // randBuf holds the final packet
    pkt_create_ipv4(randBuf, bufLen);

    int written = rump_sys_write(tunfd, randBuf, bufLen);
    printf("Written: %d\n", written);
    return 0;
}

/* Initialize rumpkernel and network setup only once. */
static
void Initialize()
{
	if (rump_init() != 0)
		__builtin_trap();
    
    int errno;
    struct sockaddr_in serv_addr; 
    struct sockaddr_in client_addr;

    // Setting up the tun device
	tunfd = netcfg_rump_if_tun("/dev/tun0", "tun0", "192.168.0.5", "255.255.255.0", "192.168.0.1");
    if(tunfd < 0)
	{
		printf("Error in creating and configuring tun0 device");
		__builtin_trap();
	}
}

int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	static bool Initialized;

	if (!Initialized) {
		Initialize();
		Initialized = true;
	}

	if (ip_input_fuzz(Data, Size)) {
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
/* For manual testing only. */
int main()
{

	rump_init();

	int errno;

    // Preparing the IP packet
    int bufLen = 30; // Bytes;
    char randBuf[bufLen];
    memcpy(&randBuf, "abcdefghijklmnopqrstuvwxyzabcd", bufLen);

    // randBuf holds the final packet
    pkt_create_ipv4(randBuf, bufLen);

	// Setting up the tun device
	int tunfd = netcfg_rump_if_tun("/dev/tun0", "tun0", "192.168.0.5", "255.255.255.0", "192.168.0.1");
    if(tunfd < 0)
	{
		printf("Error in creating and configuring tun0 device");
		return -1;
	}
    else{
		int written = rump_sys_write(tunfd, randBuf, bufLen);
		printf("Written: %d\n", written);

		rump_sys_close(tunfd);
		return 0;
    }
}
#endif