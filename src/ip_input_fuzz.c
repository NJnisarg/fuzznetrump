/**
 * To compile this file:
 * gcc ip_input_fuzz.c -lrump -lrumpvfs -lrumpnet -lrumpnet_net -lrumpnet_netinet -lrumpnet_tun
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <rump/rump.h>
#include <rump/rump_syscalls.h>

#include "pkt_create.c"
#include "net_config.c"

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
