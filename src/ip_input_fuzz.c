/**
 * To compile this file:
 * gcc pkt_create.c ip_input_fuzz.c -lrump -lrumpvfs -lrumpnet -lrumpnet_net -lrumpnet_netinet -lrumpnet_tun
 */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <arpa/inet.h>

#include <sys/stat.h>
#include <sys/param.h>
#include <sys/socketvar.h>
#include <sys/socket.h> 
#include <sys/ioctl.h>
#include <sys/types.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_ether.h>
#include <net/if_bridgevar.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/icmp6.h>

#include <rump/rump.h>
#include <rump/rump_syscalls.h>

#include "pkt_create.h"

static void send_data()
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "tun0");

    int sockfd; 
    char *hello = "Hello from client"; 
    struct sockaddr_in servaddr; 
  
    // Creating socket file descriptor 
    if ( (sockfd = rump_sys_socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("socket creation failed"); 
        return;
    } 
  
	// assign IP, PORT 
    servaddr.sin_family = AF_INET; 
    inet_pton(AF_INET, "192.168.0.5", &servaddr.sin_addr);
    servaddr.sin_port = htons(8000); 
  
    // Binding newly created socket to given IP and verification 
    if ((rump_sys_bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) { 
        printf("socket bind failed...\n"); 
    } 

    memset(&servaddr, 0, sizeof(servaddr)); 
      
    // Filling server information 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_port = htons(8000); 
    inet_pton(AF_INET, "192.168.0.1", &servaddr.sin_addr);
      
    int n, len; 
      
    int val = rump_sys_sendto(sockfd, (const char *)hello, strlen(hello), 
        0, (const struct sockaddr *) &servaddr,  
            sizeof(servaddr)); 
    printf("Val from sendto:%d\n", val);
    printf("Hello message sent.\n"); 
  
    rump_sys_close(sockfd); 
    return; 
}

static void
netcfg_rump_if(const char *ifname, const char *addr, const char *mask)
{
	struct ifaliasreq ia;
    struct ifreq ifr;
	struct sockaddr_in *sin;
	in_addr_t inaddr, inmask, dstaddr;
	int s, rv;

	s = -1;
	if ((s = rump_sys_socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("Socket creation failed");
        return;
	}

	inaddr = inet_addr(addr);
	inmask = inet_addr(mask);
	dstaddr = inet_addr("192.168.0.1");

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, ifname);
    ifr.ifr_flags = IFF_UP | IFF_RUNNING | IFF_POINTOPOINT | IFF_MULTICAST;

	/* Address */
	memset(&ia, 0, sizeof(ia));
	strcpy(ia.ifra_name, ifname);
	sin = (struct sockaddr_in *)&ia.ifra_addr;
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_addr.s_addr = inaddr;

	/* Netmask */
	sin = (struct sockaddr_in *)&ia.ifra_mask;
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_addr.s_addr = inmask;

	/* Broadcast address */
	sin = (struct sockaddr_in *)&ia.ifra_broadaddr;
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_addr.s_addr = inaddr | ~inmask;

	/* Dest address */
	sin = (struct sockaddr_in *)&ia.ifra_dstaddr;
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_addr.s_addr = dstaddr;

	rv = rump_sys_ioctl(s, SIOCAIFADDR, &ia);
	printf("IOCTL VALUE:%d\n", rv);

    rv = rump_sys_ioctl(s, SIOCSIFFLAGS, &ifr);
    printf("IOCTL VALUE:%d\n", rv);
	rump_sys_close(s);
}

int main()
{

	rump_init();
    // Preparing the IP packet
    int bufLen = 30; // Bytes;
    char randBuf[bufLen];
    memcpy(&randBuf, "abcdabchijklmnopqrstuvwxyzabcd", bufLen);

    // randBuf holds the final packet
    pkt_create_ipv4(randBuf, bufLen);

	int errno;

	int tunfd = rump_sys_open("/dev/tun0", O_RDWR);
	printf("Tun FD:%d\n",tunfd);

	if(tunfd > 0)
	{
        netcfg_rump_if("tun0", "192.168.0.5","255.255.255.0");

		int written = rump_sys_write(tunfd, randBuf, bufLen);
		printf("Written: %d\n", written);

		send_data();

		char buf[30];
		int red = rump_sys_read(tunfd, buf, 100);
		printf("Value of read:%d\n", red);
		printf("%s\n", buf);
	}
	else{
		perror("Error in tunfd:");
	}
	rump_sys_close(tunfd);

}
