#include <stdio.h>
#include <fcntl.h>
#include <err.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <netinet6/in6.h>
#include <netinet6/in6_var.h>

#include <rump/rump.h>
#include <rump/rump_syscalls.h>

#define tappath "/dev/tap0"
#define tapname "tap0"
#define CLIENT_ADDR "192.168.0.5"
#define SERVER_ADDR "192.168.0.1"
#define NETMASK "255.255.255.0"

int
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

void 
get_ether_addr(char* device, char* ether_addr)
{
	int			mib[6];
	size_t len;
	char			*buf;
	unsigned char		*ptr;
	struct if_msghdr	*ifm;
	struct sockaddr_dl	*sdl;

	mib[0] = CTL_NET;
	mib[1] = AF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_LINK;
	mib[4] = NET_RT_IFLIST;
	if ((mib[5] = if_nametoindex(device)) == 0) {
		perror("if_nametoindex error");
		exit(2);
	}

	if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
		perror("sysctl 1 error");
		exit(3);
	}

	if ((buf = malloc(len)) == NULL) {
		perror("malloc error");
		exit(4);
	}

	if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
		perror("sysctl 2 error");
		exit(5);
	}

	ifm = (struct if_msghdr *)buf;
	sdl = (struct sockaddr_dl *)(ifm + 1);
	ptr = (unsigned char *)LLADDR(sdl);
	sprintf(ether_addr, "%02x:%02x:%02x:%02x:%02x:%02x", *ptr, *(ptr+1), *(ptr+2),
			*(ptr+3), *(ptr+4), *(ptr+5));

	return;
}

int main()
{
    struct ifaliasreq ia;
	struct ifreq ifr;
	struct sockaddr_in client_addr, server_addr, netmask;
	const char *ifname = strrchr(tappath, '/') + 1;
	char* ether_addr;
	int s, tapfd;

	/* Getting a socket for IOCTLs */
	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
		warn("Can't create datagram socket");
		return -1;
	}

	/* Making a request to create tap device */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, tapname, (size_t)sizeof(tapname));
	if((ioctl(s, SIOCIFCREATE, (void *)&ifr)) == -1)
	{
		warn("Can't create the TAP Device");
		close(s);
		return -1;
	}

	close(s);

	/* Getting the MAC Address of the created device */
	get_ether_addr(tapname, ether_addr);
	printf("TAP ETHER ADDR:%s\n", ether_addr);

	/* Setting socket addresses for using with ip src and dest */
	if (makeaddr(&client_addr, CLIENT_ADDR) == -1)
		return -1;
	if (makeaddr(&server_addr, SERVER_ADDR) == -1)
		return -1;
	if (makeaddr(&netmask, NETMASK) == -1)
		return -1;

	/* Getting a socket for ioctls */
	if ((s = socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
		warn("Can't create datagram socket");
		return -1;
	}

	/* Address Request */
	memset(&ia, 0, sizeof(ia));
	strcpy(ia.ifra_name, ifname);

	/* Src Addr */
	*(struct sockaddr_in *)&ia.ifra_addr = client_addr;
	/* Netmask */
	*(struct sockaddr_in *)&ia.ifra_mask = netmask;
	/* Dest address */
	*(struct sockaddr_in *)&ia.ifra_dstaddr = server_addr;

	/* IOCTLs */
	if (ioctl(s, SIOCAIFADDR, &ia) == -1) {
		warn("SIOAIFADDR failed for %s", ifname);
		return -1;
	}

	/* For setting flags on device */
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);
	ifr.ifr_flags = (short)
	    (IFF_UP | IFF_RUNNING | IFF_POINTOPOINT | IFF_MULTICAST);
	if (ioctl(s, SIOCSIFFLAGS, &ifr) == -1) {
		warn("SIOSIFFLAGS failed for %s", ifname);
		return -1;
	}


	/* Opening the tap device */
	if ((tapfd = open(tappath, O_RDWR)) == -1){
		warn("Can't open `%s'", tappath);
		return -1;
	}
	printf("The TAP FD is :%d\n", tapfd);

	/* Close the socket */
	close(tapfd);
    close(s);
}