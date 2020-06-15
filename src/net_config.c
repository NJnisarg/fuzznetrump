#include <stdio.h>
#include <fcntl.h>
#include <err.h>
#include <unistd.h>
#include <string.h>

#include <arpa/inet.h>

#include <sys/ioctl.h>

#include <net/if.h>

#include <rump/rump.h>
#include <rump/rump_syscalls.h>

#include "extern.h"

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

int
netcfg_rump_if_tun(const char *tunpath, const struct sockaddr_in *src,
    const struct sockaddr_in *dst, const struct sockaddr_in *mask)
{
	struct ifaliasreq ia;
	struct ifreq ifr;
	const char *ifname = strrchr(tunpath, '/') + 1;
	// struct sockaddr_in *sin;
	int s, tunfd;

	if ((tunfd = rump_sys_open(tunpath, O_RDWR)) == -1){
		warn("Can't open `%s'", tunpath);
		return -1;
	}

	if ((s = rump_sys_socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
		warn("Can't create datagram socket");
		rump_sys_close(tunfd);
		return -1;
	}

	/* Address Request */
	memset(&ia, 0, sizeof(ia));
	strcpy(ia.ifra_name, ifname);

	/* Src Addr */
	*(struct sockaddr_in *)&ia.ifra_addr = *src;
	/* Netmask */
	*(struct sockaddr_in *)&ia.ifra_mask = *mask;
	/* Dest address */
	*(struct sockaddr_in *)&ia.ifra_dstaddr = *dst;

	/* Broadcast address */
	// sin = (struct sockaddr_in *)&ia.ifra_broadaddr;
	// memset(sin, 0, sizeof(*sin));
	// sin->sin_family = AF_INET;
	// sin->sin_len = sizeof(struct sockaddr_in);
	// sin->sin_addr.s_addr = src->sin_addr.s_addr | ~mask->sin_addr.s_addr;

	/* IOCTLs */
	if (rump_sys_ioctl(s, SIOCAIFADDR, &ia) == -1) {
		warn("SIOAIFADDR failed for %s", ifname);
		goto out;
	}

	/* For setting flags on device */
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);
	ifr.ifr_flags = (short)
	    (IFF_UP | IFF_RUNNING | IFF_POINTOPOINT | IFF_MULTICAST);
	if (rump_sys_ioctl(s, SIOCSIFFLAGS, &ifr) == -1) {
		warn("SIOSIFFLAGS failed for %s", ifname);
		goto out;
	}

	/* Close the socket */
	rump_sys_close(s);
	return tunfd;

out:
	rump_sys_close(tunfd);
    rump_sys_close(s);
	return -1;
}
