#include <stdio.h>
#include <fcntl.h>
#include <err.h>
#include <unistd.h>
#include <string.h>

#include <arpa/inet.h>

#include <sys/ioctl.h>

#include <net/if.h>
#include <netinet6/in6.h>
#include <netinet6/in6_var.h>

#include <rump/rump.h>
#include <rump/rump_syscalls.h>

#include "../include/net_config.h"

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
makeaddr6(struct sockaddr_in6 *addr, const char *name)
{
	memset(addr, 0, sizeof(*addr));
	addr->sin6_family = AF_INET6;
	addr->sin6_len = sizeof(*addr);
	if (inet_pton(AF_INET6, name, &addr->sin6_addr) < 0)  { 
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

int
netcfg_rump_if_tun6(const char *tunpath, struct sockaddr_in6 *src,
    const struct sockaddr_in6 *dst, const struct sockaddr_in6 *prefix)
{
	struct in6_aliasreq ia;
	struct in6_ifreq ifr;
	const char *ifname = strrchr(tunpath, '/') + 1;
	unsigned int ifindex;
	int s, tunfd;

	if ((tunfd = rump_sys_open(tunpath, O_RDWR)) == -1){
		warn("Can't open `%s'", tunpath);
		return -1;
	}

	if ((s = rump_sys_socket(PF_INET6, SOCK_DGRAM, 0)) == -1) {
		warn("Can't create datagram socket");
		rump_sys_close(tunfd);
		return -1;
	}

	/* Address Request */
	memset(&ia, 0, sizeof(ia));
	strcpy(ia.ifra_name, ifname);

	/* Src Addr */
	*(struct sockaddr_in6 *)&ia.ifra_addr = *src;
	/* prefix mask */
	*(struct sockaddr_in6 *)&ia.ifra_prefixmask = *prefix;

	/* This right here is the reason for my 3 days worth of sleep */ 
	ia.ifra_lifetime.ia6t_vltime = 0xffffffff;
	ia.ifra_lifetime.ia6t_pltime = 0xffffffff;

	/* IOCTLs */
	if (rump_sys_ioctl(s, SIOCAIFADDR_IN6, &ia) == -1) {
		warn("SIOCAIFADDR_IN6 failed for %s", ifname);
		goto out;
	}

	/* For setting flags on device */
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);
	ifr.ifr_flags = (short)
	    (IFF_UP | IFF_RUNNING | IFF_POINTOPOINT | IFF_MULTICAST);
	if (rump_sys_ioctl(s, SIOCSIFFLAGS, &ifr) == -1) {
		warn("SIOCSIFFLAGS failed for %s", ifname);
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
