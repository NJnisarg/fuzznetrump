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
		return -1;
	}

	if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
		perror("sysctl 1 error");
		return -1;
	}

	if ((buf = malloc(len)) == NULL) {
		perror("malloc error");
		return -1;
	}

	if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
		perror("sysctl 2 error");
		return -1;
	}

	ifm = (struct if_msghdr *)buf;
	sdl = (struct sockaddr_dl *)(ifm + 1);
	ptr = (unsigned char *)LLADDR(sdl);
	sprintf(ether_addr, "%02x:%02x:%02x:%02x:%02x:%02x", *ptr, *(ptr+1), *(ptr+2),
			*(ptr+3), *(ptr+4), *(ptr+5));

	return 0;
}

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
netcfg_rump_if_tap(const char *tapname, const char *tappath, char* ether_addr, const struct sockaddr_in *src,
    const struct sockaddr_in *dst, const struct sockaddr_in *mask)
{
	struct ifaliasreq ia;
	struct ifreq ifr;
	const char *ifname = strrchr(tappath, '/') + 1;
	int s, tapfd;

	/* Getting a socket for IOCTLs */
	if ((s = rump_sys_socket(PF_INET, SOCK_DGRAM, 0)) == -1) {
		warn("Can't create datagram socket");
		return -1;
	}

	/* Making a request to create tap device */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, tapname, (size_t)sizeof(tapname));
	if((rump_sys_ioctl(s, SIOCIFCREATE, (void *)&ifr)) == -1)
	{
		warn("Can't create the TAP Device");
		rump_sys_close(s);
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
		return -1;
	}

	/* For setting flags on device */
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);
	ifr.ifr_flags = (short)
	    (IFF_UP | IFF_RUNNING | IFF_POINTOPOINT | IFF_MULTICAST);
	if (rump_sys_ioctl(s, SIOCSIFFLAGS, &ifr) == -1) {
		warn("SIOSIFFLAGS failed for %s", ifname);
		return -1;
	}

	/* Getting the MAC Address of the created device */
	if(get_ether_addr(tapname, ether_addr) == -1)
	{
		warn("Can't get MAC Address of the TAP Device");
		rump_sys_close(s);
		return -1;
	}

	/* Opening the tap device */
	if ((tapfd = rump_sys_open(tappath, O_RDWR)) == -1){
		warn("Can't open `%s'", tappath);
		return -1;
	}

    rump_sys_close(s);
	return tapfd;

out:
	rump_sys_close(tapfd);
    rump_sys_close(s);
	return -1;
}

int
netcfg_rump_if_tun(const char *tunpath, const struct sockaddr_in *src,
    const struct sockaddr_in *dst, const struct sockaddr_in *mask)
{
	struct ifaliasreq ia;
	struct ifreq ifr;
	const char *ifname = strrchr(tunpath, '/') + 1;
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