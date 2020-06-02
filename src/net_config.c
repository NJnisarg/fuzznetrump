#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <arpa/inet.h>

#include <sys/ioctl.h>

#include <net/if.h>

#include <rump/rump.h>
#include <rump/rump_syscalls.h>

int
netcfg_rump_if_tun(const char *tunpath, const char *ifname, const char *addr, const char *mask, const char* daddr)
{
    int errno;

	struct ifaliasreq ia;
    struct ifreq ifr;

	struct sockaddr_in *sin;
	in_addr_t inaddr, inmask, dstaddr;

	int s, rv;
    int tunfd;

    tunfd = -1;
    if((tunfd = rump_sys_open(tunpath, O_RDWR)) < 0){
        perror("Tun device open failed:");
        return tunfd;
    }

	s = -1;
	if ((s = rump_sys_socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed:");
        rump_sys_close(tunfd);
        return s;
	}

	inaddr = inet_addr(addr);
	inmask = inet_addr(mask);
	dstaddr = inet_addr(daddr);

    /* For setting flags on device */
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, ifname);
    ifr.ifr_flags = IFF_UP | IFF_RUNNING | IFF_POINTOPOINT | IFF_MULTICAST;

	/* Address Request */
	memset(&ia, 0, sizeof(ia));
	strcpy(ia.ifra_name, ifname);

    /* Src Addr */
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

    /* IOCTLs */
	rv = rump_sys_ioctl(s, SIOCAIFADDR, &ia);
    if(rv < 0)
    {
        perror("SIOCAIFADDR IOCTL:");
        rump_sys_close(tunfd);
        rump_sys_close(s);
        return rv;
    }

    rv = rump_sys_ioctl(s, SIOCSIFFLAGS, &ifr);
    if(rv < 0)
    {
        perror("SIOCSIFFLAGS IOCTL:");
        rump_sys_close(tunfd);
        rump_sys_close(s);
        return rv;
    }

    /* Close the socket */
	rump_sys_close(s);

    return tunfd;
}

#if 0
int main()
{
    int tunfd = netcfg_rump_if_tun("/dev/tun0", "tun0", "192.168.0.5", "255.255.255.0", "192.168.0.1");
    if(tunfd < 0)
        printf("Error in creating and configuring tun0 device");
    else{
        printf("tun0 fd is: %d\n", tunfd);
    }
}
#endif