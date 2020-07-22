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

#define tunpath "/dev/tun0"
#define CLIENT_ADDR "2001:db8::1234"
#define SERVER_ADDR "2001:db8::1235"
#define PREFIX "ffff:ffff:ffff:ffff:0000:0000:0000:0000"


int main()
{
    struct sockaddr_in6 addr, prefix, srv;
    struct in6_aliasreq ia;
	struct in6_ifreq ifr;
	const char *ifname = strrchr(tunpath, '/') + 1;
	unsigned int ifindex;
	int s, tunfd;

	if ((tunfd = open(tunpath, O_RDWR)) == -1){
		warn("Can't open `%s'", tunpath);
		return -1;
	}

	if ((s = socket(PF_INET6, SOCK_DGRAM, 0)) == -1) {
		warn("Can't create datagram socket");
		close(tunfd);
		return -1;
	}

    memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_len = sizeof(addr);
	if (inet_pton(AF_INET6, CLIENT_ADDR, &addr.sin6_addr) < 0)  { 
		warn("Invalid address/Address not supported"); 
	}

    memset(&prefix, 0, sizeof(prefix));
	prefix.sin6_family = AF_INET6;
	prefix.sin6_len = sizeof(prefix);
	if (inet_pton(AF_INET6, PREFIX, &prefix.sin6_addr) < 0)  { 
		warn("Invalid address/Address not supported"); 
	}

    memset(&srv, 0, sizeof(srv));
	srv.sin6_family = AF_INET6;
	srv.sin6_len = sizeof(srv);
	if (inet_pton(AF_INET6, SERVER_ADDR, &srv.sin6_addr) < 0)  { 
		warn("Invalid address/Address not supported"); 
	}
	

	/* Address Request */
	memset(&ia, 0, sizeof(ia));
	strcpy(ia.ifra_name, ifname);

	/* Src Addr */
	*(struct sockaddr_in6 *)&ia.ifra_addr = addr;
    *(struct sockaddr_in6 *)&ia.ifra_prefixmask = prefix;
	ia.ifra_lifetime.ia6t_vltime = 0xffffffff;
	ia.ifra_lifetime.ia6t_pltime = 0xffffffff;
    

    /* For setting flags on device */
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ifname);
	ifr.ifr_flags = (short)
	    (IFF_UP | IFF_RUNNING | IFF_POINTOPOINT);
	if (ioctl(s, SIOCSIFFLAGS, &ifr) == -1) {
		warn("SIOCSIFFLAGS failed for %s", ifname);
	}    

	/* IOCTLs */
	if (ioctl(s, SIOCAIFADDR_IN6, &ia) == -1) {
		warn("SIOCAIFADDR_IN6 failed for %s", ifname);
	}

	/* Close the socket */
	// rump_sys_close(s);
	// return tunfd;
    close(s);

// out:
// 	close(tunfd);
//     close(s);
// 	return -1;
}