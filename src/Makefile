
WARNS=6
NOMAN=1

.include <bsd.own.mk>

PROG=ip_output_fuzz
SRCS=ip_output_fuzz.c pkt_create.c net_config.c
LDADD+= -lrump -lrumpvfs -lrumpnet -lrumpnet_net -lrumpnet_netinet -lrumpnet_tun

.include <bsd.prog.mk>
