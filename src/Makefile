
WARNS=6
NOMAN=1

.include <bsd.own.mk>

PROG=ip_output_fuzz
SRCS=ip_output_fuzz.c pkt_create.c net_config.c
LDADD+= -lrump -lrumpvfs -lrumpnet -lrumpnet_net -lrumpnet_netinet -lrumpnet_tun

PROG=ip_input_fuzz
SRCS=ip_input_fuzz.c pkt_create.c net_config.c
LDADD+= -lrump -lrumpvfs -lrumpnet -lrumpnet_net -lrumpnet_netinet -lrumpnet_tun

PROG=reader_writer_test
SRCS=reader_writer_test.c pkt_create.c net_config.c
LDADD+= -lrump -lrumpvfs -lrumpnet -lrumpnet_net -lrumpnet_netinet -lrumpnet_tun

.include <bsd.prog.mk>
