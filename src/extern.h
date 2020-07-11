int pkt_create_ipv4(void *, size_t, const struct sockaddr_in *,
    const struct sockaddr_in *);
int pkt_create_udp4(void *, size_t, const struct sockaddr_in *,
    const struct sockaddr_in *);
int pkt_create_icmp4(void *, size_t, const struct sockaddr_in *,
    const struct sockaddr_in *);
int makeaddr(struct sockaddr_in *addr, const char *name);
int netcfg_rump_if_tun(const char *, const struct sockaddr_in *,
    const struct sockaddr_in *, const struct sockaddr_in *);
