int pkt_create_ether(void *buf, size_t buflen, 
    const char* src_mac, const char* dst_mac);
int pkt_create_ipv4(void *, size_t, const struct sockaddr_in *,
    const struct sockaddr_in *);
int pkt_create_ipv6(void *, size_t, const struct sockaddr_in6 *,
    const struct sockaddr_in6 *);
int pkt_create_udp4(void *, size_t, const struct sockaddr_in *,
    const struct sockaddr_in *);
int pkt_create_icmp4(void *, size_t, const struct sockaddr_in *,
    const struct sockaddr_in *);