int makeaddr(struct sockaddr_in *addr, const char *name);
int netcfg_rump_if_tun(const char *, const struct sockaddr_in *,
    const struct sockaddr_in *, const struct sockaddr_in *);
int makeaddr6(struct sockaddr_in6 *addr, const char *name);
int netcfg_rump_if_tun6(const char *, struct sockaddr_in6 *,
    const struct sockaddr_in6 *, const struct sockaddr_in6 *);