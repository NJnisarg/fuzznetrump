## Introduction

- The files we are looking for are: `ip_input.c` inside `src/sys/netinet/`
- The functions are are looking for:
    - ipintr()
    - ip_input()
    - ip_forward()
    - ip_dooptions()
    - ipsec_input()
    - ip_mforward()
    - ip_reass_packet()

### ipintr (394 - 405)

- This function does IP software interrupt handling
- Checks if the `LP_INTR` flag was set
- Then takes a lock 
- Loops through the packets on the ip input queue
- For each packet it calls `ip_input`
- Then breaks from the loop when queue is empty and unlocks

### ip_input (411 - 823)

- This function takes the mbuf
- If carries out a check of `LP_INTR` flag
- Asserts that mbuf has m_flag set to `M_PKTHDR`
- Grabs the interface that received this packet
    - If the interface is not there, then `goto out`
- `goto out`:
    - This simply frees the mbuf and drops the packet silently
- Next it checks if there are no IP addresses assigned to the interfaces, then drop the packets
- Check the alignment of the IP header, if not then copy it to a new mbuf with space for link headers as well
    - NOTE: Look into `m_pullup` and `m_copyup`
- Next checks the IP Version
- Next check the header length of IP, should be atleast `sizeof(struct ip)`
- Check if hlen > m->m_len, then call `m_pullup`
- Checking if the src address is multicast address. If yes then drop it
- If src or dst ip is of localhost format, then check if the interface is loopback or not. If not loopback, then drop the packet
- Next we check the checksum value
    - If hardware checksum capability is on for the given device, then we check if Checksum calculated by the device was ok or not
    - If checksum not ok, drop the packet
    - If hardware checksum is not there, then we do software checksum if its not a loopback device
    - If checksum is not ok, drop the packet

- Next we retrieve the len of packet and check if it is atleast as large as hlen. If not the discard the packet
- Next we check if the mbuf chain has enough len(`m->m_pkthdr.len > len`) to store a packet with `len = ip->ip_len`, if not then drop the packet, if there is excess amount of space, then trim the mbuf_chain
- Set the `M_CANFASTFWD` flag.(Note: Look into what this is)
- Next we pass the packet through input packet filter hooks if ipsec is not enabled/used or ipsec does not force to skip pfil.
- We run the `pfil_run_hooks` function and check if the packet filter dropped the packet or not. If they dropped then we `goto out`
- After running through the hooks(which might have modified the mbuf chain), check if m->mlen is atleast the size of Ip Header, if not then run `m_pullup` if that fails then drop the packet.
- We will do a similar check for hlen and m->mlen
- We also set the srcrt = 1 in case the ip->dst address is modified by a pfil hook to indicate the `ip_forward` function that it was done by a hook and not by a source routing option
- Then pass the packet to `altq_input`
- Carry out IP Options Processing(`ip_dooptions`). If error then the `ip_dooptions` will send an icmp error message and return non zero value. We drop the packet on error.
- Next we check if the packet is destined for some interface on our host system. If yes we process it by `goto ours`, if no then continue the processing
- Next we do multicast processing.(includes acting as mrouter).
- Check if the dest addr was broadcast, if yes the push it up the stack(`goto ours`)
- Next if `ip_forwarding` is not enabled then we drop the packet now.
- If `ip_forwarding` is enabled then:
    - If there was non-zero downmatch then we send out an icmp error saying host unreachable
    - Process for ipsec policy. If there is no issue we move ahead.
    - Next we carry out `ip_forward`
- `goto ours`:
    - It carries reassembly if needed.
    - If there was an error in reassembly then it discards the packet
    - IPsec related processing(Read more later)
    - Update some received bytes stats on the interface
    - Lookup the protocol from the `inetsw` and pass the packet to the `pr_input` function for the transport layer protocol.
- End of the input processing.
