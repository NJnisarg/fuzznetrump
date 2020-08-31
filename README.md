## Introduction

This project is a part of GSoC 2020. The aim is to fuzz the network stack of NetBSD in a rumpkernel environment.
This link to the project is [here](https://summerofcode.withgoogle.com/projects/#6486401496907776).

## Components Involved and setup:

- Honggfuzz
- NetBSD + Rumpkernel
- Fuzzing test programs

#### NetBSD + Rumpkernel
- Prepare an installation of NetBSD either on an actual machine or on a Virtual machine using qemu(or other possible VM Managers). It is also recommended to setup up the following things while installing:
    - pkgsrc
    - pkgin
    - configuring the network settings
    - setting up sshd
- Grab the NetBSD sources(https://github.com/NetBSD/src)
    - ``` git clone https://github.com/NetBSD/src ```
- In order to have the fuzzing APIs of the rumpkernel, a set of patches need to be applied to the netbsd/src. This repo contains a directory under `src/patches` and a script `src/patches/apply_patchset.sh`. Simply copy the patches and the script to `netbsd/src` and run the script from the root. That should apply the required patches in the codebase.
- Build the distribution with fuzzer coverage
    - ```sudo ./build.sh -m amd64 -N0 -u -U -T ../tooldir -D ../destdir -R ../releasedir -O ../objdir -V MAKECONF=/dev/null -V MKCOMPAT=no -V MKDEBUGLIB=yes -V MKDEBUG=yes -V MKSANITIZER=yes -V USE_SANITIZER=fuzzer-no-link,address -V MKLLVM=yes -V MKGCC=no -V HAVE_LLVM=yes -j4 distribution```
    - In the above command the syntax might vary a bit but please ensure the -V flags are passed as shown above. Follow this guide for more info about `build.sh`: https://www.netbsd.org/docs/guide/en/chap-build.html . Follow `section 31.7.3 Using build.sh options` for more details about the flags and options used.
- After building the distribution have honggfuzz installed following steps below

#### Honggfuzz:
- Honggfuzz is an open source fuzzer maintained by Google.
- It is a feedback driven evolutionary fuzzer.
- Link to repo: https://github.com/google/honggfuzz
- honggfuzz is a part of pkgsrc in NetBSD under devel/honggfuzz.
- The first step is to install honggfuzz on the VM:
    - Get pkgsrc => http://www.netbsd.org/docs/pkgsrc/getting.html . Generally during a fresh installation of the OS, pkgsrc could be installed automatically or you could install it when prompted.
    - Guide on how to use pkgsrc => http://wiki.netbsd.org/pkgsrc/how_to_use_pkgsrc/
    - Navigate to /usr/pkgsrc
    -   ```
        cd devel/honggfuzz
        make install 
        ```
    - The above step will install honggfuzz. At the time of writing this documentation, pkgsrc had honggfuzz version 1.7

#### Fuzzing test programs

- After having the distribution built and honggfuzz ready, grab the fuzzing test program files (.c source files) and carryout the following steps:
- Turn off the `aslr` : `sysctl -w security.pax.aslr.global=0`
- Mount useful directories and chroot: (Here `destdir/` is the directory used in the above steps for building the netbsd from `src`)
    - mount -t null /dev destdir/dev
    - mount -t null /dev/pts destdir/dev/pts
    - mount -t null /tmp destdir/tmp
    - mkdir -p destdir/usr/pkg
    - mount -t null /usr/pkg destdir/usr/pkg
- Copy over the `fuzznetrump/src` into `/tmp`
- chroot into destdir: `chroot destdir/` and `cd /tmp/src/hfuzz`
- Run compile.sh with the correct argument as the file you want to compile. Example: `./compile.sh hfuzz_ip_input.c`. This will generate a `./a.out` file
- Create a corpus: `mkdir corpus`. This is where honggfuzz maintains a corpus of input for further fuzzing of the given program.
- Finally run the compiled test using `honggfuzz`.
    - `honggfuzz -P -f corpus/ -- ./a.out`

#### Example:
- The above process is captured in the following example: http://netbsd.org/~kamil/rump/rump_pub_etfs_register_buffer.c

## Work done as a part of GSoC

#### GSoC Reports
- As a part of GSoC in order to dive into details, reports for the different phases of GSoC are linked in this repo. Please have a look. For a brief information, read the below sections.
- Reports located at: `https://github.com/NJnisarg/fuzznetrump/tree/master/docs`


#### Protocol Fuzzing

- Mainly the worked done revolved around developing a set of files for which can be seen under `src/hfuzz` which carry out the fuzzing of various major protocols of the Internet network stack.
- These protocols include: IPv4, IPv6, ICMP, UDP, Ethernet
- This work can be extended to more protocols following a similar approach
- In order to fuzz the protocols, `rumpkernel` was used. In order to carry out direct feeding to honggfuzz input, certain addtional APIs were introduced into the OS which are a part of this repo under `src/patches` which need to be applied to `NetBSD/src` in order to carry out fuzzing.
- These additional APIs/functions exposed the internal functions of the network stack to be fed direct data for fuzzing purpose. For each protocol one such function is implemented for the rumpkernel. In future, this could be made systematic framework as a part of rumpkernel APIs.

#### Packet creation and Network config

- One of the other major components of these fuzzing tests, were the `helpers` located under `src/helpers` and `src/include`. 
- The `src/helpers/pkt_create.c` contains the functions to forge a packet from the fuzzer input and feed it to the network stack. This packet forging is main feature of this work since it allows us to optimize certain trivial cases where packet can get rejected trivially.
- The `src/helpers/net_config.c` contains functions to configure network devices like TUN and TAP device and other utility functions in order to setup certain network topology before starting the fuzzing.

#### Preliminary results

As a part of the fuzzing effort for certain protocols we did capture a few bugs while carrying out fuzzing. A couple of them are listed here:

1.) A heap-buffer-overflow bug caught by the use of ASAN while fuzzing ICMP input processing function while calculating the internet checksum. Here is a snippet of the GDB output:
```
==4903==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x625000142000 at pc 0x7f7ff6c8ad1a bp 0x7f7fffffc7b0 sp 0x7f7fffffc7a8
READ of size 4 at 0x625000142000 thread T0
[New process 4903]
[Detaching after fork from child process 5809]
    #0 0x7f7ff6c8ad19 in rumpns_cpu_in_cksum /media/njnisarg/Projects/netbsd/src/sys/rump/net/lib/libnet/../../../../netinet/cpu_in_cksum.c:302:15
    #1 0x7f7ff6c452aa in _icmp_input /media/njnisarg/Projects/netbsd/src/sys/rump/net/lib/libnet/../../../../netinet/ip_icmp.c:480:6
    #2 0x7f7ff6c4acff in rumpns_fuzzrump_icmp_input /media/njnisarg/Projects/netbsd/src/sys/rump/net/lib/libnet/../../../../netinet/ip_icmp.c:431:2
    #3 0x526158 in icmp_input_fuzz /tmp/hfuzz/hfuzz_icmp_input_fuzz.c:61:5
    #4 0x525f26 in LLVMFuzzerTestOneInput /tmp/hfuzz/hfuzz_icmp_input_fuzz.c:115:6
    #5 0x5158e6 in HonggfuzzRunOneInput (/tmp/hfuzz/a.out+0x5158e6)
    #6 0x515ac2 in HonggfuzzMain (/tmp/hfuzz/a.out+0x515ac2)
    #7 0x41ec8c in ___start (/tmp/hfuzz/a.out+0x41ec8c)

0x625000142000 is located 0 bytes to the right of 4096-byte region [0x625000141000,0x625000142000)
allocated by thread T0 here:
    #0 0x50c309 in posix_memalign (/tmp/hfuzz/a.out+0x50c309)
    #1 0x7f7ff520f5ba in rumpuser_malloc /media/njnisarg/Projects/netbsd/src/lib/librumpuser/rumpuser_mem.c:55:7
    #2 0x7f7ff76f2621 in rump_hypermalloc /media/njnisarg/Projects/netbsd/src/lib/librump/../../sys/rump/librump/rumpkern/vm.c:1282:10
    #3 0x7f7ff76f2b44 in rumpns_uvm_km_kmem_alloc /media/njnisarg/Projects/netbsd/src/lib/librump/../../sys/rump/librump/rumpkern/vm.c:886:16

SUMMARY: AddressSanitizer: heap-buffer-overflow /media/njnisarg/Projects/netbsd/src/sys/rump/net/lib/libnet/../../../../netinet/cpu_in_cksum.c:302:15 in rumpns_cpu_in_cksum
Shadow bytes around the buggy address:

```

2.) Another problem we detected was a kernel panic when a malformed packet not aligned according to it's length was processed by the IP input processing function. Here is a snippet of the GDB backtrace:
```
Thread 1 "" received signal SIGABRT, Aborted.
0x00007f7ff3b7f0fa in _lwp_kill () from /usr/lib/libc.so.12
(gdb) bt
#0  0x00007f7ff3b7f0fa in _lwp_kill () from /usr/lib/libc.so.12
#1  0x00007f7ff3b7ed69 in abort () at /media/njnisarg/Projects/netbsd/src/lib/libc/stdlib/abort.c:74
#2  0x00007f7ff521ca08 in rumpuser_exit (rv=-1) at /media/njnisarg/Projects/netbsd/src/lib/librumpuser/rumpuser.c:236
#3  0x00007f7ff770235b in cpu_reboot (howto=<optimized out>, bootstr=<optimized out>) at /media/njnisarg/Projects/netbsd/src/lib/librump/../../sys/rump/librump/rumpkern/emul.c:429
#4  0x00007f7ff7601c7c in kern_reboot (howto=4, bootstr=0x0) at /media/njnisarg/Projects/netbsd/src/lib/librump/../../sys/rump/../kern/kern_reboot.c:73
#5  0x00007f7ff75f6676 in vpanic (fmt=<optimized out>, ap=<optimized out>) at /media/njnisarg/Projects/netbsd/src/lib/librump/../../sys/rump/../kern/subr_prf.c:290
#6  0x00007f7ff7533771 in panic (fmt=0x7f7ff707c680 "%s: m_data not in packet(dat = %p, len = %d, low = %p, high = %p)")
    at /media/njnisarg/Projects/netbsd/src/lib/librump/../../sys/rump/../kern/subr_prf.c:209
#7  0x00007f7ff706c4b0 in m_verify_packet (m=<optimized out>) at /media/njnisarg/Projects/netbsd/src/lib/librumpnet/../../sys/rump/../kern/uipc_mbuf.c:2272
#8  0x00007f7ff6c34a68 in ip_input (m=0x1639) at /media/njnisarg/Projects/netbsd/src/sys/rump/net/lib/libnet/../../../../netinet/ip_input.c:808
#9  0x00007f7ff6c31207 in fuzzrump_ip_input (d=<optimized out>, len=5022) at /media/njnisarg/Projects/netbsd/src/sys/rump/net/lib/libnet/../../../../netinet/ip_input.c:430
#10 0x0000000000526104 in ip_input_fuzz (randBuf=0x7f7fe7dff800 "J\210", bufLen=5022) at hfuzz_ip_input_fuzz.c:59
#11 0x0000000000525ec7 in LLVMFuzzerTestOneInput (Data=0x7f7fe7dff800 "J\210", Size=5022) at hfuzz_ip_input_fuzz.c:95
#12 0x0000000000515887 in HonggfuzzRunOneInput ()
#13 0x0000000000515a63 in HonggfuzzMain ()
#14 0x000000000041ec2d in ___start ()
#15 0x00007f7ff7c0cb70 in ?? () from /libexec/ld.elf_so
#16 0x0000000000000001 in ?? ()
#17 0x00007f7fffffee28 in ?? ()
#18 0x0000000000000000 in ?? ()

```

#### Further steps

- We would like to standardize this fuzzing process and add support for more protocols. There are a ton of network protocols yet to be fuzzed like TCP, SCTP, network drivers similar to Ethernet and so on.
- Make the process of finding crashes more easily reproducible.
- Gather more stats like code coverage regarding the fuzzing process using tools like `gcov`.
