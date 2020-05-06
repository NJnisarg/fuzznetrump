## Introduction

This project is a part of GSoC 2020. The aim is to fuzz the network stack of NetBSD in a rumpkernel environment.

## Components Involved and setup:

- Honggfuzz
- NetBSD + Rumpkernel
- Fuzzing test programs

#### NetBSD + Rumpkernel
- Prepare an installation of NetBSD either on an actual machine or on a Virtual machine using qemu(or other possible VM Managers)
- Grab the NetBSD sources(https://github.com/NetBSD/src)
    - ``` git clone https://github.com/NetBSD/src ```
- Build the distribution with fuzzer coverage
    - ```./build.sh -j8 -N0 -U -u -V MAKECONF=/dev/null -V MKCOMPAT=no -V MKDEBUGLIB=yes -V MKDEBUG=yes -V MKSANITIZER=yes -V USE_SANITIZER=fuzzer-no-link -V MKLLVM=yes -V MKGCC=no -V HAVE_LLVM=yes -O /public/netbsd.fuzzer distribution```
    - In the above command please replace -O with suitable objdir. Follow this guide for more info about `build.sh`: https://www.netbsd.org/docs/guide/en/chap-build.html . Follow `section 31.7.3 Using build.sh options` for more details about the flags and options used.
- After building the distribution have honggfuzz installed following steps below

#### Honggfuzz:
- Honggfuzz is an open source fuzzer maintained by Google.
- It is a feedback driven evolutionary fuzzer.
- Link to repo: https://github.com/google/honggfuzz
- honggfuzz is a part of pkgsrc in NetBSD under devel/honggfuzz.
- The first step is to install honggfuzz on the client:
    - Get pkgsrc => http://www.netbsd.org/docs/pkgsrc/getting.html . Generally during a fresh installation of the OS, pkgsrc could be installed automatically.
    - Guide on how to use pkgsrc => http://wiki.netbsd.org/pkgsrc/how_to_use_pkgsrc/
    - Navigate to /usr/pkgsrc
    -   ```
        cd devel/honggfuzz
        make install 
        ```
    - The above step will install honggfuzz. At the time of writing this documentation, pkgsrc had honggfuzz version 1.7

#### Fuzzing test programs

- After having the distribution built and honggfuzz ready, grab the fuzzing test program files (.c source files) and carryout the following steps:
- Mount useful directories and chroot:
    - `mount -t null /dev /public/netbsd.fuzzer/destdir.amd64/dev`
    - `mount -t null /dev/pts /public/netbsd.fuzzer/destdir.amd64/dev/pts`
    - `mount -t null /tmp /public/netbsd.fuzzer/destdir.amd64/tmp`
    - `mkdir -p /public/netbsd.fuzzer/destdir.amd64/usr/pkg`
    - `mount -t null /usr/pkg /public/netbsd.fuzzer/destdir.amd64/usr/pkg`
    - `chroot /public/netbsd.fuzzer/destdir.amd64`
    - `cd /tmp`
- Place the fuzzing test .c file in `/tmp` directory
- Compile the .c file using `hfuzz-clang`:
    - `hfuzz-clang -lrumpvfs -lrump -lrumpfs_ffs -lrumpuser -lrumpdev_disk -lrumpdev -pthread fuzzing_test_file.c`
    - Here we are linking different rumpkernel libraries based on what components we are using from rumpkernel
- Create a corpus: `mkdir corpus`. This is where honggfuzz maintains a corpus of input for further fuzzing of the given program.
- Finally run the compiled test using `honggfuzz`.
    - `honggfuzz -P -f corpus/ -- ./a.out`

#### Example:
- The above process is captured in the following example: http://netbsd.org/~kamil/rump/rump_pub_etfs_register_buffer.c