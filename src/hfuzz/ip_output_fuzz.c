#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ip.h>

#include <rump/rump.h>
#include <rump/rump_syscalls.h>

#include "../pkt_create.c"
#include "../net_config.c"

/* Global vars */
int tunfd, sock;

/* entry point for library fuzzers (libFuzzer/honggfuzz) */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);


static int
ip_output_fuzz(const uint8_t *randBuf, size_t bufLen)
{
	int errno;
    struct sockaddr_in serv_addr; 
    struct sockaddr_in client_addr; 
    
    // Setting socket addresses for using with ip src and dest
    client_addr.sin_family = AF_INET;
    serv_addr.sin_family = AF_INET;
    if(inet_pton(AF_INET, "192.168.0.1", &serv_addr.sin_addr)<=0)  // Convert IPv4 addresses from text to binary form 
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        return -1; 
    }
    if(inet_pton(AF_INET, "192.168.0.5", &client_addr.sin_addr)<=0)  
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        return -1; 
    }

    // Preparing the IP packet
    memcpy(&randBuf, "abcdefghijklmnopqrstuvwxyzabcd", bufLen);

    // randBuf holds the final packet
    pkt_create_ipv4(randBuf, bufLen);

    // Setting the header included flag for RAW IP to not touch the IP header
    int one=1;
    const int *val = &one;
    if (rump_sys_setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        printf ("Warning: Cannot set HDRINCL!\n");
        return -1;
    }


    // Sending down the socket
    int written = rump_sys_sendto(sock , randBuf , bufLen , 0, (struct sockaddr *) &serv_addr, sizeof (serv_addr));
    if (written == -1)
    {
        printf("sendto failed\n");
        perror("Error in sending:");
    }
    else if ((size_t)written != bufLen)
    {
        printf("sendto did not write all data\n");
        printf("Amount of buffer written: %d\n", written);
    }
    else{
        printf("All data written\n");
    }

    return 0;
}

/* Initialize rumpkernel and network setup only once. */
static
void Initialize()
{
	if (rump_init() != 0)
		__builtin_trap();
    
    int errno;
    struct sockaddr_in serv_addr; 
    struct sockaddr_in client_addr;

    // Setting up the tun device
	tunfd = netcfg_rump_if_tun("/dev/tun0", "tun0", "192.168.0.5", "255.255.255.0", "192.168.0.1");
    if(tunfd < 0)
	{
		printf("Error in creating and configuring tun0 device");
		__builtin_trap();
	}

    // Creating the socket
    if ((sock = rump_sys_socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
        rump_sys_close(tunfd);
        __builtin_trap();
    } 
   
    
    // Setting socket addresses for using with ip src and dest
    client_addr.sin_family = AF_INET;
    serv_addr.sin_family = AF_INET;
    if(inet_pton(AF_INET, "192.168.0.1", &serv_addr.sin_addr)<=0)  // Convert IPv4 addresses from text to binary form 
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        rump_sys_close(tunfd);
        rump_sys_close(sock);
        __builtin_trap();
    }
    if(inet_pton(AF_INET, "192.168.0.5", &client_addr.sin_addr)<=0)  
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        rump_sys_close(tunfd);
        rump_sys_close(sock);
        __builtin_trap();
    }
  
    // Binding newly created socket to given IP and verification 
    if ((rump_sys_bind(sock, (const struct sockaddr *)&client_addr, sizeof(client_addr))) != 0) { 
        printf("socket bind failed...\n"); 
        rump_sys_close(tunfd);
        rump_sys_close(sock);
        __builtin_trap();
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
	static bool Initialized;

	if (!Initialized) {
		Initialize();
		Initialized = true;
	}

	if (ip_output_fuzz(Data, Size)) {
		/**
		 * We shall return 0 on error paths as otherwise
		 * a fuzzer (honggfuzz) restarts the fuzzing process 
		 * and restarting the program costs time.
		 */
		return 0;
	}

	return 0;
}

#ifdef MAIN
/* For manual testing only. */
int
main()
{
    // We initialize rump
    rump_init();

    int errno;
    int sock = 0; 
    struct sockaddr_in serv_addr; 
    struct sockaddr_in client_addr;

    // Setting up the tun device
	int tunfd = netcfg_rump_if_tun("/dev/tun0", "tun0", "192.168.0.5", "255.255.255.0", "192.168.0.1");
    if(tunfd < 0)
	{
		printf("Error in creating and configuring tun0 device");
		return -1;
	}

    // Creating the socket
    if ((sock = rump_sys_socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
        rump_sys_close(sock);
        return -1; 
    } 
   
    
    // Setting socket addresses for using with ip src and dest
    client_addr.sin_family = AF_INET;
    serv_addr.sin_family = AF_INET;
    if(inet_pton(AF_INET, "192.168.0.1", &serv_addr.sin_addr)<=0)  // Convert IPv4 addresses from text to binary form 
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        rump_sys_close(tunfd);
        rump_sys_close(sock);
        return -1; 
    }
    if(inet_pton(AF_INET, "192.168.0.5", &client_addr.sin_addr)<=0)  
    { 
        printf("\nInvalid address/ Address not supported \n"); 
        rump_sys_close(tunfd);
        rump_sys_close(sock);
        return -1; 
    }
  
    // Binding newly created socket to given IP and verification 
    if ((rump_sys_bind(sock, (const struct sockaddr *)&client_addr, sizeof(client_addr))) != 0) { 
        printf("socket bind failed...\n"); 
        rump_sys_close(tunfd);
        rump_sys_close(sock);
        return -1;
    }

    // Preparing the IP packet
    int bufLen = 30; // Bytes;
    char randBuf[bufLen];
    memcpy(&randBuf, "abcdefghijklmnopqrstuvwxyzabcd", bufLen);

    // randBuf holds the final packet
    pkt_create_ipv4(randBuf, bufLen);

    // Setting the header included flag for RAW IP to not touch the IP header
    int one=1;
    const int *val = &one;
    if (rump_sys_setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        printf ("Warning: Cannot set HDRINCL!\n");
        rump_sys_close(tunfd);
        rump_sys_close(sock);
        return -1;
    }


    // Sending down the socket
    int written = rump_sys_sendto(sock , randBuf , bufLen , 0, (struct sockaddr *) &serv_addr, sizeof (serv_addr));
    if (written == -1)
    {
        printf("sendto failed\n");
        perror("Error in sending:");
    }
    else if ((size_t)written != bufLen)
    {
        printf("sendto did not write all data\n");
        printf("Amount of buffer written: %d\n", written);
    }
    else{
        printf("All data written\n");
    }

    // Close and return
    rump_sys_close(tunfd);
    rump_sys_close(sock);
    return 0;    
}
#endif