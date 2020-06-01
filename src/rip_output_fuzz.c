/**
 * To compile this file:
 * gcc pkt_create.c rip_output_fuzz.c -lrump -lrumpvfs -lrumpnet -lrumpnet_net -lrumpnet_netinet
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <rump/rump.h>
#include <rump/rump_syscalls.h>

#include "pkt_create.h"

int
main()
{
    // We initialize rump
    rump_init();

    int errno;
    int sock = 0; 
    struct sockaddr_in serv_addr; 
    struct sockaddr_in client_addr;

    // Creating the socket
    if ((sock = rump_sys_socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) 
    { 
        printf("\n Socket creation error \n"); 
        return -1; 
    } 
   
    
    // Setting socket addresses for using with ip src and dest
    client_addr.sin_family = AF_INET;
    serv_addr.sin_family = AF_INET;
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0)  // Convert IPv4 addresses from text to binary form 
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
    close(sock);
    return 0;    
}