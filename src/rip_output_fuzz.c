#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<fcntl.h>
#include<unistd.h>

#include<netinet/in.h>
#include<netinet/ip.h>

#include"pkt_create.h"


int
main()
{
    int sock = 0; 
    struct sockaddr_in serv_addr; 
    struct sockaddr_in client_addr;

    // Creating the socket
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) 
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
    int bufSize = 30; // Bytes;
    char randBuf[bufSize];
    memcpy(&randBuf, "abcdefghijklmnopqrstuvwxyzabcd", bufSize);

    // randBuf holds the final packet
    pkt_create_ipv4(randBuf, bufSize);

    // Setting the header included flag for RAW IP to not touch the IP header
    int one=1;
    const int *val = &one;
    if (setsockopt (sock, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        printf ("Warning: Cannot set HDRINCL!\n");
        return -1;
    }


    // Sending down the socket
    sendto(sock , randBuf , bufSize , 0, (struct sockaddr *) &client_addr, sizeof (client_addr));

    // Close and return
    close(sock);
    return 0;    
}