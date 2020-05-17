#include<fcntl.h>
#include<unistd.h>
#include<stdio.h>
#include<sys/ioctl.h>
#include<stdlib.h>
#include<string.h>

#include<net/if.h>
#include<net/if_tun.h>

#define TUN_PATH "/dev/tun0"

int tun_alloc() {

	struct ifreq ifr;
	int fd, err;

	/* open the clone device */
	if((fd = open(TUN_PATH,O_RDWR)) < 0 ) {
		printf("Error in opening the fd\n");
		return fd;
	}

	// /* preparation of the struct ifr, of type "struct ifreq" */
	// memset(&ifr, 0, sizeof(ifr));
	// ifr.ifr_flags = IFF_UP;   /* Setting the Device up */

	// /* try to initialize the address */
	// if((err = ioctl(fd, SIOCGIFFLAGS, &ifr)) < 0 ) {
	// 	printf("Error in IOCTL call\n");
	// 	close(fd);
	// 	return err;
	// }

	// printf("flags: %d", ifr.ifr_flags);

	// // /* if the operation was successful, write back the name of the
	// // * interface to the variable "dev", so the caller can know
	// // * it. Note that the caller MUST reserve space in *dev (see calling
	// // * code below) */
	// // strcpy(dev, ifr.ifr_name);

	// // /* this is the special file descriptor that the caller will use to talk
	// // * with the virtual interface */
	int written = write(fd, "", 0);
	printf("Data written: %d\n", write);

	close(fd);
	return fd;
}

int main()
{
	int fd = tun_alloc();
	if(fd<0)
		printf("Error in the tun allocation: %d\n", fd);
	else
		printf("The FD is: %d\n", fd);
	
}
