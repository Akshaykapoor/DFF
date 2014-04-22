#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ip6.h>

//#include "dff.h"

#define BUF_SIZE 500

int
main(int argc, char *argv[])
{
    char *src_ip, *dst_ip;
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sfd, s, j;
    size_t len;
    ssize_t nread;
    char buf[BUF_SIZE];
    struct ip6_hdr ip6hdr;
    //struct dff_header dff;
/*
   if (argc < 3) {
        fprintf(stderr, "Usage: %s host port msg...\n", argv[0]);
        exit(EXIT_FAILURE);
    }
*/
   /* Obtain address(es) matching host/port */
#if 0
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET6;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol */

   s = getaddrinfo("fe80::a00:27ff:fe30:9ae9%eth0", "8888", &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }
#endif

   /* getaddrinfo() returns a list of address structures.
       Try each address until we successfully connect(2).
       If socket(2) (or connect(2)) fails, we (close the socket
       and) try the next address. */

#if 0
   for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        //  sfd = socket(AF_INET6, SOCK_DGRAM, 255);
        if (sfd == -1)
            continue;

       if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
            break;                  

       close(sfd);
    }

   if (rp == NULL) {               // No address succeeded 
        fprintf(stderr, "Could not connect\n");
        exit(EXIT_FAILURE);
    }
#endif
   // Let the kernel compute the checksum for the packets
#if 0
   int offset = 2;
   if(setsockopt(sfd, IPPROTO_IPV6, IPV6_CHECKSUM, &offset, sizeof(offset)) < 0)
   {
      perror("setsockopt()");
      exit(EXIT_FAILURE);
   }

   freeaddrinfo(result);           /* No longer needed */
#endif
#if 0
   /* Send remaining command-line arguments as separate
       datagrams, and read responses from server */

   // Making the IPv6 header

   strcpy(src_ip,"fe80::a00:27ff:fe98:bb2b");
   strcpy(dst_ip,"::1");
   ip6hdr.ip6_flow = htonl ((6<<28) | (0<<20) | 0);
   ip6hdr.ip6_plen = htons(40);
   ip6hdr.ip6_nxt = 255;
   ip6hdr.ip6_hops = 255;

   if ((status = inet_pton(AF_INET6, src_ip, &(ip6hdr.ip6_src))) != 1)
   {
      fprintf(stderr,"inet_pton() failed.\nError message: %s",strerror(status));      exit(EXIT_FAILURE);
   }

 
   if ((status = inet_pton(AF_INET6, dst_ip, &(ip6hdr.ip6_dst))) != 1)
   {
      fprintf(stderr,"inet_pton() failed.\nError message: %s",strerror(status));      exit(EXIT_FAILURE);
   }

#endif

	// Making ancillary data for sendmsg()

        struct cmsghdr *cmsg;
        struct msghdr msg;
        struct iovec iov[1];
        struct sockaddr_in6 server_addr;
        char buffer[50];
	char buffer2[50];
        int pton_fd;
	int sock_fd;
	int currentlen;
	void *extbuf;
	socklen_t extlen;
	void *databuf;
	int offset;
	uint16_t value2;
	int cmsglen;

	#define IPV6_TLV_ROUTERALERT 5
	#define IPV6_TLV_DFF 0XEE

	if ((sock_fd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0){
		perror("socket() error");
		exit(EXIT_FAILURE);
	}

	//TODO try setsockopt() as an option for HopbyHop
	int on = 2;
#if 0
	if (setsockopt(sock_fd, IPPROTO_IPV6, IPV6_HOPOPTS, &on, sizeof(on)) < 0) {
		perror("setcokopt()");
		exit(EXIT_FAILURE);	
	}
#endif
	printf("sock_fd:%d\n", sock_fd);

	printf("sock fd:%d\n", sock_fd);

        memset(&buffer,'A', sizeof(buffer));
	//memset(cmsg, 0, sizeof(struct cmsghdr));
	memset(&buffer2, 'B', sizeof(buffer2));

	//sending hop by hop option headers as ancillary data

	currentlen = inet6_opt_init(NULL,0);
        if (currentlen == -1){
                perror("1st opt_init");
                exit(EXIT_FAILURE);
        }
        printf("Hop by Hop length: %d\n", currentlen);

        currentlen = inet6_opt_append(NULL, 0, currentlen, IPV6_TLV_ROUTERALERT, 2, 2, NULL);
        if (currentlen == -1) {
                perror("append() error");
                exit(EXIT_FAILURE);
        }

        currentlen = inet6_opt_finish(NULL, 0, currentlen);
        if (currentlen == -1) {
                perror("1st opt_finish");
                exit(EXIT_FAILURE);
        }

        printf("currentlen: %d\n",currentlen);
        extlen = currentlen;

	//initailising CMESG header for hop by hop options.
	cmsglen = CMSG_SPACE(extlen);
	cmsg = malloc(cmsglen);

        if (cmsg == NULL) {
                perror("malloc");
                exit(EXIT_FAILURE);
        }

	cmsg->cmsg_len = CMSG_LEN(extlen);
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_HOPOPTS;
        extbuf = CMSG_DATA(cmsg);

        printf("Size of extbuf: %ld\n",sizeof(extbuf));

	currentlen = inet6_opt_init(extbuf, extlen);
        if (currentlen == -1) {
                perror("2nd opt_init");
                exit(EXIT_FAILURE);
        }

	currentlen = inet6_opt_append(extbuf, extlen, currentlen, IPV6_TLV_ROUTERALERT, 2, 2, &databuf);
        if (currentlen == -1) {
                perror("append() error");
                exit(EXIT_FAILURE);
        }
	
	offset = 0;
	value2 = 0x1211;
        offset = inet6_opt_set_val(databuf, offset, &value2, sizeof(value2));


        currentlen = inet6_opt_finish(extbuf, extlen, currentlen);
        if (currentlen == -1)
                perror("opt_finish");


        iov[0].iov_base = extbuf;
        iov[0].iov_len = sizeof(extbuf);
	//iov[1].iov_base = buffer2;
	//iov[1].iov_len = sizeof(buffer2);
        msg.msg_name = (struct sockaddr *)&server_addr;
        msg.msg_namelen = sizeof(server_addr);
	msg.msg_control = cmsg;
	msg.msg_controllen = cmsglen;
	msg.msg_flags = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

        server_addr.sin6_family = AF_INET6;
        server_addr.sin6_port = htons(8989);
        server_addr.sin6_scope_id = if_nametoindex("eth0");

        pton_fd = inet_pton(AF_INET6, "fe80::a00:27ff:fe30:9ae9", &(server_addr.sin6_addr));

        if(pton_fd < 0)
        {
                perror("pton error");
                exit(EXIT_FAILURE);
        }

# if 0
   for (j = 3; j < argc; j++) {
        len = strlen(argv[j]) + 1;
                /* +1 for terminating null byte */

       if (len + 1 > BUF_SIZE) {
            fprintf(stderr,
                    "Ignoring long message in argument %d\n", j);
            continue;
        }

       if (send(sfd, argv[j], len, 0) != len) {
            fprintf(stderr, "partial/failed write\n");
            exit(EXIT_FAILURE);
        }
#endif
while(1)
{
	if (sendmsg(sock_fd, &msg, 0) < 0)
	{
		perror("sendmsg()");
		exit(EXIT_FAILURE);
	}
	printf("data sent\n");
	
}
	//printf("MSg %s\n", argv[j]);
	//printf("Number of bytes to write: %ld\n", len);
	
	
        nread = read(sfd, buf, BUF_SIZE);
        if (nread == -1) {
            perror("read");
            exit(EXIT_FAILURE);
        }

       printf("Received %ld bytes: %s\n", (long) nread, buf);
       //printPacket(buf);

   exit(EXIT_SUCCESS);
}



      

