#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>

#define BUF_SIZE 500

int
main(int argc, char *argv[])
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sfd, s;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;
    ssize_t nread;
    char buf[BUF_SIZE];


   if (argc != 2) {
        fprintf(stderr, "Usage: %s port\n", argv[0]);
        exit(EXIT_FAILURE);
    }

   memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET6;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
    hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
    hints.ai_protocol = 0;          /* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

   s = getaddrinfo(NULL, argv[1], &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }

   /* getaddrinfo() returns a list of address structures.
       Try each address until we successfully bind(2).
       If socket(2) (or bind(2)) fails, we (close the socket
       and) try the next address. */

   for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype,
                rp->ai_protocol);
       if (sfd == -1)
            continue;

       if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;                  /* Success */

       close(sfd);
    }

   if (rp == NULL) {               /* No address succeeded */
        fprintf(stderr, "Could not bind\n");
        exit(EXIT_FAILURE);
    }


   int setsock_offset = 1;
#if 1 
   if (setsockopt(sfd, IPPROTO_IPV6, IPV6_RECVHOPOPTS, &setsock_offset, sizeof(setsock_offset)) < 0)
        {
                perror("setsockopt");
                exit(EXIT_FAILURE);
        }
#endif
   freeaddrinfo(result);           /* No longer needed */

   /* Read datagrams and echo them back to sender */

   // Ancillary data for recvmsg()

	struct sockaddr_storage recv_addr;
	struct cmsghdr *cmsgptr;
	struct msghdr msg;
	struct iovec iov[1];
	char buffer[100];
	int bytes_read ;
	int currentlen, extension_len;
	void *extptr;
	socklen_t cmsgspace;
	#define IPV6_TLV_ROUTERALERT 5
	#define IPV6_TLV_DFF 0xEE

	memset(&buffer, 0, sizeof(buffer));
	memset(&recv_addr, 0, sizeof(recv_addr));	
	memset(iov, 0, sizeof(iov));
	memset(&msg, 0, sizeof(msg));
	//memset(cmsgptr, 0, sizeof(cmsgptr));
	
	currentlen = inet6_opt_init(NULL,0);
        if (currentlen == -1)
        {
                perror("1st opt_init");
                exit(EXIT_FAILURE);
        }

        currentlen = inet6_opt_append(NULL, 0, currentlen, IPV6_TLV_DFF, 3, 2, NULL);
        if (currentlen == -1)
        {
                perror("1st append");
                exit(EXIT_FAILURE);
        }

        currentlen = inet6_opt_finish(NULL, 0, currentlen);
        if (currentlen == -1)
        {
                perror("1st finish");
                exit(EXIT_FAILURE);
        }

        extension_len = currentlen;
        cmsgspace = CMSG_SPACE(extension_len);
	printf("cmsgspace:%d\n",cmsgspace);
        cmsgptr = malloc(cmsgspace);
        if (cmsgptr == NULL)
        {
                perror("malloc");
                exit(EXIT_FAILURE);
        }

        extptr = CMSG_DATA(cmsgptr);



	iov[0].iov_base = buffer;
	iov[0].iov_len = sizeof(buffer);
	msg.msg_name = &recv_addr;
	msg.msg_namelen = sizeof(recv_addr);
	msg.msg_control = cmsgptr;
	msg.msg_controllen = cmsgspace;
	msg.msg_flags = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;


	while(1)
	{
		if((bytes_read = recvmsg(sfd, &msg, 0)) == -1) {
			perror("recvmsg() error");
			exit(EXIT_FAILURE);
		}
		else
			printf("successful\n");
	
		if (msg.msg_controllen !=0 && 
		    cmsgptr->cmsg_level == IPPROTO_IPV6 &&
		    cmsgptr->cmsg_type == IPV6_HOPOPTS)
			printf("received ancillary data\n");
	}

   for (;;) {
        peer_addr_len = sizeof(struct sockaddr_storage);
        nread = recvfrom(sfd, buf, BUF_SIZE, 0,
                (struct sockaddr *) &peer_addr, &peer_addr_len);
        if (nread == -1)
            continue;               /* Ignore failed request */

       char host[NI_MAXHOST], service[NI_MAXSERV];

       s = getnameinfo((struct sockaddr *) &peer_addr,
                        peer_addr_len, host, NI_MAXHOST,
                        service, NI_MAXSERV, NI_NUMERICSERV);
       if (s == 0)
            printf("Received %ld bytes from %s:%s\n",
                    (long) nread, host, service);
        else
            fprintf(stderr, "getnameinfo: %s\n", gai_strerror(s));

       if (sendto(sfd, buf, nread, 0,
                    (struct sockaddr *) &peer_addr,
                    peer_addr_len) != nread)
            fprintf(stderr, "Error sending response\n");
    }
}
