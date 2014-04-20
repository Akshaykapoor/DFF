/*** IPPROTO_RAW receiver ***/
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip6.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

#define IPV6_TLV_ROUTERALERT 5
#define IPV6_TLV_DFF 0x1F

int print_options(void *, socklen_t);

int main(void)
{
	int s,ret;
	struct sockaddr_in6 clientaddr;
	struct sockaddr_storage src_addr;
	int clilen = sizeof(clientaddr);
	char packet[500] = {};
	int setsock_offset = 1;
	
	//-----for ancillary data
	int 			currentlen;
	void 			*extptr;
	struct sockaddr_in6 	addr;
	struct msghdr		msg;
	struct cmsghdr		*cmsgptr;
	struct iovec		iov[1];
	void 			*extbuf;
	socklen_t		extension_len;
	socklen_t 		extlen;
	socklen_t		cmsgspace;
	char 			databuf[800] = {};

	memset(packet, 0, sizeof(packet));
	memset(&cmsgptr, 0, sizeof(cmsgptr));
	memset(databuf, 0, sizeof(databuf));
	memset(&msg, 0, sizeof(msg));
	memset(&src_addr, 0, sizeof(src_addr));
	memset(iov, 0, sizeof(iov));

	if ((s = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("error:");
		exit(EXIT_FAILURE);
	}
#if 0
	
	if ( fcntl(s, F_SETFL, O_NONBLOCK) < 0) {
		perror("FCNTL ERROR");
		exit(EXIT_FAILURE);
	}
#endif
	
#if 1 
	if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVHOPOPTS, &setsock_offset, sizeof(setsock_offset)) < 0) 
	{
		perror("setsockopt");
		exit(EXIT_FAILURE);
	} 
#endif 	
	currentlen = inet6_opt_init(NULL,0);
	if (currentlen == -1)
	{
		perror("1st opt_init");
		exit(EXIT_FAILURE);
	}

	currentlen = inet6_opt_append(NULL,0,currentlen, IPV6_TLV_ROUTERALERT, 2, 2, NULL);
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
	cmsgptr = malloc(cmsgspace);
	if (cmsgptr == NULL)
	{
 		perror("malloc");
		exit(EXIT_FAILURE);
	}

	//cmsgptr->cmsg_len	= CMSG_LEN(extension_len);
	//cmsgptr->cmsg_level	= IPPROTO_IPV6;
	//cmsgptr->cmsg_type	= IPV6_HOPOPTS;	

	extptr = CMSG_DATA(cmsgptr);

	//socklen_t src_addr_len = (socklen_t)sizeof(src_addr);
	
	
	//memset(iov, 0, sizeof(iov));
	//memset(&src_addr, 0, sizeof(src_addr));

	iov[0].iov_base = databuf;
	iov[0].iov_len = sizeof(databuf);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;
	msg.msg_name = &src_addr;
	msg.msg_namelen = sizeof(src_addr);
	msg.msg_control = cmsgptr;
	msg.msg_controllen = cmsgspace;
	
	//memset(packet, 0, sizeof(packet));
	//memset(&src_addr, 0, sizeof(src_addr));
	socklen_t *len = (socklen_t *)sizeof(src_addr);
	//int fromlen = sizeof(src_addr);

	while(1) 
	{
		printf("Waiting for packets...\n");
#if 0	
		if (recvmsg(s, &msg, 0) == -1) 
		{
			perror("packet receive error:");
			return;
		}
		else
			printf("successful\n");
#endif		
#if 1
		memset(&clientaddr, 0, sizeof(clientaddr));
		clilen = sizeof (clientaddr);
		
		//if ((ret=recvfrom(s,packet,sizeof(packet),0,(struct sockaddr*)&clientaddr,&clilen))== -1)
		if ((ret=read(s,packet,sizeof(packet)))== -1)
		{
			perror("recvfrom error:");
			exit(EXIT_FAILURE);
		}else {
			printf("recvfrom success! bytes %d\n", ret);
		}

#endif
		if (msg.msg_controllen != 0 && 
		    cmsgptr->cmsg_level == IPPROTO_IPV6 &&
		    cmsgptr->cmsg_type == IPV6_HOPOPTS ) {
		
			print_options(extptr, extension_len);
			printf("Inside msg..header\n");
		}
	}
}

int print_options(void *extbuf, socklen_t extlen) 
{
	struct ip6_hbh *ext;
	int currentlen;
	uint8_t type;
	socklen_t len;
	void *databuf;
	int offset;
	uint8_t value;
	uint16_t value1;

	ext = (struct ip6_hbh *)extbuf;
	printf("nxt header %u, len: %u (bytes%d)\n", ext->ip6h_nxt, ext->ip6h_len, (ext->ip6h_len + 1)*8);

	currentlen = 0;
	while(1)
	{
		currentlen = inet6_opt_next(extbuf, extlen, currentlen, &type, &databuf);
		if(currentlen == -1)
			break;
		printf("Received opt %u len %u\n", type, len);
		switch(type)
		{
			case IPV6_TLV_DFF:
				offset = 0;
				offset = inet6_opt_get_val(databuf, offset, &value, sizeof(value) );
				printf("1 byte field %x\n", value);
				offset = inet6_opt_get_val(databuf, offset, &value1, sizeof(value1) );
				printf("2 byte field %x\n", value1);
				break;

			default:
				printf("unknown option :%x\n", type);
				break;
		}
	}
	return(0);
}			
