#include <sys/socket.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <time.h>
#include <netinet/udp.h>

#define DEST "::1"
#define IPV6_TLV_DFF 0xEE
#define IPV6_TLV_ROUTERALERT 5
#define NEXT_HOP 9
#define PADN 1

short unsigned sequence_number();
short unsigned number;


int main(void)
{

	int j=0, pton_fd;
	int i=0;
	struct ip6_hbh hbh_hdr;
  	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	struct udphdr *udphdr;
	int cmsglen;
	int tx_len;	//used for udp payload
	char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
	int s,status;
	struct sockaddr_in6 daddr;
	char packet[40];
	char payload[20];
	//uint8_t IP_DFF = 0xEE;
	//-----members for ancillary data-----------

	struct iovec iov[2];	
	void *extbuf;
	socklen_t extlen;
	int currentlen;
	void *databuf;
	int offset;
	uint8_t value;
	uint8_t value1;
	uint8_t value2;

	/* add payload after extension header */

	memset(payload,'A', sizeof(payload));
	
	/* point the iphdr to the beginning of the packet */
	struct ip6_hdr *ip = (struct ip6_hdr *)packet;  

	if ((s = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror("error:");
		exit(EXIT_FAILURE);
	}

     	int setsock_offset = 2;
	if(setsockopt(s, IPPROTO_IPV6, IPV6_CHECKSUM, &setsock_offset, sizeof(setsock_offset) < 0))
	{
	   perror("setsockopt");
	   exit(EXIT_FAILURE);
	}


	daddr.sin6_family = AF_INET6;
	daddr.sin6_port = 0; /* not needed in SOCK_RAW */
	daddr.sin6_scope_id = if_nametoindex("eth0");

	pton_fd = inet_pton(AF_INET6, "fe80::a00:27ff:fe30:9ae9", (struct in6_addr *)&daddr.sin6_addr.s6_addr);
	
	if (pton_fd == 0)
	{
		printf("Does not contain a character string representing a network address");
		exit(EXIT_FAILURE);
	}
	else if (pton_fd < 0)
	{
		perror("pton()");
		exit(EXIT_FAILURE);
	}

	ip->ip6_flow = htonl ((6<<28) | (0<<20) | 0);
	ip->ip6_plen = htons (28);
	ip->ip6_nxt = 0;
	ip->ip6_hops = 64;
#if 0	
	// Define TCP header
	udphdr->source	= htons(3423);
	udphdr->dest	= htons(5342);
	udphdr->check	= 0;
	tx_len += sizeof(struct udphdr);	
#endif	

	if ((status = inet_pton(AF_INET6, "fe80::921b:eff:fe03:637d", &(ip->ip6_src))) != 1)
   	{
      		fprintf(stderr,"inet_pton() failed.\nError message: %s",strerror(status));      exit(EXIT_FAILURE);
   	}


   	if ((status = inet_pton(AF_INET6, "fe80::a00:27ff:fe30:9ae9", &(ip->ip6_dst))) != 1)
   	{
      		fprintf(stderr,"inet_pton() failed.\nError message: %s",strerror(status));      exit(EXIT_FAILURE);
   	}


	// Specifying the ancillary data for Hop-by-Hop headers
	currentlen = inet6_opt_init(NULL,0);
	if (currentlen == -1){
		perror("1st opt_init");
		exit(EXIT_FAILURE);
	}
	printf("Hop by Hop length: %d\n", currentlen);
	
	// Setting Hop by Hop extension header next field
	//hbh_hdr.ip6h_nxt = 59;
	//hbh_hdr.ip6h_len = 0;

	currentlen = inet6_opt_append(NULL, 0, currentlen, IPV6_TLV_ROUTERALERT, 2, 1, NULL);
	if (currentlen == -1) {
		printf("ERROR NO: %d\n",errno);
		//perror("1st opt_append");
		fprintf(stderr, "append error %s, %s\n",strerror(errno),strerror(currentlen));
		exit(EXIT_FAILURE);
	}

	currentlen = inet6_opt_finish(NULL, 0, currentlen);
	if (currentlen == -1) {
		perror("1st opt_finish");
		exit(EXIT_FAILURE);
	}

	printf("currentlen: %d\n",currentlen);
	extlen = currentlen;

	cmsglen = CMSG_SPACE(extlen);
	cmsg = malloc(sizeof(cmsglen));
	if (cmsg == NULL) {
		perror("msg malloc");
		exit(EXIT_FAILURE);
	}

	cmsg->cmsg_len = CMSG_LEN(extlen);
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_HOPOPTS;
	extbuf = CMSG_DATA(cmsg);

	extbuf = malloc(extlen);
	printf("Size of extbuf: %ld",sizeof(extbuf));
	
	if (extbuf == NULL) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}


	printf("Extenlen: %d\n",extlen);

	//hbh_hdr.ip6h_nxt = 59;
	currentlen = inet6_opt_init(extbuf, extlen);
	if (currentlen == -1) {
		perror("2nd opt_init");
		exit(EXIT_FAILURE);
	}

	//extbuf = (unsigned char*)extbuf;
	//char ip6hop_nexth_value = 59;
	*(unsigned char*)(extbuf) = 59;
	unsigned char* temp = extbuf;

	//for(i=0; i<extlen;i++) {
	//	printf("Ext buffer is: %d\n",*temp);
	//	temp++;
	//}
	
	currentlen = inet6_opt_append(extbuf, extlen, currentlen, IPV6_TLV_ROUTERALERT, 2, 1, &databuf);
	if (currentlen == -1) {
		perror("append() error");
		exit(EXIT_FAILURE);
	}

	printf("len after append:%d\n", currentlen);

	//insert value for the version and flags 
	offset = 0;
	value = 0x11;
	offset = inet6_opt_set_val(databuf, offset, &value, sizeof(value));

	//value1 = 0x01;

	//printf("Data buffer is: %x\n",databuf);
	//offset = inet6_opt_set_val(databuf, offset, &value1, sizeof(value1));
	
	value2 = 0x12;
	offset = inet6_opt_set_val(databuf, offset, &value2, sizeof(value2));
      	
	currentlen = inet6_opt_finish(extbuf, extlen, currentlen);
	if (currentlen == -1)
		perror("opt_finish");
 	
	//*(uint8_t)(extbuf) = 59;
	printf("Data buffer is: %x\n",*(unsigned char*)(databuf));
	
	printf("Extlen is: %d\n",extlen);
	printf("Currentlen is: %d\n", currentlen);

	unsigned char* temp1 = databuf;
	for(j=0; j<3;j++) {
		printf("Data buffer is: %d\n",*temp1);
		temp1++;
	}

	for(i=0;i<extlen;i++) {
		printf("exbuf is:%d\n",*temp);
		temp++;
	}
/*
	cmsglen = CMSG_SPACE(extlen);
	cmsg = malloc(cmsglen);
	if (cmsg == NULL) {
		perror("msg malloc");
		exit(EXIT_FAILURE);
	}

	cmsg->cmsg_len = CMSG_LEN(extlen);
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_HOPOPTS;
	extbuf = CMSG_DATA(cmsg);
*/
	iov[0].iov_base = packet;
	iov[0].iov_len = sizeof(packet);
	iov[1].iov_base = extbuf;
	iov[1].iov_len = sizeof(extbuf);
	iov[2].iov_base = payload;
	iov[2].iov_len = sizeof(payload);
	//iov[2].iov_base = databuf;
	//iov[2].iov_len = sizeof(databuf);
	msg.msg_control = cmsg;
	msg.msg_controllen = cmsglen;
	msg.msg_name = (struct sockaddr*)&daddr;
	msg.msg_namelen = sizeof(daddr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 2;
	msg.msg_flags = 0;	
	while(1) {
		sleep(1);
		/*if (sendto(s, (char *)packet, sizeof(packet), 0, 
			(struct sockaddr *)&daddr, (socklen_t)sizeof(daddr)) < 0)
			perror("packet send error:");
	}*/
		if (sendmsg(s, &msg, 2) < 0) {
			perror("sendmsg()");
		}
		else
			printf("data sent\n");
	}
	exit(EXIT_SUCCESS);
}

short unsigned sequence_number()
{
	number = rand();
	return number;
}
