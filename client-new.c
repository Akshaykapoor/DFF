#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ip6.h>
#include <errno.h>
#include <pthread.h>

#define IPV6_TLV_DFF 0XEE
#define BUF_SIZE 500
#define SIZE 1000
static uint16_t number = 1; //used for sequence number
//struct msghdr msg; //global beacuse used in fill() and sendmsg()
//struct sockaddr_in6 server_addr;
//struct cmsghdr *cmsg;

#if 1 
		//uint16_t number = 1;	// used for sequence number
	        struct cmsghdr *cmsg;
        	struct msghdr msg;
        	struct iovec iov[1];
	        struct sockaddr_in6 server_addr;
	        //char buffer[50];
		//char buffer2[50];
        	int pton_fd;
		int sock_fd;
		//int currentlen;
		void *extbuf;
		socklen_t extlen;
		//void *databuf;
		//int offset;
		//uint8_t value1;
		uint16_t value2;
		int cmsglen;


#endif

int ret1, ret2;

void fill_hop_by_hop_options();
uint16_t sequence_number();
void print_opt(void *, socklen_t);
void* sending_handler();
void* receiving_handler();

struct Processed_set 
{
uint16_t seq_no;
struct in6_addr orig_addr;
struct msghdr packet_data;
};

struct Processed_set processed_set[SIZE];


int
main(int argc, char *argv[])
{

    int sock_fd;
    char *src_ip, *dst_ip;
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sfd, s, j;
    size_t len;
    ssize_t nread;
    char buf[BUF_SIZE];
    struct ip6_hdr ip6hdr;

    pthread_t sending_thread;
    pthread_t receiving_thread;

    int send_err;
    int recv_err;
    int*ptr[2];
   
    send_err = pthread_create(&sending_thread, NULL, &sending_handler, NULL);
    if (send_err != 0)
	fprintf(stderr, "can't craete thread: %s\n",strerror(send_err));
    else
	fprintf(stderr, "thread created\n");

    recv_err = pthread_create(&receiving_thread, NULL, &receiving_handler, NULL);   
    if (recv_err != 0)
	fprintf(stderr, "cant create receiver thread: %s\n",strerror(recv_err));
    else
	fprintf(stderr, "receiver thread created\n");

    pthread_join(sending_thread, (void**)&(ptr[0]));
    pthread_join(receiving_thread, (void**)&(ptr[1]));

   return 0;

}    

void* sending_handler()
{

		#if 0
		struct cmsghdr *cmsg;
        	struct msghdr *msg;
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
		uint8_t value1;
		uint16_t value2;
		int cmsglen;
		#endif

		int sock_fd;
		//struct msghdr *msg;
	
		if ((sock_fd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0){
			perror("socket() error");
			exit(EXIT_FAILURE);
		}
	struct sockaddr_in6 *sender_address = malloc(sizeof(struct sockaddr_in6));
	char buf[INET_ADDRSTRLEN];
	
	int i = 0;
	while (1)
	{

		fill_hop_by_hop_options();	// fills the msg headers with the options
		sleep(1);
	
		if(processed_set[i].seq_no == -1)
			continue;

		processed_set[i++].seq_no = value2;
		printf("sequence_no: %x\n", value2);

		sender_address = (struct sockaddr_in6 *)msg.msg_name;
		//printf("address: %s\n", inet_ntop(AF_INET6, &sender_address->sin6_addr, buf,sizeof(buf)));
		processed_set[i++].orig_addr = (struct in6_addr)sender_address->sin6_addr;
		processed_set[i++].packet_data = msg;

		if (sendmsg(sock_fd, &msg, 0) < 0)
		{
			perror("sendmsg()");
			exit(EXIT_FAILURE);
		}
		printf("data sent\n");

		#if 0
		int bytes_read;
		int retry_count = 0;
		bytes_read = recvmsg(sock_fd, &msg, MSG_DONTWAIT);
		if (retry_count < 5 && errno !=EAGAIN && bytes_read < 0)
		{
			printf("Trying to listen again...\n");
			retry_count++;
		}
		else if(errno != EAGAIN)
		{
			perror("recvmsg");
			exit(EXIT_FAILURE);
		}
		//print_opt(extbuf, extlen);
		printf("recevied response\n");
		#endif
		//pthread_exit(&ret1);
	}
	pthread_exit(&ret1);
}

void* receiving_handler()
{
	struct addrinfo *result, *rp;
	struct addrinfo hints;

	int recv_fd;
	int retry_count = 0;
	int bytes_read;

	struct sockaddr_in6 recv_addr;
	struct msghdr *recv_msg = (struct msghdr*)malloc(sizeof(struct msghdr));
	struct iovec recv_iov[1];
	struct cmsghdr *cmsgptr;
	socklen_t cmsgspace;
	void *extptr;
	int extension_len;
	char buffer[200];
	int len; 
	int s;
	char port[] = "9898";

	memset(&recv_addr, 0, sizeof(recv_addr));
	memset(recv_iov, 0, sizeof(iov));
	memset(recv_msg, 0, sizeof(recv_msg));
	memset(&buffer, 0, sizeof(buffer));
	
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = 0;
	hints.ai_addr = NULL;
	hints.ai_canonname = NULL;
	hints.ai_next = NULL;

	s = getaddrinfo(NULL, port, &hints, &result);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n",gai_strerror(s));
		exit(EXIT_FAILURE);
	}

	/* getaddrinfo() returns a list of address structures.
	   Try each until we successfully bind()
           If socket() or bind() fails, we close the socket and
           try the next address. */

	for(rp = result; rp != NULL; rp = rp->ai_next) 
	{
		recv_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (recv_fd == -1)
			continue;
		if(bind(recv_fd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;
		close(recv_fd);
	}

	if (rp == NULL) {
		fprintf(stderr, "Could not bind\n");
		exit(EXIT_FAILURE);
	}
	

	//printf("recv_fd: %d\n",recv_fd);
	int setsock_offset = 1;
	if (setsockopt(recv_fd, IPPROTO_IPV6, IPV6_RECVHOPOPTS, &setsock_offset, sizeof(setsock_offset)) < 0)
        {
                perror("setsockopt");
                exit(EXIT_FAILURE);
        }

	freeaddrinfo(result); /* no longer needed */

        len = inet6_opt_init(NULL,0);
        if (len == -1){
                perror("1st opt_init");
                exit(EXIT_FAILURE);
        }
         
	//printf("Hop by Hop length: %d\n", len);
 
        len = inet6_opt_append(NULL, 0, len, IPV6_TLV_DFF, 3, 2, NULL);
        
	if (len == -1) {
	        perror("append() error");
                exit(EXIT_FAILURE);
        }
 
        len = inet6_opt_finish(NULL, 0, len);
        if (len == -1) {
                perror("1st opt_finish");
                exit(EXIT_FAILURE);
        }
 
        //printf("currentlen: %d\n",len);
        extension_len = len;

        cmsgspace = CMSG_SPACE(extlen);
        cmsgptr = malloc(cmsgspace);
 
        if (cmsgptr == NULL) {
              perror("malloc");
              exit(EXIT_FAILURE);
        }
 
        extptr = CMSG_DATA(cmsgptr);
	
	recv_msg->msg_control = cmsgptr;
	recv_msg->msg_controllen = cmsgspace;
	recv_msg->msg_name = &recv_addr;
	recv_msg->msg_namelen = sizeof(recv_addr);
	recv_msg->msg_iov = recv_iov;
	recv_msg->msg_iovlen = 1;
	recv_msg->msg_flags = 0;
	recv_iov[0].iov_base = extptr;	
	recv_iov[0].iov_len = sizeof(extptr);

	printf("recf_fd:%d\n",recv_fd);



	while(1)
	{
		sleep(1);
                bytes_read = recvmsg(recv_fd, recv_msg, MSG_DONTWAIT);
                if (bytes_read < 0)
                {
                        printf("Trying to listen again...\n");
                        retry_count++;
			printf("received nothin....\n");
                }
                else if (bytes_read > 0)
                {
			if(recv_msg->msg_controllen != 0 &&
			   cmsgptr->cmsg_level == IPPROTO_IPV6 &&
			   cmsgptr->cmsg_type == IPV6_HOPOPTS) {
				
                        	print_opt(extptr, extension_len);

			}
			else
				printf("Packet does not contain HBH options\n");

                        printf("received response\n");
                }
	}
	pthread_exit(&ret2);
}


// Making ancillary data for sendmsg()
void fill_hop_by_hop_options()
	{
		#if 0
		//uint16_t number = 1;	// used for sequence number
	        struct cmsghdr *cmsg;
        	//struct msghdr msg;
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
		uint8_t value1;
		uint16_t value2;
		int cmsglen;

		#endif
		int currentlen;
		int offset;
		uint8_t value1;
		//uint16_t value2;
		void *databuf;
		
		//TODO try setsockopt() as an option for HopbyHop

		//sending hop by hop option headers as ancillary data
	
		currentlen = inet6_opt_init(NULL,0);
        	if (currentlen == -1){
        	        perror("1st opt_init");
        	        exit(EXIT_FAILURE);
        	}
        	//printf("Hop by Hop length: %d\n", currentlen);
	
        	currentlen = inet6_opt_append(NULL, 0, currentlen, IPV6_TLV_DFF, 3, 2, NULL);
        	if (currentlen == -1) {
        	        perror("append() error");
        	        exit(EXIT_FAILURE);
        	}
	
        	currentlen = inet6_opt_finish(NULL, 0, currentlen);
        	if (currentlen == -1) {
        	        perror("1st opt_finish");
        	        exit(EXIT_FAILURE);
        	}
	
        	//printf("currentlen: %d\n",currentlen);
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
	
        	//printf("Size of extbuf: %ld\n",sizeof(extbuf));
	
		currentlen = inet6_opt_init(extbuf, extlen);
        	if (currentlen == -1) {
        	        perror("2nd opt_init");
        	        exit(EXIT_FAILURE);
        	}
	
		currentlen = inet6_opt_append(extbuf, extlen, currentlen, IPV6_TLV_DFF, 3, 2, &databuf);
        	if (currentlen == -1) {
        	        perror("append() error");
        	        exit(EXIT_FAILURE);
        	}
		
		offset = 0;
		value1 = 0x01;
		offset = inet6_opt_set_val(databuf, offset, &value1, sizeof(value1));
	
		//value2 = 0x1211;
		value2 = sequence_number();
        	offset = inet6_opt_set_val(databuf, offset, &value2, sizeof(value2));
	
		printf("Inside fun sequence number:%x\n",value2);
        	currentlen = inet6_opt_finish(extbuf, extlen, currentlen);
        	if (currentlen == -1)
        	        perror("opt_finish");
	
		//printf("struct size:%d\n",msg.msg_namelen);	
        	server_addr.sin6_family = AF_INET6;
        	server_addr.sin6_port = htons(8989);
        	server_addr.sin6_scope_id = if_nametoindex("eth0");
	
        	pton_fd = inet_pton(AF_INET6, "2001::1", &(server_addr.sin6_addr));
	
        		if(pton_fd < 0)
        		{
        	        	perror("pton error");
        	        	exit(EXIT_FAILURE);
        		}	
	
        	iov[0].iov_base = extbuf;
        	iov[0].iov_len = sizeof(extbuf);
        	msg.msg_name = (struct sockaddr *)&server_addr;
        	msg.msg_namelen = sizeof(server_addr);
		msg.msg_control = cmsg;
		msg.msg_controllen = cmsglen;
		msg.msg_flags = 0;
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
	
	}

uint16_t sequence_number()
{
	//number = number + 1;
	return number++;
}

#if 1
void
print_opt(void *extptr, socklen_t extension_len)
{

        printf("Printing received response \n");
        int     currentlen;
        uint8_t         type;
        socklen_t       len;
        void            *databuf;
        uint8_t         flags;
        uint16_t        seq_no;
        struct ip6_hbh  *ext;
	int offset;

        memset(&ext, 0, sizeof(&ext));
        currentlen = 0;
        ext = (struct ip6_hbh *)extptr;
        printf("nxt %u, len %u (bytes %d)\n", ext->ip6h_nxt, ext->ip6h_len, (ext->ip6h_len + 1) * 8);

        currentlen = inet6_opt_next(extptr, extension_len, currentlen, &type, &len, &databuf);
        if (currentlen == -1)
        {
                perror("opt_next()");
                exit(EXIT_FAILURE);
        }

        printf("Received opt %u len %u\n",type, len);
        
        switch(type)
        {
                case IPV6_TLV_DFF:
		  	offset = 0;
                        offset = inet6_opt_get_val(databuf, offset, &flags, sizeof(flags));
                        printf("Flag field is %x\n",flags);

                        offset = inet6_opt_get_val(databuf, offset, &seq_no, sizeof(seq_no));

                        printf("Seq no: %x\n",seq_no);
                        break;
                default:
                        printf("Received unknown option\n");
                        break;
        }
}
#endif

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

	//printf("MSg %s\n", argv[j]);
	//printf("Number of bytes to write: %ld\n", len);
	
#if 0	
        nread = read(sfd, buf, BUF_SIZE);
        if (nread == -1) {
            perror("read");
            exit(EXIT_FAILURE);
        }

       printf("Received %ld bytes: %s\n", (long) nread, buf);
       //printPacket(buf);

   exit(EXIT_SUCCESS);
}
#endif




      

