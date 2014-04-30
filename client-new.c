#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/ip6.h>

#define BUF_SIZE 500
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

		#define IPV6_TLV_ROUTERALERT 5
		#define IPV6_TLV_DFF 0XEE

#endif

void fill_hop_by_hop_options();
uint16_t sequence_number();
void print_opt(void *, socklen_t);

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

	while(1)
	{
	
		if ((sock_fd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0){
			perror("socket() error");
			exit(EXIT_FAILURE);
		}
	
		fill_hop_by_hop_options();	// fills the msg headers with the options
		sleep(1);
		if (sendmsg(sock_fd, &msg, 0) < 0)
		{
			perror("sendmsg()");
			exit(EXIT_FAILURE);
		}
		printf("data sent\n");
		
		#if 1	
		if (recvmsg(sock_fd, &msg, 0) < 0)
		{
			perror("recvmsg()");
			exit(EXIT_FAILURE);
		}
		print_opt(extbuf, extlen);
		printf("recevied response\n");
		#endif
	}
	return 0;
}

	// Making ancillary data for sendmsg()
	void fill_hop_by_hop_options()
	{
		#if 0 
		//uint16_t number = 1;	// used for sequence number
	        //struct cmsghdr *cmsg;
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

		#define IPV6_TLV_ROUTERALERT 5
		#define IPV6_TLV_DFF 0XEE

		#endif

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
		memset(&msg, 0, sizeof(msg));
		memset(&buffer2, 'B', sizeof(buffer2));
	
		//sending hop by hop option headers as ancillary data
	
		currentlen = inet6_opt_init(NULL,0);
        	if (currentlen == -1){
        	        perror("1st opt_init");
        	        exit(EXIT_FAILURE);
        	}
        	printf("Hop by Hop length: %d\n", currentlen);
	
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
	
	
        	currentlen = inet6_opt_finish(extbuf, extlen, currentlen);
        	if (currentlen == -1)
        	        perror("opt_finish");
	
		//printf("struct size:%d\n",msg.msg_namelen);	
        	server_addr.sin6_family = AF_INET6;
        	server_addr.sin6_port = htons(8989);
        	server_addr.sin6_scope_id = if_nametoindex("eth0");
	
        	pton_fd = inet_pton(AF_INET6, "2001::3", &(server_addr.sin6_addr));
	
        		if(pton_fd < 0)
        		{
        	        	perror("pton error");
        	        	exit(EXIT_FAILURE);
        		}	
	
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
	
	}

uint16_t sequence_number()
{
	//number = number + 1;
	return number++;
}

void
print_opt(void *extptr, socklen_t extension_len)
{

        printf("Inside the extern function\n");
        int     currentlen;
        uint8_t         type;
        socklen_t       len;
        void            *databuf;
        uint8_t         flags;
        uint16_t        seq_no;
        struct ip6_hbh  *ext;

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




      

