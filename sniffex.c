#include <pcap.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <assert.h>
#include <net/ethernet.h>
#include <netinet/ip6.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>
#include <pthread.h>
	
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518
#define ETH_P_802_EX1 0x88B5
/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

#define SIZE 100
#define ETH_P_802_EX1 0x88B5
#define IPV6_TLV_DFF 0xEE
/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};


// Global definitions for src and dest MAC

struct sniff_ethernet eth_header;
pthread_mutex_t lock;
pthread_mutex_t p_tuple_lock;

struct Stored_packet{ 
	short sequence_number;
	unsigned char message[78];
};
struct Stored_packet *stored_packet[SIZE];

struct parameters{
	u_char *param1;
	const struct pcap_pkthdr *param2;
	const u_char *param3;
};


struct Processed_set {
	short p_sequence_number;
	struct in6_addr p_origin_address;
	struct ether_addr p_prev_hop;
	struct ether_addr p_neighbor_list[SIZE];
};

struct Processed_set *processed_tuple[SIZE];

void initialize_Packet()
{
	int i;
	for(i=0; i< SIZE; i++)
		stored_packet[i] = NULL;
	
}

void initialize_Processed_set()
{
	int i;
	for(i = 0; i < SIZE; i++)
		processed_tuple[i] = NULL;
}

void
create_thread(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/*
 * used for sending neighbor discovery message 
 */

char* neigh_disc()
{
	FILE *fp;
	int status;
	char path[100];
	char *mac = malloc(sizeof(path));
	
	fp = popen("ndisc6 -1 2001::1 eth0 | awk '/Target/{print $4}'","r");
	if (fp == NULL) {
		perror("error in popen()");
		exit(EXIT_FAILURE);
	}

	while (fgets(path,100, fp) != NULL)
		//printf("%s", path);

	strcpy(mac, path);
	//printf("Mac from pointer: %s\n", mac);
	status = pclose(fp);
	if (status == -1) {
		perror("pclose error()");
		exit(EXIT_FAILURE);
	}
	return mac;
}

/*
 *disect/print packet
 */

int get_mac_address()
{
	struct ifreq  s;
	int fd = socket(AF_INET6, SOCK_DGRAM, 0);
	
	unsigned char *hwaddress = (unsigned char *)malloc(sizeof(ETHER_ADDR_LEN));
	strcpy(s.ifr_name, "eth0");
	
	if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) 
	{
		int i;
		for(i=0; i<6; ++i){
			//printf("%02x:",(unsigned char)s.ifr_addr.sa_data[i]);
			hwaddress[i] = (unsigned char)s.ifr_addr.sa_data[i]; 
		}
		//printf("hwaddres: %s",hwaddress);
		//printf("\n");
	}
	close(fd);
	return 1;
}


void fill_local_packet_pool(unsigned char* ip6_packet, short seq_no)
{

	int i = 0;
	while( stored_packet[i] != NULL)
	{
		i++;
		i=i%SIZE;
	}

	struct Stored_packet * tempPacket;
	tempPacket = (struct Stored_packet *) malloc(sizeof(struct Stored_packet));
	if( tempPacket == NULL)
	{
		printf("Error in malloc\n");
	}
	stored_packet[i]= tempPacket;

	memcpy( stored_packet[i]->message, ip6_packet, 78);
	stored_packet[i]->sequence_number = seq_no;

}


int check_for_prev_ack(short prev_seq_no)
{
	int i;
	pthread_mutex_lock(&lock);
	for(i=0; i < SIZE; i++)
	{
		if(stored_packet[i]->sequence_number == prev_seq_no)
			return 1;
		else
			continue;
	}
	return 0;
}

void set_ack(short seq_no)
{
	int i;
	pthread_mutex_lock(&lock);
	for(i=0;i<SIZE;i++)
	{
		if(stored_packet[i] != NULL )
		     if( stored_packet[i]->sequence_number == seq_no) {
			free(stored_packet[i]);
			stored_packet[i] = NULL;
			printf("Deleting the stored packet: %d ##################\n",seq_no);
		}
		else
			continue;
	}
	pthread_mutex_unlock(&lock);
	return;
}

#if 0
void send_l2_ack(struct ether_header * ethernet , short seq_no, struct ether_header *prev_ether_addr)
{
	char str[] = "08:00:27:35:8f:db";
	struct ether_addr *ea = ether_aton(str);
	struct sniff_ethernet eth_header;

	memcpy(&eth_header.ether_dhost,(void *) &ea->ether_addr_octet, sizeof(struct ether_addr));

	memcpy(&eth_header.ether_shost, &ethernet->ether_dhost, sizeof(struct ether_addr));

	eth_header.ether_type = htons(ETH_P_802_EX1);
	unsigned char frame[sizeof(struct ether_header) + sizeof(short)];
	memcpy(frame, &eth_header, sizeof(struct ether_header));
	memcpy(frame + sizeof(struct ether_header), &seq_no, sizeof(short));

	pcap_t *send_handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev;

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		fprintf(stderr, "Couldn't find device: %s\n",errbuf);
		exit(EXIT_FAILURE);
	}

	send_handle = pcap_open_live(dev, 96, 0, 0, errbuf);
	if (send_handle == NULL)
	{
		fprintf(stderr, "Couldn't open device: %s: %s\n",dev ,errbuf);
		exit(EXIT_FAILURE);
	}

	if (pcap_inject(send_handle, frame, sizeof(frame)) == -1)
	{
		pcap_perror(send_handle, 0);
		pcap_close(send_handle);
		exit(EXIT_FAILURE);
	}

	pcap_close(send_handle);
	printf("Sent L2 ack for seq_no:%x\n",seq_no);
}
#endif

#if 1
void send_l2_ack(struct ether_header * ethernet , short seq_no)
{
	char str[] = "08:00:27:e3:6f:5b";
	struct ether_addr *ea = ether_aton(str);
	struct sniff_ethernet eth_header;

	memcpy(&eth_header.ether_dhost, &ethernet->ether_shost, sizeof(struct ether_addr));

	memcpy(&eth_header.ether_shost, (void *)&ea->ether_addr_octet, sizeof(struct ether_addr));

	eth_header.ether_type = htons(ETH_P_802_EX1);
	unsigned char frame[sizeof(struct ether_header) + sizeof(short)];
	memcpy(frame, &eth_header, sizeof(struct ether_header));
	memcpy(frame + sizeof(struct ether_header), &seq_no, sizeof(short));

	pcap_t *send_handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev;

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		fprintf(stderr, "Couldn't find device: %s\n",errbuf);
		exit(EXIT_FAILURE);
	}

	send_handle = pcap_open_live(dev, 96, 0, 0, errbuf);
	if (send_handle == NULL)
	{
		fprintf(stderr, "Couldn't open device: %s: %s\n",dev ,errbuf);
		exit(EXIT_FAILURE);
	}

	if (pcap_inject(send_handle, frame, sizeof(frame)) == -1)
	{
		pcap_perror(send_handle, 0);
		pcap_close(send_handle);
		exit(EXIT_FAILURE);
	}

	pcap_close(send_handle);
	printf("Sent L2 ack for seq_no:%x\n",seq_no);
}
#endif

void send_to_next_hop(unsigned char *ip6_packet)
{
	

	struct sniff_ethernet *send_ether;

	send_ether = (struct sniff_ethernet *)(ip6_packet);

	char *mac_addr = neigh_disc();
	//printf("Mac addr is: %s\n", mac_addr);
	struct ether_addr *address = ether_aton(mac_addr);
	//printf("Address: %s\n", address->ether_addr_octet);	

	memcpy(&send_ether->ether_dhost, (void *)&address->ether_addr_octet, sizeof(struct ether_addr));	

	//get_mac_address();
	char str[] = "08:00:27:e3:6f:5b";
	struct ether_addr *ea = ether_aton(str);

	//ea = ether_aton(str);

	memcpy(&send_ether->ether_shost,(void *)&ea->ether_addr_octet, sizeof(struct ether_addr));

	
	pcap_t *send_handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev;

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		fprintf(stderr, "Couldn't find device: %s\n",errbuf);
		exit(EXIT_FAILURE);
	}

	send_handle = pcap_open_live(dev, 96, 0, 0, errbuf);
	if (send_handle == NULL)
	{
		fprintf(stderr, "Couldn't open device: %s: %s\n",dev ,errbuf);
		exit(EXIT_FAILURE);
	}

	//printf("size of ip6_packet:%d\n",sizeof(ip6_packet));
	if (pcap_inject(send_handle, ip6_packet, 78) == -1)
	{
		pcap_perror(send_handle, 0);
		pcap_close(send_handle);
		exit(EXIT_FAILURE);
	}

	pcap_close(send_handle);
	printf("Sent IP6 packet to next hop \n");

}

int check_for_processed_tuple(short seq_no, struct in6_addr *origin_addr)
{
	int i, temp;
	for(i = 0; i < SIZE; i++)
	{
		if(processed_tuple[i] != NULL) {
			if(processed_tuple[i]->p_sequence_number == seq_no)
			{
				temp = memcmp(&(processed_tuple[i]->p_origin_address), origin_addr, sizeof(struct in6_addr));
				if(temp == 0){
				    printf("Processed tuple exists\n");	
				    return 1;
				}
			}
		}
		else
			continue;
	}
	return 0;
}

/*When a packet is recived by a router, add in processed set only if it is 
not meant for that router. Befor adding check to see if there is an entry in the set or not. Check to see if it has the same p_orig_address and p_seq_no
If not then add an entry in the set, select the next hop to send to.

 */
void add_in_processed_set( struct in6_addr *orig_addr, short seq_no, struct ether_addr *prev_hop)
{
	int i;
	while (stored_packet[i] != NULL)	
	{
		i++;
		i = i%SIZE;
	}

	pthread_mutex_lock(&p_tuple_lock);
	struct Processed_set * tempTuple;
	tempTuple = (struct Processed_set *)malloc(sizeof(struct Processed_set));
	if (tempTuple == NULL)
		printf("Error in malloc\n");

	processed_tuple[i] = tempTuple;

	memcpy(&(processed_tuple[i]->p_origin_address), orig_addr, sizeof(struct in6_addr));	

	processed_tuple[i]->p_sequence_number = seq_no;

	memcpy(&(processed_tuple[i]->p_prev_hop), prev_hop, sizeof(struct ether_addr));

	printf("Entry made in Processed_set-------------------\n");
	
	pthread_mutex_unlock(&p_tuple_lock);
} 


void send_dropped_packet(int i)
{

	struct ether_header src;
	unsigned char *addr = (unsigned char *)malloc(sizeof(78));
	//for(i = 0; i < SIZE; i++)
	//{
		if (stored_packet[i] != NULL)
		{
			printf("Found packet in pool\n");
			addr =  stored_packet[i]->message;
		}
//	}

	pcap_t *send_handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev;

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		fprintf(stderr, "Couldn't find device: %s\n",errbuf);
		exit(EXIT_FAILURE);
	}

	send_handle = pcap_open_live(dev, 96, 0, 0, errbuf);
	if (send_handle == NULL)
	{
		fprintf(stderr, "Couldn't open device: %s: %s\n",dev ,errbuf);
		exit(EXIT_FAILURE);
	}

	//printf("size of ip6_packet:%d\n",sizeof(ip6_packet));
	if (pcap_inject(send_handle, addr, 78) == -1)
	{
		pcap_perror(send_handle, 0);
		pcap_close(send_handle);
		exit(EXIT_FAILURE);
	}

	pcap_close(send_handle);
	printf("Sending...DUP packet \n");
}

//void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)

void check_for_l2_ack(short seq_no)
{

	printf("Checking for L2 Ack ********\n");
	int i, var;
	int ack_not_received;
	//time_t startTime = time(NULL);
	//while(time(NULL) - startTime < 5)
	sleep(5);
	{
		//pthread_mutex_lock(&lock);
		for(i = 0; i < SIZE; i++)
		{
			if(stored_packet[i] != NULL )
				if( stored_packet[i]->sequence_number == seq_no)
			{
				ack_not_received = 1;
				var = i;
				
			}
			else {
				ack_not_received = 0;
				return;
			}
		}
	}
	//pthread_mutex_unlock(&lock);
	#if 1 
	if(ack_not_received){
		printf("ACK not received\n");
		//send_dropped_packet(var);
	}
	else
		printf("ACK received.............********\n");

	#endif
	return;
}

void *got_packet(void *thrd_args)
{
	struct parameters *thread_args;
	thread_args = thrd_args;
	
	u_char *args = thread_args->param1;
	const struct pcap_pkthdr *header = thread_args->param2;
	const	u_char *packet = thread_args->param3;

	// defining the pcap_argumets again to be used in thread

	static int count = 1;                   /* packet counter */
	unsigned char *ip_dff;
	struct ether_header *prev_ether_addr = (struct ether_header *)malloc(sizeof(struct ether_header));
	/* declare pointers to packet headers */
	struct ether_header *ethernet;  /* The ethernet header [1] */
	int first_packet;
	short *seq_no, prev_seq_no;
	struct ip6_hbh *hopbyhop;
	unsigned char ip6_packet[78] = {};	
	printf("\nPacket number %d:\n", count);
	count++;
	
	/* Used for displaying src and dst ip addresses*/
	struct ip6_hdr *ip6header;	
	ip6header = (struct ip6_hdr *)(packet + SIZE_ETHERNET);

	/* define ethernet header for L2 ACK*/
	ethernet = (struct ether_header *)(packet);
	const u_int16_t type = ethernet->ether_type;

	printf("Thread id:%u\n",pthread_self());	

	switch(ntohs(type)) {
	case ETH_P_802_EX1:
		printf("L2 ACK..\n");
		seq_no = (short *)(packet + SIZE_ETHERNET);
		printf("Seq_no of L2 ACK is: %x\n", *seq_no);
		//printf("Received L2 ACK from \n");
		
		//send_dropped_packet(*seq_no);	
		set_ack(*seq_no);
		
		//send_l2_ack(ethernet, *seq_no, prev_ether_addr);
		return;
	case ETHERTYPE_IPV6:
		printf("Its an IPv6\n");
	
		ip_dff = (unsigned char *)(packet + SIZE_ETHERNET + 40 + 2);
		printf("Opt type: %x\n", *ip_dff);
		
		if (*ip_dff != IPV6_TLV_DFF)
		{
			printf("Not a IP_DFF packet, do not process\n");
			return;
		}
		
		memcpy(ip6_packet, packet, 78);
		
		if(memcmp(ip6_packet, packet, 78) == 0)
			printf("Copied correctly\n");
		else
			printf("Not copied crrectly\n");

		hopbyhop = (struct ip6_hbh *)(packet + SIZE_ETHERNET + 40);
		printf("Next header field:%d\n",hopbyhop->ip6h_nxt);

		seq_no = (short *)(packet + SIZE_ETHERNET + 40 + 2 + 3);
		printf("Seq_no of packet to be forwarded:%x\n",*seq_no);

		struct in6_addr *orig_addr = &ip6header->ip6_src;
		if (!(check_for_processed_tuple(*seq_no, orig_addr)))
			add_in_processed_set(orig_addr, *seq_no, (struct ether_addr *)&ethernet->ether_shost);

		// used to keep track of prev ack
		//prev_seq_no = *seq_no;
		send_l2_ack(ethernet, *seq_no);
		fill_local_packet_pool(ip6_packet, *seq_no);
		prev_ether_addr = (struct ether_header *)(ip6_packet);
		send_to_next_hop(ip6_packet);

		/* Check if ACK for prvious packet recived or not.
		 * If not recevied then return and wait for ACK.
		 */
		#if 1
		check_for_l2_ack(*seq_no);
		//send_to_next_hop(ip6_packet);
		#endif
		return;
	default:
		printf("Protocol unknown\n");
		return;
	}


	// Display MAC addresses of the received packet 
	printf("\nDestination MacAddr: %02x:%02x:%02x:%02x:%02x:%02x\n", (unsigned)ethernet->ether_dhost[0],
		(unsigned)ethernet->ether_dhost[1],
		(unsigned)ethernet->ether_dhost[2],
		(unsigned)ethernet->ether_dhost[3],
		(unsigned)ethernet->ether_dhost[4],
		(unsigned)ethernet->ether_dhost[5]);
	
	printf("\nSource MacAddr: %02x:%02x:%02x:%02x:%02x:%02x\n", (unsigned)ethernet->ether_shost[0],
		(unsigned)ethernet->ether_shost[1],
		(unsigned)ethernet->ether_shost[2],
		(unsigned)ethernet->ether_shost[3],
		(unsigned)ethernet->ether_shost[4],
		(unsigned)ethernet->ether_shost[5]);

	assert(header->caplen <= header->len);
	assert(header->caplen >= sizeof(struct ether_header));

	/* print source and destination IP addresses */

	ip6header = (struct ip6_hdr *)(packet + SIZE_ETHERNET);
	char src_buf[INET6_ADDRSTRLEN];
	char dst_buf[INET6_ADDRSTRLEN];
	char host_addr[] = "2001::3";

	printf("From: %s\n", inet_ntop(AF_INET6, &ip6header->ip6_src, src_buf, sizeof(src_buf)));
	
	printf("To: %s\n", inet_ntop(AF_INET6, &ip6header->ip6_dst, dst_buf, sizeof(dst_buf)));

	int i = memcmp(src_buf, host_addr,sizeof(host_addr));
	if(i < 0 || i > 0)
		printf("Address not equal\n");
	else
		printf("Addresses are equal\n");

	/* define/compute ip header offset */
	
	
	/*
	 * Sending received packet again to next hop
	 */

	//unsigned char ip6_packet[78] = {};
	//memcpy(ip6_packet, packet, 78);

	//fill_local_packet_pool( ip6_packet, *seq_no);

	#if 0
	struct sniff_ethernet *send_ether;

	send_ether = (struct sniff_ethernet *)(ip6_packet);

	char *mac_addr = neigh_disc();
	printf("Mac addr is: %s\n", mac_addr);
	struct ether_addr *address = ether_aton(mac_addr);
	//printf("Address: %s\n", address->ether_addr_octet);	

	memcpy(&send_ether->ether_dhost, (void *)&address->ether_addr_octet, sizeof(struct ether_addr));	

	#if 1 
	//int a = get_mac_address();
	//char str[] = "08:00:27:e3:6f:5b";
	//struct ether_addr *ea = ether_aton(str);

	ea = ether_aton(str);

	memcpy(&send_ether->ether_shost,(void *)&ea->ether_addr_octet, sizeof(struct ether_addr));
	//memcpy(&send_ether->ether_dhost,(void *)&ea->ether_addr_octet, sizeof(struct ether_addr));
	
	/*Injecting IPv6 packet to next hop*/
	if(pcap_inject(send_handle, ip6_packet, sizeof(ip6_packet)) == -1) {
		pcap_perror(send_handle,0);
		pcap_close(send_handle);
		exit(1);
	}

	printf("sent ip6 packet to next hop......\n");
	#endif
	
	/* Injecting L2 ACK fame*/
	if(pcap_inject(send_handle, frame, sizeof(frame))==-1) {
   	       pcap_perror(send_handle,0);
               pcap_close(send_handle);
	       exit(1);
    	}

	pcap_close(send_handle);
	printf("L2 ACK sent\n");
	#endif

	pthread_exit(NULL);
return;
}

void create_thread(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	struct parameters thrd_args;
	thrd_args.param1 = args;
	thrd_args.param2 = header;
	thrd_args.param3 = packet;

	pthread_t packet_handler;
	int pkt_err;

	pkt_err = pthread_create(&packet_handler, NULL, &got_packet, (void *)&thrd_args);

	if (pkt_err != 0)
		fprintf(stderr, "can't create thread: %s\n",strerror(pkt_err));
	//else
		//fprintf(stderr, "New thread for packet....\n");

}

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */
	pcap_t *send_handle;

	char filter_exp[] = "ether dst host 08:00:27:e3:6f:5b";
	//char filter_exp[] = "src host 2001::3 and dst host 2001::1";		/* filter expression [3] */

	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 20;			/* number of packets to capture */
	initialize_Packet();
	initialize_Processed_set();
	
	pthread_t packet_handler;
	int pkt_err;
	int *ptr[2];

	/* check for capture device name on command-line */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		exit(EXIT_FAILURE);
	}
	else {
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n",
			    errbuf);
			exit(EXIT_FAILURE);
		}
	}
	
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	pcap_setdirection(handle, PCAP_D_IN);

	//memset(frame, 0xff, sizeof(struct ether_header));
	/*
	send_handle = pcap_open_live(dev, 96, 0, 0, errbuf);
	if(send_handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}
	printf("send handle created\n");
	*/
	/* now we can set our callback function */
	pcap_loop(handle, -1, create_thread, NULL);
	pcap_freecode(&fp);
	pcap_close(handle);
	//memcpy(frame, &eth_header, sizeof(struct ether_header));
	//memcpy(frame + sizeof(struct ether_header), &seq_no, sizeof(short));
	
	/*
        send_handle = pcap_open_live(dev, 96, 0, 0, errbuf);
        if (send_handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf    );
                exit(EXIT_FAILURE);
        } 
	printf("created handle for send\n");
	*/
	/*
	int i = 0;
	for(i = 0; i < 10; i++)	{
		if(pcap_inject(send_handle, frame, sizeof(frame))==-1) {
   	 	       pcap_perror(send_handle,0);
        	       pcap_close(send_handle);
		       exit(1);
    		}
		printf("packet sent\n");
	} */


	/* cleanup */
	//pcap_freecode(&fp);
	//pcap_close(handle);
	//pcap_close(send_handle);
	printf("\nCapture complete.\n");

return 0;
}

