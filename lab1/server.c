#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

/* DEFINE BEGIN - packet struct */
typedef struct packet {
    unsigned int total_frag;
    unsigned int frag_no;
    unsigned int size;
    char* filename;
    char filedata[1000];
} packet;
/* DEFINE END - packet struct */

/* DEFINE BEGIN - ack struct */
typedef struct ack {
    unsigned int status;
    unsigned int frag_no;
} ack;
/* DEFINE END - ack struct */

/* FUNCTION BEGIN - initialize + bind socket */
int initialize_bind_socket(struct sockaddr_in * server_addr_info, unsigned short port_number) {
    
    /* build server's IP address */
    server_addr_info->sin_family = AF_INET; /* for IPv4 */
    server_addr_info->sin_addr.s_addr = htonl(INADDR_ANY); /* IP address can be anything */
    server_addr_info->sin_port = htons(port_number); /* user-input port number */

    /* open a socket */
    int sock_fd = -1;
    while (sock_fd < 0) {
        sock_fd = socket(AF_INET, SOCK_DGRAM, 0); /* domain, socket type, protocol */
    }
    int bind_success = -1;
    while (bind_success < 0) {
        bind_success = bind(sock_fd, (struct sockaddr *) server_addr_info, sizeof(*server_addr_info));
    }
    printf("Bind at socket %u\n",sock_fd);
    return sock_fd;
}
/* FUNCTION BEGIN - initialize + bind socket */

/* FUNCTION BEGIN - initialize + populate ack */
void initialize_populate_ack(ack * outgoing_ack, unsigned int frag_no) {
    bzero(outgoing_ack,sizeof(*outgoing_ack));
    outgoing_ack->status = 0;
    outgoing_ack->frag_no = frag_no;
    return;
}
/* FUNCTION END - initialize ack */

/* FUNCTION BEGIN - copy data */
void copy_data(char * data_packet, packet * incoming_packet) {
    unsigned int i;
    for (i = 0; i < incoming_packet->size; i++) {
        data_packet[i] = incoming_packet->filedata[i];
    }
    return;
}

/* FUNCTION END - copy data */

/* FUNCTION BEGIN - main */
int main(int argc, char * argv[]) {
	
	/* section 1 - BEGIN */
    /* initialize address info variables */
	unsigned short port_number = 22000; /* default to 22000 */
	int sock_fd = -1;
	struct sockaddr_in server_addr_info, anyclient_addr_info;
	unsigned int anyclient_len;

	/* pre-processing */
	bzero(&server_addr_info, sizeof(server_addr_info)); 
	if (argc == 2) {
		port_number = atoi(argv[1]);
	}

    /* initialize + bind socket */
    sock_fd = initialize_bind_socket(&server_addr_info, port_number);
    /* section 1 - END */

    /* section 3 - BEGIN */	
	unsigned int packet_recv_number = 0; /* data structure to track the next fragment number to receive */
    unsigned int num_packets = 100000000; /* initialize to arbitrarily high number */
    packet incoming_packet; /* data structure to receive incoming packets */
    ack outgoing_ack; /* data structure to send outgoing acks */
    char ** data_packets;
    while (packet_recv_number <= num_packets) {
        /* reset outgoing ack data structure */
        initialize_populate_ack(&outgoing_ack,packet_recv_number);
        /* reset incoming packet data structure */
		bzero(&incoming_packet, sizeof(incoming_packet));
		do {
            /* send ack/nack */
        } while (recvfrom(sock_fd,&incoming_packet,sizeof(incoming_packet),MSG_DONTWAIT,(struct sockaddr *) &anyclient_addr_info,&anyclient_len) < 0);


        int recv_success = recvfrom(sock_fd,&incoming_packet,sizeof(incoming_packet),0,(struct sockaddr *) &anyclient_addr_info,&anyclient_len);
	    if (recv_success >= 0) {
            printf("Received packet %u with total frag %u\n",incoming_packet.frag_no,incoming_packet.total_frag);
            /* update num_packets once a packet is received, and allocate memory accordingly */
            if (incoming_packet.total_frag < num_packets) {
                num_packets = incoming_packet.total_frag;
                printf("Updated num packets: %u\n",num_packets);
                data_packets = malloc(sizeof(char *) * num_packets);
                unsigned int i;
                for (i = 0; i < num_packets; i++) {
                    data_packets[i] = (char *) malloc(sizeof(char) * 1000 + 1);
                }
            }
            /* if incoming packet frag no. matches packet, copy data, set outgoing ack status to true, and increment packet_recv_number */
            if (incoming_packet.frag_no == packet_recv_number) {
                copy_data(data_packets[packet_recv_number],&incoming_packet);
                printf("Copied data\n");
                outgoing_ack.status = 1;
                packet_recv_number++;
            } else if (incoming_packet.frag_no < packet_recv_number) {
                outgoing_ack.status = 1;
                outgoing_ack.frag_no = incoming_packet.frag_no;
            }
        }
        /* send ack/nack */
        sendto(sock_fd,&outgoing_ack,sizeof(outgoing_ack),0,(struct sockaddr *) &anyclient_addr_info,anyclient_len);
        printf("Sent ack to client\n");
    }
    /* section 3 - END */

	/* close socket */
    close(sock_fd);
    /* free dynamically allocated memory */
    unsigned int i;
    for (i = 0; i < num_packets; i++) {
        free(data_packets[i]);
    }
    free(data_packets);
	return 0;
}
/* FUNCTION END - main */	
