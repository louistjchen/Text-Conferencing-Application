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

/* FUNCTION BEGIN - decipher packet */
void decipher_packet(packet * incoming_ack, char * incoming_ack_str) {
    bzero(incoming_ack,sizeof(*incoming_ack));
    char tmp[1000];
    int i, j, k;
    for (i = 0, j = 0, k = 0; j < 4;) {
        if (incoming_ack_str[i] == ':') {
            tmp[k] = '\0';
            if (j == 0) {
                    incoming_ack->total_frag = atoi(tmp);
            } else if (j == 1) {
                    incoming_ack->frag_no = atoi(tmp);
            } else if (j == 2) {
                    incoming_ack->size = atoi(tmp);
            } else {
                    /* free previous incoming packet's filename */
                    free(incoming_ack->filename);
                    incoming_ack->filename = (char *)malloc(sizeof(char) * strlen(tmp));
                    strcpy(incoming_ack->filename, tmp);
            }
            j++;
            i++;
            k = 0;
            bzero(tmp,sizeof(tmp));
        } else {
            tmp[k] = incoming_ack_str[i];
            i++;
            k++;
            tmp[k+1]='\0';
        }
    }
    for (j = 0; j < incoming_ack->size; j++) {
        incoming_ack->filedata[j] = incoming_ack_str[i+j];
    }
    printf("File name:%s string:%s\n",incoming_ack->filename,incoming_ack->filedata);
    return;
}
/* FUNCTION END - decipher packet */

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
	unsigned int curr = 0; /* data structure to track the next fragment number to receive */
    unsigned int num_packets = 100000000; /* initialize to arbitrarily high number */
    char incoming_packet_str[1100]; /* string to capture incoming packets */
    char outgoing_ack_str[1000]; /* string to capture outgoing acks */
    packet incoming_packet;
    char file_name[1000];
    char **file_data = NULL;
    while (curr < num_packets) {
        /* reset incoming packet str */
		bzero(incoming_packet_str, sizeof(incoming_packet_str));
        /* check for incoming packets */
        int recv_success = recvfrom(sock_fd,incoming_packet_str,sizeof(incoming_packet_str),0,(struct sockaddr *) &anyclient_addr_info,&anyclient_len);
	    if (recv_success >= 0) {
            printf("Received packet %s\n",incoming_packet_str);
            decipher_packet(&incoming_packet,incoming_packet_str);
            /* if receiving packet for the first time, must update num_packets */
            if (incoming_packet.frag_no == 1) { 
                num_packets = incoming_packet.total_frag;
                strcpy(file_name, incoming_packet.filename);
                file_data = (char **)malloc( sizeof(char *) * incoming_packet.total_frag );
            }
            file_data[curr] = (char *)malloc( sizeof(char) * incoming_packet.size );
            sprintf(file_data[curr], incoming_packet.filedata);
            /* incoming packet is the one server is waiting for */
            if (incoming_packet.frag_no == curr + 1) {
                /* send ack in filedata */
                sprintf(outgoing_ack_str,"%u:%u:3:%s:ack\0",incoming_packet.total_frag,incoming_packet.frag_no,incoming_packet.filename);
                curr++;
            }
            
        } else {
            /* send no-ack in filedata when recv_success < 0 */
            sprintf(outgoing_ack_str,"0:%u:5:nofile:noack\0",curr+1);
        }
        /* send ack/nack */
        sendto(sock_fd,outgoing_ack_str,sizeof(outgoing_ack_str),0,(struct sockaddr *) &anyclient_addr_info,anyclient_len);
        printf("Sent ack to client\n");
    }
    /* section 3 - END */

	/* close socket */
    close(sock_fd);
    /* write filedata to file stream */
    FILE * file_pointer = fopen("output.txt", "w");
    int i;
    for(i = 0; i < num_packets; i++) {
        fputs(file_data[i], file_pointer);
        free(file_data[i]);
    }
    free(file_data);
    free(incoming_packet.filename);
    fclose(file_pointer);


	return 0;
}
/* FUNCTION END - main */	
