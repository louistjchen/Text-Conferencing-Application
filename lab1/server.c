#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>

/* DEFINE BEGIN - packet struct */
typedef struct packet {
    unsigned int total_frag;
    unsigned int frag_no;
    unsigned int size;
    char* filename;
    char filedata[1000];
} packet;
/* DEFINE END - packet struct */

/* FUNCTION BEGIN - copy string */
int copy_string(char * dest, char * src, int size) {
    int n;
    for (n = 0; n < size - 1; n++) {
        dest[n] = src[n];
    }
    dest[n] = '\0';
    return n;
}
/* FUNCTION END - copy string */



/* FUNCTION BEGIN - initialize + bind socket */
int initialize_bind_socket(struct sockaddr_in * server_addr_info, unsigned short port_number) {
    
    /* build server's IP address */
    server_addr_info->sin_family = AF_INET; 
    server_addr_info->sin_addr.s_addr = htonl(INADDR_ANY); 
    server_addr_info->sin_port = htons(port_number); 

    /* open a socket */
    int sock_fd = -1;
    while (sock_fd < 0) {
        sock_fd = socket(AF_INET, SOCK_DGRAM, 0); 
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
    return;
}
/* FUNCTION END - decipher packet */




/* FUNCTION BEGIN - main */
int main(int argc, char * argv[]) {
	
    /* initialize address info variables */
	unsigned short port_number = 22000; 
	int sock_fd = -1;
	struct sockaddr_in server_addr_info, anyclient_addr_info;
	unsigned int anyclient_len = sizeof(anyclient_addr_info);

	/* pre-processing */
	bzero(&server_addr_info, sizeof(server_addr_info)); 
	if (argc == 2) {
		port_number = atoi(argv[1]);
	}

    /* initialize + bind socket */
    sock_fd = initialize_bind_socket(&server_addr_info, port_number);

	unsigned int curr = 0; /* data structure to track the next fragment number to receive */
    unsigned int num_packets = 100000000; /* initialize to arbitrarily high number */
    unsigned int last_packet_size = 1000; /* initialize to 1000 */
    char incoming_packet_str[1100]; /* string to capture incoming packets */
    char outgoing_ack_str[1000]; /* string to capture outgoing acks */
    packet incoming_packet;
    char file_name[1000];
    char **file_data = NULL;
    
    bool malloc2d = false;
    bool *malloced = NULL;

    while (curr < num_packets + 1) {
        /* reset incoming packet str */
		bzero(incoming_packet_str, sizeof(incoming_packet_str));
        /* check for incoming packets */
        int recv_success = recvfrom(sock_fd,incoming_packet_str,sizeof(incoming_packet_str),0,(struct sockaddr *) &anyclient_addr_info,&anyclient_len);
	    if (recv_success >= 0) {
            printf("Received packet from client\n");
            //if(curr == num_packets)
            //    printf("%s\n", incoming_packet_str);
            /* close server connection if receive FIN */
            if (strcmp(incoming_packet_str, "__FINISH__") == 0) {
                printf("Server received FIN packet\n");
                break;
            }
            decipher_packet(&incoming_packet,incoming_packet_str);
            /* if receiving packet for the first time, must update num_packets */
            if (!malloc2d && incoming_packet.frag_no == 1) { 
                num_packets = incoming_packet.total_frag;
                strcpy(file_name, incoming_packet.filename);
                file_data = (char **)malloc( sizeof(char *) * incoming_packet.total_frag );

		malloced = (bool *)malloc( sizeof(bool)*incoming_packet.total_frag );
		int x;
		for(x = 0; x < incoming_packet.total_frag; x++)
			malloced[x] = false;
		malloc2d = true;
            }
	    	 
	    // test timeout
	    //char test;
	    //scanf("%c", &test);

	    if(!malloced[curr]){
	            file_data[curr] = (char *)malloc( sizeof(char) * incoming_packet.size );
		    malloced[curr] = true;
	    }
            /* if receiving packet for the last time, must update last_packet_size */
            if (curr == num_packets-1) {
                last_packet_size = incoming_packet.size;
            }
            copy_string(file_data[curr],incoming_packet.filedata,incoming_packet.size);
            /* incoming packet is the one server is waiting for */
            if (curr == incoming_packet.frag_no - 1) {
                sprintf(outgoing_ack_str,"%u:%u:3:%s:ack\0",incoming_packet.total_frag,incoming_packet.frag_no,incoming_packet.filename);
                curr++;
            } else if (curr == incoming_packet.frag_no) {
            /* incoming packet is one that the server already accepted previously */
                sprintf(outgoing_ack_str,"%u:%u:3:%s:ack\0",incoming_packet.total_frag,incoming_packet.frag_no,incoming_packet.filename);
            }
            
        } else {
            sprintf(outgoing_ack_str,"0:%u:5:nofile:noack\0",curr+1);
        }
        /* send ack/nack */
        sendto(sock_fd,outgoing_ack_str,sizeof(outgoing_ack_str),0,(struct sockaddr *) &anyclient_addr_info,anyclient_len);
        printf("Server sent ack/nack for packet %u\n",curr+1);
    }

    /* write filedata to file stream */
    FILE * file_pointer = fopen("output.txt", "w");
    int i, packet_size;
    for(i = 0; i < num_packets; i++) {
        packet_size = 1000;
        if (i == num_packets-1) { 
            packet_size = last_packet_size;
        }
        int j;
        for (j = 0; j < packet_size-1; j++) {
            fwrite(&file_data[i][j],1,sizeof(char),file_pointer);
        }
        free(file_data[i]);
    }
    free(file_data);
    free(incoming_packet.filename);
    fclose(file_pointer);

    // close socket
    close(sock_fd);


	return 0;
}
/* FUNCTION END - main */	
