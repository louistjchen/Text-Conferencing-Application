#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <math.h>

/* DEFINE BEGIN - struct packet */
typedef struct packet {
    unsigned int total_frag;
    unsigned int frag_no;
    unsigned int size;
    char * filename;
    char filedata[1000];
} packet;
/* DEFINE END - struct packet */

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

/* FUNCTION BEGIN - format string */
int format_string(char * dest, unsigned int total_frag, unsigned int frag_no, unsigned int size, char * filename, char * filedata) {
    sprintf(dest,"%u:%u:%u:%s:", total_frag, frag_no, size, filename);
    int len = strlen(dest);
    int n;
    for (n = len; n < len + size; n++) {
        dest[n] = filedata[n-len];
    }
    dest[n] = '\0';
    return len + size;
}
/* FUNCTION END - format string */

/* FUNCTION BEGIN - initialize socket */
int initialize_socket(struct sockaddr_in * server_addr_info, char * server_ip_addr, unsigned short port_number) {

    /* build server's IP address */
    server_addr_info->sin_family = AF_INET; /* for IPv4 */
    server_addr_info->sin_port = htons(port_number);
    
    inet_pton(AF_INET, server_ip_addr, (struct in_addr *) &(server_addr_info->sin_addr));

    /* open a socket */
    int sock_fd = -1;
    while (sock_fd < 0) {
        sock_fd = socket(AF_INET, SOCK_DGRAM, 0); /* domain, socket type, protocol */    
    }
    return sock_fd;
}
/* FUNCTION END - initialize socket */

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
	unsigned short port_number = 22000; 
	int sock_fd = -1;
	struct sockaddr_in server_addr_info;
    int server_len = sizeof(server_addr_info);
	char * server_ip_addr = "127.0.0.1";

	/* pre-processing */
	bzero(&server_addr_info, sizeof(server_addr_info));
	if (argc == 3) {
		server_ip_addr = argv[1];
		port_number = atoi(argv[2]);
	}

    /* initialize socket */
    sock_fd = initialize_socket(&server_addr_info, server_ip_addr, port_number);
    printf("Initialize socket %d\n",sock_fd);
	
	/* ask user to input file name */
	char transport_type[1000];
	char transport_file_name[1000];
	FILE * file_pointer = NULL;
	printf("Please input <transport protocol type> <transport file path>: ");
	scanf("%s", transport_type);
	scanf("%s", transport_file_name);
	if(strcmp(transport_type, "ftp") != 0) {
		printf("Please check transport protocol type and restart the program.\n");
		return 0;
	}
    file_pointer = fopen(transport_file_name,"r");
	if(file_pointer == NULL) {
		printf("Entered file path is invalid. Please confirm and restart the program.\n");
		return 0;
	} 
    /* section 1 - END */    

    /* section 3 - BEGIN */
    /* determine file size (total # bytes) */
    struct stat st;
    unsigned int file_size = 0;
    if (!stat(transport_file_name,&st)) {
        file_size = st.st_size;
    }
    /* dynamically allocate space for char array to load all the data into */
    char * filedata = malloc(sizeof(char) * (file_size + 1));
    /* load entire file into char array above */
    int n, count;
    count = 0;
    while (!feof(file_pointer)) {
        n = fread(&filedata[count],sizeof(char),1,file_pointer);
        count += n;
    }
    filedata[file_size] = '\0';
    fclose(file_pointer);

    /* determine number of packets */
    int last_packet_size = file_size % 999;
    int num_packets = (last_packet_size) ? ((file_size/999) + 1) : (file_size/999);
	/* initialize all outgoing packets */
    packet * outgoing_packet = (packet *)malloc(sizeof(packet) * num_packets);
    int i, packet_size;
    for (i = 0; i < num_packets; i++) {
        outgoing_packet[i].total_frag = num_packets;
        outgoing_packet[i].frag_no = i+1;
        outgoing_packet[i].size = (i == num_packets-1) ? (last_packet_size+1) : 1000;
        copy_string(outgoing_packet[i].filedata,&filedata[i*999],outgoing_packet[i].size);    
        outgoing_packet[i].filename = transport_file_name;
    }

    /* send packets to server */
    unsigned int curr = 0; /* counter to track current pending packet number */
    char outgoing_packet_str[1100]; /* string to capture outgoing packets */
    char incoming_ack_str[1000]; /* string to capture incoming acks */
    packet incoming_ack;
    struct timeval start, stop;
    while (curr < num_packets) {
        /* initialize outgoing packet str */
        bzero(outgoing_packet_str,sizeof(outgoing_packet_str));
        format_string(outgoing_packet_str,outgoing_packet[curr].total_frag,outgoing_packet[curr].frag_no,outgoing_packet[curr].size,outgoing_packet[curr].filename,outgoing_packet[curr].filedata);
        /* reset incoming ack str*/
        bzero(incoming_ack_str,sizeof(incoming_ack_str));
        /* initialize ack boolean flag to false */
        int ack_flag = 0;
        do {
            /* send the packet once */
            gettimeofday(&start, NULL); /* start time */
            printf("Send packet\n");
            sendto(sock_fd,outgoing_packet_str,sizeof(outgoing_packet_str),0,(struct sockaddr *) &server_addr_info,server_len);
            /* check for incoming ack/nack */
            printf("Wait on ack \n");
            int recv_success = recvfrom(sock_fd,incoming_ack_str,sizeof(incoming_ack_str),0,(struct sockaddr *) &server_addr_info,&server_len);
            if (recv_success >= 0) {
                gettimeofday(&stop, NULL); /* stop time */
                printf("Received ack from server\n");
                /* decipher packet */
                decipher_packet(&incoming_ack,incoming_ack_str);
                // printf("total frag:%u frag no:%u size:%u filename:%s filedata:%s\n",incoming_ack.total_frag,incoming_ack.frag_no, incoming_ack.size, incoming_ack.filename, incoming_ack.filedata);
                if (incoming_ack.frag_no == curr + 1 && incoming_ack.size == 3) {
                    ack_flag = 1;
                    curr++;
                }
                printf("RTT (milliseconds): %f\n",(float)(stop.tv_usec - start.tv_usec)/1000);
            }
            /* reset incoming ack data structure before next iteration */
            bzero(&incoming_ack_str,sizeof(incoming_ack_str));
        } while (!ack_flag);        
    }


    // struct timeval start, stop; /* initialize variables to measure elapsed time */
    /* measure elapsed time */
    // printf("RTT (milliseconds): %f\n", (float)(stop.tv_usec - start.tv_usec)/1000);
    /* section 3 - END */

    /* close socket */
    close(sock_fd);
    /* free dynamically allocated memory */
    free(outgoing_packet);
	return 0;
}
/* FUNCTION END - main */
