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
	FILE * fp = NULL;
	printf("Please input <transport protocol type> <transport file path>: ");
	scanf("%s", transport_type);
	scanf("%s", transport_file_name);
	if(strcmp(transport_type, "ftp") != 0) {
		printf("Please check transport protocol type and restart the program.\n");
		return 0;
	}
    FILE * file_pointer = fopen(transport_file_name, "r");
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
    char * filedata = malloc(sizeof(char) * file_size);
    /* load entire file into char array above */
    memcpy(filedata, file_pointer, file_size);
    /* determine number of packets */
    int last_packet_size = file_size % 1000;
    int num_packets = (last_packet_size) ? ((file_size/1000) + 1) : (file_size/1000);
    printf("Num packets:%u Last packet size:%u\n",num_packets,last_packet_size);
	/* initialize all outgoing packets */
    char ** outgoing_packet = malloc(sizeof(char *) * num_packets);
    int i, j, packet_size;
    for (i = 0; i < num_packets; i++) {
        packet_size = (i == num_packets - 1) ? last_packet_size : 1000;
        outgoing_packet[i] = (char *)malloc(sizeof(char) * 1100);
        j = sprintf(outgoing_packet[i],"%u:%u:%u:%s:%s",num_packets,i,packet_size,transport_file_name,filedata + (i*1000));
    }
    unsigned int current_packet = 0; /* counter to track current pending packet */
    // while (packet_sent_number < num_packets) {
    //     /* initialize outgoing packet data structure */
    //     initialize_packet(&outgoing_packet,num_packets,current_packet,transport_file_name);
    //     /* populate packet with specific info */
    //     populate_packet(&outgoing_packet,packet_sent_number,last_packet_size,data_packets[packet_sent_number]);
    //     /* reset incoming ack data structure */
    //     bzero(&incoming_ack,sizeof(incoming_ack));
    //     /* initialize ack boolean flag to false */
    //     int ack_flag = 0;
    //     do {
    //         /* first send the packet once */
    //         printf("Send packet %d\n",packet_sent_number);
    //         sendto(sock_fd,&outgoing_packet,sizeof(outgoing_packet),0,(struct sockaddr *) &server_addr_info,server_len);
    //         /* check for incoming ack/nack */
    //         printf("Wait on ack \n");
    //         int recv_success = recvfrom(sock_fd,&incoming_ack,sizeof(incoming_ack),0,(struct sockaddr *) &server_addr_info,&server_len);
    //         if (recv_success >= 0) {
    //             printf("Received ack from server\n");
    //             /* if incoming ack frag no. matches packet and incoming ack status is true, increment packet_sent_number */
    //             if (incoming_ack.frag_no == packet_sent_number && incoming_ack.status) {
    //                 ack_flag = 1;
    //                 packet_sent_number++;
    //             }
    //         }
    //         /* reset incoming ack data structure before next iteration */
    //         bzero(&incoming_ack,sizeof(incoming_ack));
    //     } while (!ack_flag);        
    // }


    // struct timeval start, stop; /* initialize variables to measure elapsed time */

    // int send_success = -1;
	// char msg[] = "ftp";
	// int server_len = sizeof(server_addr_info);
	// gettimeofday(&start, NULL); /* start time */
	// while (send_success < 0) {
	// 	send_success = sendto(sock_fd, msg, strlen(msg), 0, (struct sockaddr *) &server_addr_info, server_len);
	// }
	// printf("Sent message\n");

	/* print server's reply */
	// int recv_success = -1;
	// while (recv_success < 0) {
	// 	bzero(buf, BUFSIZE);
	// 	recv_success = recvfrom(sock_fd, buf, BUFSIZE, 0, (struct sockaddr *) &server_addr_info, &server_len);
	// }
	// gettimeofday(&stop, NULL); /* stop time */
	// printf("RTT (milliseconds): %f\n", (float)(stop.tv_usec - start.tv_usec)/1000);
	// // printf("Received message\n");

	// if (strstr(buf,"yes") != NULL) {
	// 	printf("A file transfer can start\n");
	// } else {
	// 	printf("Failed :\(\n");
	// }
    /* section 3 - END */

    // /* close socket */
    // close(sock_fd);
    // /* free dynamically allocated memory */
    // for (i = 0; i < num_packets; i++) {
    //     free(data_packets[i]);
    // }
    // free(data_packets);
	return 0;
}
/* FUNCTION END - main */
