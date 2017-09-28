#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#define BUFSIZE 100 /* set incoming message size to max 100 Bytes */

int main(int argc, char * argv[]) {
	
	/* declare variables */
	unsigned short port_number = 22000; /* default to 22000 */
	int client_fd = -1;
	struct sockaddr_in server_addr;
	char * server_in_addr = "127.0.0.1";
	char buf[BUFSIZE];


	
	/* pre-processing */
	bzero(&server_addr, sizeof(server_addr));
	
	if (argc == 3) {
		server_in_addr = argv[1];
		port_number = atoi(argv[2]);
	}

	/* build server's IP address */
	server_addr.sin_family = AF_INET; /* for IPv4 */
	server_addr.sin_port = htons(port_number);
	
	inet_pton(AF_INET, server_in_addr, (struct in_addr *) &(server_addr.sin_addr));
	/* open a socket */
	while (client_fd < 0) {
		client_fd = socket(AF_INET, SOCK_DGRAM, 0); /* domain, socket type, protocol; use SOCK_STREAM to open TCP socket, SOCK_DGRAM to open UDP socket */
	}
	// printf("Opened socket at %d\n", client_fd);
	
	/* ask user to input file name */
	char transport_type[10];
	char transport_path[20];
	FILE * fp = NULL;
	printf("Please input <transport protocol type> <transport file path>: ");
	scanf("%s", transport_type);
	scanf("%s", transport_path);
	if(strcmp(transport_type, "ftp") != 0) {
		printf("Please check transport protocol type and restart the program.\n");
		return 0;
	}
	if(fopen(transport_path, "r") == NULL) {
		printf("Entered file path is invalid. Please confirm and restart the program.\n");
		return 0;
	}

	/* send message to server */
	int send_success = -1;
	char msg[] = "ftp";
	int server_len = sizeof(server_addr);
	while (send_success < 0) {
		send_success = sendto(client_fd, msg, strlen(msg), 0, (struct sockaddr *) &server_addr, server_len);
	}
	// printf("Sent message\n");

	/* print server's reply */
	int recv_success = -1;
	while (recv_success < 0) {
		bzero(buf, BUFSIZE);
		recv_success = recvfrom(client_fd, buf, BUFSIZE, 0, (struct sockaddr *) &server_addr, &server_len);
	}
	// printf("Received message\n");

	if (strstr(buf,"yes") != NULL) {
		printf("A file transfer can start\n");
	} else {
		printf("Failed :\(\n");
	}

	return 0;
}
