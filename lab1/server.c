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
	int server_fd = -1;
	struct sockaddr_in server_addr, anyclient_addr;
	socklen_t addrlen;
	char buf[BUFSIZE]; 

	/* pre-processing */
	bzero(&server_addr, sizeof(server_addr)); /* clear server_addr */

	if (argc == 2) {
		port_number = atoi(argv[1]);
	}

	/* build server's IP address */
	server_addr.sin_family = AF_INET; /* for IPv4 */
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY); /* IP address can be anything, as client will have the same IP address */
	server_addr.sin_port = htons(port_number); /* use user-input port number */

	/* open a socket and bind to local interface */
	while (server_fd < 0) {
		server_fd = socket(AF_INET, SOCK_DGRAM, 0); /* domain, socket type, protocol; use SOCK_STREAM to open TCP socket, SOCK_DGRAM to open UDP socket */
	}
	// printf("Opened socket at %d\n", server_fd);
	int bind_success = -1;
	while (bind_success < 0) {
		bind_success = bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)); /* socket file descriptor, pointer to sockaddr, size of sockaddr */
	}
	// printf("Bind socket\n");

	/* now receive incoming connectionless packets */
	int recv_success = -1;
	while (recv_success < 0) {
		bzero(buf, BUFSIZE);
		recv_success = recvfrom(server_fd, buf, BUFSIZE, 0, (struct sockaddr *) &anyclient_addr, &addrlen); /* socket, buffer,  buffer length, flags, pointer to sockaddr, size of sockaddr */		
	}
	// printf("Received message\n");

	char * reply;
	if (strstr(buf,"ftp") != NULL) {
		reply = "yes";
	}
	else {
		reply = "no";
	}
	
	int send_success = -1;
	while (send_success < 0) {
		send_success = sendto(server_fd, reply, strlen(reply), 0, (struct sockaddr *) &anyclient_addr, addrlen);
	}
	// printf("Send message\n");
	
	close(server_fd);
	return 0;
}	
