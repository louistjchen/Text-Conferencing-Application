#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

/* some macros */
#define MAX_NAME 1024
#define MAX_DATA 1024
#define LOGIN		100
#define LO_ACK		101
#define LO_NAK		102
#define EXIT		103
#define JOIN		104
#define JN_ACK		105
#define JN_NAK		106
#define LEAVE_SESS	107
#define NEW_SESS	108
#define NS_ACK		109
#define MESSAGE		110
#define QUERY		111
#define QU_ACK		112

/* protocol structture */
struct lab3message {
	unsigned int type;
	unsigned int size;
	unsigned char source[MAX_NAME];
	unsigned char data[MAX_DATA];
};


int main (int argc, char *argv[]) {

	char command[100];
	char clientID[100];
	char clientPW[100];
	char serverIP[100];
	char serverPN[100];


	/* prompt user to login */
	do {
		printf("Please login (i.e. /login <client ID> <password> <server-IP> <server-port>): ");
		scanf("%s", &command);
		scanf("%s", &clientID);
		scanf("%s", &clientPW);
		scanf("%s", &serverIP);
		scanf("%s", &serverPN);
	} while(strcmp(command, "/login") != 0);


	/* check if entered server is valid; if so then connect */
	int sockfd = -1;
	int portnum = atoi(serverPN);
	struct sockaddr_in serveraddr;
	struct hostent *server = NULL;

	while(sockfd < 0) // create a socket
		sockfd = socket(AF_INET, SOCK_STREAM, 0);

	server = gethostbyname(serverIP); // check server IP validity
	if(server == NULL) {
		printf("ERROR: Server DNS not found.\n");
		return -1;
	}

	bzero( (char*) &serveraddr, sizeof(serveraddr) );
	serveraddr.sin_family = AF_INET;
	bcopy( (char*) server->h_addr, (char*) &serveraddr.sin_addr.s_addr, server->h_length );
	serveraddr.sin_port = htons(portnum);

	int connect_success = connect(sockfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr));
	if(connect_success < 0) {
		printf("ERROR: Server connection fails.\n");
		return -1;
	}
	else
		printf("Connected to server.\n");


	/* send & receive */
	int send_success = -1;
	while(send_success < 0)
		send_success = write(sockfd, "hi from client", strlen("hi frmo client"));
	char buf[MAX_DATA];
	bzero(buf, MAX_DATA);
	int recv_success = -1;
	while(recv_success < 0)
		recv_success = read(sockfd, buf, MAX_DATA);

	printf("Echo from server: %s\n", buf);


	return 0;
}
