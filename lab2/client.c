#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

/* some macros */
#define MAX_NAME	1024
#define MAX_DATA	1024
#define PACKET_SIZE	2056
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

	char command[64];
	char clientID[64];
	char clientPW[64];
	char serverIP[64];
	char serverPN[64];

initial_stage:

	/* prompt user to login */
	do{
		printf("Please enter command: ");
		scanf("%s", command);
		scanf("%s", clientID);
		scanf("%s", clientPW);
		scanf("%s", serverIP);
		scanf("%s", serverPN);
	} while( strcmp(command, "/login") != 0 );


	/* check if entered server is valid; if so then connect */
	int sockfd;
	int portnum = atoi(serverPN);
	struct sockaddr_in serveraddr;
	struct hostent *server;

	sockfd = socket(AF_INET, SOCK_STREAM, 0); // create socket
	if(sockfd < 0) {
		printf("ERROR: Socket opening fails.\n");
		return -1;
	}

	server = gethostbyname(serverIP); // check server IP validity
	if(server == NULL) {
		printf("ERROR: Server DNS not found.\n");
		return -1;
	}

	bzero(&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr = *((struct in_addr *)server->h_addr);
	serveraddr.sin_port = htons(portnum);

	if( connect(sockfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0 ) {
		printf("ERROR: Server connection fails.\n");
		return -1;
	}
	else {
		printf("Server connection is established.\n");
	}


	/* verify client credential */
	struct lab3message packet;

	packet.type = LOGIN;
	packet.size = PACKET_SIZE;
	strncpy(packet.source, clientID, MAX_NAME);
	strncpy(packet.data, clientPW, MAX_DATA);

	if( send(sockfd, &packet, sizeof(packet), 0) < 0 ) {
		printf("ERROR: LOGIN send fails.\n");
		return -1;
	}

	bzero((char *)&packet, sizeof(packet));
	if( recv(sockfd, &packet, sizeof(packet), 0) < 0 ) {
		printf("ERROR: LOGIN recv fails.\n");
		return -1;
	}

	if(packet.type == LO_ACK) {
		printf("LOGIN is acknowledged.\n");
	}
	else if(packet.type == LO_NAK) {
		printf("ERROR: LOGIN is not acknowledged.\n");
		printf("Reason: %s\n", packet.data);
		goto initial_stage;
	}
	else {
		printf("ERROR: LOGIN unknown status \"%u\" is returned.\n", packet.type);
		goto initial_stage;
	}


	/* prompt user to input command */
	char sessionID[64];
	char scan[MAX_DATA];
	char text[MAX_DATA];
	bool clientInSession = false;
	while(1) {
	
		printf("Please enter command: ");
		scanf("%s", command);

		/* /login			prompt user that he/she is already logged in 	*/
		if( strcmp(command, "/login") == 0 ) {
			printf("User \"%s\" is currently logged in.\n");
			printf("Please logout before attempting new login.\n");
		}

		/* /logout			exit the server and reprompt for login		*/
		else if( strcmp(command, "/logout") == 0 ) {
			bzero((char *)&packet, sizeof(packet));
			packet.type = EXIT;
			packet.size = PACKET_SIZE;
			strncpy(packet.source, clientID, MAX_NAME);

			if( send(sockfd, &packet, sizeof(packet), 0) < 0 ) {
				printf("ERROR: LOGOUT send fails.\n");
				return -1;
			}
			printf("User \"%s\" is successfully logged out.\n", clientID);
			goto initial_stage;
		}

		/* /joinsession <session ID>	join session with given session id		*/
		else if( strcmp(command, "/joinsession") == 0 ) {
			scanf("%s", sessionID);
			if(clientInSession) {
				printf("ERROR: User is already in session %s.\n", sessionID);
			}
			else {
				bzero((char *)&packet, sizeof(packet));
				packet.type = JOIN;
				packet.size = PACKET_SIZE;
				strncpy(packet.source, clientID, MAX_NAME);
				strncpy(packet.data, sessionID, MAX_DATA);

				if( send(sockfd, &packet, sizeof(packet), 0) < 0 ) {
					printf("ERROR: JOIN send fails.\n");
					return -1;
				}
				bzero((char *)&packet, sizeof(packet));
				if( recv(sockfd, &packet, sizeof(packet), 0) < 0 ) {
					printf("ERROR: JOIN recv fails.\n");
					return -1;
				}

				if(packet.type == JN_ACK) {
					printf("JOIN is acknowledged.\n");
					clientInSession = true;
				}
				else if(packet.type == JN_NAK) {
					printf("ERROR: JOIN is not acknowledged.\n");
					printf("Reason: %s\n", packet.data);
				}
				else {
					printf("ERROR: JOIN unknown status \"%u\"is returned\n", packet.type);
				}
			}
		}

		/* /leavesession		leave the currently established session		*/
		else if( strcmp(command, "/leavesession") == 0 ) {
			if(clientInSession) {
				bzero((char *)&packet, sizeof(packet));
				packet.type = LEAVE_SESS;
				packet.size = PACKET_SIZE;
				strncpy(packet.source, clientID, MAX_NAME);
				strncpy(packet.data, sessionID, MAX_DATA);
				
				if( send(sockfd, &packet, sizeof(packet), 0) < 0 ) {
					printf("ERROR: LEAVE_SESS send fails.\n");
					return -1;
				}
				clientInSession = false;
				printf("User \"%s\" successfully left session \"%s\".\n", clientID, sessionID);
			}
			else {
				printf("ERROR: User is not in a session yet.\n");
			}
		}

		/* /createsession <session ID>	create a new conference session and join it	*/
		else if( strcmp(command, "/createsession") == 0 ) {
			scanf("%s", sessionID);
			if(clientInSession) {
				printf("ERROR: User is already in session %s.\n", sessionID);
			}
			else {
				bzero((char *)&packet, sizeof(packet));
				packet.type = NEW_SESS;
				packet.size = PACKET_SIZE;
				strncpy(packet.source, clientID, MAX_NAME);
				strncpy(packet.data, sessionID, MAX_DATA);

				if( send(sockfd, &packet, sizeof(packet), 0) < 0 ) {
					printf("ERROR: NEW_SESS send fails.\n");
					return -1;
				}
				bzero((char *)&packet, sizeof(packet));
				if( recv(sockfd, &packet, sizeof(packet), 0) < 0 ) {
					printf("ERROR: NEW_SESS recv fails.\n");
					return -1;
				}

				if(packet.type == NS_ACK) {
					printf("NEW_SESS is acknowledged.\n");

					bzero((char *)&packet, sizeof(packet));
					packet.type = JOIN;
					packet.size = PACKET_SIZE;
					strncpy(packet.source, clientID, MAX_NAME);
					strncpy(packet.data, sessionID, MAX_DATA);
	
					if( send(sockfd, &packet, sizeof(packet), 0) < 0 ) {
						printf("ERROR: JOIN send fails.\n");
						return -1;
					}
					bzero((char *)&packet, sizeof(packet));
					if( recv(sockfd, &packet, sizeof(packet), 0) < 0 ) {
						printf("ERROR: JOIN recv fails.\n");
						return -1;
					}
	
					if(packet.type == JN_ACK) {
						printf("JOIN is acknowledged.\n");
						clientInSession = true;
					}
					else if(packet.type == JN_NAK) {
						printf("ERROR: JOIN is not acknowledged.\n");
						printf("Reason: %s\n", packet.data);
					}
					else {
						printf("ERROR: JOIN unknown status \"%u\"is returned\n", packet.type);
					}
				}
				else {
					printf("ERROR: NEW_SESS unknown status \"%u\"is returned.\n", packet.type);
				}
			}
		}

		/* /list			list of connected clients & available sessions	*/
		else if( strcmp(command, "/list") == 0 ) {
			bzero((char *)&packet, sizeof(packet));
			packet.type = QUERY;
			packet.size = PACKET_SIZE;
			strncpy(packet.source, clientID, MAX_NAME);

			if( send(sockfd, &packet, sizeof(packet), 0) < 0 ) {
				printf("ERROR: QUERY send fails.\n");
				return -1;
			}
			bzero((char *)&packet, sizeof(packet));
			if( recv(sockfd, &packet, sizeof(packet), 0) < 0 ) {
				printf("ERROR: QUERY recv fails.\n");
				return -1;
			}

			if(packet.type == QU_ACK) {
				printf("QUERY is acknowledged.\n");
				printf("List: %s", packet.data);
			}
			else {
				printf("ERROR: QUERY unknown status is returned.\n");
			}
		}

		/* /quit			safe logout and terminate the program		*/
		else if( strcmp(command, "/quit") == 0 ) {
			if(clientInSession) { // leave the session if connected to one
				bzero((char *)&packet, sizeof(packet));
				packet.type = LEAVE_SESS;
				packet.size = PACKET_SIZE;
				strncpy(packet.source, clientID, MAX_NAME);
				strncpy(packet.data, sessionID, MAX_DATA);
				
				if( send(sockfd, &packet, sizeof(packet), 0) < 0 ) {
					printf("ERROR: LEAVE_SESS send fails.\n");
					return -1;
				}
				clientInSession = false;
				printf("User \"%s\" successfully left session \"%s\".\n", clientID, sessionID);
			}

			bzero((char *)&packet, sizeof(packet)); // safe logout
			packet.type = EXIT;
			packet.size = PACKET_SIZE;
			strncpy(packet.source, clientID, MAX_NAME);

			if( send(sockfd, &packet, sizeof(packet), 0) < 0 ) {
				printf("ERROR: LOGOUT send fails.\n");
				return -1;
			}
			printf("User \"%s\" is successfully logged out.\n", clientID);

			break;
		}

		/* <text>			send a message to current conference session	*/
		else {
			bzero((char *)&packet, sizeof(packet));
			packet.type = MESSAGE;
			packet.size = PACKET_SIZE;
			strncpy(packet.source, clientID, MAX_NAME);

			if( strlen(command) < MAX_DATA ) // concatenate the first word in message (scanned by command)
				strcat(text, command);
			while( getchar() != '\n' ) { // scan the entire message before \n
				scanf("%s", scan);
				if( (strlen(text) + strlen(scan)) < MAX_DATA )
					strcat(text, scan);
			}
			strncpy(packet.data, text, MAX_DATA);

			if(clientInSession) { // send the message if client is in a session
				if( send(sockfd, &packet, sizeof(packet), 0) < 0 ) {
					printf("ERROR: MESSAGE send fails.\n");
					return -1;
				}
				printf("Message \"%s\" is successfully sent to session \"%s\".\n", packet.data, sessionID);
			}
			else {
				printf("ERROR: User is not in a session yet.\n");
			}
		}

	}

	printf("Client is terminated.\n");
	return 0;
}


