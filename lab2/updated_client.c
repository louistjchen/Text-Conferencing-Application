/*
 * 	ECE361 - Text Conferencing Lab
 *
 * 	Louis Chen		1000303502
 * 	Chia-Hang Chang		1000611260
 *
 */

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

#define STDIN       0

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

    int sockfd = -1;
    int portnum = -1;
    struct sockaddr_in serveraddr;
    struct hostent *server;

    // initialize basic server info
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;

	// prompt user to input command
	char sessionID[64];
	char sessionScan[64];
	char text[MAX_DATA];
    bool clientConnected = false;
	bool clientInSession = false;

    char inputBuffer[MAX_DATA];
    fd_set readfds;
    int fdmax = STDIN;
	
    while(1) {

        // clear fd set
        FD_ZERO(&readfds);

        // add STDIN to fd set
        FD_SET(STDIN, &readfds);
        fdmax = STDIN;

        // add server fd to fd set, if initialized
        if (clientConnected) {
            FD_SET(sockfd, &readfds);
            fdmax = sockfd;
        }

        // wait for activity on one of the fds
        if (select(fdmax+1, &readfds, NULL, NULL, NULL) == -1) {
            fprintf(stderr, "Select() failed\n");
        }

        // if something happened on STDIN, it is user input
        if (FD_ISSET(STDIN, &readfds)) {
            
            // read user input from stdin
            memset(inputBuffer, 0, sizeof(inputBuffer));
            fgets(inputBuffer, MAX_DATA, stdin);

            // check if empty user input
            int inputLen = strlen(inputBuffer)-1;
            if (inputLen <= 0) {
                fprintf(stderr,"Fgets() failed to read user input\n");
                continue;
            }
            
            // remove trailing newline character
            if (inputBuffer[inputLen] == '\n') {
                inputBuffer[inputLen] = '\0';
            }

            printf("\"%s\" was read from stdin.\n",inputBuffer);

            // login
            if (strstr(inputBuffer,"/login") != NULL) {
                
                // check if client already in session
                if (clientInSession) {
                    fprintf(stderr,"Client already in session, please log out before attempting new login\n");
                    continue;
                }

                // split string
                // get the first token
                char *token = strtok(inputBuffer, " ");
                int count = 0;                

                while (token != NULL) {
                    if (count == 1) {
                        strncpy(clientID, token, strlen(token));
                        clientID[strlen(token)] = '\0';
                        // printf("Client ID: %s\n",clientID);
                    } else if (count == 2) {
                        strncpy(clientPW, token, strlen(token));
                        clientPW[strlen(token)] = '\0';
                        // printf("Client PW: %s\n",clientPW);
                    } else if (count == 3) {
                        strncpy(serverIP, token, strlen(token));
                        serverIP[strlen(token)] = '\0';
                        // printf("Server IP: %s\n",serverIP);
                    } else if (count == 4) {
                        strncpy(serverPN, token, strlen(token));
                        serverPN[strlen(token)] = '\0';
                        // printf("Server PN: %s\n",serverPN);
                    }

                    count++;
                    token = strtok(NULL, " ");
                }

                // check that all required input arguments are passed in
                if (count < 4) {
                    memset(clientID, 0, 64);
                    memset(clientPW, 0, 64);
                    memset(serverIP, 0, 64);
                    memset(serverPN, 0, 64);
                    fprintf(stderr,"Login failed, missing arguments\n");
                    continue;
                }

                // try connecting to server
                portnum = atoi(serverPN);
                // check server IP is valid
                server = gethostbyname(serverIP);
                if (server == NULL) {
                    memset(clientID, 0, 64);
                    memset(clientPW, 0, 64);
                    memset(serverIP, 0, 64);
                    memset(serverPN, 0, 64);
                    fprintf(stderr,"Server DNS not found\n");
                    continue;
                }

                // create socket
                sockfd = socket(AF_INET, SOCK_STREAM, 0);
                if (sockfd < 0) {
                    memset(clientID, 0, 64);
                    memset(clientPW, 0, 64);
                    memset(serverIP, 0, 64);
                    memset(serverPN, 0, 64);
                    fprintf(stderr,"Socket() failed\n");
                    continue;
                }
                printf("Server %d\n",sockfd);

                memcpy((char *)&serveraddr.sin_addr.s_addr,(char *)server->h_addr,server->h_length);
                serveraddr.sin_port = htons(portnum);
                
                if( connect(sockfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0 ) {
                    memset(&serveraddr, 0, sizeof(serveraddr));
                    serveraddr.sin_family = AF_INET;
                	fprintf(stderr, "Connect() failed\n");
                	continue;
                }

                printf("Server connection established\n");
                clientConnected = true;

                // send packet to server to verify credentials
                struct lab3message packet;
                packet.type = LOGIN;
                packet.size = PACKET_SIZE;
	            
                strncpy(packet.source, clientID, MAX_NAME);
	            strncpy(packet.data, clientPW, MAX_DATA);

	            if( send(sockfd, &packet, sizeof(packet), 0) < 0 ) {
	            	fprintf(stderr,"Login packet send failed\n");
	            	continue;
	            }
                
            }
            // logout
            else if (strstr(inputBuffer, "/logout") != NULL) {
                struct lab3message packet;
                packet.type = EXIT;
                packet.size = PACKET_SIZE;

                // check that client is actually logged in
                if (!clientConnected) {
                    fprintf(stderr,"Please log in with a valid client first\n");
                    continue;
                }

                strncpy(packet.source, clientID, MAX_NAME);
                
                if ( send(sockfd, &packet, sizeof(packet), 0) < 0) {
                    fprintf(stderr,"Logout packet send failed\n");
                    continue;
                }

                
                printf("Client \"%s\" has logged out\n", clientID);
                // clear info
                memset(clientID, 0, 64);
                memset(clientPW, 0, 64);
                memset(serverIP, 0, 64);
                memset(serverPN, 0, 64);
                memset(&serveraddr, 0, sizeof(serveraddr));
                serveraddr.sin_family = AF_INET;

                // close socket
                close(sockfd);
                clientConnected = false;
                
            }
            // join session OR create session
            else if (strstr(inputBuffer, "/joinsession") != NULL || strstr(inputBuffer, "/createsession") != NULL) {
                bool createSession = false;
                
                // check if client already in session
                if (clientInSession) {
                    fprintf(stderr,"Client already in session, please log out before creating new session\n");
                    continue;
                }

                // split string
                // get the first token
                char *token = strtok(inputBuffer, " ");
                if (strstr(token,"/createsession") != NULL) {
                    createSession = true;
                }
                int count = 0;

                while (token != NULL) {
                    if (count == 1) {
                        strncpy(sessionScan, token, strlen(token));
                        sessionScan[strlen(token)] = '\0';
                    }
                    
                    count++;
                    token = strtok(NULL, " ");
                }
                // check that all required input arguments are passed in
                if (count < 1) {
                    memset(sessionScan, 0, 64);
                    fprintf(stderr,"Join session failed, missing arguments\n");
                    continue;
                }
                
                // send packet to server
                struct lab3message packet;
                if (createSession) {
                    packet.type = NEW_SESS;
                } else {
                    packet.type = JOIN;
                }
                packet.size = PACKET_SIZE;

                strncpy(packet.source, clientID, MAX_NAME);
                strncpy(packet.data, sessionScan, MAX_DATA);

                if ( send(sockfd, &packet, sizeof(packet), 0) < 0 ) {
                    memset(sessionScan, 0, 64);
                    fprintf(stderr,"Join session send failed\n");
                    continue;
                }
            }
            // leave session
            else if (strstr(inputBuffer, "leavesession") != NULL) {
                if (!clientInSession) {
                    fprintf(stderr,"Client \"%s\" is not in any active session yet, cannot leave a session\n", clientID);
                    continue;
                }
                
                // send packet to server
                struct lab3message packet;
                packet.type = LEAVE_SESS;
                packet.size = PACKET_SIZE;

                strncpy(packet.source, clientID, MAX_NAME);
                strncpy(packet.data, sessionID, MAX_DATA);

                if ( send(sockfd, &packet, sizeof(packet), 0) < 0 ) {
                    fprintf(stderr,"Leave session send failed\n");
                    continue;
                }

                // clear info
                printf("Client \"%s\" has left session \"%s\"\n", clientID, sessionID);
                memset(sessionID, 0, 64);
                clientInSession = false;
            }
            // list
            else if (strstr(inputBuffer, "list") != NULL) {
                
                // send packet to server
                struct lab3message packet; 
                packet.type = QUERY;
                packet.size = PACKET_SIZE;

                strncpy(packet.source, clientID, MAX_NAME);
                
                if ( send(sockfd, &packet, sizeof(packet), 0) < 0 ) {
                    fprintf(stderr, "Query send failed\n");
                    continue;
                }
            }
            // quit (first leave session, if in active session, then log out
            else if (strstr(inputBuffer, "quit") != NULL) {
                
                struct lab3message leave_packet, logout_packet;
                // check if client is even connected
                if (!clientConnected) {
                    printf("No established connection, just exit\n");
                    break;
                }

                // check if client is in active session
                if (!clientInSession) {
                    printf("Client \"%s\" is not in any active session, just log out\n", clientID);
                    goto logout;
                }

leavesession:
                // send packet to server
                leave_packet.type = LEAVE_SESS;
                leave_packet.size = PACKET_SIZE;

                strncpy(leave_packet.source, clientID, MAX_NAME);
                strncpy(leave_packet.data, sessionID, MAX_DATA);

                if ( send(sockfd, &leave_packet, sizeof(leave_packet), 0) < 0 ) {
                    fprintf(stderr, "Quit (leave session) send failed\n");
                    continue;
                }

                // clear info
                printf("Client \"%s\" has left session \"%s\"\n", clientID, sessionID);
                memset(sessionID, 0, 64);
                clientInSession = false;
logout:
                // send packet to server
                logout_packet.type = EXIT;
                logout_packet.size = PACKET_SIZE;

                strncpy(logout_packet.source, clientID, MAX_NAME);

                if ( send(sockfd, &logout_packet, sizeof(logout_packet), 0) < 0 ) {
                    fprintf(stderr, "Quit (log out) send failed\n");
                    if (!clientInSession) {
                        continue;
                    } else {
                        break;
                    }
                }

                printf("Client \"%s\" has logged out\n", clientID);
                // clear info
                memset(clientID, 0, 64);
                memset(clientPW, 0, 64);
                memset(serverIP, 0, 64);
                memset(serverPN, 0, 64);
               
                // closet socket
                close(sockfd);
                clientConnected = false; 

                break;
            
            }
            // write message
            else {
                
                // check if client is connected
                if (!clientConnected) {
                    fprintf(stderr, "No established connection, log in with valid client name and password in order to send messages\n");
                    continue;
                }

                // check if client is in active session
                if (!clientInSession) {
                    fprintf(stderr, "Client \"%s\" is not in any active session, join a session in order to send messages\n", clientID);
                    continue;
                }

                // send packet to server
                struct lab3message packet;
                packet.type = MESSAGE;
                packet.size = PACKET_SIZE;

                strncpy(packet.source, clientID, MAX_NAME);
                strncpy(packet.data, inputBuffer, MAX_DATA);

                if ( send(sockfd, &packet, sizeof(packet), 0) < 0 ) {
                    fprintf(stderr,"Message send failed\n");
                    continue;
                }

                printf("Client \"%s\" successfully sent message to all other clients in session \"%s\"\n", clientID, sessionID);
            }
        }

        // if something happend on sockfd, it is an incoming packet from the server
        if (FD_ISSET(sockfd, &readfds)) {
            struct lab3message packet;
	        if( recv(sockfd, &packet, sizeof(packet), 0) < 0 ) {
	        	fprintf(stderr,"Recv() failed\n");
	        	continue;
	        }

            // login ack
	        if (packet.type == LO_ACK) {
	        	printf("Login is acknowledged\n");
	        }
            // login nack
	        else if (packet.type == LO_NAK) {
	        	fprintf(stderr,"Login is not acknowledged\n");
	        	fprintf(stderr,"Reason: %s\n", packet.data);
                clientConnected = false;
            }
            // join ack
            else if (packet.type == JN_ACK) {
                printf("Join session is acknowledged\n");
                clientInSession = true;
                strncpy(sessionID, packet.data, strlen(packet.data));
                sessionID[strlen(packet.data)] = '\0';
                printf("Client \"%s\" has successfully joined session \"%s\"\n", clientID, sessionID);
            }
            // join nak
            else if (packet.type == JN_NAK) {
                fprintf(stderr, "Join session is not acknowledged\n");
                fprintf(stderr, "Reason: %s\n", packet.data);
            }
            // new session ack
            else if (packet.type == NS_ACK) {
                printf("Create session is acknowledged\n");
                clientInSession = true;
                strncpy(sessionID, packet.data, strlen(packet.data));
                sessionID[strlen(packet.data)] = '\0';
                printf("Client \"%s\" has successfully joined session \"%s\"\n", clientID, sessionID);
            }
            // query ack
            else if (packet.type == QU_ACK) {
                printf("Query is acknowledged\n");
                printf("List of available sessions and in-session clients: \n%s", packet.data);
            }
            // incoming message
            else if (packet.type == MESSAGE) {
                if (!clientInSession) {
                    fprintf(stderr,"Client \"%s\" is not in any active session yet, should not receive multicast messages\n", clientID);
                    continue;
                }
                printf("Message sent by \"%s\" from session \"%s\" is as follows:\n", packet.source, sessionID);
                printf("\t%s\n", packet.data);
            }
        
        }
 
		// /* poll for potential input message with timeout */

		// printf("Please enter command: ");
		// scanf("%s", command);

		// /* /quit			safe logout and terminate the program		*/
		// else if( strcmp(command, "/quit") == 0 ) {
		// 	if(clientInSession) { // leave the session if connected to one
		// 		bzero((char *)&packet, sizeof(packet));
		// 		packet.type = LEAVE_SESS;
		// 		packet.size = PACKET_SIZE;
		// 		strncpy(packet.source, clientID, MAX_NAME);
		// 		strncpy(packet.data, sessionID, MAX_DATA);
		// 		
		// 		if( send(sockfd, &packet, sizeof(packet), 0) < 0 ) {
		// 			printf("ERROR: LEAVE_SESS send fails.\n");
		// 			return -1;
		// 		}
		// 		clientInSession = false;
		// 		printf("User \"%s\" successfully left session \"%s\".\n", clientID, sessionID);
		// 		sessionID[0] = '\0';
		// 	}

		// 	bzero((char *)&packet, sizeof(packet)); // safe logout
		// 	packet.type = EXIT;
		// 	packet.size = PACKET_SIZE;
		// 	strncpy(packet.source, clientID, MAX_NAME);

		// 	if( send(sockfd, &packet, sizeof(packet), 0) < 0 ) {
		// 		printf("ERROR: LOGOUT send fails.\n");
		// 		return -1;
		// 	}
		// 	printf("User \"%s\" is successfully logged out.\n", clientID);

		// 	break;
		// }

		// /* <text>			send a message to current conference session	*/
		// else {
		// 	bzero((char *)&packet, sizeof(packet));
		// 	packet.type = MESSAGE;
		// 	packet.size = PACKET_SIZE;
		// 	strncpy(packet.source, clientID, MAX_NAME);

		// 	bzero((char *)text, MAX_DATA);
		// 	if( strlen(command) < MAX_DATA ) { // concatenate the first word in message (scanned by command)
		// 		strcat(text, command);
		// 		text[strlen(command)] = '\0';
		// 	}
		// 	char c = getchar();
		// 	while( c != '\n' ) { // scan the entire message before \n
		// 		int len = strlen(text);
		// 		if( (len + 1) < MAX_DATA ) {
		// 			text[len] = c;
		// 			text[len+1] = '\0';
		// 			c = getchar();
		// 		}
		// 		else {
		// 			break;
		// 		}
		// 	}
		// 	strncpy(packet.data, text, MAX_DATA);

		// 	if(clientInSession) { // send the message if client is in a session
		// 		if( send(sockfd, &packet, sizeof(packet), 0) < 0 ) {
		// 			printf("ERROR: MESSAGE send fails.\n");
		// 			return -1;
		// 		}
		// 		printf("Message \"%s\" is successfully sent to session \"%s\".\n", packet.data, sessionID);
		// 	}
		// 	else {
		// 		printf("ERROR: User \"%s\" is not in a session yet.\n", clientID);
		// 		printf("       Cannot print message: \"%s\"\n", packet.data);
		// 	}
		// }

	}

	printf("Program terminated.\n");
	return 0;
}


