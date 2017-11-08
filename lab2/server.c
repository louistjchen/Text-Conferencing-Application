#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>

// for debugging
#include <assert.h>

// some common macros
#define MAX_NAME            1024
#define MAX_DATA            1024
#define MAX_SESSION_ID_LEN  1024
#define MAX_IP_ADDR_LEN     14
#define MAX_PORT_NO         65535
#define MAX_NUM_CLIENTS     6

// some control macros
#define LOGIN       100
#define LO_ACK      101
#define LO_NAK      102
#define EXIT        103
#define JOIN        104
#define JN_ACK      105
#define JN_NAK      106
#define LEAVE_SESS  107
#define NEW_SESS    108
#define NS_ACK      109
#define MESSAGE     110
#define QUERY       111
#define QU_ACK      112

/* DEFINE BEGIN - message structure */
typedef struct lab3message {
    unsigned int type;
    unsigned int size;
    unsigned char source[MAX_NAME];
    unsigned char data[MAX_DATA];
} lab3message;
/* DEFINE END - message structure */

/* DEFINE BEGIN - global info */
char* client_list[MAX_NUM_CLIENTS] = {"haojin","zeyufan","chiahangchang","louischen","xinghangli","juntuchen"};
char* password_list[MAX_NUM_CLIENTS] = {"haojin","zeyufan","chiahangchang","louischen","xinghangli","juntuchen"};
int serverfd; // initialize in main()
int clientfds[MAX_NUM_CLIENTS]; // initialize in main()
char* fd_index_to_client_id_map[MAX_NUM_CLIENTS] = {NULL};
bool is_client_connected[MAX_NUM_CLIENTS] = {false};
/* DEFINE END - global info */

// /* DEFINE BEGIN - array of session IDs and corresponding connected clients */
// typedef struct connected_clients {
//     bool is_client_connected[MAX_NUM_CLIENTS];
//     char* client_id[MAX_NUM_CLIENTS];
//     char* client_ip_addr[MAX_NUM_CLIENTS];
//     unsigned short client_port_no[MAX_NUM_CLIENTS];
// } connected_clients;
// 
// // at most MAX_NUM_CLIENTS sessions, 1 per client
// connected_clients* session_id[MAX_NUM_CLIENTS] = {NULL}; 
// /* DEFINE END - array of session IDs and corresponding connected clients */

/* FUNCTION BEGIN - check connecting client is not logging in with taken client ID */
// return true if taken, else return false
bool is_client_id_taken(char* client_id) {
    int i;
    for (i = 0; i < MAX_NUM_CLIENTS; i++) {
        if (clientfds[i] > -1 && fd_index_to_client_id_map[i] != NULL) {
            if (strcmp(fd_index_to_client_id_map[i],client_id) == 0) {
                if (is_client_connected[i] == true) {
                    return true;
                }
            }
        }
    }
    return false;
}
/* FUNCTION END - check connecting client is not logging in with taken client ID */

/* FUNCTION BEGIN - disconnect client by fd index */
void disconnect_client_by_fd_index(int fd_index) {
    if (fd_index_to_client_id_map[fd_index] != NULL) {
        free(fd_index_to_client_id_map[fd_index]);
    }
    is_client_connected[fd_index] = false;
    return;
}
/* FUNCTION END - disconnect client by fd index */

/* FUNCTION BEGIN - map fd index to client ID */
void map_fd_index_to_client_id(int fd_index, char* client_id) {
    assert(fd_index_to_client_id_map[fd_index] == NULL);
    // dynamically allocate memory for client ID
    int len = strlen(client_id);
    fd_index_to_client_id_map[fd_index] = (char *) malloc( sizeof(char) * len);
    strncpy(fd_index_to_client_id_map[fd_index],client_id,len);
    return;
}
/* FUNCTION END - map fd index to client ID */


/* FUNCTION BEGIN - check connecting client is logging in with valid password */
// return true if valid, else return false
bool is_client_pw_valid(char* client_id, char* client_pw) {
    int i; 
    for (i = 0; i < MAX_NUM_CLIENTS; i++) {
        if (strcmp(client_list[i],client_id) == 0) {
            if (strcmp(password_list[i],client_pw) == 0) {
                return true;
            }
        }
    }
    return false;
}
/* FUNCTION END - check connecting client is logging in with valid password */



/* FUNCTION BEGIN - handle different packets */
void handle_msg(int fd_index, lab3message* incoming_msg, lab3message* outgoing_msg) {
    // check incoming msg has content
    assert(incoming_msg->type >= 100 && incoming_msg->type <= 112);
    
    // copy client ID into outgoing msg
    strncpy(outgoing_msg->source,incoming_msg->source,strlen(incoming_msg->source));

    // set outgoing msg size to size of lab3message
    outgoing_msg->size = sizeof(lab3message);

    // check incoming msg type
    int result = -1;
    switch(incoming_msg->type) {
        case LOGIN:
            // check that a connecting client is not logging in with taken client ID
            if (is_client_id_taken(incoming_msg->source) == true) {
                outgoing_msg->type = LO_NAK;
                snprintf(outgoing_msg->data,MAX_DATA,"client ID %s is already taken",outgoing_msg->source);
                fprintf(stderr,"Client ID %s is already taken\n",outgoing_msg->source);
            } else {
                // check that password is valid for given client
                if (is_client_pw_valid(incoming_msg->source,incoming_msg->data) == true) {                    
                    outgoing_msg->type = LO_ACK;
                    map_fd_index_to_client_id(fd_index,incoming_msg->source);
                    printf("Client %s logged in successfully\n",outgoing_msg->source);
                } else {
                    outgoing_msg->type = LO_NAK;
                    snprintf(outgoing_msg->data,MAX_DATA,"client %s does not have valid password",outgoing_msg->source);
                    fprintf(stderr,"Client %s does not have valid password\n",outgoing_msg->source);
                }
            } 
            break;
        case EXIT:
            // close client connection
            break;
        case JOIN:
            // check that session ID exists
            printf("Client about to join session\n");
            break;
        case LEAVE_SESS:
            // free client entry from session
            printf("Client about to leave session\n");
            break;
        case NEW_SESS:
            // create new session, and add client entry to session
            printf("Client about to create new session\n");
            break; 
        case MESSAGE:
            // broadcast message to all other clients in same session
            printf("Client about to broadcast message\n");
            break;
        case QUERY:
            // output list of connected clients and sessions
            printf("Client about to query for connected clients and sessions\n");
            break;
        default:
            // not sure
            break; 
    }
    return;
}
/* FUNCTION END - handle different packets */

int main(int argc, char **argv) {

    struct sockaddr_in server_addr_info;
    struct sockaddr_in client_addr_info;
    socklen_t client_addr_len = sizeof(client_addr_info);
    unsigned short port_no = 22000;
    serverfd = -1;
    // initialize client fds to -1
    int i;
    for (i = 0; i < MAX_NUM_CLIENTS; i++) {
        clientfds[i] = -1;
    }

    // check command line arguments
    if (argc < 2) {
        fprintf(stderr, "Port number not specified\n");
        exit(-1);
    }
    if (atoi(argv[1]) > MAX_PORT_NO) {
        fprintf(stderr, "Port number exceeds maximum limit\n");
        exit(-1);
    }
    port_no = atoi(argv[1]);

    // build server internet address
    bzero(&server_addr_info, sizeof(server_addr_info));
    server_addr_info.sin_family = AF_INET;
    server_addr_info.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr_info.sin_port = htons(port_no);

    // create server socket
    while (serverfd < 0) {
        serverfd = socket(AF_INET, SOCK_STREAM, 0);
        printf("Server %d\n", serverfd);
    }

    // bind internet address to socket
    int bind_success = -1;
    while (bind_success < 0) {
        bind_success = bind(serverfd, (struct sockaddr *) &server_addr_info, sizeof(server_addr_info));
    }

    // set sock options
    int opt = true;
    setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, (char *) &opt, sizeof(opt));

    // need to implement listen() and select()
    int listen_success = -1;
    while (listen_success < 0) {
        listen_success = listen(serverfd, 10); // at most 10 clients
    }
    printf("Listening for incoming clients\n");

    // fd_set masterfds;    // master file descriptor list
    fd_set readfds;      // temp file descriptor list
    
    // keep track of max file descriptor
    int currfd = -1;
    int newfd = -1;
    int fdmax = serverfd;

    // client data
    lab3message incoming_msg;
    lab3message outgoing_msg;
    int nbytes = 0;

    int fd_error = 0;
    socklen_t fd_error_len = sizeof(fd_error);

    while (true) {

        // clear fd set
        FD_ZERO(&readfds);
        
        // add server fd to fd set
        FD_SET(serverfd, &readfds);

        // add client fds to fd set
        int j;
        for (j = 0; j < MAX_NUM_CLIENTS; j++) {
            currfd = clientfds[j];
            if(currfd > -1) {
                // check client fd was not terminated halfway
                fd_error = 0;
                int fd_state = getsockopt(currfd, SOL_SOCKET, SO_ERROR, &fd_error, &fd_error_len);
                // successfully get error code, and zero error status
                if (fd_state == 0 && fd_error == 0) {
                    printf("Push socket %d into readfds\n",currfd);
                    FD_SET(currfd, &readfds);
                } else {
                    // disconnect client by fd index
                    printf("Disconnect socket \n");
                    disconnect_client_by_fd_index(j);
                    close(currfd);
                    clientfds[j] = -1;
                }
            }
            if (currfd > fdmax) {
                fdmax = currfd;
            }
        }

        // wait for activity on one of the fds
        if (select(fdmax+1, &readfds, NULL, NULL, NULL) == -1) {
            fprintf(stderr, "Select() failed\n");
            exit(-1);
        }
       
        // printf("Waiting for activity on one of the fds\n"); 
        for (j = 0; j < MAX_NUM_CLIENTS; j++) {
            currfd = clientfds[j];
            if (FD_ISSET(currfd, &readfds)) {
                printf("Socket %d is ready for read\n",currfd);
                // if something happened on server fd, it is an incoming client connection
                if (currfd == serverfd) {
                    bzero(&client_addr_info, client_addr_len);
                    newfd = accept(serverfd, (struct sockaddr *) &client_addr_info, &client_addr_len);

                    if (newfd == -1) {
                        fprintf(stderr, "Accept() failed\n");
                    } else {
                        // add new fd to array of client fds
                        int k;
                        for (k = 0; k < MAX_NUM_CLIENTS; k++) {
                            // add new fd in the first available position
                            if (clientfds[k] == -1) {
                                printf("Server accepted new connection at socket %d\n",newfd);
                                clientfds[k] = newfd;
                                break;
                            }
                        }
                    }
                // else it's an I/O operation on one of the client fds
                } else {
                    // got error or connection closed by client
                    if ((nbytes = recv(currfd, &incoming_msg, sizeof(incoming_msg), 0)) <= 0) {
                        // connection closed
                        if (nbytes == 0) {
                            fprintf(stderr,"Socket %d already closed connection\n",currfd);
                        // got error
                        } else {
                            fprintf(stderr,"Recv() failed\n");
                        }
                        // disconnect client by fd index
                        disconnect_client_by_fd_index(j);
                        close(currfd);
                        clientfds[j] = -1;
                    // got data from client
                    } else {
                        bzero(&outgoing_msg,sizeof(outgoing_msg));
                        handle_msg(j, &incoming_msg, &outgoing_msg);
                        // need to send outgoing msg to client
                        // if (incoming_msg.type == LOGIN || incoming_msg.type == JOIN || incoming_msg.type == NEW_SESS || incoming_msg.type == QUERY) {
                        //     if (FD_ISSET(currfd, &readfds)) {
                        //         if (send(currfd, &outgoing_msg, sizeof(outgoing_msg), 0) == -1) {
                        //             fprintf(stderr,"Send() failed\n");
                        //         }
                        //     }
                        // }
                    }
                } // END handle data from client
            } // END got new incoming connection
        } // END looping through file descriptors
    } // END while loop

    
    return 0;
}

// int select(int numfds, fd_set *readfds, fd_set *writefds, fdset *exceptfds, struct timeval *timeout);
// Setting timeout to NULL = never timeout, wait until 1st file descriptor is ready
// Setting timeout to zero = timeout immediately, poll all file descriptors in your sets

// FD_SET(int fd, fd_set *set);     -> Add fd to the set.
// FD_CLR(int fd, fd_set *set);     -> Remove fd from the set.
// FD_ISSET(int fd, fd_set *set);   -> Return true if fd is in the set.
// FD_ZERO(fd_set *set);            -> Clear all entries from the set.

// "netstat -ntlp | grep LISTEN"    -> Returns currently occupied port numbers

// recv(socket_fd, incoming_msg, sizeof(incoming_msg), MSG_PEEK | MSG_DONTWAIT)     -> non-blocking read

