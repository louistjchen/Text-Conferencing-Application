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
#define MAX_NUM_CLIENTS     6
#define MAX_PORT_NO         65535

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

// /* DEFINE BEGIN - list of session IDs and corresponding info */
typedef struct session {
    char            session_id[MAX_SESSION_ID_LEN];
    bool            client_connected_mask[MAX_NUM_CLIENTS];
    char*           client_ip_addr_mask[MAX_NUM_CLIENTS];
    unsigned int    client_port_no_mask[MAX_NUM_CLIENTS];
} session;

session* session_list[MAX_NUM_CLIENTS] = {NULL}; // at most 1 session per client
// /* DEFINE END - list of session IDs and corresponding info */

/* FUNCTION BEGIN - check that session exists */
bool is_session_valid(char* session_id) {
    int i;
    bool found_match = false;
    for (i = 0; i < MAX_NUM_CLIENTS; i++) {
        if (session_list[i] != NULL) {
            if (strcmp(session_list[i]->session_id,session_id) == 0) {
                found_match = true;
                break;
            }
        }
    }
    return found_match;
}
/* FUNCTION END - check that session exists */



/* FUNCTION BEGIN - join session */
void join_session(char* client_id, char* session_id, char* client_ip_addr, unsigned short client_port_no) {
    int index = -1;
    int i;
    // find index corresponding to client id
    for (i = 0; i < MAX_NUM_CLIENTS; i++) {
        if (strcmp(client_list[i],client_id) == 0) {
            index = i;
            break;
        }
    }
    // find matching session id
    for (i = 0; i < MAX_NUM_CLIENTS; i++) {
        // found match
        if (strcmp(session_list[i]->session_id,session_id) == 0) {
            session_list[i]->client_connected_mask[index] = true;
            if (session_list[i]->client_ip_addr_mask[index] == NULL) {
                session_list[i]->client_ip_addr_mask[index] = (char *) malloc( sizeof(char) * (strlen(client_ip_addr)+1));
            }
            strncpy(session_list[i]->client_ip_addr_mask[index],client_ip_addr,strlen(client_ip_addr));
            session_list[i]->client_ip_addr_mask[index][strlen(client_ip_addr)] = '\0';
            session_list[i]->client_port_no_mask[index] = client_port_no;
            break;
        }
    }
    return;
}
/* FUNCTION END - join session */



/* FUNCTION BEGIN - create session */
void create_session(char* client_id, char* session_id, unsigned short client_port_no) {
    int i;
    int first_null_index = MAX_NUM_CLIENTS;
    bool found_match = false;
    for (i = 0; i < MAX_NUM_CLIENTS; i++) {
        if (session_list[i] != NULL) {
            // found existing session with matching session id
            if (strcmp(session_list[i]->session_id,session_id) == 0) {
                found_match = true;
                break;
            }
        } else {
            if (i < first_null_index) {
                first_null_index = i;
            }
        }
    }
    if (!found_match) {
        session_list[first_null_index] = (session *) malloc( sizeof(session) );
        strncpy(session_list[first_null_index]->session_id,session_id,strlen(session_id));
        session_list[first_null_index]->session_id[strlen(session_id)] = '\0';
        int j;
        for (j = 0; j < MAX_NUM_CLIENTS; j++) {
            session_list[first_null_index]->client_connected_mask[j] = false;
            session_list[first_null_index]->client_ip_addr_mask[j] = NULL;
            session_list[first_null_index]->client_port_no_mask[j] = client_port_no;
        }
    }
    return;
}
/* FUNCTION END - create session */



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

/* FUNCTION BEGIN - check that client ID is valid */
bool is_client_id_valid(char* client_id) {
    int i;
    for (i = 0; i < MAX_NUM_CLIENTS; i++) {
        if (strcmp(client_list[i],client_id) == 0) {
            return true;
        }
    }
    return false;
}
/* FUNCTION END - check that client ID is valid */



/* FUNCTION BEGIN - disconnect client by fd index */
void disconnect_client_by_fd_index(int fd_index) {
    if (fd_index_to_client_id_map[fd_index] != NULL) {
        free(fd_index_to_client_id_map[fd_index]);
        fd_index_to_client_id_map[fd_index] = NULL;
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
    fd_index_to_client_id_map[fd_index] = (char *) malloc( sizeof(char) * (len+1)); // +1 for terminating NULL
    strncpy(fd_index_to_client_id_map[fd_index],client_id,len);
    fd_index_to_client_id_map[fd_index][len] = '\0';
    is_client_connected[fd_index] = true;
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
bool handle_msg(int fd_index, lab3message* incoming_msg, lab3message* outgoing_msg, char* client_ip_addr, unsigned short client_port_no) {
    // check incoming msg has content
    assert(incoming_msg->type >= 100 && incoming_msg->type <= 112);
    
    // copy client ID into outgoing msg
    strncpy(outgoing_msg->source,incoming_msg->source,strlen(incoming_msg->source));
    outgoing_msg->source[strlen(incoming_msg->source)] = '\0';

    // set outgoing msg size to size of lab3message
    outgoing_msg->size = sizeof(lab3message);

    // set to false if encounter any login failure
    bool login_result = true;
    // check incoming msg type
    switch(incoming_msg->type) {
        case LOGIN:
            // check that connecting client has valid client ID
            if (is_client_id_valid(incoming_msg->source) == false) {
                outgoing_msg->type = LO_NAK;
                snprintf(outgoing_msg->data,MAX_DATA,"client ID %s is not valid",outgoing_msg->source);
                fprintf(stderr,"Client ID %s is not valid\n",outgoing_msg->source);
                login_result = false;
                break;
            }
            // check that connecting client is not logging in with taken client ID
            if (is_client_id_taken(incoming_msg->source) == true) {
                outgoing_msg->type = LO_NAK;
                snprintf(outgoing_msg->data,MAX_DATA,"client ID %s is already taken",outgoing_msg->source);
                fprintf(stderr,"Client ID %s is already taken\n",outgoing_msg->source);
                login_result = false;
                break;
            }
            // check that password is valid for given client
            if (is_client_pw_valid(incoming_msg->source,incoming_msg->data) == false) {
                outgoing_msg->type = LO_NAK;
                snprintf(outgoing_msg->data,MAX_DATA,"client %s does not have valid password",outgoing_msg->source);
                fprintf(stderr,"Client ID %s does not have valid password\n",outgoing_msg->source);
                login_result = false;
                break;
            }
            // everything works up til now
            map_fd_index_to_client_id(fd_index,incoming_msg->source);
            outgoing_msg->type = LO_ACK;
            printf("Client %s logged in successfully\n",outgoing_msg->source);
            break;
        case EXIT:
            // close client connection
            break;
        case JOIN:
            // check that session exists
            if (is_session_valid(incoming_msg->data) == false) {
                outgoing_msg->type = JN_NAK;
                snprintf(outgoing_msg->data,MAX_DATA,"session ID %s does not exist",incoming_msg->data);
                fprintf(stderr,"Session ID %s does not exist\n",incoming_msg->data);
                break;
            }
            join_session(incoming_msg->source,incoming_msg->data,client_ip_addr,client_port_no);
            outgoing_msg->type = JN_ACK;
            snprintf(outgoing_msg->data,MAX_DATA,incoming_msg->data);
            printf("Client %s joined session ID %s successfully\n",outgoing_msg->source,incoming_msg->data);
            break;
        case LEAVE_SESS:
            // free client entry from session
            printf("Client about to leave session\n");
            break;
        case NEW_SESS:
            // create new session, and add client entry to session; if session already exists, join existing session
            create_session(incoming_msg->source,incoming_msg->data,client_port_no);
            join_session(incoming_msg->source,incoming_msg->data,client_ip_addr,client_port_no);
            outgoing_msg->type = NS_ACK;
            strncpy(outgoing_msg->data,incoming_msg->data,strlen(incoming_msg->data));
            outgoing_msg->data[strlen(incoming_msg->data)] = '\0';
            printf("Client %s created and joined new session ID \"%s\" successfully\n",outgoing_msg->source,incoming_msg->data);
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
    return login_result;
}
/* FUNCTION END - handle different packets */

int main(int argc, char **argv) {

    struct sockaddr_in server_addr_info;
    struct sockaddr_in client_addr_info;
    socklen_t client_addr_len = sizeof(client_addr_info);
    unsigned short port_no = 22000;
    serverfd = -1;
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
        fdmax = serverfd;

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
                    FD_SET(currfd, &readfds);
                } else {
                    // disconnect client by fd index
                    printf("Hard disconnect socket %d\n", currfd);
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
       
        // if something happened on server fd, it is an incoming client connection
        if (FD_ISSET(serverfd, &readfds)) {
            newfd = accept(serverfd, (struct sockaddr *) &client_addr_info, &client_addr_len);

            if (newfd == -1) {
                fprintf(stderr, "Accept() failed\n");
            } else {
                // add new fd to array of client fds
                int k;
                for (k = 0; k < MAX_NUM_CLIENTS; k++) {
                    // check if newfd already exists in clientfds
                    if (clientfds[k] == newfd) {
                        break;
                    }
                    // add new fd in the first available position
                    if (clientfds[k] == -1) {
                        printf("Server accepted new connection at socket %d\n",newfd);
                        clientfds[k] = newfd;
                        break;
                    }
                }
            }
        }

        // else it's an I/O operation on one of the client fds
        for (j = 0; j < MAX_NUM_CLIENTS; j++) {
            currfd = clientfds[j];
            if (FD_ISSET(currfd, &readfds)) {
                printf("Detected activity at socket %d\n",currfd);
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
                    // extract client IP address and port number
                    getpeername(currfd, (struct sockaddr *) &client_addr_info, &client_addr_len);
                    char* client_ip_addr = inet_ntoa(client_addr_info.sin_addr);
                    // clear outgoing msg
                    bzero(&outgoing_msg,sizeof(outgoing_msg));
                    bool login_success = handle_msg(j, &incoming_msg, &outgoing_msg, client_ip_addr, port_no);
                    // need to send outgoing msg to client
                    if (incoming_msg.type == LOGIN || incoming_msg.type == JOIN || incoming_msg.type == NEW_SESS || incoming_msg.type == QUERY) {
                        if (FD_ISSET(currfd, &readfds)) {
                            if (send(currfd, &outgoing_msg, sizeof(outgoing_msg), 0) == -1) {
                                fprintf(stderr,"Send() failed\n");
                            }
                        }
                    }
                    // need to perform proper exit on client socket or login failure
                    if (!login_success || incoming_msg.type == EXIT) {
                        printf("Entered exit\n");
                        disconnect_client_by_fd_index(j);
                        close(currfd);
                        clientfds[j] = -1;
                        if (incoming_msg.type == EXIT) {
                            printf("Client ID %s has logged out\n",incoming_msg.source);
                        }
                    }
                    
                }
            } // END got new incoming connection
        } // END looping through file descriptors
    } // END while loop

    
    return 0;
}

