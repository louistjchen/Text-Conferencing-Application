/*
 * 	ECE361 - Text Conferencing Lab
 *
 * 	Louis Chen		1000303502
 * 	Chia-Hang Chang		1000611260
 *
 */

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
    int             num_connected_clients;
    int             connected_client_fds[MAX_NUM_CLIENTS];
    bool            connected_client_status[MAX_NUM_CLIENTS];
    char*           connected_client_ip_addr[MAX_NUM_CLIENTS];
    unsigned int    connected_client_port_no[MAX_NUM_CLIENTS];
} session;

session* session_list[MAX_NUM_CLIENTS] = {NULL}; // at most 1 session per client
// /* DEFINE END - list of session IDs and corresponding info */

/* FUNCTION BEGIN - broadcast to all connected clients */
void broadcast_to_all_connected_clients(int client_fd, lab3message* outgoing_msg) {
    int i, j;
    bool found_match = false;
    for (i = 0; i < MAX_NUM_CLIENTS; i++) {
        if (session_list[i] != NULL) {
            for (j = 0; j < MAX_NUM_CLIENTS; j++) {
                if (session_list[i]->connected_client_fds[j] == client_fd) {
                    found_match = true;
                    goto broadcast;
                }
            }
        }
    }
broadcast:
    if (found_match) {
        printf("Client %s is in session ID \"%s\", broadcast to all other clients in this session\n", outgoing_msg->source, session_list[i]->session_id);
        for (j = 0; j < MAX_NUM_CLIENTS; j++) {
            int tmp_fd = session_list[i]->connected_client_fds[j];
            if (tmp_fd > -1 && tmp_fd != client_fd) {
                if (send(tmp_fd, outgoing_msg, sizeof(*outgoing_msg),0) == -1) {
                    fprintf(stderr,"Send() failed\n");
                }
            } 
        }
    } else {
        printf("Client %s is not in a session, do nothing\n", outgoing_msg->source);
    }
    return;
}
/* FUNCTION END - broadcast to all connected clients */

/* FUNCTION BEGIN - print sessions and clients */
void print_sessions_and_clients(lab3message* outgoing_msg) {
    int i, j;
    for (i = 0; i < MAX_NUM_CLIENTS; i++) {
        sprintf(outgoing_msg->data,"\tSession ID:");
        if (session_list[i] != NULL) {
            sprintf(outgoing_msg->data,"%s\n",session_list[i]->session_id);
            for (j = 0; j < MAX_NUM_CLIENTS; j++) {
                sprintf(outgoing_msg->data,"\t\tClient ID:");    
                if (session_list[i]->connected_client_status[j] == true) {
                    sprintf(outgoing_msg->data,"%s\n",client_list[j]);
                }
            }
        }
    }
    return;
}
/* FUNCTION END - print sessions and clients */

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

/* FUNCTION BEGIN - leave session by client fd */
void leave_session_by_fd(int client_fd) {
    int i, j;
    bool found_match = false;
    for (i = 0; i < MAX_NUM_CLIENTS; i++) {
        for (j = 0; j < MAX_NUM_CLIENTS; j++) {
            if (session_list[i] != NULL) {
                if (session_list[i]->connected_client_fds[j] == client_fd) {
                    found_match = true;
                    goto found;
                }
            }
        }
    }
found:
    if (found_match) {
        printf("Client %s has left session ID \"%s\"\n",client_list[j],session_list[i]->session_id);
        session_list[i]->num_connected_clients--;
        session_list[i]->connected_client_fds[j] = -1;
        session_list[i]->connected_client_status[j] = false;
        if (session_list[i]->connected_client_ip_addr[j] != NULL) {
            free(session_list[i]->connected_client_ip_addr[j]);
            session_list[i]->connected_client_ip_addr[j] = NULL;
        }
        // if no more connected clients, kill the session
        if (session_list[i]->num_connected_clients == 0) {
            printf("No more clients connected to session ID \"%s\", killing the session\n",session_list[i]->session_id);
            free(session_list[i]);
            session_list[i] = NULL;
        }
    }
    return;
}
/* FUNCTION END - leave session by client fd */

/* FUNCTION BEGIN - join session */
void join_session(int currfd, char* client_id, char* session_id, char* client_ip_addr, unsigned short client_port_no) {
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
            session_list[i]->num_connected_clients++;
            session_list[i]->connected_client_fds[index] = currfd;
            session_list[i]->connected_client_status[index] = true;
            if (session_list[i]->connected_client_ip_addr[index] == NULL) {
                session_list[i]->connected_client_ip_addr[index] = (char *) malloc( sizeof(char) * (strlen(client_ip_addr)+1));
            }
            strncpy(session_list[i]->connected_client_ip_addr[index],client_ip_addr,strlen(client_ip_addr));
            session_list[i]->connected_client_ip_addr[index][strlen(client_ip_addr)] = '\0';
            session_list[i]->connected_client_port_no[index] = client_port_no;
            break;
        }
    }
    return;
}
/* FUNCTION END - join session */



/* FUNCTION BEGIN - create session */
bool create_session(char* client_id, char* session_id, unsigned short client_port_no) {
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
            session_list[first_null_index]->num_connected_clients = 0;
            session_list[first_null_index]->connected_client_fds[j] = -1;
            session_list[first_null_index]->connected_client_status[j] = false;
            session_list[first_null_index]->connected_client_ip_addr[j] = NULL;
            session_list[first_null_index]->connected_client_port_no[j] = client_port_no;
        }
    }
    return found_match;
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
    // set to true if session to create already exists
    bool session_exists = false;
    // tmp counters
    int i, j;
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
            join_session(clientfds[fd_index],incoming_msg->source,incoming_msg->data,client_ip_addr,client_port_no);
            outgoing_msg->type = JN_ACK;
            snprintf(outgoing_msg->data,MAX_DATA,incoming_msg->data);
            printf("Client %s joined session ID \"%s\" successfully\n",outgoing_msg->source,incoming_msg->data);
            break;
        case LEAVE_SESS:
            // free client entry from session
            leave_session_by_fd(clientfds[fd_index]);
            break;
        case NEW_SESS:
            // create new session, and add client entry to session; if session already exists, join existing session
            session_exists = create_session(incoming_msg->source,incoming_msg->data,client_port_no);
            join_session(clientfds[fd_index],incoming_msg->source,incoming_msg->data,client_ip_addr,client_port_no);
            outgoing_msg->type = NS_ACK;
            strncpy(outgoing_msg->data,incoming_msg->data,strlen(incoming_msg->data));
            outgoing_msg->data[strlen(incoming_msg->data)] = '\0';
            if (!session_exists) {
                printf("Client %s created new session ID \"%s\" successfully\n",outgoing_msg->source,incoming_msg->data);
            }
            printf("Client %s joined new session ID \"%s\" successfully\n",outgoing_msg->source,incoming_msg->data);
            break; 
        case MESSAGE:
            // broadcast message to all other clients in same session
            outgoing_msg->type = MESSAGE;
            strncpy(outgoing_msg->data,incoming_msg->data,strlen(incoming_msg->data));
            outgoing_msg->data[strlen(incoming_msg->data)] = '\0';
            broadcast_to_all_connected_clients(clientfds[fd_index],outgoing_msg);
            break;
        case QUERY:
            // output list of connected clients and sessions
            printf("Client about to query for connected clients and sessions\n");
            outgoing_msg->type = QU_ACK;
            for (i = 0; i < MAX_NUM_CLIENTS; i++) {
                if (session_list[i] != NULL) {
                    strcat(outgoing_msg->data, "\tSession ID: ");
                    strcat(outgoing_msg->data, session_list[i]->session_id);
                    strcat(outgoing_msg->data, "\n");
                    for (j = 0; j < MAX_NUM_CLIENTS; j++) {
                        if (session_list[i]->connected_client_status[j] == true) {
                            strcat(outgoing_msg->data, "\t\tClient ID: ");
                            strcat(outgoing_msg->data, client_list[j]);
                            strcat(outgoing_msg->data, "\n");
                        }
                    }
                }
            }
            if (strlen(outgoing_msg->data) == 0) {
                strcat(outgoing_msg->data,"\tNo active sessions\n");
            }
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
    serverfd = socket(AF_INET, SOCK_STREAM, 0);
    if (serverfd < 0) {
        fprintf(stderr,"Failed to create server socket\n");
        return -1;
    }
    printf("Server %d\n", serverfd);

    // bind internet address to socket
    if (bind(serverfd, (struct sockaddr *) &server_addr_info, sizeof(server_addr_info)) < 0) {
        fprintf(stderr,"Failed to bind internet address to server socket\n");    
        return -1;
    }

    // set sock options
    int opt = true;
    setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, (char *) &opt, sizeof(opt));

    // need to implement listen() and select()
    if (listen(serverfd, 10) < 0) { // at most 10 clients
        fprintf(stderr,"Failed to listen for incoming client connections\n");
    }
    printf("Listening for incoming client connections\n");

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
                    printf("Hard disconnect socket %d\n", currfd);
                    // remove client from its active session
                    leave_session_by_fd(currfd);
                    // disconnect client by fd index
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
                    // remove client from its active session 
                    leave_session_by_fd(currfd);
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
                        printf("Entered !login_success or exit\n");
                        if (incoming_msg.type == EXIT) {
                            leave_session_by_fd(currfd);
                            printf("Client %s has logged out\n",incoming_msg.source);
                        }
                        disconnect_client_by_fd_index(j);
                        close(currfd);
                        clientfds[j] = -1;
                    }
                    if (incoming_msg.type == LEAVE_SESS) {
                        printf("Entered leave_sess\n");
                        leave_session_by_fd(currfd);
                    }
                    
                }
            } // END got new incoming connection
        } // END looping through file descriptors
    } // END while loop

    
    return 0;
}

