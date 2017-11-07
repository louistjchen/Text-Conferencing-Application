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

// Some common macros
#define MAX_NAME            1024
#define MAX_DATA            1024
#define MAX_SESSION_ID_LEN  1024
#define MAX_IP_ADDR_LEN     14
#define MAX_PORT_NO         65535

// Some control macros
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
struct lab3message {
    unsigned int type;
    unsigned int size;
    unsigned char source[MAX_NAME];
    unsigned char data[MAX_DATA];
};
/* DEFINE END - message structure */

/* DEFINE BEGIN - client password list */
char* client_list[6] = {"haojin","zeyufan","chiahangchang","louischen","xinghangli","juntuchen"};
char* password_list[6] = {"haojin","zeyufan","chiahangchang","louischen","xinghangli","juntuchen"};
/* DEFINE END - client password list */

/* DEFINE BEGIN - connected client struct */
typedef struct connected_client {
    char* client_id[MAX_NAME];
    char* session_id[MAX_SESSION_ID_LEN];
    char* ip_addr[MAX_IP_ADDR_LEN];
    unsigned short port_no;
} connected_client;
/* DEFINE END - connected client struct */

int main(int argc, char **argv) {

    struct sockaddr_in server_addr_info;
    int serverfd = -1;
    unsigned short port_no = 22000;

    // check command line arguments
    if (argc < 2) {
        fprintf(stderr, "Port number not specified\n");
        exit(1);
    }
    if (atoi(argv[1]) > MAX_PORT_NO) {
        fprintf(stderr, "Port number exceeds maximum limit\n");
        exit(1);
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
    }

    // bind internet address to socket
    int bind_success = -1;
    while (bind_success < 0) {
        bind_success = bind(serverfd, (struct sockaddr *) &server_addr_info, sizeof(server_addr_info));
    }

    fd_set readfds, writefds;
    FD_ZERO(&readfds);
    FD_ZERO(&writefds);
    
    // need to implement listen() and select()


    return 0;
}

