/* CMPS 352 - Team Project Fall 2018
** Team 1: Sean McTiernan, Gianni Mejia, Danielle Abril, David Albertson
** 11-9-2018
** 
** This program acts as the clientside of a group chat, which allows multiple
** users to send and receive messages to and from each other.
** The user sends a message through the client to the server, then the server 
** relays the message to each user connected to the server.
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#define PORT "17150"

// GLOBAL VARIABLE
int clientFlag = 0;

// DECLARATIONS
void *readFromKB(void *ptr);
void *clientReceive(void *ptr);
int get_server_connection(char *hostname, char *port);
void compose_http_request(char *http_request, char *filename);
void web_browser(int p_conn, char *message);
void print_ip( struct addrinfo *ai);

int main(int argc, char *argv[]) {
	int p_conn;  
    char http_request[128];
	pthread_t readfromKB, cReceive;
	
    if (argc != 3) {
		printf("usage: client HOST HTTPORT \n");
        exit(1);
    }

    // get a connection to server
    if ((p_conn = get_server_connection(argv[1], argv[2])) == -1) {
       printf("connection error\n");
       exit(1);
    }

	pthread_create(&readfromKB, NULL, readFromKB, (void *) (long) p_conn);
	pthread_create(&cReceive, NULL, clientReceive, (void *) (long) p_conn);
	
	pthread_join(readfromKB, NULL);
	pthread_join(cReceive, NULL);
    // close the socket when done
    close(p_conn);
}

/* This function is used to read keyboard input from a user and send it 
** to the server.
*/
void *readFromKB(void *ptr) {
	int keepGoing = 1;
	char message[128];
	char username[30];
	char password[30];
	int socket = (int) ptr;
	char userandmessage[158];
	char exit[10] = "==exit==\n";
	char typeCode[4]; // Type 1 = regular message; Type 2 = join group; Type 3 = disconnect
	char type1[4] = "/=1";
	char type2[4] = "/=2";
	char type3[4] = "/=3";
	char join1[12] = "/join cs_1\n";
	char join2[12] = "/join cs_1\n";
	char join3[10] = "/join os\n";
	printf("Please enter your username: ");
	fgets(username, 30, stdin);
	if(send(socket, username, sizeof(username), 0) < 0) {
		perror("send");
	}
	printf("Please enter your password: ");
	fgets(password, 30, stdin);
	if(send(socket, password, sizeof(password), 0) < 0) {
		perror("send");
	}

	while(keepGoing) {
		fgets(message, 128, stdin);
		if(!strchr(message, '\n')) {
			while(fgetc(stdin) != '\n');
		}
		if (strcmp(message, "\n") == 0) {
			//do nothing
		}
		else if(strcmp(message, "/help\n") == 0){
			printf("To send a message to a group type the name of the group followed by the message\n");
			printf("To join a group type /join followed by the name of the group\n");
			printf("To quit type ==exit==\n");
		}
		else if(strcmp(message, join1) == 0){
			printf("joining cs_1\n");
			if(send(socket, join1, sizeof(join1), 0) < 0) {
                perror("send");
            }
        }
        else if(strcmp(message, join2) == 0){
            printf("joining cs_2\n");
            if(send(socket, join2, sizeof(join2), 0) < 0) {
                perror("send");
            }
        }
        else if(strcmp(message, join3) == 0){
            printf("joining os\n");
			
            if(send(socket, join3, sizeof(join3), 0) < 0) {
                perror("send");
            }
        }
        else if(strcmp(message, exit) == 0) {//The case of a client disconnecting from the server
			keepGoing = 0;
			if(send(socket, type3, sizeof(type3), 0) < 0) {
				perror("send");
			}
			clientFlag = 1;
			break;
		}
		else {//send the message to the server
			if(send(socket, message, sizeof(message), 0) < 0) {
				perror("send");
			}
		}
		memset(message,'\0',128);
	}
	return NULL;
}

/* This function is responsible for receiving information for the 
** client from the server.
*/
void *clientReceive(void *ptr) {
	int socket = (int) ptr;
	char Message[128];
	int length;
	int end;
	int keepGoing = 1;
	while(keepGoing) {
		if(clientFlag == 1) { keepGoing = 0; }
		length = recv(socket, Message, 127, 0);
		Message[length] = '\0';
		printf("%s\n", Message);
		memset(Message, '\0', 128);
	}
	return NULL;
}

int get_server_connection(char *hostname, char *port) {
    int serverfd;
    struct addrinfo hints, *servinfo, *p;
    int status;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

   if ((status = getaddrinfo(hostname, port, &hints, &servinfo)) != 0) {
       printf("getaddrinfo: %s\n", gai_strerror(status));
       return -1;
    }

    print_ip(servinfo);
    for (p = servinfo; p != NULL; p = p ->ai_next) {
       // create a socket
       if ((serverfd = socket(p->ai_family, p->ai_socktype,
                           p->ai_protocol)) == -1) {
           printf("socket socket \n");
           continue;
       }

       // connect to the server
       if ((status = connect(serverfd, p->ai_addr, p->ai_addrlen)) == -1) {
           close(serverfd);
           printf("socket connect \n");
           continue;
       }
       break;
    }

    freeaddrinfo(servinfo);
   
    if (status != -1) return serverfd;
    else return -1;
}

void compose_http_request(char *http_request, char *filename) {
    strcpy(http_request, "GET /");
    strcpy(&http_request[5], filename);
    strcpy(&http_request[5+strlen(filename)], " ");
}

void web_browser(int p_conn, char *message) {
    int numbytes = 0;
    char buf[128];
    // send the message
    send(p_conn, message, strlen(message), 0);
    // receive message from server
    while ((numbytes=recv(p_conn, buf, sizeof(buf),  0)) > 0) {
        if (numbytes < 0)  {
           perror("recv");
           exit(1);
        }

       // the received may not end with a '\0' 
       buf[numbytes] = '\0';
       printf("%s",buf);
    }
}

void print_ip( struct addrinfo *ai) {
   struct addrinfo *p;
   void *addr;
   char *ipver;
   char ipstr[INET6_ADDRSTRLEN];
   struct sockaddr_in *ipv4;
   struct sockaddr_in6 *ipv6;
   short port = 0;

   for (p = ai; p !=  NULL; p = p->ai_next) {
      if (p->ai_family == AF_INET) {
         ipv4 = (struct sockaddr_in *)p->ai_addr;
         addr = &(ipv4->sin_addr);
         port = ipv4->sin_port;
         ipver = "IPV4";
      }
      else {
         ipv6= (struct sockaddr_in6 *)p->ai_addr;
         addr = &(ipv6->sin6_addr);
         port = ipv4->sin_port;
         ipver = "IPV6";
      }
      inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
      printf("serv ip info: %s - %s @%d\n", ipstr, ipver, ntohs(port));
   }
}
