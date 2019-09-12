/* CMPS 352 - Team Project Fall 2018
** Team 1: Sean McTiernan, Gianni Mejia, Danielle Abril, David Albertson
** 11-9-2018
** 
** This program acts as the server-side of a group chat, which allows multiple
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
#define HOST "freebsd1.cs.scranton.edu" // the hostname of the server
#define BACKLOG 10                      // how many pending connections queue will hold

typedef struct message {
	char msg[128];
	long timestamp;
	struct user *fromUser;
	struct message *nxtMessage;
	int isToCS_1;
	int isToCS_2;
	int isToOS;
} Message;

typedef struct MessageHeader {
	Message *headPtr;
	int count;
} messageHeader;

typedef struct user {
	char username[30];
	int isMemberOfCS_1;
	int isMemberOfCS_2;
	int isMemberOfOS;
	int socketID;
	int flag;
	struct user *nextUser;
	char password[30];
} User;

typedef struct userHeader {
	User *usrHeaderPtr;
	int usrCount;
} userHeader;

typedef struct GROUP {
	//char groupName[10];
	userHeader *userList;
	messageHeader *messageList;
} Group;

typedef struct CLIENTINFO {
	User *USER;
	userHeader *userHeaderPtr;
	messageHeader *clientMessageHeader;
} clientInfo;

void initializeMessageHeader(messageHeader *header) {
	header->headPtr = NULL;
	header->count = 0;
}

void initializeUserHeader(userHeader *hdr) {
	hdr->usrHeaderPtr = NULL;
	hdr->usrCount = 0;
}

void initializeUserGroup(Group *group) {
	userHeader *header = (userHeader *) malloc(sizeof(userHeader));
	group->userList=header;
	initializeUserHeader(header);
	messageHeader *msgHeader = (messageHeader *) malloc(sizeof(messageHeader));
	group->messageList=msgHeader;
	initializeMessageHeader(msgHeader);
}

messageHeader *cs1MessageList;
messageHeader *cs2MessageList;
messageHeader *osMessageList;
userHeader *cs1UserList;
userHeader *cs2UserList;
userHeader *osUserList;

void disconnect(int socket);
int checkName(User *comp1, User *comp2);
int checkPassword(User *code1, User *code2);
int userLogIn(User *usr, User *comp);
void initializeMessageHeader(messageHeader *header);
void initializeUserGroup(Group *group);
void *get_in_addr(struct sockaddr * sa);             // get internet address
int get_server_socket(char *hostname, char *port);   // get a server socket
int start_server(int serv_socket, int backlog);      // start server's listening
int accept_client(int serv_sock);                    // accept a connection from client
void *serverSend(void *ptr);						 // send messages to the client
void *serverReceive(void *ptr);						 // receive messages from the client
void start_subserver(clientInfo *client);            // start subserver as a thread
void *subserver(void *reply_sock_fd_ptr);            // subserver - subserver
void print_ip( struct addrinfo *ai);                 // print IP info from getaddrinfo()

int main(int argc, char *argv[]) {
    int http_sock_fd;			// server socket
    int reply_sock_fd;  		// client connection 
    int yes;
	userHeader *header = (userHeader *) malloc(sizeof(userHeader));
	initializeUserHeader(header);
	messageHeader *msgHeader = (messageHeader *) malloc(sizeof(messageHeader));
	initializeMessageHeader(msgHeader);
	
    if (argc != 2) {
       printf("Run: program port#\n");
       return 1;
    }
    // get a socket and bind to ip address and port
    http_sock_fd = get_server_socket(HOST, argv[1]);

    // get ready to accept connections
    if (start_server(http_sock_fd, BACKLOG) == -1) {
       printf("start server error\n");
       exit(1);
    }

    while(1) {  // accept() client connections
        if ((reply_sock_fd = accept_client(http_sock_fd)) == -1) {
            continue;
        }
		User *USR = (User *) malloc(sizeof(User));
		USR->socketID = reply_sock_fd;
		USR->flag = 0;
		
		clientInfo *client = (clientInfo *) malloc(sizeof(clientInfo));
		client->USER = USR;	
		client->userHeaderPtr = header;
		client->clientMessageHeader = msgHeader;
        // read from and write to sockets, close socket
		start_subserver(client);
		}
}

int get_server_socket(char *hostname, char *port) {
    struct addrinfo hints, *servinfo, *p;
    int status;
    int server_socket;
    int yes = 1;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((status = getaddrinfo(hostname, port, &hints, &servinfo)) != 0) {
       printf("getaddrinfo: %s\n", gai_strerror(status));
       exit(1);
    }

    for (p = servinfo; p != NULL; p = p ->ai_next) {
       // create a socket
       if ((server_socket = socket(p->ai_family, p->ai_socktype,
                           p->ai_protocol)) == -1) {
           printf("socket socket \n");
           continue;
       }
       // if the port is not released yet, reuse it.
       if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
         printf("socket option\n");
         continue;
       }

       // bind socket to an IP addr and port
       if (bind(server_socket, p->ai_addr, p->ai_addrlen) == -1) {
           printf("socket bind \n");
           continue;
       }
       break;
    }
    print_ip(servinfo);
    freeaddrinfo(servinfo);   // servinfo structure is no longer needed. free it.

    return server_socket;
}

int start_server(int serv_socket, int backlog) {
    int status = 0;
    if ((status = listen(serv_socket, backlog)) == -1) {
        printf("socket listen error\n");
    }
    return status;
}

/* NOTE: the value of reply_sock_fd is passed to pthread_create() as the
         parameter, instead of the address of reply_sock_fd. This is
         necessary because reply_sock_fd is a parameter (or local varaible)
         of start_server. After start_server returns, reply_sock_id becomes
         invalid. if the new thread is not executed before start_server()
         returns, the thread would be an invalid reply_sock_fd. Passing the
         value of reply_sock_fd avoids this problem, since the valid is
         copied to the local variable of the thread. Because our server1 is
         of 64-bits and int in c is 32 bits, we need to do type conversions
         to not cause compilation warnings
*/ 
void start_subserver(clientInfo *client) {
   pthread_t pthread;
   if (pthread_create(&pthread, NULL, subserver, (void *)client) != 0) {
      printf("failed to start subserver\n");
   }
   else {
      printf("subserver %ld started\n", (unsigned long)pthread);
   }
}

/* this is the subserver who really communicate
   with client through the reply_sock_fd.
*/
void *subserver(void *ptr) {
	clientInfo *client = (clientInfo *) ptr;
	int replySocket = client->USER->socketID;
	pthread_t sender, receiver;

	pthread_create(&sender, NULL, serverSend, (void *) client);
	pthread_create(&receiver, NULL, serverReceive, (void *) client);
	
	pthread_join(sender, NULL);
	pthread_join(receiver, NULL);

    // for testing purposes
    printf("subserver ID = %ld\n", (unsigned long) pthread_self());
    close(replySocket);

    return NULL;
 }

/* This function appends a message node to the end of the message list.
*/
void appendToMessageList(messageHeader *headerPtr, Message *nodePtr) {
	Message *temp = headerPtr->headPtr;
	if (temp == NULL) {
		headerPtr->headPtr = nodePtr;
	}
	else {
		while(temp->nxtMessage != NULL) {
			temp = temp->nxtMessage;
		}
		temp->nxtMessage = nodePtr;
		nodePtr->nxtMessage = NULL;
	}
	headerPtr->count = headerPtr->count + 1;
}

/* This function appends a user node to the end of the user list.
*/
void appendToUserList(userHeader *headerPtr, User *nodePtr) {
	User *temp = headerPtr->usrHeaderPtr;
	if (temp == NULL) {
		headerPtr->usrHeaderPtr = nodePtr;
	}
	else {
		while(temp->nextUser != NULL) {
			temp = temp->nextUser;
		}
		temp->nextUser = nodePtr;
		nodePtr->nextUser = NULL;
	}
	headerPtr->usrCount = headerPtr->usrCount + 1;
}

User *userExists(User *usr, userHeader *headerPtr) {
   User *current = headerPtr->usrHeaderPtr;
   if (current == NULL) {
	   printf("No users in list. Append.\n");
   }
   else {
	   while (current->nextUser != NULL) {
		   if (checkName(current, usr) == 1) {
			   break;
		   }
		   else {
			   current = current->nextUser;
		   }
	   }
	   if (checkName(current, usr) == 1) {
		   printf("Log in.\n");
	   }
	   else {
		   current = NULL;
		   printf("Register.\n");
	   }
   }
   return current;
}

int checkName(User *comp1, User *comp2) {
	int result = 0;
	char name1[30];
	char name2[30];
	strcpy(name1, comp1->username);
	strcpy(name2, comp2->username);
    int i;
    for (i=0; name1[i] != '\0' || name2[i] != '\0'; i++) {
		if (name1[i] != name2[i]) {
			strcpy(name2, comp2->username);
			break;
		}
		result = 1;
	}
	return result;
}

int checkPassword(User *code1, User *code2) {
	int match = 0;
	char pass1[30];
	char pass2[30];
	strcpy(pass1, code1->password);
	strcpy(pass2, code2->password);
	int j;
    for (j=0; pass1[j] != '\0' || pass2[j] != '\0'; j++) {
		if (pass1[j] != pass2[j]) {
			printf("Password does not match.\n");
			break;
		}
		match = 1;
	}
	return match;
}

int userLogIn(User *usr, User *comp) {
   int correct;
   if (checkPassword(usr, comp) == 0) {
      printf("Incorrect password. Disconnecting...\n");
	  correct = 0;
   }
   else {
      printf("Correct password. Continuing...\n");
	  correct = 1;
   }
   return correct;
}

/* This function is responsible for sending information from the server to the client.
*/
void *serverSend(void *ptr) {
	clientInfo *client = (clientInfo *) ptr;
	messageHeader *MessgHeaderPtr = client->clientMessageHeader;
	userHeader *usrHdrPtr = client->userHeaderPtr;
	User *usr = client->USER;
	char *name = usr->username;
	int socket = client->USER->socketID;
	Message *tracker;
	int compare = 0;
	int i;
	send(socket, name, sizeof(name), 0);

	while(usr->flag == 0) { sleep(1); }
	while(MessgHeaderPtr->headPtr == NULL) { sleep(1); }
	tracker = MessgHeaderPtr->headPtr;
    while (1) {
		if(MessgHeaderPtr->count > compare) {
			if(tracker->isToCS_1==1){
				if(usr->isMemberOfCS_1==1){
					send(socket, tracker->msg, strlen(tracker->msg), 0);
					compare = compare + 1;
					if(tracker->nxtMessage != NULL) {
					tracker = tracker->nxtMessage;
					}

					else {
						while(tracker->nxtMessage == NULL) { sleep(1); }
						tracker = tracker->nxtMessage;
					}
		        }	
		    } else if(tracker->isToCS_2==1){
				if(usr->isMemberOfCS_2==1){
					send(socket, tracker->msg, strlen(tracker->msg), 0);
					compare = compare + 1;
					if(tracker->nxtMessage != NULL) {
					tracker = tracker->nxtMessage;
					}

					else {
						while(tracker->nxtMessage == NULL) { sleep(1); }
						tracker = tracker->nxtMessage;
					}
		        }	
		    } else if(/*tracker->isToOS==1*/1==1){
				if(/*usr->isMemberOfOS==1*/1==1){
					send(socket, tracker->msg, strlen(tracker->msg), 0);
					compare = compare + 1;
					if(tracker->nxtMessage != NULL) {
					tracker = tracker->nxtMessage;
					}

			            else {
						while(tracker->nxtMessage == NULL) { sleep(1); }
						tracker = tracker->nxtMessage;
					}
		        }	
		    }
        }			
		else {
			sleep(1);
		}
    }
    close(socket);
    return NULL;
}

/* This function is responsible for receiving information from the client.
*/
void *serverReceive(void *ptr) {
    int read_count = -1;
	clientInfo *client = (clientInfo *) ptr;
	messageHeader *MessgHeaderPtr = client->clientMessageHeader;
	User *usr = (User *) malloc(sizeof(User));
	usr = client->USER;
	userHeader *usrHdrPtr = client->userHeaderPtr;
	int socket = usr->socketID;
	int NAMESIZE = 30;
	char name[NAMESIZE];
	int MESSAGESIZE = 128;
	char message[MESSAGESIZE];
	char *messg;
	int keepGoing = 1;
	char type1[4] = "/=1";
	char type2[4] = "/=2";
	char type3[4] = "/=3";
	char SPACE[2] = " ";
	char cs1[5] = "cs_1 ";
	char cs2[5] = "cs_2 ";
	char os[3] = "os ";
	char isJoinRequest[6] = "/join ";
	char joincs1[12] = "/join cs_1\n";
	char joincs2[12] = "/join cs_2\n";
	char joinos[10] = "/join os\n";

	Group *CS1 = (Group *) malloc(sizeof(Group));
	Group *CS2 = (Group *) malloc(sizeof(Group));
	Group *OS = (Group *) malloc(sizeof(Group));
	initializeUserGroup(CS1);
	cs1MessageList=CS1->messageList;
	initializeUserGroup(CS2);
	cs2MessageList=CS2->messageList;
	initializeUserGroup(OS);
	osMessageList=OS->messageList;
	cs1UserList=CS1->userList;
    cs2UserList=CS2->userList;
    osUserList=OS->userList;

    printf("subserver ID = %ld\n", (unsigned long) pthread_self());
    // receive from the client
    read_count = recv(socket, message, sizeof(message), 0);
	strcpy(usr->username, message);
    if (userExists(usr, usrHdrPtr) == NULL) {
	   usr->flag = 1;
	   usr->username[strlen(usr->username)-1] = '\0';
	   read_count = recv(socket, message, sizeof(message), 0);
	   strcpy(usr->password, message);
	   appendToUserList(usrHdrPtr, usr);
	   printf("User \"%s\" has connected.\n", usr->username);
	}
    else {
	   read_count = recv(socket, message, sizeof(message), 0);
	   strcpy(usr->password, message);
	   usr->password[strlen(usr->password)-1] = '\0';
	   if (userLogIn(usr, userExists(usr, usrHdrPtr)) == 0) {
		   keepGoing = 0;
		   disconnect(socket);
	   }
	   else {
	       usr->flag = 1;
	       printf("User \"%s\" has logged in.\n", usr->username);
	   }
	}
	memset(message,0,strlen(message));
	while(keepGoing) { // Infinitely receiving messages
		read_count = recv(socket, message, sizeof(message), 0);
		Message *mesg = (Message *) malloc(sizeof(Message));
		strcpy(mesg->msg, message);
		if (strcmp(mesg->msg, type3) == 0) {
			keepGoing = 0;
			printf("User \"%s\" has disconnected.\n", usr->username);
			disconnect(socket);
			strcpy(mesg->msg, SPACE);
		}
		else 
		{
			if (strcmp(mesg->msg, joincs1) == 0) {
				appendToUserList(CS1->userList, usr);
				usr->isMemberOfCS_1 = 1;
				printf("User \"%s\" added to cs_1.\n", usr->username);	
			}
			else if (strcmp(mesg->msg, joincs2) == 0) {
				appendToUserList(CS2->userList, usr);
				usr->isMemberOfCS_2 = 1;
				printf("User \"%s\" added to cs_2.\n", usr->username);
			}
			else if (strcmp(mesg->msg, joinos) == 0) {
				appendToUserList(OS->userList, usr);
				usr->isMemberOfOS = 1;
				printf("User \"%s\" added to os.\n", usr->username);
			}
			else if (strncmp(mesg->msg, isJoinRequest, 4) == 0){
				printf("ERROR: Invalid group!");
			}
			else //message is to be sent to the specified group
			{
				if (strncmp(message, cs1,4) == 0) 
				{
					if (CS1->messageList->count == 0) {
						messageHeader *CS1messages = CS1->messageList;
						CS1messages = (messageHeader *) malloc(sizeof(messageHeader));
					}
					mesg->isToCS_1=1;
					appendToMessageList(CS1->messageList, mesg);
					appendToMessageList(MessgHeaderPtr, mesg);
					printf("User \"%s\" sent message to cs_1.\n", usr->username);
					continue;
				}
				else if (strncmp(message, cs2,4) == 0)
				{
					if (CS2->messageList->count == 0) {
						messageHeader *CS2messages = CS2->messageList;
						CS2messages = (messageHeader *) malloc(sizeof(messageHeader));
					}
					mesg->isToCS_2=1;
					appendToMessageList(CS2->messageList, mesg);
					appendToMessageList(MessgHeaderPtr, mesg);
					printf("User \"%s\" sent message to cs_2.\n", usr->username);	
					continue;
				}
				else if (strncmp(message, os,2) == 0) 
				{
					if (OS->messageList->count == 0) {
						messageHeader *OSmessages = OS->messageList;
						OSmessages = (messageHeader *) malloc(sizeof(messageHeader));
					}
					mesg->isToOS=1;
					appendToMessageList(OS->messageList, mesg);
					appendToMessageList(MessgHeaderPtr, mesg);
					printf("User \"%s\" sent message to os.\n", usr->username);
					continue;
				}
				else //if the entered group DNE
				{
					printf("ERROR: Invalid group! Please join one of the existing groups (cs_1, cs_2, os)\n");
				}

			}
		}
		appendToMessageList(MessgHeaderPtr, mesg);
		message[read_count] = '\0'; // to safe-guard the string
		printf("%s : %s\n", usr->username, mesg->msg);
		memset(message,0,strlen(message));
	}
	return NULL;
}

void disconnect(int socket) {
	if(shutdown(socket, SHUT_RDWR) < 0) {
		perror("shutdown");
	}
	if(close(socket) < 0) {
		perror("close");
	}
}

int accept_client(int serv_sock) {
    int reply_sock_fd = -1;
    socklen_t sin_size = sizeof(struct sockaddr_storage);
    struct sockaddr_storage client_addr;
    char client_printable_addr[INET6_ADDRSTRLEN];

    // accept a connection request from a client
    // the returned file descriptor from accept will be used
    // to communicate with this client.
    if ((reply_sock_fd = accept(serv_sock, 
       (struct sockaddr *)&client_addr, &sin_size)) == -1) {
            printf("socket accept error\n");
    }
    else {
        // here is for info only, not really needed.
        inet_ntop(client_addr.ss_family, get_in_addr((struct sockaddr *)&client_addr), 
                          client_printable_addr, sizeof client_printable_addr);
        printf("server: connection from %s at port %d\n", client_printable_addr,
                            ((struct sockaddr_in*)&client_addr)->sin_port);
    }
    return reply_sock_fd;
}

// ======= HELP FUNCTIONS =========== //
/* the following is a function designed for testing.
   it prints the ip address and port returned from
   getaddrinfo() function */
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

void *get_in_addr(struct sockaddr * sa) {
   if (sa->sa_family == AF_INET) {
      printf("ipv4\n");
      return &(((struct sockaddr_in *)sa)->sin_addr);
   }
   else {
      printf("ipv6\n");
      return &(((struct sockaddr_in6 *)sa)->sin6_addr);
   }
}
