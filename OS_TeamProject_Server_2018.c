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
	char fromUser[30];
	struct message *nxtMessage;
} Message;

typedef struct MessageHeader {
	Message *headPtr;
	int count;
} messageHeader;

typedef struct user {
	char username[30];
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

Group *CS1; 
Group *CS2;
Group *OS;

pthread_mutex_t usermutex;
pthread_mutex_t messagemutex;

int leaveGroup(userHeader *headerPtr, User *nodePtr, int groupNumber);
void disconnect(int socket);
int findAndRemoveNewLine(char *name,int length);
int userIsMemberOf(User *suspectedUser, int groupNumber);
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
	
	CS1 = (Group *) malloc(sizeof(Group));
	CS2 = (Group *) malloc(sizeof(Group));
	OS = (Group *) malloc(sizeof(Group));
	
	initializeUserGroup(CS1);
	initializeUserGroup(CS2);
	initializeUserGroup(OS);
	
	cs1MessageList=CS1->messageList;
	cs2MessageList=CS2->messageList;
	osMessageList=OS->messageList;
	cs1UserList=CS1->userList;
    cs2UserList=CS2->userList;
    osUserList=OS->userList;
	
	pthread_mutex_init(&usermutex, NULL);
    pthread_mutex_init(&messagemutex, NULL);	
	
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
	User *temp = (User *) malloc(sizeof(User));
	User *temp2;
	User *temp3;
	temp2 = headerPtr->usrHeaderPtr;
	temp3 = nodePtr;
	
	if (temp2 == NULL) {
		headerPtr->usrHeaderPtr = nodePtr;
		printf("%s is now the first in the group", nodePtr->username);
	}
	else {
		strcpy(temp->username, temp3->username);
		temp->socketID = temp3->socketID;
		temp->flag = temp3->flag;
		temp->nextUser = temp3->nextUser;
		strcpy(temp->password, temp3->password);
		
		while(temp->nextUser != NULL) {
			temp = temp->nextUser;
		}
		temp->nextUser = nodePtr;
		nodePtr->nextUser = NULL;
		temp2->nextUser=temp;
		printf("User \"%s\" added to group.\n", nodePtr->username);
	}
	headerPtr->usrCount = headerPtr->usrCount + 1;
}

int leaveGroup(userHeader *headerPtr, User *nodePtr, int groupNumber) {
	User *temp2;
	User *temp3;
	User *temp4;
	User *temp5;
	temp2 = headerPtr->usrHeaderPtr;
	temp3 = nodePtr;
	temp4 = temp2->nextUser;
	temp5 = temp4;
	
	printf("temp3 = %s\n",temp3->username);
	printf("temp2 = %s\n",temp2->username);
	
	if (temp2 == NULL) {
		printf("Ground number %d is empty", groupNumber);
		return 0;
	}
	else if(temp4 == NULL){
		if(strcmp(temp2->username, temp3->username)==0){
			temp2= NULL;
			headerPtr->usrCount = headerPtr->usrCount - 1;
			return 1;
		}
		else{
			printf("user not in list");
			return 0;
		}
	}
	else {
		
		printf("temp3 = %s\n",temp3->username);
		
		while((strcmp(temp4->username, temp3->username)!= 0)&&(temp4->nextUser != NULL)) {
			temp5 = temp4;
			temp4 = temp4->nextUser;
		}
		temp5->nextUser = temp4->nextUser;
		temp4->nextUser = NULL;
		printf("User \"%s\" removed from group.\n", nodePtr->username);
		
		headerPtr->usrCount = headerPtr->usrCount - 1;
		return 1;
	}
	return 0;
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
int findAndRemoveNewLine(char *name,int length){
		name[length-1]='\0';
		length--;
		printf("\nname had a new line");
		return length;
}
int checkName(User *comp1, User *comp2) {
	int result = 0;
	char name1[60];
	char name2[60];
	strcpy(name1, comp1->username);
	strcpy(name2, comp2->username);
	int len1=strlen(name1);
	int len2=strlen(name2);
	
	if (name1[len1-1]=='\n'){
		len1 = findAndRemoveNewLine(name1, len1);
	}
	if (name2[len2-1]=='\n'){
		len2 = findAndRemoveNewLine(name2, len2);
	}
	
	if (len2!=len1){ 
		return 0;
	}else if(strcmp(name1,name2)==0){
		return 1;
	}else{
		return 0;
	}
}

int checkPassword(User *code1, User *code2) {
	int match = 0;
	int wrong = 0;
	char pass1[30];
	char pass2[30];
	strcpy(pass1, code1->password);
	strcpy(pass2, code2->password);
	int j;
    for (j=0; pass1[j] != (int) NULL; j++) {
		if (pass1[j] == pass2[j]) {
			continue;
		}else{
			printf("Password does not match.\n");
			wrong = 1;
			break;
		}
	}
	if (wrong == 0){
		match=1;
	}
	return match;
}

int userLogIn(User *usr, User *comp) {
   int correct;
   if (checkPassword(usr, comp) == 0) {
      printf("Incorrect password. Disconnecting...\n");//is disconnecting on server side but not client side, hence the client crashes rather than ask again
	  correct = 0;
   }
   else {
      printf("Correct password. Continuing...\n");
	  correct = 1;
   }
   return correct;
}

int userIsMemberOf(User *suspectedUser, int groupNumber){
	int keepGoing=1;
	int result = 0;
	int check =0;
	
	userHeader *Cs1UserList = cs1UserList;
    userHeader *Cs2UserList = cs2UserList;
    userHeader *OsUserList = osUserList;
    
	User *listedCs1User = Cs1UserList->usrHeaderPtr;
    User *listedCs2User = Cs2UserList->usrHeaderPtr;
	User *listedOsUser = OsUserList->usrHeaderPtr;
	
	if (groupNumber == 1) { //check if in cs1
		while(keepGoing == 1){
			if(listedCs1User!=(User *)NULL){
				check = checkName(suspectedUser, listedCs1User);
			}else{
				return 0;
			}
			if(check > 0){
				return 1;  
			}
			if(listedCs1User->nextUser != (User *)NULL) {
				listedCs1User = listedCs1User->nextUser;
			}else{
				keepGoing=0;
			}
		}
	}else if (groupNumber == 2) { //check if in cs2
	    while(keepGoing == 1){
			if(listedCs2User!=(User *)NULL){
				check = checkName(suspectedUser, listedCs2User);
			}else{
				return 0;
			}
			if(check > 0){
				return 1;  
			}
			if(listedCs2User->nextUser != (User *)NULL) {
				listedCs2User = listedCs2User->nextUser;
			}else{
				keepGoing=0;
			}
		}
	}else if (groupNumber == 3) { //check if in os
		while(keepGoing == 1){
			if(listedOsUser!=(User *)NULL){
				check = checkName(suspectedUser, listedOsUser);
			}else{
				return 0;
			}
			if(check > 0){
				return 1;  
			}
			if(listedOsUser->nextUser != (User *)NULL) {
				listedOsUser = listedOsUser->nextUser;
			}else{
				keepGoing=0;
			}
		}		
	}
	return result;
}


/* This function is responsible for sending information from the server to the client.
*/
void *serverSend(void *ptr) {
	clientInfo *client = (clientInfo *) ptr;
	messageHeader *Cs1MessgHeaderPtr;
	messageHeader *Cs2MessgHeaderPtr;
	messageHeader *OsMessgHeaderPtr;
	User *usr = client->USER;
	Message *cs1Tracker;
	Message *cs2Tracker;
	Message *osTracker;
	Message *tracker;
	char *name = usr->username;
	char theMessage[128];
	int socket = client->USER->socketID;
	int checkCs1 = 0;
	int checkCs2 = 0;
	int checkOs = 0;
	
	int compare = 0;
	int compareCs1 = 0;
	int compareCs2 = 0;
	int compareOs = 0;
	
	int firstCs1Message=1;
	int firstCs2Message=1;
	int firstOsMessage=1;
	
	int compareCs1A = 0;
	int compareCs2A = 0;
	int compareOsA = 0;
	
	int cs1Check = 1;
	int cs2Check = 2;
	int osCheck = 3;
	
	Cs1MessgHeaderPtr = cs1MessageList;
	Cs2MessgHeaderPtr = cs2MessageList;
	OsMessgHeaderPtr = osMessageList;
	
	send(socket, name, sizeof(name), 0);
    
	while(usr->flag == 0) { sleep(1); }
	
    while (1) {		
		if((char *)cs1Tracker == NULL){
			cs1Tracker = Cs1MessgHeaderPtr->headPtr;
		}
		if((char *)cs2Tracker == NULL){
			cs2Tracker = Cs2MessgHeaderPtr->headPtr;
		}
		if((char *)osTracker == NULL){
			osTracker = OsMessgHeaderPtr->headPtr;
		}
		
		checkCs1 = 0;
		checkCs2 = 0;
		checkOs = 0;
		checkCs1 = userIsMemberOf(usr, cs1Check);
		checkCs2 = userIsMemberOf(usr, cs2Check);
		checkOs = userIsMemberOf(usr, osCheck);
		
		printf("\n%s checkCs1 = %d\n",name,checkCs1);
		printf("\n%s checkCs2 = %d\n",name,checkCs2);
		printf("\n%s checkOs = %d\n",name,checkOs);
		
		compareCs1A=Cs1MessgHeaderPtr->count;
		compareCs2A=Cs2MessgHeaderPtr->count;
		compareOsA=OsMessgHeaderPtr->count;
		
		pthread_mutex_lock(&messagemutex);
		if((compareCs1A > compareCs1)&&(checkCs1 > 0)) {
			int newOne=0;
			while(compareCs1A > compareCs1){
				if(((char *)cs1Tracker->msg!=NULL)&&(strcmp(cs1Tracker->fromUser,usr->username))!=0){
					printf("send conditions satisfied\n");
					strcpy(theMessage,cs1Tracker->fromUser);
					printf("username copied: %s\n",cs1Tracker->fromUser);
					strcat(theMessage,": ");
					printf(": cated to message\n");
					strcat(theMessage, (char *)cs1Tracker->msg);
					printf("message completed. new messgage reads:\n %s",theMessage);
				}
				if((newOne == 1)||(firstCs1Message == 1)){
					firstCs1Message = 0;
					send(socket, theMessage, strlen(theMessage), 0);
				}
				compareCs1 = compareCs1 + 1;
				if((char *)cs1Tracker->nxtMessage != NULL) {
					cs1Tracker = cs1Tracker->nxtMessage;
					compareCs1 = compareCs1A - 1;
					newOne=1;
				}
				else {
					//do nothing
				}
			}
        }
		if((compareCs2A > compareCs2)&&(checkCs2 > 0)) {
			int newOne=0;
			while(compareCs2A > compareCs2){
				if(((char *)cs2Tracker->msg!=NULL)&&(strcmp(cs2Tracker->fromUser,usr->username)!=0)){
					strcpy(theMessage,cs2Tracker->fromUser);
					strcat(theMessage,": ");
					strcat(theMessage, (char *)cs2Tracker->msg);
				}
				if((newOne == 1)||(firstCs2Message == 1)){
					firstCs2Message = 0;
					send(socket, theMessage, strlen(theMessage), 0);
				}
				compareCs2 = compareCs2 + 1;
				if((char *)cs2Tracker->nxtMessage != NULL) {
					cs2Tracker = cs2Tracker->nxtMessage;
					compareCs2 = compareCs2A - 1;
					newOne=1;
				}
				else {
					compareCs2 = compareCs2A;
				}
			}
        }	
		if((compareOsA > compareOs)&&(checkOs > 0)) {
			int newOne=0;
			while(compareOsA > compareOs){
				if(((char *)osTracker->msg!=NULL)&&(strcmp(osTracker->fromUser,usr->username)!=0)){
					strcpy(theMessage,osTracker->fromUser);
					strcat(theMessage,": ");
					strcat(theMessage, (char *)osTracker->msg);
				}
				if((newOne == 1)||(firstOsMessage == 1)){
					firstOsMessage = 0;
					send(socket, theMessage, strlen(theMessage), 0);
				}
				compareOs = compareOs + 1;
				if((char *)osTracker->nxtMessage != NULL) {
					osTracker = osTracker->nxtMessage;
					compareOs = compareOsA - 1;
					newOne=1;
				}
				else {
					compareOs = compareOsA;
				}
			}
        }
		pthread_mutex_unlock(&messagemutex);
		sleep(1);
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
	int MESSAGESIZE = 128;
	char message[MESSAGESIZE];
	int keepGoing = 1;
	char type1[4] = "/=1";
	char type2[4] = "/=2";
	char type3[4] = "/=3";
	char SPACE[2] = " ";
	char cs1[5] = "cs_1 ";
	char cs2[5] = "cs_2 ";
	char os[3] = "os ";
	int cs1number = 1;
	int cs2number = 2;
	int osnumber = 3;
	char isJoinRequest[6] = "/join ";
	char joincs1[12] = "/join cs_1\n";
	char joincs2[12] = "/join cs_2\n";
	char joinos[10] = "/join os\n";
	char leavecs1[13] = "/leave cs_1\n";
	char leavecs2[13] = "/leave cs_2\n";
	char leaveos[11] = "/leave os\n";
	char cs1icecream[18] = "cs_1 /santa\n";
	char cs2icecream[18] = "cs_2 /santa\n";
	char osicecream[14] = "os /santa\n";
	char cs1tree[14] = "cs_1 /tree\n";
	char cs2tree[14] = "cs_2 /tree\n";
	char ostree[12] = "os /tree\n";
	char cs1snowman[17] = "cs_1 /snowman\n";
	char cs2snowman[17] = "cs_2 /snowman\n";
	char ossnowman[15] = "os /snowman\n";
	char cs1workingMan[20] = "cs_1 /working-man\n";
	char cs2workingMan[20] = "cs_2 /working-man\n";
	char osworkingMan[18] = "os /working-man\n";
	
	char iceCreamA[60] = " .___. \n    /,..__\\ \n   () {____} \n     (/-@-@-\\) \n";
	char iceCreamB[60] = "{'-=^=-'} \n     {  '_'  } \n      {     } \n       '___' \n";
    char treeA[60] = "    _\\/_ \n         /\\ \n        /  \\ \n       /    \\ \n";
    char treeB[60] = "/~~~~\\o \n      /o     \\ \n";
    char treeC[60] = "/~~~~*~~~\\ \n    o/    o   \\ \n    /~~~~~~~~~~\\ \n";
	char treeD[60] = "/_*__________\\ \n         || \n      \\====/ \n        \\__/ \n";
    char snowmanA[60] = "      *  .     * \n   *     . ___  * \n    .    _|___|_  . \n";
    char snowmanB[100] = "*   ('_')  v  * \n      >--(  .  )/ . \n       *(   .   )   * \n    .   '=======' * \n";
    char workingManA[60] = "    0 \n       /\\ \n   ,__/\\ '\\ \n        \\,  \\_  = \n";


	Group *cS1 = (Group *) malloc(sizeof(Group));
	Group *cS2 = (Group *) malloc(sizeof(Group));
	Group *oS = (Group *) malloc(sizeof(Group));
	
	cS1 = CS1;
	cS2 = CS2;
	oS = OS;
	
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
		
		printf("\n OSNumUsers = %d\n",oS->userList->usrCount);
		
		strcpy(mesg->fromUser,usr->username);
		if (strcmp(mesg->msg, type3) == 0) {
			keepGoing = 0;
			printf("User \"%s\" has disconnected.\n", usr->username);
			disconnect(socket);
			strcpy(mesg->msg, SPACE);
		}
		else 
		{		
			if (strcmp(mesg->msg, joincs1) == 0) {
				pthread_mutex_lock(&usermutex);
				appendToUserList(cS1->userList, usr);
				printf("User \"%s\" added to cs_1.\n", usr->username);
				pthread_mutex_unlock(&usermutex);
			}
			else if (strcmp(mesg->msg, joincs2) == 0) {
				pthread_mutex_lock(&usermutex);
				appendToUserList(cS2->userList, usr);
				printf("User \"%s\" added to cs_2.\n", usr->username);
				pthread_mutex_unlock(&usermutex);
			}
			else if (strcmp(mesg->msg, joinos) == 0) {
				pthread_mutex_lock(&usermutex);
				appendToUserList(oS->userList, usr);
				printf("User \"%s\" added to os.\n", usr->username);
				pthread_mutex_unlock(&usermutex);
			}
			else if (strncmp(mesg->msg, isJoinRequest, 4) == 0){
				printf("ERROR: Invalid group!");
			}
			if (strcmp(mesg->msg, leavecs1) == 0) {
				pthread_mutex_lock(&usermutex);
				leaveGroup(oS->userList, usr, cs1number);
				printf("User \"%s\" removed from cs_1.\n", usr->username);
				pthread_mutex_unlock(&usermutex);
			}
			else if (strcmp(mesg->msg, leavecs2) == 0) {
				pthread_mutex_lock(&usermutex);
				leaveGroup(oS->userList, usr, cs2number);
				printf("User \"%s\" removed from cs_2.\n", usr->username);
				pthread_mutex_unlock(&usermutex);
			}
			else if (strcmp(mesg->msg, leaveos) == 0) {
				pthread_mutex_lock(&usermutex);
				leaveGroup(oS->userList, usr, osnumber);
				printf("User \"%s\" removed from os.\n", usr->username);
				pthread_mutex_unlock(&usermutex);
			}
			else //message is to be sent to the specified group
			{
				if (strcmp(message, cs1icecream) == 0){
					Message *mesgA = (Message *) malloc(sizeof(Message));
					Message *mesgB = (Message *) malloc(sizeof(Message));
				    
					strcpy(mesgA->fromUser,usr->username);
					strcpy(mesgB->fromUser,usr->username);
					
					pthread_mutex_lock(&messagemutex);
					
					strcpy(mesgA->msg, iceCreamA);
					strcpy(mesgB->msg, iceCreamB);
					
					if (cS1->messageList->count == 0) {
						messageHeader *CS1messages = cS1->messageList;
						CS1messages = (messageHeader *) malloc(sizeof(messageHeader));
					}
					appendToMessageList(cS1->messageList, mesgA);
					appendToMessageList(cS1->messageList, mesgB);
					appendToMessageList(MessgHeaderPtr, mesgA);
					appendToMessageList(MessgHeaderPtr, mesgB);
					printf("User \"%s\" sent emoji to cs_1.\n", usr->username);
					pthread_mutex_unlock(&messagemutex);
				}
				else if (strcmp(message, cs1snowman) == 0){
					Message *mesgA = (Message *) malloc(sizeof(Message));
					Message *mesgB = (Message *) malloc(sizeof(Message));
				
					strcpy(mesgA->fromUser,usr->username);
					strcpy(mesgB->fromUser,usr->username);
					
					pthread_mutex_lock(&messagemutex);
					
					strcpy(mesgA->msg, snowmanA);
					strcpy(mesgB->msg, snowmanB);
					
					if (cS1->messageList->count == 0) {
						messageHeader *CS1messages = cS1->messageList;
						CS1messages = (messageHeader *) malloc(sizeof(messageHeader));
					}
					appendToMessageList(cS1->messageList, mesgA);
					appendToMessageList(cS1->messageList, mesgB);
					appendToMessageList(MessgHeaderPtr, mesgA);
					appendToMessageList(MessgHeaderPtr, mesgB);
					printf("User \"%s\" sent emoji to cs_1.\n", usr->username);
					pthread_mutex_unlock(&messagemutex);
				}
				else if (strcmp(message, cs1tree) == 0){
					Message *mesgA = (Message *) malloc(sizeof(Message));
					Message *mesgB = (Message *) malloc(sizeof(Message));
					Message *mesgC = (Message *) malloc(sizeof(Message));
					Message *mesgD = (Message *) malloc(sizeof(Message));
				
					strcpy(mesgA->fromUser,usr->username);
					strcpy(mesgB->fromUser,usr->username);
					strcpy(mesgC->fromUser,usr->username);
					strcpy(mesgD->fromUser,usr->username);
					
					pthread_mutex_lock(&messagemutex);
					
					strcpy(mesgA->msg, treeA);
					strcpy(mesgB->msg, treeB);
					strcpy(mesgC->msg, treeC);
					strcpy(mesgD->msg, treeD);
					
					if (cS1->messageList->count == 0) {
						messageHeader *CS1messages = cS1->messageList;
						CS1messages = (messageHeader *) malloc(sizeof(messageHeader));
					}
					appendToMessageList(cS1->messageList, mesgA);
					appendToMessageList(cS1->messageList, mesgB);
					appendToMessageList(cS1->messageList, mesgC);
					appendToMessageList(cS1->messageList, mesgD);
					appendToMessageList(MessgHeaderPtr, mesgA);
					appendToMessageList(MessgHeaderPtr, mesgB);
					appendToMessageList(MessgHeaderPtr, mesgC);
					appendToMessageList(MessgHeaderPtr, mesgD);
					printf("User \"%s\" sent emoji to cs_1.\n", usr->username);
					pthread_mutex_unlock(&messagemutex);
				}
				else if (strcmp(message, cs1workingMan) == 0){
					Message *mesgA = (Message *) malloc(sizeof(Message));
				
					strcpy(mesgA->fromUser,usr->username);
					
					pthread_mutex_lock(&messagemutex);
					
					strcpy(mesgA->msg, workingManA);
					
					if (cS1->messageList->count == 0) {
						messageHeader *CS1messages = cS1->messageList;
						CS1messages = (messageHeader *) malloc(sizeof(messageHeader));
					}
					appendToMessageList(cS1->messageList, mesgA);
					appendToMessageList(MessgHeaderPtr, mesgA);
					printf("User \"%s\" sent emoji to cs_1.\n", usr->username);
					pthread_mutex_unlock(&messagemutex);
				}
				else if (strcmp(message, cs2icecream) == 0){
					Message *mesgA = (Message *) malloc(sizeof(Message));
					Message *mesgB = (Message *) malloc(sizeof(Message));
				
					strcpy(mesgA->fromUser,usr->username);
					strcpy(mesgB->fromUser,usr->username);
					
					pthread_mutex_lock(&messagemutex);
					
					strcpy(mesgA->msg, iceCreamA);
					strcpy(mesgB->msg, iceCreamB);
					
					if (cS2->messageList->count == 0) {
						messageHeader *CS2messages = cS2->messageList;
						CS2messages = (messageHeader *) malloc(sizeof(messageHeader));
					}
					appendToMessageList(cS2->messageList, mesgA);
					appendToMessageList(cS2->messageList, mesgB);
					appendToMessageList(MessgHeaderPtr, mesgA);
					appendToMessageList(MessgHeaderPtr, mesgB);
					printf("User \"%s\" sent emoji to cs_2.\n", usr->username);
					pthread_mutex_unlock(&messagemutex);
				}
				else if (strcmp(message, cs2snowman) == 0){
					Message *mesgA = (Message *) malloc(sizeof(Message));
					Message *mesgB = (Message *) malloc(sizeof(Message));
				
					strcpy(mesgA->fromUser,usr->username);
					strcpy(mesgB->fromUser,usr->username);
					
					pthread_mutex_lock(&messagemutex);
					
					strcpy(mesgA->msg, snowmanA);
					strcpy(mesgB->msg, snowmanB);
					
					if (cS2->messageList->count == 0) {
						messageHeader *CS2messages = cS2->messageList;
						CS2messages = (messageHeader *) malloc(sizeof(messageHeader));
					}
					appendToMessageList(cS2->messageList, mesgA);
					appendToMessageList(cS2->messageList, mesgB);
					appendToMessageList(MessgHeaderPtr, mesgA);
					appendToMessageList(MessgHeaderPtr, mesgB);
					printf("User \"%s\" sent emoji to cs_2.\n", usr->username);
					pthread_mutex_unlock(&messagemutex);
				}
				else if (strcmp(message, cs2tree) == 0){
					Message *mesgA = (Message *) malloc(sizeof(Message));
					Message *mesgB = (Message *) malloc(sizeof(Message));
					Message *mesgC = (Message *) malloc(sizeof(Message));
					Message *mesgD = (Message *) malloc(sizeof(Message));
				
					strcpy(mesgA->fromUser,usr->username);
					strcpy(mesgB->fromUser,usr->username);
					strcpy(mesgC->fromUser,usr->username);
					strcpy(mesgD->fromUser,usr->username);
					
					pthread_mutex_lock(&messagemutex);
					
					strcpy(mesgA->msg, treeA);
					strcpy(mesgB->msg, treeB);
					strcpy(mesgC->msg, treeC);
					strcpy(mesgD->msg, treeD);
					
					if (cS2->messageList->count == 0) {
						messageHeader *CS2messages = cS2->messageList;
						CS2messages = (messageHeader *) malloc(sizeof(messageHeader));
					}
					appendToMessageList(cS2->messageList, mesgA);
					appendToMessageList(cS2->messageList, mesgB);
					appendToMessageList(cS2->messageList, mesgC);
					appendToMessageList(cS2->messageList, mesgD);
					appendToMessageList(MessgHeaderPtr, mesgA);
					appendToMessageList(MessgHeaderPtr, mesgB);
					appendToMessageList(MessgHeaderPtr, mesgC);
					appendToMessageList(MessgHeaderPtr, mesgD);
					printf("User \"%s\" sent emoji to cs_2.\n", usr->username);
					pthread_mutex_unlock(&messagemutex);
				}
				else if (strcmp(message, cs2workingMan) == 0){
					Message *mesgA = (Message *) malloc(sizeof(Message));
				
					strcpy(mesgA->fromUser,usr->username);
					
					pthread_mutex_lock(&messagemutex);
					
					strcpy(mesgA->msg, workingManA);
					
					if (cS2->messageList->count == 0) {
						messageHeader *CS2messages = cS2->messageList;
						CS2messages = (messageHeader *) malloc(sizeof(messageHeader));
					}
					appendToMessageList(cS2->messageList, mesgA);
					appendToMessageList(MessgHeaderPtr, mesgA);
					printf("User \"%s\" sent emoji to cs_2.\n", usr->username);
					pthread_mutex_unlock(&messagemutex);
				}
				else if (strcmp(message, osicecream) == 0){
					Message *mesgA = (Message *) malloc(sizeof(Message));
					Message *mesgB = (Message *) malloc(sizeof(Message));
				
					strcpy(mesgA->fromUser,usr->username);
					strcpy(mesgB->fromUser,usr->username);
					
					pthread_mutex_lock(&messagemutex);
					
					strcpy(mesgA->msg, iceCreamA);
					strcpy(mesgB->msg, iceCreamB);
					
					if (oS->messageList->count == 0) {
						messageHeader *OSmessages = oS->messageList;
						OSmessages = (messageHeader *) malloc(sizeof(messageHeader));
					}
					appendToMessageList(oS->messageList, mesgA);
					appendToMessageList(oS->messageList, mesgB);
					appendToMessageList(MessgHeaderPtr, mesgA);
					appendToMessageList(MessgHeaderPtr, mesgB);
					printf("User \"%s\" sent emoji to os.\n", usr->username);
					pthread_mutex_unlock(&messagemutex);
				}
				else if (strcmp(message, ossnowman) == 0){
					Message *mesgA = (Message *) malloc(sizeof(Message));
					Message *mesgB = (Message *) malloc(sizeof(Message));
				
					strcpy(mesgA->fromUser,usr->username);
					strcpy(mesgB->fromUser,usr->username);
					
					pthread_mutex_lock(&messagemutex);
					
					strcpy(mesgA->msg, snowmanA);
					strcpy(mesgB->msg, snowmanB);
					
					if (oS->messageList->count == 0) {
						messageHeader *OSmessages = oS->messageList;
						OSmessages = (messageHeader *) malloc(sizeof(messageHeader));
					}
					appendToMessageList(oS->messageList, mesgA);
					appendToMessageList(oS->messageList, mesgB);
					appendToMessageList(MessgHeaderPtr, mesgA);
					appendToMessageList(MessgHeaderPtr, mesgB);
					printf("User \"%s\" sent emoji to os.\n", usr->username);
					pthread_mutex_unlock(&messagemutex);
				}
				else if (strcmp(message, ostree) == 0){
					Message *mesgA = (Message *) malloc(sizeof(Message));
					Message *mesgB = (Message *) malloc(sizeof(Message));
					Message *mesgC = (Message *) malloc(sizeof(Message));
					Message *mesgD = (Message *) malloc(sizeof(Message));
				
					strcpy(mesgA->fromUser,usr->username);
					strcpy(mesgB->fromUser,usr->username);
					strcpy(mesgC->fromUser,usr->username);
					strcpy(mesgD->fromUser,usr->username);
					
					pthread_mutex_lock(&messagemutex);
					
					strcpy(mesgA->msg, treeA);
					strcpy(mesgB->msg, treeB);
					strcpy(mesgC->msg, treeC);
					strcpy(mesgD->msg, treeD);
					
					if (oS->messageList->count == 0) {
						messageHeader *OSmessages = oS->messageList;
						OSmessages = (messageHeader *) malloc(sizeof(messageHeader));
					}
					appendToMessageList(oS->messageList, mesgA);
					appendToMessageList(oS->messageList, mesgB);
					appendToMessageList(oS->messageList, mesgC);
					appendToMessageList(oS->messageList, mesgD);
					appendToMessageList(MessgHeaderPtr, mesgA);
					appendToMessageList(MessgHeaderPtr, mesgB);
					appendToMessageList(MessgHeaderPtr, mesgC);
					appendToMessageList(MessgHeaderPtr, mesgD);
					printf("User \"%s\" sent emoji to os.\n", usr->username);
					pthread_mutex_unlock(&messagemutex);
				}
				else if (strcmp(message, osworkingMan) == 0){
					Message *mesgA = (Message *) malloc(sizeof(Message));
				
					strcpy(mesgA->fromUser,usr->username);
					
					pthread_mutex_lock(&messagemutex);
					
					strcpy(mesgA->msg, workingManA);
					
					if (oS->messageList->count == 0) {
						messageHeader *OSmessages = oS->messageList;
						OSmessages = (messageHeader *) malloc(sizeof(messageHeader));
					}
					appendToMessageList(oS->messageList, mesgA);
					appendToMessageList(MessgHeaderPtr, mesgA);
					printf("User \"%s\" sent emoji to os.\n", usr->username);
					pthread_mutex_unlock(&messagemutex);
				}
				if (strncmp(message, cs1,4) == 0) 
				{				
					pthread_mutex_lock(&messagemutex);
					if (cS1->messageList->count == 0) {
						messageHeader *CS1messages = cS1->messageList;
						CS1messages = (messageHeader *) malloc(sizeof(messageHeader));
					}
					appendToMessageList(cS1->messageList, mesg);
					appendToMessageList(MessgHeaderPtr, mesg);
					printf("User \"%s\" sent message to cs_1.\n", usr->username);
					pthread_mutex_unlock(&messagemutex);
				}
				else if (strncmp(message, cs2,4) == 0)
				{
					pthread_mutex_lock(&messagemutex);
					if (cS2->messageList->count == 0) {
						messageHeader *CS2messages = cS2->messageList;
						CS2messages = (messageHeader *) malloc(sizeof(messageHeader));
					}
					appendToMessageList(cS2->messageList, mesg);
					appendToMessageList(MessgHeaderPtr, mesg);
					printf("User \"%s\" sent message to cs_2.\n", usr->username);
					pthread_mutex_unlock(&messagemutex);
				}
				else if (strncmp(message, os,2) == 0) 
				{
					pthread_mutex_lock(&messagemutex);
					if (oS->messageList->count == 0) {
						messageHeader *OSmessages = oS->messageList;
						OSmessages = (messageHeader *) malloc(sizeof(messageHeader));
					}
					appendToMessageList(oS->messageList, mesg);
					appendToMessageList(MessgHeaderPtr, mesg);
					printf("User \"%s\" sent message to os.\n", usr->username);
					pthread_mutex_unlock(&messagemutex);
				}
				else //if the entered group DNE
				{
					printf("ERROR: Invalid group! Please join one of the existing groups (cs_1, cs_2, os)\n");
				}

			}
			
		}
		message[read_count] = '\0'; // to safe-guard the string
		printf("%s : %s\n", usr->username, mesg->msg);
		memset(message,0,strlen(message));
		sleep(1);
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
