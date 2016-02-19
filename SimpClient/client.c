/*------------------------------
* client.c
* Description: HTTP client program
* CSC 361
* Instructor: Kui Wu
-------------------------------*/

/* define maximal string and reply length, this is just an example.*/
/* MAX_RES_LEN should be defined larger (e.g. 4096) in real testing. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define MAX_STR_LEN 120
#define MAX_RES_LEN 120

/* --------- Main() routine ------------
 * three main task will be excuted:
 * accept the input URI and parse it into fragments for further operation
 * open socket connection with specified sockid ID
 * use the socket id to connect sopecified server
 * don't forget to handle errors
 */

main(int argc, char *argv[])
{
    if(argc != 2){
    	printf("Usage incorrect.\nProper usage: ./SimpClient <uri>\n");
    	exit(0);
    }
    char uri[MAX_STR_LEN];
    char hostname[MAX_STR_LEN];
    char identifier[MAX_STR_LEN];
    int *is_ip; //used to determine whether IP or Hostname.
    *is_ip = 0;
    int sockid, port;
    port = 80; //Port Default
    strcpy(uri,argv[1]); //Copying input uri to uri

    parse_URI(uri, hostname, &port, identifier);
    sockid = open_connection(hostname, port, is_ip);
   	perform_http(sockid, identifier,hostname, is_ip);
}

/*------ Parse an "uri" into "hostname" and resource "identifier" --------*/

parse_URI(char *uri, char *hostname, int *port, char *identifier)
{
	printf("--- Request Begins ---\n");
  	printf("GET %s HTTP/1.0\n", uri);
	char *saveptr;
	char *str;
	char *port_str;
	char *args[265];
	char *temp;

	temp = (char *) malloc(100);
	int i = 0;
	str = strtok_r(uri,"/", &saveptr);

  //tokenizing input.
	while(str!=NULL){
		args[i] = str;
		i = i+1;
		str = strtok_r(NULL,"/",&saveptr);
	}
	strcat(args[1], "\0");
	strcpy(temp,args[1]);

  //Checks for ":" to tell if there is port
	port_str = strtok_r(temp,":",&saveptr);
	if(port_str && strcmp(port_str,args[1])!=0){
		strcpy(args[1],temp);
		*port = atoi(saveptr); //Changes port from 80 to given port.
	}

  //Copying strings to hostname+identifier

  if(!args[1]){ // Check for hostname
    printf("ERROR: No hostname found\n");
    exit(0);
  }
	strcpy(hostname,args[1]);
	printf("Host: %s\n", hostname);
	hostname = strcat(hostname, "\0");

  if(!args[2]){ // Check for identifier
    printf("ERROR: No identifier found\n");
    exit(0);
  }
	strcpy(identifier,args[2]);
	free(temp);
}

/*------------------------------------*
* connect to a HTTP server using hostname and port,
* and get the resource specified by identifier
*--------------------------------------*/
perform_http(int sockfd, char *identifier, char *hostname, int *is_ip)
{
	 char message[100], server_reply[4096];
	
  //Puts correct request into message string
	 sprintf(message,"GET http://%s/%s HTTP/1.0", hostname, identifier);

	 printf("--- Request End ---\n");
	 printf("HTTP request sent, awaiting response...\n\n");
	 bzero(server_reply, 4096);
    if( send(sockfd , message , strlen(message) , 0) < 0)
    {
        printf("Failed to send request to server\n");
        return;
    }
     if(read(sockfd, server_reply , 4096) < 0)
    {
        printf("Failed to recieve info. from server\n");
        return;
    }
    char *stringthing;
    char *is_HTTP;
    char *saveptr = server_reply;
    printf("--- Response header ---\n");

    //Checks for HTTP/1.0 status
    is_HTTP = strstr(server_reply,"HTTP/1.0");
    if(!is_HTTP){
      printf("ERROR: HTTP Request is of the wrong type\n");
      exit(0);
    }
   
    //Checks for a header, if finds splits into header and body + outputs seperately
    stringthing = strstr(server_reply,"\r\n\r\n");
    if(stringthing){
   	 	char dest[4096];
    	strncpy(dest, saveptr, stringthing-server_reply);

   		printf("%s\n\n",dest);

   	 	printf("--- Response Body ---\n");
    	printf("%s\n", stringthing+4);
   		close(sockfd);
   	}
   	else{
   		printf("No header was received\n\n");
   		printf("--- Response Body ---\n");
   		printf("%s\n",server_reply);
	}
}

/*---------------------------------------------------------------------------*
 *
 * open_conn() routine. It connects to a remote server on a specified port.
 *
 *---------------------------------------------------------------------------*/

int open_connection(char *hostname, int port, int *is_ip)
{

  int sockfd;
  int i; // used for for-loop
  char ip_str[100];
  int ip_no;

  struct sockaddr_in server_addr;
  struct in_addr **addr_list;
  struct hostent *server_ent;
  sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);

  if(sockfd == -1){
  	printf("Socket could not be generated");
  }
  ip_no = inet_addr(hostname);

  // Checks for IP vs. Hostname format
  if(ip_no != -1){
  		*is_ip = 1;

      // Setting server info for IP
  		server_addr.sin_addr.s_addr = ip_no;
    	server_addr.sin_family = AF_INET;
    	server_addr.sin_port = htons( port );
  }
 else{
 	 if((server_ent = gethostbyname(hostname)) == NULL){
  		printf("Hostname not recognized\n");
  	}
  	else{

		addr_list = (struct in_addr **) server_ent->h_addr_list;

		for(i = 0; addr_list[i] != NULL; i++) 
    	{
        	strcpy(ip_str , inet_ntoa(*addr_list[i]) );
    	}
    }


    //Setting server info for hostname
    server_addr.sin_addr.s_addr = inet_addr(ip_str);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons( port );
}
    //Connection Attempt
    if((connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr))<0)){
    	printf("Connection error, disconnecting.\n");
    	exit(0);
    	return;
    }
    else{
    	printf("Connection: Keep-Alive\n\n");
    }

  return sockfd;
}
