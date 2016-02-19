/*------------------------------
* server.c
* Description: HTTP server program
* CSC 361
* Instructor: Kui Wu
-------------------------------*/


#define MAX_STR_LEN 120         /* maximum string length */
#define SERVER_PORT_ID 9898     /* server port number */

/*void cleanExit();

/*---------------------main() routine--------------------------*
 * tasks for main
 * generate socket and get socket id,
 * max number of connection is 3 (maximum length the queue of pending connections may grow to)
 * Accept request from client and generate new socket
 * Communicate with client and close new socket after done
 *---------------------------------------------------------------------------*/

/*Required Headers*/
 
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
 

// <--- BREAKS DOWN SENT REQUEST TO METHOD(HTTP STATUS) + FILE --->
parse_request(char* request, char* method, char* file){
	char *saveptr;
	char *str;
	char *args[265];
	char *temp;

	// TOKENIZATION
	temp = (char *) malloc(100);
	int i = 0;
	str = strtok_r(request," ", &saveptr);

	while(str!=NULL){
		args[i] = str;
		i = i+1;
		str = strtok_r(NULL,"/",&saveptr);
	}

	//REMOVES HTTP/1.0 FROM FILE NAME
	args[3] = strtok_r(args[3], " ", &saveptr);
	if(!args[3]){
		printf("Usage incorrect\n");
		exit(0);
	}
	else{
		strcpy(method,args[0]);
		strcpy(file, args[3]);
	}
}

// <--- OPENS CONNECTION FOR SERVER --->
int open_connection(int argc, char* argv[]){
	int listen_fd, comm_fd;

	struct sockaddr_in servaddr;

	listen_fd = socket(AF_INET, SOCK_STREAM, 0);

    //Fixes issue with connections.
	if(setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0){
		error("Error: socket could not be opened");
	}

 	//Empties out serveraddr
	bzero( &servaddr, sizeof(servaddr));

	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htons(INADDR_ANY);
    //Makes sure port no. is usable.
	if(argc == 3){
		if(!(servaddr.sin_port = htons(atoi(argv[2])))){
			printf("Error: Given port number cannot be used\n");
			exit(0);
		}

	}
	else{
		servaddr.sin_port = htons(80);
	}

	bind(listen_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));

	listen(listen_fd, 10);

	return comm_fd = accept(listen_fd, (struct sockaddr*) NULL, NULL);
}


/* <-- FINDS FILE SENT FROM REQUEST IN REGARDS TO INPUTTED DIRECTORY -->
   <------- ALSO WRITES TO FILE AFTERWARDS + CLOSES COMM SOCKET ------->
*/
find_file(int socket, char* str, char* dir){
	FILE *fp;
	int flen;
	char *buffer;
	char *reply;
	char status[4096];
	char method[MAX_STR_LEN];
	char file[MAX_STR_LEN];
	strcat(dir,"/");
	time_t curr_time = time(NULL);
	struct tm tm = *localtime(&curr_time);



	parse_request(str, method, file);

	strcat(dir,file);
	if(strcmp(method,"GET")!=0){ //Checks to make sure request is GET
		sprintf(status,"Server-time:%d/%d/%d.\nHTTP/1.0 505: Not Implemented\r\n\r\n", tm.tm_mday,  tm.tm_mon+1, tm.tm_year+1900);
		write(socket, status, strlen(status));
		close(socket);
		return;
	}

	fp = fopen(file, "rb");
	if(!fp){ // Checks if file exists in given directory
		sprintf(status,"Server-time:%d/%d/%d.\nHTTP/1.0 404: File Not Found\r\n\r\n", tm.tm_mday,  tm.tm_mon+1, tm.tm_year+1900);
		write(socket,status, strlen(status));
		close(socket);
		return;
	}
	else{ // Else file is found
		
		fseek(fp,0,SEEK_END);
		flen = ftell(fp);
		rewind(fp);
		//buffer to read from file.
		buffer = (char*) malloc(flen+1);
		sprintf(status,"Server-time: %d/%d/%d.\nHTTP/1.0 200:File Found\r\n\r\n", tm.tm_mday,  tm.tm_mon+1, tm.tm_year+1900);
		reply = (char*) malloc(flen+strlen(status)+2);
		//use reply to know we have enough space
		strcpy(reply, status);
		//reads from file.
		fread(buffer, flen, 1, fp);
		fclose(fp);
		// Adds buffer to status+reply
		strcat(reply, buffer);

		//writes to file
		write(socket, reply, strlen(reply)+1);
		close(socket);
		free(buffer);
		free(reply);
		return;
	}
}

int main(int argc, char *argv[])
{
 	if(argc == 1 || argc > 3){
 		printf("Wrong amount of arguments supplied.\nUsage: ./SimpServer <directory> <port> OR ./SimpServer <directory>\n");
 		exit(0);
 	}

 	char str[100];

   int comm_fd = open_connection(argc, argv);
 
 	while(1){
        bzero( str, 100);
 
        read(comm_fd,str,100);

        find_file(comm_fd,str, argv[2]);
        break;
      }
 
}
