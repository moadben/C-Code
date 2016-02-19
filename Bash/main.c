/*
 * main.c
 *
 * A simple program to illustrate the use of the GNU Readline library
 */
 
/* LEFT TO IMPLEMENT:
	- ERROR CHECKING FOR KILLS
	- PARTY MODE
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <sys/types.h>
#include <sys/wait.h>

 static void background(char *arguments[], int *total_procs);
 static void list_background(int *total_procs);
 static void bg_kill(char *arguments[], int *total_procs);
 static void proc_dec(int pid, int *total_procs);
 static void command(char *arguments[], int *total_procs);


struct Jobs {
   char*  job_name;
   pid_t job_id;
   int job_no;
   char is_stopped;
};

struct Jobs jobs[5];
int curr_jobs = 0;


void background(char *arguments[], int *total_procs){
	if(arguments[1] == NULL){
		printf("No process was given\n");
		return;
	}
	if(curr_jobs>=5){
		printf("ERROR: Too many jobs already running.\n");
		return;
	}
	char *argsv[64];
	int i = 1;
	int j = 0;
	char *process;
	process = (char*) malloc(50);
	strcpy(process,arguments[1]);
	while(arguments[i]!=NULL){
		argsv[j] = arguments[i];
		j = j+1;
		i = i+1;
	}
	argsv[j] = NULL;

	pid_t child_pid = fork();
	if(child_pid == 0){
		execvp(argsv[0],argsv);
		perror("execvp");
	}
	if(child_pid == -1){
		printf("Something went wrong\n");
		return;
	}
	else{
		jobs[curr_jobs].job_id = child_pid;
		jobs[curr_jobs].is_stopped = 'R';
		strcpy(jobs[curr_jobs].job_name, process);
		jobs[curr_jobs].job_no = curr_jobs+1;
		*total_procs = *total_procs+1;
		curr_jobs = curr_jobs+1;
	}
	free(process);
}


void list_background(int *total_procs){
	int i = 0;
	while(i != curr_jobs){
		printf("%d[%c]: %s\n", i, jobs[i].is_stopped, jobs[i].job_name);
		i = i+1;
	}
	if(i == 0){
		printf("There are no current processes running.\n");
	}
	else{
		printf("Total Processes: %d\n", i);
	}
}


	void proc_stop(char *arguments[]){
		int temp = atoi(arguments[1]);
		if(!temp){
			printf("ERROR: Argument was not a number\n");
			return;
		}
		if(temp>5){
			printf("ERROR: Argument was too large.\n");
			return;
		}
		if(temp>(curr_jobs-1)){
			printf("ERROR: Job does not exist\n");
			return;
		}
		pid_t proc_kill = jobs[temp].job_id;
		if(jobs[temp].is_stopped == 'S'){
			printf("The job has already been stopped\n");
		}
		kill(proc_kill, SIGSTOP);
		jobs[temp].is_stopped = 'S';

	}

	void proc_start(char *arguments[]){
		int temp = atoi(arguments[1]);
		if(!temp){
			printf("ERROR: Argument was not a number\n");
			return;
		}
		if(temp>5){
			printf("ERROR: Argument was too large.\n");
			return;
		}
		if(temp>(curr_jobs-1)){
			printf("ERROR: Job does not exit\n");
			return;
		}
		pid_t proc_kill = jobs[temp].job_id;
		if(jobs[temp].is_stopped == 'R'){
			printf("The job is already running\n");
		}
		kill(proc_kill, SIGCONT);
		jobs[temp].is_stopped = 'R';

	}


void bg_kill(char *arguments[], int *total_procs){
	pid_t pid;
	int status;
	int temp = atoi(arguments[1]);
	if(!temp){
		printf("ERROR: Argument was not a number.\n");
		return;
	}
	if(temp>5){
		printf("ERROR: Argument was too large.\n");
		return;
	}
	if(temp>(curr_jobs-1)){
		printf("ERROR: Job does not exit.\n");
		return;
	}
	pid_t proc_kill = jobs[temp].job_id;
	//if(kill(proc_kill,0) == 0){
		 kill(proc_kill,SIGKILL);
	//}
	pid = (waitpid(-1,&status,WNOHANG));
	if(pid > 0){
			proc_dec(pid, total_procs);
		}
}

void proc_dec(int pid, int *total_procs){
	int k = 0;
	printf("Process %d has terminated\n", (int) pid);
	while(k !=curr_jobs-1){
		jobs[k] = jobs[k+1];
		k = k+1;
	}
	*total_procs = *total_procs-1;
	curr_jobs = curr_jobs-1;
}


void command(char *arguments[], int *total_procs){
	if(strcmp(arguments[0], "bgkill") == 0){
		bg_kill(arguments, total_procs);
		return;
	}

	if(strcmp(arguments[0], "stop") == 0){
		proc_stop(arguments);
		return;
	}

	if(strcmp(arguments[0], "start") == 0){
		proc_start(arguments);
		return;
	}

	if(strcmp(arguments[0], "bg") == 0){
		background(arguments, total_procs);
		return;
	}

	if(strcmp(arguments[0], "bglist") == 0){
		list_background(total_procs);
		return;
	}
	else if(strcmp(arguments[0],"exit") == 0){
		exit(0);
	}

	else if(strcmp(arguments[0],"cd") == 0){
		if(strcmp(arguments[1],"..") == 0){
			chdir("..");
		}
		if(chdir(arguments[1])!=0){
			perror("chdir");
			return;
		}
		return;
	}
	else{
		pid_t child_pid = fork();
		if(child_pid ==0 ){
			execvp(arguments[0],arguments);
			perror("execvp");
		}
		else{
			int status;
			wait(&status);
		}
	}
}



int main ( void )
{
	char *saveptr;
	char *cwd;
	int i = 0;
	cwd = (char *) malloc(100);
	int temp = 0;
	int *total_procs = &temp;
	int f;
	for(f = 0; f<5; f++){
		jobs[f].job_name = (char *) malloc(50);
	}

	for (;;)
	{
		int status;
		pid_t pid;

		pid = (waitpid(-1,&status,WNOHANG));
		if( pid > 0){
			proc_dec((int)pid, total_procs);
		}
		
		char *arguments[64];
		i = 0;

		bzero(cwd, 100);
		cwd = getcwd(cwd, 100);
		printf("%s", cwd);

		char 	*cmd = readline (":");
		if(!*cmd){
			continue;
		}

		char *f_name = strtok_r(cmd, " ", &saveptr);
		
		while(f_name!=NULL){
			arguments[i] = f_name;
			i= i+1;
			f_name = strtok_r(NULL, " ", &saveptr);
		}
		arguments[i] = NULL;
		command(arguments, total_procs);
		free (cmd);
	}

	free (cwd);
	for(f = 0; f<5; f++){
		free(jobs[f].job_name);
	}


}
