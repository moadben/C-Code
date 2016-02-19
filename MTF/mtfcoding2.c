#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int count = 0;



void move_to_front(int index, char*** words){
	int i;
	char *t = (*words)[index];
	for(i = index; i>=1; i--){
		(*words)[i] = (*words)[i-1];
	}
	
	(*words)[0] = t;

}



void reallocate_words(char*** words_ptr, int* words_size_pointer){
	*words_size_pointer = *words_size_pointer*2;
	*words_ptr = (char**) realloc(*words_ptr, (*words_size_pointer) * (sizeof(**words_ptr)));

}


void add_word(char*** words, char* word, int* words_size_pointer){
	int len = strlen(word);
	char* temp = (char*) malloc((len+1)*sizeof(char));
	strcpy(temp, word);
	if ((count) >= *words_size_pointer){
		reallocate_words(words,words_size_pointer);
	}

	(*words)[count] = temp;
	count++;
}


void encode_word(int* words_size_pointer, FILE *f, char* word, char*** words){
	int i;
	int x;
	int pos;
	printf("words equals: '%s', length: '%zu'\n", word, strlen(word));
	if(count == 0){
		add_word(words, word, words_size_pointer);
		fputc(129, f);
		fputs((*words)[0], f);
		return;
	}
	for(i=0; i<count; i++){
		if(strcmp((*words)[i], word) == 0){
			break;
		}
	}
	if(i>=count){
		if((i+1)>=121 && (i+1)<376){
			add_word(words, word, words_size_pointer);
			fputc(121+128, f);
			x = (i-121)+1;
			if((x+1) == 1){
				printf("%d\n", x);
				fputc('\00', f);
			}
			else{
				fputc(x, f);
			}
			fputs((*words)[i], f);
			move_to_front(i, words);
		}
		else if((i+1)>=376){
			add_word(words, word, words_size_pointer);
			fputc(122+128, f);
			fputc(((i+1)-376)/256, f);
			fputc(((i+1)-376)%256, f);
			fputs((*words)[i], f);
			move_to_front(i, words);
		}			
		else{
			add_word(words, word, words_size_pointer);
			fputc(count+128, f);
			fputs((*words)[i], f);
			move_to_front(i, words);
		}
	}
	else{
		if((i+1)>=121 && (i+1)<376){
			fputc(121+128, f);
			fputc((i+1)-121, f);
			move_to_front(i, words);
		}
		else if((i+1)>=376){
			fputc(122+128, f);
			fputc(((i+1)-376)/256, f);
			fputc(((i+1)-376)%256, f);
			move_to_front(i, words);
		}
		else{
			fputc(i+129, f);
			move_to_front(i, words);
		}
	}


}


// Taken from Dr. Zastre's online code to remove newlines from the end of a line.
void chomp(char *line){
	if(line[strlen(line)-1] == '\n'){
		line[strlen(line)-1] = '\0';
	}
}

void sep_words(char*** words, char *line, int* words_size_pointer, FILE *f){
	char* x;
	int i = 0;
	x = strtok(line, " ");
	while(x != NULL){
		encode_word(words_size_pointer,f, x, words);
		x = strtok(NULL, " ");
	}	
}


void readline(FILE *f_two, FILE *f, char*** words, int* words_size_pointer){
	char *line;
	size_t len = 0;
	ssize_t temp;
	int count;
	do{
		temp = getline(&line,&len,f);
		printf("%s", line);
		if(temp!= -1){
			chomp(line);
			sep_words(words, line, words_size_pointer, f_two);
			fputc('\n', f_two);
		}
			line = NULL;
	}while(temp!=-1);
	fclose(f);
	fclose(f_two);
}
	

int main(int argc, char *argv[]){
	int x;
	int i;
	int j;
	x = strlen(argv[1]);
	char fi[x];
	char* mtf = "mtf";
	FILE *f;
	FILE *f_two;
	for(j = 0; j<(x-3); j++){
		fi[j] = argv[1][j];
	}
	strcat(fi, mtf);
	f = fopen(argv[1], "r");
	f_two = fopen(fi, "w");
	fputc(0xFA, f_two);
	fputc(0XCE, f_two);
	fputc(0XFA, f_two);
	fputc(0XDF, f_two);
	if(f == NULL){
		return 1;
	}
	
	char** words_ptr;
	int words_size = 5;
	int* words_size_pointer = &words_size;
	words_ptr = (char **) malloc(*words_size_pointer * (sizeof(*words_ptr)));
	char*** words = &words_ptr;
	readline(f_two, f, words, words_size_pointer);
	free((*words));
	return 0;


}
