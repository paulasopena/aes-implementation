#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "../inc/utils.h"

int main(void){
    //Find and open the file
    FILE *file = fopen("../src/aes_sample.in", "rb"); 
    if(!file){
        perror("Error opening the file"); 
        return 1;
    }

    //Establish the end of the file
    fseek(file,0, SEEK_END); 
    long file_size = ftell(file); 
    rewind(file); 
    
    //Set the memory where we are going to save the content of the file
    unsigned char *buffer = (unsigned char *)malloc(file_size); 
    if(!buffer){
        perror("Memory allocation of the buffer failed."); 
        fclose(file); 
        return 1; 
    }

    //Reading the file and saving it in the allocated memory for it
    size_t bytes_read = fread(buffer,1,file_size, file); 
    if(bytes_read != file_size){
        perror("File read error."); 
        free(buffer); 
        fclose(file); 
        return 1;
    }
    fclose(file); 

    printf("File contents in bytes: \n"); 
    for(long i =0; i<file_size; i++){
        printf("%02x ", buffer[i]); 
        if((i+1)%16 == 0){
            printf("\n"); 
        }
    }
    printf("\n"); 
    free(buffer); 
    return 0;
}