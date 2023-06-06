#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

#define	ET_NONE	0	//No file type 
#define	ET_REL	1	//Relocatable file 
#define	ET_EXEC	2	//Executable file 
#define	ET_DYN	3	//Shared object file 
#define	ET_CORE	4	//Core file 

#define SHT_SYMTAB 0x3


/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {
	FILE* filePointer=NULL;
	filePointer = fopen(exe_file_name, "r");
	if (filePointer==NULL) {
		printf("failed to open");
		return 0;
	}
	Elf64_Ehdr header;
	int currentLocation = SEEK_SET;
	fseek(filePointer, EI_NIDENT*sizeof(char), currentLocation); // Now at e_type
	currentLocation += EI_NIDENT*sizeof(char);
	fread(&header.e_type, sizeof(header.e_type), 1, filePointer);
	currentLocation += sizeof(header.e_type);
	if(header.e_type != ET_EXEC){
		*error_val = -3;
		return -3;
	}
	fseek(filePointer, 22, currentLocation); // Now at e_shoff
	currentLocation += 22;
	fread(&header.e_shoff, sizeof(header.e_shoff), 1, filePointer);
	currentLocation+=sizeof(header.e_shoff);
	fseek(filePointer, 12, currentLocation);
	currentLocation += 12;
	fread(&header.e_shnum, sizeof(header.e_shnum), 1, filePointer);
	currentLocation += sizeof(header.e_shnum);
	fseek(filePointer, header.e_shoff, SEEK_SET); // Now at section header table
	currentLocation=header.e_shoff;
	Elf64_Shdr currentSectionHeader;
	for(int i=0; i<header.e_shnum; i++){
		fread(&currentSectionHeader.sh_name, sizeof(currentSectionHeader.sh_name), 1, filePointer); // read section name to progress file pointer
		fread(&currentSectionHeader.sh_type, sizeof(currentSectionHeader.sh_type), 1, filePointer); // read section type
		if(currentSectionHeader.sh_type == SHT_SYMTAB){ // check if section is a symbol table
			break;
		}else{
			fseek(filePointer, sizeof(Elf64_Shdr), currentLocation); // if not continue to next section
			currentLocation += sizeof(Elf64_Shdr);
		}
	}
	// Now currentSectionHeader is the Symbol Table, hopefully
	printf("type of currentSectionHeader is %u\n", currentSectionHeader.sh_type);


	fclose(filePointer);
	return 0;
}


int main(int argc, char *const argv[]) {
	int err = 0;
	unsigned long addr = find_symbol(argv[1], argv[2], &err);

	if (addr > 0)
		printf("%s will be loaded to 0x%lx\n", argv[1], addr);
	else if (err == -2)
		printf("%s is not a global symbol! :(\n", argv[1]);
	else if (err == -1)
		printf("%s not found!\n", argv[1]);
	else if (err == -3)
		printf("%s not an executable! :(\n", argv[2]);
	else if (err == -4)
		printf("%s is a global symbol, but will come from a shared library\n", argv[1]);
	return 0;
}