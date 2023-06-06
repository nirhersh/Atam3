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

#define SHT_SYMTAB 0x2
#define SHT_STRTAB 0x3
#define STB_GLOBAL 1
#define STB_LOCAL 0

/*
TO DO:
find the name of the symbol from strtab
*/ 


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
		fclose(filePointer);
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
		fclose(filePointer);
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
	Elf64_Shdr symbolTableSection;
	Elf64_Shdr stringTableSection;
	for(int i=0; i<header.e_shnum; i++){
		fread(&currentSectionHeader.sh_name, sizeof(currentSectionHeader.sh_name), 1, filePointer); // read section name to progress file pointer
		fread(&currentSectionHeader.sh_type, sizeof(currentSectionHeader.sh_type), 1, filePointer); // read section type
		fread(&currentSectionHeader.sh_flags, sizeof(currentSectionHeader.sh_flags), 1, filePointer);
		fread(&currentSectionHeader.sh_addr, sizeof(currentSectionHeader.sh_addr), 1, filePointer);
		fread(&currentSectionHeader.sh_offset, sizeof(currentSectionHeader.sh_offset), 1, filePointer);
		fread(&currentSectionHeader.sh_size, sizeof(currentSectionHeader.sh_size), 1, filePointer);
		fread(&currentSectionHeader.sh_link, sizeof(currentSectionHeader.sh_link), 1, filePointer);
		fread(&currentSectionHeader.sh_info, sizeof(currentSectionHeader.sh_info), 1, filePointer);
		fread(&currentSectionHeader.sh_addralign, sizeof(currentSectionHeader.sh_addralign), 1, filePointer);
		fread(&currentSectionHeader.sh_entsize, sizeof(currentSectionHeader.sh_entsize), 1, filePointer);
		if(currentSectionHeader.sh_type == SHT_SYMTAB){ // check if section is a symbol table
			symbolTableSection=currentSectionHeader;
		}
		if(currentSectionHeader.sh_type == SHT_STRTAB){ // Check if section is string table
			stringTableSection=currentSectionHeader;
		}
	}
	// CurrentLocation is beginning of SymTab
	currentLocation = symbolTableSection.sh_offset;
	if(symbolTableSection.sh_entsize == 0){
		printf("imashcha malca");
		return -1;
	}
	int numOfSymbols = symbolTableSection.sh_size / symbolTableSection.sh_entsize;

	// Looking for the symbol with the provided name
	Elf64_Sym currentSymbol;
	bool foundSymbol = false, foundGlobal=false;
	for(int i=0; i < numOfSymbols; i++){
		fread(&currentSymbol.st_name, sizeof(currentSymbol.st_name), 1, filePointer);
		// find name in here
		if(strcmp(currentSymbol.st_name, symbol_name) == 0){
			foundSymbol=true;
			fread(&currentSymbol.st_info, sizeof(currentSymbol.st_info), 1, filePointer);
			if (ELF64_ST_BIND(currentSymbol.st_info)==STB_GLOBAL){
				foundGlobal = true;
				break;
			}
		}
		fseek(filePointer, symbolTableSection.sh_entsize, currentLocation);
		currentLocation += symbolTableSection.sh_entsize;
	}
	currentLocation += sizeof(currentSymbol.st_name) + sizeof(currentSymbol.st_info);
	if (foundSymbol==false) {
		*error_val=-1;
		fclose(filePointer);
		return -1;
	}
	if (foundGlobal == false){
		*error_val = -2;
		fclose(filePointer);
		return -2;
	}
	// we found a global symbol
	fread(&currentSymbol.st_other, sizeof(currentSymbol.st_other), 1, filePointer);
	fread(&currentSymbol.st_shndx, sizeof(currentSymbol.st_shndx), 1, filePointer);
	currentLocation += sizeof(currentSymbol.st_other) + sizeof(currentSymbol.st_shndx);
	if (currentSymbol.st_shndx==SHN_UNDEF) {
		*error_val=-4;
		fclose(filePointer);
		return -4;
	}
	*error_val = 1;
	
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