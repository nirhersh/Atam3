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
bool compare(FILE* string1, char* string2);

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
	FILE* strtabPointer = NULL;
	filePointer = fopen(exe_file_name, "rb");
	strtabPointer = fopen(exe_file_name, "rb");
	if (filePointer==NULL) {
		printf("failed to open");
		fclose(filePointer);
		return 0;
	}
	Elf64_Ehdr header;
	fread(&header, sizeof(Elf64_Ehdr), 1, filePointer);
	// int currentLocation = SEEK_SET;
	// fseek(filePointer, EI_NIDENT*sizeof(char), currentLocation); // Now at e_type
	// currentLocation += EI_NIDENT*sizeof(char);
	// fread(&header.e_type, sizeof(header.e_type), 1, filePointer);
	// currentLocation += sizeof(header.e_type);
	if(header.e_type != ET_EXEC){
		*error_val = -3;
		fclose(filePointer);
		return 0;
	}

	// fseek(filePointer, 22, currentLocation); // Now at e_shoff
	// currentLocation += 22;
	// fread(&header.e_shoff, sizeof(header.e_shoff), 1, filePointer);
	// currentLocation+=sizeof(header.e_shoff);
	// fseek(filePointer, 12, currentLocation);
	// currentLocation += 12;
	// fread(&header.e_shnum, sizeof(header.e_shnum), 1, filePointer);
	// currentLocation += sizeof(header.e_shnum);
	// fseek(filePointer, header.e_shoff, SEEK_SET); // Now at section header table
	int currentLocation=header.e_shoff;
	fseek(filePointer, currentLocation, SEEK_SET);
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
			// symbolTableSection=currentSectionHeader;
			memcpy(&symbolTableSection.sh_name, &currentSectionHeader.sh_name, sizeof(currentSectionHeader.sh_name));
			memcpy(&symbolTableSection.sh_type, &currentSectionHeader.sh_type, sizeof(currentSectionHeader.sh_type));
			memcpy(&symbolTableSection.sh_flags, &currentSectionHeader.sh_flags, sizeof(currentSectionHeader.sh_flags));
			memcpy(&symbolTableSection.sh_addr, &currentSectionHeader.sh_addr, sizeof(currentSectionHeader.sh_addr));
			memcpy(&symbolTableSection.sh_offset, &currentSectionHeader.sh_offset, sizeof(currentSectionHeader.sh_offset));
			memcpy(&symbolTableSection.sh_size, &currentSectionHeader.sh_size, sizeof(currentSectionHeader.sh_size));
			memcpy(&symbolTableSection.sh_link, &currentSectionHeader.sh_link, sizeof(currentSectionHeader.sh_link));
			memcpy(&symbolTableSection.sh_info, &currentSectionHeader.sh_info, sizeof(currentSectionHeader.sh_info));
			memcpy(&symbolTableSection.sh_addralign, &currentSectionHeader.sh_addralign, sizeof(currentSectionHeader.sh_addralign));
			memcpy(&symbolTableSection.sh_entsize, &currentSectionHeader.sh_entsize, sizeof(currentSectionHeader.sh_entsize));
		}
		if(currentSectionHeader.sh_type == SHT_STRTAB){ // Check if section is string table
			// stringTableSection=currentSectionHeader;
			memcpy(&stringTableSection.sh_name, &currentSectionHeader.sh_name, sizeof(currentSectionHeader.sh_name));
			memcpy(&stringTableSection.sh_type, &currentSectionHeader.sh_type, sizeof(currentSectionHeader.sh_type));
			memcpy(&stringTableSection.sh_flags, &currentSectionHeader.sh_flags, sizeof(currentSectionHeader.sh_flags));
			memcpy(&stringTableSection.sh_addr, &currentSectionHeader.sh_addr, sizeof(currentSectionHeader.sh_addr));
			memcpy(&stringTableSection.sh_offset, &currentSectionHeader.sh_offset, sizeof(currentSectionHeader.sh_offset));
			memcpy(&stringTableSection.sh_size, &currentSectionHeader.sh_size, sizeof(currentSectionHeader.sh_size));
			memcpy(&stringTableSection.sh_link, &currentSectionHeader.sh_link, sizeof(currentSectionHeader.sh_link));
			memcpy(&stringTableSection.sh_info, &currentSectionHeader.sh_info, sizeof(currentSectionHeader.sh_info));
			memcpy(&stringTableSection.sh_addralign, &currentSectionHeader.sh_addralign, sizeof(currentSectionHeader.sh_addralign));
			memcpy(&stringTableSection.sh_entsize, &currentSectionHeader.sh_entsize, sizeof(currentSectionHeader.sh_entsize));
		}
	}
	// CurrentLocation is beginning of SymTab
	currentLocation = symbolTableSection.sh_offset;
	int numOfSymbols = symbolTableSection.sh_size / symbolTableSection.sh_entsize;

	// Looking for the symbol with the provided name
	fseek(filePointer, currentLocation, SEEK_SET);
	// filePointer is now at SymTab
	Elf64_Sym currentSymbol;
	bool foundSymbol = false, foundGlobal=false;
	for(int i=0; i < numOfSymbols; i++){
		fread(&currentSymbol.st_name, sizeof(currentSymbol.st_name), 1, filePointer);
		fread(&currentSymbol.st_info, sizeof(currentSymbol.st_info), 1, filePointer);
		fread(&currentSymbol.st_other, sizeof(currentSymbol.st_other), 1, filePointer);
		fread(&currentSymbol.st_shndx, sizeof(currentSymbol.st_shndx), 1, filePointer);
		fread(&currentSymbol.st_value, sizeof(currentSymbol.st_value), 1, filePointer);
		fread(&currentSymbol.st_size, sizeof(currentSymbol.st_size), 1, filePointer);

		fseek(strtabPointer, stringTableSection.sh_offset + currentSymbol.st_name, SEEK_SET);
		if(compare(strtabPointer, symbol_name)){
			foundSymbol=true;
			// fread(&currentSymbol.st_info, sizeof(currentSymbol.st_info), 1, filePointer);
			if (ELF64_ST_BIND(currentSymbol.st_info)==STB_GLOBAL){
				foundGlobal = true;
				break;
			}
		}
		// fseek(filePointer, symbolTableSection.sh_entsize, currentLocation);
		currentLocation += symbolTableSection.sh_entsize;
	}
	// currentLocation += sizeof(currentSymbol.st_name) + sizeof(currentSymbol.st_info);
	if (foundSymbol==false) {
		*error_val=-1;
		fclose(filePointer);
		fclose(strtabPointer);
		return 0;
	}
	if (foundGlobal == false){
		*error_val = -2;
		fclose(filePointer);
		fclose(strtabPointer);
		return 0;
	}
	// we found a global symbol yayyyyyyyyyyy
	// fread(&currentSymbol.st_other, sizeof(currentSymbol.st_other), 1, filePointer);
	// fread(&currentSymbol.st_shndx, sizeof(currentSymbol.st_shndx), 1, filePointer);
	// currentLocation += sizeof(currentSymbol.st_other) + sizeof(currentSymbol.st_shndx);
	if (currentSymbol.st_shndx==SHN_UNDEF) {
		*error_val=-4;
		fclose(filePointer);
		fclose(strtabPointer);
		return 0;
	}
	*error_val = 1;
	
	fclose(filePointer);
	fclose(strtabPointer);
	return currentSymbol.st_value;
}

bool compare(FILE* string1, char* string2){
	printf("comparing.\n");
	char c = fgetc(string1);
	int index = 0;
	while(c != '\0' || string2[index] != '\0'){
		printf("%c\n", c);
		printf("%c\n", string2[index]);
		if(c != string2[index]){
			return false;
		}
		index++;
		c = fgetc(string1);
	}
	if(c == '\0' && string2[index] == '\0'){
		return true;
	}
	return false;
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