#include "Debugger.h"
#include "elf64.h"

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
	FILE* relaPointer = NULL;
	FILE* symbolTablePointer = NULL;
	filePointer = fopen(exe_file_name, "rb");
	strtabPointer = fopen(exe_file_name, "rb");
	relaPointer = fopen(exe_file_name, "rb");
	symbolTablePointer = fopen(exe_file_name, "rb");
	if (filePointer==NULL) {
		printf("failed to open");
		fclose(filePointer);
		return 0;
	}
	Elf64_Ehdr header;
	fread(&header, sizeof(Elf64_Ehdr), 1, filePointer);
	
	if(header.e_type != ET_EXEC){
		*error_val = -3;
		fclose(filePointer);
		fclose(strtabPointer);
		fclose(relaPointer);
		fclose(symbolTablePointer);
		return 0;
	}
	int currentLocation=header.e_shoff;
	fseek(filePointer, currentLocation, SEEK_SET);
	Elf64_Shdr currentSectionHeader;
	Elf64_Shdr symbolTableSection;
	Elf64_Shdr stringTableSection;
	Elf64_Shdr dynamicSymbolTableSection;
	Elf64_Shdr relaSection;
	Elf64_Addr relaOffset;
	Elf64_Shdr* shdrs = malloc(sizeof(Elf64_Shdr) * header.e_shnum);
	read(filePointer, shdrs, sizeof(Elf64_Shdr) * header.e_shnum);
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
		if(currentSectionHeader.sh_type == SHT_DYNSYM){
			dynamicSymbolTableSection=currentSectionHeader;
		}
		if(currentSectionHeader.sh_type == SHT_RELA){
			relaSection = currentSectionHeader;
			Elf64_Shdr symTab = shdrs[relaSection.sh_link];
			Elf64_Shdr strTab = shdrs[symTab.sh_link];
			int numOfEntries = relaSection.sh_size / relaSection.sh_entsize; 
			fseek(relaPointer, relaSection.sh_offset, SEEK_SET);
			
			Elf64_Rela current_rela;
			for(int j=0; j<(numOfEntries); j++){
				fread(&current_rela, sizeof(current_rela), 1, relaPointer);
				int index = ELF64_R_SYM(current_rela.r_info);
				Elf64_Sym current_symbol;
				fseek(symbolTablePointer, symTab.sh_offset + index*symTab.sh_entsize, SEEK_SET);
				fread(&current_symbol, sizeof(current_symbol), 1, symbolTablePointer);
				fseek(symbolTablePointer, strTab.sh_offset + current_symbol.st_name, SEEK_SET);
				if(compare(symbolTablePointer, symbol_name)){
					relaOffset=current_rela.r_offset;
				}
			}
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

		fseek(strtabPointer, symbolTableSection.sh_offset + symbolTableSection.sh_size + currentSymbol.st_name, SEEK_SET);
		if(compare(strtabPointer, symbol_name)){
			foundSymbol=true;
			if (ELF64_ST_BIND(currentSymbol.st_info)==STB_GLOBAL){
				foundGlobal = true;
				break;
			}
		}
		currentLocation += symbolTableSection.sh_entsize;
	}
	if (foundSymbol==false) {
		*error_val=-1;
		fclose(filePointer);
		fclose(strtabPointer);
		fclose(relaPointer);
		fclose(symbolTablePointer);		return 0;
	}
	if (foundGlobal == false){
		*error_val = -2;
		fclose(filePointer);
		fcolse(relaPointer);
		fclose(symbol_name);
		fclose(strtabPointer);
		return 0;
	}
	// we found a global symbol yayyyyyyyyyyy
	if (currentSymbol.st_shndx==SHN_UNDEF) {
		*error_val=-4;
		
		fclose(filePointer);
		fclose(strtabPointer);
		fcolse(relaPointer);
		fclose(symbol_name);
		return relaOffset;
	}
	*error_val = 1;
	
	fclose(filePointer);
	fclose(strtabPointer);
	fcolse(relaPointer);
	fclose(symbol_name);
	return currentSymbol.st_value;
}

bool compare(FILE* string1, char* string2){
	char* tempString = string2;
	char c = fgetc(string1);
	if(tempString == NULL  || string1 == NULL){
		return false;
	}
	while(c != '\0' || *tempString != '\0'){
		if(c != *tempString){
			return false;
		}
		++tempString;
		c = fgetc(string1);
	}
	if(c == '\0' && *tempString == '\0'){
		return true;
	}
	return false;
}


int main_hw3(int argc, char *const argv[]) {
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