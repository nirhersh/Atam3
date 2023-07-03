#ifndef DEBUGGER_H
#define DEBUGGER_H

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
#define SHT_DYNSYM 0xb
#define SHT_REL 0x9
#define SHT_RELA 0x4

#define PREFIX "PRF::"

bool compare(FILE* string1, char* string2);
unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val);


#endif //DEBUGGER_H