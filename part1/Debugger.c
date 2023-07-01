#include "Debugger.h"
#include "hw3_part1.c"

int main(int argc, char* argv[])
{
    char* func_name=argv[1];
    char* prog_name=argv[2];
    char* prog_args[] = {NULL};
    for(int i=3; i<argc; i++){
        prog_args[i-3] = argv[i];
    }

    int error_val;
    unsigned long addr=find_symbol(func_name, prog_name, &error_val);

    if (error_val==-3) {
        printf("PRF:: %s not an executable!\n", prog_name);
        return 0;
    }else if(error_val == -1){
        printf("PRF:: %s not found! :(\n", func_name);
        return 0;
    } else if (error_val == -2) {
        printf("PRF:: %s is not a global symbol!\n", func_name)
    }else if (error_val == -4){
        // part 5 here
    }
    //part6 here

    
}