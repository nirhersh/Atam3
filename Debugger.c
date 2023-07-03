#include "Debugger.h"

pid_t run_target(const char* prog_name, char* prog_args[]);
void run_debugger(pid_t child_pid, unsigned long func_addr, bool dynlinked);

int main(int argc, char* argv[])
{
    char* func_name=argv[1];
    char* prog_name=argv[2];
    char* prog_args[argc + 1];
    for(int i=2; i<argc; i++){
        prog_args[i-2] = argv[i];
    }
    
    prog_args[argc] = NULL;
    int error_val;
    bool dynlinked=false;
    unsigned long addr=find_symbol(func_name, prog_name, &error_val);
    //printf("found symbol at address %lu\n", addr);
    
    if (error_val==-3) {
        printf("PRF:: %s not an executable!\n", prog_name);
        return 0;
    }else if(error_val == -1){
        printf("PRF:: %s not found! :(\n", func_name);
        return 0;
    } else if (error_val == -2) {
        printf("PRF:: %s is not a global symbol!\n", func_name);
        return 0;
    }else if (error_val == -4){
        //printf("hello2\n");
        dynlinked=true;
    }
    //part6 here
    pid_t child_pid;
    child_pid=run_target(prog_name, prog_args);
    //printf("ran target\n");
    run_debugger(child_pid, addr, dynlinked);
    //printf("finished\n");
    return 0;
}

pid_t run_target(const char* prog_name, char** prog_args)
{
    pid_t pid;
    pid=fork();
    if (pid>0)
        return pid;
    else if (pid==0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(prog_name, prog_args);
    }else{
        perror("fork");
        return -1;
    }
}

void run_debugger(pid_t child_pid, unsigned long func_addr, bool dynlinked)
{
    int wait_status;
    int call_counter=0;
    struct user_regs_struct regs;
    unsigned long got_addr;
    unsigned long got_data;
    bool first_call = true;
    
    // Wait for child to stop on first instruction
    waitpid(child_pid,&wait_status, 0);
    //printf("got address: %lx\n", func_addr);
    if(dynlinked){
        got_addr = func_addr;
        func_addr=ptrace(PTRACE_PEEKTEXT, child_pid, (void*)got_addr, NULL);
        //func_addr -= 6;
        got_data = func_addr;
    }

    long data=ptrace(PTRACE_PEEKTEXT, child_pid, (void*)func_addr, NULL); // data at the address of the function
    long ret_data, return_address=-1;
    unsigned long data_trap= (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)func_addr, (void*) data_trap);
    //printf("func address: %lx\n", func_addr);

    // Let the child continue until it first reaches the address
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);
    wait(&wait_status);
    while(!WIFEXITED(wait_status)) {
        //printf("got signal %d\n", WTERMSIG(wait_status));
        // ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        // printf("%llx\n", regs.rip - 1);
        if (WTERMSIG(wait_status)==127) {
            //printf("got trapped\n");
            // child arrived at breakpoint
            ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
            if(dynlinked){
                //printf("dynlinked\n");
                //first_call = false;
                // while(ptrace(PTRACE_PEEKTEXT, child_pid, (void*)got_addr, NULL) == got_data){
                //     printf("single step\n");
                //     ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
                // }
                // printf("got changed\n");
                func_addr = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)got_addr, NULL);
                // data=ptrace(PTRACE_PEEKTEXT, child_pid, (void*)func_addr, NULL); // data at the address of the dynamic function
                // data_trap= (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
                // ptrace(PTRACE_POKETEXT, child_pid, (void*)func_addr, (void*) data_trap);
                // ptrace(PTRACE_CONT, child_pid, NULL, NULL);
            }
            if (regs.rip -1 == func_addr)
            {
                return_address = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)regs.rsp, NULL);
                call_counter++;
                printf("PRF:: run #%d first parameter is %d\n", call_counter, (int)regs.rdi);

                // Remove breakpoint at func_addr
                ptrace(PTRACE_POKETEXT, child_pid, (void*)func_addr, (void*)data);
                regs.rip -=1;
                ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

                // set breakpoint at return_addr
                ret_data=ptrace(PTRACE_PEEKTEXT, child_pid, (void*)return_address, NULL);
                data_trap = (ret_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
                ptrace(PTRACE_POKETEXT, child_pid, (void*)return_address, (void*) data_trap);
            }
            else if(regs.rip - 1 == return_address){
                if (return_address==-1)
                    printf("I love ATAM <3\n");
                printf("PRF:: run #%d returned with %d\n", call_counter, (int)regs.rax);

                // Remove breakpoint at return_addr
                ptrace(PTRACE_POKETEXT, child_pid, (void*)return_address, (void*)ret_data);
                regs.rip -=1;
                ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

                // set breakpoint at func_addr
                data=ptrace(PTRACE_PEEKTEXT, child_pid, (void*)func_addr, NULL);
                data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
                ptrace(PTRACE_POKETEXT, child_pid, (void*)func_addr, (void*) data_trap);
            }
        }
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);
    }
}
