#include "dwarf4/dwarf4.h"
#include <sys/ptrace.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <fcntl.h>
#include <inttypes.h>
#include <readline/readline.h>
#include <readline/history.h>

#define MAX_N_CHILD_ARGS 256

#define MAX_N_BREAKPOINTS 256

#define PARSE_MAX_N_TOKENS 16
#define PARSE_MAX_TOKEN_LEN 256

#define PARSE_NO_ERROR  0
#define PARSE_ERROR     1

#define EXECUTE_NO_ERROR    0
#define EXECUTE_ERROR       1

#define REG_NO_ERROR        0
#define REG_ERROR_NOTFOUND  1

#define MAIN_NO_ERROR       0
#define MAIN_ERROR_ARGS     1

// Breakpoint errors -- must be less than 0
#define BP_ERR_DUPLICATE    -1
#define BP_ERR_TOOMANY      -2
#define BP_ERR_NOLINE       -3

#define PC_REGNAME  "rip"

#define MAX_STACK_TRACE_DEPTH   256

typedef struct debug_state_t {
    int hit_bp;
} debug_state_t;

typedef struct bp_t {
    void *addr;
    unsigned char orig_data;
    int exists;
} bp_t;

typedef enum cmd_type_t {
    CMD_BP_SET,
    CMD_BP_DEL,
    CMD_BP_LIST,
    CMD_CONTINUE,
    CMD_NEXT,
    CMD_PRINT_MEM,
    CMD_SET_MEM,
    CMD_PRINT_REG,
    CMD_SET_REG,
    CMD_BACKTRACE
} cmd_type_t;

typedef struct cmd_bp_set_info_t {
    unsigned int line;
} cmd_bp_set_info_t;

typedef struct cmd_bp_del_info_t {
    unsigned int idx;
} cmd_bp_del_info_t;

typedef struct cmd_print_mem_info_t {
    void *addr;
} cmd_print_mem_info_t;

typedef struct cmd_set_mem_info_t {
    void *addr;
    char new_value;
} cmd_set_mem_info_t;

typedef struct cmd_print_reg_info_t {
    char regname[9];    // longest reg name is orig_rax (8 chars) + '\0'
} cmd_print_reg_info_t;

typedef struct cmd_set_reg_info_t {
    char regname[9];
    unsigned long long new_value;
} cmd_set_reg_info_t;

typedef struct cmd_t {
    cmd_type_t type;
    union {
        cmd_bp_set_info_t bp_set_info;
        cmd_bp_del_info_t bp_del_info;
        cmd_print_mem_info_t print_mem_info;
        cmd_set_mem_info_t set_mem_info;
        cmd_print_reg_info_t print_reg_info;
        cmd_set_reg_info_t set_reg_info;
    };
} cmd_t;



pid_t child_pid = 0;
bp_t breakpoints[MAX_N_BREAKPOINTS] = {{ 0 }};
int n_breakpoints = 0;
debug_state_t state = { 0 };


void sigint_handler(int signum) {
    ptrace(PTRACE_INTERRUPT, child_pid, NULL, NULL);
}

void tokenize(char *cmd_str, char cmd_tokens[PARSE_MAX_N_TOKENS][PARSE_MAX_TOKEN_LEN], unsigned int *n_tokens) {
    int cur_token = 0;
    int cur_idx = 0;
    for(int i = 0; ; i++) {
        if(cmd_str[i] == ' ') {
            if (cur_idx > 0) {
                // Advance to the next token
                cmd_tokens[cur_token++][cur_idx] = '\0';
                cur_idx = 0;
            } else {
                cur_idx++;
            }
        } else if (cmd_str[i] == '\0') {
            // End of cmd str
            if (cur_idx > 0) {
                cmd_tokens[cur_token++][cur_idx] = '\0';
            }
            break;
        } else {
            cmd_tokens[cur_token][cur_idx++] = cmd_str[i];
        }
        if (cur_token == PARSE_MAX_N_TOKENS) {
            break;
        }
        if (cur_idx == PARSE_MAX_TOKEN_LEN-1) {
            cmd_tokens[cur_token++][cur_idx] = '\0';
            cur_idx = 0;
            if (cur_token == PARSE_MAX_N_TOKENS) {
                break;
            }
        }
    }
    *n_tokens = cur_token;
}

int get_ll(const char *str, long long *num) {
    errno = 0;
    char *end;
    *num = strtoll(str, &end, 10);
    if (errno || end != str + strlen(str)) {
        return 1;
    }
    return 0;
}

int get_addr_of_var(const char *varname, void **addr) {
    long long addr_num;
    int err = get_ll(varname, &addr_num);
    *addr = (void*)addr_num;
    return err;
}

void setup_inferior(const char *path, char *const argv[]) {
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execv(path, argv);
}

void *rel_to_abs_addr(pid_t pid, void *addr) {
    char fname[128];
    sprintf(fname, "/proc/%d/maps", pid);
    FILE *f = fopen(fname, "r");
    fseek(f, 0, SEEK_SET);
    char offset_str[13];
    fscanf(f, "%12s", offset_str);
    long offset = strtol(offset_str, NULL, 16);
    return (void*)(addr + offset);
}

void *line_to_addr(unsigned int line, int *err) {
    void *addr;
    *err = dwarf4_query_line("hello.c", line, &addr);
    if (!*err) {
        return rel_to_abs_addr(child_pid, addr);
    } else {
        return NULL;
    }
}

void enable_bp(bp_t *bp) {
    if (!bp->exists) {
        unsigned long data = ptrace(PTRACE_PEEKDATA, child_pid, bp->addr, NULL);
        unsigned long int3 = 0xcc;
        unsigned long data_with_int3 = ((data & ~0xff) | int3);
        bp->orig_data = data & 0xff;
        ptrace(PTRACE_POKEDATA, child_pid, bp->addr, data_with_int3);
        data = ptrace(PTRACE_PEEKDATA, child_pid, bp->addr, NULL);
        bp->exists = 1;
    }
}

void disable_bp(bp_t *bp) {
    if (bp->exists) {
        long data = ptrace(PTRACE_PEEKDATA, child_pid, bp->addr, NULL);
        long restored_data = ((data & ~0xff) | bp->orig_data);
        ptrace(PTRACE_POKEDATA, child_pid, bp->addr, restored_data);
        //printf("Disabling bp at %p: instruction %lx -> %lx\n", bp->addr, data, restored_data);
        bp->exists = 0;
    }
}

int create_bp(unsigned int line) {
    int err = 0;
    void *addr = line_to_addr(line, &err);
    if (err) {
        return BP_ERR_NOLINE;
    }
    int avail_idx = -1;
    int is_duplicate = 0;
    for(int i = 0; i < MAX_N_BREAKPOINTS; i++) {
        if(avail_idx == -1 && !breakpoints[i].exists)
            avail_idx = i;
        if(breakpoints[i].exists && breakpoints[i].addr == addr)
            return BP_ERR_DUPLICATE;
    }
    if(avail_idx == MAX_N_BREAKPOINTS) {
        return BP_ERR_TOOMANY;
    }
    breakpoints[avail_idx].addr = addr;
    enable_bp(&breakpoints[avail_idx]);
    return avail_idx;
}

int get_bp_at_addr(void *addr) {
    int n_bp = 0;
    for(int i = 0; i < MAX_N_BREAKPOINTS; i++) {
        if (breakpoints[i].exists && breakpoints[i].addr == addr) {
            return i;
        }
    }
    return -1;
}

void list_breakpoints() {
    for (int i = 0; i < MAX_N_BREAKPOINTS; i++) {
        if (breakpoints[i].exists) {
            printf("%d\t%p\n", i, breakpoints[i].addr);
        }
    }
}

unsigned long long *get_reg_in_regs(struct user_regs_struct *regs, char *reg_str) {
    unsigned long long *reg;
    if (!strcmp(reg_str, "r15")) { reg = &regs->r15; }
    else if (!strcmp(reg_str, "r14")) { reg = &regs->r14; }
    else if (!strcmp(reg_str, "r13")) { reg = &regs->r13; }
    else if (!strcmp(reg_str, "r12")) { reg = &regs->r12; }
    else if (!strcmp(reg_str, "rbp")) { reg = &regs->rbp; }
    else if (!strcmp(reg_str, "rbx")) { reg = &regs->rbx; }
    else if (!strcmp(reg_str, "r11")) { reg = &regs->r11; }
    else if (!strcmp(reg_str, "r10")) { reg = &regs->r10; }
    else if (!strcmp(reg_str, "r9")) { reg = &regs->r9; }
    else if (!strcmp(reg_str, "r8")) { reg = &regs->r8; }
    else if (!strcmp(reg_str, "rax")) { reg = &regs->rax; }
    else if (!strcmp(reg_str, "rcx")) { reg = &regs->rcx; }
    else if (!strcmp(reg_str, "rdx")) { reg = &regs->rdx; }
    else if (!strcmp(reg_str, "rsi")) { reg = &regs->rsi; }
    else if (!strcmp(reg_str, "rdi")) { reg = &regs->rdi; }
    else if (!strcmp(reg_str, "orig_rax")) { reg = &regs->orig_rax; }
    else if (!strcmp(reg_str, "rip")) { reg = &regs->rip; }
    else if (!strcmp(reg_str, "cs")) { reg = &regs->cs; }
    else if (!strcmp(reg_str, "eflags")) { reg = &regs->eflags; }
    else if (!strcmp(reg_str, "rsp")) { reg = &regs->rsp; }
    else if (!strcmp(reg_str, "ss")) { reg = &regs->ss; }
    else if (!strcmp(reg_str, "fs_base")) { reg = &regs->fs_base; }
    else if (!strcmp(reg_str, "gs_base")) { reg = &regs->gs_base; }
    else if (!strcmp(reg_str, "ds")) { reg = &regs->ds; }
    else if (!strcmp(reg_str, "es")) { reg = &regs->es; }
    else if (!strcmp(reg_str, "fs")) { reg = &regs->fs; }
    else if (!strcmp(reg_str, "gs")) { reg = &regs->gs; }
    else { reg = NULL; }
    return reg;
}

unsigned long get_mem(void *addr) {
    unsigned long data = ptrace(PTRACE_PEEKDATA, child_pid, addr, NULL);
    return data;
}

void get_regs(struct user_regs_struct *regs) {
    ptrace(PTRACE_GETREGS, child_pid, NULL, (void*)regs);
}

void set_regs(struct user_regs_struct *regs) {
    ptrace(PTRACE_SETREGS, child_pid, NULL, (void*)regs);
}

unsigned long long get_reg(char *regname, int *err) {
    struct user_regs_struct regs = { 0 };
    get_regs(&regs);
    unsigned long long *reg = get_reg_in_regs(&regs, regname);
    if (reg) {
        if (err)
            *err = REG_NO_ERROR;
        return *reg;
    } else if (err) {
        *err = REG_ERROR_NOTFOUND;
    }
    return 0;
}

void set_reg(char *regname, unsigned long long val, int *err) {
    struct user_regs_struct regs = { 0 };
    get_regs(&regs);
    unsigned long long *reg = get_reg_in_regs(&regs, regname);
    if (reg) {
        *reg = val;
        set_regs(&regs);
        if (err)
            *err = REG_NO_ERROR;
    } else if (err) {
        *err = REG_ERROR_NOTFOUND;
    }
}

// Must be called upon any continue/step command after hitting a breakpoint,
// even if the breakpoint was disabled already! Otherwise the instruction on
// which the breakpoint was set will be skipped.
void step_over_breakpoint(int *status, debug_state_t *state) {
    state->hit_bp = 0;
    void *bp_addr = (void*)(get_reg(PC_REGNAME, NULL) - 1);
    int bp_idx = get_bp_at_addr(bp_addr);
    int must_disable_bp = (bp_idx != -1 && breakpoints[bp_idx].exists);
    if (must_disable_bp) {
        disable_bp(&breakpoints[bp_idx]);
    }
    set_reg(PC_REGNAME, (unsigned long long)bp_addr, NULL);
    ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
    waitpid(child_pid, status, 0);
    if (must_disable_bp) {
        enable_bp(&breakpoints[bp_idx]);
    }
}

void print_backtrace() {
    printf("rip: %p\n", (void*)get_reg(PC_REGNAME, NULL));
    int reg_err = 0;
    void *fp = (void*)get_reg("rbp", &reg_err);
    if (!reg_err) {
        void *ret_addr = (void*)get_mem(fp + 8);
        int i = 0;
        for (i = 0; i < MAX_STACK_TRACE_DEPTH && fp && ret_addr < 0x700000000000; i++) {
            printf("rbp: %p\tret: %p\n", fp, ret_addr);
            fp = (void*)get_mem(fp);
            ret_addr = (void*)get_mem(fp + 8);
        }
        if (i == MAX_STACK_TRACE_DEPTH) {
            printf("Max stack trace depth reached\n");
        }
    } else {
        printf("Error: couldn't get reg rbp\n");
    }
}

int cmd_parse(char *cmd_str, cmd_t *cmd) {
    char cmd_tokens[PARSE_MAX_N_TOKENS][PARSE_MAX_TOKEN_LEN];
    unsigned int n_tokens;
    tokenize(cmd_str, cmd_tokens, &n_tokens);
    if(n_tokens < 1) {
        fprintf(stderr, "Error: no valid command found\n");
        return PARSE_ERROR;
    }
    if(!strcmp(cmd_tokens[0], "b")) {
        cmd->type = CMD_BP_SET;
        if(n_tokens < 2) {
            fprintf(stderr, "Error: too few arguments to set breakpoint\n");
            return PARSE_ERROR;
        }
        long long line_no;
        int num_error = get_ll(cmd_tokens[1], &line_no);
        if(num_error || line_no < 1) {
            fprintf(stderr, "Error: breakpoint line is not a valid number\n");
            return PARSE_ERROR;
        }
        cmd->bp_set_info.line = (unsigned int) line_no;
    } else if(!strcmp(cmd_tokens[0], "d")) {
        cmd->type = CMD_BP_DEL;
        if(n_tokens < 2) {
            fprintf(stderr, "Error: too few arguments to delete breakpoint\n");
            return PARSE_ERROR;
        }
        long long idx;
        int num_err = get_ll(cmd_tokens[1], &idx);
        if(num_err) {
            fprintf(stderr, "Error: breakpoint index is not a valid number\n");
            return PARSE_ERROR;
        }
        cmd->bp_del_info.idx = idx;
    } else if(!strcmp(cmd_tokens[0], "bl")) {
        cmd->type = CMD_BP_LIST;
    } else if(!strcmp(cmd_tokens[0], "c")) {
        cmd->type = CMD_CONTINUE;
    } else if(!strcmp(cmd_tokens[0], "n")) {
        cmd->type = CMD_NEXT;
    } else if(!strcmp(cmd_tokens[0], "p")) {
        cmd->type = CMD_PRINT_MEM;
        if(n_tokens < 2) {
            fprintf(stderr, "Error: too few arguments to print memory\n");
            return PARSE_ERROR;
        }
        int addr_error = get_addr_of_var(cmd_tokens[1],
                &cmd->print_mem_info.addr);
        if(addr_error) {
            fprintf(stderr, "Error: memory address is not a valid number\n");
            return PARSE_ERROR;
        }
    } else if(!strcmp(cmd_tokens[0], "s")) {
        cmd->type = CMD_SET_MEM;
        if(n_tokens < 3) {
            fprintf(stderr, "Error: too few arguments to set memory\n");
            return PARSE_ERROR;
        }
        int addr_error = get_addr_of_var(cmd_tokens[1],
                &cmd->set_mem_info.addr);
        if(addr_error) {
            fprintf(stderr, "Error: memory address is not a valid number\n");
            return PARSE_ERROR;
        }
        long long new_value;
        int num_err = get_ll(cmd_tokens[2], &new_value);
        if (num_err) {
            fprintf(stderr, "Error: new value is not a valid number\n");
            return PARSE_ERROR;
        }
        cmd->set_mem_info.new_value = (char)new_value;
    } else if(!strcmp(cmd_tokens[0], "pr")) {
        cmd->type = CMD_PRINT_REG;
        if(n_tokens < 2) {
            fprintf(stderr, "Error: too few arguments to print register\n");
            return PARSE_ERROR;
        }
        memcpy(cmd->print_reg_info.regname, cmd_tokens[1], 8);
        cmd->print_reg_info.regname[8] = '\0';
    } else if(!strcmp(cmd_tokens[0], "sr")) {
        cmd->type = CMD_SET_REG;
        if(n_tokens < 3) {
            fprintf(stderr, "Error: too few arguments to set register\n");
            return PARSE_ERROR;
        }
        memcpy(cmd->set_reg_info.regname, cmd_tokens[1], 8);
        cmd->set_reg_info.regname[8] = '\0';
        long long new_value;
        int num_err = get_ll(cmd_tokens[2], &new_value);
        cmd->set_reg_info.new_value = (unsigned long long)new_value;
        if(num_err) {
            fprintf(stderr, "Error: new register value is not a valid number\n");
            return PARSE_ERROR;
        }
    } else if(!strcmp(cmd_tokens[0], "bt")) {
        cmd->type = CMD_BACKTRACE;
    } else {
        fprintf(stderr, "Error: command not recognized\n");
        return PARSE_ERROR;
    }
    return PARSE_NO_ERROR;
}

int cmd_execute(cmd_t *cmd, int *status, debug_state_t *state) {
    switch(cmd->type) {
        case CMD_BP_SET: {
            int bp_idx = create_bp(cmd->bp_set_info.line);
            if (bp_idx >= 0) {
                printf("Enabled breakpoint %d at %p\n", bp_idx, breakpoints[bp_idx].addr);
            } else {
                switch (bp_idx) {
                    case BP_ERR_DUPLICATE:
                        fprintf(stderr, "Error: breakpoint already exists there\n");
                        break;
                    case BP_ERR_TOOMANY:
                        fprintf(stderr, "Error: max number of breakpoints reached\n");
                        break;
                    case BP_ERR_NOLINE:
                        fprintf(stderr, "Error: breakpoint cannot be set on line %d\n", cmd->bp_set_info.line);
                        break;
                }
                return EXECUTE_ERROR;
            }
            break;
        } case CMD_BP_DEL: {
            unsigned int idx = cmd->bp_del_info.idx;
            if (idx >= MAX_N_BREAKPOINTS || !breakpoints[idx].exists) {
                fprintf(stderr, "Error: breakpoint does not exist\n");
                return EXECUTE_ERROR;
            }
            disable_bp(&breakpoints[idx]);
            printf("Disabled breakpoint %d\n", idx);
            break;
        } case CMD_BP_LIST: {
            list_breakpoints();
            break;
        } case CMD_CONTINUE: {
            printf("Continuing...\n");
            if (state->hit_bp) {
                //printf("Stepping over breakpoint\n");
                step_over_breakpoint(status, state);
            }
            state->hit_bp = 0;
            ptrace(PTRACE_CONT, child_pid, NULL, NULL);
            waitpid(child_pid, status, 0);
            break;
        } case CMD_NEXT: {
            if (state->hit_bp) {
                //printf("Stepping over breakpoint\n");
                step_over_breakpoint(status, state);
            }
            ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
            waitpid(child_pid, status, 0);
            break;
        } case CMD_PRINT_MEM: {
            unsigned long data = get_mem(cmd->print_mem_info.addr);
            printf("0x%lx\n", data);
            break;
        } case CMD_SET_MEM: {
            ptrace(PTRACE_POKEDATA, child_pid, cmd->set_mem_info.addr, cmd->set_mem_info.new_value);
            break;
        } case CMD_PRINT_REG: {
            int reg_err;
            unsigned long long reg_val = get_reg(cmd->print_reg_info.regname, &reg_err);
            if (!reg_err) {
                printf("Register value: %llx\n", reg_val);
            } else {
                printf("Error: register not found\n");
            }
            break;
        } case CMD_SET_REG: {
            int reg_err;
            set_reg(cmd->set_reg_info.regname, cmd->set_reg_info.new_value, &reg_err);
            if (!reg_err) {
                printf("Register set successfully\n");
            } else {
                printf("Error: register not found\n");
            }
            break;
        } case CMD_BACKTRACE: {
            print_backtrace();
        } default: {
            break;
        }
    }
    return 0;
}

static void attach_to_inferior(pid_t pid)
{
    child_pid = pid;
    printf("Starting on PID %d\n", pid);
    /*ptrace(PTRACE_SEIZE, pid, NULL, NULL);
    ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);*/

    int status;
    debug_state_t state;
    state.hit_bp = 0;
    waitpid(pid, &status, 0);
    ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_EXITKILL);
    char *cmd_str;
    while(1) {
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP || WSTOPSIG(status) == SIGINT) {
            if (get_bp_at_addr((void*)(get_reg(PC_REGNAME, NULL) - 1)) != -1) {
                state.hit_bp = 1;
                printf("Stopped at breakpoint\n");
            }
            cmd_str = readline(">");
            if (!cmd_str) {
                break;
            }
            add_history(cmd_str);
            int parse_err = 0;
            int execute_err = 0;
            cmd_t cmd;
            parse_err = cmd_parse(cmd_str, &cmd);
            free(cmd_str);
            if (!parse_err) {
                execute_err = cmd_execute(&cmd, &status, &state);
            }
        } else if (WIFEXITED(status)) {
            printf("Inferior exited\n");
            exit(0);
        }
    }
}

void dbg_inferior_exec(const char *path, char *const argv[])
{
    do {
        pid_t result = fork();
        switch (result) {
            case 0:   // inferior
                setup_inferior(path, argv);
                break;
            case -1:  // error
                break;
            default:  // debugger
                attach_to_inferior(result);
                break;
        }
    } while (child_pid == -1 && errno == EAGAIN);
}

void usage(char *name) {
    printf("Usage: %s [program] [program_args]\n", name);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        usage(argv[0]);
        return MAIN_ERROR_ARGS;
    }
    signal(SIGINT, sigint_handler);
    char *child_argv[MAX_N_CHILD_ARGS + 1] = { 0 }; // null-terminated
    for (int i = 0; i < argc - 2 && i < MAX_N_CHILD_ARGS; i++) {
        child_argv[i] = argv[i + 2];
    }
    dwarf4_init(argv[1]);
    using_history();
    dbg_inferior_exec(argv[1], child_argv);

    return MAIN_NO_ERROR;
}
