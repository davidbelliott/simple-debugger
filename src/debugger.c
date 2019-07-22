#include <sys/ptrace.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <inttypes.h>
#include <readline/readline.h>
#include <readline/history.h>

#define PARSE_MAX_N_TOKENS 16
#define PARSE_MAX_TOKEN_LEN 256


pid_t child_pid;

typedef struct bp_t {
    pid_t pid;
    void *addr;
    char orig_data;
    int enabled;
} bp_t;

typedef enum cmd_type_t {
    CMD_BP_SET,
    CMD_BP_DEL,
    CMD_CONTINUE,
    CMD_NEXT,
    CMD_PRINT_MEM,
    CMD_SET_MEM,
    CMD_PRINT_REG,
    CMD_SET_REG
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

void sigint_handler(int signum) {
    printf("Handling SIGINT on PID %d...\n", child_pid);
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

int get_char(const char *str, char *num) {
    *num = 1;
    return 0;
}

int get_int(const char *str, int *num) {
    *num = 1;
    return 0;
}

int get_long(const char *str, long *num) {
    *num = 1;
    return 0;
}

int get_ull(const char *str, unsigned long long *num) {
    *num = 1;
    return 0;
}

int get_addr_of_var(const char *varname, void **addr) {
    long addr_num;
    int err = get_long(varname, &addr_num);
    *addr = (void*)addr_num;
    return err;
}

/* Used for ignored arguments */
static const pid_t ignored_pid;
static const void *ignored_ptr;


static const void *no_continue_signal = 0;

void setup_inferior(const char *path, char *const argv[])
{
  //ptrace(PTRACE_TRACEME, ignored_pid, ignored_ptr, ignored_ptr);
  execv(path, argv);
}

void enable_bp(bp_t *bp) {
    long data = ptrace(PTRACE_PEEKDATA, bp->pid, bp->addr, NULL);
    printf("Before: %lx\n", data);
    long int3 = 0xcc;
    long data_with_int3 = ((data & ~0xff) | int3);
    bp->orig_data = data & 0xff;
    ptrace(PTRACE_POKEDATA, bp->pid, bp->addr, data_with_int3);
    data = ptrace(PTRACE_PEEKDATA, bp->pid, bp->addr, NULL);
    printf("After: %lx\n", data);
    bp->enabled = 1;
}

void disable_bp(bp_t *bp) {
    long data = ptrace(PTRACE_PEEKDATA, bp->pid, bp->addr, NULL);
    long restored_data = ((data & ~0xff) | bp->orig_data);
    ptrace(PTRACE_POKEDATA, bp->pid, bp->addr, restored_data);
    printf("Disabling bp at %p: instruction %lx -> %lx\n", bp->addr, data, restored_data);
    bp->enabled = 0;
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

int cmd_parse(char *cmd_str, cmd_t *cmd) {
    char cmd_tokens[PARSE_MAX_N_TOKENS][PARSE_MAX_TOKEN_LEN];
    unsigned int n_tokens;
    tokenize(cmd_str, cmd_tokens, &n_tokens);
    if(n_tokens < 1) {
        return 1;
    }
    if(!strcmp(cmd_tokens[0], "b")) {
        cmd->type = CMD_BP_SET;
        if(n_tokens < 2) {
            return 1;
        }
        int num_error = get_int(cmd_tokens[1], &cmd->bp_set_info.line);
        if(num_error) {
            return 1;
        }
    } else if(!strcmp(cmd_tokens[0], "d")) {
        cmd->type = CMD_BP_DEL;
        if(n_tokens < 2) {
            return 1;
        }
        int num_err = get_int(cmd_tokens[1], &cmd->bp_del_info.idx);
        if(num_err) {
            return 1;
        }
    } else if(!strcmp(cmd_tokens[0], "c")) {
        cmd->type = CMD_CONTINUE;
    } else if(!strcmp(cmd_tokens[0], "n")) {
        cmd->type = CMD_NEXT;
    } else if(!strcmp(cmd_tokens[0], "p")) {
        cmd->type = CMD_PRINT_MEM;
        if(n_tokens < 3) {
            return 1;
        }
        int addr_error = get_addr_of_var(cmd_tokens[1],
                &cmd->print_mem_info.addr);
        if(addr_error) {
            return 1;
        }
    } else if(!strcmp(cmd_tokens[0], "s")) {
        cmd->type = CMD_SET_MEM;
        if(n_tokens < 3) {
            return 1;
        }
        int addr_error = get_addr_of_var(cmd_tokens[1],
                &cmd->set_mem_info.addr);
        if(addr_error) {
            return 1;
        }
        char new_value;
        int num_err = get_char(cmd_tokens[2], &cmd->set_mem_info.new_value);
        if (num_err) {
            return 1;
        }
    } else if(!strcmp(cmd_tokens[0], "pr")) {
        cmd->type = CMD_PRINT_REG;
        if(n_tokens < 2) {
            return 1;
        }
        memcpy(cmd->print_reg_info.regname, cmd_tokens[1], 8);
        cmd->print_reg_info.regname[8] = '\0';
    } else if(!strcmp(cmd_tokens[0], "sr")) {
        cmd->type = CMD_SET_REG;
        if(n_tokens < 3) {
            return 1;
        }
        memcpy(cmd->set_reg_info.regname, cmd_tokens[1], 8);
        cmd->set_reg_info.regname[8] = '\0';
        int num_err = get_ull(cmd_tokens[2], &cmd->set_reg_info.new_value);
        if(num_err) {
            return 1;
        }
    } else {
        return 1;
    }
    return 0;
}

int cmd_execute(cmd_t *cmd) {
    return 0;
}

static void attach_to_inferior(pid_t pid)
{
    child_pid = pid;
    printf("Starting on PID %d\n", pid);
    ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_EXITKILL);
    ptrace(PTRACE_SEIZE, pid, NULL, NULL);
    ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
    while(1) {
        int status;
        waitpid(pid, &status, 0);
        printf("Waitpid finished\n");
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
            int parse_err = 0;
            int execute_err = 0;
            int cont = 0;
            do {
                char *cmd_str = readline(">");
                if (!cmd_str) {
                    exit(0);
                }
                cmd_t cmd;
                parse_err = cmd_parse(cmd_str, &cmd);
                free(cmd_str);
                if (!parse_err) {
                    execute_err = cmd_execute(&cmd);
                    if (execute_err) {
                        printf("Error: could not execute\n");
                    }
                } else {
                    printf("Error: could not parse\n");
                }
            } while (parse_err || execute_err || !cont);
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

int main()
{
    signal(SIGINT, sigint_handler);
    char *argv[1] = { 0 };
    dbg_inferior_exec("./hello", argv);

    return 0;
}
