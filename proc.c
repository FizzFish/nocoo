#include "proc.h"
#include "queue.h"

extern FILE* logfp;
bool in_white(char *abs_name)
{
    char white_file[20] = "white";
    FILE *fp = fopen(white_file, "r");
    size_t size = 0;
    char *line = NULL;
    while(getline(&line, &size, fp) != -1)
    {
        if (strncmp(abs_name, line, strlen(abs_name)) == 0) {
            //printf("in white list\n");
            fclose(fp);
            return true;
        }
    }
    fclose(fp);
    return false;
}

bool is_elf(char * elf_name)
{
    FILE *fp = fopen(elf_name, "r");
    if (fp == NULL)
        return false;
    char magic[5];
    fread(magic, 1, 4, fp);
    fclose(fp);
    if ((uint8_t)magic[0] == 0x7f && (uint8_t)magic[1] == 0x45 
        && (uint8_t)magic[2] == 0x4c && (uint8_t)magic[3] == 0x46)
        return true;
    return false;
}

bool root_own(int pid)
{
    char status_file[50];
    sprintf(status_file, "/proc/%d/status", pid);
    size_t size = 0;
    char *line = NULL;
    FILE *fp = fopen(status_file, "r");
    int uid = 0;
    char match[20];
    regmatch_t pmatch[2];
    const size_t nmatch = 2;
    if (!fp) {
        perror("open status failed");
        return true;
    }
    while(getline(&line, &size, fp) != -1)
    {
        if (strstr(line, "Uid:") != NULL) {
            regex_t reg;
            const char *pattern = "^Uid:.([0-9]+).+$";
            regcomp(&reg, pattern, REG_EXTENDED);
            int status = regexec(&reg, line, nmatch, pmatch, 0);
            if (status == REG_NOMATCH) {
                regfree(&reg);
                perror("No match");
                return true;
            } else {
                int len = pmatch[1].rm_eo - pmatch[1].rm_so;
                memcpy(match, line + pmatch[1].rm_so, len);
                match[len] = 0;
                uid = atoi(match);
            }
            regfree(&reg);
        }
    }
    if (uid == 0)
        return true;
    return false;
}

bool is_file(Argument* arg, char* cwd)
{
    //check if arg is config file
    if (arg->origin[0] == '/') {
        strcpy(arg->real, arg->origin);
        return false;
    }
    if (!access(arg->origin, 0)) {
        strcpy(arg->real, arg->origin);
        return true;
    }
    sprintf(arg->real, "%s/%s", cwd, arg->origin);
    if (!access(arg->real, 0)) {
        return true;
    }
    strcpy(arg->real, arg->origin);
    return false;
}

bool can_fuzz_file(Process* proc)
{
    Argument *argp;
    bool find = false;
    bool first = true;
    QSIMPLEQ_FOREACH(argp, &proc->arglist, node)
    {
        if(!find && is_file(argp, proc->cwd)) {
            find = true;
            strcat(proc->fuzz_cmd, " @@");
            proc->fuzz_arg = argp;
        } else {
            strcat(proc->fuzz_cmd, " ");
            strcat(proc->fuzz_cmd, argp->real);
        }
    }
    if (find) {
        proc->fuzz_kind = 1;
        //fprintf(logfp, "File fuzz %d, cmd is %s\n", proc->pid, proc->fuzz_cmd);
        printf("File fuzz %d, cmd is %s, fuzz arg is %s\n", proc->pid, proc->fuzz_cmd, proc->fuzz_arg->origin);
    }
    return find;
}

bool can_fuzz_protocol(Process* proc, TcpList* tcplist)
{
    char fd[50], file[300], real[50];
    struct dirent * pdir;
    int socknum = 0;
    sprintf(fd, "/proc/%d/fd", proc->pid);
    DIR * fd_dir = opendir(fd);
    if (fd_dir < 0) {
        perror("opendir");
    }
    while((pdir = readdir(fd_dir)) != 0) {
        sprintf(file, "%s/%s", fd, pdir->d_name);
        if (readlink(file, real, 50) < 0)
            continue;
        if (strstr(real, "socket"))
            socknum = atoi(real+8);
    }
    if (socknum) {
        tcpEntry *tcp;
        QSIMPLEQ_FOREACH(tcp, tcplist, next)
            if (tcp->inode == socknum) {
                proc->port = tcp->rport;
                proc->fuzz_kind = 2;
                //fprintf(logfp, "Protocol fuzz %d, cmd is %s\n", proc->pid, proc->fuzz_cmd);
                printf("Protocol fuzz %d, cmd is %s\n", proc->pid, proc->fuzz_cmd);
                return true;
            }
    }
    return false;
}

// 0: CANNOT; 1: FILE; 2: PROTOCOL
int can_fuzz(Process* pro, TcpList* tcplist)
{
    if (in_white(pro->abs_name)) {
        return 0;
    }
    if (!is_elf(pro->elf_name))
        return 0;
#if 0
    if (root_own(pro->pid))
        return 0;
#endif
    extract_cmd(pro);
    if (can_fuzz_file(pro))
        return 1;
    else if (can_fuzz_protocol(pro, tcplist))
        return 2;
}

static bool get_link(char* path, char** real)
{
    char link[1024];
    int len = readlink(path, link, 1024);
    if (len < 0)
        return false;
    link[len] = 0;
    *real = malloc(len+1);
    strcpy(*real, link);
    return true;
}

Process* get_process(int pid)
{
    Process *proc = malloc(sizeof(Process));
    memset(proc, 0, sizeof(Process));
    proc->pid = pid;
    QSIMPLEQ_INIT(&proc->arglist);

    char file_name[100];
    sprintf(file_name, "/proc/%d/exe", pid);
    if (!get_link(file_name, &proc->elf_name)) {
        free(proc);
        return NULL;
    }
    proc->abs_name = strrchr(proc->elf_name, '/') + 1;
    //printf("%s %s %s\n", proc->elf_name, proc->elf_name, proc->abs_name);

    // analysis /proc/pid/cwd
    sprintf(file_name, "/proc/%d/cwd", pid);
    if (!get_link(file_name, &proc->cwd)) {
        free(proc->elf_name);
        free(proc);
        return NULL;
    }
    return proc;
}

void extract_cmd(Process *proc)
{
    // analysis /proc/pid/cmdline
    char file_name[100];
    sprintf(file_name, "/proc/%d/cmdline", proc->pid);
    FILE* fp = fopen(file_name, "r");
    if (!fp)
        perror("fread");
    size_t size = 0;
    char *line = NULL;
    int c;
    char arg[10240], *p = arg;
    bool first = true;
    int cmd_size = strlen(proc->elf_name);
    while((c = fgetc(fp)) != EOF)
    {
        *p++ = c;
        if (!c) {
            if (first) {
                first = false;
                proc->argnum = 1;
            } else {
                Argument *argument = malloc(sizeof(Argument));
                memset(argument, 0, sizeof(Argument));
                argument->origin = malloc(strlen(arg)+1);
                argument->real = malloc(strlen(proc->cwd) + strlen(arg)+2);
                strcpy(argument->origin, arg);
                QSIMPLEQ_INSERT_TAIL(&proc->arglist, argument, node);
                cmd_size += (strlen(proc->cwd) + strlen(arg)+2);
                proc->argnum++;
            }
            memset(arg, 0 , 1024);
            p = arg;
        }
    }
    proc->fuzz_cmd = malloc(cmd_size+10);
    strcpy(proc->fuzz_cmd, proc->elf_name);
    fclose(fp);
}

static void safe_free(void *p)
{
    if (p)
        free(p);
}
void free_proc(Process * proc)
{
    Argument* argp;
    QSIMPLEQ_FOREACH(argp, &proc->arglist, node)
    {
        safe_free(argp->origin);
        safe_free(argp->real);
        safe_free(argp);
    }
    safe_free(proc->elf_name);
    safe_free(proc->cwd);
    safe_free(proc->fuzz_cmd);
    safe_free(proc);
}

