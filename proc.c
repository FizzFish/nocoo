#include "proc.h"
#include "queue.h"

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
    char match[10];
    regmatch_t pmatch[2];
    const size_t nmatch = 2;
    if (!fp) {
        printf("%s\n", status_file);
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
                printf("line is %s\n", line);
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
    if (!access(arg->origin, 0)) {
        strcpy(arg->real, arg->origin);
        return true;
    }
    char path[50];
    if (!access(path, 0)) {
        strcpy(arg->real, path);
        return true;
    }
    strcpy(arg->real, arg->origin);
    return false;
}

bool can_fuzz_file(Process* pro)
{
    Argument *argp;
    bool find = false;
    bool first = true;
    QSIMPLEQ_FOREACH(argp, &pro->arglist, node)
    {
        if(!find && is_file(argp, pro->cwd)) {
            find = true;
            strcat(pro->fuzz_cmd, " @@");
            pro->fuzz_arg = argp;
        } else {
            strcat(pro->fuzz_cmd, " ");
            strcat(pro->fuzz_cmd, argp->real);
        }
    }
    printf("%s %s\n", __func__, pro->fuzz_cmd);
    return find;
}

bool can_fuzz_protocol(Process* proc)
{
    char fd[50], file[300], real[50];
    struct dirent * pdir;
    int socknum = 0;
    sprintf(fd, "/proc/%d/fd", proc->pid);
    DIR * fd_dir = opendir(fd);
    while((pdir = readdir(fd_dir)) != 0) {
        sprintf(file, "%s/%s", fd, pdir->d_name);
        if (readlink(file, real, 50) < 0)
            continue;
        if (strstr(real, "socket"))
            socknum = atoi(real+8);
    }
    if (socknum) {
        proc->socknum = socknum;

        return true;
    }
    return false;
}

// 0: CANNOT; 1: FILE; 2: PROTOCOL
int can_fuzz(Process* pro)
{
    if (in_white(pro->abs_name))
        return 0;
    if (!is_elf(pro->elf_name))
        return 0;
    if (root_own(pro->pid))
        return 0;
    if (can_fuzz_file(pro))
        return 1;
    else if (can_fuzz_protocol(pro))
        return 2;
}

Process* get_process(int pid)
{
    Process *proc = malloc(sizeof(Process));
    proc->pid = pid;
    QSIMPLEQ_INIT(&proc->arglist);
    char file_name[50];
    FILE *fp;
    // analysis /proc/pid/exe
    sprintf(file_name, "/proc/%d/exe", pid);
    if(readlink(file_name, proc->elf_name, 50) < 0)
        return NULL;
    proc->abs_name = strrchr(proc->elf_name, '/') + 1;
    //printf("%s %s %s\n", proc->elf_name, proc->elf_name, proc->abs_name);

    // analysis /proc/pid/cwd
    sprintf(file_name, "/proc/%d/cwd", pid);
    if(readlink(file_name, proc->cwd, 50) < 0)
        return NULL;
    //printf("cwd is %s\n", proc->cwd);

    // analysis /proc/pid/cmdline
    sprintf(file_name, "/proc/%d/cmdline", pid);
    fp = fopen(file_name, "r");
    if (!fp)
        perror("fread");
    size_t size = 0;
    char *line = NULL;
    int c;
    char arg[10240], *p = arg;
    bool first = true;
    while((c = fgetc(fp)) != EOF)
    {
        *p++ = c;
        if (!c) {
            if (first) {
                first = false;
                memcpy(proc->fuzz_cmd, proc->elf_name, strlen(proc->elf_name));
            } else {
                Argument *argument = malloc(sizeof(Argument));
                argument->origin = malloc(strlen(arg));
                argument->real = malloc(strlen(proc->cwd) + strlen(arg));
                memcpy(argument->origin, arg, strlen(arg));
                QSIMPLEQ_INSERT_TAIL(&proc->arglist, argument, node);
            }
            memset(arg, 0 , 1024);
            p = arg;
        }
    }
    fclose(fp);
    return proc;
}


