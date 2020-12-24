#include "proc.h"
#include <sys/wait.h>

FILE* logfp;
TcpList tcplist;
void search_process(void);

extern void prepare_env(Fuzz*);
extern void sniffer(int);

static void handle_timeout(int sig) {
    search_process();
}

void fuzz(Process * proc)
{
    Fuzz fuzz;
    fuzz.root = malloc(6);
    fuzz.in = malloc(strlen(proc->abs_name)+10);
    sprintf(fuzz.root, "%d", proc->pid);
    sprintf(fuzz.in, "%d/%s", proc->pid, "in");
    fuzz.proc = proc;
    
    prepare_env(&fuzz);
    int pid = fork();
    int status;
    if (pid < 0)
        perror("fork");
    if (!pid) {
        sniffer(10086);
    }
    waitpid(pid, &status, 0);
    //printf("%d: %s %s\n", proc->pid, fuzz.root, fuzz.in);
    //printf("%s\n", proc->fuzz_cmd);
    free(fuzz.root);
    free(fuzz.in);
}
int getval(char* line, regmatch_t *pmatch, int index, int base)
{
    char match[50];
    int len = pmatch[index].rm_eo - pmatch[index].rm_so;
    char *end;
    memcpy(match, line + pmatch[index].rm_so, len);
    match[len] = 0;
    puts(match);
    return (int)strtol(match, &end, base);
}
void procNet() {
    char path[50] = "/proc/net/tcp";
    size_t size = 0;
    char *line = NULL;
    char match[50];
    regmatch_t pmatch[10];
    size_t nmatch = 10; 
    //0: 00000000:AE0F 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 29467 1 0000000000000000 100 0 0 10 0
    const char *pattern = "^\\s*([0-9]+): ([0-9A-F]+):(....) ([0-9A-F]+):(....) (..) ([^ ]+ ){3}\\s*([0-9]+)\\s+[0-9]+\\s+([0-9]+).*$";
    regex_t reg;
    regcomp(&reg, pattern, REG_EXTENDED);
    FILE *fp = fopen(path, "r");
    bool first = true;
    QSIMPLEQ_INIT(&tcplist);
    while(getline(&line, &size, fp) != -1)
    {
        if (first) {
            first = false;
            continue;
        }
        //puts(line);
        int status = regexec(&reg, line, nmatch, pmatch, 0);
        if (status != REG_NOMATCH) {
            tcpEntry *tcp = malloc(sizeof(tcpEntry));
            tcp->raddr = getval(line, pmatch, 2, 16);
            tcp->rport =  getval(line, pmatch, 3, 16);
            tcp->laddr = getval(line, pmatch, 4, 16);
            tcp->lport =  getval(line, pmatch, 5, 16);
            tcp->state = getval(line, pmatch, 6, 16);
            tcp->inode = getval(line, pmatch, 9, 10);
            QSIMPLEQ_INSERT_TAIL(&tcplist, tcp, next);
            //printf("extract %d:%d %d:%d %d %d\n", ra, rp, la, lp, state, inode);
        }
            
    }
    regfree(&reg);
}

void search_process() {
    DIR * proc_dir = opendir("/proc");
    struct dirent * pdir;
    char status_file[300];//like /proc/100/status
    int pid;
    char path[100]; Process *proc = NULL; 
    while((pdir = readdir(proc_dir)) != 0) {
        //if inode == 0, continue
        if (pdir->d_ino == 0)
            continue;
        if(pdir->d_name[0] < '0' || pdir->d_name[0] > '9')
            continue;
        pid = atoi(pdir->d_name);
        proc = get_process(pid);
        if (!proc) {
            free(proc);
            continue;
        }
        if (can_fuzz(proc, &tcplist))
            break;
    }
    if (proc)
        fuzz(proc);
    free(proc);
}

int main() {
    /**
    int pid = fork();
    if (pid < 0)
        perror("fork");
    if (!pid)
        search_process();
    */
    logfp = fopen("log", "w");
    procNet();
#if 1
    signal(SIGALRM, handle_timeout);
    struct itimerval it;
    it.it_value.tv_sec = 1;
    it.it_value.tv_usec = 0;
    it.it_interval.tv_sec = 10;
    it.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &it, NULL);
    while(1);
#endif
    fclose(logfp);
    return 0;
}
