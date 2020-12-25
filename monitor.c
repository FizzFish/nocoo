#include "proc.h"
#include <sys/wait.h>

FILE* logfp;
TcpList tcplist;
void search_process(void);

extern void prepare_env(Fuzz*);
extern void sniffer(int, int);

static void handle_timeout(int sig) {
    printf("##################TIME OUT######################\n");
    search_process();
}

void fuzz(Process * proc)
{
    Fuzz fuzz;
    sprintf(fuzz.root, "d%d", proc->pid);
    sprintf(fuzz.in, "%s/in", fuzz.root);
    sprintf(fuzz.out, "%s/out", fuzz.root);
    fuzz.proc = proc;
    
    prepare_env(&fuzz);
    printf("%d: %s %s\n", proc->pid, fuzz.root, fuzz.in);
    printf("...............................\n");
    printf("cmd %s\n", proc->fuzz_cmd);
    printf("...............................\n");

    int pid, status;
    if (proc->fuzz_kind == 2) {
        char pcap[250];
        sprintf(pcap, "%s/pcap", fuzz.in);
        int infd = open(pcap, O_WRONLY | O_CREAT, S_IRWXU | S_IROTH);
        if (infd < 0)
            perror("open");
        pid = fork();
        if (pid < 0)
            perror("fork");
        if (!pid) {
            sniffer(proc->port, infd);
        }
        waitpid(pid, &status, 0);
        printf("status is %d\n", status);
    }
#if 1
    pid = fork();
    if (pid < 0)
        perror("fork");
    if (!pid) {
        Argument* argp;
        int argnum = proc->argnum;
        char ** argv;
        int i = 0;
        if (proc->fuzz_kind == 1) {
            //bin/afl-fuzz -i in -o out -Q -m none
            char **ffuzz_arg = {"bin/afl-fuzz", "-i", fuzz.in, "-o", fuzz.out,
                "-Q", "-m", "none"};
            argnum += 9;
            i = 8;
            argv = malloc(argnum * sizeof(char*));
            memcpy(argv, ffuzz_arg, 8 * sizeof(char*));
        } else {
        }
        argv[i] = malloc(sizeof(proc->elf_name)+1);
        strcpy(argv[i], proc->elf_name);
        i++;
        QSIMPLEQ_FOREACH(argp, &proc->arglist, node)
        {
            argv[i] = malloc(sizeof(argp->real)+1);
            strcpy(argv[i], argp->real);
            i++;
        }
        argv[i] = NULL;
        for(i=0;i<argnum;i++)
            puts(argv[i]);

        execv(proc->elf_name, argv);
    }
#endif
    waitpid(pid, &status, 0);
    printf("fuzz end\n");

}
int getval(char* line, regmatch_t *pmatch, int index, int base)
{
    char match[50];
    int len = pmatch[index].rm_eo - pmatch[index].rm_so;
    char *end;
    memcpy(match, line + pmatch[index].rm_so, len);
    match[len] = 0;
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
    char path[100];
    Process *proc = NULL; 
    bool find = false;
    while((pdir = readdir(proc_dir)) != 0) {
        //if inode == 0, continue
        if (pdir->d_ino == 0)
            continue;
        if(pdir->d_name[0] < '0' || pdir->d_name[0] > '9')
            continue;
        pid = atoi(pdir->d_name);
        proc = get_process(pid);
        if (!proc) {
            continue;
        }
        if (can_fuzz(proc, &tcplist)) {
            find = true;
            break;
        }
        free_proc(proc);
    }

    if (find) {
        printf("find proc %d\n", proc->pid);
        fuzz(proc);
        free(proc);
    }
    printf("Not find Process\n");
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
#if 0
    signal(SIGALRM, handle_timeout);
    struct itimerval it;
    it.it_value.tv_sec = 1;
    it.it_value.tv_usec = 0;
    it.it_interval.tv_sec = 10;
    it.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &it, NULL);
#endif
    while(1) {
        search_process();
        printf("sleeping.....\n");
        sleep(30);
    }
    fclose(logfp);
    return 0;
}
