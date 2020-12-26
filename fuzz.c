#include "proc.h"

TcpList tcplist;

static void prepare_fuzz(Fuzz *fuzz, Process * proc)
{
    sprintf(fuzz->root, "env/%d", proc->pid);
    sprintf(fuzz->in, "%s/in", fuzz->root);
    sprintf(fuzz->out, "%s/out", fuzz->root);
    fuzz->proc = proc;
    
    prepare_env(fuzz);
    show_fuzz_cmd(proc);

    int pid, status;
    if (proc->fuzz_kind == 2) {
        char pcap[250];
        sprintf(pcap, "%s/pcap", fuzz->in);
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
        //printf("status is %d\n", status);
    }
}

static int fuzz_pid;
static void handle_timeout(int sig) {
    fprintf(logfp, "timeout kill %d\n", fuzz_pid);
    kill(fuzz_pid, SIGINT);
}

void fuzz(Process * proc)
{
    Fuzz fuzz;
    prepare_fuzz(&fuzz, proc);
    int pid = fork();
    if (pid < 0)
        perror("fork");
    if (!pid) {
        //while(1);
        Argument* argp;
        int argnum = proc->argnum;
        char ** argv, **basearg;
        int i = 0, basenum = 8;
        if (proc->fuzz_kind == 1) {
            //bin/afl-fuzz -i in -o out -Q -m none
            char *fuzz_arg[] = {"./afl-fuzz", "-i", fuzz.in, "-o", fuzz.out,
                "-Q", "-m", "none"};
            basearg = fuzz_arg;
        } else {
        /**
            ./afl-fuzz -Q -d -i python/in/ -o python/out \
            -N tcp://127.0.0.1/8001 \
            -P FTP -D 10000 -q 3 -s 3 -E -K -R \
            python3 -m http.server 8001
        */
            char *proto = "FTP";// need to configure
            char *fuzz_arg[] = {"./afl-fuzz", "-i", fuzz.in, "-o", fuzz.out,
                "-Q", "-m", "none",
                "-N", "tcp://127.0.0.1/8001", 
                "-P",  proto, "-D", "10000", "-q", "3", "-s", "3", "-E", "-K", "-R"};
            basearg = fuzz_arg;
        }
        argnum += basenum+1;
        i = basenum;
        argv = malloc(argnum * sizeof(char*));
        memcpy(argv, basearg, basenum * sizeof(char*));

        argv[i] = malloc(sizeof(proc->elf_name)+1);
        strcpy(argv[i], proc->elf_name);
        i++;
        QSIMPLEQ_FOREACH(argp, &proc->arglist, node)
        {
            if (!argp->kind) {
                argv[i] = malloc(sizeof(argp->name)+1);
                strcpy(argv[i], argp->name);
            } else {
                argv[i] = "@@";
            }
            i++;
        }
        argv[i] = NULL;
#if 0
        for(i=0;i<argnum;i++)
            if(argv[i]) {
                fprintf(logfp, "%s ", argv[i]);
            }
        fprintf(logfp, "\n");
#endif
        close(1);
        execv("afl-fuzz", argv);
    }

    fuzz_pid = pid;
    int status;
    signal(SIGALRM, handle_timeout);
#if 0
    struct itimerval it;
    it.it_value.tv_sec = 5;
    it.it_value.tv_usec = 0;
    it.it_interval.tv_sec = 1;
    it.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &it, NULL);
#endif
    alarm(15);
    waitpid(fuzz_pid, &status, 0);
    fprintf(logfp, "fuzz end, status=%d\n", status);

}

static int getval(char* line, regmatch_t *pmatch, int index, int base)
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
