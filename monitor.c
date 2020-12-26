#include "proc.h"
#include <sys/wait.h>

FILE* logfp;

extern TcpList tcplist;
#if 0
static void handle_timeout(int sig) {
    printf("##################TIME OUT######################\n");
    search_process();
}
#endif

static void handle_cancle(int sig) {
    fclose(logfp);
    exit(0);
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
        fuzz(proc);
        free_proc(proc);
    } else
        printf("Not find Process\n");
}

int main() {
    //logfp = fopen("log", "w");
    logfp = stdout;
    procNet();
    signal(SIGINT,handle_cancle);
    while(1) {
        search_process();
        printf("sleeping.....\n");
//        sleep(30);
    }
    fclose(logfp);
    return 0;
}
