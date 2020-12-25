#include "proc.h"
FILE *logfp;
extern void sniffer(int);
extern bool can_fuzz_file(Process*);
int main(int argc, char ** argv)
{
    int pid = atoi(argv[1]);
    Process *proc = get_process(pid);
    extract_cmd(proc);
    can_fuzz_file(proc);
    return 0;
}
