#include "proc.h"

int main(int argc, char ** argv)
{
    int pid = atoi(argv[1]);
    /**
    char elf[50], real[50];
    char *abs;
    sprintf(elf, "/proc/%d/exe", pid);
    if(readlink(elf, real, 50) < 0)
        perror("readlink");
    abs = strrchr(real, '/') + 1;
    in_white(abs);
    is_elf(real);
    root_own(pid);
    */

    Process *pro = get_process(pid);
    return 0;
}
