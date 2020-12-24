#include "proc.h"
FILE *logfp;
extern void sniffer(int);
int main(int argc, char ** argv)
{
    sniffer(10086);
    return 0;
}
