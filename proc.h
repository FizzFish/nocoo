#include<stdio.h>
#include<stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <regex.h>
#include <string.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<sys/time.h>
#include<fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <unistd.h>
#include "queue.h"

/**
In proc.h, we wrap some functions to get the information from /proc/pid.
*/

typedef struct Argument Argument;

struct Argument
{
    char *origin;
    char *real;
    QSIMPLEQ_ENTRY(Argument) node;
};


typedef struct Process
{
    int pid;
    char elf_name[100];
    char *abs_name;
    char cwd[200];
    bool fuzz_kind; //0: CANNOT; 1: FILEFUZZ; 2: PROFUZZ
    Argument* fuzz_arg;
    int socknum;
    char fuzz_cmd[1024];
    QSIMPLEQ_HEAD(, Argument) arglist;
} Process;

bool in_white(char*);
bool is_elf(char*);
bool root_own(int);
bool has_file_in_arg(int);
bool is_listen(int);

Process* get_process(int);
bool filter(Process*);
int can_fuzz(Process*);

