#include<stdio.h>
#include<stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <regex.h>
#include <string.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include <unistd.h>
#include "queue.h"

/**
In proc.h, we wrap some functions to get the information from /proc/pid.
*/

typedef struct Argument Argument;

struct Argument
{
    char origin[20];
    char real[20];
    QLIST_ENTRY(Argument) node;
};


typedef struct Process
{
    int pid;
    char elf_name[50];
    char real_name[50];
    char *abs_name;
    char cwd[50];
    bool fuzz_kind; //0: CANNOT; 1: FILEFUZZ; 2: PROFUZZ
    Argument* fuzz_arg;
    char fuzz_cmd[100];
    QLIST_HEAD(, Argument) arglist;
} Process;

bool in_white(char*);
bool is_elf(char*);
bool root_own(int);
bool has_file_in_arg(int);
bool is_listen(int);

Process* get_process(int);
bool filter(Process*);
int can_fuzz(Process*);

