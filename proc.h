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

/**
In proc.h, we wrap some functions to get the information from /proc/pid.
*/

bool in_white(char*);
bool is_elf(char*);
bool root_own(int);
bool has_file_in_arg(int);
bool is_listen(int);

