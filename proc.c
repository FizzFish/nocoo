#include "proc.h"

bool in_white(char *abs_name)
{
    char white_file[20] = "white";
    FILE *fp = fopen(white_file, "r");
    size_t size = 0;
    char *line = NULL;
    while(getline(&line, &size, fp) != -1)
    {
        if (strncmp(abs_name, line, strlen(abs_name)) == 0) {
            printf("in white list\n");
            fclose(fp);
            return true;
        }
    }
    fclose(fp);
    return false;
}

bool is_elf(char * elf_name)
{
    FILE *fp = fopen(elf_name, "r");
    if (fp == NULL)
        perror("open failed");
    char magic[5];
    fread(magic, 1, 4, fp);
    fclose(fp);
    if ((uint8_t)magic[0] == 0x7f && (uint8_t)magic[1] == 0x45 
        && (uint8_t)magic[2] == 0x4c && (uint8_t)magic[3] == 0x46)
        return true;
    return false;
}

bool root_own(int pid)
{
    char status_file[50];
    sprintf(status_file, "/proc/%d/status", pid);
    size_t size = 0;
    char *line = NULL;
    FILE *fp = fopen(status_file, "r");
    int uid = 0;
    char match[10];
    regmatch_t pmatch[2];
    const size_t nmatch = 2;
    if (!fp)
        perror("open status failed");
    while(getline(&line, &size, fp) != -1)
    {
        if (strstr(line, "Uid:") != NULL) {
            regex_t reg;
            const char *pattern = "^Uid:.([0-9]+).+$";
            regcomp(&reg, pattern, REG_EXTENDED);
            int status = regexec(&reg, line, nmatch, pmatch, 0);
            if (status == REG_NOMATCH) {
                printf("line is %s\n", line);
                perror("No match");
            } else {
                int len = pmatch[1].rm_eo - pmatch[1].rm_so;
                memcpy(match, line + pmatch[1].rm_so, len);
                match[len] = 0;
                printf("match find %s\n", match);
                uid = atoi(match);
            }
            regfree(&reg);
        }
    }
    printf("uid=%d\n", uid);
    if (uid == 0)
        return true;
    return false;
}

bool has_file_in_arg(int pid)
{
    return true;
}

bool is_listen(int pid)
{
    return true;
}

