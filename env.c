#include "proc.h"
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>

int copyFile(const char* src, const char* des)
{
    int nRet = 0;
    FILE* pSrc = NULL, *pDes = NULL;
    pSrc = fopen(src, "r");
    pDes = fopen(des, "w+");
    fprintf(logfp, "copyFile: %s => %s\n", src, des);
    if (pSrc && pDes)
    {
        int nLen = 0;
        char szBuf[1024] = {0};
        while((nLen = fread(szBuf, 1, sizeof szBuf, pSrc)) > 0)
        {
            fwrite(szBuf, 1, nLen, pDes);
        }
    }
    else
        nRet = -1;

    if (pSrc)
        fclose(pSrc), pSrc = NULL;

    if (pDes)
        fclose(pDes), pDes = NULL;

    return nRet;
}

void prepare_env(Fuzz* fuzz)
{
    if (access("env", 0)) {
        mkdir("env", 0755);
    }

    if (access(fuzz->root, 0)) {
        mkdir(fuzz->root, 0755);
    }

    if (access(fuzz->in, 0)) {
        mkdir(fuzz->in, 0755);
    }

    char dst[100];
    Process *proc = fuzz->proc;
    sprintf(dst, "%s/%s", fuzz->root, get_abs_name(proc));
    copyFile(proc->elf_name, dst);
    chmod(dst, 0777);

    if (proc->fuzz_arg) {
        char *abs = strrchr(proc->fuzz_arg->name, '/') + 1;
        sprintf(dst, "%s/%s", fuzz->in, abs);
        copyFile(proc->fuzz_arg->name, dst);
    }

}

void sniffer(int port, int infd)
{
    int sock_raw;
	int saddr_size , data_size;
	struct sockaddr saddr;
	struct in_addr in;
    struct sockaddr_in source,dest;
	sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
	unsigned char *buffer = (unsigned char *)malloc(65536); //Its Big!

	if(sock_raw < 0)
	{
		fprintf(logfp, "Cannot create RawSocket\n");
		return;
	}
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 100000;
    fprintf(logfp, "Sniffer port %d\n", port);
    int state = 0;
	while(1)
	{
		saddr_size = sizeof saddr;
		//Receive a packet
		data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
		if(data_size <0 )
		{
            if (state == 0)
                fprintf(logfp, "Cannot recv any packets in 30s\n");
            close(infd);
            close(sock_raw);
			return;
		}
		//Now process the packet
        int iphdrlen = ((struct iphdr*)buffer)->ihl * 4;
        struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
        int dport = ntohs(tcph->dest);
        int header_size = iphdrlen + tcph->doff * 4;
        if (dport == port && data_size > header_size) {
            write(infd, buffer + header_size, data_size - header_size);

            if (state == 0) {
                state = 1;
                tv.tv_sec = 1;
                tv.tv_usec = 100000;
                if (setsockopt(sock_raw, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
                    fprintf(logfp, "Cannot create RawSocket\n");
                }
            }
        }
	
	}
}

