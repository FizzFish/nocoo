#include "proc.h"
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header
#include<sys/socket.h>
#include<arpa/inet.h>

extern FILE* logfp;
int copyFile(const char* src, const char* des)
{
    int nRet = 0;
    FILE* pSrc = NULL, *pDes = NULL;
    pSrc = fopen(src, "r");
    pDes = fopen(des, "w+");


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
    mkdir(fuzz->root, 0777);

    mkdir(fuzz->in, 0777);

    char dst[100];
    sprintf(dst, "%s/%s", fuzz->in, fuzz->proc->abs_name);
    copyFile(fuzz->proc->elf_name, dst);
    chmod(dst, 0777);

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
    logfp = stdout;

	if(sock_raw < 0)
	{
		printf("Socket Error\n");
		return;
	}
    printf("%s %d\n", __func__, port);
	while(1)
	{
		saddr_size = sizeof saddr;
		//Receive a packet
		data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
        printf("..");
		if(data_size <0 )
		{
			printf("Recvfrom error , failed to get packets\n");
			return;
		}
		//Now process the packet
        int iphdrlen = ((struct iphdr*)buffer)->ihl * 4;
        struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen);
        int dport = ntohs(tcph->dest);
        int header_size = iphdrlen + tcph->doff * 4;
        if (dport == port
            && data_size > header_size)
            {
                write(infd, buffer + header_size, data_size - header_size);
            }
	
	}
    close(infd);
	close(sock_raw);
}

