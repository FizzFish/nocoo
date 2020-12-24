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

void print_tcp_packet(unsigned char* Buffer, int Size);
void sniffer(int port)
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
		printf("Socket Error\n");
		return;
	}
	while(1)
	{
		saddr_size = sizeof saddr;
		//Receive a packet
		data_size = recvfrom(sock_raw , buffer , 65536 , 0 , &saddr , &saddr_size);
		if(data_size <0 )
		{
			printf("Recvfrom error , failed to get packets\n");
			return;
		}
		//Now process the packet
        print_tcp_packet(buffer, data_size);
	}
	close(sock_raw);
}

void PrintData (unsigned char* data , int Size)
{
    int i, j;	
	for(i=0 ; i < Size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			fprintf(logfp,"         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					fprintf(logfp,"%c",(unsigned char)data[j]); //if its a number or alphabet
				
				else fprintf(logfp,"."); //otherwise print a dot
			}
			fprintf(logfp,"\n");
		} 
		
		if(i%16==0) fprintf(logfp,"   ");
			fprintf(logfp," %02X",(unsigned int)data[i]);
				
		if( i==Size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) fprintf(logfp,"   "); //extra spaces
			
			fprintf(logfp,"         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) fprintf(logfp,"%c",(unsigned char)data[j]);
				else fprintf(logfp,".");
			}
			fprintf(logfp,"\n");
		}
	}
}

void print_tcp_packet(unsigned char* Buffer, int Size)
{
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)Buffer;
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen);
			
	fprintf(logfp,"\n\n***********************TCP Packet*************************\n");	
		
	//print_ip_header(Buffer,Size);
		
	fprintf(logfp,"\n");
	fprintf(logfp,"TCP Header\n");
	fprintf(logfp,"   |-Source Port      : %u\n",ntohs(tcph->source));
	fprintf(logfp,"   |-Destination Port : %u\n",ntohs(tcph->dest));
	fprintf(logfp,"   |-Sequence Number    : %u\n",ntohl(tcph->seq));
	fprintf(logfp,"   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
	fprintf(logfp,"   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	//fprintf(logfp,"   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	//fprintf(logfp,"   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	fprintf(logfp,"   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
	fprintf(logfp,"   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
	fprintf(logfp,"   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
	fprintf(logfp,"   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
	fprintf(logfp,"   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
	fprintf(logfp,"   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
	fprintf(logfp,"   |-Window         : %d\n",ntohs(tcph->window));
	fprintf(logfp,"   |-Checksum       : %d\n",ntohs(tcph->check));
	fprintf(logfp,"   |-Urgent Pointer : %d\n",tcph->urg_ptr);
	fprintf(logfp,"\n");
	fprintf(logfp,"                        DATA Dump                         ");
	fprintf(logfp,"\n");
		
	fprintf(logfp,"IP Header\n");
	PrintData(Buffer,iphdrlen);
		
	fprintf(logfp,"TCP Header\n");
	PrintData(Buffer+iphdrlen,tcph->doff*4);
		
	fprintf(logfp,"Data Payload\n");	
	PrintData(Buffer + iphdrlen + tcph->doff*4 , (Size - tcph->doff*4-iph->ihl*4) );
						
	fprintf(logfp,"\n###########################################################");
}
