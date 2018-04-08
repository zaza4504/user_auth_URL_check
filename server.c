#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <time.h> 
#include <inttypes.h>
#include <openssl/sha.h>
#include <getopt.h>
#include "./userauthurlcheck.h"

int ProcessUDP(int serverport, char* passwd, int udptraffic);
int ProcessMsg(int connfd, char mode);
int createTCPMsg(char *buffer, TCPMSG* TCPMsg);
int readn(int socket, void* buffer, unsigned int n);

/* test username and password */
char* username1="aaa\0";
char* passwd1="bb11cc\0";

int main(int argc, char *argv[])
{

	int listenfd = 0, connfd = 0;
	struct sockaddr_in serv_addr; 
	int n=0;
	int flag=0;
	int udptraffic=0;
	char mode;
	int serverport=0;
	int pid;
	int optval;
	char sendBuff[1025];
	char Msg[1025];
	char buffer[20];

	int arg1=0;
	int arg2=0;
	int c;

	while (1)
	{
		static struct option long_options[] =
		{
			{"port",    required_argument, 0, 'T'},
			{"debug",    no_argument, 0, 'd'},
			{"normal",    no_argument, 0, 'n'},
			{"udptraffic",    no_argument, 0, 't'},
			{0, 0, 0, 0}
		};

		/* getopt_long stores the option index here. */
		int option_index = 0;

		c = getopt_long (argc, argv, "T:dnt",
				long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c)
		{
			case 0:
				/* If this option set a flag, do nothing else now. */
				if (long_options[option_index].flag != 0)
					break;
				if (optarg)
					printf ("\n");
				break;

			case 'T':
				arg1++;
				serverport=atoi(optarg);
				sprintf(buffer,"%d",serverport);
				if(strncmp(buffer,optarg,strlen(optarg))){
					printf("Invalid server prot:%s\n",optarg);
					return -1;
				}
				break;
			case 'd':
				arg2++;
				mode='D';
				break;
			case 'n':
				arg2++;
				mode='1';
				break;
			case 't':
				udptraffic=1;
				break;

			case '?':
				/* getopt_long already printed an error message. */
				break;

			default:
				abort ();
		}
	}

	if(arg1!=1 || arg2!=1){
		printf("Usage: server -T <server port>  -d/n -t\n");
		return -1;
	}
	/* end  */


	listenfd = socket(AF_INET, SOCK_STREAM, 0);

	optval = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);


	printf("listen on socket: %d, port: %d\n",listenfd, serverport);
	memset(&serv_addr, '0', sizeof(serv_addr));
	memset(sendBuff, '0', sizeof(sendBuff)); 

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(serverport); 

	if(bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr))){
		printf("bind error:%s\n",strerror(errno));
		close(listenfd);
		return -1;
	} 

	if(listen(listenfd, 10)){
		printf("listen error:%s\n",strerror(errno));
		close(listenfd);
		return -1;
	} 

	while(1){
		connfd = accept(listenfd, (struct sockaddr*)NULL, NULL); 

		if(connfd<0){
			printf("accept error:%s\n",strerror(errno));
			close(listenfd);
			return -1;
		} 

		/* fork */
		if((pid=fork())==0){
			/* in child */
			if(mode=='D'){
				/* debug mode  */
				printf("[Debug mode]\n");
			} else {
				/* normal  mode*/
				printf("[Normal mode]\n");
			}

			if(ProcessMsg(connfd,mode)<0){
				return -1;
			}
			printf("Close TCP connection ...\n");
			printf("Start UDP query process ...\n");
			ProcessUDP(serverport, passwd1,udptraffic);
			return 0;

		}

		if(pid<0){
			/* fork error */
			printf("Fork error:%s\n",strerror(errno));
			close(connfd);
			close(listenfd);
			return -1;
		} else {
			/* in parent */
			close(connfd);
		}
	}


}


int sha256(char* string, char* hashresult)
{
	int i=0;
	int offset=0;

	unsigned char hash[SHA256_DIGEST_LENGTH];

	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, string, strlen(string));
	SHA256_Final(hash, &sha256);

	for (i=0;i<SHA256_DIGEST_LENGTH;i++){
		offset += snprintf(hashresult+offset,64-offset,"%X",hash[i]);
	}
	return 0;
}

int ProcessMsg(int connfd, char mode)
{
	int flag=0;
	char SHAbuffer[65];
	char H2[32];
	char recvBuffer[2000];
	char sendBuffer[2000];
	uint16_t n=0;
	TCPMSG TCPMsg;	
	A0 a0;
	A1 a1;
	A2 a2; 
	A3 a3;

	srand(time(NULL));


	printf("Read A0 ......\n");
	if(readn(connfd,recvBuffer,2)!=2){
		printf("Cannot read TCPMsg head\n");
		return -1;
	}

	n=ntohs((*((uint16_t*)recvBuffer)))-2;
	
	if(readn(connfd,recvBuffer+2,n)!=n){
		printf("Cannot read cmd\n");
		return -1;
	}

	TCPMsg.mode=(char)(*(recvBuffer+13));

	if(TCPMsg.mode!=mode){
		printf("We are running in %s mode, receive package in %s mode\n",mode=='D'?"Debug":"Normal",TCPMsg.mode=='D'?"Debug":"Normal");
		return -1;
	}		

	if(mode!='D'){
		if (strncmp(recvBuffer+17, username1,ntohs(*((uint8_t*)(recvBuffer+16))))) {
			char a[*((uint8_t*)(recvBuffer+16))+1];
			memset(a,0,sizeof(a));
			memcpy(a, recvBuffer+17,*((uint8_t*)(recvBuffer+16)));
			printf("No such username:%s, len:%s\n", a, *((uint8_t*)(recvBuffer+16)));
			flag=1;
		}	
	}

	/* create A1 TCP message */
	TCPMsg.MsgLen=20;
	TCPMsg.MsgLen=htons(TCPMsg.MsgLen);
	TCPMsg.mode=mode;
	createTCPMsg(sendBuffer,&TCPMsg);
	TCPMsg.MsgLen=ntohs(TCPMsg.MsgLen);

	memcpy(sendBuffer+14,"A1",2);

	/* generate the random value and send it to client*/
	if(mode=='D'){
		a1.AUTH1=123456;
	}else{
		a1.AUTH1=rand();
	}

	a1.AUTH1=htonl(a1.AUTH1);
	memcpy(sendBuffer+16,&a1.AUTH1,4);

	printf("Send A1 --- AUTH1:%d\n",ntohl(a1.AUTH1));
	n=write(connfd,sendBuffer,TCPMsg.MsgLen);

	printf("Read A2 ......\n");
	/* receive H1 from client */
	if(readn(connfd,recvBuffer,2)!=2){
		perror("Cannot read TCPMsg head\n");
		return -1;
	}


	n=ntohs((*((uint16_t*)recvBuffer)))-2;
	if(readn(connfd,recvBuffer+2,n)!=n){
		perror("Cannot read cmd\n");
		return -1;
	}

	/* caculate the SHA256 hash fo passwd+R */
	memset(H2,'\0',sizeof(H2));
	sprintf(H2,"%s",passwd1);
	sprintf(H2+strlen(passwd1),"%d",ntohl(a1.AUTH1));
	memset(SHAbuffer,'\0',sizeof(SHAbuffer));
	sha256(H2,SHAbuffer);


	/* create A3 message  */
	TCPMsg.MsgLen=21;
	TCPMsg.MsgLen=htons(TCPMsg.MsgLen);
	createTCPMsg(sendBuffer,&TCPMsg);
	TCPMsg.MsgLen=ntohs(TCPMsg.MsgLen);

	memcpy(sendBuffer+14,"A3",2);

	if(mode=='D'){
		a3.status=0;
		a3.SID=654321;

	}else{
		/* no such user or wrong TCP HASH */
		if(flag==1 || strncmp(SHAbuffer,recvBuffer+16,64)){
			perror("Wrong TCP HASH value\n");

			/* send status 1 and session ID 999999 back due to wrong HASH value */
			a3.status=1;
			a3.SID=654321;
		} else {
			/* success, send status 0 and a randon session ID back */
			a3.status=0;
			a3.SID=rand();
		}
	}

	a3.SID=htonl(a3.SID);
	memcpy(sendBuffer+16,&a3.status,1);
	memcpy(sendBuffer+17,&a3.SID,4);

	printf("Send A3 --- Status:%d, SID:%d\n",a3.status,ntohl(a3.SID));
	n=write(connfd,sendBuffer,TCPMsg.MsgLen);
	if(n<0){
		printf("send A3 message failed: %s\n",strerror(errno));
		return -1;
	}

	if(a3.status==1){
		printf("Stop the service due to wrong TCP HASH\n");
		return -1;
	}

	return 0;
}

int ProcessUDP(int serverport, char*passwd, int udptraffic)
{
	int udpSocket, nBytes;
	char buffer[2000];
	char qrybuffer[2000];
	char rplbuffer[2000];
	char SHAHash[64];
	struct sockaddr_in serverAddr, clientAddr;
	socklen_t addr_size, client_addr_size;
	int optval=1;
	int n=0;
	int HMAClen=0;
	int urllen=0;
	char mode;
	struct timeval tv; /* timeout variable for udp traffic verification */
	UDPRPLMSG UDPRplMsg, *ptr;


	udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
	setsockopt(udpSocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);
	/* 5 seconds timeout for udp traffic verification */
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	setsockopt(udpSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(udpSocket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	bzero(&serverAddr, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serverAddr.sin_port = htons(serverport);

	if(bind(udpSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr))){
		printf("bind error:%s\n",strerror(errno));
		return -1;
	}

	addr_size=sizeof(serverAddr);
	memset(qrybuffer,'\0',sizeof(qrybuffer));

	/* Waiting for the UDP package from client */
	nBytes = recvfrom(udpSocket,qrybuffer,sizeof(qrybuffer),0,(struct sockaddr *)&serverAddr, &addr_size);
	if(nBytes<0){
		printf("Recv UDP query package failed: %s, read:%d\n",strerror(errno),nBytes);
		return -1;
	}



	urllen=ntohs(((UDPQRYMSG*)qrybuffer)->urllen);
	memset(buffer,'\0',sizeof(buffer));
	memcpy(buffer,qrybuffer+14,urllen);
	/* create UDP replay package, TID=TID+1 */
	UDPRplMsg.dir='C';
	UDPRplMsg.TID=ntohl(((UDPQRYMSG*)qrybuffer)->TID)+1;
	UDPRplMsg.SID=ntohl(((UDPQRYMSG*)qrybuffer)->SID);

	printf("Receive UDP query: SID:%d, TID:%d, URL:%s\n",UDPRplMsg.SID,UDPRplMsg.TID-1,buffer);

	time_t t=time(0);
	UDPRplMsg.timestamp=(uint32_t)t;
	/* OK status = 0 */
	UDPRplMsg.status=0;

	mode=((UDPQRYMSG*)qrybuffer)->ver;
	/* set debug SID to 654321  */
	if(mode=='D'){
		UDPRplMsg.ver='D';
		UDPRplMsg.maclen=1;
		UDPRplMsg.SHAHash[0]='D';

		/* Wrong HASH, status NOTOK, set status 1 */
		if((*((char*)(qrybuffer+ntohs(((UDPQRYMSG*)qrybuffer)->len)+2)))!='D'){
			printf("Wrong HASH for Debug mode:%c\n",*(qrybuffer+((UDPQRYMSG*)qrybuffer)->len+2));
			UDPRplMsg.status=1;
		}
	} else if(mode=='1'){
		UDPRplMsg.ver='1';
		memcpy(UDPRplMsg.SHAHash,SHAHash,sizeof(SHAHash));
		UDPRplMsg.maclen=sizeof(SHAHash);

		/* generate local SHAHash of (TID+passwd) for HMAC-SHA256 */
		strncpy(buffer,passwd,strlen(passwd));
		memcpy(buffer+strlen(passwd),qrybuffer,ntohs(((UDPQRYMSG*)qrybuffer)->len));
		sha256(buffer,SHAHash);

		/* Wrong HASH, status NOTOK, set status 1 */
		if(strncmp(SHAHash,(qrybuffer+ntohs(((UDPQRYMSG*)qrybuffer)->len)+sizeof(uint16_t)),sizeof(SHAHash))){
			printf("Wrong HASH in UDP query package:%s\n",SHAHash);
			UDPRplMsg.status=1;
		}

		if(udptraffic==1){		
			/* generate local SHAHash of (TID+passwd) for UDP ACK check */
			strncpy(buffer,passwd,strlen(passwd));
			sprintf(buffer+strlen(passwd),"%d",UDPRplMsg.TID-1);
			sha256(buffer,SHAHash);

			/* send the UDP ACK back to client */
			printf("Send UDP-traffic verifying ACK package\n");
			if(sendtoTimeout(udpSocket,SHAHash,sizeof(SHAHash),0,(struct sockaddr *)&serverAddr,addr_size)){
				perror("Send UDPACK error\n");
				return -1;
			}
		}
	}else {
		/* Wrong version, status NOTOK, set status 1 */
		printf("Error: Wrong Version!\n");
		UDPRplMsg.status=1;
	}



	printf("Send UDP Reply packet --- SID:%d, TID:%d, Timestamp:%d, Status:%d\n",UDPRplMsg.SID,UDPRplMsg.TID,UDPRplMsg.timestamp,UDPRplMsg.status);

	UDPRplMsg.len=18;
	UDPRplMsg.len=htons(UDPRplMsg.len);
	UDPRplMsg.SID=htonl(UDPRplMsg.SID);
	UDPRplMsg.TID=htonl(UDPRplMsg.TID);
	UDPRplMsg.timestamp=htonl(UDPRplMsg.timestamp);
	UDPRplMsg.maclen=htonl(UDPRplMsg.maclen);


	if(udptraffic==1){
		/* send the UDPRPLMSG to client */
		if(SendTo(udpSocket,&UDPRplMsg,sizeof(UDPRplMsg),0,(struct sockaddr *)&serverAddr,addr_size, passwd, ntohl(UDPRplMsg.TID))){
			perror("Normal mode --- Send UDP package error\n");
			return -1;
		}
	}else{
		if(sendtoTimeout(udpSocket,&UDPRplMsg,sizeof(UDPRplMsg),0,(struct sockaddr *)&serverAddr,addr_size)){
			perror("Debug mode --- Send UDP package error\n");
			return -1;
		}

	}

}

int SendTo(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen, char* passwd, uint32_t TID)
{
	int n=3;
	char buffer[2000];
	char qrybuffer[2000];
	char rplbuffer[2000];
	char SHAHash[64];
	UDPRPLMSG UDPRplMsg;

	socklen_t addr_len=addrlen;

	/* generate local SHAHash of (TID+passwd) for UDPACK check */
	strncpy(buffer,passwd,strlen(passwd));
	sprintf(buffer+strlen(passwd),"%d",TID);
	sha256(buffer,SHAHash);

	while(1){
		if(sendtoTimeout(sockfd,buf,len,flags,dest_addr, addr_len)){
			return -1;
		}


		/* recv the UDPACK from server  */
		if(recvfromTimeout(sockfd,rplbuffer,sizeof(SHAHash),flags,dest_addr, &addr_len)){
			n--;
			if(n){
				/* Try re-send the UDP package 3 times if we didn't receive the ACK package due to timeout */
				continue;
			} else {
				/* Didn't receive the ACK package, give up */
				printf("EXIT: Re-sent 3 times\n");
				return -1;
			}
		}

		/* reveive the ACK success */
		break;
	}

	/* compare the local SHAHash with the SHAHash in UDPACK from server */
	if(strncmp(rplbuffer,SHAHash,sizeof(SHAHash))){
		perror("Wrong UDPACK!\n");
		return -1;
	}

	return 0;
}

int sendtoTimeout(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen)
{
	int nBytes=0;
	int n=3;
	while(1){
		nBytes = sendto(sockfd,buf,len,flags,dest_addr, addrlen);

		if (nBytes < 0) {
			if (errno == EWOULDBLOCK) {
				printf("5 sec timeout for sending UDP package: %d\n",n);
				n--;
				if(n){
					continue;
				} else {
					printf("Send UDP package timeout:%s\n",strerror(errno));
					return -1;

				}
			} else{
				printf("Send UDP package failed:%s\n",strerror(errno));
				return -1;
			}
		}
		return 0;
	}
}

int recvfromTimeout(int sockfd, void *buf, size_t len, int flags,
		struct sockaddr *src_addr, socklen_t *addrlen)
{
	int nBytes=0;

	/* structure UDPRPLMSG is aligned and fix length, so we can read the content directly from socket to a UDPRPLMSG structure */
	nBytes = recvfrom(sockfd,buf,len,flags,src_addr, addrlen);

	if (nBytes < 0) {
		if (errno == EWOULDBLOCK) {
			printf("5 sec timeout for receiving UDP package\n");
			return -1;
		} else{
			printf("Receive UDP package failed:%s\n",strerror(errno));
			return -1;
		}
	}
	return 0;
}



int readn(int socket, void* buffer, unsigned int n)
{
	int count=n;
	int rec=0;
	TCPMSG* TCPMsg=buffer;

	while (count>0)
	{
		rec = read(socket, buffer, count);
		if (rec < 0 )
		{
			if(errno==EINTR)
				continue;
			else
				return -1;
		}

		if(rec==0)
			return n-count;
		buffer+=rec;
		count-=rec;
	}
	return n;
}

int createTCPMsg(char *buffer, TCPMSG* TCPMsg)
{
	memcpy(buffer,&TCPMsg->MsgLen,2);
	memcpy(buffer+2,"DISTRIB2015",11);
	memcpy(buffer+13,&TCPMsg->mode,1);
}
