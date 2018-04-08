#include <signal.h>
#include <unistd.h>
#include <stdlib.h>

#define MAX_RUNTIME 60*60  /* one hour in seconds */

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#include <inttypes.h> /* uint16_t */

#include <openssl/sha.h>
#include <getopt.h>
#include "./userauthurlcheck.h"

int createTCPMsg(char *buffer, TCPMSG* TCPMsg);
int readn(int socket, void* buffer, unsigned int n);
int ProcessUDP(char* server, int serverport, char mode, uint32_t SID, char* url, char* passwd, int udptraffic);

	static void
watchdog(int signro)
{
	exit(signro);  /* process will exit when the timer signal arrives */
}

int main(int argc, char *argv[])
{
	if( signal(SIGALRM, watchdog) == SIG_ERR ) {
		exit(2); /* something went wrong in setting signal */
	}

	alarm( MAX_RUNTIME );  /* after this time the program will always exit */


	int 	sockfd = 0;
	char 	recvBuffer[2000];
	char 	sendBuffer[2000];
	char	buffer[20];
	char 	H1[64];
	struct 	sockaddr_in serv_addr;
	char* 	passwdbuffer;
	void* 	Msg;
	int 	error;
	char 	server[60];
	struct 	hostent* serverhost;
	int 	serverport;
	char	user[64]; 
	char	pwd[20];
	char	url[1920]; /* URL request, The Max of UDP package is 2000, url length cannot exceed 1920 */	
	char	mode;  /* debuge mode D or normal mode 1 */
	int	auth=0;  /* extra functionality */
	int	arg1=0;
	int	arg2=0;
	int 	udptraffic=0;
	uint32_t	DebugSID=1000;
	uint16_t	n=0;

	TCPMSG	TCPMsg;
	UDPQRYMSG UDPQryMsg;
	UDPRPLMSG UDPRplMsg;
	A0	a0; 
	A1	a1; 
	A2	a2; 
	A3	a3;

	/* process cmd line */
	int c;

	while (1){
		static struct option long_options[] =
		{
			{"server",     required_argument,       0, 'N'},
			{"port",  required_argument,       0, 'T'},
			{"user",  required_argument, 0, 'U'},
			{"pwd",  required_argument, 0, 'P'},
			{"query",    required_argument, 0, 'q'},
			{"debug",    no_argument, 0, 'd'},
			{"normal",    no_argument, 0, 'n'},
			{"udptraffic",    no_argument, 0, 't'},
			{0, 0, 0, 0}
		};

		/* getopt_long stores the option index here. */
		int option_index = 0;
		/* parse command line*/
		c = getopt_long (argc, argv, "N:T:U:P:q:dnt",
				long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c){

			case 'N':
				arg1++;
				if(strlen(optarg)>sizeof(server)){
					perror("Cannot handle such server name/IP\n");
					return 1;
				}
				memcpy(server,optarg,strlen(optarg)); /* get server address */
				break;

			case 'T':
				arg1++;
				serverport=atoi(optarg);	/* get server port */
				sprintf(buffer,"%d",serverport);
				if(strncmp(buffer,optarg,strlen(optarg))){
					printf("Invalid server prot:%s\n",optarg);
					return -1;
				}
				break;

			case 'U':
				arg1++;
				if(strlen(optarg)>sizeof(user)){
					return 1;
				}
				memcpy(user,optarg,strlen(optarg));	/* get username */
				break;

			case 'P':
				arg1++;
				if(strlen(optarg)>sizeof(pwd)){
					perror("Passwd is less than 20\n");
					return 1;
				}
				memcpy(pwd,optarg,strlen(optarg));	/* get password */
				break;

			case 'q':
				arg1++;
				if(strlen(optarg)>sizeof(url)){
					perror("URL qury url is less than 200\n");
					return 1;
				}
				memcpy(url,optarg,strlen(optarg));	/* get url */
				break;

			case 'd':
				arg2++;
				mode='D';	/* debug mode */
				break;

			case 'n':
				arg2++;
				mode='1';	/* normal mode */
				break;

			case 't':
				udptraffic=1;
				break;

			case '?':
				/* getopt_long already printed an error message. */
				break;

			default:
				abort ();	/* wrong command line request */
		}
	}
	/* check if the command line usage is correct */
	if(arg1!=5 || arg2!=1){
		perror("Usage: client -N <serverIP> -T <port> -U <user> -P <passwd> -q <QueryURL> -d/n -t\n ");
		return 1;
	}

	/* create socket */
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		printf("\n Error : Could not create socket \n");
		return 1;
	} 

	memset(&serv_addr, '0', sizeof(serv_addr)); /* initialize server address */

	serv_addr.sin_family = AF_INET;	 /* AF_INET */ 
	serv_addr.sin_port = htons(serverport); /* server port */

	/* conver hostname to ip address */
	if(server[0]>'9'||server[0]<'0'){
		struct addrinfo hints, *serverinfo;
		struct sockaddr_in *h;
		int error;

		memset(&hints, 0, sizeof hints);
		hints.ai_family = AF_INET; // use AF_INET6 to force IPv6
		hints.ai_socktype = SOCK_STREAM;

		error = getaddrinfo(server, NULL, &hints, &serverinfo);
		if (error) {
			errx(1, "%s", gai_strerror(error));
			return 1;
		}
		h=(struct sockaddr_in *) serverinfo->ai_addr;
		memcpy(server,inet_ntoa(h->sin_addr),strlen(inet_ntoa(h->sin_addr)));
	} 

	/*check validity of ip address */
	if(inet_pton(AF_INET, server, &serv_addr.sin_addr)<=0) {
		printf("Invalid IP address\n");
		close(sockfd);
		return 1;
	}

	/* create connection to server*/
	if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))){
		printf("%s\n",strerror(errno));
		close(sockfd);
		return 1;
	}

	/* create A0 message head */
	TCPMsg.MsgLen=htons(14+3+strlen(user));
	TCPMsg.mode=mode;
	createTCPMsg(sendBuffer,&TCPMsg);
	TCPMsg.MsgLen=ntohs(TCPMsg.MsgLen);

	/* create A0 cmd */
	memcpy(sendBuffer+14,"A0",2);
	a0.NameLen=htons(strlen(user));
	memcpy(sendBuffer+16,&a0.NameLen,1);
	memcpy(sendBuffer+17,user,strlen(user));

	/* send the A0 message to server */
	if((write(sockfd,sendBuffer,TCPMsg.MsgLen))==-1) {
		printf("Error : Cannot Send TCP message\n");
		close(sockfd);
		return 1;	
	}

	/* read A1 message from server  */
	if(readn(sockfd,recvBuffer,2)!=2){
		perror("Cannot read TCPMsg head\n");
		return 1;
	}
	/* read the cmd part */
	n=ntohs((*((uint16_t*)recvBuffer)))-2;
	if(readn(sockfd,recvBuffer+2,n)!=n){
		perror("Cannot read cmd\n");
		return 1;
	}

	/* Passwd + AUTH1 (Radom number from server) */
	sprintf(H1,"%s",pwd);
	sprintf(H1+strlen(pwd),"%d",ntohl(*((uint32_t*)(recvBuffer+16))));

	/* calculate the SHA HASH (passwd + AUTH1) */
	if(mode=='D'){
		memset(a2.SHAHash,'f',64);
	}else{
		sha256(H1,a2.SHAHash);
	}
	/* create A2 message */
	TCPMsg.MsgLen=htons(80);
	createTCPMsg(sendBuffer,&TCPMsg);
	TCPMsg.MsgLen=ntohs(TCPMsg.MsgLen);
	memcpy(sendBuffer+14,"A2",2);
	memcpy(sendBuffer+16,a2.SHAHash,64);

	/* send A2 message to server */
	if(write(sockfd,&sendBuffer,TCPMsg.MsgLen)<0) {
		printf("Error : Cannot Send A2 TCP message\n");
		close(sockfd);
		return 1;	
	}

	/* read A3 message from server */
	if(readn(sockfd,recvBuffer,2)!=2){
		perror("Cannot read TCPMsg head\n");
		return 1;
	}
	/* read cmd part */
	n=ntohs((*((uint16_t*)recvBuffer)))-2;  
	if(readn(sockfd,recvBuffer+2,n)!=n){
		perror("Cannot read cmd\n");
		return 1;
	}

	/* check the status byte, if it is , the user is authenticated */
	if(mode=='D'){
		ProcessUDP(server,serverport,mode,ntohl(*((uint32_t*)(recvBuffer+17))),url,pwd, udptraffic);//SERVER PORT
	}else{
		if(*((uint8_t*)(recvBuffer+16))==0){
			/* Success Authenticated  */
			ProcessUDP(server,serverport,mode,ntohl(*((uint32_t*)(recvBuffer+17))),url,pwd, udptraffic);//SERVER PORT
		} else {
			printf("you are not authenticated... Connection close\n");
			return 1;
		}
	}

	return 0;
}

/* calculates ssh hash */
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


/* handles udp messages */
int ProcessUDP(char* server, int serverport, char mode, uint32_t SID, char* url, char* passwd, int udptraffic)
{
	int udpSocket, nBytes;
	char buffer[2000];
	char qrybuffer[2000];
	char rplbuffer[2000];
	char SHAHash[64];
	struct sockaddr_in serverAddr, clientAddr;
	socklen_t addr_size;
	int n=3; /* number of retry for udp traffic verification */
	uint16_t maclen;
	struct timeval tv; /* timeout variable for udp traffic verification */

	UDPRPLMSG UDPRplMsg;
	UDPQRYMSG UDPQryMsg, *p;

	memset(qrybuffer,'\0',sizeof(qrybuffer));	/* initialize query buffer */

	bzero(&serverAddr, sizeof(serverAddr));	/* initialize server address */
	serverAddr.sin_family = AF_INET;	/* AF_INET */
	serverAddr.sin_port = htons(serverport);	/* serverport */
	inet_pton(AF_INET, server, &serverAddr.sin_addr);
	udpSocket= socket(AF_INET, SOCK_DGRAM, 0);	/* udp socket */

	UDPQryMsg.dir='S';	/* message will be sent to server */
	UDPQryMsg.urllen=htons(strlen(url));
	UDPQryMsg.len=14+strlen(url);
	UDPQryMsg.len=htons(UDPQryMsg.len);

	/* structure UDPQRYMG is aligned. It can be read/write directly from/to a buffer for first six members */
	if(mode=='D'){	/* debug mode */
		printf("Debug mode SID:%d\n",SID);
		UDPQryMsg.ver='D';	/* debug */
		UDPQryMsg.SID=htonl(SID);	/* session id for debug mode */
		UDPQryMsg.TID=100000;	/* transaction id for debug mode */
		printf("Debug mode TID:%d\n",UDPQryMsg.TID);
		UDPQryMsg.TID=htonl(UDPQryMsg.TID);
		maclen=1;
		maclen=htons(maclen);		
		memcpy(qrybuffer,&UDPQryMsg,sizeof(UDPQryMsg));
		memcpy(qrybuffer+14,url,strlen(url));	/* copy the url to qrybuffer */
		memcpy(qrybuffer+14+strlen(url),&maclen,sizeof(maclen));	/* copy the maclen to qrybuffer */
		SHAHash[0]='D';	/* hash value for debug mode */
		memcpy(qrybuffer+14+strlen(url)+sizeof(maclen),SHAHash,1);
	}else{	/* normal mode */
		UDPQryMsg.ver='1';	/* normal mode */
		UDPQryMsg.SID=htonl(SID);
		UDPQryMsg.TID=htonl(rand());	/* random transaction id */
		maclen=htons(sizeof(SHAHash));
		memcpy(qrybuffer,&UDPQryMsg,sizeof(UDPQryMsg));
		memcpy(qrybuffer+14,url,strlen(url));	/* copy the url to qrybuffer */
		memcpy(qrybuffer+14+strlen(url),&maclen,sizeof(maclen));	/* copy the maclen to qrybuffer */
		memset(buffer,'\0',sizeof(buffer));	/* initialize buffer for sha hash calculation */
		memcpy(buffer,passwd,strlen(passwd));
		memcpy(buffer+strlen(passwd),qrybuffer,ntohs(((UDPQRYMSG*)qrybuffer)->len));
		sha256(buffer,SHAHash);	/* calculate sha hash value */
		memcpy(qrybuffer+14+strlen(url)+sizeof(maclen),SHAHash,sizeof(SHAHash));
	}

	addr_size=sizeof(serverAddr);	/* server address size */

	/* 5 seconds timeout for udp traffic verification */
	tv.tv_sec = 5;
	tv.tv_usec = 0;
	setsockopt(udpSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	setsockopt(udpSocket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));


	if(mode!='D'&&udptraffic==1){
		/* send udp package to server with UDP traffic verified */
		if(SendTo(udpSocket,qrybuffer,ntohs(UDPQryMsg.len)+2+ntohs(maclen),0,(struct sockaddr *)&serverAddr, addr_size, passwd,ntohl(UDPQryMsg.TID))){
			perror("SendTo Error\n");
			return -1;
		}
		/* Receive reply UDP package from server after sending the UDP packge */
		if(recvfromTimeout(udpSocket,&UDPRplMsg,sizeof(UDPRplMsg),0,(struct sockaddr *)&serverAddr, &addr_size)){
			return -1;
		}
		/* generate local SHAHash of (TID+passwd) for UDPACK check for udp traffic verification*/
		strncpy(buffer,passwd,strlen(passwd));
		sprintf(buffer+strlen(passwd),"%d",ntohl(UDPRplMsg.TID));
		sha256(buffer,SHAHash);

		/* send UDPACK package */
		if(sendtoTimeout(udpSocket,SHAHash,sizeof(SHAHash),0,(struct sockaddr *)&serverAddr, addr_size)){
			perror("2 send ACK Error\n");
			return -1;
		}
	}else{
		/* NO UDP traffic verified  */
		if(sendtoTimeout(udpSocket,qrybuffer,ntohs(UDPQryMsg.len)+2+ntohs(maclen),0,(struct sockaddr *)&serverAddr, addr_size)){
			//if(sendtoTimeout(udpSocket,qrybuffer,sizeof(qrybuffer),0,(struct sockaddr *)&serverAddr, addr_size)){
			perror("1 SendTo Error\n");
			return -1;
		}
		if(recvfromTimeout(udpSocket,&UDPRplMsg,sizeof(UDPRplMsg),0,(struct sockaddr *)&serverAddr, &addr_size)){
			return -1;
		}

		}

		/* OUTPUT OF THE PROGRAM */
		/*	Server will respond to the query and the client will print out the query results (time and OK/NOTOK) to the user. 0 means OK | 1 means NOTOK*/
		printf("Receive UDP --- TID:%d, Timestamp: %d, Status:%s, Status Value: 0x%x\n",ntohl(UDPRplMsg.TID),ntohl(UDPRplMsg.timestamp),UDPRplMsg.status==0?"OK":"NOTOK", UDPRplMsg.status);

		close(udpSocket);
		return 0;
	}

	/* send udp package to server */
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

		/* generate local SHAHash of (TID+passwd) for UDPACK check for udp traffic verification*/
		strncpy(buffer,passwd,strlen(passwd));
		sprintf(buffer+strlen(passwd),"%d",TID);
		sha256(buffer,SHAHash);

		/* try to send udp package 3 times */
		while(1){
			if(sendtoTimeout(sockfd,buf,len,flags,dest_addr, addr_len)){
				printf("Send failed\n");
				return -1;
			}
			printf("Wait for UDP-traffic verifying ACK ....\n");
			/* recv the UDPACK from server  */
			if(recvfromTimeout(sockfd,rplbuffer,sizeof(SHAHash),flags,dest_addr, &addr_len)){
				n--;
				if(n){
					continue;
				} 
				else {
					printf("EXIT: Re-sent 3 times\n");
					return -1;
				}
			}

			break;
		}

		/* compare the local SHAHash with the SHAHash in UDPACK from server for correct udp traffic verification*/
		if(strncmp(rplbuffer,SHAHash,sizeof(SHAHash))){
			perror("Wrong UDPACK!\n");
			return 1;
		}

		return 0;
	}

	/* send udp package with timeout */
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
				}
				else{
					printf("Send UDP package failed:%s\n",strerror(errno));
					return -1;
				}
			}
			return 0;
		}
	}

	/* reviece udp package with timeout */
	int recvfromTimeout(int sockfd, void *buf, size_t len, int flags,
			struct sockaddr *src_addr, socklen_t *addrlen)
	{	
		int nBytes=0;

		nBytes = recvfrom(sockfd,buf,len,flags,src_addr, addrlen);

		if (nBytes < 0) {
			if (errno == EWOULDBLOCK) {
				printf("5 sec timeout for receiving UDP package\n");
				return -1;
			} 
			else{
				printf("Receive UDP package failed:%s\n",strerror(errno));
				return -1;
			}
		}

		return 0;
	}

	/* partial read function taken from lecture slides*/
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

	/* create tcp message header */
	int createTCPMsg(char *buffer, TCPMSG* TCPMsg)
	{
		memcpy(buffer,&TCPMsg->MsgLen,2);
		memcpy(buffer+2,"DISTRIB2015",11);
		memcpy(buffer+13,&TCPMsg->mode,1);
	}

