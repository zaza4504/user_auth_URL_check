/* YAO PENG 245151 */
/* ANIL BASLAMISLI 245167 */

struct TCPMSG {
	uint16_t	MsgLen;
	char		IdStr[11]; // "DISTRIB2015";
	char		mode;
	char*		cmd[128];
};

struct A0 {
	char		CmdStr[2]; // "A0";	
	uint8_t		NameLen;
	char		UserName[64];
};
struct A1 {
	char		CmdStr[2]; // "A1";	
	uint32_t	AUTH1;
};
struct A2 {
	char		CmdStr[2]; // "A2";	
	char		SHAHash[64];
};
struct A3 {
	char		CmdStr[2]; // "A3";	
	uint8_t		status;
	uint32_t	SID;
};


/* 
 * Max length is 2000 bytes and condering the alignment the max url is 1920 
 * As length of url is dynamic, we don't need this member
 * This structure is still aligned. It can be read directly from a buffer for first six members
 * */
struct UDPQRYMSG{
	char		ver; // 1
	char		dir; // 1
	uint16_t	len; // 2
	uint32_t	SID; // 4
	uint32_t	TID; // 4
	uint16_t	urllen; // 2
	//char		url[1920];
	uint16_t	maclen; // 2
	char		SHAHash[64]; // 64
};

/*
 * structure UDPRPLMSG is aligned and fix length
 * We can directly read it from a buffer
 * */
struct UDPRPLMSG{
	char		ver; // 1
	char		dir; // 1
	uint16_t	len; // 2
	uint32_t	SID; // 4
	uint32_t	TID; // 4
	uint32_t	timestamp; // 4
	char		nouse; // 1
	uint8_t		status; // 1
	uint16_t	maclen; // 2
	char		SHAHash[64]; // 64
};

struct UDPACK{
	char		SHAHash[64];  /* sha265 hash of (UDPQRYMSG.TID + passwd)  */
};

typedef struct TCPMSG TCPMSG;
typedef struct UDPQRYMSG UDPQRYMSG;
typedef struct UDPRPLMSG UDPRPLMSG;
typedef struct UDPACK UDPACK;
typedef	struct A0	A0;
typedef	struct A1	A1;
typedef	struct A2	A2;
typedef	struct A3	A3;


int sha256(char* string, char* hashresult);
