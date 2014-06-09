/*  
*
* FakeSkype : Skype reverse engineering proof-of-concept client
*
* Ouanilo MEDEGAN (c) 2006
* http://www.oklabs.net
*
* Feel free to modifiy, update or redistribute (Quotation appreciated ;))
*
*/

#include <windows.h>

#include "Common.h"
#include "LocalNode.h"

uchar	 NodeID[NODEID_SZ] = {0};
uint	 StartTime = 0;

void	 InitUpTime()
{
	StartTime = GetTickCount();
}

uint	 GetUpTime()
{
	return ((GetTickCount() - StartTime) / 1000);
}

void	 InitNodeId()
{
	*(__int64*)NodeID = BytesRandomI64();
	
	/*printf("NodeID : \n");
	showmem(NodeID, NODEID_SZ);
	printf("\n");*/

	//FIXED NODEID
	//memcpy_s(NodeID, NODEID_SZ, "\x49\x63\xff\xee\xe0\x5c\x9d\xf8", NODEID_SZ);
	memcpy_s(NodeID, NODEID_SZ, "\x97\xca\xb1\x72\x06\xf6\x72\xb4", NODEID_SZ);
}

uchar	 *GetNodeId()
{
	return (&NodeID[0]);
}

void	 InitListeningPort()
{
	//Listen On Port DEF_LPORT
}

uint	 GetListeningPort()
{
	return (DEF_LPORT);
}

void	 InitLocalNode()
{
	InitUpTime();
	InitNodeId();
	InitListeningPort();
}
