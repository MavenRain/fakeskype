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

#include "Common.h"

//Host		Session_SN;
CLocation Session_Node;

static void DumpBuffer(unsigned char *buffer, unsigned char *pBuf)
{
	SResponse Response={0};
	unsigned int Idx;
	unsigned char *pStart = buffer;

	while (pStart < pBuf)
	{
		ZeroMemory (&Response, sizeof(Response));
		ManageObjects(&pStart, pBuf-pStart, &Response);
		if (Response.NbObj)
		{
			printf ("\n");
			for (Idx = 0; Idx < Response.NbObj; Idx++)
			{
				DumpObj(Response.Objs[Idx]);

				if (Response.Objs[Idx].Family == OBJ_FAMILY_BLOB)
				{
					SResponse	BlobR;
					uchar		*Blob;
					int IdxSub;

					Blob = Response.Objs[Idx].Value.Memory.Memory;
					ZeroMemory(&BlobR, sizeof(BlobR));
					ManageObjects(&Blob, Response.Objs[Idx].Value.Memory.MsZ, &BlobR);
					for (IdxSub = 0; IdxSub < BlobR.NbObj; IdxSub++)
					{
						DumpObj(BlobR.Objs[IdxSub]);
					}
				}
			}
			printf ("-------------------------------------------------------------------------------\n");
		} else printf ("%02X ", *(pStart-1));
		// FIXME: free the objects
	}
	printf ("\n");
}

void DumpSkypeTraffic(char *pszFile)
{
	FILE *fp = fopen(pszFile, "rb");
	char szLine[128], szLineBak[128], *pTok, *p;
	unsigned char buffer[32768],*pBuf, *pOldBuf;

	pBuf = buffer;
	while (fgets(szLine, sizeof(szLine), fp))
	{
		pOldBuf = pBuf;
		strcpy (szLineBak, szLine);
		for (pTok=strtok(szLine, " "); pTok; pTok=strtok(NULL, " "))
		{
			if (*pTok=='|') pTok++;
			for (p=pTok+(strlen(pTok)-1); p>pTok && (*p==10 || *p==13 ||*p=='|'); p--) *p=0;
			if (*pTok==10 || *pTok==13 || strlen(pTok)!=2) continue;
			sscanf (pTok, "%02X", pBuf);
			pBuf++;
		}
		if (pBuf == pOldBuf)
		{
			DumpBuffer (buffer, pBuf);
			printf (szLineBak);
			pBuf = buffer;
		}
	}
	DumpBuffer (buffer, pBuf);
 	fclose(fp);
}

int			main(int argc, char* argv[])
{
	WORD	wVersionRequested;
	WSADATA wsaData;
	int		err, account;
	char	*User, *Pass;

	BYTE TestBuf[32]={0}, *PRequest=TestBuf;
	short sVal;

	//WriteValue(&PRequest, 0x148 + 0x48);
	//WriteValue(&PRequest, 0x14E + 0x46 + 0x4D);
	//WriteValue(&PRequest, (0x190+0x2) *2);
	//WriteValue(&PRequest, 0x1E1);

	//TestBuf[0]=0x96;
	//TestBuf[1]=0x03;
	//ReadValue(&PRequest, &sVal);

	//DumpSkypeTraffic ("F:\\Skype.Reverse.Engineered\\traffic.txt");
	//return 0;

	account = 0;

	if (account == 0)
	{
		User = "ojaXXXX"; 
		Pass = "canXXXX";
	}
	else if (account == 1)
	{
		User = "mysXXX"; 
		Pass = "epiXXX";
	}
	else if (account == 2)
	{
		User = "chiXXX"; 
		Pass = "canXXX";
	}
	else if (account == 3)
	{
		User = "couXXX";
		Pass = "iboXXX";
	};

	User = "XXXXXXXX";
	Pass = "XXXXXXXX";


	wVersionRequested = MAKEWORD(2, 2);
	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0)
	{
		printf("Unable to start WSA Lib\n");
		return (0xBADF00D);
	}

	//FIXED NODEID

	InitLocalNode();

	HostScan(&Session_Node);

	//TestInitialPing(Session_Node);
	//return 0;

	PerformLogin(User, Pass);	

	SendPresence(Session_Node, User);

	EventContacts(User, Pass);	
	
	SearchContactList(Session_Node.SNAddr, User);

	InitialPingOnLine(Session_Node, User);

	Listen2SN(Session_Node.SNAddr);

	WSACleanup();

	return 0;
}
