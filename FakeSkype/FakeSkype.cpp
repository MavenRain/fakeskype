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

Host		Session_SN;

void DumpSkypeTraffic(char *pszFile)
{
	FILE *fp = fopen(pszFile, "rb");
	char szLine[128], *pTok;
	unsigned char buffer[32768],*pBuf = buffer, *pStart = buffer;
	SResponse Response={0};
	unsigned int Idx;

	while (fgets(szLine, sizeof(szLine), fp))
	{
		for (pTok=strtok(szLine, " "); pTok; pTok=strtok(NULL, " "))
		{
			if (*pTok==10 || *pTok==13 || strlen(pTok)!=2) continue;
			sscanf (pTok, "%02X", pBuf);
			pBuf++;
		}
	}
	while (pStart < pBuf)
	{
		ZeroMemory (&Response, sizeof(Response));
		ManageObjects(&pStart, pBuf-pStart, &Response);
		for (Idx = 0; Idx < Response.NbObj; Idx++)
			DumpObj(Response.Objs[Idx]);
		printf ("-------------------------------------------------------------------------------\n");
		// FIXME: free the objects
	}
 	fclose(fp);
}

int			main(int argc, char* argv[])
{
	WORD	wVersionRequested;
	WSADATA wsaData;
	int		err, account;
	char	*User, *Pass;

	//DumpSkypeTraffic ("F:\\Skype.Reverse.Engineered\\traffic.txt");
	//return 0;

	account = 0;

	if (account == 0)
	{
		User = "oj.med"; 
		Pass = "canastas";
	}
	else if (account == 1)
	{
		User = "mysegfault"; 
		Pass = "epitech";
	}
	else if (account == 2)
	{
		User = "chien.lunatic"; 
		Pass = "canastas";
	}
	else if (account == 3)
	{
		User = "courausarah1";
		Pass = "ibounanta";
	}
	else if (account == 4)
	{
		User = "james.de.meza"; 
		Pass = "cognac48";
	}
	else if (account == 5)
	{
		User = "phet78"; 
		Pass = "phet1461";
	}
	else if (account == 6)
	{
		User = "anne.fleur1984"; 
		Pass = "petipengouin";
	}
	else if (account == 7)
	{
		User = "oj.med.perm"; 
		Pass = "canastas";
	}
	else if (account == 8)
	{
		User = "oj.prez"; 
		Pass = "canastas";
	}
	else if (account == 9)
	{
		User = "oj.one"; 
		Pass = "canastas";
	}
	else if (account == 10)
	{
		User = "oj.two"; 
		Pass = "canastas";
	}

	wVersionRequested = MAKEWORD(2, 2);
	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0)
	{
		printf("Unable to start WSA Lib\n");
		return (0xBADF00D);
	}

	//FIXED NODEID

	InitLocalNode();

	InitKeyServer();

	HostScan(&Session_SN);

	PerformLogin(User, Pass);	

	SendPresence(Session_SN, User);

	EventContacts(User, Pass);	
	
	SearchContactList(Session_SN, User);

	InitialPingOnLine(Session_SN, User);

	Listen2SN(Session_SN);

	EndKeyServer();	

	WSACleanup();

	return 0;
}
