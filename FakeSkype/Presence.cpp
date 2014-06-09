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

#include "Presence.h"

uchar	DirBlob[0x148 + 0x48] = {0};

void	BuildLocationBlob(CLocation Location, uchar *Buffer)
{
	uchar *start = Buffer;

	*(unsigned int *)Buffer = *(unsigned int *)Location.NodeID;
	*(unsigned int *)(Buffer + 4) = *(unsigned int *)(Location.NodeID + 4);
	Buffer += NODEID_SZ;

	*Buffer++ = Location.bHasPU;

	// Assumption:
	// Maybe this is the index to where to start search and it's over when you either hit 00 address or end of routing info?
	if (Location.bHasPU)
	{
		// Local - Supernode - External IP
		*(unsigned int *)Buffer = inet_addr(Location.PVAddr.ip);
		Buffer += sizeof(unsigned int);
		*(unsigned short *)Buffer = htons(Location.PVAddr.port);
		Buffer += sizeof(unsigned short);

		*(unsigned int *)Buffer = inet_addr(Location.SNAddr.ip);
		Buffer += sizeof(unsigned int);
		*(unsigned short *)Buffer = htons(Location.SNAddr.port);
		Buffer += sizeof(unsigned short);

		if (Location.BlobSz > Buffer - start)
		{
			*(unsigned int *)Buffer = inet_addr(Location.PUAddr.ip);
			Buffer += sizeof(unsigned int);
			*(unsigned short *)Buffer = htons(Location.PUAddr.port);
			Buffer += sizeof(unsigned short);
		}
	}
	else
	{
		// Supernode - 0 - Local ??
		// But there also is: External - Supernode - Local??
		*(unsigned int *)Buffer = inet_addr(Location.SNAddr.ip);
		Buffer += sizeof(unsigned int);
		*(unsigned short *)Buffer = htons(Location.SNAddr.port);
		Buffer += sizeof(unsigned short);

		*(unsigned int *)Buffer = inet_addr(Location.PUAddr.ip);
		Buffer += sizeof(unsigned int);
		*(unsigned short *)Buffer = htons(Location.PUAddr.port);
		Buffer += sizeof(unsigned short);

		*(unsigned int *)Buffer = inet_addr(Location.PVAddr.ip);
		Buffer += sizeof(unsigned int);
		*(unsigned short *)Buffer = htons(Location.PVAddr.port);
		Buffer += sizeof(unsigned short);
	}
}

void	BuildSignedMetaData(uchar *Location, uchar *SignedMD)
{
	uchar			MetaData[0xFF] = {0};
	uchar			MD2Sign[0x80] = {0};
	uchar			*Browser, *Mark;
	uint			Idx, Size;
	ObjectDesc		ObjLocation;
	SHA_CTX			CredCtx, MDCtx;
	int				RSARes;

	RSARes = 0;
	Browser = MetaData;
	ZeroMemory(Browser, 0xFF);

	Mark = Browser;

	*Browser++ = RAW_PARAMS;
	WriteValue(&Browser, 0x01);

	ObjLocation.Family = OBJ_FAMILY_BLOB;
	ObjLocation.Id = OBJ_ID_CILOCATION;
	ObjLocation.Value.Memory.Memory = Location;
	ObjLocation.Value.Memory.MsZ = LOCATION_SZ;
	WriteObject(&Browser, ObjLocation);

	Size = (uint)(Browser - Mark);

	// MD2Sign:
	// [4BBBBBBBBB..BA][SIGNEDCREDENTIALS][METADATA][SIGNEDMETADATA]
	// Mark            ^(20 bytes) 
	// 
	//                                    [SIGNEDMETADATA]BC
	//                                   ^-v4
	//	                        [METADATA]
	//                         ^v5
	// 4B BBBBBBBBBBBBBBBBBB BA


	MD2Sign[0x00] = 0x4B;
	
	for (Idx = 1; Idx < (0x80 - (Size + (2 * SHA_DIGEST_LENGTH)) - 2); Idx++)
		MD2Sign[Idx] = 0xBB;
	MD2Sign[Idx++] = 0xBA;

	Mark = MD2Sign + Idx;
	SHA1_Init(&CredCtx);
	SHA1_Update(&CredCtx, GLoginD.SignedCredentials.Memory, GLoginD.SignedCredentials.MsZ);
	SHA1_Final(MD2Sign + Idx, &CredCtx);
	Idx += SHA_DIGEST_LENGTH;

	memcpy_s(MD2Sign + Idx, Size + SHA_DIGEST_LENGTH, MetaData, Size);
	Idx += Size;

	SHA1_Init(&MDCtx);
	SHA1_Update(&MDCtx, Mark, SHA_DIGEST_LENGTH + Size);
	SHA1_Final(MD2Sign + Idx, &MDCtx);
	Idx += SHA_DIGEST_LENGTH;
	
	MD2Sign[Idx] = 0xBC;

	RSARes = RSA_private_encrypt(sizeof(MD2Sign), MD2Sign, SignedMD, GLoginD.RSAKeys, RSA_NO_PADDING);
}

void	SendPresence(CLocation Local_Node, char *User)
{
	uchar			Request[0xFFF];
	ProbeHeader		*PHeader;
	ushort			TransID;
	uchar			*PRequest, *Mark;
	int				BaseSz;
	uint			PSize;
	ObjectDesc		ObjDirBlob;
	Host			CurSN;
	sockaddr_in		LocalBind;
	SOCKET			SNUDPSock;
	queue<SlotInfo>	Slot;
	queue<Host>		Hosts;
	uchar			Buffer[LOCATION_SZ] = {0};
	static int		Init = 0;

	SetConsoleTitle("FakeSkype - Broadcasting Presence..");

	if (Init == 0)
	{
		BuildLocationBlob(Local_Node, &Buffer[0]);
DumpLocation(&Local_Node);
		
		*(unsigned int *)DirBlob = htonl(0x000000C4 + 0x40);
		memcpy_s(DirBlob + 0x04, 0xC4 + 0x40, GLoginD.SignedCredentials.Memory, GLoginD.SignedCredentials.MsZ);
		BuildSignedMetaData(Buffer, &DirBlob[0xC8 + 0x40]);
		memcpy_s (&DirBlob[0xC8 + 0x40 + 0x80], 8, &Buffer[LOCATION_SZ-8], 8);
		Init = 1;
	}

	/* First notify the supernode about our presence */
	PRequest = Request;
	TransID = BytesRandomWord();
	BaseSz = 0x150 + 0x44 + 2;
	WriteValue(&PRequest, BaseSz);
	WriteValue(&PRequest, 0x1E1);

	*PRequest++ = RAW_PARAMS;
	WriteValue(&PRequest, 0x01);		
	ObjDirBlob.Family = OBJ_FAMILY_BLOB;
	ObjDirBlob.Id = OBJ_ID_DIRBLOB;
	ObjDirBlob.Value.Memory.Memory = DirBlob;
	ObjDirBlob.Value.Memory.MsZ = 0x148 + 0x48;
	WriteObject(&PRequest, ObjDirBlob);

	SendAnnounce(TransID, Local_Node.SNAddr.socket, Local_Node.SNAddr, (BaseSz+6)*2, &Local_Node.SNAddr.Connected, &Keys);
	CipherTCP(&(Keys.SendStream), Request, 3);
	CipherTCP(&(Keys.SendStream), Request + 3, (uint)(PRequest - Request) - 3);
	if (SendPacketTCP(Local_Node.SNAddr.socket, Local_Node.SNAddr, Request, (uint)(PRequest - Request), HTTPS_PORT, &(Local_Node.SNAddr.Connected)))
	{
	showmem(RecvBuffer, RecvBufferSz);
		CipherTCP(&(Keys.RecvStream), RecvBuffer, RecvBufferSz);
		
		printf("Ack Received..\n");
	showmem(RecvBuffer, RecvBufferSz);
	printf("\n\n");
	}


	/* Then send our location blob to the list of supernodes */
	SNUDPSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	ZeroMemory((char *)&LocalBind, sizeof(LocalBind));
	LocalBind.sin_family = AF_INET;
	LocalBind.sin_addr.s_addr = htonl(INADDR_ANY);
	LocalBind.sin_port = htons(DEF_LPORT);
	bind(SNUDPSock, (struct sockaddr *)&LocalBind, sizeof(LocalBind));

	RequestSlotInfos(Local_Node.SNAddr, &Slot, 0x12, GetAssociatedSlotID(User));
	if (Slot.size() == 0)
	{
		RequestSlotInfos(Local_Node.SNAddr, &Slot, 0x12, GetAssociatedSlotID(User));
		if (Slot.size() == 0)
		{
			printf("Unable to get Slot Info.. Aborting..\n");
			ExitProcess(0);
		}
	}

	Hosts = *(Slot.front().SNodes);
	
	while (!(Hosts.empty()))
	{
		CurSN = Hosts.front();
		BaseSz = 0x150 + 0x48 + 3 /* 3=bytes of Object 0x1F, remove if not neded */;

		ZeroMemory(Request, 0xFFF);

		TransID = BytesRandomWord();
		PHeader = (ProbeHeader *)Request;
		PHeader->TransID = htons(TransID+1);
		PHeader->PacketType = PKT_TYPE_OBFSUK;
		PHeader->IV = htonl(GenIV());

		PRequest = Request + sizeof(*PHeader);
		Mark = PRequest;

		WriteValue(&PRequest, BaseSz);			
		WriteValue(&PRequest, 0x62);
		*((short*)PRequest) = htons(TransID);
		PRequest+=sizeof(short);

		*PRequest++ = RAW_PARAMS;
		WriteValue(&PRequest, 0x02);		/* 2 Objects, reduce to 1 if 0x1F not needed */

		/* Don't know if this is needed, fuond it in most transactions... */
		ObjectDesc Obj={0};
		Obj.Family = OBJ_FAMILY_NBR;
		Obj.Id = 0x1F;
		Obj.Value.Nbr = 0x01;
		WriteObject(&PRequest, Obj);

		ObjDirBlob.Family = OBJ_FAMILY_BLOB;
		ObjDirBlob.Id = OBJ_ID_DIRBLOB;
		ObjDirBlob.Value.Memory.Memory = DirBlob;
		ObjDirBlob.Value.Memory.MsZ = 0x148 + 0x48;
		WriteObject(&PRequest, ObjDirBlob);

		PSize = (uint)(PRequest - Mark);

		PHeader->Crc32 = htonl(crc32(Mark, PSize, -1));

//printf ("Sending Presence to %s:%d\n", CurSN.ip, CurSN.port);
//showmem(Request, sizeof(ProbeHeader) + PSize);

		Cipher(Mark, PSize, htonl(my_public_ip), htonl(inet_addr(CurSN.ip)), htons(PHeader->TransID), htonl(PHeader->IV), 0);

		if (SendPacket(SNUDPSock, CurSN, Request, sizeof(ProbeHeader) + PSize))
		{
			struct in_addr	PublicIP;

			PublicIP.S_un.S_addr = my_public_ip;
			if (UnCipherObfuscated(RecvBuffer, RecvBufferSz, inet_ntoa(PublicIP), CurSN.ip) == 0)
			{
				printf("Unable to uncipher Packet..\n");
				goto Skip;
			}
			printf("Ack Received..\n");
//showmem(RecvBuffer, RecvBufferSz);
//printf("\n\n");
		}
		else
		{
			printf("No Response to DirBlob BroadCast..\n");
			goto Skip;
		}
Skip:
		Hosts.pop();
	}
	printf("\n");
}
