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

#include "SearchContacts.h"

int	SearchContact(Host Session_SN, char *User, Contact *ContactSH, char *User2Search, queue<Host> Hosts)
{
	uchar			Request[0xFFF];
	uchar			UnRSA[0xFFF];
	uchar			RsaKey[MODULUS_SZ] = {0};
	ProbeHeader		*PHeader;
	ushort			TransID;
	uchar			*PRequest, *Mark;
	int				BaseSz;
	uint			PSize;
	ObjectDesc		ObjNbr, ObjUser, ObjMiscDatas;
	Host			CurSN;
	RSA				*SkypeRSA;
	int				Found = 0;
	sockaddr_in		LocalBind;
	SOCKET			SNUDPSock;
	uint CiIdx = 0;
	uint LdIdx = 0;
	uint Idx = 0;

	
	SNUDPSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	ZeroMemory((char *)&LocalBind, sizeof(LocalBind));
	LocalBind.sin_family = AF_INET;
	LocalBind.sin_addr.s_addr = htonl(INADDR_ANY);
	LocalBind.sin_port = htons(DEF_LPORT);
	bind(SNUDPSock, (struct sockaddr *)&LocalBind, sizeof(LocalBind));

	if (Hosts.size() == 0)
	{
		printf("Unable to get Confirmed SuperNode.. Aborting..\n");
		return (0);
	}

	while (!(Hosts.empty()))
	{
		CurSN = Hosts.front();
		BaseSz = 0x16 + (int)strlen(User2Search);

		ZeroMemory(Request, 0xFFF);

		TransID = BytesRandomWord();
		PHeader = (ProbeHeader *)Request;
		PHeader->TransID = htons(TransID);
		PHeader->PacketType = PKT_TYPE_OBFSUK;
		PHeader->IV = htonl(GenIV());

		PRequest = Request + sizeof(*PHeader);
		Mark = PRequest;

		WriteValue(&PRequest, BaseSz);
		WriteValue(&PRequest, 0x72);
		*(unsigned short *)PRequest = htons(TransID - 1);
		PRequest += 2;

		*PRequest++ = RAW_PARAMS;
		WriteValue(&PRequest, 0x02);

		*PRequest++ = 0x05;
		WriteValue(&PRequest, 0x00);

		*PRequest++ = RAW_PARAMS;
		WriteValue(&PRequest, 0x03);

		ObjNbr.Family = OBJ_FAMILY_NBR;
		ObjNbr.Id = 0x02;
		ObjNbr.Value.Nbr = 0x10;
		WriteObject(&PRequest, ObjNbr);

		ObjNbr.Family = OBJ_FAMILY_NBR;
		ObjNbr.Id = 0x01;
		ObjNbr.Value.Nbr = 0x00;
		WriteObject(&PRequest, ObjNbr);

		ObjUser.Family = OBJ_FAMILY_STRING;
		ObjUser.Id = OBJ_ID_USER2SEARCH;
		ObjUser.Value.Memory.Memory = (uchar *)User2Search;
		ObjUser.Value.Memory.MsZ = (int)strlen(User2Search);
		WriteObject(&PRequest, ObjUser);

		uint	MiscDatas[] = {0x10, 0x0B};
		ObjMiscDatas.Family = OBJ_FAMILY_INTLIST;
		ObjMiscDatas.Id = 0x01;
		ObjMiscDatas.Value.Memory.Memory = (uchar *)(&MiscDatas[0]);
		ObjMiscDatas.Value.Memory.MsZ = 0x02;
		WriteObject(&PRequest, ObjMiscDatas);

		PSize = (uint)(PRequest - Mark);

		PHeader->Crc32 = htonl(crc32(Mark, PSize, -1));

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
			//showmem(RecvBuffer, RecvBufferSz);
			//printf("\n\n");
		}
		else
		{
			printf("No Response to contact search..\n");
			goto Skip;
		}

		uchar		*Browser;
		SResponse	Response;
		
		Browser = RecvBuffer;

		Response.Objs = NULL;
		Response.NbObj = 0;
		UDPResponseManager(&Browser, (uint *)&RecvBufferSz, &Response);

		for (Idx = 0; Idx < Response.NbObj; Idx++)
		{
			switch (Response.Objs[Idx].Id)
			{
			case OBJ_ID_DIRBLOB:
				uchar	*PostProcessed;
				char	*Key;
				uint	PPsZ, KeyIdx, Save;

				/*memcpy_s(Response.Objs[Idx].Value.Memory.Memory, Response.Objs[Idx].Value.Memory.MsZ, data, sizeof(data));
				Response.Objs[Idx].Value.Memory.MsZ = sizeof(data);*/

 				PPsZ = htonl(*(uint *)Response.Objs[Idx].Value.Memory.Memory) - 4;
				KeyIdx = htonl(*(uint *)(Response.Objs[Idx].Value.Memory.Memory + 4));
				Response.Objs[Idx].Value.Memory.Memory += 8;
				Response.Objs[Idx].Value.Memory.MsZ -= 8;
				
				SkypeRSA = RSA_new();
				Key = KeySelect(KeyIdx);
				BN_hex2bn(&(SkypeRSA->n), Key);
				BN_hex2bn(&(SkypeRSA->e), "10001");
				Response.Objs[Idx].Value.Memory.MsZ -= PPsZ;
				Save = PPsZ;
				ZeroMemory(UnRSA, 0xFFF);
				PPsZ = RSA_public_decrypt(PPsZ, Response.Objs[Idx].Value.Memory.Memory, UnRSA, SkypeRSA, RSA_NO_PADDING);
				RSA_free(SkypeRSA);
				
				int	Suite;
				
				Suite = Save - PPsZ;
				Response.Objs[Idx].Value.Memory.Memory += PPsZ;
				PostProcessed = FinalizeLoginDatas(UnRSA, &PPsZ, ((Save - PPsZ) > 0) ? Response.Objs[Idx].Value.Memory.Memory : NULL, (Save - PPsZ));
				if (PostProcessed == NULL)
				{
					printf("Bad Datas [Credentials] Finalization..\n");
					goto Skip;
				}

				SResponse LoginDatas;

				LoginDatas.Objs = NULL;
				LoginDatas.NbObj = 0;
				ManageObjects(&PostProcessed, PPsZ, &LoginDatas);

				for (LdIdx = 0; LdIdx < LoginDatas.NbObj; LdIdx++)
				{
					switch (LoginDatas.Objs[LdIdx].Id)
					{
						case OBJ_ID_LDMODULUS:
							if (LoginDatas.Objs[LdIdx].Family == OBJ_FAMILY_BLOB)
							{
								ZeroMemory(RsaKey, MODULUS_SZ);
								memcpy_s(RsaKey, MODULUS_SZ, LoginDatas.Objs[LdIdx].Value.Memory.Memory, LoginDatas.Objs[LdIdx].Value.Memory.MsZ);
								ContactSH->RsaPubKey = LoginDatas.Objs[LdIdx].Value.Memory;
								break;
							}
							default :
							printf("Non critical Object %d:%d..\n", LoginDatas.Objs[LdIdx].Family, LoginDatas.Objs[LdIdx].Id);
							DumpObj(LoginDatas.Objs[LdIdx]);
							break;
					}
				}

				//Save Contact LoginDatas (Credentials, Expriry, Login etc..)

				SkypeRSA = RSA_new();
				BN_hex2bn(&(SkypeRSA->n), Bin2HexStr(RsaKey, MODULUS_SZ));
				BN_hex2bn(&(SkypeRSA->e), "10001");
				PPsZ = Response.Objs[Idx].Value.Memory.MsZ;
				Response.Objs[Idx].Value.Memory.MsZ -= PPsZ;
				Save = PPsZ;
				PPsZ = 0x80;
				ZeroMemory(UnRSA, 0xFFF);
				PPsZ = RSA_public_decrypt(PPsZ, Response.Objs[Idx].Value.Memory.Memory, UnRSA, SkypeRSA, RSA_NO_PADDING);
				RSA_free(SkypeRSA);

				Suite = Save - PPsZ;
				Response.Objs[Idx].Value.Memory.Memory += PPsZ;
				PostProcessed = FinalizeLoginDatas(UnRSA, &PPsZ, (Suite > 0) ? Response.Objs[Idx].Value.Memory.Memory : NULL, Suite);
				if (PostProcessed == NULL)
				{
					printf("Bad Datas [ContactInfos] Finalization..\n");
					goto Skip;
				}

				PostProcessed += SHA_DIGEST_LENGTH;
				PPsZ -= SHA_DIGEST_LENGTH;

				SResponse ContactInfos;

				ContactInfos.Objs = NULL;
				ContactInfos.NbObj = 0;
				ManageObjects(&PostProcessed, PPsZ, &ContactInfos);

				for (CiIdx = 0; CiIdx < ContactInfos.NbObj; CiIdx++)
				{
					switch (ContactInfos.Objs[CiIdx].Id)
					{
						case OBJ_ID_CIRNAME:
							ContactSH->RealDName = _strdup((char *)ContactInfos.Objs[CiIdx].Value.Memory.Memory);
							break;
						case OBJ_ID_CILANG:
							ContactSH->Langue = _strdup((char *)ContactInfos.Objs[CiIdx].Value.Memory.Memory);
							break;
						case OBJ_ID_CIREGION:
							ContactSH->Region = _strdup((char *)ContactInfos.Objs[CiIdx].Value.Memory.Memory);
							break;
						case OBJ_ID_CIVILLE:
							ContactSH->Ville = _strdup((char *)ContactInfos.Objs[CiIdx].Value.Memory.Memory);
							break;
						case OBJ_ID_CILOCATION:
							CLocation		ContactLocation;

							LocationBlob2Location(ContactInfos.Objs[CiIdx].Value.Memory.Memory, &ContactLocation, ContactInfos.Objs[CiIdx].Value.Memory.MsZ);
showmem(ContactInfos.Objs[CiIdx].Value.Memory.Memory, ContactInfos.Objs[CiIdx].Value.Memory.MsZ);
							ContactSH->Locations->push_back(ContactLocation);
							break;
						default :
							break;
					}
				}

				ContactSH->OnLineStatus = 0;
				Found = 1;
				break;
			default:
				printf("Non critical Object %d:%d..\n", Response.Objs[Idx].Family, Response.Objs[Idx].Id);
				DumpObj(Response.Objs[Idx]);
				break;
			}
		}
Skip:
		if (Found)
			break;
		Hosts.pop();
	}
	return (Found);
}

Memory_U	GetAuthCert(queue<Contact> ContactsList, Contact *PeerContact)
{
	Contact		CurContact;
	Memory_U	Empty;

	Empty.Memory = NULL;
	Empty.MsZ = 0;

	while (!ContactsList.empty())
	{
		CurContact = ContactsList.front();
		if (strcmp((char *)CurContact.InternalName, (char *)PeerContact->InternalName) == 0)
			return (CurContact.AuthCert);
		ContactsList.pop();
	}
	return (Empty);
}

void	BuildSlotList(queue<Contact> ContactsList, SlotInfo **SlotsList)
{
	uint	Idx;

	*SlotsList = (SlotInfo *)malloc(ContactsList.size() * sizeof(SlotInfo));
	ZeroMemory(*SlotsList, ContactsList.size() * sizeof(SlotInfo));

	Idx = 0;
	while (!ContactsList.empty())
	{
		(*SlotsList)[Idx].SlotID = GetAssociatedSlotID((char *)(ContactsList.front().InternalName));
		(*SlotsList)[Idx].NbSN = 0;
		(*SlotsList)[Idx].AssociatedName = ContactsList.front().InternalName;
		(*SlotsList)[Idx].SNodes = new queue<Host>;
		ContactsList.pop();
		Idx++;
	}
}

void	SearchContactList(Host Session_SN, char *User)
{
	size_t		ContactSz = Contacts.size();
	size_t		CSzSave = ContactSz;
	Contact		CurContact;
	SlotInfo	*Slots;
	uint		Idx;
	queue<Host> Hosts2Ask;

	SetConsoleTitle("FakeSkype - Defining Buddies Online Status..");

	BuildSlotList(Contacts, &Slots);
	FillSlotsListSN(Session_SN, Slots, Contacts.size());

	while (ContactSz--)
	{
		Idx = 0;
		CurContact = Contacts.front();

		for (Idx = 0; Idx < CSzSave; Idx++)
		{
			if ((Slots[Idx].SlotID == GetAssociatedSlotID((char *)(CurContact.InternalName))) && (strcmp((char *)Slots[Idx].AssociatedName , (char *)CurContact.InternalName) == 0))
			{
				Hosts2Ask = *(Slots[Idx].SNodes);
				break;
			}
		}
		printf("Searching Infos for %s (Slot #%d)..\n\n", CurContact.InternalName, Slots[Idx].SlotID);
		if (SearchContact(Session_SN, User, &CurContact, (char *)CurContact.InternalName, Hosts2Ask))
		{
			list<CLocation>::iterator Location;

			printf("\nInfos Learned for %s.. Let's Ping This one..\n", CurContact.InternalName);
			for (Location = CurContact.Locations->begin(); Location != CurContact.Locations->end(); Location++)
			{
				printf("Infos Learned : ");
				DumpLocation(&(*Location));
			}
			printf("\n");
		}
		else
			printf("\nNo Info found about %s.. Must be offline since at least 72h..\n\n", CurContact.InternalName);

		Contacts.pop();
		Contacts.push(CurContact);
	}
}

int	InitialPing(CLocation Local_Node, char *User, Contact *ContactSH, char *User2Search)
{
	uchar						Request[0xFFF];
	ProbeHeader					*PHeader;
	ushort						TransID;
	uchar						*PRequest, *Mark;
	int							BaseSz;
	uint						PSize;
	ObjectDesc					ObjNbr, ObjUser, ObjNode;
	Host						ContactSN;
	int							Found = 0;
	sockaddr_in					LocalBind;
	SOCKET						SNUDPSock;
	list<CLocation>::iterator	Location;
	uint						MyOnlineStatus = STATUS_ONLINE;
	
	SNUDPSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	ZeroMemory((char *)&LocalBind, sizeof(LocalBind));
	LocalBind.sin_family = AF_INET;
	LocalBind.sin_addr.s_addr = htonl(INADDR_ANY);
	LocalBind.sin_port = htons(DEF_LPORT);
	bind(SNUDPSock, (struct sockaddr *)&LocalBind, sizeof(LocalBind));

	for (Location = ContactSH->Locations->begin(); Location != ContactSH->Locations->end(); Location++)
	{
		printf("Pinging Node : ");
		DumpLocation(&(*Location));

		ContactSN = Location->SNAddr;
		
		BaseSz = 0x26 + Location->BlobSz + Local_Node.BlobSz + (int)strlen(User2Search) + (int)strlen(User);

		ZeroMemory(Request, 0xFFF);

		TransID = BytesRandomWord();
		PHeader = (ProbeHeader *)Request;
		PHeader->TransID = htons(TransID);
		PHeader->PacketType = PKT_TYPE_OBFSUK;
		PHeader->IV = htonl(GenIV());

		PRequest = Request + sizeof(*PHeader);
		Mark = PRequest;

		/* FIXME: This should work too, so that we can send as 0x42, but as long as the other code works,
		          we have other priorities...
		 */
#if 0
		{
			uchar	PeerNode[LOCATION_SZ] = {0}, LocalNode[LOCATION_SZ] = {0};

			BuildLocationBlob (*Location, PeerNode);
			// This location blob has the NodeID wrong.. I don't know if this just needs
			// to be swapped here or if it gets parsed wrong, but until I find out, let's
			// swap it like in the original code
			*(unsigned int *)PeerNode = htonl(*(unsigned int *)PeerNode);
			*(unsigned int *)(PeerNode + 4)= htonl(*(unsigned int *)(PeerNode + 4));

			skype_thing userinfo[] = {
				{OBJ_FAMILY_NBR    , 0x10, MyOnlineStatus, 0}
			};
			DECL_OBJLIST(lst_userinfo,userinfo);

			skype_thing peers[] = {
				{OBJ_FAMILY_STRING , 0x00, (u32)User2Search  , strlen(User2Search)},
				{OBJ_FAMILY_STRING , 0x02, (u32)User         , strlen(User)},
				{OBJ_FAMILY_OBJLIST, 0x04, (u32)&lst_userinfo, 0},
				{OBJ_FAMILY_BLOB   , 0x0C, (u32)LocalNode    , Local_Node.BlobSz},
				{OBJ_FAMILY_NBR    , 0x0F, 0x00              , 0},
			};
			DECL_OBJLIST(lst_peers,peers);

			skype_thing req[] = {
				{OBJ_FAMILY_NBR    , 0x00, 0x02           , 0},
				{OBJ_FAMILY_BLOB   , 0x01, (u32)PeerNode  , Location->BlobSz},
				{OBJ_FAMILY_NBR    , 0x02, 0x51           , 0},
				{OBJ_FAMILY_OBJLIST, 0x03, (u32)&lst_peers, 0},
				{OBJ_FAMILY_NBR    , 0x04, 0x1C           , 0}
			};

			BaseSz = SizeObjects_(EXT_PARAMS, req) + 2;
			WriteValue(&PRequest, BaseSz);
			WriteValue(&PRequest, 0x1AA);
			*(unsigned short *)PRequest = htons(TransID - 1);
			PRequest += 2;
			WriteObjects_(EXT_PARAMS, &PRequest, req);
		}
#endif


#if 1
		WriteValue(&PRequest, BaseSz);
		WriteValue(&PRequest, 0x1AA);
		*(unsigned short *)PRequest = htons(TransID - 1);
		PRequest += 2;

		*PRequest++ = RAW_PARAMS;
		WriteValue(&PRequest, 0x06);

		ObjNbr.Family = OBJ_FAMILY_NBR;
		ObjNbr.Id = 0x00;
		ObjNbr.Value.Nbr = 0x02;
		WriteObject(&PRequest, ObjNbr);

		uchar	Node[LOCATION_SZ] = {0};
		BuildLocationBlob (*Location, Node);
		// This location blob has the NodeID wrong.. I don't know if this just needs
		// to be swapped here or if it gets parsed wrong, but until I find out, let's
		// swap it like in the original code
		*(unsigned int *)Node = htonl(*(unsigned int *)Node);
		*(unsigned int *)(Node + 4)= htonl(*(unsigned int *)(Node + 4));
		ObjNode.Family = OBJ_FAMILY_BLOB;
		ObjNode.Id = 0x01;
		ObjNode.Value.Memory.Memory = Node;
		ObjNode.Value.Memory.MsZ = Location->BlobSz;
		WriteObject(&PRequest, ObjNode);


		ObjNbr.Family = OBJ_FAMILY_NBR;
		ObjNbr.Id = 0x02;
		ObjNbr.Value.Nbr = 0x51;
		WriteObject(&PRequest, ObjNbr);

		*PRequest++ = OBJ_FAMILY_OBJLIST;
		WriteValue(&PRequest, 0x03);

		*PRequest++ = RAW_PARAMS;
		WriteValue(&PRequest, 0x05);

		ObjUser.Family = OBJ_FAMILY_STRING;
		ObjUser.Id = OBJ_ID_USER2SEARCH;
		ObjUser.Value.Memory.Memory = (uchar *)User2Search;
		ObjUser.Value.Memory.MsZ = (int)strlen(User2Search);
		WriteObject(&PRequest, ObjUser);

		ObjUser.Family = OBJ_FAMILY_STRING;
		ObjUser.Id = 0x02;
		ObjUser.Value.Memory.Memory = (uchar *)User;
		ObjUser.Value.Memory.MsZ = (int)strlen(User);
		WriteObject(&PRequest, ObjUser);

		BuildLocationBlob (Local_Node, Node);
		ObjNode.Family = OBJ_FAMILY_BLOB;
		ObjNode.Id = 0x0C;
		ObjNode.Value.Memory.Memory = Node;
		ObjNode.Value.Memory.MsZ = Local_Node.BlobSz;
		WriteObject(&PRequest, ObjNode);

		ObjNbr.Family = OBJ_FAMILY_NBR;
		ObjNbr.Id = 0x0F;
		ObjNbr.Value.Nbr = 0x00;
		WriteObject(&PRequest, ObjNbr);

		ObjNbr.Family = OBJ_FAMILY_NBR;
		ObjNbr.Id = 0x13;
		ObjNbr.Value.Nbr = 0x00;
		WriteObject(&PRequest, ObjNbr);

		ObjNbr.Family = OBJ_FAMILY_NBR;
		ObjNbr.Id = 0x04;
		//ObjNbr.Value.Nbr = 0x1E;
		ObjNbr.Value.Nbr = 0x1C;
		WriteObject(&PRequest, ObjNbr);

		ObjNbr.Family = OBJ_FAMILY_NBR;
		ObjNbr.Id = 0x10;
		ObjNbr.Value.Nbr = MyOnlineStatus;
		WriteObject(&PRequest, ObjNbr);
#endif

		PSize = (uint)(PRequest - Mark);

		PHeader->Crc32 = htonl(crc32(Mark, PSize, -1));

		//showmem(Request, sizeof(ProbeHeader) + PSize);

		Cipher(Mark, PSize, htonl(my_public_ip), htonl(inet_addr(ContactSN.ip)), htons(PHeader->TransID), htonl(PHeader->IV), 0);

		if (SendPacket(SNUDPSock, ContactSN, Request, sizeof(ProbeHeader) + PSize))
		{
			struct in_addr	PublicIP;

			PublicIP.S_un.S_addr = my_public_ip;
			if (UnCipherObfuscated(RecvBuffer, RecvBufferSz, inet_ntoa(PublicIP), ContactSN.ip) == 0)
			{
				printf("Unable to uncipher Packet..\n");
				goto Skip;
			}
			//showmem(RecvBuffer, RecvBufferSz);
			//printf("\n\n");

			uchar		*Browser;
			SResponse	Response;
			
			Browser = RecvBuffer;

			Response.Objs = NULL;
			Response.NbObj = 0;
			UDPResponseManager(&Browser, (uint *)&RecvBufferSz, &Response);

			// FIXME: On some contacts, I'm getting 0x03 back when they are online..
			// I also once got 0x1B3. Therefore If don't know how to handle these replies, as they
			// Also seem legit to me. 
			if (Response.Cmd == 0x293)
			{
				Location->OnLineNode = 1;
				return (1);
			}
			else
				goto Skip;
		}
		else
		{
			printf("No Response to contact ping..\n");
			goto Skip;
		}
Skip:
		Location->OnLineNode = 0;
		continue;
	}
	return (Found);
}

void TestInitialPing(CLocation Local_Node)
{
	// Pinging Node : 0x76f2bb31922892e3-1-l192.168.210.35:46573-s213.199.179.152:40001
	Contact c;
	CLocation		ContactLocation = {0};

	ContactLocation.bHasPU = 1;
	memcpy (ContactLocation.NodeID, "\x31\xbb\xf2\x76\xe3\x92\x28\x92", sizeof(ContactLocation.NodeID));
	strcpy (ContactLocation.PVAddr.ip, "192.168.210.35");
	ContactLocation.PVAddr.port = 46573;
	strcpy (ContactLocation.SNAddr.ip, "213.199.179.152");
	ContactLocation.SNAddr.port = 40001;
	ContactLocation.BlobSz = 0x15;

	c.Locations = new list<CLocation>;
	c.Locations->push_back(ContactLocation);
	InitialPing(Local_Node, "XXXXXXXXX", &c, "XXXXXXXXX");
}

void	InitialPingOnLine(CLocation Local_Node, char *User)
{
	size_t		ContactSz = Contacts.size();
	Contact		*CurContact;
	uint		OneOnline = 0;

	while (ContactSz--)
	{
		CurContact = &(Contacts.front());

		if (CurContact->OnLineStatus == 0)
		{
			printf("Initial Pinging Contact : %s\n", (CurContact->RealDName) ? (CurContact->RealDName) : (char *)(CurContact->InternalName));
			if (InitialPing(Local_Node, User, CurContact, (char *)(CurContact->InternalName)))
			{
				printf("%s Online..\n", (char *)(CurContact->InternalName));
				OneOnline = 1;
				CurContact->OnLineStatus = 1;
			}
			else
				cprintf(FOREGROUND_RED, "%s OffLine..\n", (char *)(CurContact->InternalName));
			printf("\n");
		}

		Contacts.pop();
		Contacts.push(*CurContact);
	}

	if (OneOnline == 0)
		cprintf(FOREGROUND_BLUE, "There is no Online contact in your list..\n");
	else
	{
		ContactSz = Contacts.size();

		while (ContactSz--)
		{
			CurContact = &(Contacts.front());

			if (CurContact->OnLineStatus == 1)
				cprintf(FOREGROUND_BLUE, "%s is OnLine..\n", (char *)(CurContact->InternalName));

			Contacts.pop();
			Contacts.push(*CurContact);
		}
	}

	printf("\n");
}
