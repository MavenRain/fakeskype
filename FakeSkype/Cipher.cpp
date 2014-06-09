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

#include "Cipher.h"

#define	 SEED_CRC_LEN	12
#define	 RC4_KLEN		88



void	InitKey(RC4_context	*rc4, unsigned int Seed)
{
	Skype_RC4_Expand_IV (rc4, Seed, 1);
}

void	UncipherObfuscatedTCPCtrlPH(unsigned char *Ciphered)
{
	unsigned int	Seed, i;
	RC4_context rc4;

	Seed = htonl(*(unsigned int *)Ciphered);
	
	Skype_RC4_Expand_IV (&rc4, Seed, 1);
	RC4_crypt (Ciphered + 0x04, 0x0A, &rc4, 0);
}

int		UnCipherObfuscated(unsigned char *Ciphered, unsigned int CipheredLen, char *cip, char *chost_ip)
{
	CipheredPacketHeader	*Header;
	unsigned char	ToCrc[SEED_CRC_LEN] = {0};
	unsigned int	seed, ip, host_ip, i, ResLen, offset, ret, skiphdr = 0;
	unsigned char	Key[RC4_KLEN] = {0};
	unsigned short	TransID;
	RC4_context rc4;

	do
	{
		if (Ciphered[2] != 0x02)
		{
			// There seems to be some special for long packets exceeding 0x54B bytes..?
			if (!(Ciphered[2] & 0x0F) == 0x0F || !(Ciphered[6] == 0x02))
				return (-1);
		}

		Header = (CipheredPacketHeader *)Ciphered;
		ip = htonl(inet_addr(cip));
		host_ip = htonl(inet_addr(chost_ip));
		TransID = htons(Header->TransID);
		if ((Ciphered[2] & 0x0F) == 0x0F) 
			Header = (CipheredPacketHeader *)(Ciphered + 4);
		
		memcpy(ToCrc, (void *)&host_ip, 4);
		memcpy(ToCrc + 4, (void *)&ip, 4);
		memcpy(ToCrc + 8, (void *)&TransID, 2);

		seed = crc32(ToCrc, SEED_CRC_LEN, -1) ^ htonl(Header->IV);

		Skype_RC4_Expand_IV (&rc4, seed, 1);
		offset = sizeof(CipheredPacketHeader);
		if ((Ciphered[2] & 0x0F) == 0x0F) 
		{
			offset += 4;
			if (CipheredLen >= 0x54B)
				ResLen = 0x54B - offset;
			else 
				ResLen = CipheredLen - offset;
		} else {
			ResLen = CipheredLen - offset;
		}
		CipheredLen -= ( ResLen + offset);
		RC4_crypt (Ciphered + offset, ResLen, &rc4, 0);
		ret = (crc32(Ciphered + offset, ResLen, -1) == htonl(Header->Crc32));
		if (skiphdr)
		{
			memmove (Ciphered, Ciphered + offset, ResLen + CipheredLen);
			Ciphered += ResLen;
		} else Ciphered += ResLen + offset;
		skiphdr = 1;
	} while (CipheredLen);
	return ret;
}

void	Cipher(unsigned char *Data, unsigned int len, unsigned int ip, unsigned int host_ip, unsigned short TransID, unsigned int IV, BYTE IsResend)
{
	unsigned char	ToCrc[SEED_CRC_LEN] = {0};
	unsigned int	seed, i;
	unsigned char	*Result;
	RC4_context rc4;

	memcpy(ToCrc, (void *)&ip, 4);
	memcpy(ToCrc + 4, (void *)&host_ip, 4);
	memcpy(ToCrc + 8, (void *)&TransID, 2);

	if (!IsResend)
		seed = crc32(ToCrc, SEED_CRC_LEN, -1) ^ IV;
	else
		seed = TransID ^ IV;

	Skype_RC4_Expand_IV (&rc4, seed, 1);
	RC4_crypt (Data, len, &rc4, 0);

}

void	CipherTCP(RC4_context *rc4, unsigned char *Data, unsigned int len)
{
	RC4_crypt (Data, len, rc4, 0);
}
