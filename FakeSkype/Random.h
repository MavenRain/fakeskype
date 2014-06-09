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

#ifndef RANDOM_H
#define RANDOM_H

#include "Common.h"

uint	BytesSHA1(BYTE *Data, DWORD Length);
uint	BytesRandom();
__int64 BytesRandomI64();
ushort	BytesRandomWord();
__int64 PlatFormSpecific();
void	FillMiscDatas(unsigned int *Datas);
void	SpecialSHA(uchar *SessionKey, uint SkSz, uchar *SHAResult, uint ResSz);
void	BuildUnFinalizedDatas(uchar *Datas, uint Size, uchar *Result);
uchar	*FinalizeLoginDatas(uchar *Buffer, uint *Size, uchar *Suite, int SuiteSz);
void	GenSessionKey(uchar *Buffer, uint Size);
void	GetSessionKey(uchar *Buffer);

#endif /*RANDOM_H*/
