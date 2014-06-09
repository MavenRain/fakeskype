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

#ifndef SESSIONMANAGER_H
#define SESSIONMANAGER_H

#include "Common.h"

uint	BuildUserPacket(Host Relay, uchar **Buffer, ushort InternTID, ushort Cmd, AesStream_S *AesStream, uint NbObj, ...);
void	InitSession(SessProp *SessionProposal);

#endif /*SESSIONMANAGER_H*/
