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

#ifndef CHATMANAGER_H
#define CHATMANAGER_H

#include "Common.h"

void	BuildHeader2Send(Host Relay, SessProp *SessionProposal, uchar **ResponseBuffer, uint *BRSize, uint *SeqNbr, char *Msg);
void	BuildBody2Send(Host Relay, SessProp *SessionProposal, uchar **ResponseBuffer, uint *BRSize, uint *SeqNbr, queue<uint> MidList);
void	BuildUIC2Send(Host Relay, SessProp *SessionProposal, uchar **ResponseBuffer, uint *BRSize, uint *SeqNbr, uint UicID);

#endif /*CHATMANAGER_H*/
