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

#ifndef SESSIONCMDMANAGER_H
#define SESSIONCMDMANAGER_H

#include "Common.h"

int		ManageSessionCMD(Host Relay, SessProp *SessionProposal, uchar **ResponseBuffer, SResponse Response, uint *BRSize);

#endif /*SESSIONCMDMANAGER_H*/
