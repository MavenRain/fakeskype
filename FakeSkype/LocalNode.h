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

#ifndef LOCALNODE_H
#define LOCALNODE_H

#include "Common.h"

void	 InitLocalNode();

uint	 GetUpTime();
uchar	*GetNodeId();
uint	 GetListeningPort();

#endif /*LOCALNODE_H*/
