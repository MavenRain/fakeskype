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

#ifndef PRESENCE_H
#define PRESENCE_H

#include "Common.h"

void	BuildLocationBlob(CLocation Location, uchar *Buffer);
void	SendPresence(CLocation Local_Node, char *User);

#endif /*PRESENCE_H*/
