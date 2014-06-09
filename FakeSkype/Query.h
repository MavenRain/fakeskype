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

#ifndef QUERY_H
#define QUERY_H

#include "Common.h"

void	HandleQuery(Host Session_SN, uchar *Query, int Size);

#endif /*QUERY_H*/
