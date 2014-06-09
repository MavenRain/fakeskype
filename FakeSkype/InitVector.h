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

#ifndef INITVECTOR_H
#define INITVECTOR_H

#include "Common.h"

unsigned int Update(unsigned int iv);
unsigned int GenIV();

#endif /*INITVECTOR_H*/
