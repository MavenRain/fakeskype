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

#ifndef SEARCHCONTACTS_H
#define SEARCHCONTACTS_H

#include "Common.h"

Memory_U	GetAuthCert(queue<Contact> ContactsList, Contact *PeerContact);
int			SearchContact(Host Session_SN, char *User, Contact *ContactSH, char *User2Search, queue<Host> Hosts);
void		SearchContactList(Host Session_SN, char *User);
void		InitialPingOnLine(CLocation Local_Node, char *User);
void TestInitialPing(CLocation Local_Node);

#endif /*SEARCHCONTACTS_H*/
