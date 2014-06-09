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

#ifndef PARENTNODE_H
#define PARENTNODE_H

#include "Common.h"

uint	GetAssociatedSlotID(char *User);
void	RequestSlotInfos(Host Session_SN, queue<SlotInfo> *Slots, int NbAddrs, uint SlotID);
void	RequestSlotBlocInfos(Host Session_SN, queue<SlotInfo> *Slots, int NbSlots, int NbAddrs);
void	FillSlotsListSN(Host Session_SN, SlotInfo *SlotsList, size_t NbSlots);
void	GetSNode(Host Session_SN, char *User, queue<Host> *Hosts, int NbAddrs, uint SlotID);
void	PerformFireWallTest(Host ParentNode);
void	SubmitUpdatedProps(Host ParentNode);

#endif /*PARENTNODE_H*/
