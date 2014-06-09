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

#include		<stdio.h>
#include		"Common.h"

void			showmem(uchar *Mem, uint Sz)
{
	unsigned int i, j;

	if ((Sz == 0) || (Mem == NULL))
	{
		cprintf(RED, "ShowMem Error..\n");
		return ;
	}
 
    printf("0x%04x: ", 0);
    for (i = 0; i < Sz; i++)
	{
		printf("%02x%c", Mem[i], ' ');
		if ((i % 16) == 15)
		{
			printf(" ");
			for (j = 0; j < 16; j++)
				printf("%c", isprint(Mem[i - 15 + j]) ? Mem[i - 15 + j] : '.');
			if (i < (Sz - 1))
				printf( "\n0x%04x: ", i + 1);
		}
	}
	if (i % 16)
	{
		printf( "%*s ", 3 * (16 - (i % 16)), "" );
		for (j = 0; j < i % 16; j++)
			printf( "%c", isprint(Mem[i - (i % 16) + j]) ? Mem[i - (i % 16) + j] : '.' );
	}
	printf( "\n" );
}
