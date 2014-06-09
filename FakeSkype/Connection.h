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

#include "Common.h"

namespace	Epyks
{
	enum	CSTATUS
	{
		SOCKERROR = -1, DISCONNECTED = 0, CONNECTED = 1
	};

	class	Connection
	{
	private:
		sockaddr_in		SendAddr;

		void	Flush();
		int		_Send(uchar *Datas, uint Size);
	public:
		string	IPAddress;
		ushort	Port;
		CSTATUS	Status;
		SOCKET	Socket;
		uchar	RecvBuffer[0xFFF];
		uint	RecvBufferSz;
		RC4Keys	Keys;

		Connection(string IPAddress, ushort Port);
		int		Connect();
		int		Send(uchar *Datas, uint Size);

		CSTATUS	GetStatus();
		void	Reset();
	};
};
