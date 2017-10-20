import std.stdio;

import buffer.message;
import buffer.rpc.server;

__gshared Server!(Business) server;

void main()
{
	Message.settings(1229, CryptType.XTEA, "1234");
	server = new Server!(Business)();
ubyte[] aa = [4, 205, 0, 0, 0, 43, 0, 1, 0, 5, 76, 111, 103, 105, 110, 119, 228, 36, 74, 40, 127, 219, 75, 64, 81, 34, 43, 186, 152, 225, 153, 4, 38, 91, 94, 190, 77, 247, 14, 205, 171, 99, 157, 175, 10, 244, 79, 103, 136];
	writeln(server.Handler(aa));
}

class Business
{
	mixin (LoadBufferScript!`
		message(1) LoginInfo {
			string	name;
			string	password;
		}
		
		message(2) LoginRetInfo {
			int32	id;
			string	name;
		}
	`);
	
	//alias _buffer_MESSAGE_ALIAS_1 = LoginInfo;
	
	LoginRetInfo Login(string name, string password)
	{
		LoginRetInfo lr = new LoginRetInfo();

		return lr;
	}
}