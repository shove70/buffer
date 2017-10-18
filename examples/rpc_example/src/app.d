import std.stdio;

import buffer.message;
import buffer.rpc.client;

mixin (LoadBufferScript!`
	message(1) Login {
		string	name;
		string	password;
	}
	
	message(2) LoginRet {
		int32	id;
		string	name;
	}
`);

ubyte[] TcpRequestHandler(ubyte[] data)
{
	Login login = Message.deserialize!Login(data);
	LoginRet lr = new LoginRet();
	lr.id = 1000;
	lr.name = login.name;
	return lr.serialize();
}

void main()
{
	Message.settings(1229, CryptType.XTEA, "1234");
	Client.bindTcpRequestHandler(data => TcpRequestHandler(data));
	
	LoginRet lr = Client.call!(Login, LoginRet)("admin", "123456");
	writeln(lr.id);
	writeln(lr.name);
}