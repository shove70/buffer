import std.stdio;

import buffer.message;
import buffer.rpc.client;

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

ubyte[] TcpRequestHandler(ubyte[] data)
{
	LoginInfo log_info = Message.deserialize!LoginInfo(data);
	LoginRetInfo ret = new LoginRetInfo();
	ret.id = 1000;
	ret.name = log_info.name;
	return ret.serialize();
}

void main()
{
	Message.settings(1229, CryptType.XTEA, "1234");
	Client.bindTcpRequestHandler(data => TcpRequestHandler(data));
	
	LoginRetInfo lr = Client.call!(LoginInfo, LoginRetInfo)("Login", "admin", "123456");
	if (lr !is null)
	{
		writeln(lr.id);
		writeln(lr.name);
	}
}