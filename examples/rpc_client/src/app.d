import std.stdio;
import std.socket;

import buffer;
import buffer.rpc.client;

mixin(LoadBufferScript!`
    message LoginInfo {
        string name;
        string password;
    }

    message LoginRetInfo {
        int32  id;
        string name;
    }
`);

void main()
{
    Message.settings(1229, CryptType.XTEA, "1234");
    Client.setServerHost("127.0.0.1", 10_000);

    LoginRetInfo ret = Client.call!LoginRetInfo("login", "admin", "123456");
    if (ret !is null)
    {
        writeln(ret.id);
        writeln(ret.name);
    }

    // or:

    long userId = Client.call!long("getUserId", "admin");
    writeln(userId);
}
