import std.stdio;
import std.socket;

import buffer.message;
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

ubyte[] TcpRequestHandler(ubyte[] data)
{
    TcpSocket socket = new TcpSocket();
    socket.blocking = true;
    socket.bind(new InternetAddress("127.0.0.1", 0));
    socket.connect(new InternetAddress("127.0.0.1", 10000));
    socket.send(data);

    ubyte[] rec_data = new ubyte[1024];
    long len = socket.receive(rec_data);
    socket.close();

    return rec_data[0..len];
}

void main()
{
    Message.settings(1229, CryptType.XTEA, "1234");
    Client.bindTcpRequestHandler(data => TcpRequestHandler(data));

    LoginRetInfo ret = Client.call!LoginRetInfo("Login", "admin", "123456");
    if (ret !is null)
    {
        writeln(ret.id);
        writeln(ret.name);
    }

    // or:

    long userId = Client.call!long("GetUserId", "admin");
    writeln(userId);
}
