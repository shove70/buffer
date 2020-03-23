import std.stdio;
import std.socket;
import std.concurrency;
import core.thread;

import buffer;
import buffer.rpc.server;

class Business
{
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

    LoginRetInfo login(string name, string password)
    {
        // Access the database, check the user name and password, assuming the validation passed, the user's ID is 1
        int userId = 1;
        // ...
        // Check OK.

        LoginRetInfo ret = new LoginRetInfo();
        ret.id = userId;
        ret.name = name;

        return ret;
    }

    long getUserId(string name)
    {
        // Access the database, query the user's id by name, assuming the user's ID is 1
        long userId = 1;
        // ...
        // Query OK.

        return userId;
    }
}


__gshared Server!(Business) server;

void main()
{
    Message.settings(1229, CryptType.XTEA, "1234");
    server = new Server!(Business)();

    TcpSocket socket = new TcpSocket();
    socket.bind(new InternetAddress("127.0.0.1", 10000));
    socket.listen(10);

    while (true)
    {
        Socket accept = socket.accept();
        spawn(&acceptHandler, cast(shared Socket) accept);
    }
}

void acceptHandler(shared Socket accept)
{
    Socket socket = cast(Socket) accept;

    while (true)
    {
        ubyte[] data = new ubyte[1024];
        long len = socket.receive(data);

        if (len > 0)
        {
            ubyte[] ret_data = server.Handler(data[0..len]);

            if (ret_data != null)
            {
                socket.send(ret_data.dup);
            }
        }
    }
}
