[![Build Status](https://travis-ci.org/shove70/buffer.svg?branch=master)](https://travis-ci.org/shove70/buffer)
[![GitHub tag](https://img.shields.io/github/tag/shove70/buffer.svg?maxAge=86400)](https://github.com/shove70/buffer/releases)

# A simple and practical protocol buffer & RPC library.

At present, it has only dlang and C++ implementations, and will add more language support in the future, such as: Lua, Java, python, ruby, golang, rust...

C++ project on github:

https://github.com/shove70/shove.c


### Quick Start:

```d
import std.stdio;
import buffer.message;

mixin (LoadBufferFile!"message.buffer");
mixin (LoadBufferScript!`
    message Sample {
        string name;
        int32  age;
        int16  sex;
    }
`);

// Simple:

void main()
{
    Sample sample = new Sample();
    sample.name = "Tom";
    sample.age = 20;
    sample.sex = 1;
    ubyte[] buf = sample.serialize();
    writeln(buf);

    Sample sam = Message.deserialize!Sample(buf);
    writeln("name:\t",  sam.name);
    writeln("age:\t",   sam.age);
    writeln("sex:\t",   sam.sex);
}

// Advanced:

void main()
{
    // Set magic number, encryption method and key.
    Message.settings(1229, CryptType.XTEA, "1234");

    Sample sample = new Sample();
    sample.name = "Tom";
    sample.age = 20;
    sample.sex = 1;
    ubyte[] buf = sample.serialize();
    writeln(buf);

    string name;
    string method;
    Message.getMessageInfo(buf, name, method);

    switch (name)
    {
    case "Sample":
        Sample sam = Message.deserialize!Sample(buf);
        writeln("name:\t",  sam.name);
        writeln("age:\t",   sam.age);
        writeln("sex:\t",   sam.sex);
        break;
    case "...":
        break;
    default:
        break;
    }
}
```

### RPC Client:

```d
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
    Client.bindTcpRequestHandler(data => TcpRequestHandler(data));

    long userId = Client.call!long("GetUserId", "admin");
    writeln(userId);

    // or:

    LoginRetInfo ret = Client.call!LoginRetInfo("Login", "admin", "123456");
    if (ret !is null)
    {
        writeln(ret.id);
        writeln(ret.name);
    }
}

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
```

### RPC Server:

```d
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

    long GetUserId(string name)
    {
        // Access the database, query the user's id by name, assuming the user's ID is 1
        int userId = 1;
        // ...
        // Query OK.
        
        return userId;
    }

    LoginRetInfo Login(string name, string password)
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
}

__gshared Server!(Business) server;

void main()
{
    Message.settings(1229, CryptType.XTEA, "1234");
    server = new Server!(Business)();

    TcpSocket socket = new TcpSocket();
    socket.blocking = true;
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
                socket.send(ret_data);
        }
    }
}
```
