module buffer.rpc.client;

import core.stdc.errno;
import std.meta : staticIndexOf;
import std.traits;
import std.conv : to;
import std.variant;
import std.socket;
import std.bitmanip;
import std.exception;
import std.typecons;
import std.datetime;

import crypto.rsa;

import buffer.message;

/// Rpc client
class Client
{
    private __gshared string host;
    private __gshared ushort port;

    static void setServerHost(const string host, const ushort port)
    {
        Client.host = host;
        Client.port = port;
    }

    /++
        Use global magic, host, port and other information. need call settings(), setServerHost() at before call this.
        When clients do not need to connect to different servers, using it can simplify calls.
    +/
    static T call(T, Params...)(const string method, Params params)
    if ((staticIndexOf!(T, supportedBuiltinTypes) != -1) || ((BaseTypeTuple!T.length > 0) && is(BaseTypeTuple!T[0] == Message)))
    {
        enforce(host != string.init, "Server host and port must be set.");
        return callEx!(T, Params)(host, port, Message._magic, Message._crypt, Message._key, Message._rsaKey, method, params);
    }

    /++
        With Server host, port, magic, cryptType, key parameters, not need call setServerHost(), settings().
        When the same client needs to connect to different servers, it needs to be used.
    +/
    static T callEx(T, Params...)(const string host, const ushort port,
        const ushort magic, const CryptType crypt, const string key, Nullable!RSAKeyInfo rsaKey,
        const string method, Params params)
    if ((staticIndexOf!(T, supportedBuiltinTypes) != -1) || ((BaseTypeTuple!T.length > 0) && is(BaseTypeTuple!T[0] == Message)))
    {
        enforce(host != string.init, "Server host and port must be set.");
        enforce(method.length > 0, "Paramter method must be set.");

        TcpSocket socket = new TcpSocket();
        socket.setOption(SocketOptionLevel.SOCKET, SocketOption.RCVTIMEO, 30.seconds);
        socket.setOption(SocketOptionLevel.SOCKET, SocketOption.SNDTIMEO, 30.seconds);
        socket.connect(new InternetAddress(host, port));

        T result = callEx!(T, Params)(socket, magic, crypt, key, rsaKey, method, params);

        socket.shutdown(SocketShutdown.BOTH);
        socket.close();

        return result;
    }

    /++
        With Socket socket, magic, cryptType, key parameters, not need call setServerHost(), settings().
        When the same client needs to connect to different servers, it needs to be used.
        At the same time, if long connection mode is adopted, it needs to be used as well.
    +/
    static T callEx(T, Params...)(Socket socket,
        const ushort magic, const CryptType crypt, const string key, Nullable!RSAKeyInfo rsaKey,
        const string method, Params params)
    if ((staticIndexOf!(T, supportedBuiltinTypes) != -1) || ((BaseTypeTuple!T.length > 0) && is(BaseTypeTuple!T[0] == Message)))
    {
        enforce(socket.isAlive, "The socket is not connected to the server.");
        enforce(method.length > 0, "Paramter method must be set.");

        ubyte[] response = request(socket, Message.serialize_without_msginfo(magic, crypt, key, rsaKey, method, params));
        string name;
        string res_method;
        Variant[] res_params = Message.deserializeEx(magic, crypt, key, rsaKey, response, name, res_method);
        
        //enforce(method == res_method);

        static if (isBuiltinType!T)
        {
            enforce(res_params.length == 1, "The number of response parameters from the server is incorrect.");

            return res_params[0].get!T;
        }
        else
        {
            alias FieldTypes = FieldTypeTuple!T;
            enforce(FieldTypes.length == res_params.length, "Incorrect number of parameters, " ~ T.stringof ~ " requires " ~ FieldTypes.length.to!string ~ " parameters.");

            T message = new T();

            foreach (i, type; FieldTypes)
            {
                mixin(`
                    message.` ~ FieldNameTuple!T[i] ~ ` = res_params[` ~ i.to!string ~ `].get!` ~ type.stringof ~ `;
                `);
            }

            return message;
        }
    }

    /++
        Note:
        The caller is responsible for connection and closure without actively closing the socket.
        But you need to close the exception before throwing it to release server resources.
    +/
    private static ubyte[] request(Socket socket, const ubyte[] data)
    {
        long len;
        for (size_t off; off < data.length; off += len)
        {
            len = socket.send(data[off..$]);

            if (len > 0)
            {
                continue;
            }
            else if (len == 0)
            {
                socket.shutdown(SocketShutdown.BOTH);
                socket.close();

                throw new Exception("Server socket close at sending. error: " ~ formatSocketError(errno));
            }
            else
            {
                if (errno == EINTR) // || errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    len = 0;
                    continue;
                }

                socket.shutdown(SocketShutdown.BOTH);
                socket.close();

                throw new Exception("Server socket error at sending. error: " ~ formatSocketError(errno));
            }
        }

        ubyte[] receive(long length)
        {
            ubyte[] buf = new ubyte[cast(uint)length];
            long len;

            for (size_t off; off < buf.length; off += len)
            {
                len = socket.receive(buf[off..$]);

                if (len > 0)
                {
                    continue;
                }
                else if (len == 0)
                {
                    return null;
                }
                else
                {
                    if (errno == EINTR) // || errno == EAGAIN || errno == EWOULDBLOCK)
                    {
                        len = 0;
                        continue;
                    }

                    return null;
                }
            }

            return buf;
        }

        len = cast(long)(ushort.sizeof + int.sizeof);
        ubyte[] buffer = receive(len);

        if (buffer.length != len)
        {
            socket.shutdown(SocketShutdown.BOTH);
            socket.close();

            throw new Exception("Server socket error at receiving. error: " ~ formatSocketError(errno));
        }

        len = buffer.peek!int(2);
        ubyte[] buf = receive(len);

        if (buf.length != len)
        {
            socket.shutdown(SocketShutdown.BOTH);
            socket.close();

            throw new Exception("Server socket error at receiving. error: " ~ formatSocketError(errno));
        }

        return buffer ~ buf;
    }
}
