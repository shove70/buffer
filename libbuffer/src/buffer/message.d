module buffer.message;

import std.traits;
import std.typecons;
import std.variant;
import std.conv : to;

import cryption.rsa;

public import buffer.compiler;
public import buffer.packet;

abstract class Message
{
public:

    alias byte    int8;
    alias ubyte   uint8;
    alias short   int16;
    alias ushort  uint16;
    alias int     int32;
    alias uint    uint32;
    alias long    int64;
    alias ulong   uint64;
    alias float   float32;
    alias double  float64;
    //bool
    //char
    //string

    @property ushort messageId()
    {
        return _messageId;
    }

    @property TypeInfo_Class messageName()
    {
        return _messages[_messageId];
    }

    static void settings(ushort magic, CryptType crypt = CryptType.NONE, string key = string.init)
    {
        assert(crypt == CryptType.NONE || (crypt != CryptType.NONE && key != string.init),
                "Must specify key when specifying the type of CryptType.");

        _magic = magic;
        _crypt = crypt;
        _key   = key;

        if (_crypt == CryptType.RSA)
        {
            _rsaKey = RSA.decodeKey(Message._key);

            assert(!_rsaKey.isNull, "Rsakey is incorrect.");
        }
    }

    static ubyte[] serialize_without_msginfo(Params...)(string method, Params params)
    {
        Variant[] t_params;

        foreach(p; params)
        {
            t_params ~= Variant(p);
        }

        return Packet.build(_magic, _crypt, _key, _rsaKey, 0x00, method, t_params);
    }

    static void getMessageInfo(ubyte[] buffer, out ushort messageId, out TypeInfo_Class messageName, out string method)
    {
        Packet.parseInfo(buffer, messageId, method);

        if (messageId in _messages)
        {
            messageName = _messages[messageId];
        }
    }

    static Variant[] deserialize(ubyte[] buffer, out ushort messageId, out TypeInfo_Class messageName, out string method)
    {
        Variant[] ret = Packet.parse(buffer, _magic, _crypt, _key, _rsaKey, messageId, method);

        if (messageId in _messages)
        {
            messageName = _messages[messageId];
        }

        return ret;
    }

    static T deserialize(T)(ubyte[] buffer) if (BaseTypeTuple!T.length > 0 && is(BaseTypeTuple!T[0] == Message))
    {
        string method;

        return deserialize!T(buffer, method);
    }

    static T deserialize(T)(ubyte[] buffer, out string method) if (BaseTypeTuple!T.length > 0 && is(BaseTypeTuple!T[0] == Message))
    {
        ushort messageId;
        TypeInfo_Class messageName;
        Variant[] params = deserialize(buffer, messageId, messageName, method);

        if (messageName is null || params == null)
            return null;

        T message = new T();
        if (message.messageId != messageId)
        {
            assert(0, "The type T(" ~ T.classinfo.name ~ ") of the incoming template is incorrect. It should be " ~ messageName.name);
        }

        foreach (i, type; FieldTypeTuple!(T))
        {
            mixin(`
                message.` ~ FieldNameTuple!T[i] ~ ` = params[` ~ i.to!string ~ `].get!` ~ type.stringof ~ `;
            `);
        }

        return message;
    }

protected:

    ubyte[] serialize(T)(T message, string method = string.init) if (BaseTypeTuple!T.length > 0 && is(BaseTypeTuple!T[0] == Message))
    {
        assert(message !is null, "The object to serialize cannot be null.");

        Variant[] params;

        foreach (i, type; FieldTypeTuple!T)
        {
            mixin(`
                params ~= Variant(message.` ~ FieldNameTuple!T[i] ~ `);
            `);
        }

        return Packet.build(_magic, _crypt, _key, _rsaKey, message.messageId, method, params);
    }

    ushort _messageId;
    __gshared static TypeInfo_Class[ushort] _messages;

private:

    __gshared static ushort              _magic;
    __gshared static CryptType           _crypt;
    __gshared static string              _key;
    __gshared static Nullable!RSAKeyInfo _rsaKey;
}
