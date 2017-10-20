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
        assert(Message._crypt == CryptType.NONE || (Message._crypt != CryptType.NONE && Message._key != string.init),
                "Must specify key when specifying the type of CryptType.");

        Message._magic = magic;
        Message._crypt = crypt;
        Message._key   = key;

        if (Message._crypt == CryptType.RSA)
        {
            Message._rsaKey = RSA.decodeKey(Message._key);

            assert(!Message._rsaKey.isNull, "Rsakey is incorrect.");
        }
    }

    static void getMessageInfo(ubyte[] buffer, out ushort messageId, out TypeInfo_Class messageClass, out string method)
    {
        Packet.parseInfo(buffer, messageId, method);
        
        if (messageId in _messages)
        {
            messageClass = _messages[messageId];
        }
    }

    static Variant[] deserialize(ubyte[] buffer, out ushort messageId, out TypeInfo_Class messageClass, out string method)
    {
        Variant[] ret = Packet.parse(buffer, Message._magic, Message._crypt, Message._key, Message._rsaKey, messageId, method);

        if (messageId in _messages)
        {
            messageClass = _messages[messageId];
        }

        return ret;
    }

    static T deserialize(T)(ubyte[] buffer)
    {
        string method;

        return deserialize!T(buffer, method);
    }

    static T deserialize(T)(ubyte[] buffer, out string method)
    {
        ushort messageId;
        TypeInfo_Class messageClass;
        Variant[] params = deserialize(buffer, messageId, messageClass, method);

        if (messageClass is null || params == null)
            return null;

        T message = new T();
        if (message.messageId != messageId)
        {
            assert(0, "The type T(" ~ T.classinfo.name ~ ") of the incoming template is incorrect. It should be " ~ messageClass.name);
        }

        foreach (i, type; FieldTypeTuple!(T))
        {
            mixin("
                message." ~ FieldNameTuple!T[i] ~ " = params[" ~ i.to!string ~ "].get!" ~ type.stringof ~ ";
            ");
        }

        return message;
    }

protected:

    ubyte[] serialize(T)(T message, string method = string.init)
    {
        assert(message !is null, "The object to serialize cannot be null.");

        Variant[] params;

        foreach (i, type; FieldTypeTuple!T)
        {
            mixin("
                params ~= Variant(message." ~ FieldNameTuple!T[i] ~ ");
            ");
        }

        return Packet.build(Message._magic, Message._crypt, Message._key, Message._rsaKey, message.messageId, method, params);
    }
    
    ushort _messageId;
    __gshared static TypeInfo_Class[ushort] _messages;

private:

    __gshared static ushort              _magic;
    __gshared static CryptType           _crypt;
    __gshared static string              _key;
    __gshared static Nullable!RSAKeyInfo _rsaKey;
}
