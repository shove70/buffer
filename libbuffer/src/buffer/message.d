module buffer.message;

import std.traits;
import std.conv : to;
import std.bitmanip;
import std.typecons;
import std.variant;

import cryption.tea.xtea;
import cryption.aes;
import cryption.rsa;

public import buffer.compiler;
import buffer.utils;

enum CryptType
{
    NONE = 0,
    XTEA = 1,
    AES =  2,
    RSA =  3
}

template TypeID(Type)
{
         static if (is(Unqual!Type == byte))
        const ubyte TypeID = 0x01;
    else static if (is(Unqual!Type == ubyte))
        const ubyte TypeID = 0x02;
    else static if (is(Unqual!Type == short))
        const ubyte TypeID = 0x03;
    else static if (is(Unqual!Type == ushort))
        const ubyte TypeID = 0x04;
    else static if (is(Unqual!Type == int))
        const ubyte TypeID = 0x05;
    else static if (is(Unqual!Type == uint))
        const ubyte TypeID = 0x06;
    else static if (is(Unqual!Type == long))
        const ubyte TypeID = 0x07;
    else static if (is(Unqual!Type == ulong))
        const ubyte TypeID = 0x08;
    else static if (is(Unqual!Type == float))
        const ubyte TypeID = 0x20;
    else static if (is(Unqual!Type == double))
        const ubyte TypeID = 0x21;
    else static if (is(Unqual!Type == string))
        const ubyte TypeID = 0x50;
    else
        static assert(0, "Data types that are not supported: " ~ typeid(Type));
}

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
        assert(buffer != null && buffer.length >= 12, "Incorrect buffer length.");

        messageId = buffer.peek!ushort(6);
        if (messageId in _messages)
        {
            messageClass = _messages[messageId];
        }

        ushort t_method_len = buffer.peek!ushort(8);
        if (t_method_len > 0)
        {
            method = cast(string) buffer[10 .. 10 + t_method_len];
        }
    }

    static Variant[] deserialize(ubyte[] buffer, out ushort messageId, out TypeInfo_Class messageClass, out string method)
    {
        assert(buffer != null && buffer.length >= 12, "Incorrect buffer length.");

        ushort t_magic, t_crc;
        int t_len;
        t_magic = buffer.peek!ushort(0);
        t_len = buffer.peek!int(2);

        if ((t_magic != Message._magic) || (t_len > buffer.length - 6))
            return null;

        buffer = buffer[0 .. t_len + 6];
        t_crc = buffer.peek!ushort(buffer.length - 2);
        if (strToByte_hex(MD5(buffer[0 .. $ - 2])[0 .. 4]) != buffer[$ - 2 .. $])
            return null;

        getMessageInfo(buffer, messageId, messageClass, method);

        ushort t_method_len = buffer.peek!ushort(8);
        buffer = buffer[10 + t_method_len .. $ - 2];

        final switch (Message._crypt)
        {
        case CryptType.NONE:
            break;
        case CryptType.XTEA:
            buffer = Xtea.decrypt(buffer, Message._key);
            break;
        case CryptType.AES:
            buffer = AESUtils.decrypt!AES128(buffer, Message._key);
            break;
        case CryptType.RSA:
            buffer = RSA.decrypt(Message._rsaKey, buffer);
            break;
        }

        ubyte typeId;
        int pos;
        Variant[] ret;

        while (pos < (buffer.length - 1))
        {
            typeId = buffer[pos];
            pos++;

            if (typeId == TypeID!byte)
            {
                ret ~= Variant(buffer.peek!byte(pos));
                pos += byte.sizeof;
            }
            else if (typeId == TypeID!ubyte)
            {
                ret ~= Variant(buffer.peek!ubyte(pos));
                pos += ubyte.sizeof;
            }
            else if (typeId == TypeID!short)
            {
                ret ~= Variant(buffer.peek!short(pos));
                pos += short.sizeof;
            }
            else if (typeId == TypeID!ushort)
            {
                ret ~= Variant(buffer.peek!ushort(pos));
                pos += ushort.sizeof;
            }
            else if (typeId == TypeID!int)
            {
                ret ~= Variant(buffer.peek!int(pos));
                pos += int.sizeof;
            }
            else if (typeId == TypeID!uint)
            {
                ret ~= Variant(buffer.peek!uint(pos));
                pos += uint.sizeof;
            }
            else if (typeId == TypeID!long)
            {
                ret ~= Variant(buffer.peek!long(pos));
                pos += long.sizeof;
            }
            else if (typeId == TypeID!ulong)
            {
                ret ~= Variant(buffer.peek!ulong(pos));
                pos += ulong.sizeof;
            }
            else if (typeId == TypeID!float)
            {
                ret ~= Variant(buffer.peek!float(pos));
                pos += float.sizeof;
            }
            else if (typeId == TypeID!double)
            {
                ret ~= Variant(buffer.peek!double(pos));
                pos += double.sizeof;
            }
            else if (typeId == TypeID!string)
            {
                int temp = buffer.peek!int(pos);
                pos += 4;
                ret ~= Variant(cast(string) buffer[pos .. pos + temp]);
                pos += temp;
            }
            else
            {
                assert(0, "Data types id that are not supported: " ~ typeId.to!string);
            }
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

    /*
    static T deserialize(T)(ubyte[] buffer, ref string method)
    {
        assert(buffer != null && buffer.length >= 12, "Incorrect buffer length.");

        ushort t_magic, t_crc;
        int t_len;
        t_magic = buffer.peek!ushort(0);
        t_len = buffer.peek!int(2);

        if ((t_magic != Message._magic) || (t_len > buffer.length - 6))
            return null;

        buffer = buffer[0 .. t_len + 6];
        t_crc = buffer.peek!ushort(buffer.length - 2);
        if (strToByte_hex(MD5(buffer[0 .. $ - 2])[0 .. 4]) != buffer[$ - 2 .. $])
            return null;

        ushort t_messageId = buffer.peek!ushort(6);

        T message = new T();
        if (message.messageId != t_messageId)
        {
            assert(0, "The type T(" ~ T.classinfo.name ~ ") of the incoming template is incorrect. It should be " ~ _messages[t_messageId].name);
        }

        ushort t_method_len = buffer.peek!ushort(8);
        method = cast(string) buffer[10 .. 10 + t_method_len];
        buffer = buffer[10 + t_method_len .. $ - 2];

        final switch (Message._crypt)
        {
        case CryptType.NONE:
            break;
        case CryptType.XTEA:
            buffer = Xtea.decrypt(buffer, Message._key);
            break;
        case CryptType.AES:
            buffer = AESUtils.decrypt!AES128(buffer, Message._key);
            break;
        case CryptType.RSA:
            buffer = RSA.decrypt(Message._rsaKey, buffer);
            break;
        }

        ubyte typeId;
        int temp, pos;

        foreach (i, type; FieldTypeTuple!(T))
        {
            static if (is(Unqual!type == string))
            {
                mixin("
                    typeId = buffer[pos];
                    assert(" ~ TypeID!type.to!string ~ " == typeId, \"Data type mismatch.\");
                    pos++;
                    temp = buffer.peek!int(pos);
                    pos += 4;
                    message." ~ FieldNameTuple!T[i] ~ " = cast(string)buffer[pos..pos + temp];
                    pos += temp;
                ");
            }
            else
            {
                mixin("
                    typeId = buffer[pos];
                    assert(" ~ TypeID!type.to!string ~ " == typeId, \"Data type mismatch.\");
                    pos++;
                    message." ~ FieldNameTuple!T[i] ~ " = buffer.peek!" ~ type.stringof ~ "(pos);
                    pos += " ~ type.sizeof.to!string ~ ";
                ");
            }
        }

        return message;
    }
    */
protected:

    ubyte[] serialize(T)(T message, string method = string.init)
    {
        assert(message !is null, "The object to serialize cannot be null.");
        assert(method.length <= 255, "Paramter method cannot be greater than 255 characters.");

        ubyte[] temp1, temp2;
        ubyte[] tlv;

        foreach (i, type; FieldTypeTuple!T)
        {
            static if (is(Unqual!type == string))
            {
                mixin("
                    temp1 = new ubyte[4];
                    temp2 = cast(ubyte[])message." ~ FieldNameTuple!T[i] ~ ";
                    temp1.write!int(cast(int)temp2.length, 0);
                    tlv ~= cast(ubyte)" ~ TypeID!type.to!string ~ ";
                    tlv ~= temp1;
                    tlv ~= temp2;
                ");
            }
            else
            {
                mixin("
                    temp1 = new ubyte[" ~ type.sizeof.to!string ~ "];
                    temp1.write!" ~ type.stringof ~ "(message." ~ FieldNameTuple!T[i] ~ ", 0);
                    tlv ~= cast(ubyte)" ~ TypeID!type.to!string ~ ";
                    tlv ~= temp1;
                ");
            }
        }

        final switch (Message._crypt)
        {
        case CryptType.NONE:
            break;
        case CryptType.XTEA:
            tlv = Xtea.encrypt(tlv, Message._key);
            break;
        case CryptType.AES:
            tlv = AESUtils.encrypt!AES128(tlv, Message._key);
            break;
        case CryptType.RSA:
            tlv = RSA.encrypt(Message._rsaKey, tlv);
            break;
        }

        ubyte[] method_buf = cast(ubyte[]) method;
        ubyte[] buffer = new ubyte[10];

        buffer.write!ushort(Message._magic, 0);
        buffer.write!int(cast(int)(2 + 2 + method_buf.length + tlv.length + 2), 2);
        buffer.write!ushort(messageId, 6);
        buffer.write!ushort(cast(ushort) method_buf.length, 8);
        if (method_buf.length > 0)
            buffer ~= method_buf;
        buffer ~= tlv;
        buffer ~= strToByte_hex(MD5(buffer)[0 .. 4]);

        return buffer;
    }

    ushort _messageId;
    __gshared static TypeInfo_Class[ushort] _messages;

private:

    __gshared static ushort              _magic;
    __gshared static CryptType           _crypt;
    __gshared static string              _key;
    __gshared static Nullable!RSAKeyInfo _rsaKey;
}
