module buffer.packet;

import std.variant;
import std.bitmanip;
import std.traits;
import std.typecons;
import std.conv : to;

import cryption.aes;
import cryption.tea.xtea;
import cryption.rsa;

import buffer.utils;

enum CryptType
{
    NONE = 0,
    XTEA = 1,
    AES  = 2,
    RSA  = 3
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
    else static if (is(Unqual!Type == bool))
        const ubyte TypeID = 0x30;
    else static if (is(Unqual!Type == char))
        const ubyte TypeID = 0x40;
    else static if (is(Unqual!Type == string))
        const ubyte TypeID = 0x41;
    else
        static assert(0, "Data types that are not supported: " ~ typeid(Type));
}

package class Packet
{
    static ubyte[] build(ushort magic, CryptType crypt, string key, Nullable!RSAKeyInfo rsaKey, ushort messageId, string method, Variant[] params)
    {
        assert(params.length > 0, "Parameter params must be provided.");
        assert(method.length <= 255, "Paramter method cannot be greater than 255 characters.");

        ubyte[] temp;
        ubyte[] tlv;

        void put(T)(Variant v)
        {
            tlv ~= TypeID!T;
            temp = new ubyte[T.sizeof];
            temp.write!T(v.get!T, 0);
            tlv ~= temp;
        }

        foreach (v; params)
        {
            if (v.type == typeid(byte))
            {
                put!byte(v);
            }
            else if (v.type == typeid(ubyte))
            {
                put!ubyte(v);
            }
            else if (v.type == typeid(short))
            {
                put!short(v);
            }
            else if (v.type == typeid(ushort))
            {
                put!ushort(v);
            }
            else if (v.type == typeid(int))
            {
                put!int(v);
            }
            else if (v.type == typeid(uint))
            {
                put!uint(v);
            }
            else if (v.type == typeid(long))
            {
                put!long(v);
            }
            else if (v.type == typeid(ulong))
            {
                put!ulong(v);
            }
            else if (v.type == typeid(float))
            {
                put!float(v);
            }
            else if (v.type == typeid(double))
            {
                put!double(v);
            }
            else if (v.type == typeid(bool))
            {
                put!bool(v);
            }
            else if (v.type == typeid(char))
            {
                put!char(v);
            }
            else if (v.type == typeid(string))
            {
                tlv ~= TypeID!string;
                string str = v.get!string;
                temp = new ubyte[4];
                temp.write!int(cast(int) str.length, 0);
                tlv ~= temp;
                temp = cast(ubyte[]) str;
                tlv ~= temp;
            }
            else
            {
                assert(0, "Data types id that are not supported: " ~ v.type.toString);
            }
        }

        final switch (crypt)
        {
        case CryptType.NONE:
            break;
        case CryptType.XTEA:
            tlv = Xtea.encrypt(tlv, key);
            break;
        case CryptType.AES:
            tlv = AESUtils.encrypt!AES128(tlv, key);
            break;
        case CryptType.RSA:
            tlv = RSA.encrypt(rsaKey, tlv);
            break;
        }

        ubyte[] method_buf = cast(ubyte[]) method;
        ubyte[] buffer = new ubyte[10];

        buffer.write!ushort(magic, 0);
        buffer.write!int(cast(int)(2 + 2 + method_buf.length + tlv.length + 2), 2);
        buffer.write!ushort(messageId, 6);
        buffer.write!ushort(cast(ushort) method_buf.length, 8);
        if (method_buf.length > 0)
            buffer ~= method_buf;
        buffer ~= tlv;
        buffer ~= strToByte_hex(MD5(buffer)[0 .. 4]);

        return buffer;
    }

    static void parseInfo(ubyte[] buffer, out ushort messageId, out string method)
    {
        assert(buffer != null && buffer.length >= 12, "Incorrect buffer length.");

        messageId = buffer.peek!ushort(6);

        ushort t_method_len = buffer.peek!ushort(8);
        if (t_method_len > 0)
        {
            method = cast(string) buffer[10 .. 10 + t_method_len];
        }
    }

    static Variant[] parse(ubyte[] buffer, ushort magic, CryptType crypt, string key, Nullable!RSAKeyInfo rsaKey, out ushort messageId, out string method)
    {
        assert(buffer != null && buffer.length >= 12, "Incorrect buffer length.");

        ushort t_magic, t_crc;
        int t_len;
        t_magic = buffer.peek!ushort(0);
        t_len = buffer.peek!int(2);

        if ((t_magic != magic) || (t_len > buffer.length - 6))
            return null;

        buffer = buffer[0 .. t_len + 6];
        t_crc = buffer.peek!ushort(buffer.length - 2);
        if (strToByte_hex(MD5(buffer[0 .. $ - 2])[0 .. 4]) != buffer[$ - 2 .. $])
            return null;

        parseInfo(buffer, messageId, method);

        ushort t_method_len = buffer.peek!ushort(8);
        buffer = buffer[10 + t_method_len .. $ - 2];

        final switch (crypt)
        {
        case CryptType.NONE:
            break;
        case CryptType.XTEA:
            buffer = Xtea.decrypt(buffer, key);
            break;
        case CryptType.AES:
            buffer = AESUtils.decrypt!AES128(buffer, key);
            break;
        case CryptType.RSA:
            buffer = RSA.decrypt(rsaKey, buffer);
            break;
        }

        ubyte typeId;
        int pos;
        Variant[] ret;

        void get(T)()
        {
            ret ~= Variant(buffer.peek!T(pos));
            pos += T.sizeof;
        }

        while (pos < buffer.length)
        {
            typeId = buffer[pos];
            pos++;

            if (typeId == TypeID!byte)
            {
                get!byte;
            }
            else if (typeId == TypeID!ubyte)
            {
                get!ubyte;
            }
            else if (typeId == TypeID!short)
            {
                get!short;
            }
            else if (typeId == TypeID!ushort)
            {
                get!ushort;
            }
            else if (typeId == TypeID!int)
            {
                get!int;
            }
            else if (typeId == TypeID!uint)
            {
                get!uint;
            }
            else if (typeId == TypeID!long)
            {
                get!long;
            }
            else if (typeId == TypeID!ulong)
            {
                get!ulong;
            }
            else if (typeId == TypeID!float)
            {
                get!float;
            }
            else if (typeId == TypeID!double)
            {
                get!double;
            }
            else if (typeId == TypeID!bool)
            {
                get!bool;
            }
            else if (typeId == TypeID!char)
            {
                get!char;
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
}
