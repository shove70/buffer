module buffer.packet;

import std.variant;
import std.bitmanip;
import std.traits;
import std.typecons;
import std.conv : to;
import std.exception;

import crypto.aes;
import crypto.tea;
import crypto.rsa;

import buffer.utils;

enum CryptType
{
    NONE            = 0,
    XTEA            = 1,
    AES             = 2,
    RSA             = 3,
    RSA_XTEA_MIXIN  = 4
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
    else static if (is(Unqual!Type == real))
        const ubyte TypeID = 0x22;
    else static if (is(Unqual!Type == bool))
        const ubyte TypeID = 0x30;
    else static if (is(Unqual!Type == char))
        const ubyte TypeID = 0x40;
    else static if (is(Unqual!Type == string))
        const ubyte TypeID = 0x41;
    else
        static assert(0, "Data types that are not supported: " ~ typeid(Type));
}

package:

class Packet
{
    static ubyte[] build(ushort magic, CryptType crypt, string key, Nullable!RSAKeyInfo rsaKey, string name, string method, Variant[] params)
    {
        assert(name.length <= 255, "Paramter name cannot be greater than 255 characters.");
        assert(method.length <= 255, "Paramter method cannot be greater than 255 characters.");
        assert(params.length > 0, "Parameter params must be provided.");

        ubyte[] tlv;
        BufferBuilder bb = new BufferBuilder(&tlv);

        foreach (v; params)
        {
            if (v.type == typeid(byte))
            {
                bb.put!byte(v.get!byte, true, false, 0);
            }
            else if (v.type == typeid(ubyte))
            {
                bb.put!ubyte(v.get!ubyte, true, false, 0);
            }
            else if (v.type == typeid(short))
            {
                bb.put!short(v.get!short, true, false, 0);
            }
            else if (v.type == typeid(ushort))
            {
                bb.put!ushort(v.get!ushort, true, false, 0);
            }
            else if (v.type == typeid(int))
            {
                bb.put!int(v.get!int, true, false, 0);
            }
            else if (v.type == typeid(uint))
            {
                bb.put!uint(v.get!uint, true, false, 0);
            }
            else if (v.type == typeid(long))
            {
                bb.put!long(v.get!long, true, false, 0);
            }
            else if (v.type == typeid(ulong))
            {
                bb.put!ulong(v.get!ulong, true, false, 0);
            }
            else if (v.type == typeid(float))
            {
                bb.put!float(v.get!float, true, false, 0);
            }
            else if (v.type == typeid(double))
            {
                bb.put!double(v.get!double, true, false, 0);
            }
            else if (v.type == typeid(real))
            {
                bb.put!real(v.get!real, true, false, 0);
            }
            else if (v.type == typeid(bool))
            {
                bb.put!bool(v.get!bool, true, false, 0);
            }
            else if (v.type == typeid(char))
            {
                bb.put!char(v.get!char, true, false, 0);
            }
            else if (v.type == typeid(string))
            {
                bb.put!string(v.get!string, true, true, 4);
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
            tlv = Xtea.encrypt(tlv, key, 64, PaddingMode.PKCS5);
            break;
        case CryptType.AES:
            tlv = AESUtils.encrypt!AES128(tlv, key, iv, PaddingMode.PKCS5);
            break;
        case CryptType.RSA:
            tlv = RSA.encrypt(rsaKey, tlv);
            break;
        case CryptType.RSA_XTEA_MIXIN:
            tlv = RSA.encrypt(rsaKey, tlv, true);
        }

        ubyte[] buffer;
        bb = new BufferBuilder(&buffer);
        bb.put!ushort(magic, false, false, 0);
        bb.put!int(0, false, false, 0);    // length, seize a seat.
        bb.put!string(name, false, true, 2);
        bb.put!string(method, false, true, 2);
        buffer ~= tlv;
        buffer.write!int(cast(int)(buffer.length - 2 - 4 + 2), 2);
        buffer ~= strToByte_hex(MD5(buffer)[0 .. 4]);

        return buffer;
    }

    static size_t parseInfo(ubyte[] buffer, out string name, out string method)
    {
        enforce(buffer != null && buffer.length >= 10, "Incorrect buffer length.");

        ushort len1 = buffer.peek!ushort(6);
        if (len1 > 0)
        {
            name = cast(string) buffer[8 .. 8 + len1];
        }

        ushort len2 = buffer.peek!ushort(8 + len1);
        if (len2 > 0)
        {
            method = cast(string) buffer[10 + len1 .. 10 + len1 + len2];
        }

        return 10 + len1 + len2;
    }

    static Variant[] parse(ubyte[] buffer, ushort magic, CryptType crypt, string key, Nullable!RSAKeyInfo rsaKey, out string name, out string method)
    {
        enforce(buffer != null && buffer.length >= 10, "Incorrect buffer length.");

        ushort t_magic;
        int t_len;
        t_magic = buffer.peek!ushort(0);
        t_len = buffer.peek!int(2);

        if ((t_magic != magic) || (t_len > cast(int)buffer.length - 6))
        {
            return null;
        }

        buffer = buffer[0 .. t_len + 6];
        if (strToByte_hex(MD5(buffer[0 .. $ - 2])[0 .. 4]) != buffer[$ - 2 .. $])
        {
            return null;
        }

        size_t tlv_pos = parseInfo(buffer, name, method);
        buffer = buffer[tlv_pos .. $ - 2];

        final switch (crypt)
        {
        case CryptType.NONE:
            break;
        case CryptType.XTEA:
            buffer = Xtea.decrypt(buffer, key, 64, PaddingMode.PKCS5);
            break;
        case CryptType.AES:
            buffer = AESUtils.decrypt!AES128(buffer, key, iv, PaddingMode.PKCS5);
            break;
        case CryptType.RSA:
            buffer = RSA.decrypt(rsaKey, buffer);
            break;
        case CryptType.RSA_XTEA_MIXIN:
            buffer = RSA.decrypt(rsaKey, buffer, true);
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
            else if (typeId == TypeID!real)
            {
                //get!real;
                ret ~= Variant(ubyteToReal(buffer[pos .. pos + real.sizeof]));
                pos += real.sizeof;
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

private:

    static ubyte[] iv = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
}

class BufferBuilder
{
    public ubyte[]* buffer;

    this(ubyte[]* buffer)
    {
        this.buffer = buffer;
    }

    size_t put(T)(T value, bool isWriteTypeInfo, bool isWriteLengthInfo, int lengthBytes)
    {
        assert(lengthBytes == 0 || lengthBytes == 2 || lengthBytes == 4);

        ubyte[] buf_data;
        size_t len;

        if (isWriteTypeInfo)
        {
            *buffer ~= TypeID!T;
        }

        static if (is(Unqual!T == string))
        {
            buf_data = cast(ubyte[])value;
            len = buf_data.length;
        }
        else static if (is(Unqual!T == real))
        {
            buf_data = realToUByte(value);
            len = real.sizeof;
        }
        else
        {
            buf_data = new ubyte[T.sizeof];
            buf_data.write!T(value, 0);
            len = T.sizeof;
        }

        if (isWriteLengthInfo && lengthBytes > 0)
        {
            ubyte[] buf_len = new ubyte[lengthBytes];
            if (lengthBytes == 2)
                buf_len.write!ushort(cast(ushort)len, 0);
            else
                buf_len.write!int(cast(int)len, 0);

            *buffer ~= buf_len;
        }

        *buffer ~= buf_data;

        return len;
    }
}
