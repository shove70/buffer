module buffer.packet;

import std.meta : AliasSeq, staticIndexOf;
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

/// All encryption supported.
enum CryptType
{
    NONE            = 0,
    XTEA            = 1,
    AES             = 2,
    RSA             = 3,
    RSA_XTEA_MIXIN  = 4
}

package:

/// These two items must correspond one by one.
alias supportedBuiltinTypes = AliasSeq!(     byte, ubyte, short, ushort, int,  uint, long, ulong, float, double, real, bool, char, string);
immutable byte[] supportedBuiltinTypeNos = [ 0x01, 0x02,  0x03,  0x04,   0x05, 0x06, 0x07, 0x08,  0x20,  0x21,   0x22, 0x30, 0x40, 0x41 ];

/// Convert Type to TypeNo.
template TypeNo(T)
{
    enum idx = staticIndexOf!(T, supportedBuiltinTypes);
    static assert(idx != -1, "Data types that are not supported: " ~ typeid(T));
    enum TypeNo = supportedBuiltinTypeNos[idx];
}

alias write = std.bitmanip.write;

class Packet
{
    static ubyte[] build(const ushort magic, const CryptType crypt, const string key, Nullable!RSAKeyInfo rsaKey,
        const string name, const string method, Variant[] params)
    {
        assert(name.length <= 255, "Paramter name cannot be greater than 255 characters.");
        assert(method.length <= 255, "Paramter method cannot be greater than 255 characters.");

        ubyte[] tlv;
        BufferBuilder bb = new BufferBuilder(&tlv);

        foreach (v; params)
        {
            bool typeValid;
            static foreach (T; supportedBuiltinTypes)
            {
                if (v.type == typeid(T))
                {
                    static if (is(T == string))
                        bb.put!T(v.get!T, true, true, 4);
                    else
                        bb.put!T(v.get!T, true, false, 0);
                    typeValid = true;
                }
                else if (v.type == typeid(ConstOf!T))
                {
                    static if (is(Unique!T == string))
                        bb.put!T(v.get!(const T), true, true, 4);
                    else
                        bb.put!T(v.get!(const T), true, false, 0);
                    typeValid = true;
                }
                else if (v.type == typeid(SharedOf!T))
                {
                    static if (is(Unique!T == string))
                        bb.put!T(v.get!(shared T), true, true, 4);
                    else
                        bb.put!T(v.get!(shared T), true, false, 0);
                    typeValid = true;
                }
                else if (v.type == typeid(SharedConstOf!T))
                {
                    static if (is(Unique!T == string))
                        bb.put!T(v.get!(shared const T), true, true, 4);
                    else
                        bb.put!T(v.get!(shared const T), true, false, 0);
                    typeValid = true;
                }
                else if (v.type == typeid(ImmutableOf!T))
                {
                    static if (is(Unique!T == string))
                        bb.put!T(v.get!(immutable T), true, true, 4);
                    else
                        bb.put!T(v.get!(immutable T), true, false, 0);
                    typeValid = true;
                }
            }

            assert(typeValid, "Data types id that are not supported: " ~ v.type.toString);
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
                tlv = RSA.encrypt(rsaKey.get, tlv);
                break;
            case CryptType.RSA_XTEA_MIXIN:
                tlv = RSA.encrypt(rsaKey.get, tlv, true);
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

    static size_t parseInfo(const ubyte[] buffer, out string name, out string method)
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

    static Variant[] parse(const ubyte[] buffer, const ushort magic, const CryptType crypt, const string key, Nullable!RSAKeyInfo rsaKey, out string name, out string method)
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

        ubyte[] buf = cast(ubyte[]) buffer[0 .. t_len + 6];
        if (strToByte_hex(MD5(buf[0 .. $ - 2])[0 .. 4]) != buf[$ - 2 .. $])
        {
            return null;
        }

        size_t tlv_pos = parseInfo(buf, name, method);
        buf = buf[tlv_pos .. $ - 2];

        final switch (crypt)
        {
            case CryptType.NONE:
                break;
            case CryptType.XTEA:
                buf = Xtea.decrypt(buf, key, 64, PaddingMode.PKCS5);
                break;
            case CryptType.AES:
                buf = AESUtils.decrypt!AES128(buf, key, iv, PaddingMode.PKCS5);
                break;
            case CryptType.RSA:
                buf = RSA.decrypt(rsaKey.get, buf);
                break;
            case CryptType.RSA_XTEA_MIXIN:
                buf = RSA.decrypt(rsaKey.get, buf, true);
                break;
        }

        ubyte typeNo;
        int pos;
        Variant[] ret;

        while (pos < buf.length)
        {
            typeNo = buf[pos];
            pos++;

            bool typeValid;
            static foreach (idx, T; supportedBuiltinTypes)
            {
                if (typeNo == supportedBuiltinTypeNos[idx])
                {
                    typeValid = true;

                    static if (is(T == real))
                    {
                        //get!real;
                        ret ~= Variant(ubytesToReal(buf[pos .. pos + real.sizeof]));
                        pos += real.sizeof;
                    }
                    else static if (is(T == string))
                    {
                        immutable temp = buf.peek!int(pos);
                        pos += 4;
                        ret ~= Variant(cast(string) buf[pos .. pos + temp]);    // !! May be: invalid UTF-8 sequence.
                        pos += temp;
                    }
                    else
                    {
                        ret ~= Variant(buf.peek!T(pos));
                        pos += T.sizeof;
                    }
                }
            }
            assert(typeValid, "Data types id that are not supported: " ~ typeNo.to!string);
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

    size_t put(T)(const T value, const bool isWriteTypeInfo, const bool isWriteLengthInfo, const int lengthBytes)
    {
        assert(lengthBytes == 0 || lengthBytes == 2 || lengthBytes == 4);

        ubyte[] buf_data;
        size_t len;

        if (isWriteTypeInfo)
        {
            *buffer ~= TypeNo!T;
        }

        static if (is(Unqual!T == string))
        {
            buf_data = cast(ubyte[])value;
            len = buf_data.length;
        }
        else static if (is(Unqual!T == real))
        {
            buf_data = realToUBytes(value);
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
