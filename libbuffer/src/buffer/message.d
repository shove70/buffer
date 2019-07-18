module buffer.message;

import std.traits;
import std.typecons;
import std.variant;
import std.conv : to;
import std.exception;

import crypto.rsa;

public import buffer.compiler;
public import buffer.packet;
import buffer.utils;

///
abstract class Message
{
public:

    alias int8     = byte;
    alias uint8    = ubyte;
    alias int16    = short;
    alias uint16   = ushort;
    alias int32    = int;
    alias uint32   = uint;
    alias int64    = long;
    alias uint64   = ulong;
    alias float32  = float;
    alias float64  = double;
    alias float128 = real;
    //bool
    //char
    //string

    ///
    static void settings(ushort magic, CryptType crypt = CryptType.NONE, string key = string.init)
    {
        assert((crypt == CryptType.NONE) || (crypt != CryptType.NONE && key != string.init),
                "Must specify key when specifying the type of CryptType.");

        _magic = magic;
        _crypt = crypt;
        _key   = key;

        if ((_crypt == CryptType.RSA) || (_crypt == CryptType.RSA_XTEA_MIXIN))
        {
            _rsaKey = RSA.decodeKey(Message._key);

            enforce(!_rsaKey.isNull, "Rsakey is incorrect.");
        }
    }

    ///
    static void settings(ushort magic, RSAKeyInfo rsaKey, bool mixinXteaMode = false)
    {
        _magic = magic;
        _crypt = mixinXteaMode ? CryptType.RSA_XTEA_MIXIN : CryptType.RSA;
        _rsaKey = rsaKey;
    }

    ///
    static ubyte[] serialize_without_msginfo(Params...)(string method, Params params)
    {
        Variant[] t_params;

        foreach(p; params)
        {
            t_params ~= Variant(p);
        }

        return Packet.build(_magic, _crypt, _key, _rsaKey, string.init, method, t_params);
    }

    static void getMessageInfo(ubyte[] buffer, out string name, out string method)
    {
        Packet.parseInfo(buffer, name, method);
    }

    ///
    static Variant[] deserialize(ubyte[] buffer, out string name, out string method)
    {
        return Packet.parse(buffer, _magic, _crypt, _key, _rsaKey, name, method);
    }

    ///
    static T deserialize(T)(ubyte[] buffer)
    if ((BaseTypeTuple!T.length > 0) && is(BaseTypeTuple!T[0] == Message))
    {
        string method;

        return deserialize!T(buffer, method);
    }

    ///
    static T deserialize(T)(ubyte[] buffer, out string method)
    if ((BaseTypeTuple!T.length > 0) && is(BaseTypeTuple!T[0] == Message))
    {
        string name;
        const Variant[] params = deserialize(buffer, name, method);

        if (name == string.init || params == null)
        {
            return null;
        }

        T message = new T();
        if (getClassSimpleName(T.classinfo.name) != name)
        {
            assert(0, "The type T(" ~ T.classinfo.name ~ ") of the incoming template is incorrect. It should be " ~ name);
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

    ubyte[] serialize(T)(T message, string method = string.init)
    if ((BaseTypeTuple!T.length > 0) && is(BaseTypeTuple!T[0] == Message))
    {
        assert(message !is null, "The object to serialize cannot be null.");

        Variant[] params;

        foreach (i, type; FieldTypeTuple!T)
        {
            mixin(`
                params ~= Variant(message.` ~ FieldNameTuple!T[i] ~ `);
            `);
        }

        return Packet.build(_magic, _crypt, _key, _rsaKey, getClassSimpleName(T.classinfo.name), method, params);
    }

private:

    __gshared ushort              _magic;
    __gshared CryptType           _crypt;
    __gshared string              _key;
    __gshared Nullable!RSAKeyInfo _rsaKey;
}
