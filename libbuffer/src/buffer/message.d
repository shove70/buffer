module buffer.message;

import std.traits;
import std.stdio;
import std.conv;
import std.bitmanip;
import std.typecons;

import cryption.rsa;
import cryption.tea.xtea;

public import buffer.compiler;
import buffer.utils;

enum CryptType
{
	NONE	= 0,
	XTEA	= 1,
	RSA		= 2
}

abstract class Message
{
public:

	alias byte			int8;
	alias ubyte			uint8;
	alias short			int16;
	alias ushort		uint16;
	alias int			int32;
	alias uint			uint32;
	alias long			int64;
	alias ulong			uint64;
	alias float			float32;
	alias double		float64;
	//string

	void settings(ushort magic, ushort msgVersion, ushort method, CryptType crypt = CryptType.NONE, string key = string.init)
	{
		this._magic			= magic;
		this._msgVersion	= msgVersion;
		this._method		= method;
		this._crypt			= crypt;
		this._key			= key;
		
		if (this._crypt == CryptType.RSA && this._key != string.init)
		{
			this._rsaKey = RSA.decodeKey(this._key);
		}
	}
	
	void settings(ushort magic, ushort msgVersion, ushort method, RSAKeyInfo key)
	{
		settings(magic, msgVersion, method);

		this._crypt			= CryptType.RSA;
		this._rsaKey		= key;
	}

	static T deserialize(T)(ubyte[] buffer, ushort magic, CryptType crypt = CryptType.NONE, string key = string.init)
	{
		if (crypt == CryptType.RSA && key != string.init)
		{
			RSAKeyInfo rsaKey = RSA.decodeKey(key);
			return deserialize!T(buffer, magic, rsaKey);
		}
		
		return deserialize!T(buffer, magic, crypt, key, Nullable!RSAKeyInfo());
	}
	
	static T deserialize(T)(ubyte[] buffer, ushort magic, RSAKeyInfo key)
	{
		return deserialize!T(buffer, magic, CryptType.RSA, string.init, Nullable!RSAKeyInfo(key));
	}

protected:

	ushort				_magic;
	ushort				_msgVersion;
	ushort				_method;
	CryptType			_crypt;
	string				_key;
	Nullable!RSAKeyInfo	_rsaKey;
	
	ubyte[] serialize(T)(Message message)
	{
		T m = cast(T)message;

		ubyte[] temp1, temp2;

		ubyte[] tlv = new ubyte[4];
		tlv.write!ushort(_msgVersion,	0);
		tlv.write!ushort(_method,		2);

		foreach(i, type; Fields!T) {
			static if (is(type == string)) {
				mixin("
					temp1 = new ubyte[4];
					temp2 = cast(ubyte[])m." ~ getFieldName!(T, i) ~ ";
					temp1.write!int(cast(int)temp2.length, 0);
					tlv ~= temp1;
					tlv ~= temp2;
				");
			} else {
				mixin("
					temp1 = new ubyte[" ~ getTypeSize!(type).to!string ~ "];
					temp1.write!" ~ type.stringof ~ "(m." ~ getFieldName!(T, i) ~ ", 0);
					tlv ~= temp1;
				");
			}
		}

		final switch(this._crypt)
		{
			case CryptType.NONE:
				break;
			case CryptType.XTEA:
				tlv = xteaEncrypt(tlv, this._key);
				break;
			case CryptType.RSA:
				tlv = RSA.encrypt(this._rsaKey, tlv);
				break;
		}
		
		ubyte[] buffer = new ubyte[6];
		buffer.write!ushort(_magic, 0);
		buffer.write!int(cast(int)tlv.length + 2, 2);
		buffer ~= tlv;
		buffer ~= strToByte_hex(MD5(buffer)[0..4]);
		
		return buffer;
	}
	
private:

	template getFieldName(Type, size_t i)
	{
	    static assert((is(Unqual!Type == class) || is(Unqual!Type == struct)), "Type must be class or struct: type = " ~ Type.stringof);
	    static assert(i < Type.tupleof.length, text(Type.stringof, " has ", Type.tupleof.length, " attributes: given index = ", i));
	
	    enum getFieldName = __traits(identifier, Type.tupleof[i]);
	}
	
	template getTypeSize(Type)
	{
		enum getTypeSize = Type.sizeof;
	}

	static T deserialize(T)(ubyte[] buffer, ushort magic, CryptType crypt, string key, Nullable!RSAKeyInfo rsaKey = Nullable!RSAKeyInfo())
	{
		if (buffer.length < 12)
			return null;

		ushort t_magic, t_crc;
		int t_len;
		t_magic = buffer.peek!ushort(0);
		t_len = buffer.peek!int(2);
		
		if ((t_magic != magic) || (t_len > buffer.length - 6))
			return null;

		buffer = buffer[0..t_len + 6];
		t_crc = buffer.peek!ushort(buffer.length - 2);
		if (strToByte_hex(MD5(buffer[0..$ - 2])[0..4]) != buffer[$ - 2..$])
			return null;

		buffer = buffer[6..$ - 2];

		final switch(crypt)
		{
			case CryptType.NONE:
				break;
			case CryptType.XTEA:
				buffer = xteaDecrypt(buffer, key);
				break;
			case CryptType.RSA:
				buffer = RSA.decrypt(rsaKey, buffer);
				break;
		}

		ushort t_msgVersion, t_method;
		t_msgVersion	= buffer.peek!ushort(0);
		t_method		= buffer.peek!ushort(2);
		buffer 			= buffer[4..$];

		T message = new T();
        
        message._magic		= magic;
        message._msgVersion	= t_msgVersion;
        message._method		= t_method;
        message._crypt		= crypt;
        message._key		= key;
        message._rsaKey		= rsaKey;

		int temp, pos;
		foreach(i, type; Fields!(T)) {
			static if (is(type == string)) {
				mixin("
					temp = buffer.peek!int(pos);
					pos += 4;
					message." ~ getFieldName!(T, i) ~ " = cast(string)buffer[pos..pos + temp];
					pos += temp;
				");
			} else {
				mixin("
					message." ~ getFieldName!(T, i) ~ " = buffer.peek!" ~ type.stringof ~ "(pos);
					pos += " ~ getTypeSize!(type).to!string ~ ";
				");
			}
		}

		return message;
	}
}

import buffer.message;

final class Sample : buffer.message.Message
{
	int32 age;
	string name;
	int16 age2;

	ubyte[] serialize()
	{
		return super.serialize!(typeof(this))(this);
	}
}