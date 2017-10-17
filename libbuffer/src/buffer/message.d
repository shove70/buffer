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
		assert(Message._crypt == CryptType.NONE || (Message._crypt != CryptType.NONE && Message._key != string.init), "Must specify key when specifying the type of CryptType.");
		
		Message._magic	= magic;
		Message._crypt	= crypt;
		Message._key	= key;
		
		if (Message._crypt == CryptType.RSA)
		{
			Message._rsaKey = RSA.decodeKey(Message._key);
		}
	}

	static TypeInfo_Class getMessageTypeInfo(ubyte[] buffer)
	{
		if (buffer.length < 10)
			return null;
		
		ushort t_messageId = buffer.peek!ushort(6);
		if (t_messageId in _messages)
			return _messages[t_messageId];
			
		return null;
	}

	static T deserialize(T)(ubyte[] buffer)
	{
		if (buffer.length < 10)
			return null;

		ushort t_magic, t_crc;
		int t_len;
		t_magic = buffer.peek!ushort(0);
		t_len = buffer.peek!int(2);
		
		if ((t_magic != Message._magic) || (t_len > buffer.length - 6))
			return null;

		buffer = buffer[0..t_len + 6];
		t_crc = buffer.peek!ushort(buffer.length - 2);
		if (strToByte_hex(MD5(buffer[0..$ - 2])[0..4]) != buffer[$ - 2..$])
			return null;
		
		ushort t_messageId = buffer.peek!ushort(6);
		T message = new T();
		if (message.messageId != t_messageId)
		{
			throw new Exception("The type T(" ~ T.classinfo.name ~ ") of the incoming template is incorrect. It should be " ~ _messages[t_messageId].name);
		}

		buffer = buffer[8..$-2];
		final switch(Message._crypt)
		{
			case CryptType.NONE:
				break;
			case CryptType.XTEA:
				buffer = xteaDecrypt(buffer, Message._key);
				break;
			case CryptType.RSA:
				buffer = RSA.decrypt(Message._rsaKey, buffer);
				break;
		}

		int temp, pos;
		foreach(i, type; FieldTypeTuple!(T)) {
			static if (is(type == string)) {
				mixin("
					temp = buffer.peek!int(pos);
					pos += 4;
					message." ~ FieldNameTuple!T[i] ~ " = cast(string)buffer[pos..pos + temp];
					pos += temp;
				");
			} else {
				mixin("
					message." ~ FieldNameTuple!T[i] ~ " = buffer.peek!" ~ type.stringof ~ "(pos);
					pos += " ~ type.sizeof.to!string ~ ";
				");
			}
		}

		return message;
	}

protected:

	ubyte[] serialize(T)(T message)
	{
		ubyte[] temp1, temp2;
		ubyte[] tlv;

		foreach(i, type; FieldTypeTuple!T) {
			static if (is(type == string)) {
				mixin("
					temp1 = new ubyte[4];
					temp2 = cast(ubyte[])message." ~ FieldNameTuple!T[i] ~ ";
					temp1.write!int(cast(int)temp2.length, 0);
					tlv ~= temp1;
					tlv ~= temp2;
				");
			} else {
				mixin("
					temp1 = new ubyte[" ~ type.sizeof.to!string ~ "];
					temp1.write!" ~ type.stringof ~ "(message." ~ FieldNameTuple!T[i] ~ ", 0);
					tlv ~= temp1;
				");
			}
		}

		final switch(Message._crypt)
		{
			case CryptType.NONE:
				break;
			case CryptType.XTEA:
				tlv = xteaEncrypt(tlv, Message._key);
				break;
			case CryptType.RSA:
				tlv = RSA.encrypt(Message._rsaKey, tlv);
				break;
		}
		
		ubyte[] buffer = new ubyte[8];
		buffer.write!ushort(Message._magic, 0);
		buffer.write!int(cast(int)tlv.length + 4, 2);
		buffer.write!ushort(messageId, 6);
		buffer ~= tlv;
		buffer ~= strToByte_hex(MD5(buffer)[0..4]);
		
		return buffer;
	}

	ushort _messageId;
	__gshared static TypeInfo_Class[ushort] _messages;

private:

	__gshared static ushort					_magic;
	__gshared static CryptType				_crypt;
	__gshared static string					_key;
	__gshared static Nullable!RSAKeyInfo	_rsaKey;
}
