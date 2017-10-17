module buffer.utils;

import std.conv;
import std.string;
import std.digest.md;
import std.array;

import cryption.tea.xtea;

public string MD5(scope const(void[])[] src...)
{
	auto md5 = new MD5Digest();
	ubyte[] hash = md5.digest(src);
	
    return toHexString(hash).toUpper();
}

public ubyte[] strToByte_hex(string input)
{
	Appender!(ubyte[]) app;
	for (int i; i < input.length; i += 2)
	{
		app.put(input[i .. i + 2].to!ubyte(16));
	}
	
	return app.data;
}

public string byteToStr_hex(T = byte)(T[] buffer)
{
	Appender!string app;
	foreach (b; buffer)
	{
		app.put(rightJustify(b.to!string(16).toUpper(), 2, '0'));
	}
	return app.data;
}