import std.stdio;

import buffer.message;

mixin (LoadBufferFile!"message.buffer");

mixin (LoadBufferScript!`
	message(3) Sample {
		string	name;
		int32	age;
		int16	sex;
	}
`);

void main()
{
	Message.settings(1229, CryptType.XTEA, "1234");

	Sample sample = new Sample();
	sample.name = "Tom";
	sample.age = 20;
	sample.sex = 1;
	ubyte[] buf = sample.serialize();
	writeln(buf);
	
	Sample sam = Message.deserialize!Sample(buf);
	writeln("msgid:\t", sam.messageId);
	writeln("name:\t", sam.name);
	writeln("age:\t", sam.age);
	writeln("sex:\t", sam.sex);
}
