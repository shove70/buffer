import std.stdio;

import buffer.message;

mixin (LoadBufferFile!"message.buffer");

mixin (LoadBufferScript!`
	message Sample {
		string	name;
		int32	age;
		int16	sex;
	}
`);

void main()
{
	Register register = new Register();
	register.settings(1229, 1, 0xFF, CryptType.XTEA, "1234");
	register.name = "Tom";
	register.password = "123456";
	register.age = 20;
	ubyte[] buf = register.serialize();
	
	register = Message.deserialize!Register(buf, 1229, CryptType.XTEA, "1234");
	writeln(register.name);
	writeln(register.password);
	writeln(register.age);
}
