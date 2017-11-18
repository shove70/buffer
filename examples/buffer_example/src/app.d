import std.stdio;

import buffer;

mixin(LoadBufferFile!"message.buffer");

mixin(LoadBufferScript!`
	message Sample {
		string	name;
		int32	age;
		int16	sex;
	}
`);

// Simple:
void main()
{
    Sample sample = new Sample();
    sample.name = "Tom";
    sample.age = 20;
    sample.sex = 1;
    ubyte[] buf = sample.serialize();
    writeln(buf);

    Sample sam = Message.deserialize!Sample(buf);
    writeln("name:\t",  sam.name);
    writeln("age:\t",   sam.age);
    writeln("sex:\t",   sam.sex);
}

// Advanced:
void main_()
{
    // Set magic number, encryption method and key.
    Message.settings(1229, CryptType.XTEA, "1234");

    Sample sample = new Sample();
    sample.name = "Tom";
    sample.age = 20;
    sample.sex = 1;
    ubyte[] buf = sample.serialize();
    writeln(buf);

    string name;
    string method;
    Message.getMessageInfo(buf, name, method);

    switch (name)
    {
    case "Sample":
        Sample sam = Message.deserialize!Sample(buf);
        writeln("name:\t",  sam.name);
        writeln("age:\t",   sam.age);
        writeln("sex:\t",   sam.sex);
        break;
    case "...":
        break;
    default:
        break;
    }
}
