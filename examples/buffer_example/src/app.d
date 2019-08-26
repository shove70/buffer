import std.stdio;

import buffer.message;

mixin(LoadBufferFile!"message.buffer");

mixin(LoadBufferScript!`
    message Sample {
        string  name;
        int32   age;
        int16   sex;
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
    string publicKey      = "AAAAIEsD3P0HLddeKShoVDfNCdOl6krCWBS/FPTyWCf15tOZ/2U=";
    string privateKey     = "AAAAIEsD3P0HLddeKShoVDfNCdOl6krCWBS/FPTyWCf15tOZOD1j37Rl0gAyVRNy7AVBbFrdERVgxJE1OxHm6AGajXE=";

    // Set magic number, encryption method and key.
    Message.settings(1229, CryptType.RSA_XTEA_MIXIN, publicKey);

    Sample sample = new Sample();
    sample.name = "Tom";
    sample.age = 20;
    sample.sex = 1;
    ubyte[] buf = sample.serialize();
    writeln(buf);

    Message.settings(1229, CryptType.RSA_XTEA_MIXIN, privateKey);
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
