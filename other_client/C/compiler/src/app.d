import std.array;
import std.stdio;
import std.file;
import std.conv;
import std.string;

import buffer.compiler;

void main(string[] args)
{
    if (args.length < 3)
    {
        writeln("Usage: ./buffc input_filename(.buffer) output_filename(.h)");
        return;
    }

    Token[] tokens = lexer(std.file.readText(args[1]));
    Sentence[] sentences = parser(tokens);
    
    Appender!string code;
    code.put("#pragma once\r\n\r\n");
    code.put("#include <vector>\r\n");
    code.put("#include \"message.h\"\r\n\r\n");
    code.put("using namespace std;\r\n");
    code.put("using namespace buffc;\r\n\r\n");

    foreach (sentence; sentences)
    {
        code.put("class " ~ sentence.name ~ " : Message {\r\n");
        code.put("public:\r\n");
        code.put("\tstring _className = \"" ~ sentence.name ~ "\";\r\n\r\n");

        foreach (field; sentence.fields)
        {
            code.put("\t" ~ field.type ~ " " ~ field.name ~ ";\r\n");
        }

        code.put("\r\n");
        code.put("\tvoid setValue(vector<Any>& params) {\r\n");

        foreach (i, field; sentence.fields)
        {
            code.put("\t\t" ~ field.name ~ " = params[" ~ i.to!string ~ "].cast<" ~ field.type ~ ">();\r\n");
        }

        code.put("\t}\r\n\r\n");
        code.put("\tvoid serialize(vector<ubyte>& buffer, string method = \"\") {\r\n");
        code.put("\t\tMessage::serialize(buffer, \"" ~ sentence.name ~ "\", method");

        foreach (i, field; sentence.fields)
        {
            code.put(", " ~ field.name);
        }

        code.put(");\r\n");
        code.put("\t}\r\n");
        code.put("};\r\n");
    }

    std.file.write(args[2], cast(ubyte[])code.data);
}