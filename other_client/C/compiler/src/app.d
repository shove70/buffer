import std.array;
import std.stdio;
import std.file;
import std.path;
import std.algorithm;
import std.conv;
import std.string;
import std.uni;

import buffer.compiler;

void main(string[] args)
{
    if (args.length < 3)
    {
        writeln("Usage: ./buffc src_path dst_path");
        return;
    }

    string src = args[1];
    string dst = args[2];

    if (!std.file.exists(src))
    {
        writeln("The src path" ~ src ~ " not exists.");
        return;
    }
    
    if (std.file.isFile(src))
    {
        writeln("The src path" ~ src ~ " is a file, not a path.");
        return;
    }

    if (std.file.exists(dst) && std.file.isFile(dst))
    {
        writeln("The dst path" ~ src ~ " is a file, not a path.");
        return;
    }

    string libIncludePath = "{ Replace the real path }";

    if (args.length >= 4)
    {
        libIncludePath = "../components/buffc";
    }

    std.file.mkdirRecurse(dst);
    
    foreach (DirEntry e; dirEntries(src, SpanMode.shallow).filter!(a => a.isFile))
    {
        string srcFile = e.name;
        if (toLower(std.path.extension(srcFile)) != ".buffer")
        {
            continue;
        }
        string fileName = baseName(e.name, ".buffer");
        string dstFilename = buildPath(dst, fileName ~ ".h");

        Token[] tokens = lexer(std.file.readText(e.name));
        Sentence[] sentences = parser(tokens);
        
        Appender!string code;
        code.put("#pragma once\r\n\r\n");
        code.put("#include <vector>\r\n");
        code.put("#include \"" ~ libIncludePath ~ "/message.h\"\r\n\r\n");
        code.put("using namespace std;\r\n");
        code.put("using namespace buffer;\r\n\r\n");
    
        foreach (sentence; sentences)
        {
            code.put("class " ~ sentence.name ~ " : Message\r\n");
            code.put("{\r\n");
            code.put("public:\r\n");
            code.put("\tstring _className() { return \"" ~ sentence.name ~ "\"; }\r\n\r\n");

            foreach (field; sentence.fields)
            {
                code.put("\t" ~ field.type ~ " " ~ field.name ~ ";\r\n");
            }
    
            code.put("\r\n");
            code.put("\tvoid setValue(vector<Any>& params)\r\n");
            code.put("\t{\r\n");
    
            foreach (i, field; sentence.fields)
            {
                code.put("\t\t" ~ field.name ~ " = params[" ~ i.to!string ~ "].cast<" ~ field.type ~ ">();\r\n");
            }
    
            code.put("\t}\r\n\r\n");
            code.put("\tvoid serialize(vector<ubyte>& buffer, string method = \"\")\r\n");
            code.put("\t{\r\n");
            code.put("\t\tMessage::serialize(buffer, \"" ~ sentence.name ~ "\", method");
    
            foreach (i, field; sentence.fields)
            {
                code.put(", " ~ field.name);
            }
    
            code.put(");\r\n");
            code.put("\t}\r\n");
            code.put("};\r\n\r\n");
        }
    
        std.file.write(dstFilename, cast(ubyte[])code.data);
    }
}