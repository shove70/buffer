module buffer.rpc.server;

import std.meta : staticIndexOf;
import std.traits;
import std.algorithm.searching;
import std.conv : to;
import std.variant;

import buffer.message;

class Server(Business)
{
    static immutable string[] builtinFunctions = [ "__ctor", "__dtor", "opEquals", "opCmp", "toHash", "toString", "Monitor", "factory" ];
    private Business business = new Business();

    this()
    {
        business = new Business();
    }

    ubyte[] Handler(string Package = string.init, Stuff...)(const ubyte[] data, Stuff stuff)
    {
        string name;
        string method;
        Variant[] params = Message.deserialize(data, name, method);
        foreach (s; stuff)
        {
            params ~= Variant(s);
        }

        foreach (member; __traits(allMembers, Business))
        {
            alias funcs = MemberFunctionsTuple!(Business, member);

            static if (funcs.length > 0 && !canFind(builtinFunctions, member))
            {
                static assert(funcs.length == 1, "The function of RPC call doesn't allow the overloads, function: " ~ member);

                alias func = typeof(funcs[0]);
                alias ParameterTypes = ParameterTypeTuple!func;
                alias T = ReturnType!func;

                static assert((staticIndexOf!(T, supportedBuiltinTypes) != -1) || ((BaseTypeTuple!T.length > 0) && is(BaseTypeTuple!T[0] == Message)),
                        "The function of RPC call return type is incorrect, function: " ~ member);

                static if (Package != string.init)
                {
                    mixin("import " ~ Package ~ ";");
                }

                static if (isBuiltinType!T)
                {
                    mixin(`
                        if (method == "` ~ member ~ `")
                        {
                            if (params.length < ` ~ ParameterTypes.length.to!string ~ `)
                            {
                                import std.stdio;
                                writeln("Incorrect number of parameters, ` ~ member ~ ` requires ` ~ ParameterTypes.length.to!string ~ ` parameters.");
                                assert(0, "Incorrect number of parameters, ` ~ member ~ ` requires ` ~ ParameterTypes.length.to!string ~ ` lengthString!(ParameterTypes.length).");
                            }

                            T ret = business.` ~ member ~ `(` ~ combineParams!ParameterTypes ~ `);

                            return Message.serialize_without_msginfo(method, ret);
                        }
                    `);
                }
                else
                {
                    mixin(`
                        if (method == "` ~ member ~ `")
                        {
                            if (params.length < ` ~ ParameterTypes.length.to!string ~ `)
                            {
                                import std.stdio;
                                writeln("Incorrect number of parameters, ` ~ member ~ ` requires ` ~ ParameterTypes.length.to!string ~ ` parameters.");
                                assert(0, "Incorrect number of parameters, ` ~ member ~ ` requires ` ~ ParameterTypes.length.to!string ~ ` parameters.");
                            }

                            T ret = business.` ~ member ~ `(` ~ combineParams!ParameterTypes ~ `);

                            if (ret is null)
                            {
                                return null;
                            }

                            return ret.serialize();
                        }
                    `);
                }
            }
        }

        assert(0, "The server does not implement client call method: " ~ method);
    }

    private static string combineParams(ParameterTypes...)()
    {
        string s;

        foreach (i, type; ParameterTypes)
        {
            if (i > 0) s ~= ", ";

            s ~= ("params[" ~ i.to!string ~ "].get!" ~ type.stringof);
        }

        return s;
    }
}
