module buffer.rpc.server;

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

    ubyte[] Handler(string Package = string.init, Stuff...)(ubyte[] data, Stuff stuff)
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
            alias MemberFunctionsTuple!(Business, member) funcs;

            static if (funcs.length > 0 && !canFind(builtinFunctions, member))
            {
                static assert(funcs.length == 1, "The function of RPC call doesn't allow the overloads, function: " ~ member);

                alias typeof(funcs[0]) func;
                alias ParameterTypeTuple!func ParameterTypes;
                alias ReturnType!func T;

                static assert((
                        is(T == byte) || is(T == ubyte)  || is(T == short) || is(T == ushort) || is(T == int)  || is(T == uint)
                     || is(T == long) || is(T == ulong)  || is(T == float) || is(T == double) || is(T == real) || is(T == bool)
                     || is(T == char) || is(T == string) || ((BaseTypeTuple!T.length > 0) && is(BaseTypeTuple!T[0] == Message))),
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
