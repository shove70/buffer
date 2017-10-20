module buffer.rpc.client;

import std.traits;
import std.conv : to;

import buffer.message;

alias TcpRequestHandler = ubyte[]delegate(ubyte[] data);

class Client
{
    static TcpRequestHandler handler = null;

    static void bindTcpRequestHandler(TcpRequestHandler handler)
    {
        Client.handler = handler;
    }

    static T2 call(T1, T2, Params...)(string method, Params params)
    {
        assert(handler != null, "TcpRequestHandler must be bound.");
        assert(method.length > 0, "Paramter method must be set.");

        alias fieldTypes = FieldTypeTuple!T1;
        static assert(fieldTypes.length == params.length, "Incorrect number of parameters, " ~ T1.stringof ~ " requires " ~ fieldTypes.length.to!string ~ " parameters.");

        T1 t1 = new T1();

        static foreach (i, type; FieldTypeTuple!T1)
        {
            mixin("
                t1." ~ FieldNameTuple!T1[i] ~ " = params[" ~ i.to!string ~ "];
            ");
        }

        return Message.deserialize!T2(handler(t1.serialize(method)));
    }
}
