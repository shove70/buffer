module buffer.rpc.client;

import std.traits;
import std.conv : to;
import std.variant;

import buffer.message;

alias TcpRequestHandler = ubyte[]delegate(ubyte[] data);

class Client
{
    static TcpRequestHandler handler = null;

    static void bindTcpRequestHandler(TcpRequestHandler handler)
    {
        Client.handler = handler;
    }

    static T call(T, Params...)(string method, Params params) if (
            is(T == byte) || is(T == ubyte) || is(T == short) || is(T == ushort) || is(T == int)  || is(T == uint)
         || is(T == long) || is(T == ulong) || is(T == float) || is(T == double) || is(T == bool) || is(T == char)
         || is(T == string) || (BaseTypeTuple!T.length > 0 && is(BaseTypeTuple!T[0] == Message)))
    {
        assert(handler != null, "TcpRequestHandler must be bound.");
        assert(method.length > 0, "Paramter method must be set.");

        ubyte[] response = handler(Message.serialize_without_msginfo(method, params));
        ushort messageId;
        TypeInfo_Class messageName;
        string res_method;
        Variant[] res_params = Message.deserialize(response, messageId, messageName, res_method);
        
        //assert(method == res_method);

        static if (isBuiltinType!T)
        {
            assert(res_params.length == 1, "The number of response parameters from the server is incorrect.");

            return res_params[0].get!T;
        }
        else
        {
            alias FieldTypes = FieldTypeTuple!T;
            static assert(FieldTypes.length == params.length, "Incorrect number of parameters, " ~ T.stringof ~ " requires " ~ FieldTypes.length.to!string ~ " parameters.");

            T message = new T();

            foreach (i, type; FieldTypes)
            {
                mixin(`
                    message.` ~ FieldNameTuple!T[i] ~ ` = res_params[` ~ i.to!string ~ `].get!` ~ type.stringof ~ `;
                `);
            }

            return message;
        }
    }
}
