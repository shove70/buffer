module buffer.rpc.client;

import std.meta : staticIndexOf;
import std.traits;
import std.conv : to;
import std.variant;

import buffer.message;

alias TcpRequestHandler = ubyte[] delegate(ubyte[] data);

class Client
{
    static TcpRequestHandler handler = null;

    static void bindTcpRequestHandler(TcpRequestHandler handler)
    {
        Client.handler = handler;
    }

    static T call(T, Params...)(string method, Params params)
    if ((staticIndexOf!(T, supportedBuiltinTypes) != -1) || ((BaseTypeTuple!T.length > 0) && is(BaseTypeTuple!T[0] == Message)))
    {
        assert(handler != null, "TcpRequestHandler must be bound.");
        assert(method.length > 0, "Paramter method must be set.");

        ubyte[] response = handler(Message.serialize_without_msginfo(method, params));
        string name;
        string res_method;
        Variant[] res_params = Message.deserialize(response, name, res_method);
        
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
