module buffer.rpc.client;

import std.traits;
import std.conv;

import buffer.message;

alias dgTcpRequestHandler = ubyte[] delegate(ubyte[] data);

class Client
{
	static dgTcpRequestHandler handler = null;
	
	static void bindTcpRequestHandler(dgTcpRequestHandler handler)
	{
		Client.handler = handler;
	}
	
	static T2 call(T1, T2, Params...)(Params params)
	{
		T1 t1 = new T1();
		
		foreach (i, type; FieldTypeTuple!T1)
        {
            mixin("
				t1." ~ FieldNameTuple!T1[i] ~ " = params[" ~ i.to!string ~ "];
			");
        }
        
		return Message.deserialize!T2(handler(t1.serialize()));
	}
}