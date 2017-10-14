module buffer.compiler;

import std.string;
import std.conv;
import std.array;
import std.typecons;

template LoadBufferFile(string fileName)
{
	pragma(msg, "Compiling file: ", fileName, "...");
	const char[] LoadBufferFile = compiler!(import(fileName));
}

template LoadBufferScript(string src)
{
	pragma(msg, "Compiling script: ", extractScriptfragment(src), "...");
	const char[] LoadBufferScript = compiler!src;
}

private string compiler(string source)()
{
	Token[] tokens = lexer(source);
	Sentence[] sentences = parser(tokens);
	
	Appender!string code;
	code.put("import buffer.message;\r\n\r\n");
	
	foreach(sentence; sentences)
	{
		code.put("final class " ~ sentence.name ~ " : buffer.message.Message\r\n");
		code.put("{\r\n");
		
		foreach(field; sentence.fields)
		{
			code.put("\t" ~ field.type ~ " " ~ field.name ~ ";\r\n");
		}
		
		code.put("\r\n");
		code.put("\tubyte[] serialize()\r\n");
		code.put("\t{\r\n");
		code.put("\t\treturn super.serialize!(typeof(this))(this);\r\n");
		code.put("\t}\r\n}\r\n\r\n");
	}

	return code.data;
}

/// lexer

private enum TokenType
{
	Define			= 1,	// message
	Keyword			= 2,	// type: int8...
	Identifier		= 3,
	SentenceEnd		= 100,	// ;
	DelimiterOpen	= 110,	// {
	DelimiterClose	= 111	// }
}

private const string[] keywords	= ["int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64", "float32", "float64", "string"];

private struct Token
{
	TokenType	type;
	string		name;
	
	this(string name)
	{
		if (name == "message") {
			this.type = TokenType.Define;
		} else if (inArray(name, keywords)) {
			this.type = TokenType.Keyword;
		} else {
			this.type = TokenType.Identifier;
		}
		
		this.name = name;
	}
	
	this(TokenType type, string name)
	{
		this.type = type;
		this.name = name;
	}
}

private Token[] lexer(string source)
{
	/* State transition diagram:
	0:	none		1: word			2: {		3: ;		4: }
		-1: /		-2: //			-3: /*
	
	0	-> \s[ \f\n\r\t\v]		0
		-> A..Za..z_			1
		-> {					2 -> add token -> 0
		-> ;					3 -> add token -> 0
		-> }					4 -> add token -> 0
		-> /					hang state, -1
		-> other				Exception
	1	-> \s[ \f\n\r\t\v]		1 -> add token -> 0
		-> A..Za..z0..9_		1
		-> {					1 -> add token -> 2 -> add token -> 0
		-> ;					1 -> add token -> 3 -> add token -> 0
		-> }					1 -> add token -> 4 -> add token -> 0
		-> /					hang state, -1
		-> other				Exception
	2	->						0
	3	->						0
	4	->						0
	-1	-> /					-2
		-> *					-3
		-> other				Exception
	-2	-> \n					restore state, hang = 0
		-> other				skip
	-3	-> /					if last is * then restore state & hang = 0, else skip
		-> other				skip
	*/
	
	Token[] tokens;
	int state = 0;
	int stateHang;
	char last;
	string token = string.init;
	
	source ~= "\r\n";
	foreach(i, ch; source)
	{
		switch (state)
		{
			case 0:
				if (isWhitespace(ch))
					continue;
				else if (isIdentifierFirstChar(ch)) {
					token = ch.to!string;
					state = 1;
				} else if (ch == '{') {
					tokens ~= Token(TokenType.DelimiterOpen, "{");
					state = 0;
				} else if (ch == ';') {
					tokens ~= Token(TokenType.SentenceEnd, ";");
					state = 0;
				} else if (ch == '}') {
					tokens ~= Token(TokenType.DelimiterClose, "}");
					state = 0;
				} else if (ch == '/') {
					stateHang = state;
					state = -1;
				} else {
					throw new Exception("Invalid character." ~ ch.to!string);
				}
				break;
			case 1:
				if (isWhitespace(ch)) {
					tokens ~= Token(token);
					token = string.init;
					state = 0;
				} else if (isIdentifierChar(ch)) {
					token ~= ch.to!string;
				} else if (ch == '{') {
					tokens ~= Token(token);
					tokens ~= Token(TokenType.DelimiterOpen, "{");
					token = string.init;
					state = 0;
				} else if (ch == ';') {
					tokens ~= Token(token);
					tokens ~= Token(TokenType.SentenceEnd, ";");
					token = string.init;
					state = 0;
				} else if (ch == '}') {
					tokens ~= Token(token);
					tokens ~= Token(TokenType.DelimiterClose, "}");
					token = string.init;
					state = 0;
				} else if (ch == '/') {
					stateHang = state;
					state = -1;
				} else {
					throw new Exception("Invalid character." ~ ch.to!string);
				}
				break;
			case -1:
				if (ch == '/') {
					state = -2;
				} else if (ch == '*') {
					state = -3;
				} else {
					throw new Exception("Invalid character." ~ ch.to!string);
				}
				break;
			case -2:
				if (ch == '\n') {
					state = stateHang;
					stateHang = 0;
				} else {
					continue;
				}
				break;
			case -3:
				if ((ch == '/') && (last == '*')) {
					state = stateHang;
					stateHang = 0;
				} else {
					continue;
				}
				break;
			default:
				break;
		}

		last = ch;
	}

	return tokens;
}

private bool isWhitespace(char ch)
{
	return ch == ' ' || ch == '　' || ch == '\f' || ch == '\n' || ch == '\r' || ch == '\t' || ch == '\v';
}

private bool isIdentifierFirstChar(char ch)
{
	return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || ch == '_';
}

private bool isIdentifierChar(char ch)
{
	return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || ch == '_' || (ch >= '0' && ch <= '9');
}

private bool inArray(string str, const string[] aArray)
{
	foreach(s; aArray)
	{
		if (s == str) return true;
	}
	
	return false;
}

private string extractScriptfragment(string source)
{
	string ret = string.init;
	
	foreach(ch; source) {
		if (ret.length >= 50)
			break;
		if (!isWhitespace(ch))
			ret ~= ch.to!string;
		else if ((ret.length > 0) && (ret[$ - 1] != ' '))
			ret ~= " ";
	}
	
	return ret;
}

/// parser

private struct Field
{
	string type;
	string name;
}

private struct Sentence
{
	string name;
	Field[] fields;
}

private Sentence[] parser(Token[] tokens)
{
	Sentence[] sentences;
	int pos;
	while (pos < tokens.length - 1)
	{
		if (tokens[pos].type != TokenType.Define)
		{
			throw new Exception("Syntax error at " ~ tokens[pos].name);
		}
		
		sentences ~= parser_define(tokens, pos);
	}
	
	return sentences;
}

private Sentence parser_define(Token[] tokens, ref int pos)
{
	if ((tokens.length - pos < 4) || (tokens[pos].type != TokenType.Define) || (tokens[pos + 1].type != TokenType.Identifier) || (tokens[pos + 2].type != TokenType.DelimiterOpen))
	{
		throw new Exception("Syntax error at " ~ tokens[pos].name);
	}
	
	Sentence sentence;
	sentence.name = tokens[pos + 1].name;
	pos += 3;
	
	while (pos < tokens.length)
	{
		Nullable!Field field = parser_field(tokens, pos);
		
		if (field.isNull)
			return sentence;

		sentence.fields ~= field;
	}
	
	return sentence;
}

private Nullable!Field parser_field(Token[] tokens, ref int pos)
{
	if ((tokens.length - pos >= 1) && (tokens[pos].type == TokenType.DelimiterClose))
	{
		pos++;
		return Nullable!Field();
	}
	
	if ((tokens.length - pos < 3) || (tokens[pos].type != TokenType.Keyword) || (tokens[pos + 1].type != TokenType.Identifier) || (tokens[pos + 2].type != TokenType.SentenceEnd))
	{
		throw new Exception("Syntax error at " ~ tokens[pos].name);
	}
	
	Field field;
	field.type = tokens[pos].name;
	field.name = tokens[pos + 1].name;
	pos += 3;
	
	return Nullable!Field(field);
}

/*
import buffer.message;

final class Sample : buffer.message.Message
{
	int32 age;
	string name;
	int16 age2;

	ubyte[] serialize()
	{
		return super.serialize!(typeof(this))(this);
	}
}*/