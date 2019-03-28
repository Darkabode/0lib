#ifndef __0LIB_JSON_H_
#define __0LIB_JSON_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * JSON type identifier. Basic types are:
 * 	o Object
 * 	o Array
 * 	o String
 * 	o Other primitive: number, boolean (true/false) or null
 */
typedef enum {
	JSON_PRIMITIVE = 0,
	JSON_OBJECT = 1,
	JSON_ARRAY = 2,
	JSON_STRING = 3
} jsmntype_t;

typedef enum {
	/* Not enough tokens were provided */
	JSON_ERROR_NOMEM = -1,
	/* Invalid character inside JSON string */
	JSON_ERROR_INVAL = -2,
	/* The string is not a full JSON packet, more bytes expected */
	JSON_ERROR_PART = -3,
} jsmnerr_t;

/**
 * JSON token description.
 * @param		type	type (object, array, string etc.)
 * @param		start	start position in JSON data string
 * @param		end		end position in JSON data string
 */
typedef struct
{
	jsmntype_t type;
	int start;
	int end;
	int size;
	int parent;
} jsmntok_t;

/**
 * JSON parser. Contains an array of token blocks available. Also stores
 * the string being parsed now and current position in that string
 */
typedef struct
{
	uint32_t pos; /* offset in the JSON string */
	uint32_t toknext; /* next token to allocate */
	int toksuper; /* superior token node, e.g parent object or array */
} jsmn_parser_t;

void json_init(jsmn_parser_t *parser);

jsmnerr_t json_parse(jsmn_parser_t* parser, const char* js, size_t len, jsmntok_t* tokens, uint32_t num_tokens);

#ifdef __cplusplus
}
#endif

#endif // __0LIB_JSON_H_
