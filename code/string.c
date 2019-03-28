#include "zmodule.h"
#include "string.h"
#include "memory.h"

#define SDS_MAX_PREALLOC (1024*1024)

typedef struct _zmstr_header
{
	uint32_t len;
	uint32_t memory_free;
	wchar_t buf[];
} zmstr_header_t;


wchar_t* __stdcall zs_new_with_len(const wchar_t* ptr, uint32_t initlen)
{
	zmstr_header_t* pZmsHdr;

	pZmsHdr = memory_alloc(sizeof(zmstr_header_t) + sizeof(wchar_t) * (initlen + 1));
	if (pZmsHdr == NULL) {
		return NULL;
	}
	pZmsHdr->len = initlen;
	pZmsHdr->memory_free = 0;
	if (initlen && ptr) {
		__movsb((uint8_t*)pZmsHdr->buf, (const uint8_t*)ptr, sizeof(wchar_t) * initlen);
	}
	return (wchar_t*)pZmsHdr->buf;
}

wchar_t* __stdcall zs_new(const wchar_t* ptr)
{
	uint32_t initlen = (ptr == NULL) ? 0 : fn_lstrlenW(ptr);
	return zs_new_with_len(ptr, initlen);
}

wchar_t* __stdcall zs_empty()
{
	return zs_new_with_len(L"", 0);
}

wchar_t* __stdcall zs_duplicate(const wchar_t* s)
{
	return zs_new_with_len(s, fn_zs_length(s));
}

void __stdcall zs_free(wchar_t* s)
{
	if (s == NULL) {
		return;
	}
	memory_free((uint8_t*)s - sizeof(zmstr_header_t));
}

uint32_t __stdcall zs_length(const wchar_t* s)
{
	zmstr_header_t* pZmsHdr = (zmstr_header_t*)((uint8_t*)s - sizeof(zmstr_header_t));
	return pZmsHdr->len;
}

uint32_t __stdcall zs_available(const wchar_t* s)
{
	zmstr_header_t* pZmsHdr = (zmstr_header_t*)((uint8_t*)s - sizeof(zmstr_header_t));
	return pZmsHdr->memory_free;
}

char* __stdcall zs_to_str(wchar_t* zs, uint32_t codePage)
{
	char* str = NULL;
	int strALen;
	uint32_t zlen = zs_length(zs);

	if (zs == NULL) {
		return str;
	}

	strALen = fn_WideCharToMultiByte(codePage, 0, zs, zlen, NULL, 0, NULL, NULL);
	if (strALen > 0) {
		str = memory_alloc(strALen + 1);
		if (!fn_WideCharToMultiByte(codePage, 0, zs, zlen, str, strALen, NULL, NULL)) {
			memory_free(str);
			return NULL;
		}
	}

	return str;
}

wchar_t* __stdcall zs_make_room_for(wchar_t* zs, uint32_t addlen)
{
	zmstr_header_t *pZmsHdr, *newsh;
	uint32_t memory_free = zs_available(zs);
	uint32_t len, newlen;

	if (memory_free >= addlen) {
		return zs;
	}
	len = zs_length(zs);
	pZmsHdr = (zmstr_header_t*)((uint8_t*)zs - sizeof(zmstr_header_t));
	newlen = len + addlen;
	if (newlen < SDS_MAX_PREALLOC) {
		newlen <<= 1;
	}
	else {
		newlen += SDS_MAX_PREALLOC;
	}
	newsh = memory_realloc(pZmsHdr, sizeof(zmstr_header_t) + sizeof(wchar_t) * (newlen + 1));
	if (newsh == NULL) {
		return NULL;
	}

	newsh->memory_free = newlen - len;
	return newsh->buf;
}

wchar_t* __stdcall zs_catlen(wchar_t* zs, const void* t, uint32_t len)
{
	zmstr_header_t* pZmsHdr;
	uint32_t curlen = zs_length(zs);

	if (t == NULL || len == 0) {
		return zs;
	}

	zs = zs_make_room_for(zs, len);
	if (zs == NULL) {
		return NULL;
	}
	pZmsHdr = (zmstr_header_t*)((uint8_t*)zs - sizeof(zmstr_header_t));
	__movsb((uint8_t*)(zs + curlen), (const uint8_t*)t, len * sizeof(wchar_t));
	pZmsHdr->len = curlen + len;
	pZmsHdr->memory_free = pZmsHdr->memory_free - len;
	return zs;
}

wchar_t* __stdcall zs_cat(wchar_t* s, const wchar_t* t)
{
	if (t == NULL) {
		return s;
	}
	return zs_catlen(s, t, fn_lstrlenW(t));
}

void __stdcall zs_update_length(wchar_t* zs)
{
	zmstr_header_t* pZmsHdr = (void*)((uint8_t*)zs - sizeof(zmstr_header_t));
	uint32_t reallen = fn_lstrlenW(zs);
	pZmsHdr->memory_free += (pZmsHdr->len - reallen);
	pZmsHdr->len = reallen;
}

wchar_t* __stdcall zs_grow(wchar_t* zs, size_t len)
{
	zmstr_header_t* pZmsHdr = (void*)((uint8_t*)zs - sizeof(zmstr_header_t));
	
	if (len < 0) {
		pZmsHdr->len += len;
		pZmsHdr->memory_free -= len;
		zs[pZmsHdr->len] = L'\0';
	}
	else {
		zs = zs_make_room_for(zs, len);
	}
	return zs;
}

wchar_t __stdcall zs_lastchar(const wchar_t* zs)
{
	return zs[zs_length(zs)];
}

wchar_t* __cdecl zs_catprintf(wchar_t* zs, const wchar_t* fmt, ...)
{
	int len;
	va_list ap;
	wchar_t* out = memory_alloc(4096);
	va_start(ap, fmt);
	len = fn_wvsprintfW(out, fmt, ap);
	va_end(ap);
	zs = zs_catlen(zs, out, len);
	memory_free(out);
	return zs;
}

wchar_t* __stdcall zs_append_slash_if_needed(wchar_t* zs)
{
	if (zs_lastchar(zs) != _pZmoduleBlock->slashString[0]) {
		zs = zs_cat(zs, _pZmoduleBlock->slashString);
	}
	return zs;
}

int __stdcall zs_ends_with(wchar_t* zs, const wchar_t* subStr)
{
    int zsLen = zs_length(zs);
    int subLen = fn_lstrlenW(subStr);
    if (zsLen < subLen) {
        return 0;
    }
    return (fn_lstrcmpW(zs + zsLen - subLen, subStr) == 0 ? 1 : 0);
}

///* Modify an wchar_t* string on-place to make it empty (zero length).
//* However all the existing buffer is not discarded but set as memory_free space
//* so that next append operations will not require allocations up to the
//* number of bytes previously available. */
//void sdsclear(wchar_t* s) {
//	zmstr_header_t *pZmsHdr = (void*)(s - sizeof *pZmsHdr);;
//	pZmsHdr->memory_free += pZmsHdr->len;
//	pZmsHdr->len = 0;
//	pZmsHdr->buf[0] = '\0';
//}
//
//
///* Reallocate the wchar_t* string so that it has no memory_free space at the end. The
//* contained string remains not altered, but next concatenation operations
//* will require a reallocation.
//*
//* After the call, the passed wchar_t* string is no longer valid and all the
//* references must be substituted with the new pointer returned by the call. */
//wchar_t* sdsRemoveFreeSpace(wchar_t* s) {
//	zmstr_header_t *pZmsHdr;
//
//	pZmsHdr = (void*)(s - sizeof *pZmsHdr);;
//	pZmsHdr = realloc(pZmsHdr, sizeof *pZmsHdr + pZmsHdr->len + 1);
//	pZmsHdr->memory_free = 0;
//	return pZmsHdr->buf;
//}
//
///* Return the total size of the allocation of the specifed wchar_t* string,
//* including:
//* 1) The wchar_t* header before the pointer.
//* 2) The string.
//* 3) The memory_free buffer at the end if any.
//* 4) The implicit null term.
//*/
//size_t sdsAllocSize(wchar_t* s) {
//	zmstr_header_t *pZmsHdr = (void*)(s - sizeof *pZmsHdr);;
//
//	return sizeof(*pZmsHdr) + pZmsHdr->len + pZmsHdr->memory_free + 1;
//}
//
///* Increment the wchar_t* length and decrements the left memory_free space at the
//* end of the string according to 'incr'. Also set the null term
//* in the new end of the string.
//*
//* This function is used in order to fix the string length after the
//* user calls sdsMakeRoomFor(), writes something after the end of
//* the current string, and finally needs to set the new length.
//*
//* Note: it is possible to use a negative increment in order to
//* right-trim the string.
//*
//* Usage example:
//*
//* Using sdsIncrLen() and sdsMakeRoomFor() it is possible to mount the
//* following schema, to cat bytes coming from the kernel to the end of an
//* wchar_t* string without copying into an intermediate buffer:
//*
//* oldlen = zs_length(s);
//* s = sdsMakeRoomFor(s, BUFFER_SIZE);
//* nread = read(fd, s+oldlen, BUFFER_SIZE);
//* ... check for nread <= 0 and handle it ...
//* sdsIncrLen(s, nread);
//*/
//void sdsIncrLen(wchar_t* s, int incr)
//{
//	zmstr_header_t *pZmsHdr = (void*)(s - sizeof *pZmsHdr);;
//
//	pZmsHdr->len += incr;
//	pZmsHdr->memory_free -= incr;
//	s[pZmsHdr->len] = '\0';
//}
//
///* Destructively modify the wchar_t* string 's' to hold the specified binary
//* safe string pointed by 't' of length 'len' bytes. */
//wchar_t* sdscpylen(wchar_t* s, const char *t, size_t len) {
//	zmstr_header_t *pZmsHdr = (void*)(s - sizeof *pZmsHdr);;
//	size_t totlen = pZmsHdr->memory_free + pZmsHdr->len;
//
//	if (totlen < len) {
//		s = sdsMakeRoomFor(s, len - pZmsHdr->len);
//		if (s == NULL) return NULL;
//		pZmsHdr = (void*)(s - sizeof *pZmsHdr);;
//		totlen = pZmsHdr->memory_free + pZmsHdr->len;
//	}
//	memcpy(s, t, len);
//	s[len] = '\0';
//	pZmsHdr->len = len;
//	pZmsHdr->memory_free = totlen - len;
//	return s;
//}
//
///* Like sdscpylen() but 't' must be a null-termined string so that the length
//* of the string is obtained with strlen(). */
//wchar_t* sdscpy(wchar_t* s, const char *t) {
//	return sdscpylen(s, t, strlen(t));
//}
//
///* Like sdscatpritf() but gets va_list instead of being variadic. */
//wchar_t* sdscatvprintf(wchar_t* s, const char *fmt, va_list ap) {
//	va_list cpy;
//	char *buf, *t;
//	size_t buflen = 16;
//
//	while (1) {
//		buf = memory_alloc(buflen);
//		if (buf == NULL) return NULL;
//		buf[buflen - 2] = '\0';
//		va_copy(cpy, ap);
//		vsnprintf(buf, buflen, fmt, cpy);
//		if (buf[buflen - 2] != '\0') {
//			memory_free(buf);
//			buflen *= 2;
//			continue;
//		}
//		break;
//	}
//	t = sdscat(s, buf);
//	memory_free(buf);
//	return t;
//}
///* Remove the part of the string from left and from right composed just of
//* contiguous characters found in 'cset', that is a null terminted C string.
//*
//* After the call, the modified wchar_t* string is no longer valid and all the
//* references must be substituted with the new pointer returned by the call.
//*
//* Example:
//*
//* s = zs_new("AA...AA.a.aa.aHelloWorld     :::");
//* s = sdstrim(s,"A. :");
//* printf("%s\n", s);
//*
//* Output will be just "Hello World".
//*/
//void sdstrim(wchar_t* s, const char *cset) {
//	zmstr_header_t *pZmsHdr = (void*)(s - sizeof *pZmsHdr);;
//	char *start, *end, *sp, *ep;
//	size_t len;
//
//	sp = start = s;
//	ep = end = s + zs_length(s) - 1;
//	while (sp <= end && strchr(cset, *sp)) sp++;
//	while (ep > start && strchr(cset, *ep)) ep--;
//	len = (sp > ep) ? 0 : ((ep - sp) + 1);
//	if (pZmsHdr->buf != sp) memmove(pZmsHdr->buf, sp, len);
//	pZmsHdr->buf[len] = '\0';
//	pZmsHdr->memory_free = pZmsHdr->memory_free + (pZmsHdr->len - len);
//	pZmsHdr->len = len;
//}
//
///* Turn the string into a smaller (or equal) string containing only the
//* substring specified by the 'start' and 'end' indexes.
//*
//* start and end can be negative, where -1 means the last character of the
//* string, -2 the penultimate character, and so forth.
//*
//* The interval is inclusive, so the start and end characters will be part
//* of the resulting string.
//*
//* The string is modified in-place.
//*
//* Example:
//*
//* s = zs_new("Hello World");
//* sdsrange(s,1,-1); => "ello World"
//*/
//void sdsrange(wchar_t* s, int start, int end) {
//	zmstr_header_t *pZmsHdr = (void*)(s - sizeof *pZmsHdr);;
//	size_t newlen, len = zs_length(s);
//
//	if (len == 0) return;
//	if (start < 0) {
//		start = len + start;
//		if (start < 0) start = 0;
//	}
//	if (end < 0) {
//		end = len + end;
//		if (end < 0) end = 0;
//	}
//	newlen = (start > end) ? 0 : (end - start) + 1;
//	if (newlen != 0) {
//		if (start >= (signed)len) {
//			newlen = 0;
//		}
//		else if (end >= (signed)len) {
//			end = len - 1;
//			newlen = (start > end) ? 0 : (end - start) + 1;
//		}
//	}
//	else {
//		start = 0;
//	}
//	if (start && newlen) memmove(pZmsHdr->buf, pZmsHdr->buf + start, newlen);
//	pZmsHdr->buf[newlen] = 0;
//	pZmsHdr->memory_free = pZmsHdr->memory_free + (pZmsHdr->len - newlen);
//	pZmsHdr->len = newlen;
//}
//
///* Apply tolower() to every character of the wchar_t* string 's'. */
//void sdstolower(wchar_t* s) {
//	int len = zs_length(s), j;
//
//	for (j = 0; j < len; j++) s[j] = tolower(s[j]);
//}
//
///* Apply toupper() to every character of the wchar_t* string 's'. */
//void sdstoupper(wchar_t* s) {
//	int len = zs_length(s), j;
//
//	for (j = 0; j < len; j++) s[j] = toupper(s[j]);
//}
//
///* Compare two wchar_t* strings s1 and s2 with memcmp().
//*
//* Return value:
//*
//*     1 if s1 > s2.
//*    -1 if s1 < s2.
//*     0 if s1 and s2 are exactly the same binary string.
//*
//* If two strings share exactly the same prefix, but one of the two has
//* additional characters, the longer string is considered to be greater than
//* the smaller one. */
//int sdscmp(const wchar_t* s1, const wchar_t* s2) {
//	size_t l1, l2, minlen;
//	int cmp;
//
//	l1 = zs_length(s1);
//	l2 = zs_length(s2);
//	minlen = (l1 < l2) ? l1 : l2;
//	cmp = memcmp(s1, s2, minlen);
//	if (cmp == 0) return l1 - l2;
//	return cmp;
//}
//
///* Split 's' with separator in 'sep'. An array
//* of wchar_t* strings is returned. *count will be set
//* by reference to the number of tokens returned.
//*
//* On out of memory, zero length string, zero length
//* separator, NULL is returned.
//*
//* Note that 'sep' is able to split a string using
//* a multi-character separator. For example
//* sdssplit("foo_-_bar","_-_"); will return two
//* elements "foo" and "bar".
//*
//* This version of the function is binary-safe but
//* requires length arguments. sdssplit() is just the
//* same function but for zero-terminated strings.
//*/
//wchar_t* *sdssplitlen(const char *s, int len, const char *sep, int seplen, int *count) {
//	int elements = 0, slots = 5, start = 0, j;
//	wchar_t* *tokens;
//
//	if (seplen < 1 || len < 0) return NULL;
//
//	tokens = memory_alloc(sizeof(wchar_t*)*slots);
//	if (tokens == NULL) return NULL;
//
//	if (len == 0) {
//		*count = 0;
//		return tokens;
//	}
//	for (j = 0; j < (len - (seplen - 1)); j++) {
//		/* make sure there is room for the next element and the final one */
//		if (slots < elements + 2) {
//			wchar_t* *newtokens;
//
//			slots *= 2;
//			newtokens = realloc(tokens, sizeof(wchar_t*)*slots);
//			if (newtokens == NULL) goto cleanup;
//			tokens = newtokens;
//		}
//		/* search the separator */
//		if ((seplen == 1 && *(s + j) == sep[0]) || (memcmp(s + j, sep, seplen) == 0)) {
//			tokens[elements] = zs_new_with_len(s + start, j - start);
//			if (tokens[elements] == NULL) goto cleanup;
//			elements++;
//			start = j + seplen;
//			j = j + seplen - 1; /* skip the separator */
//		}
//	}
//	/* Add the final element. We are sure there is room in the tokens array. */
//	tokens[elements] = zs_new_with_len(s + start, len - start);
//	if (tokens[elements] == NULL) goto cleanup;
//	elements++;
//	*count = elements;
//	return tokens;
//
//cleanup:
//	{
//		int i;
//		for (i = 0; i < elements; i++) zs_free(tokens[i]);
//		memory_free(tokens);
//		*count = 0;
//		return NULL;
//	}
//}
//
///* Free the result returned by sdssplitlen(), or do nothing if 'tokens' is NULL. */
//void zs_freesplitres(wchar_t* *tokens, int count) {
//	if (!tokens) return;
//	while (count--)
//		zs_free(tokens[count]);
//	memory_free(tokens);
//}
//
///* Create an wchar_t* string from a long long value. It is much faster than:
//*
//* sdscatprintf(zs_empty(),"%lld\n", value);
//*/
//wchar_t* sdsfromlonglong(long long value) {
//	char buf[32], *p;
//	unsigned long long v;
//
//	v = (value < 0) ? -value : value;
//	p = buf + 31; /* point to the last character */
//	do {
//		*p-- = '0' + (v % 10);
//		v /= 10;
//	} while (v);
//	if (value < 0) *p-- = '-';
//	p++;
//	return zs_new_with_len(p, 32 - (p - buf));
//}
//
///* Append to the wchar_t* string "s" an escaped string representation where
//* all the non-printable characters (tested with isprint()) are turned into
//* escapes in the form "\n\r\a...." or "\x<hex-number>".
//*
//* After the call, the modified wchar_t* string is no longer valid and all the
//* references must be substituted with the new pointer returned by the call. */
//wchar_t* sdscatrepr(wchar_t* s, const char *p, size_t len) {
//	s = sdscatlen(s, "\"", 1);
//	while (len--) {
//		switch (*p) {
//		case '\\':
//		case '"':
//			s = sdscatprintf(s, "\\%c", *p);
//			break;
//		case '\n': s = sdscatlen(s, "\\n", 2); break;
//		case '\r': s = sdscatlen(s, "\\r", 2); break;
//		case '\t': s = sdscatlen(s, "\\t", 2); break;
//		case '\a': s = sdscatlen(s, "\\a", 2); break;
//		case '\b': s = sdscatlen(s, "\\b", 2); break;
//		default:
//			if (isprint(*p))
//				s = sdscatprintf(s, "%c", *p);
//			else
//				s = sdscatprintf(s, "\\x%02x", (uint8_t)*p);
//			break;
//		}
//		p++;
//	}
//	return sdscatlen(s, "\"", 1);
//}
//
///* Helper function for sdssplitargs() that returns non zero if 'c'
//* is a valid hex digit. */
//int is_hex_digit(char c) {
//	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
//		(c >= 'A' && c <= 'F');
//}
//
///* Helper function for sdssplitargs() that converts a hex digit into an
//* integer from 0 to 15 */
//int hex_digit_to_int(char c) {
//	switch (c) {
//	case '0': return 0;
//	case '1': return 1;
//	case '2': return 2;
//	case '3': return 3;
//	case '4': return 4;
//	case '5': return 5;
//	case '6': return 6;
//	case '7': return 7;
//	case '8': return 8;
//	case '9': return 9;
//	case 'a': case 'A': return 10;
//	case 'b': case 'B': return 11;
//	case 'c': case 'C': return 12;
//	case 'd': case 'D': return 13;
//	case 'e': case 'E': return 14;
//	case 'f': case 'F': return 15;
//	default: return 0;
//	}
//}
//
///* Split a line into arguments, where every argument can be in the
//* following programming-language REPL-alike form:
//*
//* foo bar "newline are supported\n" and "\xff\x00otherstuff"
//*
//* The number of arguments is stored into *argc, and an array
//* of wchar_t* is returned.
//*
//* The caller should memory_free the resulting array of wchar_t* strings with
//* zs_freesplitres().
//*
//* Note that sdscatrepr() is able to convert back a string into
//* a quoted string in the same format sdssplitargs() is able to parse.
//*
//* The function returns the allocated tokens on success, even when the
//* input string is empty, or NULL if the input contains unbalanced
//* quotes or closed quotes followed by non space characters
//* as in: "foo"bar or "foo'
//*/
//wchar_t* *sdssplitargs(const char *line, int *argc) {
//	const char *p = line;
//	char *current = NULL;
//	char **vector = NULL;
//
//	*argc = 0;
//	while (1) {
//		/* skip blanks */
//		while (*p && isspace(*p)) p++;
//		if (*p) {
//			/* get a token */
//			int inq = 0;  /* set to 1 if we are in "quotes" */
//			int insq = 0; /* set to 1 if we are in 'single quotes' */
//			int done = 0;
//
//			if (current == NULL) current = zs_empty();
//			while (!done) {
//				if (inq) {
//					if (*p == '\\' && *(p + 1) == 'x' &&
//						is_hex_digit(*(p + 2)) &&
//						is_hex_digit(*(p + 3)))
//					{
//						uint8_t byte;
//
//						byte = (hex_digit_to_int(*(p + 2)) * 16) +
//							hex_digit_to_int(*(p + 3));
//						current = sdscatlen(current, (char*)&byte, 1);
//						p += 3;
//					}
//					else if (*p == '\\' && *(p + 1)) {
//						char c;
//
//						p++;
//						switch (*p) {
//						case 'n': c = '\n'; break;
//						case 'r': c = '\r'; break;
//						case 't': c = '\t'; break;
//						case 'b': c = '\b'; break;
//						case 'a': c = '\a'; break;
//						default: c = *p; break;
//						}
//						current = sdscatlen(current, &c, 1);
//					}
//					else if (*p == '"') {
//						/* closing quote must be followed by a space or
//						* nothing at all. */
//						if (*(p + 1) && !isspace(*(p + 1))) goto err;
//						done = 1;
//					}
//					else if (!*p) {
//						/* unterminated quotes */
//						goto err;
//					}
//					else {
//						current = sdscatlen(current, p, 1);
//					}
//				}
//				else if (insq) {
//					if (*p == '\\' && *(p + 1) == '\'') {
//						p++;
//						current = sdscatlen(current, "'", 1);
//					}
//					else if (*p == '\'') {
//						/* closing quote must be followed by a space or
//						* nothing at all. */
//						if (*(p + 1) && !isspace(*(p + 1))) goto err;
//						done = 1;
//					}
//					else if (!*p) {
//						/* unterminated quotes */
//						goto err;
//					}
//					else {
//						current = sdscatlen(current, p, 1);
//					}
//				}
//				else {
//					switch (*p) {
//					case ' ':
//					case '\n':
//					case '\r':
//					case '\t':
//					case '\0':
//						done = 1;
//						break;
//					case '"':
//						inq = 1;
//						break;
//					case '\'':
//						insq = 1;
//						break;
//					default:
//						current = sdscatlen(current, p, 1);
//						break;
//					}
//				}
//				if (*p) p++;
//			}
//			/* add the token to the vector */
//			vector = realloc(vector, ((*argc) + 1)*sizeof(char*));
//			vector[*argc] = current;
//			(*argc)++;
//			current = NULL;
//		}
//		else {
//			/* Even on empty input string return something not NULL. */
//			if (vector == NULL) vector = memory_alloc(sizeof(void*));
//			return vector;
//		}
//	}
//
//err:
//	while ((*argc)--)
//		zs_free(vector[*argc]);
//	memory_free(vector);
//	if (current) zs_free(current);
//	*argc = 0;
//	return NULL;
//}
//
///* Modify the string substituting all the occurrences of the set of
//* characters specified in the 'from' string to the corresponding character
//* in the 'to' array.
//*
//* For instance: sdsmapchars(mystring, "ho", "01", 2)
//* will have the effect of turning the string "hello" into "0ell1".
//*
//* The function returns the wchar_t* string pointer, that is always the same
//* as the input pointer since no resize is needed. */
//wchar_t* sdsmapchars(wchar_t* s, const char *from, const char *to, size_t setlen) {
//	size_t j, i, l = zs_length(s);
//
//	for (j = 0; j < l; j++) {
//		for (i = 0; i < setlen; i++) {
//			if (s[j] == from[i]) {
//				s[j] = to[i];
//				break;
//			}
//		}
//	}
//	return s;
//}
//
///* Join an array of C strings using the specified separator (also a C string).
//* Returns the result as an wchar_t* string. */
//wchar_t* sdsjoin(char **argv, int argc, char *sep, size_t seplen) {
//	wchar_t* join = zs_empty();
//	int j;
//
//	for (j = 0; j < argc; j++) {
//		join = sdscat(join, argv[j]);
//		if (j != argc - 1) join = sdscatlen(join, sep, seplen);
//	}
//	return join;
//}
//
///* Like sdsjoin, but joins an array of SDS strings. */
//wchar_t* sdsjoinsds(wchar_t* *argv, int argc, const char *sep, size_t seplen) {
//	wchar_t* join = zs_empty();
//	int j;
//
//	for (j = 0; j < argc; j++) {
//		join = sdscatsds(join, argv[j]);
//		if (j != argc - 1) join = sdscatlen(join, sep, seplen);
//	}
//	return join;
//}
