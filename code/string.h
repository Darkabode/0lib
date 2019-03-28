#ifndef __COMMON_STRING_H_
#define __COMMON_STRING_H_

wchar_t* __stdcall zs_new_with_len(const wchar_t* ptr, uint32_t initlen);
wchar_t* __stdcall zs_new(const wchar_t* ptr);
wchar_t* __stdcall zs_empty(void);
wchar_t* __stdcall zs_duplicate(const wchar_t* s);
void __stdcall zs_free(wchar_t* s);
uint32_t __stdcall zs_length(const wchar_t* s);
uint32_t __stdcall zs_available(const wchar_t* s);
char* __stdcall zs_to_str(wchar_t* zs, uint32_t codePage);
wchar_t* __stdcall zs_make_room_for(wchar_t* zs, uint32_t addlen);
wchar_t* __stdcall zs_catlen(wchar_t* zs, const void* t, uint32_t len);
wchar_t* __stdcall zs_cat(wchar_t* s, const wchar_t* t);
int __stdcall zs_cmpn(wchar_t* zs1, wchar_t* zs2);
void __stdcall zs_update_length(wchar_t* zs);
wchar_t* __stdcall zs_grow(wchar_t* zs, size_t len);
wchar_t __stdcall zs_lastchar(const wchar_t* zs);
wchar_t* __cdecl zs_catprintf(wchar_t* zs, const wchar_t* fmt, ...);

wchar_t* __stdcall zs_append_slash_if_needed(wchar_t* zs);

int __stdcall zs_ends_with(wchar_t* zs, const wchar_t* subStr);
/*
wchar_t* sdsgrowzero(wchar_t* s, size_t len);
wchar_t* sdscatsds(wchar_t* s, const wchar_t* t);
wchar_t* sdscpylen(wchar_t* s, const char *t, size_t len);
wchar_t* sdscpy(wchar_t* s, const char *t);

wchar_t* sdscatvprintf(wchar_t* s, const char *fmt, va_list ap);
wchar_t* sdscatprintf(wchar_t* s, const char *fmt, ...);

void sdstrim(wchar_t* s, const char *cset);
void sdsrange(wchar_t* s, int start, int end);
void sdsclear(wchar_t* s);
int sdscmp(const wchar_t* s1, const wchar_t* s2);
wchar_t* *sdssplitlen(const char *s, int len, const char *sep, int seplen, int *count);
void zs_freesplitres(wchar_t* *tokens, int count);
void sdstolower(wchar_t* s);
void sdstoupper(wchar_t* s);
wchar_t* sdsfromlonglong(long long value);
wchar_t* sdscatrepr(wchar_t* s, const char *p, size_t len);
wchar_t* *sdssplitargs(const char *line, int *argc);
wchar_t* sdsmapchars(wchar_t* s, const char *from, const char *to, size_t setlen);
wchar_t* sdsjoin(char **argv, int argc, char *sep, size_t seplen);
wchar_t* sdsjoinsds(wchar_t* *argv, int argc, const char *sep, size_t seplen);

// Low level functions exposed to the user API.
wchar_t* sdsMakeRoomFor(wchar_t* s, size_t addlen);
void sdsIncrLen(wchar_t* s, int incr);
wchar_t* sdsRemoveFreeSpace(wchar_t* s);
size_t sdsAllocSize(wchar_t* s);
*/

#endif // __COMMON_STRING_H_
