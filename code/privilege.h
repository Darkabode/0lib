#ifndef __COMMON_PRIVILEGES_H_
#define __COMMON_PRIVILEGES_H_

#define IS_ELEVATED                   0x00010000

#define MANDATORY_LEVEL_UNTRUSTED     0x00000100
#define MANDATORY_LEVEL_LOW           0x00000200
#define MANDATORY_LEVEL_MEDIUM        0x00000400
#define MANDATORY_LEVEL_HIGH          0x00000800
#define MANDATORY_LEVEL_SYSTEM        0x00001000
#define MANDATORY_LEVEL_SECUREPROCESS 0x00002000

#define ACCESS_FULL                   0x00000001
#define ACCESS_GUEST                  0x00000010
#define ACCESS_USER                   0x00000020
#define ACCESS_ADMIN                  0x00000040


NTSTATUS __stdcall privelege_enable(HANDLE hToken, const char* privName);

uint32_t __stdcall privilege_check_sid_in_group(PTOKEN_GROUPS pGroupInfo, DWORD subAuthority1); // used internal
uint32_t __stdcall privelege_get_security_mask(HANDLE hToken);

#endif // __COMMON_PRIVILEGES_H_