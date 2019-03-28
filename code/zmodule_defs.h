#ifndef __ZMODULE_ZMODULEDEFS_H_
#define __ZMODULE_ZMODULEDEFS_H_

#define ZMODULE_REASON_START    0x00000001 // EXE.
#define ZMODULE_REASON_LOAD     0x00000002 // DLL при wdReason = DLL_PROCESS_ATTACH.
#define ZMODULE_REASON_UNLOAD   0x00000003 // DLL при wdReason = DLL_PROCESS_DETACH.

#define ZMODULE_MACHINE_IA32    0x00
#define ZMODULE_MACHINE_AMD64   0x01
#define ZMODULE_MACHINE_IA64    0x02

#define ZMODULE_NUMBEROF_DIRECTORY_ENTRIES  2

#define ZMODULE_DIRECTORY_ENTRY_EXPORT      0
#define ZMODULE_DIRECTORY_ENTRY_BASERELOC   1

#pragma pack(push, 1)

typedef struct _zmodule_data_directory {
    uint32_t virtualAddress;
    uint32_t size;
} zmodule_data_directory_t, *pzmodule_data_directory_t;

typedef struct _zmodule_header64
{
    uint8_t machine; // ZMODULE_MACHINE_
    uint8_t numberOfSections;
    uint16_t sizeOfBaseHeader;
    uint32_t sizeOfHeaders;
    uint32_t sizeOfImage;
    uint64_t imageBase;
    zmodule_data_directory_t dataDirectory[ZMODULE_NUMBEROF_DIRECTORY_ENTRIES];
} zmodule_header64_t, *pzmodule_header64_t;

typedef struct _zmodule_header32
{
    uint8_t machine; // ZMODULE_MACHINE_
    uint8_t numberOfSections;
    uint16_t sizeOfBaseHeader;
    uint32_t sizeOfHeaders;
    uint32_t sizeOfImage;
    uint32_t imageBase;
    zmodule_data_directory_t dataDirectory[ZMODULE_NUMBEROF_DIRECTORY_ENTRIES];
} zmodule_header32_t, *pzmodule_header32_t;

#ifdef _WIN64

typedef zmodule_header64_t zmodule_header_t;
typedef pzmodule_header64_t pzmodule_header_t;

#else

typedef zmodule_header32_t zmodule_header_t;
typedef pzmodule_header32_t pzmodule_header_t;

#endif // _WIN64

typedef struct _zmodule_section_header
{
    uint32_t virtualAddress;
    uint32_t pointerToRawData;
    uint32_t sizeOfRawData;
} zmodule_section_header_t, *pzmodule_section_header_t;

#pragma pack(pop)

#endif // __ZMODULE_ZMODULEDEFS_H_
