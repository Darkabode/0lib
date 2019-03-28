#include "zmodule.h"

uint64_t zmodule_get_image_base(uint8_t* imageBase)
{
    uint64_t result = 0;
    pzmodule_header_t pZModuleHdr = (pzmodule_header_t)imageBase;

    if (pZModuleHdr->machine == ZMODULE_MACHINE_AMD64) {
        result = ((pzmodule_header64_t)pZModuleHdr)->imageBase;
    }
    else if (pZModuleHdr->machine == ZMODULE_MACHINE_IA32) {
        result = ((pzmodule_header32_t)pZModuleHdr)->imageBase;
    }

    return result;
}

uint8_t* zmodule_get_directory(uint8_t* imageBase, uint32_t directoryIndex, uint32_t* pSize)
{
    pzmodule_header32_t pZModule32Hdr;
    pzmodule_header64_t pZModule64Hdr;
    uint32_t va = 0;

    pZModule32Hdr = (pzmodule_header32_t)imageBase;
    if (pZModule32Hdr->machine == ZMODULE_MACHINE_IA32) {
        va = pZModule32Hdr->dataDirectory[directoryIndex].virtualAddress;
        if (va) {
            if (pSize != NULL) {
                *pSize = pZModule32Hdr->dataDirectory[directoryIndex].size;
            }

            return imageBase + va;
        }
        else {
            return (uint8_t*)-1;
        }
    }
    else if (pZModule32Hdr->machine == ZMODULE_MACHINE_AMD64) {
        pZModule64Hdr = (pzmodule_header64_t)pZModule32Hdr;
        va = pZModule64Hdr->dataDirectory[directoryIndex].virtualAddress;
        if (va) {
            if (pSize) {
                *pSize = pZModule64Hdr->dataDirectory[directoryIndex].size;
            }

            return imageBase + va;
        }
        else {
            return (uint8_t*)-1;
        }
    }

    return NULL;
}

PIMAGE_BASE_RELOCATION zmodule_process_relocation_block(uint8_t* pBlock, uint32_t relocsCount, uint16_t* pNextOffset, uint64_t delta)
{
    uint8_t* pFixupVA = NULL;
    uint16_t offset = 0;
    LONG lTemp = 0;

    for ( ; relocsCount--; pNextOffset++) {
        offset = *pNextOffset & ((uint16_t) 0xFFF);
        pFixupVA = pBlock + offset;

        switch ((*pNextOffset) >> 12) {
#ifdef _WIN64
            case IMAGE_REL_BASED_DIR64:
                *(uint64_t UNALIGNED*)pFixupVA += delta;
                break;
#else
            case IMAGE_REL_BASED_HIGHLOW:
                *(int32_t UNALIGNED*)pFixupVA += (uint32_t)delta;
                break;
            case IMAGE_REL_BASED_HIGH:
                lTemp = (*(uint16_t*)pFixupVA) << 16;
                lTemp += (uint32_t)delta;
                *(uint16_t*) pFixupVA = (uint16_t)(lTemp >> 16);
                break;
            case IMAGE_REL_BASED_LOW:
                lTemp = *((PSHORT)pFixupVA);
                lTemp += (uint32_t)delta;
                *((uint16_t*)pFixupVA) = (uint16_t)lTemp;
                break;
#endif // _WIN64
            case IMAGE_REL_BASED_ABSOLUTE:
                break;
            default:
                return (PIMAGE_BASE_RELOCATION)NULL;
        }
    }

    return (PIMAGE_BASE_RELOCATION)pNextOffset;
}

int zmodule_process_relocs(uint8_t* imageBase, uint64_t delta)
{
    uint32_t totalCountBytes = 0;
    uint8_t* pBlock;
    uint32_t sizeOfBlock;
    uint16_t* pNextOffset = NULL;
    PIMAGE_BASE_RELOCATION pNextBlock;

    pNextBlock = (PIMAGE_BASE_RELOCATION)zmodule_get_directory(imageBase, ZMODULE_DIRECTORY_ENTRY_BASERELOC, &totalCountBytes);
    if ((uint8_t*)pNextBlock == (uint8_t*)-1) {
        return 1;
    }
    if (pNextBlock == NULL || totalCountBytes == 0) {
        return 0;
    }

    while (totalCountBytes > 0 && pNextBlock != NULL) {
        sizeOfBlock = pNextBlock->SizeOfBlock;
        totalCountBytes -= sizeOfBlock;
        sizeOfBlock -= sizeof(IMAGE_BASE_RELOCATION);
        sizeOfBlock /= sizeof(uint16_t);
        pNextOffset = (uint16_t*)((uint8_t*)pNextBlock + sizeof(IMAGE_BASE_RELOCATION));

        pBlock = imageBase + pNextBlock->VirtualAddress;
        pNextBlock = zmodule_process_relocation_block(pBlock, sizeOfBlock, pNextOffset, delta);
    }

    return 1;
}

//#ifndef _ZMODULE_BUILD
//
//uint8_t* zmodule_load_sections(uint8_t* pOrigImage, uint32_t* pImageSize, uint32_t pageProtect)
//{
//    uint8_t* pNewImage;
//    pzmodule_header_t pZModuleHdr = (pzmodule_header_t)pOrigImage;
//    uint32_t sizeOfImage;
//
//    if (pZModuleHdr->machine == ZMODULE_MACHINE_AMD64) {
//        sizeOfImage = ((pzmodule_header64_t)pZModuleHdr)->sizeOfImage;
//    }
//    else /*if (pZModuleHdr->machine == ZMODULE_MACHINE_IA32)*/ {
//        sizeOfImage = ((pzmodule_header32_t)pZModuleHdr)->sizeOfImage;
//    }
//
//    pNewImage = (uint8_t*)fn_VirtualAlloc(NULL, sizeOfImage, MEM_RESERVE | MEM_COMMIT, pageProtect);
//    if (pNewImage != NULL) {
//        uint8_t i;
//        pzmodule_section_header_t pSectionHdr = (pzmodule_section_header_t)(pOrigImage + pZModuleHdr->sizeOfBaseHeader);
//
//        if (pImageSize != NULL) {
//            *pImageSize = sizeOfImage;
//        }
//
//        __movsb(pNewImage, pOrigImage, pSectionHdr->pointerToRawData);
//
//        for (i = 0; i < pZModuleHdr->numberOfSections; ++i) {
//            if (pSectionHdr[i].sizeOfRawData > 0) {
//                __movsb(pNewImage + pSectionHdr[i].virtualAddress, pOrigImage + pSectionHdr[i].pointerToRawData, pSectionHdr[i].sizeOfRawData);
//            }
//        }
//    }
//
//    return pNewImage;
//}
//
//uint8_t* zmodule_get_export(uint8_t* moduleBase, uint32_t exportNum, int bRVA)
//{
//    uint32_t exportSize;
//    PIMAGE_EXPORT_DIRECTORY pExports = (PIMAGE_EXPORT_DIRECTORY)zmodule_get_directory(moduleBase, ZMODULE_DIRECTORY_ENTRY_EXPORT, &exportSize);
//
//    if (pExports != NULL) {
//        uint32_t* addressOfFunctions;
//
//        // Должна быть таблица экспорта с ненулевым размером и двумя ординалами  @1 и @2.
//        if ((uint8_t*)pExports == moduleBase || exportSize == 0 || pExports->Base != 1 || pExports->NumberOfFunctions < (exportNum + 1)) {
//            return NULL;
//        }
//
//        addressOfFunctions = (uint32_t*)(moduleBase +  pExports->AddressOfFunctions);
//
//        // Смещения не должны быть нулевыми.
//        if (addressOfFunctions[exportNum] == 0) {
//            return NULL;
//        }
//
//        return (bRVA ? (uint8_t*)addressOfFunctions[exportNum] : moduleBase + addressOfFunctions[exportNum]);
//    }
//
//    return NULL;
//}
//
//#endif // _ZMODULE_BUILD
