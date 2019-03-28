#include "zmodule.h"
#include "raw_disk.h"

//pdisk_info_t raw_disk_open(uint32_t diskNum)
//{
//    DISK_GEOMETRY diskGeom;
//    wchar_t deviceName[MAX_PATH];
//    BOOL isOK;
//    pdisk_info_t pDiskInfo = NULL;
//    uint32_t bytes;
//
//    fn_wsprintfW(deviceName, L"\\\\.\\PhysicalDrive%u", diskNum);
//
//    isOK = 0;
//    do {
//        pDiskInfo = (pdisk_info_t)fn_VirtualAlloc(0,sizeof(disk_info_t),MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
//        if ( pDiskInfo == NULL ) {
//            //INLOG("Can't allocate memory for disk_info_t!!", 0);
//            break;
//        }
//
//        pDiskInfo->hDisk = fn_CreateFileW(deviceName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
//
//        if (pDiskInfo->hDisk == INVALID_HANDLE_VALUE) {
//            pDiskInfo->hDisk = NULL;
//            //INLOG("Can't open \\\\.\\PhysicalDrive", diskNum);
//            break;
//        }
//
//       isOK = fn_DeviceIoControl(pDiskInfo->hDisk, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &diskGeom, sizeof(diskGeom), (LPDWORD)&bytes, NULL);
//
//        if (isOK) {
//            pDiskInfo->media = diskGeom.MediaType;
//            pDiskInfo->bytesPerSec = diskGeom.BytesPerSector;
//            pDiskInfo->secsPerCyl = diskGeom.TracksPerCylinder * diskGeom.SectorsPerTrack;
//#ifdef _WIN64
//            pDiskInfo->totalSecs = (diskGeom.Cylinders.QuadPart * ((uint64_t)(pDiskInfo->secsPerCyl) * (uint64_t)(pDiskInfo->bytesPerSec)) );
//#else
//            
//            pDiskInfo->totalSecs = fn__allmul(diskGeom.Cylinders.QuadPart, fn__allmul((uint64_t)(pDiskInfo->secsPerCyl), (uint64_t)(pDiskInfo->bytesPerSec)));
//#endif // _WIN64
//        }
//    } while (0);
//
//    if ((!isOK) && (pDiskInfo != NULL))  {
//        if (pDiskInfo->hDisk != NULL) {
//            fn_CloseHandle(pDiskInfo->hDisk);
//        }
//        fn_VirtualFree(pDiskInfo, sizeof(disk_info_t), MEM_DECOMMIT|MEM_RELEASE);
//        pDiskInfo = NULL;
//    }
//
//    return pDiskInfo;
//}
//
//void raw_disk_close(pdisk_info_t pDiskInfo)
//{
//    fn_CloseHandle(pDiskInfo->hDisk);
//    fn_VirtualFree(pDiskInfo, sizeof(disk_info_t), MEM_DECOMMIT|MEM_RELEASE);
//}
//
//int raw_disk_read(pdisk_info_t pDiskInfo, void* buff, int size, uint64_t offset)
//{
//    int ret = 0;
//    uint64_t realOffset;
//    uint32_t realSize, bytes;
//    uint32_t diffOffset = 0;
//    uint8_t* pBuff;
//
//#ifdef _WIN64
//    if ((offset % pDiskInfo->bytesPerSec) || (size % pDiskInfo->bytesPerSec)) {
//        diffOffset = offset % pDiskInfo->bytesPerSec;
//#else
//    if (fn__aullrem(offset, pDiskInfo->bytesPerSec) || fn__aullrem(size, pDiskInfo->bytesPerSec)) {
//        diffOffset = fn__aullrem(offset, pDiskInfo->bytesPerSec);
//#endif // _WIN64        
//        realOffset = offset - diffOffset;
//        realSize = size + diffOffset;
//        realSize = realSize + (pDiskInfo->bytesPerSec - (realSize % pDiskInfo->bytesPerSec));
//        pBuff = (uint8_t*)fn_VirtualAlloc(0,realSize,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
//    }
//    else {
//        realOffset = offset;
//        realSize = (uint32_t)size;
//        pBuff = (uint8_t*)buff;
//    }
//
//    do {
//        if (pBuff == NULL) {
//            //INLOG("Can't allocate memory for read buffer!!", 0);
//            break;
//        }
//
//        bytes = fn_SetFilePointer(pDiskInfo->hDisk, (LONG)realOffset, &((LONG*)&realOffset)[1], FILE_BEGIN);
//
//        if (bytes == INVALID_SET_FILE_POINTER) {
//            //INLOG("Can't set pointer for reading sectors!!", 0);
//            break;
//        }
//
//        if (fn_ReadFile(pDiskInfo->hDisk, pBuff, realSize, (LPDWORD)&bytes, NULL) == 0) {
//            //INLOG("Can't read data from disk!!", 0);
//            break;
//        }
//        ret = 1;
//    } while (0);
//
//    if (pBuff != buff) {
//        if (ret) {
//            __movsb(buff, pBuff + diffOffset, size);
//        }
//        fn_VirtualFree(pBuff, realSize, MEM_DECOMMIT|MEM_RELEASE);
//    }
//
//    return ret;
//}
//
//int raw_disk_write(pdisk_info_t pDiskInfo, void* buff, int size, uint64_t offset)
//{
//    int ret = 0;
//    uint64_t realOffset;
//    uint32_t realSize, bytes;
//    uint32_t diffOffset = 0;
//    uint8_t* pBuff;
//#ifdef _WIN64
//    if ((offset % pDiskInfo->bytesPerSec) || (size % pDiskInfo->bytesPerSec)) {
//        diffOffset = offset % pDiskInfo->bytesPerSec;
//#else
//    if (fn__aullrem(offset, pDiskInfo->bytesPerSec) || fn__aullrem(size, pDiskInfo->bytesPerSec)) {
//        diffOffset = fn__aullrem(offset, pDiskInfo->bytesPerSec);
//#endif // _WIN64        
//        realOffset = offset - diffOffset;
//        realSize = diffOffset + size;
//        realSize = realSize + (pDiskInfo->bytesPerSec - (realSize % pDiskInfo->bytesPerSec));
//        pBuff = (uint8_t*)fn_VirtualAlloc(0,realSize,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
//    }
//    else {
//        realOffset = offset;
//        realSize = size;
//        pBuff = (uint8_t*)buff;
//    }
//
//    do {
//        if (pBuff == NULL) {
//            //INLOG("Can't allocate memory for write buffer!!", 0);
//            break;
//        }
//
//        bytes = fn_SetFilePointer(pDiskInfo->hDisk, (LONG)realOffset, &(((LONG*)&realOffset)[1]), FILE_BEGIN);
//
//        if (bytes == INVALID_SET_FILE_POINTER) {
//            //INLOG("Can't set pointer for writing sectors!!", 0);
//            break;
//        }
//
//        if (pBuff != buff) {
//            if (fn_ReadFile(pDiskInfo->hDisk, pBuff, realSize, (LPDWORD)&bytes, NULL) == 0) {
//                //INLOG("Can't read sectors in writing function!!", 0);
//                break;
//            }
//
//            __movsb(pBuff + diffOffset, buff, size);
//
//            fn_SetFilePointer(pDiskInfo->hDisk, (LONG)realOffset, &((LONG*)&realOffset)[1], FILE_BEGIN);
//
//            if (fn_WriteFile(pDiskInfo->hDisk, pBuff, realSize, (LPDWORD)&bytes, NULL) == 0) {
//                //INLOG("Can't write sectors!!", 0);
//                break;
//            }
//            ret = 1;
//        }
//        else {
//            if (fn_WriteFile(pDiskInfo->hDisk, pBuff, realSize, (LPDWORD)&bytes, NULL) == 0) {
//                //INLOG("Can't write sectors!!", 0);
//                break;
//            }
//            ret = 1;
//        }
//    } while (0);
//
//    if (pBuff != buff) {
//        fn_VirtualFree(pBuff, realSize, MEM_DECOMMIT|MEM_RELEASE);
//    }
//
//    return ret;	
//}
//
//uint64_t raw_get_disk_size(int dsk_num, int precision)
//{
//    pdisk_info_t pDiskInfo = NULL;
//    uint64_t mid, size  = 0;
//    uint64_t high, low;
//    uint64_t bps, pos;
//    uint32_t bytes;
//    DISK_GEOMETRY_EX dgx;
//    uint8_t buff[SECTOR_SIZE];
//
//    do {
//        if ((pDiskInfo = raw_disk_open(dsk_num)) == NULL) {
//            break;
//        }
//
//        if (fn_DeviceIoControl(pDiskInfo->hDisk, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0, (PVOID)&dgx, sizeof(dgx), (LPDWORD)&bytes, NULL)) {
//            size = dgx.DiskSize.QuadPart;
//            break;
//        }
//
//        bps = (uint64_t)pDiskInfo->bytesPerSec;
//        
//#ifdef _WIN64
//        high = (((uint64_t)pDiskInfo->secsPerCyl * bps) + pDiskInfo->totalSecs) / bps;
//        low = pDiskInfo->totalSecs / bps;
//#else
//        high = fn__aulldiv(fn__allmul((uint64_t)pDiskInfo->secsPerCyl, bps) + pDiskInfo->totalSecs, bps);
//        low = fn__aulldiv(pDiskInfo->totalSecs, bps);
//#endif // _WIN64
//        
//        size = pDiskInfo->totalSecs;
//
//        /* binary search disk space in hidden cylinder */
//        if (precision != 0) {
//            do {
//#ifdef _WIN64
//                mid = (high + low) / 2;
//                pos = mid * bps;
//#else
//                mid = fn__aulldiv(high + low, 2);
//                pos = fn__allmul(mid, bps);
//                
//#endif // _WIN64
//
//                if (raw_disk_read(pDiskInfo, buff, sizeof(buff), pos)) {
//                    low = mid+1; 
//                } else {
//                    high = mid-1;
//                }
//
//                if (high <= low) {
//#ifdef _WIN64
//                    size = low * bps;
//#else
//                    size = fn__allmul(low, bps);
//#endif // W_IN64
//                    break;
//                }
//            } while (1);
//        }
//    } while (0);
//
//    if (pDiskInfo != NULL) {
//        raw_disk_close(pDiskInfo);
//    }
//
//    return size;
//}
//
//int raw_get_drive_info(wchar_t* name, pdrive_info_t pInfo)
//{
//    int ret = 0;
//	PARTITION_INFORMATION_EX parInfoEx[2];
//	PARTITION_INFORMATION parInfo[2];
//	STORAGE_DEVICE_NUMBER stDevNum;
//	uint8_t* pbuff = NULL; //[4096];
//	uint32_t bytes, i;	
//	BOOL isOK;
//	HANDLE hDisk;
//	PVOLUME_DISK_EXTENTS diskExt;
//
//    pbuff = (uint8_t*)fn_VirtualAlloc(0,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
//
//    if (pbuff == NULL) {
//        //INLOG("Can't allocate memory for temp buffer", 0);
//        return ret;
//    }
//
//    diskExt = (PVOLUME_DISK_EXTENTS)pbuff;
//
//	__stosb(pInfo, 0, sizeof(drive_info_t));
//	
//	do {
//		DWORD err;
//		hDisk = fn_CreateFileW(name, SYNCHRONIZE | GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
//		err = fn_GetLastError();
//		if (hDisk == INVALID_HANDLE_VALUE) {
//            //INLOG("Can't open \\\\.\\GLOBALROOT\\ArcName\\multi(0)disk(0)rdisk(0)partition(1)", 0);
//            break;
//		}
//
//		isOK = fn_DeviceIoControl(hDisk, IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, parInfoEx, sizeof(parInfoEx), (LPDWORD)&bytes, NULL);
//
//		if (isOK) {
//			/*	if (ptix.PartitionStyle = PARTITION_STYLE_GPT) {
//				info->use_gpt = 1;
//			 */
//			pInfo->dsk_num = parInfoEx[0].PartitionNumber;
//			pInfo->par_size = parInfoEx[0].PartitionLength.QuadPart;				
//		}
//        else {
//			isOK = fn_DeviceIoControl(hDisk, IOCTL_DISK_GET_PARTITION_INFO, NULL, 0, parInfo, sizeof(parInfo), (LPDWORD)&bytes, NULL);
//
//			if (!isOK) {
//                //INLOG("IO error during obtaining boot disk 1", fn_GetLastError());
//                break;
//			}
//
//			pInfo->use_gpt = 0;
//			pInfo->dsk_num = parInfo[0].PartitionNumber;
//			pInfo->par_size = parInfo[0].PartitionLength.QuadPart;
//		}
//
//		isOK = fn_DeviceIoControl(hDisk, IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &stDevNum, sizeof(stDevNum), (LPDWORD)&bytes, NULL);
//
//		if (isOK) {
//			pInfo->dsk_num = 1;
//			pInfo->dsk_type = DSK_BASIC;
//			pInfo->par_numb = stDevNum.PartitionNumber;
//			pInfo->disks[0].number = stDevNum.DeviceNumber;
//			pInfo->disks[0].size = raw_get_disk_size(stDevNum.DeviceNumber, 0);
//		}
//        else {
//			isOK = fn_DeviceIoControl(hDisk, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0, diskExt, sizeof(pbuff), (LPDWORD)&bytes, NULL);
//				
//			if (isOK) {
//				for (i = 0; i < diskExt->NumberOfDiskExtents; i++) {
//					pInfo->disks[i].number = diskExt->Extents[i].DiskNumber;
//					pInfo->disks[i].prt_start = diskExt->Extents[i].StartingOffset.QuadPart;
//					pInfo->disks[i].prt_size = diskExt->Extents[i].ExtentLength.QuadPart;
//					pInfo->disks[i].size = raw_get_disk_size(pInfo->disks[i].number, 0);
//				}
//
//				if ((pInfo->dsk_num = diskExt->NumberOfDiskExtents) == 1) {
//					pInfo->dsk_type = DSK_DYN_SIMPLE;
//				}
//                else {					
//					pInfo->dsk_type = DSK_DYN_SPANNED;
//				}
//			}
//            else {
//                //INLOG("IO error during obtaining boot disk 2", 0);
//                break;
//			}
//		}
//		ret = 1;
//	} while (0);
//
//	if (hDisk != INVALID_HANDLE_VALUE) {
//		fn_CloseHandle(hDisk);
//	}
//
//    if (pbuff != NULL) {
//        fn_VirtualFree(pbuff, 4096, MEM_DECOMMIT|MEM_RELEASE);
//    }
//
//	return ret;
//}
//
//int raw_get_bootable_disk(uint32_t* pDiskNum1, uint32_t* pDiskNum2)
//{
//    int ret;
//    drive_info_t driveInfo;
//
//	// Некоторыые соответствия класса WMI Win32_DiskPartition и компонентов Arc-идентификатора:
//	// rdisk(DiskIndex)
//	// partition(Index + 1)
//    ret = raw_get_drive_info(L"\\\\.\\GLOBALROOT\\ArcName\\multi(0)disk(0)rdisk(1)partition(1)", &driveInfo);
//
//    if (ret && driveInfo.dsk_num <= 2) {
//        if (driveInfo.dsk_num > 1) {
//            *pDiskNum1 = driveInfo.disks[0].number;
//            *pDiskNum2 = driveInfo.disks[1].number;
//        }
//        else {
//            *pDiskNum1 = driveInfo.disks[0].number;
//            *pDiskNum2 = driveInfo.disks[0].number;
//        }
//    }
//    return ret;
//}
//
//int raw_check_fs_type(uint8_t* buff)
//{
//	if (fn_RtlCompareMemory(buff + 3, "NTFS    ", 8) == 8) {
//        return FS_NTFS;
//    }
//	if (fn_RtlCompareMemory(buff + 54, "FAT12   ", 8) == 8) {
//        return FS_FAT12;
//    }
//	if (fn_RtlCompareMemory(buff + 54, "FAT16   ", 8) == 8) {
//        return FS_FAT16;
//    }
//	if (fn_RtlCompareMemory(buff + 82, "FAT32   ", 8) == 8) {
//        return FS_FAT32;
//    }
//	if (fn_RtlCompareMemory(buff + 3, "EXFAT   ", 8) == 8) {
//        return FS_EXFAT;
//    }
//    return FS_UNK;
//}
