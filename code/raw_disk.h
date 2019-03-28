#ifndef __COMMON_RAWDISK_H_
#define __COMMON_RAWDISK_H_

#define SECTOR_SIZE 512
#define DSK_BASIC 0

#define DSK_DYN_SIMPLE 1
#define DSK_DYN_SPANNED 2

typedef struct _drive_info
{
	uint32_t dsk_type;      // Тип диска.
	uint32_t dsk_num;       // Число разделов на диске.
	int use_gpt;            // Использует GPT таблицу разделов.
	int par_numb;           // Номер активного раздела.
	uint64_t par_size;      // Размер раздела.
	struct {
		uint32_t number;    // Номер диска.
		uint64_t size;      // Размер диска в секторах.
		uint64_t prt_start; // Начала раздела на диске.
		uint64_t prt_size;  // Размер раздела.
	} disks[16];
} drive_info_t, *pdrive_info_t;

typedef struct _disk_info
{
	HANDLE hDisk;
	MEDIA_TYPE media;
	uint32_t bytesPerSec; // Количество байт в одном секторе.
	uint32_t secsPerCyl;  // Количество секторов в цилиндре.
	uint64_t totalSecs;   // Общее количество секторов.
} disk_info_t, *pdisk_info_t;

#define IS_INVALID_SECTOR_SIZE(_s) ( (_s) % SECTOR_SIZE )
#define _ALIGN(size, align) (((size) + ((align) - 1)) & ~((align) - 1))

#define FS_UNK   0
#define FS_FAT12 1
#define FS_FAT16 2
#define FS_FAT32 3
#define FS_NTFS  4
#define FS_EXFAT 5

#endif // __COMMON_RAWDISK_H_
