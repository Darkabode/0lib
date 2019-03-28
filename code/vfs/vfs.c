#include "vfs.h"

// void zfs_toupper(char* string, uint32_t strLen)
// {
// 	uint32_t i;
// 	for (i = 0; i < strLen; i++) {
//         if (string[i] >= 'a' && string[i] <= 'z') {
// 			string[i] -= 32;
//         }
//         if (string[i] == '\0') {
// 			break;
//         }
// 	}
// }

void zfs_tolower(char* string, uint32_t strLen)
{
	uint32_t i;
	for (i = 0; i < strLen; i++) {
        if (string[i] >= 'A' && string[i] <= 'Z') {
			string[i] += 32;
        }
        if (string[i] == '\0') {
			break;
        }
	}
}

char zfs_strmatch(const char* str1, const char* str2, uint16_t len)
{
	uint16_t i;
	char char1, char2;

	if (!len) {
		if (fn_lstrlenA(str1) != fn_lstrlenA(str2)) {
			return FALSE;
		}
		len = (uint16_t)fn_lstrlenA(str1);
	}
	
	for (i = 0; i < len; i++) {
		char1 = str1[i];
		char2 = str2[i];
		if (char1 >= 'A' && char1 <= 'Z') {
			char1 += 32;
		}
		if (char2 >= 'A' && char2 <= 'Z') {
			char2 += 32;
		}

		if (char1 != char2) {
			return FALSE;
		}
	}

	return TRUE;
}

char* zfs_strtok(const char* string, char* token, uint16_t *tokenNumber, char* last, uint16_t Length)
{
	uint16_t strLen = Length;
	uint16_t i,y, tokenStart, tokenEnd = 0;

	i = 0;
	y = 0;

	if (string[i] == '\\' || string[i] == '/') {
		i++;
	}

	tokenStart = i;

	while (i < strLen) {
		if (string[i] == '\\' || string[i] == '/') {
			y++;
			if (y == *tokenNumber) {
				tokenStart = (uint16_t)(i + 1);
			}
			if (y == (*tokenNumber + 1)) {
				tokenEnd = i;
				break;
			}
		}
		i++;
	}

	if (!tokenEnd) {
		if (*last == TRUE) {
			return NULL;
		}
        else {
            *last = TRUE;
		}
		tokenEnd = i;
	}
	if ((tokenEnd - tokenStart) <= ZFS_MAX_FILENAME) {
		__movsb(token, (string + tokenStart), (uint32_t)(tokenEnd - tokenStart));
		token[tokenEnd - tokenStart] = '\0';
	}
    else {
		__movsb(token, (string + tokenStart), ZFS_MAX_FILENAME + 1);
		token[ZFS_MAX_FILENAME] = '\0';
	}
	//token[tokenEnd - tokenStart] = '\0';
    *tokenNumber += 1;

	return token;	
}

char zfs_wildcompare(const char* pszWildCard, const char* pszString)
{
    const char* pszWc = NULL;
	const char* pszStr = NULL;	// Encourage the string pointers to be placed in memory.
    do {
        if (*pszWildCard == '*') {
			while (*(1 + pszWildCard++) == '*'); // Eat up multiple '*''s
			pszWc = (pszWildCard - 1);
            pszStr = pszString;
        }

		if (*pszWildCard == '?' && !*pszString) {
			return FALSE;	// False when the string is ended, yet a ? charachter is demanded.
		}
        if (*pszWildCard != '?' && *pszWildCard != *pszString) {
			if (pszWc == NULL) {
				return FALSE;
			}
            pszWildCard = pszWc;
            pszString = pszStr++;
        }
    } while (*pszWildCard++ && *pszString++);

	while (*pszWildCard == '*') {
		pszWildCard++;
	}

	if (!*(pszWildCard - 1)) {	// WildCard is at the end. (Terminated)
		return TRUE;	// Therefore this must be a match.
	}

	return FALSE;	// If not, then return FALSE!
}

uint32_t zfs_get_cluster_chain_number(uint32_t nEntry, uint16_t nEntrySize)
{
	uint32_t clusterChainNumber = nEntry / (BDEV_BLOCK_SIZE * ZFS_SECTORS_PER_CLUSTER / nEntrySize);
	return clusterChainNumber;
}

uint32_t zfs_get_cluster_position(uint32_t nEntry, uint16_t nEntrySize)
{
	return nEntry % ((BDEV_BLOCK_SIZE * ZFS_SECTORS_PER_CLUSTER) / nEntrySize);
}

uint32_t zfs_get_major_block_number(uint32_t nEntry, uint16_t nEntrySize)
{
	uint32_t relClusterEntry = nEntry % (BDEV_BLOCK_SIZE * ZFS_SECTORS_PER_CLUSTER / nEntrySize);
	uint32_t majorBlockNumber = relClusterEntry / (BDEV_BLOCK_SIZE / nEntrySize);
	return majorBlockNumber;
}

uint8_t zfs_get_minor_block_number(uint32_t nEntry, uint16_t nEntrySize)
{
	uint32_t relClusterEntry = nEntry % (BDEV_BLOCK_SIZE * ZFS_SECTORS_PER_CLUSTER / nEntrySize);
	uint16_t relmajorBlockEntry = (uint16_t)(relClusterEntry % (BDEV_BLOCK_SIZE / nEntrySize));
	uint8_t minorBlockNumber = (uint8_t)(relmajorBlockEntry / (BDEV_BLOCK_SIZE / nEntrySize));
	return minorBlockNumber;
}

uint32_t zfs_get_minor_block_entry(uint32_t nEntry, uint16_t nEntrySize)
{
	uint32_t relClusterEntry = nEntry % (BDEV_BLOCK_SIZE * ZFS_SECTORS_PER_CLUSTER / nEntrySize);
	uint32_t relmajorBlockEntry = (uint32_t)(relClusterEntry % (BDEV_BLOCK_SIZE / nEntrySize));
	return (relmajorBlockEntry % (BDEV_BLOCK_SIZE / nEntrySize));
}



void zfs_lock(pzfs_io_manager_t pIoman)
{
    fn_WaitForSingleObject(pIoman->mutex, INFINITE);
    while ((pIoman->locks & ZFS_LOCK)) {
        fn_ReleaseMutex(pIoman->mutex);
        fn_SwitchToThread();
        fn_WaitForSingleObject(pIoman->mutex, INFINITE);
    }
    pIoman->locks |= ZFS_LOCK;
    fn_ReleaseMutex(pIoman->mutex);
}

void zfs_unlock(pzfs_io_manager_t pIoman)
{
    fn_WaitForSingleObject(pIoman->mutex, INFINITE);
    pIoman->locks &= ~ZFS_LOCK;
    fn_ReleaseMutex(pIoman->mutex);
}

uint32_t zfs_cluster_to_lba(pzfs_io_manager_t pIoman, uint32_t Cluster)
{
    uint32_t lba = 0;

    if (pIoman) {
        if (Cluster > 1) {
            lba = ((Cluster - 2) * ZFS_SECTORS_PER_CLUSTER) + pIoman->firstDataSector;
        }
        else {
            lba = pIoman->clusterBeginLBA;
        }
    }
    return lba;
}

// uint32_t zfs_lba_to_cluster(pzfs_io_manager_t pIoman, uint32_t Address)
// {
// 	uint32_t cluster = 0;
// 	if (pIoman != NULL) {
// 		cluster = ((Address - pIoman->clusterBeginLBA) / ZFS_SECTORS_PER_CLUSTER) + 2;
// 	}
// 	return cluster;
// }

uint32_t zfs_get_entry(pzfs_io_manager_t pIoman, uint32_t nCluster, int* pError)
{
    zfs_buffer_t* pBuffer;
    uint32_t zfsOffset;
    uint32_t zfsSector;
    uint32_t zfsSectorEntry;
    uint32_t zfsEntry;
    uint32_t LBAadjust;
    uint32_t relClusterEntry;

    *pError = ERR_OK;

    if (nCluster >= pIoman->numClusters) {
        // HT: find a more specific error code
        *pError = ZFS_ERR_NOT_ENOUGH_FREE_SPACE | ZFS_GETENTRY;
        return 0;
    }
    zfsOffset = 4 * nCluster;

    zfsSector = pIoman->beginLBA + (zfsOffset / BDEV_BLOCK_SIZE);
    zfsSectorEntry = zfsOffset % BDEV_BLOCK_SIZE;

    LBAadjust = (uint32_t)(zfsSectorEntry / BDEV_BLOCK_SIZE);
    relClusterEntry = zfsSectorEntry % BDEV_BLOCK_SIZE;

    pBuffer = zfs_get_buffer(pIoman, zfsSector + LBAadjust, ZFS_MODE_READ);
    if (pBuffer == NULL) {
        *pError = ZFS_ERR_DEVICE_DRIVER_FAILED | ZFS_GETENTRY;
        return 0;
    }

    zfsEntry = *(uint32_t*)(pBuffer->pBuffer + relClusterEntry);
    zfsEntry &= 0x0fffffff;	// Clear the top 4 bits.
    zfs_release_buffer(pIoman, pBuffer);

    return zfsEntry;
}

int zfs_clear_cluster(pzfs_io_manager_t pIoman, uint32_t nCluster)
{
    pzfs_buffer_t pBuffer = NULL;
    int i;
    uint32_t BaseLBA;
    int ret = 0;

    BaseLBA = zfs_cluster_to_lba(pIoman, nCluster);

    for (i = 0; i < ZFS_SECTORS_PER_CLUSTER; i++) {
        if (i == 0) {
            pBuffer = zfs_get_buffer(pIoman, BaseLBA, ZFS_MODE_WR_ONLY);
            if (!pBuffer) {
                return ZFS_ERR_DEVICE_DRIVER_FAILED | ZFS_CLEARCLUSTER;
            }
            __stosb(pBuffer->pBuffer, 0x00, 512);
        }
        ret = zfs_write_block(pIoman, BaseLBA + i, 1, pBuffer->pBuffer);
        if (ret < 0) {
            break;
        }
    }
    pBuffer->modified = FALSE;
    zfs_release_buffer(pIoman, pBuffer);

    if (ZFS_isERR(ret)) {
        return ret;
    }

    return ERR_OK;
}

uint32_t zfs_traverse(pzfs_io_manager_t pIoman, uint32_t Start, uint32_t Count, int*pError)
{
    uint32_t i;
    uint32_t zfsEntry = Start, currentCluster = Start;

    *pError = ERR_OK;

    for (i = 0; i < Count; i++) {
        zfsEntry = zfs_get_entry(pIoman, currentCluster, pError);
        if (*pError) {
            return 0;
        }

        if (zfs_is_end_of_chain(zfsEntry)) {
            return currentCluster;
        }
        else {
            currentCluster = zfsEntry;
        }
    }

    return zfsEntry;
}

uint32_t zfs_find_end_of_chain(pzfs_io_manager_t pIoman, uint32_t Start, int*pError)
{
    uint32_t zfsEntry = Start, currentCluster = Start;

    *pError = ERR_OK;

    while (!zfs_is_end_of_chain(zfsEntry)) {
        zfsEntry = zfs_get_entry(pIoman, currentCluster, pError);
        if (*pError) {
            return 0;
        }

        if (zfs_is_end_of_chain(zfsEntry)) {
            return currentCluster;
        }
        else {
            currentCluster = zfsEntry;
        }
    }
    return zfsEntry;
}

char zfs_is_end_of_chain(uint32_t zfsEntry)
{
    char result = FALSE;
    if ((zfsEntry & 0x0fffffff) >= 0x0ffffff8) {
        result = TRUE;
    }
    if (zfsEntry == 0x00000000) {
        result = TRUE;	//Perhaps trying to read a deleted file!
    }
    return result;
}

int zfs_put_entry(pzfs_io_manager_t pIoman, uint32_t nCluster, uint32_t val)
{
    zfs_buffer_t* pBuffer;
    uint32_t zfsOffset;
    uint32_t zfsSector;
    uint32_t zfsSectorEntry;
    uint32_t LBAadjust;
    uint32_t relClusterEntry;

    // HT: avoid corrupting the disk
    if (!nCluster || nCluster >= pIoman->numClusters) {
        // find a more specific error code
        return ZFS_ERR_NOT_ENOUGH_FREE_SPACE | ZFS_PUTZFSENTRY;
    }
    zfsOffset = nCluster * 4;

    zfsSector = pIoman->beginLBA + (zfsOffset / BDEV_BLOCK_SIZE);
    zfsSectorEntry = zfsOffset % BDEV_BLOCK_SIZE;

    LBAadjust = (uint32_t)(zfsSectorEntry / BDEV_BLOCK_SIZE);
    relClusterEntry = zfsSectorEntry % BDEV_BLOCK_SIZE;

    pBuffer = zfs_get_buffer(pIoman, zfsSector + LBAadjust, ZFS_MODE_WRITE);
    if (!pBuffer) {
        return ZFS_ERR_DEVICE_DRIVER_FAILED | ZFS_PUTZFSENTRY;
    }
    val &= 0x0fffffff;	// Clear the top 4 bits.
    *(uint32_t*)(pBuffer->pBuffer + relClusterEntry) = val;
    zfs_release_buffer(pIoman, pBuffer);

    return ERR_OK;
}

uint32_t zfs_find_free_cluster(pzfs_io_manager_t pIoman, int*pError)
{
    zfs_buffer_t* pBuffer;
    uint32_t x, nCluster = pIoman->lastFreeCluster;
    uint32_t zfsOffset;
    uint32_t zfsSector;
    uint32_t zfsSectorEntry;
    uint32_t EntriesPerSector;
    uint32_t zfsEntry = 1;
    const int EntrySize = 4;

    *pError = ERR_OK;

    EntriesPerSector = BDEV_BLOCK_SIZE / EntrySize;
    zfsOffset = nCluster * EntrySize;

    for (zfsSector = (zfsOffset / BDEV_BLOCK_SIZE);
        zfsSector < pIoman->sectorsPerZFS;
        zfsSector++) {
        pBuffer = zfs_get_buffer(pIoman, pIoman->beginLBA + zfsSector, ZFS_MODE_READ);
        if (!pBuffer) {
            *pError = ZFS_ERR_DEVICE_DRIVER_FAILED | ZFS_FINDFREECLUSTER;
            return 0;
        }
        // HT double-check: don't use non-existing clusters
        if (nCluster >= pIoman->numClusters) {
            zfs_release_buffer(pIoman, pBuffer);
            *pError = ZFS_ERR_NOT_ENOUGH_FREE_SPACE | ZFS_FINDFREECLUSTER;
            return 0;
        }
        for (x = nCluster % EntriesPerSector; x < EntriesPerSector; x++) {
            zfsSectorEntry = zfsOffset % BDEV_BLOCK_SIZE;
            zfsEntry = *(uint32_t*)(pBuffer->pBuffer + zfsSectorEntry);
            zfsEntry &= 0x0fffffff;	// Clear the top 4 bits.
            if (zfsEntry == 0x00000000) {
                zfs_release_buffer(pIoman, pBuffer);
                pIoman->lastFreeCluster = nCluster;
                return nCluster;
            }
            zfsOffset += EntrySize;
            nCluster++;
        }
        zfs_release_buffer(pIoman, pBuffer);
    }
    *pError = ZFS_ERR_NOT_ENOUGH_FREE_SPACE | ZFS_FINDFREECLUSTER;
    return 0;
}

uint32_t zfs_create_cluster_chain(pzfs_io_manager_t pIoman, int*pError)
{
    uint32_t iStartCluster;
    int	Error;

    *pError = ERR_OK;

    zfs_lock(pIoman);
    iStartCluster = zfs_find_free_cluster(pIoman, &Error);
    if (ZFS_isERR(Error)) {
        *pError = Error;
        zfs_unlock(pIoman);
        return 0;
    }

    if (iStartCluster) {
        Error = zfs_put_entry(pIoman, iStartCluster, 0xFFFFFFFF); // Mark the cluster as End-Of-Chain
        if (ZFS_isERR(Error)) {
            *pError = Error;
            zfs_unlock(pIoman);
            return 0;
        }
    }
    zfs_unlock(pIoman);

    if (iStartCluster) {
        Error = zfs_decrease_free_clusters(pIoman, 1);
        if (ZFS_isERR(Error)) {
            *pError = Error;
            return 0;
        }
    }

    return iStartCluster;
}

uint32_t zfs_get_chain_length(pzfs_io_manager_t pIoman, uint32_t startCluster, uint32_t *pEndOfChain, int* pError)
{
    uint32_t len = 0, prevCluster = startCluster;

    *pError = ERR_OK;

    zfs_lock(pIoman);
    while (!zfs_is_end_of_chain(startCluster)) {
        prevCluster = startCluster;
        startCluster = zfs_get_entry(pIoman, startCluster, pError);
        if (*pError) {
            // break to call FF_unlockZFS
            len = 0;
            break;
        }
        ++len;
    }
    if (pEndOfChain) {
        *pEndOfChain = prevCluster;
    }
    zfs_unlock(pIoman);

    return len;
}

int zfs_unlink_cluster_chain(pzfs_io_manager_t pIoman, uint32_t startCluster)
{
    uint32_t zfsEntry;
    uint32_t currentCluster;
    uint32_t iLen = 0;
    uint32_t lastFree = startCluster;	/* HT addition : reset LastFreeCluster */
    int	Error;

    zfsEntry = startCluster;

    // Free all clusters in the chain!
    currentCluster = startCluster;
    zfsEntry = currentCluster;
    do {
        zfsEntry = zfs_get_entry(pIoman, zfsEntry, &Error);
        if (ZFS_isERR(Error)) {
            return Error;
        }
        Error = zfs_put_entry(pIoman, currentCluster, 0x00000000);
        if (ZFS_isERR(Error)) {
            return Error;
        }

        if (lastFree > currentCluster) {
            lastFree = currentCluster;
        }
        currentCluster = zfsEntry;
        iLen++;
    } while (!zfs_is_end_of_chain(zfsEntry));
    if (pIoman->lastFreeCluster > lastFree) {
        pIoman->lastFreeCluster = lastFree;
    }
    Error = zfs_increase_free_clusters(pIoman, iLen);
    if (ZFS_isERR(Error)) {
        return Error;
    }

    return ERR_OK;
}

uint32_t zfs_count_free_clusters(pzfs_io_manager_t pIoman, int*pError)
{
    zfs_buffer_t* pBuffer;
    uint32_t i, x;
    uint32_t zfsEntry;
    uint32_t EntriesPerSector;
    uint32_t FreeClusters = 0;

    *pError = ERR_OK;

    EntriesPerSector = BDEV_BLOCK_SIZE / 4;

    for (i = 0; i < pIoman->sectorsPerZFS; i++) {
        pBuffer = zfs_get_buffer(pIoman, pIoman->beginLBA + i, ZFS_MODE_READ);
        if (!pBuffer) {
            *pError = ZFS_ERR_DEVICE_DRIVER_FAILED | ZFS_COUNTFREECLUSTERS;
            return 0;
        }
        for (x = 0; x < EntriesPerSector; x++) {
            zfsEntry = *(uint32_t*)(pBuffer->pBuffer + x * 4) & 0x0fffffff; // Clearing the top 4 bits.
            if (!zfsEntry) {
                FreeClusters++;
            }
        }
        zfs_release_buffer(pIoman, pBuffer);
    }

    return FreeClusters <= pIoman->numClusters ? FreeClusters : pIoman->numClusters;
}

uint32_t zfs_get_free_size(pzfs_io_manager_t pIoman, int*pError)
{
    uint32_t freeClusters;

    if (pIoman) {
        zfs_lock(pIoman);
        if (!pIoman->freeClusterCount) {
            pIoman->freeClusterCount = zfs_count_free_clusters(pIoman, pError);
        }
        freeClusters = pIoman->freeClusterCount;
        zfs_unlock(pIoman);
        return (freeClusters * (ZFS_SECTORS_PER_CLUSTER * BDEV_BLOCK_SIZE));
    }
    return 0;
}

