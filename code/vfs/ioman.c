#include "vfs.h"

void zfs_init_buffer_descriptors(pzfs_io_manager_t pIoman)
{
    uint16_t i;
    pzfs_buffer_t pBuffer = pIoman->pBuffers;
    pIoman->lastReplaced = 0;
    for (i = 0; i < pIoman->cacheSize; ++i, ++pBuffer) {
        pBuffer->pBuffer = (uint8_t *)((pIoman->pCacheMem) + (BDEV_BLOCK_SIZE * i));
    }
}

pzfs_io_manager_t zfs_create_io_manager()
{
    pzfs_io_manager_t pIoman = NULL;
    
	pIoman = (pzfs_io_manager_t)memory_alloc(sizeof(zfs_io_manager_t));

	__stosb(pIoman, 0, sizeof(zfs_io_manager_t));

    pIoman->pCacheMem = (uint8_t*)memory_alloc(65536);

	__stosb(pIoman->pCacheMem, 0, 65536);

    pIoman->cacheSize = (uint16_t)(65536 / BDEV_BLOCK_SIZE);

	/*	Malloc() memory for buffer objects. (ZFS never refers to a buffer directly
		but uses buffer objects instead. Allows us to provide thread safety.
    */
	pIoman->pBuffers = (pzfs_buffer_t)memory_alloc(sizeof(zfs_buffer_t) * pIoman->cacheSize);
    __stosb(pIoman->pBuffers, 0, sizeof(zfs_buffer_t) * pIoman->cacheSize);

	zfs_init_buffer_descriptors(pIoman);

	// Finally create a Semaphore for Buffer Description modifications.
	pIoman->mutex = fn_CreateMutexA(NULL, FALSE, NULL);

	return pIoman;	// Sucess, return the created object.
}

void zfs_destroy_io_manager(pzfs_io_manager_t pIoman)
{
	if (pIoman->pBuffers != NULL) {
		memory_free(pIoman->pBuffers);
	}

	if (pIoman->pCacheMem != NULL) {
		memory_free(pIoman->pCacheMem);
	}

	// Destroy any Semaphore that was created.
	fn_CloseHandle(pIoman->mutex);

	// Finally memory_free the zfs_io_manager_t object.
	memory_free(pIoman);
}

int zfs_flush_cache(pzfs_io_manager_t pIoman)
{
	uint16_t i, x;
    

	if (pIoman == NULL) {
		return ZFS_ERR_NULL_POINTER | ZFS_FLUSHCACHE;
	}

	fn_WaitForSingleObject(pIoman->mutex, INFINITE);

	for (i = 0; i < pIoman->cacheSize; i++) {
		if ((pIoman->pBuffers + i)->numHandles == 0 && (pIoman->pBuffers + i)->modified == TRUE) {

			zfs_write_block(pIoman, (pIoman->pBuffers + i)->sector, 1, (pIoman->pBuffers + i)->pBuffer);

			// Buffer has now been flushed, mark it as a read buffer and unmodified.
			(pIoman->pBuffers + i)->mode = ZFS_MODE_READ;
			(pIoman->pBuffers + i)->modified = FALSE;

			// Search for other buffers that used this sector, and mark them as modified
			// So that further requests will result in the new sector being fetched.
			for (x = 0; x < pIoman->cacheSize; x++) {
				if (x != i) {
					if ((pIoman->pBuffers + x)->sector == (pIoman->pBuffers + i)->sector && (pIoman->pBuffers + x)->mode == ZFS_MODE_READ) {
						(pIoman->pBuffers + x)->modified = TRUE;
					}
				}
			}
		}
	}

    fn_ReleaseMutex(pIoman->mutex);

	return ERR_OK;
}

#define	ZFS_GETBUFFER_SLEEP_TIME	10
#define	ZFS_GETBUFFER_WAIT_TIME	(20000 / ZFS_GETBUFFER_SLEEP_TIME)

pzfs_buffer_t zfs_get_buffer(pzfs_io_manager_t pIoman, uint32_t Sector, uint8_t Mode)
{
	zfs_buffer_t* pBuffer;
	zfs_buffer_t* pBufLRU;
	zfs_buffer_t* pBufMatch = NULL;
	int	RetVal;
	int LoopCount = ZFS_GETBUFFER_WAIT_TIME;
    int cacheSize = pIoman->cacheSize;
    
	
	if (cacheSize <= 0) {
		return NULL;
	}

	while (!pBufMatch) {
		if (!--LoopCount) {
			//
			// *pError = FF_ERR_IOMAN_GETBUFFER_TIMEOUT;
			//
			return NULL;
		}
		fn_WaitForSingleObject(pIoman->mutex, INFINITE);

		for (pBuffer = pIoman->pBuffers; pBuffer < pIoman->pBuffers + cacheSize; pBuffer++) {
			if (pBuffer->sector == Sector && pBuffer->valid) {
				pBufMatch = pBuffer;
				break;	// Don't look further if you found a perfect match
			}
		}

		if (pBufMatch) {
			// A Match was found process!
			if (Mode == ZFS_MODE_READ && pBufMatch->mode == ZFS_MODE_READ) {
				pBufMatch->numHandles += 1;
				pBufMatch->persistance += 1;
				break;
			}

			if (pBufMatch->numHandles == 0) {
				pBufMatch->mode = (Mode & ZFS_MODE_RD_WR);
				if ((Mode & ZFS_MODE_WRITE) != 0) {	// This buffer has no attached handles.
					pBufMatch->modified = TRUE;
				}
				pBufMatch->numHandles = 1;
				pBufMatch->persistance += 1;
				break;
			}

			pBufMatch = NULL;	// Sector is already in use, keep yielding until its available!

		}
        else {
			pBufLRU   = NULL;	// So put them to NULL here

			for (pBuffer = pIoman->pBuffers; pBuffer < pIoman->pBuffers + cacheSize; pBuffer++) {
				if (pBuffer->numHandles)
					continue;  // Occupied
				pBuffer->lru += 1;

				if (!pBufLRU) {
					pBufLRU = pBuffer;
				}

				if (pBuffer->lru > pBufLRU->lru || (pBuffer->lru == pBufLRU->lru && pBuffer->persistance > pBufLRU->persistance)) {
					pBufLRU = pBuffer;
				}

			}
			// Choose a suitable buffer!
			if (pBufLRU) {
				// Process the suitable candidate.
				if (pBufLRU->modified == TRUE) {
					// Along with the TRUE parameter to indicate semapahore has been claimed
					RetVal = zfs_write_block(pIoman, pBufLRU->sector, 1, pBufLRU->pBuffer);
					if (RetVal < 0) {
						pBufMatch = NULL;
						break;
					}
				}
				if (Mode == ZFS_MODE_WR_ONLY) {
					__stosb (pBufLRU->pBuffer, '\0', BDEV_BLOCK_SIZE);
				}
                else {
					RetVal = zfs_read_block(pIoman, Sector, 1, pBufLRU->pBuffer);
					if (RetVal < 0) {
						pBufMatch = NULL;
						break;
					}
				}
				pBufLRU->mode = (Mode & ZFS_MODE_RD_WR);
				pBufLRU->persistance = 1;
				pBufLRU->lru = 0;
				pBufLRU->numHandles = 1;
				pBufLRU->sector = Sector;

				pBufLRU->modified = (Mode & ZFS_MODE_WRITE) != 0;

				pBufLRU->valid = TRUE;
				pBufMatch = pBufLRU;
				break;
			}

		}
	}
	fn_ReleaseMutex(pIoman->mutex);

	return pBufMatch;	// Return the Matched Buffer!
}

void zfs_release_buffer(pzfs_io_manager_t pIoman, pzfs_buffer_t pBuffer)
{
    
	// Protect description changes with a semaphore.
	fn_WaitForSingleObject(pIoman->mutex, INFINITE);
	if (pBuffer->numHandles) {
		pBuffer->numHandles--;
	}
    else {
		//printf ("FF_ReleaseBuffer: buffer not claimed\n");
	}
	fn_ReleaseMutex(pIoman->mutex);
}

int zfs_read_block(pzfs_io_manager_t pIoman, uint32_t ulSectorLBA, uint32_t ulNumSectors, void *pBuffer)
{
	int slRetVal = 0;

	if (pIoman->totalSectors) {
		if ((ulSectorLBA + ulNumSectors) > pIoman->totalSectors) {
			return (ZFS_ERR_OUT_OF_BOUNDS_READ | ZFS_BLOCKREAD);		
		}
	}
	
    slRetVal = bdev_read(pBuffer, ulSectorLBA, ulNumSectors, pIoman->pbs);
	return slRetVal;
}

int zfs_write_block(pzfs_io_manager_t pIoman, uint32_t ulSectorLBA, uint32_t ulNumSectors, void *pBuffer)
{
	int slRetVal = 0;

	if (pIoman->totalSectors) {
		if ((ulSectorLBA + ulNumSectors) > pIoman->totalSectors) {
			return (ZFS_ERR_OUT_OF_BOUNDS_WRITE | ZFS_BLOCKWRITE);
		}
	}
	
    slRetVal = bdev_write(pBuffer, ulSectorLBA, ulNumSectors, pIoman->pbs);

	return slRetVal;
}

int zfs_mount(pzfs_io_manager_t pIoman)
{
	zfs_buffer_t* pBuffer = 0;
    

	__stosb(pIoman->pBuffers, 0, sizeof(zfs_buffer_t) * pIoman->cacheSize);
	__stosb(pIoman->pCacheMem, 0, BDEV_BLOCK_SIZE * pIoman->cacheSize);

	zfs_init_buffer_descriptors(pIoman);
	pIoman->firstFile = 0;

	pBuffer = zfs_get_buffer(pIoman, 0, ZFS_MODE_READ);
	if (pBuffer == NULL) {
		return ERR_BAD;
	}

	// Assume ZFS16, then we'll adjust if its ZFS32
	pIoman->reservedSectors = *(uint16_t*)(pBuffer->pBuffer + ZFS_RESERVED_SECTORS);
	pIoman->beginLBA = pIoman->reservedSectors;

	pIoman->sectorsPerZFS	= *(uint32_t*)(pBuffer->pBuffer + ZFS_SECTORS_PER_ZFS);
	pIoman->rootDirCluster	= *(uint32_t*)(pBuffer->pBuffer + ZFS_ROOT_DIR_CLUSTER);
	pIoman->clusterBeginLBA	= pIoman->reservedSectors + pIoman->sectorsPerZFS;
	pIoman->totalSectors = *(uint32_t*)(pBuffer->pBuffer + ZFS_TOTAL_SECTORS);

	zfs_release_buffer(pIoman, pBuffer);	// Release the buffer finally!

	pIoman->rootDirSectors	= ((*(uint16_t*)(pBuffer->pBuffer + ZFS_ROOT_ENTRY_COUNT) * ZFS_ENTRY_SIZE) + BDEV_BLOCK_SIZE - 1) / BDEV_BLOCK_SIZE;
	pIoman->firstDataSector	= pIoman->clusterBeginLBA + pIoman->rootDirSectors;
	pIoman->dataSectors		= pIoman->totalSectors - (pIoman->reservedSectors + pIoman->sectorsPerZFS + pIoman->rootDirSectors);
	
	pIoman->numClusters = pIoman->dataSectors / ZFS_SECTORS_PER_CLUSTER;

	pIoman->partitionMounted = TRUE;
	pIoman->lastFreeCluster	= 0;
	pIoman->freeClusterCount = 0;

	return ERR_OK;
}

int zfs_open_device(pzfs_io_manager_t pIoman, const wchar_t* fsPath, uint8_t* fsKey, uint32_t keySize)
{
    BlockDriverState* bs;
    int err;
    

    err = bdev_open(&bs, fsPath);

    if (err != ERR_OK) {
        return err;
    }

    err = bdev_set_key(bs, fsKey, keySize);

    if (err != ERR_OK) {
        return err;
    }

    pIoman->pbs = bs;
    
    return err;
}

void zfs_close_device(pzfs_io_manager_t pIoman)
{
    

    bdev_close(pIoman->pbs);
}

char zfs_active_handles(pzfs_io_manager_t pIoman)
{
	uint32_t	i;
	zfs_buffer_t* pBuffer;

	for (i = 0; i < pIoman->cacheSize; ++i) {
		pBuffer = (pIoman->pBuffers + i);
		if (pBuffer->numHandles) {
			return TRUE;
		}
	}

	return FALSE;
}

int zfs_unmount(pzfs_io_manager_t pIoman)
{
	int RetVal = ERR_OK;
    

	if (!pIoman) {
		return ZFS_ERR_NULL_POINTER | ZFS_UNMOUNTPARTITION;
	}
	if (!pIoman->partitionMounted)
		return ERR_OK;

	fn_WaitForSingleObject(pIoman->mutex, INFINITE);	// Ensure that there are no File Handles
	if (!zfs_active_handles(pIoman)) {
		if (pIoman->firstFile == NULL) {
			// Release Semaphore to call this function!
			fn_ReleaseMutex(pIoman->mutex);
			zfs_flush_cache(pIoman);			// Flush any unwritten sectors to disk.
			// Reclaim Semaphore
			fn_WaitForSingleObject(pIoman->mutex, INFINITE);
			pIoman->partitionMounted = FALSE;
		}
        else {
			RetVal = ZFS_ERR_ACTIVE_HANDLES | ZFS_UNMOUNTPARTITION;
		}
	}
    else {
		RetVal = ZFS_ERR_ACTIVE_HANDLES | ZFS_UNMOUNTPARTITION;	// Active handles found on the cache.
	}
	fn_ReleaseMutex(pIoman->mutex);

	return RetVal;
}


int zfs_increase_free_clusters(pzfs_io_manager_t pIoman, uint32_t Count)
{
	int Error;
    

    if (!pIoman->freeClusterCount) {
		pIoman->freeClusterCount = zfs_count_free_clusters(pIoman, &Error);
		if (ZFS_isERR(Error)) {
			return Error;
		}
	}
    else {
		pIoman->freeClusterCount += Count;
	}

	return ERR_OK;
}

int zfs_decrease_free_clusters(pzfs_io_manager_t pIoman, uint32_t Count)
{
	int Error;
    

	if (!pIoman->freeClusterCount) {
		pIoman->freeClusterCount = zfs_count_free_clusters(pIoman, &Error);
		if (ZFS_isERR(Error)) {
			return Error;
		}
	}
    else {
		pIoman->freeClusterCount -= Count;
	}

	return ERR_OK;
}

uint32_t zfs_get_size(pzfs_io_manager_t pIoman)
{
    if (pIoman != NULL) {
        return (uint32_t)(pIoman->dataSectors * BDEV_BLOCK_SIZE);
    }
    return 0;
}
