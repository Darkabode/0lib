#include "vfs.h"

void zfs_lock_dir(pzfs_io_manager_t pIoman)
{
	fn_WaitForSingleObject(pIoman->mutex, INFINITE);
	while ((pIoman->locks & ZFS_DIR_LOCK)) {
		fn_ReleaseMutex(pIoman->mutex);
		fn_SwitchToThread(); // Keep Releasing and Yielding until we have the DIR protector.
		fn_WaitForSingleObject(pIoman->mutex, INFINITE);
	}
	pIoman->locks |= ZFS_DIR_LOCK;
	fn_ReleaseMutex(pIoman->mutex);
}

void zfs_unlock_dir(pzfs_io_manager_t pIoman)
{
    fn_WaitForSingleObject(pIoman->mutex, INFINITE);
    pIoman->locks &= ~ZFS_DIR_LOCK;
    fn_ReleaseMutex(pIoman->mutex);
}

int zfs_find_next_in_dir(pzfs_io_manager_t pIoman, pzfs_dir_entry_t pDirent, pzfs_fetch_context_t pFetchContext)
{
	uint8_t numLFNs;
	uint8_t EntryBuffer[ZFS_ENTRY_SIZE];
	int Error;

	if (!pIoman) {
		return ZFS_ERR_NULL_POINTER | ZFS_FINDNEXTINDIR;
	}

	for (; pDirent->currentItem < 0xFFFF; pDirent->currentItem += 1) {
		Error = zfs_fetch_entry_with_context(pIoman, pDirent->currentItem, pFetchContext, EntryBuffer);
		
		if (ZFS_isERR(Error)) {
			return Error;
		}
		
		if (EntryBuffer[0] != 0xE5) {
			if (zfs_is_end_of_dir(EntryBuffer)){
				return ZFS_ERR_DIR_END_OF_DIR | ZFS_FINDNEXTINDIR;
			}
			pDirent->attrib = EntryBuffer[ZFS_DIRENT_ATTRIB];
			if ((pDirent->attrib & ZFS_ATTR_LFN) == ZFS_ATTR_LFN) {
				// LFN Processing
				numLFNs = (uint8_t)(EntryBuffer[0] & ~0x40);
				pDirent->currentItem += (numLFNs - 1);
			} else if ((pDirent->attrib & ZFS_ATTR_VOLID) == ZFS_ATTR_VOLID) {
				// Do Nothing
			
			} else {
				zfs_populate_short_dirent(pDirent, EntryBuffer);
				pDirent->currentItem += 1;
				return ERR_OK;
			}
		}
	}
	
	return ZFS_ERR_DIR_END_OF_DIR | ZFS_FINDNEXTINDIR;
}

char zfs_short_name_exists(pzfs_io_manager_t pIoman, uint32_t ulDirCluster, char* szShortName, int*pError)
{
    uint16_t i;
    uint8_t EntryBuffer[ZFS_ENTRY_SIZE];
    uint8_t attrib;
	zfs_fetch_context_t	FetchContext;

    *pError = ERR_OK;

    *pError = zfs_init_entry_fetch(pIoman, ulDirCluster, &FetchContext);
	if (*pError) {
		return FALSE;
	}

	for (i = 0; i < 0xFFFF; i++) {
        *pError = zfs_fetch_entry_with_context(pIoman, i, &FetchContext, EntryBuffer);
		if (*pError) {
			break;
		}
		attrib = EntryBuffer[ZFS_DIRENT_ATTRIB];
		if (EntryBuffer[0x00] != 0xE5) {
			if (attrib != ZFS_ATTR_LFN) {
				//zfs_process_short_name((char* )EntryBuffer);
				if (zfs_is_end_of_dir(EntryBuffer)) {
					zfs_cleanup_entry_fetch(pIoman, &FetchContext);
					return FALSE;
				}
				if (fn_lstrcmpA(szShortName, (char*)EntryBuffer) == 0) {
					zfs_cleanup_entry_fetch(pIoman, &FetchContext);
					return TRUE;
				}
			}
		}
	}

	zfs_cleanup_entry_fetch(pIoman, &FetchContext);
    return FALSE;
}


uint32_t zfs_find_entry_in_dir(pzfs_io_manager_t pIoman, uint32_t DirCluster, const char* name, uint8_t pa_Attrib, pzfs_dir_entry_t pDirent, int* pError)
{
	zfs_fetch_context_t FetchContext;
	uint8_t* src;       // Pointer to read from pBuffer
	uint8_t* lastSrc;
	uint8_t	lastAttrib;
	char totalLFNs = 0;

	if (pError) {
        *pError = ERR_OK;
	}

	pDirent->currentItem = 0;
	pDirent->attrib = 0;
    pDirent->special = 0;

	zfs_init_entry_fetch(pIoman, DirCluster, &FetchContext);

	while (pDirent->currentItem < 0xFFFF) {
		if (zfs_fetch_entry_with_context(pIoman, pDirent->currentItem, &FetchContext, NULL)) {
			break;
		}
		lastSrc = FetchContext.pBuffer->pBuffer + BDEV_BLOCK_SIZE;
		for (src = FetchContext.pBuffer->pBuffer; src < lastSrc; src += ZFS_ENTRY_SIZE, pDirent->currentItem++) {
			if (zfs_is_end_of_dir(src)) {	// 0x00: end-of-dir
				zfs_cleanup_entry_fetch(pIoman, &FetchContext);
				return 0;
			}
			if (src[0] == 0xE5) {	// Entry not used
				pDirent->attrib = 0;
				continue;
			}
			lastAttrib = pDirent->attrib;
			pDirent->attrib = src[ZFS_DIRENT_ATTRIB];
            pDirent->special = src[ZFS_DIRENT_SPECIAL];
			if ((pDirent->attrib & ZFS_ATTR_LFN) == ZFS_ATTR_LFN) {
				continue;
			}
			if ((pDirent->attrib & ZFS_ATTR_VOLID) == ZFS_ATTR_VOLID) {
				totalLFNs = 0;
				continue;
			}
			__movsb((uint8_t*)pDirent->fileName, (const uint8_t*)src, ZFS_MAX_FILENAME);
            pDirent->fileName[ZFS_MAX_FILENAME] = '\0';
		    //zfs_process_short_name(pDirent->fileName);
		    totalLFNs = 0;

			if ((pDirent->attrib & pa_Attrib) == pa_Attrib){
				if (!fn_lstrcmpA(name, pDirent->fileName)) {
                    // Finally get the complete information		    
				    zfs_populate_short_dirent(pDirent, src);
				    // HT: CurrentItem wasn't increased here
				    pDirent->currentItem += 1;
					// Object found!
					zfs_cleanup_entry_fetch(pIoman, &FetchContext);
					return pDirent->objectCluster;	// Return the cluster number
				}
			}
			totalLFNs = 0;
		}
	}	// for (src = FetchContext.pBuffer->pBuffer; src < lastSrc; src += 32, pDirent->CurrentItem++)

	zfs_cleanup_entry_fetch(pIoman, &FetchContext);

	return 0;
}

uint32_t zfs_find_dir(pzfs_io_manager_t pIoman, const char* path, uint16_t pathLen, uint8_t special, int* pError)
{
    uint32_t dirCluster = pIoman->rootDirCluster;
	char mytoken[ZFS_MAX_FILENAME + 1];
	char* token;
    uint16_t it = 0;
    char last = FALSE;
    zfs_dir_entry_t myDir;

    *pError = ERR_OK;

    if (pathLen <= 1) {      // Must be the root dir! (/ or \)
		return pIoman->rootDirCluster;
    }
    
    if (path[pathLen-1] == '\\' || path[pathLen-1] == '/') {
		pathLen--;      
    }
	
    token = zfs_strtok(path, mytoken, &it, &last, pathLen);

     do {
        myDir.currentItem = 0;
        dirCluster = zfs_find_entry_in_dir(pIoman, dirCluster, token, ZFS_ATTR_DIR, &myDir, pError);

		if (*pError) {
			return 0;
		}

        if (!(special & ZFS_SPECIAL_SYSTEM) && (myDir.special & ZFS_SPECIAL_SYSTEM)) {
            return 0;
        }

		/*if (dirCluster == 0 && MyDir.CurrentItem == 2 && MyDir.FileName[0] == '.') { // .. Dir Entry pointing to root dir.
			dirCluster = pIoman->pPartition->RootDirCluster;
        }*/
        token = zfs_strtok(path, mytoken, &it, &last, pathLen);
    } while (token != NULL);

    return dirCluster;
}

void zfs_populate_short_dirent(pzfs_dir_entry_t pDirent, uint8_t* entryBuffer)
{	
	__movsb((uint8_t*)pDirent->fileName, (const uint8_t*)entryBuffer, ZFS_MAX_FILENAME);	// Copy the filename into the Dirent object.
    pDirent->fileName[ZFS_MAX_FILENAME] = '\0';

	zfs_tolower(pDirent->fileName, (uint32_t)fn_lstrlenA(pDirent->fileName));

	pDirent->objectCluster = *(uint32_t*)(entryBuffer + ZFS_DIRENT_CLUSTER);
	pDirent->createTime = *(uint32_t*)(entryBuffer + ZFS_DIRENT_CREATE_TIME);
	pDirent->modifiedTime = *(uint32_t*)(entryBuffer + ZFS_DIRENT_LASTMOD_TIME);
	pDirent->accessedTime = *(uint32_t*)(entryBuffer + ZFS_DIRENT_LASTACC_TIME);
	pDirent->filesize = *(uint32_t*)(entryBuffer + ZFS_DIRENT_FILESIZE);
	pDirent->attrib = entryBuffer[ZFS_DIRENT_ATTRIB];
    pDirent->special = entryBuffer[ZFS_DIRENT_SPECIAL];
}

/*
	Initialises a context object for FF_FetchEntryWithContext()
*/
int zfs_init_entry_fetch(pzfs_io_manager_t pIoman, uint32_t ulDirCluster, pzfs_fetch_context_t pContext)
{
	int Error;
    

	__stosb((uint8_t*)pContext, 0, sizeof(zfs_fetch_context_t));

	pContext->ulChainLength = zfs_get_chain_length(pIoman, ulDirCluster, NULL, &Error);	// Get the total length of the chain.
	if (ZFS_isERR(Error)) {
		return Error;
	}
	pContext->ulDirCluster = ulDirCluster;
	pContext->ulCurrentClusterLCN = ulDirCluster;
	pContext->ulCurrentClusterNum = 0;
	pContext->ulCurrentEntry = 0;

	return ERR_OK;
}

void zfs_cleanup_entry_fetch(pzfs_io_manager_t pIoman, pzfs_fetch_context_t pContext)
{
    

	if (pContext->pBuffer) {
		zfs_release_buffer(pIoman, pContext->pBuffer);
		pContext->pBuffer = NULL;
	}
}

int zfs_fetch_entry_with_context(pzfs_io_manager_t pIoman, uint32_t ulEntry, pzfs_fetch_context_t pContext, uint8_t *pEntryBuffer)
{
	
	uint32_t ulItemLBA;
	uint32_t ulRelItem;
	uint32_t ulClusterNum;
	int err;
    

	ulClusterNum = zfs_get_cluster_chain_number(ulEntry, ZFS_ENTRY_SIZE);
	ulRelItem = zfs_get_minor_block_entry(ulEntry, ZFS_ENTRY_SIZE);

	if (ulClusterNum != pContext->ulCurrentClusterNum) {
		// Traverse the zfs gently!
		if (ulClusterNum > pContext->ulCurrentClusterNum) {
			pContext->ulCurrentClusterLCN = zfs_traverse(pIoman, pContext->ulCurrentClusterLCN, (ulClusterNum - pContext->ulCurrentClusterNum), &err);
			if (ZFS_isERR(err)) {
				return err;
			}
		}
        else {
			pContext->ulCurrentClusterLCN = zfs_traverse(pIoman, pContext->ulDirCluster, ulClusterNum, &err);
			if (ZFS_isERR(err)) {
				return err;
			}
		}
		pContext->ulCurrentClusterNum = ulClusterNum;
	}

	if ((ulClusterNum + 1) > pContext->ulChainLength) {
		return ZFS_ERR_DIR_END_OF_DIR | ZFS_FETCHENTRYWITHCONTEXT;	// End of Dir was reached!
	}

	ulItemLBA = zfs_cluster_to_lba(pIoman, pContext->ulCurrentClusterLCN) + zfs_get_major_block_number(ulEntry, ZFS_ENTRY_SIZE);
	ulItemLBA = ulItemLBA + zfs_get_minor_block_number(ulRelItem, ZFS_ENTRY_SIZE);

	if (!pContext->pBuffer || (pContext->pBuffer->sector != ulItemLBA)) {
		if (pContext->pBuffer) {
			zfs_release_buffer(pIoman, pContext->pBuffer);
		}
		pContext->pBuffer = zfs_get_buffer(pIoman, ulItemLBA, ZFS_MODE_READ);
		if (!pContext->pBuffer) {
			return ZFS_ERR_DEVICE_DRIVER_FAILED | ZFS_FETCHENTRYWITHCONTEXT;
		}
	}
	
	if (pEntryBuffer) {	// HT Because it might be called with NULL
		__movsb(pEntryBuffer, (pContext->pBuffer->pBuffer + (ulRelItem * ZFS_ENTRY_SIZE)), ZFS_ENTRY_SIZE);
	}
	 
    return ERR_OK;
}


int zfs_push_entry_with_context(pzfs_io_manager_t pIoman, uint32_t ulEntry, pzfs_fetch_context_t pContext, uint8_t *pEntryBuffer)
{
	uint32_t ulItemLBA;
	uint32_t ulRelItem;
	uint32_t ulClusterNum;
	int	err;
    

	ulClusterNum = zfs_get_cluster_chain_number(ulEntry, ZFS_ENTRY_SIZE);
	ulRelItem = zfs_get_minor_block_entry(ulEntry, ZFS_ENTRY_SIZE);

	if (ulClusterNum != pContext->ulCurrentClusterNum) {
		// Traverse the zfs gently!
		if (ulClusterNum > pContext->ulCurrentClusterNum) {
			pContext->ulCurrentClusterLCN = zfs_traverse(pIoman, pContext->ulCurrentClusterLCN, (ulClusterNum - pContext->ulCurrentClusterNum), &err);
			if (ZFS_isERR(err)) {
				return err;
			}
		}
        else {
			pContext->ulCurrentClusterLCN = zfs_traverse(pIoman, pContext->ulDirCluster, ulClusterNum, &err);
			if (ZFS_isERR(err)) {
				return err;
			}
		}
		pContext->ulCurrentClusterNum = ulClusterNum;
	}

	if ((ulClusterNum + 1) > pContext->ulChainLength) {
		return ZFS_ERR_DIR_END_OF_DIR | ZFS_PUSHENTRYWITHCONTEXT;	// End of Dir was reached!
	}

	ulItemLBA = zfs_cluster_to_lba(pIoman, pContext->ulCurrentClusterLCN) + zfs_get_major_block_number(ulEntry, ZFS_ENTRY_SIZE);
	ulItemLBA = ulItemLBA + zfs_get_minor_block_number(ulRelItem, ZFS_ENTRY_SIZE);

	if (!pContext->pBuffer || (pContext->pBuffer->sector != ulItemLBA)) {
		if (pContext->pBuffer) {
			zfs_release_buffer(pIoman, pContext->pBuffer);
		}
		pContext->pBuffer = zfs_get_buffer(pIoman, ulItemLBA, ZFS_MODE_READ);
		if (!pContext->pBuffer) {
			return ZFS_ERR_DEVICE_DRIVER_FAILED | ZFS_PUSHENTRYWITHCONTEXT;
		}
	}

	__movsb((pContext->pBuffer->pBuffer + (ulRelItem * ZFS_ENTRY_SIZE)), pEntryBuffer, ZFS_ENTRY_SIZE);
	pContext->pBuffer->mode = ZFS_MODE_WRITE;
	pContext->pBuffer->modified = TRUE;
	 
    return ERR_OK;
}

int zfs_get_dir_entry(pzfs_io_manager_t pIoman, uint16_t nEntry, uint32_t dirCluster, pzfs_dir_entry_t pDirent)
{
	uint8_t entryBuffer[ZFS_ENTRY_SIZE];
	uint8_t numLFNs;
	zfs_fetch_context_t	FetchContext;
	int Error;
    

	Error = zfs_init_entry_fetch(pIoman, dirCluster, &FetchContext);
	if (ZFS_isERR(Error)) {
		return Error;
	}
	
	Error = zfs_fetch_entry_with_context(pIoman, nEntry, &FetchContext, entryBuffer);
	if (ZFS_isERR(Error)) {
		zfs_cleanup_entry_fetch(pIoman, &FetchContext);
		return Error;
	}
	if (entryBuffer[0] != 0xE5) {
		if (zfs_is_end_of_dir(entryBuffer)){
			zfs_cleanup_entry_fetch(pIoman, &FetchContext);
			return ZFS_ERR_DIR_END_OF_DIR | ZFS_GETDIRENTRY;
		}
		
        pDirent->special = entryBuffer[ZFS_DIRENT_SPECIAL];
		pDirent->attrib = entryBuffer[ZFS_DIRENT_ATTRIB];
		
		if ((pDirent->attrib & ZFS_ATTR_LFN) == ZFS_ATTR_LFN) {
			// LFN Processing
			numLFNs = (uint8_t)(entryBuffer[0] & ~0x40);
            pDirent->currentItem += (numLFNs - 1);
		}
        else if ((pDirent->attrib & ZFS_ATTR_VOLID) == ZFS_ATTR_VOLID) {
			// Do Nothing
		
		}
        else {
			zfs_populate_short_dirent(pDirent, entryBuffer);
			pDirent->currentItem += 1;
			zfs_cleanup_entry_fetch(pIoman, &FetchContext);
			return 0;
		}
	}

	zfs_cleanup_entry_fetch(pIoman, &FetchContext);
	return ERR_OK;
}

char zfs_is_end_of_dir(uint8_t *EntryBuffer)
{
	return !(EntryBuffer[0]);
}

int zfs_findfirst(pzfs_io_manager_t pIoman, pzfs_dir_entry_t pDirent, const char* path, uint8_t special)
{
	uint16_t pathLen;
	int	err;
	uint16_t i = 0;
	const char* szWildCard;	// Check for a Wild-card.

    pathLen = (uint16_t)fn_lstrlenA(path);

	if (pIoman == NULL) {
		return ZFS_ERR_NULL_POINTER | ZFS_FINDFIRST;
	}

    __stosb((uint8_t*)pDirent, 0, sizeof(zfs_dir_entry_t));

	pDirent->szWildCard[0] = '\0';	// WildCard blank if its not a wildCard.

	szWildCard = &path[pathLen - 1];

	if (pathLen) {
		while (*szWildCard != '\\' && *szWildCard != '/') {	// Open the dir of the last token.
			i++;
			szWildCard--;
			if (!(pathLen - i)) {
				break;
			}
		}
	}
			
	pDirent->dirCluster = zfs_find_dir(pIoman, path, pathLen - i, special, &err);
	if (ZFS_isERR(err)) {
		return err;
	}
	if (pDirent->dirCluster) {
		// Valid Dir found, copy the wildCard to filename!
		fn_lstrcpynA(pDirent->szWildCard, ++szWildCard, ZFS_MAX_FILENAME + 1);
	}

	if (pDirent->dirCluster == 0) {
		return ZFS_ERR_DIR_INVALID_PATH | ZFS_FINDFIRST;
	}

	// Initialise the Fetch Context
	err = zfs_init_entry_fetch(pIoman, pDirent->dirCluster, &pDirent->fetchContext);
	if (ZFS_isERR(err)) {
		return err;
	}
	
	pDirent->currentItem = 0;

	return zfs_findnext(pIoman, pDirent, special);
}

int zfs_findnext(pzfs_io_manager_t pIoman, pzfs_dir_entry_t pDirent, uint8_t special)
{
	int	err;
	uint8_t	numLFNs;
	uint8_t	EntryBuffer[ZFS_ENTRY_SIZE];
    

	if (pIoman == NULL) {
		return ZFS_ERR_NULL_POINTER | ZFS_FINDNEXT;
	}

	for ( ; pDirent->currentItem < 0xFFFF; ++pDirent->currentItem) {
		err = zfs_fetch_entry_with_context(pIoman, pDirent->currentItem, &pDirent->fetchContext, EntryBuffer);
		if (ZFS_isERR(err)) {
			zfs_cleanup_entry_fetch(pIoman, &pDirent->fetchContext);
			return err;
		}
		if (EntryBuffer[0] != ZFS_DELETED) {
			if (zfs_is_end_of_dir(EntryBuffer)){
				zfs_cleanup_entry_fetch(pIoman, &pDirent->fetchContext);
				return ZFS_ERR_DIR_END_OF_DIR | ZFS_FINDNEXT;
			}
			pDirent->attrib = EntryBuffer[ZFS_DIRENT_ATTRIB];
			if ((pDirent->attrib & ZFS_ATTR_LFN) == ZFS_ATTR_LFN) {
				// LFN Processing
				numLFNs = (uint8_t)(EntryBuffer[0] & ~0x40);
				// Get the shortname and check if it is marked deleted.
                pDirent->currentItem += (numLFNs - 1);
			}
            else if ((pDirent->attrib & ZFS_ATTR_VOLID) == ZFS_ATTR_VOLID) {
				// Do Nothing
			
			}
            else {
                // ѕропускаем, если не достаточно привелегий.
                if (!(special & ZFS_SPECIAL_SYSTEM) && (EntryBuffer[ZFS_DIRENT_SPECIAL] & ZFS_SPECIAL_SYSTEM)) {
                    continue;
                }
				zfs_populate_short_dirent(pDirent, EntryBuffer);
				if (pDirent->szWildCard[0]) {
					if (zfs_wildcompare(pDirent->szWildCard, pDirent->fileName)) {
						zfs_cleanup_entry_fetch(pIoman, &pDirent->fetchContext);
						pDirent->currentItem += 1;
						return ERR_OK;
					}
				}
                else {
					zfs_cleanup_entry_fetch(pIoman, &pDirent->fetchContext);
					pDirent->currentItem += 1;
					return ERR_OK;
				}
			}
		}
	}

	zfs_cleanup_entry_fetch(pIoman, &pDirent->fetchContext);
	
	return ZFS_ERR_DIR_END_OF_DIR | ZFS_FINDNEXT;
}

int zfs_rewindfind(pzfs_io_manager_t pIoman, pzfs_dir_entry_t pDirent)
{
	if (!pIoman) {
		return ZFS_ERR_NULL_POINTER | ZFS_REWINDFIND;
	}
	pDirent->currentItem = 0;
	return ERR_OK;
}

int zfs_find_free_dirent(pzfs_io_manager_t pIoman, uint32_t dirCluster, uint16_t sequential)
{

	uint8_t entryBuffer[ZFS_ENTRY_SIZE];
	uint16_t i = 0;
	uint16_t nEntry;
	int err;
	uint32_t dirLength;
	zfs_fetch_context_t	fetchContext;
    

	err = zfs_init_entry_fetch(pIoman, dirCluster, &fetchContext);
	if (ZFS_isERR(err)) {
		return err;
	}
	
	for (nEntry = 0; nEntry < 0xFFFF; nEntry++) {
		err = zfs_fetch_entry_with_context(pIoman, nEntry, &fetchContext, entryBuffer);
		if (ZFS_GETERROR(err) == ZFS_ERR_DIR_END_OF_DIR) {
			
			err = zfs_extend_directory(pIoman, dirCluster);
			zfs_cleanup_entry_fetch(pIoman, &fetchContext);

			if (ZFS_isERR(err)) {
				return err;
			}

			return nEntry;
		}
        else {
			if (ZFS_isERR(err)) {
				zfs_cleanup_entry_fetch(pIoman, &fetchContext);
				return err;
			}
		}
		if (zfs_is_end_of_dir(entryBuffer)) {	// If its the end of the Dir, then FreeDirents from here.
			// Check Dir is long enough!
			dirLength = fetchContext.ulChainLength;//FF_GetChainLength(pIoman, DirCluster, &iEndOfChain);
			if ((nEntry + sequential) > (uint16_t)(((ZFS_SECTORS_PER_CLUSTER * BDEV_BLOCK_SIZE) * dirLength) / ZFS_ENTRY_SIZE)) {
				err = zfs_extend_directory(pIoman, dirCluster);
			}

			zfs_cleanup_entry_fetch(pIoman, &fetchContext);

			if (ZFS_isERR(err)) {
				return err;
			}

			return nEntry;
		}
		if (entryBuffer[0] == 0xE5) {
			i++;
		}
        else {
			i = 0;
		}

		if (i == sequential) {
			zfs_cleanup_entry_fetch(pIoman, &fetchContext);
			return (nEntry - (sequential - 1));// Return the beginning entry in the sequential sequence.
		}
	}
	
	zfs_cleanup_entry_fetch(pIoman, &fetchContext);

	return ZFS_ERR_DIR_DIRECTORY_FULL | ZFS_FINDFREEDIRENT;
}

int zfs_put_dir_entry(pzfs_io_manager_t pIoman, uint16_t Entry, uint32_t DirCluster, pzfs_dir_entry_t pDirent)
{
	pzfs_buffer_t pBuffer;
	int	error;
	uint32_t itemLBA;
	uint32_t clusterNum;
	uint32_t relItem;
	uint32_t clusterAddress;
	uint8_t* entryPtr;
    

    clusterNum = zfs_get_cluster_chain_number(Entry, ZFS_ENTRY_SIZE);
    relItem = zfs_get_minor_block_entry(Entry, ZFS_ENTRY_SIZE);
    clusterAddress = zfs_traverse(pIoman, DirCluster, clusterNum, &error);
	
    if (ZFS_isERR(error)) {
		return error;
	}

	itemLBA = zfs_cluster_to_lba(pIoman, clusterAddress) + zfs_get_major_block_number(Entry, ZFS_ENTRY_SIZE);
	itemLBA = itemLBA + zfs_get_minor_block_number(relItem, ZFS_ENTRY_SIZE);
	
	pBuffer = zfs_get_buffer(pIoman, itemLBA, ZFS_MODE_WRITE);

	if (pBuffer == NULL) {
		return ZFS_ERR_DEVICE_DRIVER_FAILED | ZFS_PUTENTRY;
	}

    entryPtr = pBuffer->pBuffer + relItem * ZFS_ENTRY_SIZE;
	entryPtr[ZFS_DIRENT_ATTRIB] = pDirent->attrib;
    entryPtr[ZFS_DIRENT_SPECIAL] = pDirent->special;
    *(uint32_t*)(entryPtr + ZFS_DIRENT_CLUSTER) = pDirent->objectCluster;
    *(uint32_t*)(entryPtr + ZFS_DIRENT_FILESIZE) = pDirent->filesize;
	pDirent->accessedTime = utils_unixtime(0);
	*(uint32_t*)&entryPtr[ZFS_DIRENT_LASTACC_TIME] = pDirent->accessedTime;
    *(uint32_t*)&entryPtr[ZFS_DIRENT_CREATE_TIME] = pDirent->createTime;
    *(uint32_t*)&entryPtr[ZFS_DIRENT_LASTMOD_TIME] = pDirent->modifiedTime;

	zfs_release_buffer(pIoman, pBuffer);
 
    return 0;
}

int zfs_create_name(pzfs_io_manager_t pIoman, uint32_t dirCluster, char* name, char* reqName)
{
	uint16_t i, x;
	char tmpShortName[ZFS_MAX_FILENAME + 1];
	zfs_dir_entry_t	tmpDir;
	int	err;

    if (fn_lstrlenA(reqName) > ZFS_MAX_FILENAME) {
        return ZFS_ERR_DIR_NAME_TOO_LONG | ZFS_CREATESHORTNAME;
    }

    __stosb((uint8_t*)name, 0, ZFS_MAX_FILENAME);

	for (i = 0, x = 0; i < ZFS_MAX_FILENAME; x++) {
		char ch = (char) reqName[x];
        if (ch == '\0') {
			break;
        }
        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
            || (ch == '$') || (ch == '%') || (ch == '-') || (ch == '_') || (ch == '@') || (ch == '~') || (ch == '`') || (ch == '!')
            || (ch == '(') || (ch == ')') || (ch == '{') || (ch == '}') || (ch == '^') || (ch == '#') || (ch == '&') || (ch == '.')) {
            name[i++] = ch;
        }
        else {
            __stosb(name, 0, i);
            return ZFS_ERR_DIR_NAME_BAD | ZFS_CREATESHORTNAME;
		}
	}
    
	__movsb(tmpShortName, name, ZFS_MAX_FILENAME);
    tmpShortName[ZFS_MAX_FILENAME] = '\0';
	if (!zfs_find_entry_in_dir(pIoman, dirCluster, tmpShortName, 0x00, &tmpDir, &err)) {
		return ERR_OK;
	}
	return ZFS_ERR_DIR_OBJECT_EXISTS | ZFS_CREATESHORTNAME;
}

int zfs_extend_directory(pzfs_io_manager_t pIoman, uint32_t DirCluster)
{
	uint32_t CurrentCluster;
	uint32_t NextCluster;
	int Error;
    

	if (!pIoman->freeClusterCount) {
		pIoman->freeClusterCount = zfs_count_free_clusters(pIoman, &Error);
		if (ZFS_isERR(Error)) {
			return Error;
		}
		if (pIoman->freeClusterCount == 0) {
			return ZFS_ERR_ZFS_NO_FREE_CLUSTERS | ZFS_EXTENDDIRECTORY;
		}
	}
	
	zfs_lock(pIoman);
	CurrentCluster = zfs_find_end_of_chain(pIoman, DirCluster, &Error);
	if (ZFS_isERR(Error)) {
		zfs_unlock(pIoman);
		return Error;
	}

	NextCluster = zfs_find_free_cluster(pIoman, &Error);
	if (ZFS_isERR(Error)) {
		zfs_unlock(pIoman);
		return Error;
	}

	Error = zfs_put_entry(pIoman, CurrentCluster, NextCluster);
	if (ZFS_isERR(Error)) {
		zfs_unlock(pIoman);
		return Error;
	}

	Error = zfs_put_entry(pIoman, NextCluster, 0xFFFFFFFF);
	if (ZFS_isERR(Error)) {
		zfs_unlock(pIoman);
		return Error;
	}
	zfs_unlock(pIoman);

	Error = zfs_clear_cluster(pIoman, NextCluster);
	if (ZFS_isERR(Error)) {
		zfs_unlock(pIoman);
		return Error;
	}
	
	Error = zfs_decrease_free_clusters(pIoman, 1);
	if (ZFS_isERR(Error)) {
		zfs_unlock(pIoman);
		return Error;
	}

	return ERR_OK;
}

void zfs_make_name_compliant(char* name)
{
	while (*name) {
		if (*name < 0x20 || *name == 0x7F || *name == 0x22 || *name == 0x7C) {	// Leave all extended chars as they are.
            *name = '_';
		}
		if (*name >= 0x2A && *name <= 0x2F && *name != 0x2B && *name != 0x2E && *name != 0x2D) {
            *name = '_';
		}
		if (*name >= 0x3A && *name <= 0x3F) {
            *name = '_';
		}
		if (*name >= 0x5B && *name <= 0x5C) {
            *name = '_';
		}
		name++;
	}
}

int zfs_create_dirent(pzfs_io_manager_t pIoman, uint32_t dirCluster, pzfs_dir_entry_t pDirent)
{
	uint8_t	entryBuffer[ZFS_ENTRY_SIZE];
	int	freeEntry;
	int	err = ERR_OK;
	uint8_t	entries;
	zfs_fetch_context_t fetchContext;
    

	zfs_make_name_compliant(pDirent->fileName);	// Ensure we don't break the Dir tables.
	__stosb(entryBuffer, 0, sizeof entryBuffer);

    entries = 1;

	zfs_lock_dir(pIoman);
	err = zfs_create_name(pIoman, dirCluster, (char*)entryBuffer, pDirent->fileName);
	if (err < 0) {
		zfs_unlock_dir(pIoman);
		return err;
	}

    if ((freeEntry = zfs_find_free_dirent(pIoman, dirCluster, entries)) >= 0) {
		if (err == 0) {
			pDirent->createTime = utils_unixtime(0);   // Date and Time Created.
			pDirent->modifiedTime = pDirent->createTime;    // Date and Time Modified.
			pDirent->accessedTime = pDirent->createTime;    // Date of Last Access.
			*(uint32_t*)(entryBuffer + ZFS_DIRENT_CREATE_TIME) = pDirent->createTime;
			*(uint32_t*)(entryBuffer + ZFS_DIRENT_LASTMOD_TIME) = pDirent->modifiedTime;

			entryBuffer[ZFS_DIRENT_ATTRIB] = pDirent->attrib;
            entryBuffer[ZFS_DIRENT_SPECIAL] = pDirent->special;
            *(uint32_t*)(entryBuffer + ZFS_DIRENT_CLUSTER) = pDirent->objectCluster;
            *(uint32_t*)(entryBuffer + ZFS_DIRENT_FILESIZE) = pDirent->filesize;

			err = zfs_init_entry_fetch(pIoman, dirCluster, &fetchContext);
			if (err) {
				zfs_unlock_dir(pIoman);
				return err;
			}
			err = zfs_push_entry_with_context(pIoman, (uint16_t)freeEntry, &fetchContext, entryBuffer);
			zfs_cleanup_entry_fetch(pIoman, &fetchContext);
			if (err) {
				zfs_unlock_dir(pIoman);
				return err;
			}
		}
	}
	zfs_unlock_dir(pIoman);

	if (err) {
		return err;
	}

	if (pDirent) {
		pDirent->currentItem = (uint16_t) (freeEntry);
	}
	
	return ERR_OK;
}

uint32_t zfs_create_file(pzfs_io_manager_t pIoman, uint32_t dirCluster, char* fileName, pzfs_dir_entry_t pDirent, uint8_t special, int* pError)
{
    int err = ERR_OK;
	zfs_dir_entry_t	fileEntry;
    

    do {
	    __stosb(&fileEntry, 0, sizeof fileEntry);    
		fn_lstrcpynA(fileEntry.fileName, fileName, ZFS_MAX_FILENAME + 1);
        fileEntry.special = special;
	    fileEntry.objectCluster = zfs_create_cluster_chain(pIoman, &err);
        
	    if (err) {
            break;
	    }

        err = zfs_create_dirent(pIoman, dirCluster, &fileEntry);

	    if (err) {
            break;
	    }

	    zfs_flush_cache(pIoman);

	    if (pDirent) {
		    __movsb(pDirent, &fileEntry, sizeof(zfs_dir_entry_t));
	    }
    } while (0);

    *pError = err;

    if (err) {
        zfs_unlink_cluster_chain(pIoman, fileEntry.objectCluster);
        zfs_flush_cache(pIoman);
        return 0;
    }

	return fileEntry.objectCluster;
}

int zfs_mkdir(pzfs_io_manager_t pIoman, const char* path, uint8_t special)
{
	zfs_dir_entry_t	newDir;
	uint32_t dirCluster;
	const char* dirName;
	uint8_t	entryBuffer[ZFS_ENTRY_SIZE];
	uint32_t DotDotCluster;
	uint16_t	i;
	int	err = ERR_OK;
	zfs_fetch_context_t fetchContext;

	i = (uint16_t)fn_lstrlenA(path);

	while (i != 0) {
		if (path[i] == '\\' || path[i] == '/') {
			break;
		}
		i--;
	}

	dirName = (path + i + 1);

	if (i == 0) {
		i = 1;
	}

	dirCluster = zfs_find_dir(pIoman, path, i, special, &err);

	if (ZFS_isERR(err)) {
		return err;
	}

	if (!dirCluster) {
		return ZFS_ERR_DIR_INVALID_PATH | ZFS_MKDIR;
	}
	__stosb(&newDir, 0, sizeof(newDir));

	if (zfs_find_entry_in_dir(pIoman, dirCluster, dirName, 0x00, &newDir, &err)) {
		return ZFS_ERR_DIR_OBJECT_EXISTS | ZFS_MKDIR;
	}

	if (err && ZFS_GETERROR(err) != ZFS_ERR_DIR_END_OF_DIR) {
		return err;	
	}

	fn_lstrcpynA(newDir.fileName, dirName, ZFS_MAX_FILENAME + 1);
	newDir.filesize = 0;
    newDir.attrib = ZFS_ATTR_DIR;
    newDir.special = special;
	newDir.objectCluster = zfs_create_cluster_chain(pIoman, &err);
	if (ZFS_isERR(err)) {
		return err;
	}
	if (!newDir.objectCluster) {
		// Couldn't allocate any space for the dir!
		return ZFS_ERR_DIR_EXTEND_FAILED | ZFS_MKDIR;
	}
	err = zfs_clear_cluster(pIoman, newDir.objectCluster);
	if (ZFS_isERR(err)) {
		zfs_unlink_cluster_chain(pIoman, newDir.objectCluster);
		zfs_flush_cache(pIoman);
		return err;
	}

	err = zfs_create_dirent(pIoman, dirCluster, &newDir);

	if (ZFS_isERR(err)) {
		zfs_unlink_cluster_chain(pIoman, newDir.objectCluster);
		zfs_flush_cache(pIoman);
		return err;
	}
	
    __stosb(entryBuffer, 0, ZFS_ENTRY_SIZE);
	entryBuffer[0] = '.';
	entryBuffer[ZFS_DIRENT_ATTRIB] = ZFS_ATTR_DIR;
    *(uint32_t*)(entryBuffer + ZFS_DIRENT_CLUSTER) = newDir.objectCluster;

	err = zfs_init_entry_fetch(pIoman, newDir.objectCluster, &fetchContext);
	if (ZFS_isERR(err)) {
		zfs_unlink_cluster_chain(pIoman, newDir.objectCluster);
		zfs_flush_cache(pIoman);
		return err;
	}
	
	err = zfs_push_entry_with_context(pIoman, 0, &fetchContext, entryBuffer);
	if (ZFS_isERR(err)) {
		zfs_unlink_cluster_chain(pIoman, newDir.objectCluster);
		zfs_flush_cache(pIoman);
		zfs_cleanup_entry_fetch(pIoman, &fetchContext);
		return err;
	}

    __stosb(entryBuffer, 0, 64);
	entryBuffer[0] = '.';
	entryBuffer[1] = '.';
		
	if (dirCluster == pIoman->rootDirCluster) {
		DotDotCluster = 0;
	}
    else {
		DotDotCluster = dirCluster;
	}

	entryBuffer[ZFS_DIRENT_ATTRIB] = ZFS_ATTR_DIR;
    *(uint32_t*)(entryBuffer + ZFS_DIRENT_CLUSTER) = DotDotCluster;
	
	//FF_PushEntry(pIoman, MyDir.ObjectCluster, 1, EntryBuffer);
	err = zfs_push_entry_with_context(pIoman, 1, &fetchContext, entryBuffer);
	if (ZFS_isERR(err)) {
		zfs_unlink_cluster_chain(pIoman, newDir.objectCluster);
		zfs_flush_cache(pIoman);
		zfs_cleanup_entry_fetch(pIoman, &fetchContext);
		return err;
	}
	zfs_cleanup_entry_fetch(pIoman, &fetchContext);

	zfs_flush_cache(pIoman);	// Ensure dir was flushed to the disk!

	return ERR_OK;
}

int zfs_rm_lfns(pzfs_io_manager_t pIoman, uint16_t usDirEntry, pzfs_fetch_context_t pContext)
{
	int	Error;
	uint8_t	EntryBuffer[ZFS_ENTRY_SIZE];
    

    if (usDirEntry > 0 )
	    usDirEntry--;

	do {
		Error = zfs_fetch_entry_with_context(pIoman, usDirEntry, pContext, EntryBuffer);
		if (ZFS_isERR(Error)) {
			return Error;
		}
		
		if (EntryBuffer[ZFS_DIRENT_ATTRIB] == ZFS_ATTR_LFN) {
			EntryBuffer[0] = 0xE5;
			Error = zfs_push_entry_with_context(pIoman, usDirEntry, pContext, EntryBuffer);
			if (ZFS_isERR(Error)) {
				return Error;
			}
		}

		if (usDirEntry == 0) {
			break;
		}
		usDirEntry--;
	} while (EntryBuffer[ZFS_DIRENT_ATTRIB] == ZFS_ATTR_LFN);

	return ERR_OK;
}
