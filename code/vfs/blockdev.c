#include "vfs.h"

int bdev_native_open(BlockDriverState* bs, const wchar_t* fileName)
{
    bs->file = fn_CreateFileW(fileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING , 0, NULL);

    if (bs->file == INVALID_HANDLE_VALUE) {
        return ERR_BAD;
    }
    return ERR_OK;
}

int bdev_native_read(BlockDriverState* bs, uint8_t* buffer, uint32_t sector, uint16_t sectors)
{
	ulong_t Read = 0;

	fn_WaitForSingleObject(bs->fileMutex, INFINITE);
	fn_SetFilePointer(bs->file, sector * 512, NULL, FILE_BEGIN);
	fn_ReadFile(bs->file, buffer, 512 * sectors, &Read, NULL);

	fn_ReleaseMutex(bs->fileMutex);

	return Read / 512;
}

int bdev_native_write(BlockDriverState* bs, const uint8_t* buffer, ulong_t sector, uint16_t sectors)
{
	ulong_t written;
	
	fn_WaitForSingleObject(bs->fileMutex, INFINITE);
	fn_SetFilePointer(bs->file, sector * 512, NULL, FILE_BEGIN);
	fn_WriteFile(bs->file, buffer, 512 * sectors, &written, NULL);

	fn_ReleaseMutex(bs->fileMutex);

	return written / 512;
}

uint32_t bdev_pread(BlockDriverState* bs, uint32_t offset, uint8_t* buf, uint32_t count1)
{
    uint8_t tmp_buf[BDRV_SECTOR_SIZE];
    uint32_t len, nb_sectors, count;
    ulong_t sector_num;
    int ret;

    count = count1;
    /* first read to align to sector start */
    len = (BDRV_SECTOR_SIZE - offset) & (BDRV_SECTOR_SIZE - 1);
    if (len > count)
        len = count;
    sector_num = (ulong_t)(offset >> BDRV_SECTOR_BITS);
    if (len > 0) {
        if ((ret = bdev_native_read(bs, tmp_buf, sector_num, 1)) < 0)
            return ret;
        __movsb(buf, tmp_buf + (offset & (BDRV_SECTOR_SIZE - 1)), len);
        count -= len;
        if (count == 0)
            return count1;
        sector_num++;
        buf += len;
    }

    /* read the sectors "in place" */
    nb_sectors = count >> BDRV_SECTOR_BITS;
    if (nb_sectors > 0) {
        if ((ret = bdev_native_read(bs, buf, sector_num, (uint16_t)nb_sectors)) < 0)
            return ret;
        sector_num += nb_sectors;
        len = nb_sectors << BDRV_SECTOR_BITS;
        buf += len;
        count -= len;
    }

    /* add data from the last sector */
    if (count > 0) {
		if ((ret = bdev_native_read(bs, tmp_buf, sector_num, 1)) < 0) {
			return ret;
		}
        __movsb(buf, tmp_buf, count);
    }
    return count1;
}

int bdev_pwrite(BlockDriverState* bs, uint32_t offset, const uint8_t* buf, int count1)
{
    uint8_t tmp_buf[BDRV_SECTOR_SIZE];
    int len, nb_sectors, count;
    uint32_t sector_num;
    int ret;

    count = count1;
    /* first write to align to sector start */
    len = (BDRV_SECTOR_SIZE - offset) & (BDRV_SECTOR_SIZE - 1);
    if (len > count)
        len = count;
    sector_num = (offset >> BDRV_SECTOR_BITS);
    if (len > 0) {
		if ((ret = bdev_native_read(bs, tmp_buf, sector_num, 1)) < 0) {
			return ret;
		}
        __movsb(tmp_buf + (offset & (BDRV_SECTOR_SIZE - 1)), buf, len);
		if ((ret = bdev_native_write(bs, tmp_buf, sector_num, 1)) < 0) {
			return ret;
		}
        count -= len;
		if (count == 0) {
			return count1;
		}
        sector_num++;
        buf += len;
    }

    /* write the sectors "in place" */
    nb_sectors = count >> BDRV_SECTOR_BITS;
    if (nb_sectors > 0) {
        if ((ret = bdev_native_write(bs, buf, sector_num, (uint16_t)nb_sectors)) < 0)
            return ret;
        sector_num += nb_sectors;
        len = nb_sectors << BDRV_SECTOR_BITS;
        buf += len;
        count -= len;
    }

    /* add data from the last sector */
    if (count > 0) {
		if ((ret = bdev_native_read(bs, tmp_buf, sector_num, 1)) < 0) {
			return ret;
		}
        __movsb(tmp_buf, buf, count);
		if ((ret = bdev_native_write(bs, tmp_buf, sector_num, 1)) < 0) {
			return ret;
		}
    }
    return count1;
}

uint32_t bdev_write_full(HANDLE hFile, const uint8_t* buf, uint32_t count)
{
    ulong_t written;
    uint32_t total = 0;

    while (count) {
        if (!fn_WriteFile(hFile, buf, count, &written, NULL)) {
            break;
        }
        count -= written;
        buf += written;
        total += written;
    }

    return total;
}

int bdev_create(const wchar_t* fileName, uint32_t virtSize)
{
    uint32_t header_size, l1_size, i, shift;
    zfs_bdev_header_t header;
    uint64_t tmp;
    uint32_t total_size = 0;
    int ret = ERR_OK;
    HANDLE hFile;

    hFile = fn_CreateFileW(fileName, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return ERR_BAD;
    }

    total_size = virtSize / 512;
    __stosb((uint8_t*)&header, 0, sizeof(header));
    header.magic = BD_MAGIC;
    header.size = virtSize;
    header_size = sizeof(header);
    header.cluster_bits = 12; /* 4 KB clusters */
    header.l2_bits = 9; /* 4 KB L2 tables */
    header_size = (header_size + 7) & ~7;
    shift = header.cluster_bits + header.l2_bits;
    l1_size = ((total_size * 512) + (1 << shift) - 1) >> shift;

    header.l1_table_offset = header_size;

    /* write all the data */
    ret = bdev_write_full(hFile, (const uint8_t*)&header, sizeof(header));
    if (ret != sizeof(header)) {
        ret = ERR_BAD;
        goto exit;
    }
    fn_SetFilePointer(hFile, header_size, NULL, FILE_BEGIN);
    tmp = 0;
    for (i = 0;i < l1_size; ++i) {
        ret = bdev_write_full(hFile, (const uint8_t*)&tmp, sizeof(tmp));
        if (ret != sizeof(tmp)) {
            ret = ERR_BAD;
            goto exit;
        }
    }

    ret = 0;
exit:
    fn_CloseHandle(hFile);

	return ret;
}

int bdev_ptruncate(HANDLE hFile, uint32_t offset)
{
	if (!fn_SetFilePointer(hFile, (LONG)offset, NULL, FILE_BEGIN)) {
		return ERR_BAD;
	}
	if (!fn_SetEndOfFile(hFile)) {
		return ERR_BAD;
	}

	return ERR_OK;
}

int bdev_make_empty(BlockDriverState* bs)
{
    zfs_bdev_state_t *s = bs->opaque;
    uint32_t l1_length = s->l1_size * sizeof(uint64_t);
    int ret;

    __stosb((uint8_t*)s->l1_table, 0, l1_length);
	if (bdev_pwrite(bs, s->l1_table_offset, (const uint8_t*)s->l1_table, l1_length) < 0) {
		return -1;
	}
    ret = bdev_ptruncate(bs->file, s->l1_table_offset + l1_length);
	if (ret != ERR_OK) {
		return ret;
	}

    __stosb((uint8_t*)s->l2_cache, 0, s->l2_size * L2_CACHE_SIZE * sizeof(uint64_t));
	__stosb((uint8_t*)s->l2_cache_offsets, 0, L2_CACHE_SIZE * sizeof(uint64_t));
	__stosb((uint8_t*)s->l2_cache_counts, 0, L2_CACHE_SIZE * sizeof(uint32_t));

    return 0;
}

int bdev_open(BlockDriverState** pbs, const wchar_t* filename)
{
    BlockDriverState* bs;
    int ret = ERR_BAD;
    zfs_bdev_state_t* s;
    int shift;
    zfs_bdev_header_t header;

    bs = memory_alloc(sizeof(BlockDriverState));
    bs->file = NULL;
    bs->total_sectors = 0;
    bs->valid_key = 0;

	fn_lstrcpyW(bs->filename, filename);

    bs->opaque = memory_alloc(sizeof(zfs_bdev_state_t));

    if (bdev_native_open(bs, filename) != ERR_OK) {
        bs->file = NULL;
        goto free_and_fail;
    }

    s = bs->opaque;
	s->mutex = fn_CreateMutexA(NULL, FALSE, NULL);
	bs->fileMutex = fn_CreateMutexA(NULL, FALSE, NULL);

    if (bdev_pread(bs, 0, (uint8_t*)&header, sizeof(header)) != sizeof(header)) {
        goto free_and_fail;
    }

    if (header.magic != BD_MAGIC) {
        goto free_and_fail;
    }
    if (header.size <= 1 || header.cluster_bits < 9) {
        goto free_and_fail;
    }
    s->cluster_bits = header.cluster_bits;
    s->cluster_size = 1 << s->cluster_bits;
    s->cluster_sectors = 1 << (s->cluster_bits - 9);
    s->l2_bits = header.l2_bits;
    s->l2_size = 1 << s->l2_bits;
    bs->total_sectors = header.size / 512;
    s->cluster_offset_mask = (1 << (63 - s->cluster_bits)) - 1;

    /* read the level 1 table */
    shift = s->cluster_bits + s->l2_bits;
    s->l1_size = (header.size + (1 << shift) - 1) >> shift;

    s->l1_table_offset = header.l1_table_offset;
    s->l1_table = memory_alloc(s->l1_size * sizeof(uint64_t));
    if (bdev_pread(bs, s->l1_table_offset, (uint8_t*)s->l1_table, s->l1_size * sizeof(uint64_t)) != s->l1_size * sizeof(uint64_t)) {
        goto free_and_fail;
    }
    /* alloc L2 cache */
    s->l2_cache = memory_alloc(s->l2_size * L2_CACHE_SIZE * sizeof(uint64_t));
    s->cluster_cache = memory_alloc(s->cluster_size);
    s->cluster_data = memory_alloc(s->cluster_size);

    *pbs = bs;
    return ERR_OK;

free_and_fail:
    bdev_close(bs);

    return ret;
}

int bdev_set_key(BlockDriverState *bs, const uint8_t* key, uint32_t keySize)
{
    zfs_bdev_state_t *s = bs->opaque;
    uint8_t keybuf[32];

    __stosb(keybuf, 0, 32);
	if (keySize > 32) {
		keySize = 32;
	}

    __movsb(keybuf, key, keySize);
    
	if (aes_setkey_enc(&s->aes_enc_key, keybuf) != 0) {
		return -1;
	}

	if (aes_setkey_dec(&s->aes_dec_key, keybuf) != 0) {
		return -1;
	}

    bs->valid_key = 1;

    return 0;
}

void bdev_close(BlockDriverState* bs)
{
    zfs_bdev_state_t *s = bs->opaque;

    if (s != NULL) {
        if (s->l1_table != NULL) {
            memory_free(s->l1_table);
        }
        if (s->l2_cache != NULL) {
			memory_free(s->l2_cache);
        }
        if (s->cluster_cache != NULL) {
			memory_free(s->cluster_cache);
        }
        if (s->cluster_data != NULL) {
			memory_free(s->cluster_data);
        }
		fn_CloseHandle(s->mutex);
		memory_free(s);
        bs->opaque = NULL;
    }

    if (bs->file != NULL) {
        fn_CloseHandle(bs->file);
		fn_CloseHandle(bs->fileMutex);
    }

	memory_free(bs);
}

uint32_t bdev_getlength(HANDLE hFile)
{
    uint32_t loSize, hiSize;

    loSize = fn_GetFileSize(hFile, (LPDWORD)&hiSize);
    return loSize /*+ ((int64_t)hiSize << 32)*/;
}

void bdev_encrypt_sectors(uint32_t sector_num, uint8_t *out_buf, const uint8_t *in_buf, uint32_t nb_sectors, int enc, const aes_context_t* pCtx)
{
    union {
        uint32_t ll[4];
        uint8_t b[16];
    } ivec;
    uint32_t i;

    for (i = 0; i < nb_sectors; ++i) {
        ivec.ll[0] = sector_num;
        ivec.ll[1] = ivec.ll[2] = ivec.ll[3] = 0;
		aes_crypt_cbc(pCtx, enc, 512, ivec.b, in_buf, out_buf);
        ++sector_num;
        in_buf += 512;
        out_buf += 512;
    }
}

uint32_t bdev_get_cluster_offset(BlockDriverState *bs, uint32_t offset, int allocate, int n_start, int n_end)
{
    zfs_bdev_state_t *s = bs->opaque;
    int min_index, i, j, l1_index, l2_index;
    uint32_t l2_offset, *l2_table, cluster_offset, tmp;
    uint32_t min_count;
    int new_l2_table;

    l1_index = offset >> (s->l2_bits + s->cluster_bits);
    l2_offset = s->l1_table[l1_index];
    new_l2_table = 0;
    if (!l2_offset) {
        if (!allocate)
            return 0;
        /* allocate a new l2 entry */
        l2_offset = bdev_getlength(bs->file);
        /* round to cluster size */
        l2_offset = (l2_offset + s->cluster_size - 1) & ~(s->cluster_size - 1);
        /* update the L1 entry */
        s->l1_table[l1_index] = l2_offset;
        tmp = l2_offset;
        if (bdev_pwrite(bs, s->l1_table_offset + l1_index * sizeof(tmp), (const uint8_t*)&tmp, sizeof(tmp)) < 0)
            return 0;
        new_l2_table = 1;
    }
    for (i = 0; i < L2_CACHE_SIZE; i++) {
        if (l2_offset == s->l2_cache_offsets[i]) {
            /* increment the hit count */
            if (++s->l2_cache_counts[i] == 0xffffffff) {
                for (j = 0; j < L2_CACHE_SIZE; j++) {
                    s->l2_cache_counts[j] >>= 1;
                }
            }
            l2_table = s->l2_cache + (i << s->l2_bits);
            goto found;
        }
    }
    /* not found: load a new entry in the least used one */
    min_index = 0;
    min_count = 0xffffffff;
	for (i = 0; i < L2_CACHE_SIZE; ++i) {
        if (s->l2_cache_counts[i] < min_count) {
            min_count = s->l2_cache_counts[i];
            min_index = i;
        }
    }
    l2_table = s->l2_cache + (min_index << s->l2_bits);
    if (new_l2_table) {
        __stosb((uint8_t*)l2_table, 0, s->l2_size * sizeof(uint64_t));
		if (bdev_pwrite(bs, l2_offset, (const uint8_t*)l2_table, s->l2_size * sizeof(uint64_t)) < 0) {
			return 0;
		}
    }
	else {
		if (bdev_pread(bs, l2_offset, (uint8_t*)l2_table, s->l2_size * sizeof(uint64_t)) != s->l2_size * sizeof(uint64_t)) {
			return 0;
		}
    }
    s->l2_cache_offsets[min_index] = l2_offset;
    s->l2_cache_counts[min_index] = 1;
 found:
    l2_index = (offset >> s->cluster_bits) & (s->l2_size - 1);
    cluster_offset = l2_table[l2_index];
    if (!cluster_offset) {
		if (!allocate) {
			return 0;
		}
        cluster_offset = bdev_getlength(bs->file);
        if (allocate == 1) {
            /* round to cluster size */
            cluster_offset = (cluster_offset + s->cluster_size - 1) & ~(s->cluster_size - 1);
            bdev_ptruncate(bs->file, cluster_offset + s->cluster_size);
            /* if encrypted, we must initialize the cluster content which won't be written */
            if ((n_end - n_start) < s->cluster_sectors) {
                uint32_t start_sect;
                start_sect = (offset & ~(s->cluster_size - 1)) >> 9;
                __stosb(s->cluster_data + 512, 0x00, 512);
                for (i = 0; i < s->cluster_sectors; i++) {
                    if (i < n_start || i >= n_end) {
                        bdev_encrypt_sectors(start_sect + i, s->cluster_data, s->cluster_data + 512, 1, AES_ENCRYPT, &s->aes_enc_key);
						if (bdev_pwrite(bs, cluster_offset + i * 512, s->cluster_data, 512) != 512) {
							return 0;
						}
                    }
                }
            }
        }
        /* update L2 table */
        tmp = cluster_offset;
        l2_table[l2_index] = tmp;
		if (bdev_pwrite(bs, l2_offset + l2_index * sizeof(tmp), (const uint8_t*)&tmp, sizeof(tmp)) != sizeof(tmp)) {
			return 0;
		}
    }
    return cluster_offset;
}

int bdev_read(uint8_t* buf, uint32_t sector_num, uint32_t nb_sectors, BlockDriverState* bs)
{
    zfs_bdev_state_t* s = bs->opaque;
    int index_in_cluster;
    int ret = ERR_OK;
    uint32_t n;
    uint32_t cluster_offset;
    void* orig_buf;

    orig_buf = NULL;

	fn_WaitForSingleObject(s->mutex, INFINITE);

    while (nb_sectors != 0) {
        cluster_offset = bdev_get_cluster_offset(bs, sector_num << 9, 0, 0, 0);
        index_in_cluster = sector_num & (s->cluster_sectors - 1);
        n = s->cluster_sectors - index_in_cluster;
        if (n > nb_sectors) {
            n = nb_sectors;
        }

        if (!cluster_offset) {
            __stosb(buf, 0, 512 * n);
        }
        else {
            if ((cluster_offset & 511) != 0) {
                goto fail;
            }
			fn_ReleaseMutex(s->mutex);
            ret = bdev_pread(bs, ((cluster_offset >> 9) + index_in_cluster) * 512, buf, n * 512);
			fn_WaitForSingleObject(s->mutex, INFINITE);
            if (ret < ERR_OK) {
                break;
            }
            bdev_encrypt_sectors(sector_num, buf, buf, n, AES_DECRYPT, &s->aes_dec_key);
        }

        nb_sectors -= n;
        sector_num += n;
        buf += n * 512;
    }

done:
    fn_ReleaseMutex(s->mutex);

    return ret;

fail:
    ret = ERR_BAD;
    goto done;

}

int bdev_write(const uint8_t *buf, uint32_t sector_num, uint32_t nb_sectors, BlockDriverState* bs)
{
    zfs_bdev_state_t *s = bs->opaque;
    int index_in_cluster;
    uint32_t cluster_offset;
    const uint8_t *src_buf;
    int ret = ERR_OK, written;
    uint32_t n;
    uint8_t *cluster_data = NULL;
    void *orig_buf;

    if (bs->wr_highest_sector < sector_num + nb_sectors - 1) {
        bs->wr_highest_sector = sector_num + nb_sectors - 1;
    }

    orig_buf = NULL;

	fn_WaitForSingleObject(s->mutex, INFINITE);

    while (nb_sectors != 0) {
        index_in_cluster = sector_num & (s->cluster_sectors - 1);
        n = s->cluster_sectors - index_in_cluster;
        if (n > nb_sectors) {
            n = nb_sectors;
        }
        cluster_offset = bdev_get_cluster_offset(bs, sector_num << 9, 1, index_in_cluster, index_in_cluster + n);
        if (!cluster_offset || (cluster_offset & 511) != 0) {
            ret = ERR_BAD;
            break;
        }

        if (cluster_data == NULL) {
            cluster_data = memory_alloc(s->cluster_size);
            __stosb(cluster_data, 0, s->cluster_size);
        }
        bdev_encrypt_sectors(sector_num, cluster_data, buf, n, AES_ENCRYPT, /*&s->aes_encrypt_key*/&s->aes_enc_key);
        src_buf = cluster_data;

        fn_ReleaseMutex(s->mutex);
        written = bdev_pwrite(bs, ((cluster_offset >> 9) + index_in_cluster) * 512, src_buf, n * 512);
        fn_WaitForSingleObject(s->mutex, INFINITE);
        if (written < ERR_OK) {
            ret = ERR_BAD;
            break;
        }

        nb_sectors -= n;
        sector_num += n;
        buf += n * 512;
    }
    fn_ReleaseMutex(s->mutex);

	if (cluster_data != NULL) {
		memory_free(cluster_data);
	}

    return ret;
}
