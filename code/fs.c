#include "zmodule.h"
#include <direct.h>
#include <errno.h>

#include "async.h"
#include "internal.h"
#include "req-inl.h"
#include "handle-inl.h"


#define ASYNC_FS_FREE_PATHS         0x0002
#define ASYNC_FS_FREE_PTR           0x0008
#define ASYNC_FS_CLEANEDUP          0x0010


#define QUEUE_FS_TP_JOB(loop, req)                                          \
  do {                                                                      \
    async__req_register(loop, req);                                            \
    async__work_submit((loop), &(req)->work_req, async__fs_work, async__fs_done);    \
  } while (0)

#define SET_REQ_RESULT(req, result_value)                                   \
    req->result = (result_value);

#define SET_REQ_WIN32_ERROR(req, sys_errno)                                 \
  do {                                                                      \
    req->sys_errno_ = (sys_errno);                                          \
    req->result = async_translate_sys_error(req->sys_errno_);                  \
  } while (0)

#define SET_REQ_ASYNC_ERROR(req, async_errno, sys_errno)                          \
  do {                                                                      \
    req->result = (async_errno);                                               \
    req->sys_errno_ = (sys_errno);                                          \
  } while (0)

#define VERIFY_FD(fd, req)                                                  \
  if (fd == -1) {                                                           \
    req->result = ASYNC_EBADF;                                                 \
    req->sys_errno_ = ERROR_INVALID_HANDLE;                                 \
    return;                                                                 \
  }

#define FILETIME_TO_UINT(filetime)                                          \
   (*((uint64_t*) &(filetime)) - 116444736000000000ULL)

#define FILETIME_TO_TIME_T(filetime)                                        \
   (FILETIME_TO_UINT(filetime) / 10000000ULL)

#define FILETIME_TO_TIME_NS(filetime, secs)                                 \
   ((FILETIME_TO_UINT(filetime) - (secs * 10000000ULL)) * 100)

#define FILETIME_TO_TIMESPEC(ts, filetime)                                  \
   do {                                                                     \
     (ts).tv_sec = (long) FILETIME_TO_TIME_T(filetime);                     \
     (ts).tv_nsec = (long) FILETIME_TO_TIME_NS(filetime, (ts).tv_sec);      \
   } while(0)

#define TIME_T_TO_FILETIME(time, filetime_ptr)                              \
  do {                                                                      \
    uint64_t bigtime = ((int64_t) (time) * 10000000LL) +                    \
                                  116444736000000000ULL;                    \
    (filetime_ptr)->dwLowDateTime = bigtime & 0xFFFFFFFF;                   \
    (filetime_ptr)->dwHighDateTime = bigtime >> 32;                         \
  } while(0)

#define IS_SLASH(c) ((c) == L'\\' || (c) == L'/')
#define IS_LETTER(c) (((c) >= L'a' && (c) <= L'z') || \
  ((c) >= L'A' && (c) <= L'Z'))

const wchar_t JUNCTION_PREFIX[] = L"\\??\\";
const wchar_t JUNCTION_PREFIX_LEN = 4;

const wchar_t LONG_PATH_PREFIX[] = L"\\\\?\\";
const wchar_t LONG_PATH_PREFIX_LEN = 4;


int fs__capture_path(async_loop_t* loop, async_fs_t* req, const wchar_t* path, const wchar_t* new_path)
{
    wchar_t* pos;
    ssize_t buf_sz = 0, path_len, pathw_len = 0, new_pathw_len = 0;

    if (path != NULL) {
        pathw_len = fn_lstrlenW(path) + 1;
        if (pathw_len == 0) {
            return fn_GetLastError();
        }

        buf_sz += pathw_len;
    }

    if (new_path != NULL) {
        new_pathw_len = fn_lstrlenW(new_path) + 1;
        if (new_pathw_len == 0) {
            return fn_GetLastError();
        }
        buf_sz += new_pathw_len;
    }

    req->path = NULL;
    req->new_pathw = NULL;

    if (buf_sz == 0) {
        return 0;
    }

    pos = (wchar_t*)memory_alloc(buf_sz << 1);

    if (path != NULL) {
        fn_lstrcpyW(pos, path);
        req->path = pos;
        pos += fn_lstrlenW(pos) + 1;
    }

    if (new_path != NULL) {
        fn_lstrcpyW(pos, new_path);
    }

    req->flags |= ASYNC_FS_FREE_PATHS;

    return 0;
}

void async_fs_req_init(async_loop_t* loop, async_fs_t* req, async_fs_type fs_type, const async_fs_cb cb)
{
    async_req_init(loop, (async_req_t*) req);

    req->type = ASYNC_FS;
    req->loop = loop;
    req->flags = 0;
    req->fs_type = fs_type;
    req->result = 0;
    req->hFile = NULL;
    req->ptr = NULL;
    req->cb = cb;
}

int fs__readlink_handle(HANDLE handle, char** target_ptr, uint64_t* target_len_ptr)
{
    char buffer[MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
    REPARSE_DATA_BUFFER* reparse_data = (REPARSE_DATA_BUFFER*) buffer;
    wchar_t *w_target;
    DWORD w_target_len;
    char* target;
    int target_len;
    DWORD bytes;

    if (!fn_DeviceIoControl(handle, FSCTL_GET_REPARSE_POINT, NULL, 0, buffer, sizeof buffer, &bytes, NULL)) {
        return -1;
    }

    if (reparse_data->ReparseTag == IO_REPARSE_TAG_SYMLINK) {
        /* Real symlink */
        w_target = reparse_data->SymbolicLinkReparseBuffer.PathBuffer + (reparse_data->SymbolicLinkReparseBuffer.SubstituteNameOffset / sizeof(wchar_t));
        w_target_len = reparse_data->SymbolicLinkReparseBuffer.SubstituteNameLength / sizeof(wchar_t);

        /* Real symlinks can contain pretty much everything, but the only thing */
        /* we really care about is undoing the implicit conversion to an NT */
        /* namespaced path that CreateSymbolicLink will perform on absolute */
        /* paths. If the path is win32-namespaced then the user must have */
        /* explicitly made it so, and we better just return the unmodified */
        /* reparse data. */
        if (w_target_len >= 4 && w_target[0] == L'\\' && w_target[1] == L'?' && w_target[2] == L'?' && w_target[3] == L'\\') {
            /* Starts with \??\ */
            if (w_target_len >= 6 && ((w_target[4] >= L'A' && w_target[4] <= L'Z') || (w_target[4] >= L'a' && w_target[4] <= L'z')) && w_target[5] == L':' && (w_target_len == 6 || w_target[6] == L'\\')) {
                /* \??\«drive»:\ */
                w_target += 4;
                w_target_len -= 4;
            }
            else if (w_target_len >= 8 && (w_target[4] == L'U' || w_target[4] == L'u') && (w_target[5] == L'N' || w_target[5] == L'n') && (w_target[6] == L'C' || w_target[6] == L'c') && w_target[7] == L'\\') {
                /* \??\UNC\«server»\«share»\ - make sure the final path looks like */
                /* \\«server»\«share»\ */
                w_target += 6;
                w_target[0] = L'\\';
                w_target_len -= 6;
            }
        }

    }
    else if (reparse_data->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
        /* Junction. */
        w_target = reparse_data->MountPointReparseBuffer.PathBuffer + (reparse_data->MountPointReparseBuffer.SubstituteNameOffset / sizeof(wchar_t));
        w_target_len = reparse_data->MountPointReparseBuffer.SubstituteNameLength / sizeof(wchar_t);

        /* Only treat junctions that look like \??\«drive»:\ as symlink. */
        /* Junctions can also be used as mount points, like \??\Volume{«guid»}, */
        /* but that's confusing for programs since they wouldn't be able to */
        /* actually understand such a path when returned by async_readlink(). */
        /* UNC paths are never valid for junctions so we don't care about them. */
        if (!(w_target_len >= 6 && w_target[0] == L'\\' && w_target[1] == L'?' && w_target[2] == L'?' && w_target[3] == L'\\' && ((w_target[4] >= L'A' && w_target[4] <= L'Z') || (w_target[4] >= L'a' && w_target[4] <= L'z')) && w_target[5] == L':' && (w_target_len == 6 || w_target[6] == L'\\'))) {
            fn_SetLastError(ERROR_SYMLINK_NOT_SUPPORTED);
            return -1;
        }

        /* Remove leading \??\ */
        w_target += 4;
        w_target_len -= 4;
    }
    else {
        /* Reparse tag does not indicate a symlink. */
        fn_SetLastError(ERROR_SYMLINK_NOT_SUPPORTED);
        return -1;
    }

    /* If needed, compute the length of the target. */
    if (target_ptr != NULL || target_len_ptr != NULL) {
        /* Compute the length of the target. */
        target_len = fn_WideCharToMultiByte(CP_UTF8, 0, w_target, w_target_len, NULL, 0, NULL, NULL);
        if (target_len == 0) {
            return -1;
        }
    }

    /* If requested, allocate memory and convert to UTF8. */
    if (target_ptr != NULL) {
        int r;
        target = (char*)memory_alloc(target_len + 1);

        r = fn_WideCharToMultiByte(CP_UTF8, 0, w_target, w_target_len, target, target_len, NULL, NULL);
        target[target_len] = '\0';
        *target_ptr = target;
    }

    if (target_len_ptr != NULL) {
        *target_len_ptr = target_len;
    }

    return 0;
}

void fs__open(async_fs_t* req)
{
    req->hFile = fn_CreateFileW(req->path, req->access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, req->disposition, req->attributes, NULL);
    SET_REQ_WIN32_ERROR(req, fn_GetLastError());
}

void fs__close(async_fs_t* req)
{
    fn_CloseHandle(req->hFile);
    SET_REQ_RESULT(req, 0);
}

void fs__read(async_fs_t* req)
{
    int64_t offset = req->offset;
    HANDLE handle = req->hFile;
    OVERLAPPED overlapped, *overlapped_ptr;
    LARGE_INTEGER offset_;
    DWORD bytes;
    DWORD error;
    int result;
    uint32_t index;

    if (offset != -1) {
        __stosb((uint8_t*)&overlapped, 0, sizeof overlapped);

        offset_.QuadPart = offset;
        overlapped.Offset = offset_.LowPart;
        overlapped.OffsetHigh = offset_.HighPart;

        overlapped_ptr = &overlapped;
    }
    else {
        overlapped_ptr = NULL;
    }

    index = 0;
    bytes = 0;
    do {
        DWORD incremental_bytes;
        result = fn_ReadFile(handle, req->bufs[index].base, req->bufs[index].len, &incremental_bytes, overlapped_ptr);
        bytes += incremental_bytes;
        ++index;
    } while (result && index < req->nbufs);

    if (result || bytes > 0) {
        SET_REQ_RESULT(req, bytes);
    }
    else {
        error = fn_GetLastError();
        if (error == ERROR_HANDLE_EOF) {
            SET_REQ_RESULT(req, bytes);
        }
        else {
            SET_REQ_WIN32_ERROR(req, error);
        }
    }
}


void fs__write(async_fs_t* req)
{
    int64_t offset = req->offset;
    HANDLE handle = req->hFile;
    OVERLAPPED overlapped, *overlapped_ptr;
    LARGE_INTEGER offset_;
    DWORD bytes;
    int result;
    uint32_t index;

    if (offset != -1) {
        __stosb((uint8_t*)&overlapped, 0, sizeof overlapped);

        offset_.QuadPart = offset;
        overlapped.Offset = offset_.LowPart;
        overlapped.OffsetHigh = offset_.HighPart;

        overlapped_ptr = &overlapped;
    }
    else {
        overlapped_ptr = NULL;
    }

    index = 0;
    bytes = 0;
    do {
        DWORD incremental_bytes;
        result = fn_WriteFile(handle, req->bufs[index].base, req->bufs[index].len, &incremental_bytes, overlapped_ptr);
        bytes += incremental_bytes;
        ++index;
    } while (result && index < req->nbufs);

    if (result || bytes > 0) {
        SET_REQ_RESULT(req, bytes);
    }
    else {
        SET_REQ_WIN32_ERROR(req, fn_GetLastError());
    }
}

void fs__rmdir(async_fs_t* req)
{
    if (!fn_RemoveDirectoryW(req->path)) {
        SET_REQ_WIN32_ERROR(req, fn_GetLastError());
    }
    else {
        SET_REQ_RESULT(req, 0);
    }
}

void fs__unlink(async_fs_t* req)
{
    HANDLE handle;
    BY_HANDLE_FILE_INFORMATION info;
    FILE_DISPOSITION_INFORMATION disposition;
    IO_STATUS_BLOCK iosb;
    NTSTATUS status;

    handle = fn_CreateFileW(req->path, FILE_READ_ATTRIBUTES | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);

    if (handle == INVALID_HANDLE_VALUE) {
        SET_REQ_WIN32_ERROR(req, fn_GetLastError());
        return;
    }

    if (!fn_GetFileInformationByHandle(handle, &info)) {
        SET_REQ_WIN32_ERROR(req, fn_GetLastError());
        fn_CloseHandle(handle);
        return;
    }

    if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        /* Do not allow deletion of directories, unless it is a symlink. When */
        /* the path refers to a non-symlink directory, report EPERM as mandated */
        /* by POSIX.1. */

        /* Check if it is a reparse point. If it's not, it's a normal directory. */
        if (!(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
            SET_REQ_WIN32_ERROR(req, ERROR_ACCESS_DENIED);
            fn_CloseHandle(handle);
            return;
        }

        /* Read the reparse point and check if it is a valid symlink. */
        /* If not, don't unlink. */
        if (fs__readlink_handle(handle, NULL, NULL) < 0) {
            DWORD error = fn_GetLastError();
            if (error == ERROR_SYMLINK_NOT_SUPPORTED) {
                error = ERROR_ACCESS_DENIED;
            }
            SET_REQ_WIN32_ERROR(req, error);
            fn_CloseHandle(handle);
            return;
        }
    }

    /* Try to set the delete flag. */
    disposition.DeleteFile = TRUE;
    status = fn_NtSetInformationFile(handle, &iosb, &disposition, sizeof disposition, FileDispositionInformation);
    if (NT_SUCCESS(status)) {
        SET_REQ_SUCCESS(req);
    }
    else {
        SET_REQ_WIN32_ERROR(req, fn_RtlNtStatusToDosError(status));
    }

    fn_CloseHandle(handle);
}

void fs__mkdir(async_fs_t* req)
{
    fn_CreateDirectoryW(req->path, NULL);
    SET_REQ_WIN32_ERROR(req, fn_GetLastError());
}


void fs__readdir(async_fs_t* req)
{
    wchar_t* pathw = req->path;
    size_t len = fn_lstrlenW(pathw);
    int result;
    wchar_t* buf = NULL, *ptr, *name;
    HANDLE dir;
    WIN32_FIND_DATAW ent = { 0 };
    size_t buf_char_len = 4096;
    wchar_t* path2;

    if (!(fn_GetFileAttributesW(pathw) & FILE_ATTRIBUTE_DIRECTORY)) {
        req->result = ASYNC_ENOTDIR;
        req->sys_errno_ = ERROR_SUCCESS;
        return;
    }

    dir = fn_FindFirstFileW(pathw, &ent);

    if (dir == INVALID_HANDLE_VALUE) {
        SET_REQ_WIN32_ERROR(req, fn_GetLastError());
        return;
    }

    result = 0;

    do {
        name = ent.cFileName;

        if (name[0] != L'.' || (name[1] && (name[1] != L'.' || name[2]))) {
            len = fn_lstrlenW(name);

            if (buf == NULL) {
                buf = (wchar_t*)memory_alloc(buf_char_len * sizeof(wchar_t));
                ptr = buf;
            }

            while ((ptr - buf) + len + 2 > buf_char_len) {
                buf_char_len <<= 1;
                path2 = buf;
                buf = (wchar_t*)memory_realloc(buf, buf_char_len * sizeof(wchar_t));
                if (!buf) {
                    memory_free(path2);
                    req->sys_errno_ = ERROR_OUTOFMEMORY;
                    return;
                }
                ptr = buf + (ptr - path2);
            }

            fn_lstrcpyW(ptr, name);
            ptr += len + 1;
            ++result;
        }
    } while(fn_FindNextFileW(dir, &ent));

    fn_FindClose(dir);

    if (buf != NULL) {
        *ptr = L'\0';
        req->ptr = buf;
        req->flags |= ASYNC_FS_FREE_PTR;
    }
    else {
        req->ptr = NULL;
    }

    SET_REQ_RESULT(req, result);
}

int fs__stat_handle(HANDLE handle, async_stat_t* statbuf)
{
    FILE_ALL_INFORMATION file_info;
    FILE_FS_VOLUME_INFORMATION volume_info;
    NTSTATUS nt_status;
    IO_STATUS_BLOCK io_status;

    nt_status = fn_NtQueryInformationFile(handle, &io_status, &file_info, sizeof file_info, FileAllInformation);

    /* Buffer overflow (a warning status code) is expected here. */
    if (!NT_SUCCESS(nt_status)) {
        fn_SetLastError(fn_RtlNtStatusToDosError(nt_status));
        return -1;
    }

    nt_status = fn_NtQueryVolumeInformationFile(handle, &io_status, &volume_info, sizeof volume_info, FileFsVolumeInformation);

    /* Buffer overflow (a warning status code) is expected here. */
    if (io_status.Status == STATUS_NOT_IMPLEMENTED) {
        statbuf->st_dev = 0;
    }
    else if (!NT_SUCCESS(nt_status)) {
        fn_SetLastError(fn_RtlNtStatusToDosError(nt_status));
        return -1;
    }
    else {
        statbuf->st_dev = volume_info.VolumeSerialNumber;
    }

      /* Todo: st_mode should probably always be 0666 for everyone. We might also
       * want to report 0777 if the file is a .exe or a directory.
       *
       * Currently it's based on whether the 'readonly' attribute is set, which
       * makes little sense because the semantics are so different: the 'read-only'
       * flag is just a way for a user to protect against accidental deleteion, and
       * serves no security purpose. Windows uses ACLs for that.
       *
       * Also people now use async_fs_chmod() to take away the writable bit for good
       * reasons. Windows however just makes the file read-only, which makes it
       * impossible to delete the file afterwards, since read-only files can't be
       * deleted.
       *
       * IOW it's all just a clusterfuck and we should think of something that
       * makes slighty more sense.
       *
       * And async_fs_chmod should probably just fail on windows or be a total no-op.
       * There's nothing sensible it can do anyway.
       */
    statbuf->st_mode = 0;

    if (file_info.BasicInformation.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        statbuf->st_mode |= S_IFLNK;
        if (fs__readlink_handle(handle, NULL, &statbuf->st_size) != 0) {
            return -1;
        }
    }
    else if (file_info.BasicInformation.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        statbuf->st_mode |= _S_IFDIR;
        statbuf->st_size = 0;
    }
    else {
        statbuf->st_mode |= _S_IFREG;
        statbuf->st_size = file_info.StandardInformation.EndOfFile.QuadPart;
    }

    if (file_info.BasicInformation.FileAttributes & FILE_ATTRIBUTE_READONLY) {
        statbuf->st_mode |= _S_IREAD | (_S_IREAD >> 3) | (_S_IREAD >> 6);
    }
    else {
        statbuf->st_mode |= (_S_IREAD | _S_IWRITE) | ((_S_IREAD | _S_IWRITE) >> 3) | ((_S_IREAD | _S_IWRITE) >> 6);
    }

    FILETIME_TO_TIMESPEC(statbuf->st_atim, file_info.BasicInformation.LastAccessTime);
    FILETIME_TO_TIMESPEC(statbuf->st_ctim, file_info.BasicInformation.ChangeTime);
    FILETIME_TO_TIMESPEC(statbuf->st_mtim, file_info.BasicInformation.LastWriteTime);
    FILETIME_TO_TIMESPEC(statbuf->st_birthtim, file_info.BasicInformation.CreationTime);

    statbuf->st_ino = file_info.InternalInformation.IndexNumber.QuadPart;

    /* st_blocks contains the on-disk allocation size in 512-byte units. */
    statbuf->st_blocks = file_info.StandardInformation.AllocationSize.QuadPart >> 9ULL;

    statbuf->st_nlink = file_info.StandardInformation.NumberOfLinks;

      /* The st_blksize is supposed to be the 'optimal' number of bytes for reading
       * and writing to the disk. That is, for any definition of 'optimal' - it's
       * supposed to at least avoid read-update-write behavior when writing to the
       * disk.
       *
       * However nobody knows this and even fewer people actually use this value,
       * and in order to fill it out we'd have to make another syscall to query the
       * volume for FILE_FS_SECTOR_SIZE_INFORMATION.
       *
       * Therefore we'll just report a sensible value that's quite commonly okay
       * on modern hardware.
       */
    statbuf->st_blksize = 2048;

      /* Todo: set st_flags to something meaningful. Also provide a wrapper for
       * chattr(2).
       */
    statbuf->st_flags = 0;

      /* Windows has nothing sensible to say about these values, so they'll just
       * remain empty.
       */
    statbuf->st_gid = 0;
    statbuf->st_uid = 0;
    statbuf->st_rdev = 0;
    statbuf->st_gen = 0;

    return 0;
}


void fs__stat_prepare_path(wchar_t* pathw)
{
    size_t len = fn_lstrlenW(pathw);

    /* TODO: ignore namespaced paths. */
    if (len > 1 && pathw[len - 2] != L':' && (pathw[len - 1] == L'\\' || pathw[len - 1] == L'/')) {
        pathw[len - 1] = L'\0';
    }
}

void fs__stat_impl(async_fs_t* req, int do_lstat)
{
    HANDLE handle;
    DWORD flags;

    flags = FILE_FLAG_BACKUP_SEMANTICS;
    if (do_lstat) {
        flags |= FILE_FLAG_OPEN_REPARSE_POINT;
    }

    handle = fn_CreateFileW(req->path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, flags, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        SET_REQ_WIN32_ERROR(req, fn_GetLastError());
        return;
    }

    if (fs__stat_handle(handle, &req->statbuf) != 0) {
        DWORD error = fn_GetLastError();
        if (do_lstat && error == ERROR_SYMLINK_NOT_SUPPORTED) {
            /* We opened a reparse point but it was not a symlink. Try again. */
            fs__stat_impl(req, 0);
        }
        else {
            /* Stat failed. */
            SET_REQ_WIN32_ERROR(req, fn_GetLastError());
        }

        fn_CloseHandle(handle);
        return;
    }

    req->ptr = &req->statbuf;
    req->result = 0;
    fn_CloseHandle(handle);
}

void fs__stat(async_fs_t* req)
{
    fs__stat_prepare_path(req->path);
    fs__stat_impl(req, 0);
}

void fs__lstat(async_fs_t* req)
{
    fs__stat_prepare_path(req->path);
    fs__stat_impl(req, 1);
}

void fs__fstat(async_fs_t* req)
{
    int fd = req->fd;
    HANDLE handle = req->hFile;

    if (handle == 0 || handle == INVALID_HANDLE_VALUE) {
        req->sys_errno_ = ERROR_INVALID_HANDLE;
        return;
    }

    if (fs__stat_handle(handle, &req->statbuf) != 0) {
        SET_REQ_WIN32_ERROR(req, fn_GetLastError());
        return;
    }

    req->ptr = &req->statbuf;
    req->result = 0;
}

void fs__rename(async_fs_t* req)
{
    if (!fn_MoveFileExW(req->path, req->new_pathw, MOVEFILE_REPLACE_EXISTING)) {
        SET_REQ_WIN32_ERROR(req, fn_GetLastError());
        return;
    }

    SET_REQ_RESULT(req, 0);
}

void fs__fsync(async_fs_t* req)
{
    if (!fn_FlushFileBuffers(req->hFile)) {
        SET_REQ_WIN32_ERROR(req, fn_GetLastError());
    }
    else {
        SET_REQ_RESULT(req, 0);
    }
}

void fs__ftruncate(async_fs_t* req)
{
    HANDLE handle;
    NTSTATUS status;
    IO_STATUS_BLOCK io_status;
    FILE_END_OF_FILE_INFORMATION eof_info;

    eof_info.EndOfFile.QuadPart = req->offset;

    status = fn_NtSetInformationFile(req->hFile, &io_status, &eof_info, sizeof eof_info, FileEndOfFileInformation);

    if (NT_SUCCESS(status)) {
        SET_REQ_RESULT(req, 0);
    }
    else {
        SET_REQ_WIN32_ERROR(req, fn_RtlNtStatusToDosError(status));
    }
}

int fs__utime_handle(HANDLE handle, double atime, double mtime)
{
    FILETIME filetime_a, filetime_m;

    //TIME_T_TO_FILETIME((time_t) atime, &filetime_a);
    //TIME_T_TO_FILETIME((time_t) mtime, &filetime_m);
    
    if (!fn_SetFileTime(handle, NULL, &filetime_a, &filetime_m)) {
        return -1;
    }

    return 0;
}

void fs__utime(async_fs_t* req)
{
    HANDLE handle;

    handle = fn_CreateFileW(req->path, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        SET_REQ_WIN32_ERROR(req, fn_GetLastError());
        return;
    }

    if (fs__utime_handle(handle, req->atime, req->mtime) != 0) {
        SET_REQ_WIN32_ERROR(req, fn_GetLastError());
        fn_CloseHandle(handle);
        return;
    }

    fn_CloseHandle(handle);

    req->result = 0;
}

void fs__futime(async_fs_t* req)
{
    HANDLE handle = req->hFile;

    if (handle == INVALID_HANDLE_VALUE) {
        SET_REQ_WIN32_ERROR(req, ERROR_INVALID_HANDLE);
        return;
    }

    if (fs__utime_handle(handle, req->atime, req->mtime) != 0) {
        SET_REQ_WIN32_ERROR(req, fn_GetLastError());
        return;
    }

    req->result = 0;
}

void fs__link(async_fs_t* req)
{
    DWORD r = fn_CreateHardLinkW(req->new_pathw, req->path, NULL);
    if (r == 0) {
        SET_REQ_WIN32_ERROR(req, fn_GetLastError());
    }
    else {
        req->result = 0;
    }
}

void fs__symlink(async_fs_t* req)
{
    wchar_t* path = req->path;
    wchar_t* new_path = req->new_pathw;

    if (req->flags & ASYNC_FS_SYMLINK_JUNCTION) {
        HANDLE handle = INVALID_HANDLE_VALUE;
        REPARSE_DATA_BUFFER *buffer = NULL;
        int created = 0;
        int target_len;
        int is_absolute, is_long_path;
        int needed_buf_size, used_buf_size, used_data_size, path_buf_len;
        int start, len, i;
        int add_slash;
        DWORD bytes;
        wchar_t* path_buf;

        target_len = fn_lstrlenW(path);
        is_long_path = fn_StrCmpNW(path, LONG_PATH_PREFIX, LONG_PATH_PREFIX_LEN) == 0;

        if (is_long_path) {
            is_absolute = 1;
        }
        else {
            is_absolute = target_len >= 3 && IS_LETTER(path[0]) && path[1] == L':' && IS_SLASH(path[2]);
        }

        if (!is_absolute) {
            /* Not supporting relative paths */
            SET_REQ_ASYNC_ERROR(req, ASYNC_EINVAL, ERROR_NOT_SUPPORTED);
            return;
        }

        /* Do a pessimistic calculation of the required buffer size */
        needed_buf_size = FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer) + JUNCTION_PREFIX_LEN * sizeof(wchar_t) + 2 * (target_len + 2) * sizeof(wchar_t);

        /* Allocate the buffer */
        buffer = (REPARSE_DATA_BUFFER*)memory_alloc(needed_buf_size);

        /* Grab a pointer to the part of the buffer where filenames go */
        path_buf = (wchar_t*)&(buffer->MountPointReparseBuffer.PathBuffer);
        path_buf_len = 0;

        /* Copy the substitute (internal) target path */
        start = path_buf_len;

        wcsncpy((wchar_t*)&path_buf[path_buf_len], JUNCTION_PREFIX, JUNCTION_PREFIX_LEN);
        path_buf_len += JUNCTION_PREFIX_LEN;

        add_slash = 0;
        for (i = is_long_path ? LONG_PATH_PREFIX_LEN : 0; path[i] != L'\0'; i++) {
            if (IS_SLASH(path[i])) {
                add_slash = 1;
                continue;
            }

            if (add_slash) {
                path_buf[path_buf_len++] = L'\\';
                add_slash = 0;
            }

            path_buf[path_buf_len++] = path[i];
        }
        path_buf[path_buf_len++] = L'\\';
        len = path_buf_len - start;

        /* Set the info about the substitute name */
        buffer->MountPointReparseBuffer.SubstituteNameOffset = start * sizeof(wchar_t);
        buffer->MountPointReparseBuffer.SubstituteNameLength = len * sizeof(wchar_t);

        /* Insert null terminator */
        path_buf[path_buf_len++] = L'\0';

        /* Copy the print name of the target path */
        start = path_buf_len;
        add_slash = 0;
        for (i = is_long_path ? LONG_PATH_PREFIX_LEN : 0; path[i] != L'\0'; i++) {
            if (IS_SLASH(path[i])) {
                add_slash = 1;
                continue;
            }

            if (add_slash) {
                path_buf[path_buf_len++] = L'\\';
                add_slash = 0;
            }

            path_buf[path_buf_len++] = path[i];
        }
        len = path_buf_len - start;
        if (len == 2) {
            path_buf[path_buf_len++] = L'\\';
            ++len;
        }

        /* Set the info about the print name */
        buffer->MountPointReparseBuffer.PrintNameOffset = start * sizeof(wchar_t);
        buffer->MountPointReparseBuffer.PrintNameLength = len * sizeof(wchar_t);

        /* Insert another null terminator */
        path_buf[path_buf_len++] = L'\0';

        /* Calculate how much buffer space was actually used */
        used_buf_size = FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer.PathBuffer) + path_buf_len * sizeof(wchar_t);
        used_data_size = used_buf_size - FIELD_OFFSET(REPARSE_DATA_BUFFER, MountPointReparseBuffer);

        /* Put general info in the data buffer */
        buffer->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
        buffer->ReparseDataLength = used_data_size;
        buffer->Reserved = 0;

        /* Create a new directory */
        if (!fn_CreateDirectoryW(new_path, NULL)) {
            SET_REQ_WIN32_ERROR(req, fn_GetLastError());
            goto error;
        }
        created = 1;

        /* Open the directory */
        handle = fn_CreateFileW(new_path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (handle == INVALID_HANDLE_VALUE) {
            SET_REQ_WIN32_ERROR(req, fn_GetLastError());
            goto error;
        }

        /* Create the actual reparse point */
        if (!fn_DeviceIoControl(handle, FSCTL_SET_REPARSE_POINT, buffer, used_buf_size, NULL, 0, &bytes, NULL)) {
            SET_REQ_WIN32_ERROR(req, fn_GetLastError());
            goto error;
        }

        /* Clean up */
        fn_CloseHandle(handle);
        memory_free(buffer);

        SET_REQ_RESULT(req, 0);
        return;

error:
        memory_free(buffer);

        if (handle != INVALID_HANDLE_VALUE) {
            fn_CloseHandle(handle);
        }

        if (created) {
            fn_RemoveDirectoryW(new_path);
        }
    }
    else if (fn_CreateSymbolicLinkW != NULL) {
        if (!fn_CreateSymbolicLinkW(new_path, path, req->flags)) {
            SET_REQ_WIN32_ERROR(req, fn_GetLastError());
        }
        else {
            SET_REQ_RESULT(req, 0);
        }
    }
}

static void fs__readlink(async_fs_t* req)
{
    HANDLE handle;

    handle = fn_CreateFileW(req->path, 0, 0, NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);

    if (handle == INVALID_HANDLE_VALUE) {
        SET_REQ_WIN32_ERROR(req, fn_GetLastError());
        return;
    }

    if (fs__readlink_handle(handle, (char**) &req->ptr, NULL) != 0) {
        SET_REQ_WIN32_ERROR(req, fn_GetLastError());
        fn_CloseHandle(handle);
        return;
    }

    req->flags |= ASYNC_FS_FREE_PTR;
    SET_REQ_RESULT(req, 0);

    fn_CloseHandle(handle);
}

void async__fs_work(struct async__work* w)
{
    async_fs_t* req;

    req = container_of(w, async_fs_t, work_req);

#define XX(uc, lc)  case ASYNC_FS_##uc: fs__##lc(req); break;
    switch (req->fs_type) {
        XX(OPEN, open)
        XX(CLOSE, close)
        XX(READ, read)
        XX(WRITE, write)
        XX(STAT, stat)
        XX(LSTAT, lstat)
        XX(FSTAT, fstat)
        XX(FTRUNCATE, ftruncate)
        XX(UTIME, utime)
        XX(FUTIME, futime)
        XX(FSYNC, fsync)
        XX(UNLINK, unlink)
        XX(RMDIR, rmdir)
        XX(MKDIR, mkdir)
        XX(RENAME, rename)
        XX(READDIR, readdir)
        XX(LINK, link)
        XX(SYMLINK, symlink)
        XX(READLINK, readlink)
    }
}

static void async__fs_done(struct async__work* w, int status)
{
    async_fs_t* req;

    req = container_of(w, async_fs_t, work_req);
    async__req_unregister(req->loop, req);

    if (status == ASYNC_ECANCELED) {
        req->result = ASYNC_ECANCELED;
    }

    if (req->cb != NULL) {
        req->cb(req);
    }
}

void async_fs_req_cleanup(async_fs_t* req)
{
    if (req->flags & ASYNC_FS_CLEANEDUP) {
        return;
    }

    if (req->flags & ASYNC_FS_FREE_PATHS) {
        memory_free(req->path);
    }

    if (req->flags & ASYNC_FS_FREE_PTR) {
        memory_free(req->ptr);
    }

    req->path = NULL;
    req->new_pathw = NULL;
    req->ptr = NULL;

    req->flags |= ASYNC_FS_CLEANEDUP;
}

int async_fs_open(async_loop_t* loop, async_fs_t* req, const wchar_t* path, DWORD access, DWORD disposition, DWORD attributes, async_fs_cb cb)
{
    int err;

    async_fs_req_init(loop, req, ASYNC_FS_OPEN, cb);

    err = fs__capture_path(loop, req, path, NULL);
    if (err) {
        return async_translate_sys_error(err);
    }

    req->access = access;
    req->disposition = disposition;
    req->attributes = attributes;

    if (cb) {
        QUEUE_FS_TP_JOB(loop, req);
        return 0;
    }
    else {
        fs__open(req);
        return req->result;
    }
}


int async_fs_close(async_loop_t* loop, async_fs_t* req, HANDLE hFile, async_fs_cb cb)
{
    async_fs_req_init(loop, req, ASYNC_FS_CLOSE, cb);
    req->hFile = hFile;

    if (cb) {
        QUEUE_FS_TP_JOB(loop, req);
        return 0;
    }
    else {
        fs__close(req);
        return req->result;
    }
}

int async_fs_read(async_loop_t* loop, async_fs_t* req, HANDLE hFile, const async_buf_t bufs[], uint32_t nbufs, int64_t offset, async_fs_cb cb)
{
    async_fs_req_init(loop, req, ASYNC_FS_READ, cb);

    req->hFile = hFile;

    req->nbufs = nbufs;
    req->bufs = req->bufsml;
    if (nbufs > ARRAY_SIZE(req->bufsml)) {
        req->bufs = memory_alloc(nbufs * sizeof(*bufs));
    }

    __movsb((uint8_t*)req->bufs, (const uint8_t*)bufs, nbufs * sizeof(*bufs));

    req->offset = offset;

    if (cb) {
        QUEUE_FS_TP_JOB(loop, req);
        return 0;
    }
    else {
        fs__read(req);
        return req->result;
    }
}

int async_fs_write(async_loop_t* loop, async_fs_t* req, HANDLE hFile, const async_buf_t bufs[], uint32_t nbufs, int64_t offset, async_fs_cb cb)
{
    async_fs_req_init(loop, req, ASYNC_FS_WRITE, cb);

    req->hFile = hFile;

    req->nbufs = nbufs;
    req->bufs = req->bufsml;
    if (nbufs > ARRAY_SIZE(req->bufsml)) {
        req->bufs = memory_alloc(nbufs * sizeof(*bufs));
    }

    __movsb((uint8_t*)req->bufs, (const uint8_t*)bufs, nbufs * sizeof(*bufs));

    req->offset = offset;

    if (cb) {
        QUEUE_FS_TP_JOB(loop, req);
        return 0;
    }
    else {
        fs__write(req);
        return req->result;
    }
}

int async_fs_unlink(async_loop_t* loop, async_fs_t* req, const wchar_t* path, async_fs_cb cb)
{
    int err;

    async_fs_req_init(loop, req, ASYNC_FS_UNLINK, cb);

    err = fs__capture_path(loop, req, path, NULL);
    if (err) {
        return async_translate_sys_error(err);
    }

    if (cb) {
        QUEUE_FS_TP_JOB(loop, req);
        return 0;
    }
    else {
        fs__unlink(req);
        return req->result;
    }
}

int async_fs_mkdir(async_loop_t* loop, async_fs_t* req, const wchar_t* path, async_fs_cb cb)
{
    int err;

    async_fs_req_init(loop, req, ASYNC_FS_MKDIR, cb);

    err = fs__capture_path(loop, req, path, NULL);
    if (err) {
        return async_translate_sys_error(err);
    }

    if (cb) {
        QUEUE_FS_TP_JOB(loop, req);
        return 0;
    }
    else {
        fs__mkdir(req);
        return req->result;
    }
}

int async_fs_rmdir(async_loop_t* loop, async_fs_t* req, const wchar_t* path, async_fs_cb cb)
{
    int err;

    async_fs_req_init(loop, req, ASYNC_FS_RMDIR, cb);

    err = fs__capture_path(loop, req, path, NULL);
    if (err) {
        return async_translate_sys_error(err);
    }

    if (cb) {
        QUEUE_FS_TP_JOB(loop, req);
        return 0;
    }
    else {
        fs__rmdir(req);
        return req->result;
    }
}


int async_fs_readdir(async_loop_t* loop, async_fs_t* req, const wchar_t* path, async_fs_cb cb)
{
    int err;

    async_fs_req_init(loop, req, ASYNC_FS_READDIR, cb);

    err = fs__capture_path(loop, req, path, NULL);
    if (err) {
        return async_translate_sys_error(err);
    }

    if (cb) {
        QUEUE_FS_TP_JOB(loop, req);
        return 0;
    }
    else {
        fs__readdir(req);
        return req->result;
    }
}

int async_fs_link(async_loop_t* loop, async_fs_t* req, const wchar_t* path, const wchar_t* new_path, async_fs_cb cb)
{
    int err;

    async_fs_req_init(loop, req, ASYNC_FS_LINK, cb);

    err = fs__capture_path(loop, req, path, new_path);
    if (err) {
        return async_translate_sys_error(err);
    }

    if (cb) {
        QUEUE_FS_TP_JOB(loop, req);
        return 0;
    }
    else {
        fs__link(req);
        return req->result;
    }
}

int async_fs_symlink(async_loop_t* loop, async_fs_t* req, const wchar_t* path, const wchar_t* new_path, int flags, async_fs_cb cb)
{
    int err;

    async_fs_req_init(loop, req, ASYNC_FS_SYMLINK, cb);

    err = fs__capture_path(loop, req, path, new_path);
    if (err) {
        return async_translate_sys_error(err);
    }

    req->flags = flags;

    if (cb) {
        QUEUE_FS_TP_JOB(loop, req);
        return 0;
    }
    else {
        fs__symlink(req);
        return req->result;
    }
}

int async_fs_readlink(async_loop_t* loop, async_fs_t* req, const wchar_t* path, async_fs_cb cb)
{
    int err;

    async_fs_req_init(loop, req, ASYNC_FS_READLINK, cb);

    err = fs__capture_path(loop, req, path, NULL);
    if (err) {
        return async_translate_sys_error(err);
    }

    if (cb) {
        QUEUE_FS_TP_JOB(loop, req);
        return 0;
    } else {
        fs__readlink(req);
        return req->result;
    }
}

int async_fs_stat(async_loop_t* loop, async_fs_t* req, const wchar_t* path, async_fs_cb cb)
{
    int err;

    async_fs_req_init(loop, req, ASYNC_FS_STAT, cb);

    err = fs__capture_path(loop, req, path, NULL);
    if (err) {
        return async_translate_sys_error(err);
    }

    if (cb) {
        QUEUE_FS_TP_JOB(loop, req);
        return 0;
    }
    else {
        fs__stat(req);
        return req->result;
    }
}

int async_fs_lstat(async_loop_t* loop, async_fs_t* req, const wchar_t* path, async_fs_cb cb)
{
    int err;

    async_fs_req_init(loop, req, ASYNC_FS_LSTAT, cb);

    err = fs__capture_path(loop, req, path, NULL);
    if (err) {
        return async_translate_sys_error(err);
    }

    if (cb) {
        QUEUE_FS_TP_JOB(loop, req);
        return 0;
    }
    else {
        fs__lstat(req);
        return req->result;
    }
}

int async_fs_fstat(async_loop_t* loop, async_fs_t* req, async_file fd, async_fs_cb cb)
{
    async_fs_req_init(loop, req, ASYNC_FS_FSTAT, cb);
    req->fd = fd;

    if (cb) {
        QUEUE_FS_TP_JOB(loop, req);
        return 0;
    } 
    else {
        fs__fstat(req);
        return req->result;
    }
}

int async_fs_rename(async_loop_t* loop, async_fs_t* req, const wchar_t* path, const wchar_t* new_path, async_fs_cb cb)
{
    int err;

    async_fs_req_init(loop, req, ASYNC_FS_RENAME, cb);

    err = fs__capture_path(loop, req, path, new_path);
    if (err) {
        return async_translate_sys_error(err);
    }

    if (cb) {
        QUEUE_FS_TP_JOB(loop, req);
        return 0;
    }
    else {
        fs__rename(req);
        return req->result;
    }
}

int async_fs_fsync(async_loop_t* loop, async_fs_t* req, HANDLE hFile, async_fs_cb cb)
{
    async_fs_req_init(loop, req, ASYNC_FS_FSYNC, cb);
    req->hFile = hFile;

    if (cb) {
        QUEUE_FS_TP_JOB(loop, req);
        return 0;
    }
    else {
        fs__fsync(req);
        return req->result;
    }
}

int async_fs_ftruncate(async_loop_t* loop, async_fs_t* req, HANDLE hFile, int64_t offset, async_fs_cb cb)
{
    async_fs_req_init(loop, req, ASYNC_FS_FTRUNCATE, cb);

    req->hFile = hFile;
    req->offset = offset;

    if (cb) {
        QUEUE_FS_TP_JOB(loop, req);
        return 0;
    }
    else {
        fs__ftruncate(req);
        return req->result;
    }
}

int async_fs_utime(async_loop_t* loop, async_fs_t* req, const wchar_t* path, double atime, double mtime, async_fs_cb cb)
{
    int err;

    async_fs_req_init(loop, req, ASYNC_FS_UTIME, cb);

    err = fs__capture_path(loop, req, path, NULL);
    if (err) {
        return async_translate_sys_error(err);
    }

    req->atime = atime;
    req->mtime = mtime;

    if (cb) {
        QUEUE_FS_TP_JOB(loop, req);
        return 0;
    }
    else {
        fs__utime(req);
        return req->result;
    }
}

int async_fs_futime(async_loop_t* loop, async_fs_t* req, HANDLE hFile, double atime, double mtime, async_fs_cb cb)
{
    async_fs_req_init(loop, req, ASYNC_FS_FUTIME, cb);

    req->hFile = hFile;
    req->atime = atime;
    req->mtime = mtime;

    if (cb) {
        QUEUE_FS_TP_JOB(loop, req);
        return 0;
    }
    else {
        fs__futime(req);
        return req->result;
    }
}
