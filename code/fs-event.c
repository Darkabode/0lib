#include "zmodule.h"
#include "async.h"
#include "internal.h"
#include "handle-inl.h"
#include "req-inl.h"

const uint32_t async_directory_watcher_buffer_size = 4096;

void async_fs_event_queue_readdirchanges(async_loop_t* loop, async_fs_event_t* handle)
{
    __stosb((uint8_t*)&(handle->req.overlapped), 0, sizeof(handle->req.overlapped));
    if (!fn_ReadDirectoryChangesW(handle->dir_handle, handle->buffer, async_directory_watcher_buffer_size, FALSE, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_LAST_ACCESS | FILE_NOTIFY_CHANGE_CREATION | FILE_NOTIFY_CHANGE_SECURITY, NULL, &handle->req.overlapped, NULL)) {
        /* Make this req pending reporting an error. */
        SET_REQ_ERROR(&handle->req, fn_GetLastError());
        async_insert_pending_req(loop, (async_req_t*)&handle->req);
    }
    handle->req_pending = 1;
}

int async_split_path(const wchar_t* filename, wchar_t** dir, wchar_t** file)
{
    int len = fn_lstrlenW(filename);
    int i = len;
    while (i > 0 && filename[--i] != '\\' && filename[i] != '/');

    if (i == 0) {
        if (dir) {
            *dir = (wchar_t*)memory_alloc((MAX_PATH + 1) * sizeof(wchar_t));

            if (!fn_GetCurrentDirectoryW(MAX_PATH, *dir)) {
                memory_free(*dir);
                *dir = NULL;
                return -1;
            }
        }

        *file = utils_wcsdup(filename);
    }
    else {
        if (dir) {
            *dir = (wchar_t*)memory_alloc((i + 1) * sizeof(wchar_t));
            fn_lstrcpynW(*dir, filename, i);
            (*dir)[i] = L'\0';
        }

        *file = (wchar_t*)memory_alloc((len - i) * sizeof(wchar_t));
        fn_lstrcpynW(*file, filename + i + 1, len - i - 1);
        (*file)[len - i - 1] = L'\0';
    }
    return 0;
}

int async_fs_event_init(async_loop_t* loop, async_fs_event_t* handle)
{
    async__handle_init(loop, (async_handle_t*) handle, ASYNC_FS_EVENT);
    handle->dir_handle = INVALID_HANDLE_VALUE;
    handle->buffer = NULL;
    handle->req_pending = 0;
    handle->filew = NULL;
    handle->short_filew = NULL;
    handle->dirw = NULL;

    async_req_init(loop, (async_req_t*)&handle->req);
    handle->req.type = ASYNC_FS_EVENT_REQ;
    handle->req.data = handle;

    return 0;
}


int async_fs_event_start(async_fs_event_t* handle, async_fs_event_cb cb, const wchar_t* path, uint32_t flags)
{
    int is_path_dir;
    DWORD attr, last_error;
    wchar_t* dir = NULL, *dir_to_watch;
    wchar_t short_path[MAX_PATH];

    if (async__is_active(handle)) {
        return ASYNC_EINVAL;
    }

    handle->cb = cb;
    handle->path = utils_wcsdup(path);
    if (!handle->path) {
        last_error = ERROR_OUTOFMEMORY;
        goto error;
    }

    async__handle_start(handle);

    /* Determine whether path is a file or a directory. */
    attr = fn_GetFileAttributesW(path);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        last_error = fn_GetLastError();
        goto error;
    }

    is_path_dir = (attr & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;

    if (is_path_dir) {
        /* path is a directory, so that's the directory that we will watch. */
        dir_to_watch = utils_wcsdup(path);
        handle->dirw = dir_to_watch;
    }
    else {
        /*
        * path is a file.  So we split path into dir & file parts, and
        * watch the dir directory.
        */

        /* Convert to short path. */
        if (!fn_GetShortPathNameW(path, short_path, ARRAY_SIZE(short_path))) {
            last_error = fn_GetLastError();
            goto error;
        }

        if (async_split_path(path, &dir, &handle->filew) != 0) {
            last_error = fn_GetLastError();
            goto error;
        }

        if (async_split_path(short_path, NULL, &handle->short_filew) != 0) {
            last_error = fn_GetLastError();
            goto error;
        }

        dir_to_watch = dir;
    }

    handle->dir_handle = fn_CreateFileW(dir_to_watch, FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);

    if (dir) {
        memory_free(dir);
        dir = NULL;
    }

    if (handle->dir_handle == INVALID_HANDLE_VALUE) {
        last_error = fn_GetLastError();
        goto error;
    }

    if (fn_CreateIoCompletionPort(handle->dir_handle, handle->loop->iocp, (ULONG_PTR)handle, 0) == NULL) {
        last_error = fn_GetLastError();
        goto error;
    }

    if (!handle->buffer) {
        handle->buffer = (char*)memory_aligned_alloc(async_directory_watcher_buffer_size);
    }
    if (!handle->buffer) {
        last_error = ERROR_OUTOFMEMORY;
        goto error;
    }

    __stosb((uint8_t*)&(handle->req.overlapped), 0, sizeof(handle->req.overlapped));

    if (!fn_ReadDirectoryChangesW(handle->dir_handle, handle->buffer, async_directory_watcher_buffer_size, FALSE, FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_LAST_ACCESS | FILE_NOTIFY_CHANGE_CREATION | FILE_NOTIFY_CHANGE_SECURITY, NULL, &handle->req.overlapped, NULL)) {
        last_error = fn_GetLastError();
        goto error;
    }

    handle->req_pending = 1;
    return 0;

error:
    if (handle->path) {
        memory_free(handle->path);
        handle->path = NULL;
    }

    if (handle->filew) {
        memory_free(handle->filew);
        handle->filew = NULL;
    }

    if (handle->short_filew) {
        memory_free(handle->short_filew);
        handle->short_filew = NULL;
    }

    if (handle->dir_handle != INVALID_HANDLE_VALUE) {
        fn_CloseHandle(handle->dir_handle);
        handle->dir_handle = INVALID_HANDLE_VALUE;
    }

    if (handle->buffer) {
        memory_aligned_free(handle->buffer);
        handle->buffer = NULL;
    }

  return async_translate_sys_error(last_error);
}


int async_fs_event_stop(async_fs_event_t* handle)
{
    if (!async__is_active(handle)) {
        return 0;
    }

    if (handle->dir_handle != INVALID_HANDLE_VALUE) {
        fn_CloseHandle(handle->dir_handle);
        handle->dir_handle = INVALID_HANDLE_VALUE;
    }

    async__handle_stop(handle);

    if (handle->filew) {
        memory_free(handle->filew);
        handle->filew = NULL;
    }

    if (handle->short_filew) {
        memory_free(handle->short_filew);
        handle->short_filew = NULL;
    }

    if (handle->path) {
        memory_free(handle->path);
        handle->path = NULL;
    }

    if (handle->dirw) {
        memory_free(handle->dirw);
        handle->dirw = NULL;
    }

    return 0;
}


void async_process_fs_event_req(async_loop_t* loop, async_req_t* req, async_fs_event_t* handle)
{
    FILE_NOTIFY_INFORMATION* file_info;
    int err, sizew, size, result;
    char* filename = NULL;
    wchar_t* filenamew, *long_filenamew = NULL;
    DWORD offset = 0;

    handle->req_pending = 0;

    /* Don't report any callbacks if:
    * - We're closing, just push the handle onto the endgame queue
    * - We are not active, just ignore the callback
    */
    if (!async__is_active(handle)) {
        if (handle->flags & ASYNC__HANDLE_CLOSING) {
            async_want_endgame(loop, (async_handle_t*) handle);
        }
        return;
    }

    file_info = (FILE_NOTIFY_INFORMATION*)(handle->buffer + offset);

    if (REQ_SUCCESS(req)) {
        if (req->overlapped.InternalHigh > 0) {
            do {
                file_info = (FILE_NOTIFY_INFORMATION*)((char*)file_info + offset);

                /*
                 * Fire the event only if we were asked to watch a directory,
                 * or if the filename filter matches.
                 */
                if (handle->dirw || _wcsnicmp(handle->filew, file_info->FileName, file_info->FileNameLength / sizeof(wchar_t)) == 0 || _wcsnicmp(handle->short_filew, file_info->FileName, file_info->FileNameLength / sizeof(wchar_t)) == 0) {
                    if (handle->dirw) {
                        /*
                         * We attempt to convert the file name to its long form for
                         * events that still point to valid files on disk.
                         * For removed and renamed events, we do not provide the file name.
                         */
                        if (file_info->Action != FILE_ACTION_REMOVED && file_info->Action != FILE_ACTION_RENAMED_OLD_NAME) {
                            /* Construct a full path to the file. */
                            size = fn_lstrlenW(handle->dirw) + file_info->FileNameLength / sizeof(wchar_t) + 2;

                            filenamew = (wchar_t*)memory_alloc(size * sizeof(wchar_t));
                            _snwprintf(filenamew, size, L"%s\\%.*s", handle->dirw, file_info->FileNameLength / sizeof(wchar_t), file_info->FileName);

                            filenamew[size - 1] = L'\0';

                            /* Convert to long name. */
                            size = fn_GetLongPathNameW(filenamew, NULL, 0);

                            if (size) {
                                long_filenamew = (wchar_t*)memory_alloc(size * sizeof(wchar_t));
                                if (long_filenamew) {
                                    size = fn_GetLongPathNameW(filenamew, long_filenamew, size);
                                    if (size) {
                                        long_filenamew[size] = '\0';
                                    }
                                    else {
                                        memory_free(long_filenamew);
                                        long_filenamew = NULL;
                                    }
                                }
                            }

                            memory_free(filenamew);

                            if (long_filenamew) {
                                /* Get the file name out of the long path. */
                                result = async_split_path(long_filenamew, NULL, &filenamew);
                                memory_free(long_filenamew);

                                if (result == 0) {
                                    long_filenamew = filenamew;
                                    sizew = -1;
                                }
                                else {
                                    long_filenamew = NULL;
                                }
                            }

                            /*
                                * If we couldn't get the long name - just use the name
                                * provided by fn_ReadDirectoryChangesW.
                                */
                            if (!long_filenamew) {
                                filenamew = file_info->FileName;
                                sizew = file_info->FileNameLength / sizeof(wchar_t);
                            }
                        }
                        else {
                            /* Removed or renamed callbacks don't provide filename. */
                            filenamew = NULL;
                        }
                    }
                    else {
                        /* We already have the long name of the file, so just use it. */
                        filenamew = handle->filew;
                        sizew = -1;
                    }

                    if (filenamew) {
                        /* Convert the filename to utf8. */
                        size = utils_utf16_to_utf8(filenamew, sizew, NULL, 0);
                        if (size) {
                            filename = (char*)memory_alloc(size + 1);
                            size = utils_utf16_to_utf8(filenamew, sizew, filename, size);
                            if (size) {
                                filename[size] = '\0';
                            }
                            else {
                                memory_free(filename);
                                filename = NULL;
                            }
                        }
                    }

                    switch (file_info->Action) {
                        case FILE_ACTION_ADDED:
                        case FILE_ACTION_REMOVED:
                        case FILE_ACTION_RENAMED_OLD_NAME:
                        case FILE_ACTION_RENAMED_NEW_NAME:
                            handle->cb(handle, filename, ASYNC_RENAME, 0);
                            break;

                        case FILE_ACTION_MODIFIED:
                            handle->cb(handle, filename, ASYNC_CHANGE, 0);
                            break;
                    }

                    memory_free(filename);
                    filename = NULL;
                    memory_free(long_filenamew);
                    long_filenamew = NULL;
                }

                offset = file_info->NextEntryOffset;
            } while (offset && !(handle->flags & ASYNC__HANDLE_CLOSING));
        }
        else {
            handle->cb(handle, NULL, ASYNC_CHANGE, 0);
        }
    }
    else {
        err = GET_REQ_ERROR(req);
        handle->cb(handle, NULL, 0, async_translate_sys_error(err));
    }

    if (!(handle->flags & ASYNC__HANDLE_CLOSING)) {
        async_fs_event_queue_readdirchanges(loop, handle);
    }
    else {
        async_want_endgame(loop, (async_handle_t*)handle);
    }
}

void async_fs_event_close(async_loop_t* loop, async_fs_event_t* handle)
{
    async_fs_event_stop(handle);

    async__handle_closing(handle);

    if (!handle->req_pending) {
        async_want_endgame(loop, (async_handle_t*)handle);
    }
}


void async_fs_event_endgame(async_loop_t* loop, async_fs_event_t* handle)
{
    if ((handle->flags & ASYNC__HANDLE_CLOSING) && !handle->req_pending) {
        if (handle->buffer) {
        memory_aligned_free(handle->buffer);
        handle->buffer = NULL;
        }

        async__handle_close(handle);
    }
}
