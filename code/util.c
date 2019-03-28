#include "zmodule.h"
#include <direct.h>
#include <limits.h>
#include <time.h>

#include "async.h"
#include "internal.h"


/*
 * Max title length; the only thing MSDN tells us about the maximum length
 * of the console title is that it is smaller than 64K. However in practice
 * it is much smaller, and there is no way to figure out what the exact length
 * of the title is or can be, at least not on XP. To make it even more
 * annoying, GetConsoleTitle failes when the buffer to be read into is bigger
 * than the actual maximum length. So we make a conservative guess here;
 * just don't put the novel you're writing in the title, unless the plot
 * survives truncation.
 */
#define MAX_TITLE_LENGTH 8192

/* The number of nanoseconds in one second. */
#undef NANOSEC
#define NANOSEC 1000000000


/* Cached copy of the process title, plus a mutex guarding it. */
static char *process_title;
static CRITICAL_SECTION process_title_lock;

/*
 * One-time intialization code for functionality defined in util.c.
 */
void async__util_init()
{
    LARGE_INTEGER perf_frequency;

    /* Initialize process title access mutex. */
    fn_InitializeCriticalSection(&process_title_lock);
}

int async_exepath(char* buffer, size_t* size_ptr)
{
    int utf8_len, utf16_buffer_len, utf16_len;
    wchar_t* utf16_buffer;
    int err;

    if (buffer == NULL || size_ptr == NULL || *size_ptr == 0) {
        return ASYNC_EINVAL;
    }

    if (*size_ptr > 32768) {
        /* Windows paths can never be longer than this. */
        utf16_buffer_len = 32768;
    }
    else {
        utf16_buffer_len = (int) *size_ptr;
    }

    utf16_buffer = (wchar_t*)memory_alloc(sizeof(wchar_t) * utf16_buffer_len);

    /* Get the path as UTF-16. */
    utf16_len = fn_GetModuleFileNameW(NULL, utf16_buffer, utf16_buffer_len);
    if (utf16_len <= 0) {
        err = fn_GetLastError();
        goto error;
    }

    /* utf16_len contains the length, *not* including the terminating null. */
    utf16_buffer[utf16_len] = L'\0';

    /* Convert to UTF-8 */
    utf8_len = fn_WideCharToMultiByte(CP_UTF8, 0, utf16_buffer, -1, buffer, *size_ptr > INT_MAX ? INT_MAX : (int) *size_ptr, NULL, NULL);
    if (utf8_len == 0) {
        err = fn_GetLastError();
        goto error;
    }

    memory_free(utf16_buffer);

    /* utf8_len *does* include the terminating null at this point, but the */
    /* returned size shouldn't. */
    *size_ptr = utf8_len - 1;
    return 0;
 error:
    memory_free(utf16_buffer);
    return async_translate_sys_error(err);
}


int async_cwd(char* buffer, size_t* size)
{
    DWORD utf16_len;
    wchar_t utf16_buffer[MAX_PATH];
    int r;

    if (buffer == NULL || size == NULL) {
        return ASYNC_EINVAL;
    }

    utf16_len = fn_GetCurrentDirectoryW(MAX_PATH, utf16_buffer);
    if (utf16_len == 0) {
        return async_translate_sys_error(fn_GetLastError());
    }
    else if (utf16_len > MAX_PATH) {
        /* This should be impossible;  however the CRT has a code path to deal */
        /* with this scenario, so I added a check anyway. */
        return ASYNC_EIO;
    }

    /* utf16_len contains the length, *not* including the terminating null. */
    utf16_buffer[utf16_len] = L'\0';

    /* The returned directory should not have a trailing slash, unless it */
    /* points at a drive root, like c:\. Remove it if needed.*/
    if (utf16_buffer[utf16_len - 1] == L'\\' && !(utf16_len == 3 && utf16_buffer[1] == L':')) {
        utf16_len--;
        utf16_buffer[utf16_len] = L'\0';
    }

    /* Check how much space we need */
    r = fn_WideCharToMultiByte(CP_UTF8, 0, utf16_buffer, -1, NULL, 0, NULL, NULL);
    if (r == 0) {
        return async_translate_sys_error(fn_GetLastError());
    }
    else if (r > (int) *size) {
        *size = r;
        return ASYNC_ENOBUFS;
    }

    /* Convert to UTF-8 */
    r = fn_WideCharToMultiByte(CP_UTF8, 0, utf16_buffer, -1, buffer, *size > INT_MAX ? INT_MAX : (int) *size, NULL, NULL);
    if (r == 0) {
        return async_translate_sys_error(fn_GetLastError());
    }

    *size = r;
    return 0;
}

int async_chdir(const char* dir)
{
    wchar_t utf16_buffer[MAX_PATH];
    size_t utf16_len;
    wchar_t drive_letter, env_var[4];

    if (dir == NULL) {
        return ASYNC_EINVAL;
    }

    if (fn_MultiByteToWideChar(CP_UTF8, 0, dir, -1, utf16_buffer, MAX_PATH) == 0) {
        DWORD error = fn_GetLastError();
        /* The maximum length of the current working directory is 260 chars, */
        /* including terminating null. If it doesn't fit, the path name must be */
        /* too long. */
        if (error == ERROR_INSUFFICIENT_BUFFER) {
            return ASYNC_ENAMETOOLONG;
        }
        else {
            return async_translate_sys_error(error);
        }
    }

    if (!fn_SetCurrentDirectoryW(utf16_buffer)) {
        return async_translate_sys_error(fn_GetLastError());
    }

    /* Windows stores the drive-local path in an "hidden" environment variable, */
    /* which has the form "=C:=C:\Windows". SetCurrentDirectory does not */
    /* update this, so we'll have to do it. */
    utf16_len = fn_GetCurrentDirectoryW(MAX_PATH, utf16_buffer);
    if (utf16_len == 0) {
        return async_translate_sys_error(fn_GetLastError());
    }
    else if (utf16_len > MAX_PATH) {
        return ASYNC_EIO;
    }

    /* The returned directory should not have a trailing slash, unless it */
    /* points at a drive root, like c:\. Remove it if needed. */
    if (utf16_buffer[utf16_len - 1] == L'\\' && !(utf16_len == 3 && utf16_buffer[1] == L':')) {
        utf16_len--;
        utf16_buffer[utf16_len] = L'\0';
    }

    if (utf16_len < 2 || utf16_buffer[1] != L':') {
        /* Doesn't look like a drive letter could be there - probably an UNC */
        /* path. TODO: Need to handle win32 namespaces like \\?\C:\ ? */
        drive_letter = 0;
    }
    else if (utf16_buffer[0] >= L'A' && utf16_buffer[0] <= L'Z') {
        drive_letter = utf16_buffer[0];
    }
    else if (utf16_buffer[0] >= L'a' && utf16_buffer[0] <= L'z') {
        /* Convert to uppercase. */
        drive_letter = utf16_buffer[0] - L'a' + L'A';
    }
    else {
        /* Not valid. */
        drive_letter = 0;
    }

    if (drive_letter != 0) {
        /* Construct the environment variable name and set it. */
        env_var[0] = L'=';
        env_var[1] = drive_letter;
        env_var[2] = L':';
        env_var[3] = L'\0';

        if (!fn_SetEnvironmentVariableW(env_var, utf16_buffer)) {
            return async_translate_sys_error(fn_GetLastError());
        }
    }

    return 0;
}

void async_loadavg(double avg[3])
{
    /* Can't be implemented */
    avg[0] = avg[1] = avg[2] = 0;
}

uint64_t async_get_free_memory(void)
{
    MEMORYSTATUSEX memory_status;
    memory_status.dwLength = sizeof(memory_status);

    if (!fn_GlobalMemoryStatusEx(&memory_status)) {
        return -1;
    }

    return (uint64_t)memory_status.ullAvailPhys;
}

uint64_t async_get_total_memory(void)
{
    MEMORYSTATUSEX memory_status;
    memory_status.dwLength = sizeof(memory_status);

    if (!fn_GlobalMemoryStatusEx(&memory_status)) {
        return -1;
    }

    return (uint64_t)memory_status.ullTotalPhys;
}

int async_parent_pid()
{
    int parent_pid = -1;
    HANDLE handle;
    PROCESSENTRY32W pe;
    DWORD current_pid = fn_GetCurrentProcessId();

    pe.dwSize = sizeof(PROCESSENTRY32);
    handle = fn_CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (fn_Process32FirstW(handle, &pe)) {
        do {
            if (pe.th32ProcessID == current_pid) {
                parent_pid = pe.th32ParentProcessID;
                break;
            }
        } while(fn_Process32NextW(handle, &pe));
    }

    fn_CloseHandle(handle);
    return parent_pid;
}

char** async_setup_args(int argc, char** argv)
{
    return argv;
}

int async_resident_set_memory(size_t* rss)
{
    HANDLE current_process;
    PROCESS_MEMORY_COUNTERS pmc;

    current_process = fn_GetCurrentProcess();

    if (!fn_GetProcessMemoryInfo(current_process, &pmc, sizeof(pmc))) {
        return async_translate_sys_error(fn_GetLastError());
    }

    *rss = pmc.WorkingSetSize;

    return 0;
}

int async_interface_addresses(async_interface_address_t** addresses_ptr, int* count_ptr)
{
    IP_ADAPTER_ADDRESSES* win_address_buf;
    ULONG win_address_buf_size;
    IP_ADAPTER_ADDRESSES* win_address;
    async_interface_address_t* async_address_buf;
    char* name_buf;
    size_t async_address_buf_size;
    async_interface_address_t* async_address;
    int count;

    /* Fetch the size of the adapters reported by windows, and then get the */
    /* list itself. */
    win_address_buf_size = 0;
    win_address_buf = NULL;

    for (;;) {
        ULONG r;

        /* If win_address_buf is 0, then GetAdaptersAddresses will fail with */
        /* ERROR_BUFFER_OVERFLOW, and the required buffer size will be stored in */
        /* win_address_buf_size. */
        r = fn_GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, win_address_buf, &win_address_buf_size);

        if (r == ERROR_SUCCESS) {
            break;
        }

        memory_free(win_address_buf);

        switch (r) {
            case ERROR_BUFFER_OVERFLOW:
                /* This happens when win_address_buf is NULL or too small to hold */
                /* all adapters. */
                win_address_buf = memory_alloc(win_address_buf_size);
                continue;
            case ERROR_NO_DATA: {
                /* No adapters were found. */
                async_address_buf = memory_alloc(1);
                if (async_address_buf == NULL) {
                    return ASYNC_ENOMEM;
                }

                *count_ptr = 0;
                *addresses_ptr = async_address_buf;
                return 0;
            }
            case ERROR_ADDRESS_NOT_ASSOCIATED:
                return ASYNC_EAGAIN;
            case ERROR_INVALID_PARAMETER:
                /* MSDN says:
                 *   "This error is returned for any of the following conditions: the
                 *   SizePointer parameter is NULL, the Address parameter is not
                 *   AF_INET, AF_INET6, or AF_UNSPEC, or the address information for
                 *   the parameters requested is greater than ULONG_MAX."
                 * Since the first two conditions are not met, it must be that the
                 * adapter data is too big.
                 */
                return ASYNC_ENOBUFS;
            default:
                /* Other (unspecified) errors can happen, but we don't have any */
                /* special meaning for them. */
                return async_translate_sys_error(r);
        }
    }

    /* Count the number of enabled interfaces and compute how much space is */
    /* needed to store their info. */
    count = 0;
    async_address_buf_size = 0;

    for (win_address = win_address_buf; win_address != NULL; win_address = win_address->Next) {
        /* Use IP_ADAPTER_UNICAST_ADDRESS_XP to retain backwards compatibility */
        /* with Windows XP */
        IP_ADAPTER_UNICAST_ADDRESS_XP* unicast_address;
        int name_size;

        /* Interfaces that are not 'up' should not be reported. Also skip */
        /* interfaces that have no associated unicast address, as to avoid */
        /* allocating space for the name for this interface. */
        if (win_address->OperStatus != IfOperStatusUp || win_address->FirstUnicastAddress == NULL) {
            continue;
        }

        /* Compute the size of the interface name. */
        name_size = fn_WideCharToMultiByte(CP_UTF8, 0, win_address->FriendlyName, -1, NULL, 0, NULL, FALSE);
        if (name_size <= 0) {
            memory_free(win_address_buf);
            return async_translate_sys_error(fn_GetLastError());
        }
        async_address_buf_size += name_size;

        /* Count the number of addresses associated with this interface, and */
        /* compute the size. */
        for (unicast_address = (IP_ADAPTER_UNICAST_ADDRESS_XP*)win_address->FirstUnicastAddress; unicast_address != NULL; unicast_address = unicast_address->Next) {
            ++count;
            async_address_buf_size += sizeof(async_interface_address_t);
        }
    }

    /* Allocate space to store interface data plus adapter names. */
    async_address_buf = memory_alloc(async_address_buf_size);

    /* Compute the start of the async_interface_address_t array, and the place in */
    /* the buffer where the interface names will be stored. */
    async_address = async_address_buf;
    name_buf = (char*) (async_address_buf + count);

    /* Fill out the output buffer. */
    for (win_address = win_address_buf; win_address != NULL; win_address = win_address->Next) {
        IP_ADAPTER_UNICAST_ADDRESS_XP* unicast_address;
        IP_ADAPTER_PREFIX* prefix;
        int name_size;
        size_t max_name_size;

        if (win_address->OperStatus != IfOperStatusUp || win_address->FirstUnicastAddress == NULL) {
            continue;
        }

        /* Convert the interface name to UTF8. */
        max_name_size = (char*) async_address_buf + async_address_buf_size - name_buf;
        if (max_name_size > (size_t)INT_MAX) {
            max_name_size = INT_MAX;
        }
        name_size = fn_WideCharToMultiByte(CP_UTF8, 0, win_address->FriendlyName, -1, name_buf, (int) max_name_size, NULL, FALSE);
        if (name_size <= 0) {
            memory_free(win_address_buf);
            memory_free(async_address_buf);
            return async_translate_sys_error(fn_GetLastError());
        }

        prefix = win_address->FirstPrefix;

        /* Add an async_interface_address_t element for every unicast address. */
        /* Walk the prefix list in tandem with the address list. */
        for (unicast_address = (IP_ADAPTER_UNICAST_ADDRESS_XP*)win_address->FirstUnicastAddress; unicast_address != NULL && prefix != NULL; unicast_address = unicast_address->Next, prefix = prefix->Next) {
            struct sockaddr* sa;
            ULONG prefix_len;

            sa = unicast_address->Address.lpSockaddr;
            prefix_len = prefix->PrefixLength;

            __stosb((uint8_t*)async_address, 0, sizeof *async_address);

            async_address->name = name_buf;

            if (win_address->PhysicalAddressLength == sizeof(async_address->phys_addr)) {
                __movsb((uint8_t*)async_address->phys_addr, (const uint8_t*)win_address->PhysicalAddress, sizeof(async_address->phys_addr));
            }

            async_address->is_internal = (win_address->IfType == IF_TYPE_SOFTWARE_LOOPBACK);

            if (sa->sa_family == AF_INET6) {
                async_address->address.address6 = *((struct sockaddr_in6 *) sa);

                async_address->netmask.netmask6.sin6_family = AF_INET6;
                memset(async_address->netmask.netmask6.sin6_addr.s6_addr, 0xff, prefix_len >> 3);
                async_address->netmask.netmask6.sin6_addr.s6_addr[prefix_len >> 3] = 0xff << (8 - prefix_len % 8);
            }
            else {
                async_address->address.address4 = *((struct sockaddr_in *) sa);
                async_address->netmask.netmask4.sin_family = AF_INET;
                async_address->netmask.netmask4.sin_addr.s_addr = fn_htonl(0xffffffff << (32 - prefix_len));
            }
            ++async_address;
        }

        name_buf += name_size;
    }

    memory_free(win_address_buf);

    *addresses_ptr = async_address_buf;
    *count_ptr = count;

    return 0;
}


void async_free_interface_addresses(async_interface_address_t* addresses, int count)
{
    memory_free(addresses);
}

int async_getrusage(async_rusage_t *async_rusage)
{
    FILETIME createTime, exitTime, kernelTime, userTime;
    SYSTEMTIME kernelSystemTime, userSystemTime;
    int ret;

    ret = fn_GetProcessTimes(fn_GetCurrentProcess(), &createTime, &exitTime, &kernelTime, &userTime);
    if (ret == 0) {
        return async_translate_sys_error(fn_GetLastError());
    }

    ret = fn_FileTimeToSystemTime(&kernelTime, &kernelSystemTime);
    if (ret == 0) {
        return async_translate_sys_error(fn_GetLastError());
    }

    ret = fn_FileTimeToSystemTime(&userTime, &userSystemTime);
    if (ret == 0) {
        return async_translate_sys_error(fn_GetLastError());
    }

    __stosb((uint8_t*)async_rusage, 0, sizeof(*async_rusage));

    async_rusage->ru_utime.tv_sec = userSystemTime.wHour * 3600 + userSystemTime.wMinute * 60 + userSystemTime.wSecond;
    async_rusage->ru_utime.tv_usec = userSystemTime.wMilliseconds * 1000;

    async_rusage->ru_stime.tv_sec = kernelSystemTime.wHour * 3600 + kernelSystemTime.wMinute * 60 + kernelSystemTime.wSecond;
    async_rusage->ru_stime.tv_usec = kernelSystemTime.wMilliseconds * 1000;

    return 0;
}
