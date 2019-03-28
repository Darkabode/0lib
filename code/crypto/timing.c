#include "..\zmodule.h"
#include "config.h"
#include "timing.h"

struct _hr_time
{
    LARGE_INTEGER start;
};

ulong_t hardclock( void )
{
    LARGE_INTEGER offset;

    fn_QueryPerformanceCounter(&offset);

    return (ulong_t)( offset.QuadPart );
}

volatile int alarmed = 0;

ulong_t get_timer( struct hr_time *val, int reset )
{
    ulong_t delta;
    LARGE_INTEGER offset, hfreq;
    struct _hr_time *t = (struct _hr_time *) val;

    fn_QueryPerformanceCounter(&offset);
    fn_QueryPerformanceFrequency(&hfreq);

    delta = (ulong_t)( ( 1000 * ( offset.QuadPart - t->start.QuadPart ) ) / hfreq.QuadPart );

    if (reset) {
        fn_QueryPerformanceCounter(&t->start);
    }
    return delta;
}

DWORD WINAPI TimerProc( LPVOID uElapse )
{
    fn_Sleep( (DWORD) uElapse );
    alarmed = 1;
    return( TRUE );
}

void set_alarm( int seconds )
{
    DWORD ThreadId;

    alarmed = 0;
    fn_CloseHandle( fn_CreateThread( NULL, 0, TimerProc, (LPVOID) ( seconds * 1000 ), 0, &ThreadId ) );
}

void m_sleep( int milliseconds )
{
    fn_Sleep(milliseconds);
}
