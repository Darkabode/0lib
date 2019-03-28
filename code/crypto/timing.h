#ifndef POLARSSL_TIMING_H
#define POLARSSL_TIMING_H

#include "config.h"


#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          timer structure
 */
struct hr_time
{
    uint8_t opaque[32];
};

extern volatile int alarmed;

/**
 * \brief          Return the CPU cycle counter value
 */
ulong_t hardclock( void );

/**
 * \brief          Return the elapsed time in milliseconds
 *
 * \param val      points to a timer structure
 * \param reset    if set to 1, the timer is restarted
 */
ulong_t get_timer( struct hr_time *val, int reset );

/**
 * \brief          Setup an alarm clock
 *
 * \param seconds  delay before the "alarmed" flag is set
 */
void set_alarm( int seconds );

/**
 * \brief          Sleep for a certain amount of time
 *
 * \param milliseconds  delay in milliseconds
 */
void m_sleep( int milliseconds );

#ifdef __cplusplus
}
#endif

#endif /* timing.h */
