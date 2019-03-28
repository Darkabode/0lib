#ifndef POLARSSL_ENTROPY_POLL_H
#define POLARSSL_ENTROPY_POLL_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Default thresholds for built-in sources
 */
#define ENTROPY_MIN_PLATFORM    128     /**< Minimum for platform source    */
#define ENTROPY_MIN_HAVEGE      128     /**< Minimum for HAVEGE             */
#define ENTROPY_MIN_HARDCLOCK    32     /**< Minimum for hardclock()        */

/**
 * \brief           Platform-specific entropy poll callback
 */
int platform_entropy_poll( void *data, uint8_t *output, size_t len, size_t *olen );

/**
 * \brief           hardclock-based entropy poll callback
 */
int hardclock_poll(void *data, uint8_t *output, size_t len, size_t *olen );

#ifdef __cplusplus
}
#endif

#endif /* entropy_poll.h */
