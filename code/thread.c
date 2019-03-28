#include "zmodule.h"
#include "async.h"
#include "internal.h"

#define HAVE_SRWLOCK_API() (fn_TryAcquireSRWLockShared != NULL)
#define HAVE_CONDVAR_API() (fn_InitializeConditionVariable != NULL)

void async__rwlock_srwlock_init(async_rwlock_t* rwlock);
void async__rwlock_srwlock_destroy(async_rwlock_t* rwlock);
void async__rwlock_srwlock_rdlock(async_rwlock_t* rwlock);
int async__rwlock_srwlock_tryrdlock(async_rwlock_t* rwlock);
void async__rwlock_srwlock_rdunlock(async_rwlock_t* rwlock);
void async__rwlock_srwlock_wrlock(async_rwlock_t* rwlock);
int async__rwlock_srwlock_trywrlock(async_rwlock_t* rwlock);
void async__rwlock_srwlock_wrunlock(async_rwlock_t* rwlock);

void async__rwlock_fallback_init(async_rwlock_t* rwlock);
void async__rwlock_fallback_destroy(async_rwlock_t* rwlock);
void async__rwlock_fallback_rdlock(async_rwlock_t* rwlock);
int async__rwlock_fallback_tryrdlock(async_rwlock_t* rwlock);
void async__rwlock_fallback_rdunlock(async_rwlock_t* rwlock);
void async__rwlock_fallback_wrlock(async_rwlock_t* rwlock);
int async__rwlock_fallback_trywrlock(async_rwlock_t* rwlock);
void async__rwlock_fallback_wrunlock(async_rwlock_t* rwlock);

void async_cond_fallback_destroy(async_cond_t* cond);
void async_cond_fallback_signal(async_cond_t* cond);
void async_cond_fallback_broadcast(async_cond_t* cond);
void async_cond_fallback_wait(async_cond_t* cond, mutex_t* mutex);
int async_cond_fallback_timedwait(async_cond_t* cond, mutex_t* mutex, uint64_t timeout);

void async_cond_condvar_signal(async_cond_t* cond);
void async_cond_condvar_broadcast(async_cond_t* cond);
void async_cond_condvar_wait(async_cond_t* cond, mutex_t* mutex);
int async_cond_condvar_timedwait(async_cond_t* cond, mutex_t* mutex, uint64_t timeout);

void async_once(async_once_t* guard, void (*callback)(void))
{
    DWORD result;
    HANDLE existing_event, created_event;

    /* Fast case - avoid WaitForSingleObject. */
    if (guard->ran) {
        return;
    }    

    created_event = fn_CreateEventW(NULL, 1, 0, NULL);
    if (created_event == 0) {
        /* Could fail in a low-memory situation? */
        LOG("CreateEvent failed with error 0x%08X", fn_GetLastError());
        return;
    }

    existing_event = _InterlockedCompareExchangePointer(&guard->event, created_event, NULL);

    if (existing_event == NULL) {
        /* We won the race */
        callback();

        result = fn_SetEvent(created_event);
        guard->ran = 1;
    }
    else {
        /* We lost the race. Destroy the event we created and wait for the */
        /* existing one todv become signaled. */
        fn_CloseHandle(created_event);
        result = fn_WaitForSingleObject(existing_event, INFINITE);
    }
}

int async_thread_join(async_thread_t *tid)
{
    if (fn_WaitForSingleObject(*tid, INFINITE))
        return async_translate_sys_error(fn_GetLastError());
    else {
        fn_CloseHandle(*tid);
        *tid = 0;
        return 0;
    }
}

void mutex_init(mutex_t* mutex)
{
    fn_InitializeCriticalSection(mutex);
}

void mutex_destroy(mutex_t* mutex)
{
    fn_DeleteCriticalSection(mutex);
}

void mutex_lock(mutex_t* mutex)
{
    fn_EnterCriticalSection(mutex);
}

int mutex_trylock(mutex_t* mutex)
{
    if (fn_TryEnterCriticalSection(mutex)) {
        return 0;
    }
    else {
        return ASYNC_EAGAIN;
    }
}

void mutex_unlock(mutex_t* mutex)
{
    fn_LeaveCriticalSection(mutex);
}

void async_rwlock_init(async_rwlock_t* rwlock)
{
    if (HAVE_SRWLOCK_API()) {
        async__rwlock_srwlock_init(rwlock);
    }
    else {
        async__rwlock_fallback_init(rwlock);
    }
}

void async_rwlock_destroy(async_rwlock_t* rwlock)
{
    if (HAVE_SRWLOCK_API()) {
        async__rwlock_srwlock_destroy(rwlock);
    }
    else {
        async__rwlock_fallback_destroy(rwlock);
    }
}

void async_rwlock_rdlock(async_rwlock_t* rwlock)
{
    if (HAVE_SRWLOCK_API()) {
        async__rwlock_srwlock_rdlock(rwlock);
    }
    else {
        async__rwlock_fallback_rdlock(rwlock);
    }
}

int async_rwlock_tryrdlock(async_rwlock_t* rwlock)
{
    if (HAVE_SRWLOCK_API()) {
        return async__rwlock_srwlock_tryrdlock(rwlock);
    }
    else {
        return async__rwlock_fallback_tryrdlock(rwlock);
    }
}

void async_rwlock_rdunlock(async_rwlock_t* rwlock)
{
    if (HAVE_SRWLOCK_API()) {
        async__rwlock_srwlock_rdunlock(rwlock);
    }
    else {
        async__rwlock_fallback_rdunlock(rwlock);
    }
}

void async_rwlock_wrlock(async_rwlock_t* rwlock)
{
    if (HAVE_SRWLOCK_API()) {
        async__rwlock_srwlock_wrlock(rwlock);
    }
    else {
        async__rwlock_fallback_wrlock(rwlock);
    }
}

int async_rwlock_trywrlock(async_rwlock_t* rwlock)
{
    if (HAVE_SRWLOCK_API()) {
        return async__rwlock_srwlock_trywrlock(rwlock);
    }
    else {
        return async__rwlock_fallback_trywrlock(rwlock);
    }
}

void async_rwlock_wrunlock(async_rwlock_t* rwlock)
{
    if (HAVE_SRWLOCK_API()) {
        async__rwlock_srwlock_wrunlock(rwlock);
    }
    else {
        async__rwlock_fallback_wrunlock(rwlock);
    }
}

int async_sem_init(async_sem_t* sem, uint32_t value)
{
    *sem = fn_CreateSemaphoreW(NULL, value, INT_MAX, NULL);
    if (*sem == NULL) {
        return async_translate_sys_error(fn_GetLastError());
    }
    else {
        return 0;
    }
}

void async_sem_destroy(async_sem_t* sem)
{
    if (!fn_CloseHandle(*sem)) {
        LOG(__FUNCTION__": CloseHandle failed with error 0x%08X", fn_GetLastError());
    }
}

void async_sem_post(async_sem_t* sem)
{
    if (!fn_ReleaseSemaphore(*sem, 1, NULL)) {
        LOG(__FUNCTION__": ReleaseSemaphore failed with error 0x%08X", fn_GetLastError());
    }
}


void async_sem_wait(async_sem_t* sem)
{
    if (fn_WaitForSingleObject(*sem, INFINITE) != WAIT_OBJECT_0) {
        LOG(__FUNCTION__": WaitForSingleObject failed with error 0x%08X", fn_GetLastError());
    }
}

int async_sem_trywait(async_sem_t* sem)
{
    DWORD r = fn_WaitForSingleObject(*sem, 0);

    if (r == WAIT_OBJECT_0) {
        return 0;
    }

    if (r == WAIT_TIMEOUT) {
        return ASYNC_EAGAIN;
    }

    return -1;
}

void async__rwlock_srwlock_init(async_rwlock_t* rwlock)
{
    fn_InitializeSRWLock(&rwlock->srwlock_);
}

void async__rwlock_srwlock_destroy(async_rwlock_t* rwlock)
{
  (void) rwlock;
}

void async__rwlock_srwlock_rdlock(async_rwlock_t* rwlock)
{
    fn_AcquireSRWLockShared(&rwlock->srwlock_);
}

int async__rwlock_srwlock_tryrdlock(async_rwlock_t* rwlock)
{
    if (fn_TryAcquireSRWLockShared(&rwlock->srwlock_)) {
        return 0;
    }
    else {
        return ASYNC_EBUSY;  /* TODO(bnoordhuis) EAGAIN when owned by this thread. */
    }
}

void async__rwlock_srwlock_rdunlock(async_rwlock_t* rwlock)
{
    fn_ReleaseSRWLockShared(&rwlock->srwlock_);
}

void async__rwlock_srwlock_wrlock(async_rwlock_t* rwlock)
{
    fn_AcquireSRWLockExclusive(&rwlock->srwlock_);
}

int async__rwlock_srwlock_trywrlock(async_rwlock_t* rwlock)
{
    if (fn_TryAcquireSRWLockExclusive(&rwlock->srwlock_)) {
        return 0;
    }
    else {
        return ASYNC_EBUSY;  /* TODO(bnoordhuis) EAGAIN when owned by this thread. */
    }
}

void async__rwlock_srwlock_wrunlock(async_rwlock_t* rwlock)
{
    fn_ReleaseSRWLockExclusive(&rwlock->srwlock_);
}

void async__rwlock_fallback_init(async_rwlock_t* rwlock)
{
    mutex_init(&rwlock->fallback_.read_mutex_);
    mutex_init(&rwlock->fallback_.write_mutex_);

    rwlock->fallback_.num_readers_ = 0;
}

void async__rwlock_fallback_destroy(async_rwlock_t* rwlock)
{
    mutex_destroy(&rwlock->fallback_.read_mutex_);
    mutex_destroy(&rwlock->fallback_.write_mutex_);
}

void async__rwlock_fallback_rdlock(async_rwlock_t* rwlock)
{
    mutex_lock(&rwlock->fallback_.read_mutex_);

    if (++rwlock->fallback_.num_readers_ == 1) {
        mutex_lock(&rwlock->fallback_.write_mutex_);
    }

    mutex_unlock(&rwlock->fallback_.read_mutex_);
}

int async__rwlock_fallback_tryrdlock(async_rwlock_t* rwlock)
{
    int err;

    err = mutex_trylock(&rwlock->fallback_.read_mutex_);
    if (err) {
        goto out;
    }

    err = 0;
    if (rwlock->fallback_.num_readers_ == 0) {
        err = mutex_trylock(&rwlock->fallback_.write_mutex_);
    }

    if (err == 0) {
        ++rwlock->fallback_.num_readers_;
    }

    mutex_unlock(&rwlock->fallback_.read_mutex_);

out:
    return err;
}

void async__rwlock_fallback_rdunlock(async_rwlock_t* rwlock)
{
    mutex_lock(&rwlock->fallback_.read_mutex_);

    if (--rwlock->fallback_.num_readers_ == 0) {
        mutex_unlock(&rwlock->fallback_.write_mutex_);
    }

    mutex_unlock(&rwlock->fallback_.read_mutex_);
}

void async__rwlock_fallback_wrlock(async_rwlock_t* rwlock)
{
    mutex_lock(&rwlock->fallback_.write_mutex_);
}

int async__rwlock_fallback_trywrlock(async_rwlock_t* rwlock)
{
    return mutex_trylock(&rwlock->fallback_.write_mutex_);
}

void async__rwlock_fallback_wrunlock(async_rwlock_t* rwlock)
{
    mutex_unlock(&rwlock->fallback_.write_mutex_);
}

void async_cond_init(async_cond_t* cond)
{
    if (HAVE_CONDVAR_API()) {
        fn_InitializeConditionVariable(&cond->cond_var);
    }
    else {
        /* This condition variable implementation is based on the SetEvent solution
        * (section 3.2) at http://www.cs.wustl.edu/~schmidt/win32-cv-1.html
        * We could not use the SignalObjectAndWait solution (section 3.4) because
        * it want the 2nd argument (type mutex_t) of async_cond_wait() and
        * async_cond_timedwait() to be HANDLEs, but we use CRITICAL_SECTIONs.
        */
        int err;

        /* Initialize the count to 0. */
        cond->fallback.waiters_count = 0;

        fn_InitializeCriticalSection(&cond->fallback.waiters_count_lock);

        /* Create an auto-reset event. */
        cond->fallback.signal_event = fn_CreateEventW(NULL, FALSE, FALSE, NULL);
        if (!cond->fallback.signal_event) {
            err = fn_GetLastError();
            goto error2;
        }

        /* Create a manual-reset event. */
        cond->fallback.broadcast_event = fn_CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!cond->fallback.broadcast_event) {
            err = fn_GetLastError();
            goto error;
        }

        return;

    error:
        fn_CloseHandle(cond->fallback.signal_event);
    error2:
        fn_DeleteCriticalSection(&cond->fallback.waiters_count_lock);
    }
}

void async_cond_fallback_destroy(async_cond_t* cond)
{
    if (!fn_CloseHandle(cond->fallback.broadcast_event)) {
        LOG(__FUNCTION__": CloseHandle failed with error 0x%08X", fn_GetLastError());
    }
    if (!fn_CloseHandle(cond->fallback.signal_event)) {
        LOG(__FUNCTION__": CloseHandle failed with error 0x%08X", fn_GetLastError());
    }
    fn_DeleteCriticalSection(&cond->fallback.waiters_count_lock);
}

void async_cond_destroy(async_cond_t* cond)
{
    if (!HAVE_CONDVAR_API()) {
        async_cond_fallback_destroy(cond);
    }
}

void async_cond_fallback_signal(async_cond_t* cond)
{
    int have_waiters;

    /* Avoid race conditions. */
    fn_EnterCriticalSection(&cond->fallback.waiters_count_lock);
    have_waiters = cond->fallback.waiters_count > 0;
    fn_LeaveCriticalSection(&cond->fallback.waiters_count_lock);

    if (have_waiters) {
        fn_SetEvent(cond->fallback.signal_event);
    }
}

void async_cond_condvar_signal(async_cond_t* cond)
{
    fn_WakeConditionVariable(&cond->cond_var);
}

void async_cond_signal(async_cond_t* cond)
{
    if (HAVE_CONDVAR_API()) {
        async_cond_condvar_signal(cond);
    }
    else {
        async_cond_fallback_signal(cond);
    }
}

void async_cond_fallback_broadcast(async_cond_t* cond)
{
    int have_waiters;

    /* Avoid race conditions. */
    fn_EnterCriticalSection(&cond->fallback.waiters_count_lock);
    have_waiters = cond->fallback.waiters_count > 0;
    fn_LeaveCriticalSection(&cond->fallback.waiters_count_lock);

    if (have_waiters) {
        fn_SetEvent(cond->fallback.broadcast_event);
    }
}

void async_cond_condvar_broadcast(async_cond_t* cond)
{
    fn_WakeAllConditionVariable(&cond->cond_var);
}

void async_cond_broadcast(async_cond_t* cond)
{
    if (HAVE_CONDVAR_API()) {
        async_cond_condvar_broadcast(cond);
    }
    else {
        async_cond_fallback_broadcast(cond);
    }
}

int async_cond_wait_helper(async_cond_t* cond, mutex_t* mutex, DWORD dwMilliseconds)
{
    DWORD result;
    int last_waiter;
    HANDLE handles[2] = {
        cond->fallback.signal_event,
        cond->fallback.broadcast_event
    };

    /* Avoid race conditions. */
    fn_EnterCriticalSection(&cond->fallback.waiters_count_lock);
    cond->fallback.waiters_count++;
    fn_LeaveCriticalSection(&cond->fallback.waiters_count_lock);

    /* It's ok to release the <mutex> here since Win32 manual-reset events */
    /* maintain state when used with <SetEvent>. This avoids the "lost wakeup" */
    /* bug. */
    mutex_unlock(mutex);

    /* Wait for either event to become signaled due to <async_cond_signal> being */
    /* called or <async_cond_broadcast> being called. */
    result = fn_WaitForMultipleObjects(2, handles, FALSE, dwMilliseconds);

    fn_EnterCriticalSection(&cond->fallback.waiters_count_lock);
    cond->fallback.waiters_count--;
    last_waiter = result == WAIT_OBJECT_0 + 1 && cond->fallback.waiters_count == 0;
    fn_LeaveCriticalSection(&cond->fallback.waiters_count_lock);

    /* Some thread called <pthread_cond_broadcast>. */
    if (last_waiter) {
        /* We're the last waiter to be notified or to stop waiting, so reset the */
        /* the manual-reset event. */
        fn_ResetEvent(cond->fallback.broadcast_event);
    }

    /* Reacquire the <mutex>. */
    mutex_lock(mutex);

    if (result == WAIT_OBJECT_0 || result == WAIT_OBJECT_0 + 1) {
        return 0;
    }

    if (result == WAIT_TIMEOUT) {
        return ASYNC_ETIMEDOUT;
    }

    return -1; /* Satisfy the compiler. */
}

void async_cond_fallback_wait(async_cond_t* cond, mutex_t* mutex)
{
    if (async_cond_wait_helper(cond, mutex, INFINITE)) {
        LOG(__FUNCTION__": async_cond_wait_helper failed");
    }
}


void async_cond_condvar_wait(async_cond_t* cond, mutex_t* mutex)
{
    if (!fn_SleepConditionVariableCS(&cond->cond_var, mutex, INFINITE)) {
        LOG(__FUNCTION__": SleepConditionVariableCS failed with error 0x%08X", fn_GetLastError());
    }
}

void async_cond_wait(async_cond_t* cond, mutex_t* mutex)
{
    if (HAVE_CONDVAR_API()) {
        async_cond_condvar_wait(cond, mutex);
    }
    else {
        async_cond_fallback_wait(cond, mutex);
    }
}

int async_cond_fallback_timedwait(async_cond_t* cond, mutex_t* mutex, uint64_t timeout)
{
    return async_cond_wait_helper(cond, mutex, (DWORD)(timeout / 1e6));
}

int async_cond_condvar_timedwait(async_cond_t* cond, mutex_t* mutex, uint64_t timeout)
{
    if (fn_SleepConditionVariableCS(&cond->cond_var, mutex, (DWORD)(timeout / 1e6))) {
        return 0;
    }
    if (fn_GetLastError() != ERROR_TIMEOUT) {
        LOG(__FUNCTION__": SleepConditionVariableCS failed with error 0x%08X", fn_GetLastError());
    }
    return ASYNC_ETIMEDOUT;
}

int async_cond_timedwait(async_cond_t* cond, mutex_t* mutex, uint64_t timeout)
{
    if (HAVE_CONDVAR_API()) {
        return async_cond_condvar_timedwait(cond, mutex, timeout);
    }
    else {
        return async_cond_fallback_timedwait(cond, mutex, timeout);
    }
}

int async_barrier_init(async_barrier_t* barrier, uint32_t count)
{
    int err;

    barrier->n = count;
    barrier->count = 0;

    mutex_init(&barrier->mutex);

    err = async_sem_init(&barrier->turnstile1, 0);
    if (err) {
        goto error2;
    }

    err = async_sem_init(&barrier->turnstile2, 1);
    if (err) {
        goto error;
    }

    return 0;

error:
    async_sem_destroy(&barrier->turnstile1);
error2:
    mutex_destroy(&barrier->mutex);
    return err;
}

void async_barrier_destroy(async_barrier_t* barrier)
{
    async_sem_destroy(&barrier->turnstile2);
    async_sem_destroy(&barrier->turnstile1);
    mutex_destroy(&barrier->mutex);
}

int async_barrier_wait(async_barrier_t* barrier)
{
    int serial_thread;

    mutex_lock(&barrier->mutex);
    if (++barrier->count == barrier->n) {
        async_sem_wait(&barrier->turnstile2);
        async_sem_post(&barrier->turnstile1);
    }
    mutex_unlock(&barrier->mutex);

    async_sem_wait(&barrier->turnstile1);
    async_sem_post(&barrier->turnstile1);

    mutex_lock(&barrier->mutex);
    serial_thread = (--barrier->count == 0);
    if (serial_thread) {
        async_sem_wait(&barrier->turnstile1);
        async_sem_post(&barrier->turnstile2);
    }
    mutex_unlock(&barrier->mutex);

    async_sem_wait(&barrier->turnstile2);
    async_sem_post(&barrier->turnstile2);
    return serial_thread;
}

int async_key_create(async_key_t* key)
{
    key->tls_index = fn_TlsAlloc();
    if (key->tls_index == TLS_OUT_OF_INDEXES) {
        return ASYNC_ENOMEM;
    }
    return 0;
}

void async_key_delete(async_key_t* key)
{
    if (fn_TlsFree(key->tls_index) == FALSE) {
        LOG(__FUNCTION__": TlsFree faield with error 0x%08X", fn_GetLastError());
    }
    key->tls_index = TLS_OUT_OF_INDEXES;
}

void* async_key_get(async_key_t* key)
{
    void* value;

    value = fn_TlsGetValue(key->tls_index);
    if (value == NULL) {
        if (fn_GetLastError() != ERROR_SUCCESS) {
            LOG(__FUNCTION__": TlsGetValue faield with error 0x%08X", fn_GetLastError());
        }
    }
    return value;
}

void async_key_set(async_key_t* key, void* value)
{
    if (fn_TlsSetValue(key->tls_index, value) == FALSE) {
        LOG(__FUNCTION__": TlsSetValue faield with error 0x%08X", fn_GetLastError());
    }
}
