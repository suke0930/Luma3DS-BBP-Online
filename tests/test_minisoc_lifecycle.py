import re
import subprocess
import tempfile
from pathlib import Path

from _support import ROOT, function_body, read_c


SOURCE = ROOT / "sysmodules/rosalina/source/minisoc.c"


HARNESS_PREFIX = r"""
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef int32_t Result;
typedef int32_t s32;
typedef uint32_t u32;
typedef uint8_t u8;
typedef uint64_t u64;
typedef uint32_t Handle;
typedef pthread_mutex_t RecursiveLock;

#define __LOCK_INITIALIZER_RECURSIVE PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP
#define RecursiveLock_Lock(lock) testRecursiveLockLock(lock)
#define RecursiveLock_Unlock(lock) ((void)pthread_mutex_unlock(lock))
#define AtomicPostIncrement(ptr) testAtomicPostIncrement(ptr)
#define AtomicDecrement(ptr) __atomic_sub_fetch((ptr), 1, __ATOMIC_SEQ_CST)
#define R_FAILED(result) ((result) < 0)
#define R_SUCCEEDED(result) ((result) >= 0)
#define __dmb() __sync_synchronize()

#define MEMOP_ALLOC 1u
#define MEMOP_REGION_SYSTEM 2u
#define MEMOP_FREE 3u
#define MEMPERM_READ 1u
#define MEMPERM_WRITE 2u
#define MEMPERM_DONTCARE 0u
#define NDM_EXCLUSIVE_STATE_INFRASTRUCTURE 1u

static pthread_mutex_t monitorMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t monitorCondition = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t initMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t initCondition = PTHREAD_COND_INITIALIZER;
static unsigned lockAttempts;
static unsigned atomicAttempts;
static unsigned initializeCalls;
static unsigned shutdownCalls;
static unsigned closeCalls;
static unsigned freeCalls;
static unsigned nextHandle = 10;
static bool initializationEntered;
static bool releaseInitialization;
static bool failInitialization;

void testRecursiveLockLock(RecursiveLock *lock)
{
    pthread_mutex_lock(&monitorMutex);
    ++lockAttempts;
    pthread_cond_broadcast(&monitorCondition);
    pthread_mutex_unlock(&monitorMutex);
    (void)pthread_mutex_lock(lock);
}

static s32 testAtomicPostIncrement(s32 *value)
{
    s32 previous = __atomic_fetch_add(value, 1, __ATOMIC_SEQ_CST);
    pthread_mutex_lock(&monitorMutex);
    ++atomicAttempts;
    pthread_cond_broadcast(&monitorCondition);
    pthread_mutex_unlock(&monitorMutex);
    return previous;
}

static bool waitForFlag(pthread_mutex_t *mutex, pthread_cond_t *condition,
                        bool *flag, long timeoutMs)
{
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += timeoutMs / 1000;
    deadline.tv_nsec += (timeoutMs % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L)
    {
        ++deadline.tv_sec;
        deadline.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(mutex);
    int result = 0;
    while (!*flag && result != ETIMEDOUT)
        result = pthread_cond_timedwait(condition, mutex, &deadline);
    bool observed = *flag;
    pthread_mutex_unlock(mutex);
    return observed;
}

static bool waitForSecondAttempt(long timeoutMs)
{
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += timeoutMs / 1000;
    deadline.tv_nsec += (timeoutMs % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L)
    {
        ++deadline.tv_sec;
        deadline.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&monitorMutex);
    int result = 0;
    while (lockAttempts < 2u && atomicAttempts < 2u && result != ETIMEDOUT)
        result = pthread_cond_timedwait(&monitorCondition, &monitorMutex, &deadline);
    bool observed = lockAttempts >= 2u || atomicAttempts >= 2u;
    pthread_mutex_unlock(&monitorMutex);
    return observed;
}

Result miniSocInit(void);
Result miniSocExit(void);
Result miniSocExitDirect(void);
void miniSocLockState(void);
void miniSocUnlockState(bool force);

static Result SOCU_Initialize(Handle memhandle, u32 memsize)
{
    (void)memhandle;
    (void)memsize;
    pthread_mutex_lock(&initMutex);
    ++initializeCalls;
    if (initializeCalls == 1u)
    {
        initializationEntered = true;
        pthread_cond_broadcast(&initCondition);
        while (!releaseInitialization)
            pthread_cond_wait(&initCondition, &initMutex);
    }
    bool fail = failInitialization;
    pthread_mutex_unlock(&initMutex);
    return fail ? -1 : 0;
}

static Result SOCU_Shutdown(void)
{
    ++shutdownCalls;
    return 0;
}

Result srvIsServiceRegistered(bool *registered, const char *name)
{
    (void)name;
    *registered = true;
    return 0;
}

Result srvGetServiceHandle(Handle *handle, const char *name)
{
    (void)name;
    *handle = ++nextHandle;
    return 0;
}

Result svcControlMemoryEx(u32 *out, u32 address, u32 address0, u32 size,
                          u32 operation, u32 permission, bool linear)
{
    (void)address;
    (void)address0;
    (void)size;
    (void)operation;
    (void)permission;
    (void)linear;
    *out = 0x08000000u;
    return 0;
}

Result svcCreateMemoryBlock(Handle *handle, u32 address, u32 size,
                            u32 permission0, u32 permission1)
{
    (void)address;
    (void)size;
    (void)permission0;
    (void)permission1;
    *handle = ++nextHandle;
    return 0;
}

Result svcControlMemory(u32 *out, u32 address, u32 address0, u32 size,
                        u32 operation, u32 permission)
{
    (void)address;
    (void)address0;
    (void)size;
    (void)permission;
    if (operation == MEMOP_FREE) ++freeCalls;
    *out = 0;
    return 0;
}

Result svcCloseHandle(Handle handle)
{
    (void)handle;
    ++closeCalls;
    return 0;
}

void svcKernelSetState(u32 state, u32 value)
{
    (void)state;
    (void)value;
}

bool isServiceUsable(const char *service)
{
    (void)service;
    return false;
}

void ndmuInit(void) {}
void ndmuExit(void) {}
Result NDMU_EnterExclusiveState(u32 state) { (void)state; return 0; }
Result NDMU_LockState(void) { return 0; }
Result NDMU_UnlockState(void) { return 0; }
Result NDMU_LeaveExclusiveState(void) { return 0; }

"""


HARNESS_MAIN = r"""
typedef struct {
    bool autoExit;
    bool started;
    bool finished;
    Result result;
} Worker;

static pthread_mutex_t workerMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t workerCondition = PTHREAD_COND_INITIALIZER;

static void *workerMain(void *argument)
{
    Worker *worker = argument;
    pthread_mutex_lock(&workerMutex);
    worker->started = true;
    pthread_cond_broadcast(&workerCondition);
    pthread_mutex_unlock(&workerMutex);

    Result result = miniSocInit();
    if (result == 0 && worker->autoExit)
        (void)miniSocExit();

    pthread_mutex_lock(&workerMutex);
    worker->result = result;
    worker->finished = true;
    pthread_cond_broadcast(&workerCondition);
    pthread_mutex_unlock(&workerMutex);
    return NULL;
}

static int runScenario(bool fail)
{
    failInitialization = fail;
    Worker first = {.autoExit = false};
    Worker second = {.autoExit = true};
    pthread_t firstThread, secondThread;
    if (pthread_create(&firstThread, NULL, workerMain, &first) != 0)
        return 10;
    if (!waitForFlag(&initMutex, &initCondition, &initializationEntered, 2000))
    {
        pthread_mutex_lock(&initMutex);
        releaseInitialization = true;
        pthread_cond_broadcast(&initCondition);
        pthread_mutex_unlock(&initMutex);
        pthread_join(firstThread, NULL);
        return 11;
    }
    if (pthread_create(&secondThread, NULL, workerMain, &second) != 0)
    {
        pthread_mutex_lock(&initMutex);
        releaseInitialization = true;
        pthread_cond_broadcast(&initCondition);
        pthread_mutex_unlock(&initMutex);
        pthread_join(firstThread, NULL);
        return 12;
    }
    if (!waitForFlag(&workerMutex, &workerCondition, &second.started, 2000))
    {
        pthread_mutex_lock(&initMutex);
        releaseInitialization = true;
        pthread_cond_broadcast(&initCondition);
        pthread_mutex_unlock(&initMutex);
        pthread_join(firstThread, NULL);
        pthread_join(secondThread, NULL);
        return 13;
    }

    bool secondReachedLifecycle = waitForSecondAttempt(2000);
    pthread_mutex_lock(&workerMutex);
    bool finishedBeforeRelease = second.finished;
    pthread_mutex_unlock(&workerMutex);
    pthread_mutex_lock(&monitorMutex);
    unsigned locksBeforeRelease = lockAttempts;
    unsigned incrementsBeforeRelease = atomicAttempts;
    pthread_mutex_unlock(&monitorMutex);

    pthread_mutex_lock(&initMutex);
    releaseInitialization = true;
    pthread_cond_broadcast(&initCondition);
    pthread_mutex_unlock(&initMutex);
    pthread_join(firstThread, NULL);
    pthread_join(secondThread, NULL);

    bool good = secondReachedLifecycle && !finishedBeforeRelease;
    if (fail)
    {
        good = good && first.result < 0 && second.result < 0 &&
               initializeCalls == 2u && miniSocRefCount == 0 &&
               !miniSocEnabled && shutdownCalls == 2u && freeCalls == 2u &&
               closeCalls == 4u && incrementsBeforeRelease == 1u &&
               locksBeforeRelease >= 2u;
    }
    else
    {
        good = good && first.result == 0 && second.result == 0 &&
               initializeCalls == 1u && miniSocRefCount == 1 && miniSocEnabled &&
               incrementsBeforeRelease == 1u && locksBeforeRelease >= 2u;
        if (miniSocEnabled) (void)miniSocExit();
        good = good && miniSocRefCount == 0 && !miniSocEnabled && shutdownCalls == 1u &&
               freeCalls == 1u && closeCalls == 2u;
    }
    if (!good)
        fprintf(stderr,
                "fail=%d early=%d reached=%d init=(%d,%d) calls=%u refs=%d enabled=%d "
                "lock=%u atomic=%u shutdown=%u free=%u close=%u\n",
                fail, finishedBeforeRelease, secondReachedLifecycle,
                first.result, second.result, initializeCalls, miniSocRefCount,
                miniSocEnabled, locksBeforeRelease, incrementsBeforeRelease,
                shutdownCalls, freeCalls, closeCalls);
    return good ? 0 : 20;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    return runScenario(strcmp(argv[1], "failure") == 0);
}
"""


def _build_harness(directory):
    source = read_c(SOURCE)
    state = re.search(
        r"s32\s+miniSocRefCount\s*=\s*0\s*;.*?"
        r"bool\s+miniSocEnabled\s*=\s*false\s*;",
        source,
        re.S,
    )
    assert state is not None
    functions = "\n".join(
        f"Result {name}(void) {{\n{function_body(source, name)}\n}}"
        for name in ("miniSocInit", "miniSocExitDirect", "miniSocExit")
    )
    thread_state = "\n".join(
        f"void {name}(void) {{\n{function_body(source, name)}\n}}"
        for name in ("miniSocLockState",)
    )
    unlock_state = (
        "void miniSocUnlockState(bool force) {\n"
        + function_body(source, "miniSocUnlockState")
        + "\n}"
    )
    generated = "\n".join(
        (HARNESS_PREFIX, state.group(0), thread_state, unlock_state, functions, HARNESS_MAIN)
    )
    c_file = Path(directory) / "minisoc_lifecycle.c"
    binary = Path(directory) / "minisoc_lifecycle"
    c_file.write_text(generated, encoding="utf-8")
    subprocess.run(
        ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-pthread", str(c_file), "-o", str(binary)],
        check=True,
    )
    return binary


def test_minisoc_init_exit_serializes_concurrent_callers_and_failure_cleanup():
    with tempfile.TemporaryDirectory() as directory:
        binary = _build_harness(directory)
        failures = []
        for scenario in ("success", "failure"):
            result = subprocess.run(
                [str(binary), scenario], capture_output=True, text=True, timeout=8
            )
            if result.returncode != 0:
                failures.append(f"{scenario}: {result.stderr.strip()}")
        assert not failures, "miniSoc lifecycle scenarios failed: " + "; ".join(failures)


if __name__ == "__main__":
    test_minisoc_init_exit_serializes_concurrent_callers_and_failure_cleanup()
