import subprocess
import tempfile
from pathlib import Path

from _support import ROOT


SOURCE = ROOT / "sysmodules/rosalina/source/uds_service.c"
INCLUDE = ROOT / "sysmodules/rosalina/include"


HARNESS = r"""
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <3ds.h>
#include "MyThread.h"
#include "uds_service.h"

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

#define EVENT_HANDLE 0xA1u
#define PORT_HANDLE  0xB1u
#define SESSION_BASE 0xC0u
#define SESSION_CLOSED ((Result)0xC920181A)

typedef struct {
    s32 index;
    Result result;
} Reply;

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_condition = PTHREAD_COND_INITIALIZER;
static pthread_t g_mainThread;
static pthread_t g_serviceThread;
static Reply g_replies[64];
static unsigned g_replyRead;
static unsigned g_replyWrite;
static Handle g_acceptHandles[16];
static unsigned g_acceptRead;
static unsigned g_acceptWrite;
static unsigned g_waitCalls;
static s32 g_waitCounts[64];
static Handle g_waitTargets[64];
static Handle g_waitFirstHandles[64];
static u32 g_replyWords0[64];
static u32 g_replyWords1[64];
static unsigned g_acceptCalls;
static unsigned g_createEventCalls;
static unsigned g_registerCalls;
static unsigned g_unregisterCalls;
static unsigned g_threadCreateCalls;
static unsigned g_threadJoinCalls;
static bool g_unregisteredAfterJoin;
static unsigned g_signalCalls;
static unsigned g_closeMainCalls;
static unsigned g_closeWorkerCalls;
static unsigned g_closeOtherCalls;
static Handle g_closedHandles[32];
static bool g_closedByMain[32];
static unsigned g_closedCount;
static unsigned g_breakCalls;
static u32 g_breakReason;
static bool g_stopSignaled;
static bool g_failCreateEvent;
static bool g_failRegister;
static bool g_failThreadCreate;
static bool g_blockHandler;
static bool g_handlerEntered;
static bool g_releaseHandler;
static bool g_handlerCompleted;
static bool g_holdReplies;
static unsigned g_holdReplyCall;
static unsigned g_handlerCalls;
static bool g_handlerCallerIsWorker;
static bool g_handlerContextIsNull;
static u32 *g_handlerCommandBuffer;
static Result g_threadCreateFailure = -31;
static Result g_eventFailure = -21;
static Result g_registerFailure = -22;

static void *test_thread_main(void *argument);

static struct timespec deadline_after_ms(long milliseconds)
{
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += milliseconds / 1000;
    deadline.tv_nsec += (milliseconds % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        ++deadline.tv_sec;
        deadline.tv_nsec -= 1000000000L;
    }
    return deadline;
}

static bool wait_for_counter(const unsigned *counter, unsigned target)
{
    struct timespec deadline = deadline_after_ms(3000);
    pthread_mutex_lock(&g_mutex);
    int result = 0;
    while (*counter < target && result != ETIMEDOUT)
        result = pthread_cond_timedwait(&g_condition, &g_mutex, &deadline);
    bool reached = *counter >= target;
    pthread_mutex_unlock(&g_mutex);
    return reached;
}

static bool wait_for_handler(bool completed)
{
    struct timespec deadline = deadline_after_ms(3000);
    pthread_mutex_lock(&g_mutex);
    int result = 0;
    bool *flag = completed ? &g_handlerCompleted : &g_handlerEntered;
    while (!*flag && result != ETIMEDOUT)
        result = pthread_cond_timedwait(&g_condition, &g_mutex, &deadline);
    bool reached = *flag;
    pthread_mutex_unlock(&g_mutex);
    return reached;
}

static void queue_reply(s32 index, Result result)
{
    pthread_mutex_lock(&g_mutex);
    g_replies[g_replyWrite++] = (Reply){.index = index, .result = result};
    pthread_cond_broadcast(&g_condition);
    pthread_mutex_unlock(&g_mutex);
}

static void queue_accept(Handle handle)
{
    pthread_mutex_lock(&g_mutex);
    g_acceptHandles[g_acceptWrite++] = handle;
    pthread_mutex_unlock(&g_mutex);
}

static bool was_closed(Handle handle, bool byMain)
{
    bool ownerMatched = false;
    pthread_mutex_lock(&g_mutex);
    for (unsigned i = 0; i < g_closedCount; ++i)
        if (g_closedHandles[i] == handle && g_closedByMain[i] == byMain)
            ownerMatched = true;
    pthread_mutex_unlock(&g_mutex);
    return ownerMatched;
}

static int check_main_owned_cleanup(void)
{
    CHECK(g_unregisterCalls == 1);
    CHECK(g_closeMainCalls == 2);
    CHECK(g_closeOtherCalls == 0);
    CHECK(g_unregisteredAfterJoin);
    CHECK(was_closed(PORT_HANDLE, true));
    CHECK(was_closed(EVENT_HANDLE, true));
    return 0;
}

Result svcCreateEvent(Handle *event, int resetType)
{
    pthread_mutex_lock(&g_mutex);
    ++g_createEventCalls;
    pthread_mutex_unlock(&g_mutex);
    if (g_failCreateEvent) return g_eventFailure;
    if (resetType != RESET_STICKY) return -90;
    *event = EVENT_HANDLE;
    return 0;
}

Result srvRegisterService(Handle *port, const char *name, s32 maxSessions)
{
    pthread_mutex_lock(&g_mutex);
    ++g_registerCalls;
    bool callerIsMain = pthread_equal(pthread_self(), g_mainThread);
    pthread_mutex_unlock(&g_mutex);
    if (!callerIsMain || strcmp(name, "plg:UDS") != 0 || maxSessions != 4)
        return -91;
    if (g_failRegister) return g_registerFailure;
    *port = PORT_HANDLE;
    return 0;
}

Result srvUnregisterService(const char *name)
{
    pthread_mutex_lock(&g_mutex);
    ++g_unregisterCalls;
    g_unregisteredAfterJoin = g_threadJoinCalls != 0;
    bool callerIsMain = pthread_equal(pthread_self(), g_mainThread);
    pthread_mutex_unlock(&g_mutex);
    if (!callerIsMain || strcmp(name, "plg:UDS") != 0) return -92;
    return 0;
}

Result svcSignalEvent(Handle event)
{
    pthread_mutex_lock(&g_mutex);
    ++g_signalCalls;
    bool callerIsMain = pthread_equal(pthread_self(), g_mainThread);
    if (event == EVENT_HANDLE && callerIsMain) g_stopSignaled = true;
    pthread_cond_broadcast(&g_condition);
    pthread_mutex_unlock(&g_mutex);
    return event == EVENT_HANDLE && callerIsMain ? 0 : -93;
}

Result svcCloseHandle(Handle handle)
{
    pthread_mutex_lock(&g_mutex);
    if (g_closedCount < sizeof(g_closedHandles) / sizeof(g_closedHandles[0])) {
        g_closedHandles[g_closedCount++] = handle;
        g_closedByMain[g_closedCount - 1] = pthread_equal(pthread_self(), g_mainThread);
    }
    if (pthread_equal(pthread_self(), g_mainThread)) ++g_closeMainCalls;
    else if (pthread_equal(pthread_self(), g_serviceThread)) ++g_closeWorkerCalls;
    else ++g_closeOtherCalls;
    pthread_cond_broadcast(&g_condition);
    pthread_mutex_unlock(&g_mutex);
    return 0;
}

Result svcAcceptSession(Handle *session, Handle port)
{
    pthread_mutex_lock(&g_mutex);
    ++g_acceptCalls;
    bool callerIsWorker = pthread_equal(pthread_self(), g_serviceThread);
    if (g_acceptRead >= g_acceptWrite) {
        pthread_mutex_unlock(&g_mutex);
        return -94;
    }
    *session = g_acceptHandles[g_acceptRead++];
    pthread_cond_broadcast(&g_condition);
    pthread_mutex_unlock(&g_mutex);
    return callerIsWorker && port == PORT_HANDLE ? 0 : -95;
}

Result svcReplyAndReceive(s32 *index, Handle *handles, s32 handleCount,
                          Handle replyTarget)
{
    pthread_mutex_lock(&g_mutex);
    unsigned call = ++g_waitCalls;
    if (call >= sizeof(g_waitCounts) / sizeof(g_waitCounts[0])) {
        pthread_mutex_unlock(&g_mutex);
        return -96;
    }
    g_waitCounts[call] = handleCount;
    g_waitTargets[call] = replyTarget;
    g_waitFirstHandles[call] = handles[0];
    u32 *cmdbuf = getThreadCommandBuffer();
    if (replyTarget != 0) {
        g_replyWords0[call] = cmdbuf[0];
        g_replyWords1[call] = cmdbuf[1];
    }
    bool callerIsWorker = pthread_equal(pthread_self(), g_serviceThread);
    pthread_cond_broadcast(&g_condition);

    struct timespec deadline = deadline_after_ms(3000);
    int waitResult = 0;
    while (g_holdReplies && call == g_holdReplyCall && waitResult != ETIMEDOUT)
        waitResult = pthread_cond_timedwait(&g_condition, &g_mutex, &deadline);
    waitResult = 0;
    while (g_replyRead == g_replyWrite &&
           !(g_stopSignaled && handleCount > 0 && handles[0] == EVENT_HANDLE) &&
           waitResult != ETIMEDOUT)
        waitResult = pthread_cond_timedwait(&g_condition, &g_mutex, &deadline);
    if (!callerIsWorker) {
        pthread_mutex_unlock(&g_mutex);
        return -97;
    }
    if (g_replyRead < g_replyWrite) {
        Reply reply = g_replies[g_replyRead++];
        *index = reply.index;
        if (reply.result == 0 && reply.index >= 2) {
            cmdbuf[0] = 0x000F0000u;
            cmdbuf[1] = 0;
        }
        pthread_mutex_unlock(&g_mutex);
        return reply.result;
    }
    if (g_stopSignaled && handleCount > 0 && handles[0] == EVENT_HANDLE) {
        *index = 0;
        pthread_mutex_unlock(&g_mutex);
        return 0;
    }
    pthread_mutex_unlock(&g_mutex);
    return -98;
}

u32 *getThreadCommandBuffer(void)
{
    static __thread u32 commandBuffer[64];
    return commandBuffer;
}

void svcBreak(u32 reason)
{
    pthread_mutex_lock(&g_mutex);
    ++g_breakCalls;
    g_breakReason = reason;
    pthread_cond_broadcast(&g_condition);
    pthread_mutex_unlock(&g_mutex);
}

Result MyThread_Create(MyThread *thread, void (*entrypoint)(void), void *stack,
                       u32 stackSize, int priority, int affinity)
{
    (void)stack;
    (void)stackSize;
    (void)priority;
    (void)affinity;
    pthread_mutex_lock(&g_mutex);
    ++g_threadCreateCalls;
    pthread_mutex_unlock(&g_mutex);
    if (g_failThreadCreate) return g_threadCreateFailure;
    thread->entrypoint = entrypoint;
    thread->created = true;
    if (pthread_create(&thread->native, NULL, test_thread_main, thread) != 0)
        return -99;
    return 0;
}

Result MyThread_Join(MyThread *thread, s64 timeoutNs)
{
    (void)timeoutNs;
    pthread_mutex_lock(&g_mutex);
    ++g_threadJoinCalls;
    pthread_mutex_unlock(&g_mutex);
    if (!thread->created) return 0;
    int result = pthread_join(thread->native, NULL);
    if (result == 0) thread->created = false;
    return result == 0 ? 0 : -100;
}

static void *test_thread_main(void *argument)
{
    MyThread *thread = argument;
    pthread_mutex_lock(&g_mutex);
    g_serviceThread = pthread_self();
    pthread_cond_broadcast(&g_condition);
    pthread_mutex_unlock(&g_mutex);
    thread->entrypoint();
    return NULL;
}

void UdsRedirect_HandleCommands(void *context)
{
    pthread_mutex_lock(&g_mutex);
    ++g_handlerCalls;
    g_handlerCallerIsWorker = pthread_equal(pthread_self(), g_serviceThread);
    g_handlerContextIsNull = context == NULL;
    g_handlerCommandBuffer = getThreadCommandBuffer();
    g_handlerEntered = true;
    pthread_cond_broadcast(&g_condition);
    while (g_blockHandler && !g_releaseHandler)
        pthread_cond_wait(&g_condition, &g_mutex);
    g_handlerCommandBuffer[1] = 0xBEEFu;
    g_handlerCompleted = true;
    pthread_cond_broadcast(&g_condition);
    pthread_mutex_unlock(&g_mutex);
}

static int accept_one(Handle session, unsigned nextWaitCall)
{
    queue_accept(session);
    queue_reply(1, 0);
    return wait_for_counter(&g_waitCalls, nextWaitCall) ? 0 : 10;
}

static int run_startup_failures(void)
{
    g_failCreateEvent = true;
    CHECK(UdsService_Start() == g_eventFailure);
    CHECK(g_createEventCalls == 1 && g_registerCalls == 0 && g_threadCreateCalls == 0);
    CHECK(g_closeMainCalls == 0 && g_unregisterCalls == 0);

    g_failCreateEvent = false;
    g_failRegister = true;
    CHECK(UdsService_Start() == g_registerFailure);
    CHECK(g_createEventCalls == 2 && g_registerCalls == 1 && g_threadCreateCalls == 0);
    CHECK(g_closeMainCalls == 1 && g_unregisterCalls == 0);

    g_failRegister = false;
    g_failThreadCreate = true;
    CHECK(UdsService_Start() == g_threadCreateFailure);
    CHECK(g_createEventCalls == 3 && g_registerCalls == 2 && g_threadCreateCalls == 1);
    CHECK(g_closeMainCalls == 3 && g_unregisterCalls == 1);
    CHECK(g_closeOtherCalls == 0);
    return 0;
}

static int run_stop_only(void)
{
    CHECK(UdsService_Start() == 0);
    CHECK(wait_for_counter(&g_waitCalls, 1));
    CHECK(g_waitCounts[1] == 2 && g_waitTargets[1] == 0);
    CHECK(UdsService_RequestStop() == 0);
    CHECK(UdsService_StopJoin() == 0);
    CHECK(g_signalCalls == 2);
    CHECK(g_waitCounts[1] == 2);
    CHECK(check_main_owned_cleanup() == 0);
    CHECK(g_closeWorkerCalls == 0 && g_closeOtherCalls == 0);
    return 0;
}

static int run_command_then_stop(void)
{
    g_blockHandler = true;
    CHECK(UdsService_Start() == 0);
    CHECK(wait_for_counter(&g_waitCalls, 1));
    CHECK(accept_one(SESSION_BASE + 1u, 2) == 0);
    queue_reply(2, 0);
    CHECK(wait_for_handler(false));

    struct timespec before, after;
    clock_gettime(CLOCK_MONOTONIC, &before);
    CHECK(UdsService_RequestStop() == 0);
    clock_gettime(CLOCK_MONOTONIC, &after);
    long elapsedMs = (after.tv_sec - before.tv_sec) * 1000L +
                     (after.tv_nsec - before.tv_nsec) / 1000000L;
    CHECK(elapsedMs < 200);
    pthread_mutex_lock(&g_mutex);
    bool handlerStillBlocked = !g_handlerCompleted;
    pthread_mutex_unlock(&g_mutex);
    CHECK(handlerStillBlocked);

    pthread_mutex_lock(&g_mutex);
    g_releaseHandler = true;
    pthread_cond_broadcast(&g_condition);
    pthread_mutex_unlock(&g_mutex);
    CHECK(wait_for_handler(true));
    CHECK(wait_for_counter(&g_waitCalls, 3));
    CHECK(g_handlerCalls == 1 && g_handlerCallerIsWorker && g_handlerContextIsNull);
    CHECK(g_handlerCommandBuffer != NULL);
    CHECK(g_waitCounts[3] == 1);
    CHECK(g_waitFirstHandles[3] == EVENT_HANDLE);
    CHECK(g_waitTargets[3] == SESSION_BASE + 1u);
    CHECK(g_replyWords1[3] == 0xBEEFu);
    CHECK(UdsService_StopJoin() == 0);
    CHECK(check_main_owned_cleanup() == 0);
    CHECK(g_closeWorkerCalls == 1 && was_closed(SESSION_BASE + 1u, false));
    CHECK(g_closeOtherCalls == 0);
    return 0;
}

static int run_session_cap(void)
{
    CHECK(UdsService_Start() == 0);
    CHECK(wait_for_counter(&g_waitCalls, 1));
    for (unsigned i = 0; i < 5; ++i)
        CHECK(accept_one(SESSION_BASE + i + 1u, i + 2u) == 0);
    CHECK(g_acceptCalls == 5);
    CHECK(g_waitCounts[6] == 6);
    CHECK(g_waitTargets[6] == 0);
    CHECK(g_closeWorkerCalls == 1 && was_closed(SESSION_BASE + 5u, false));
    CHECK(UdsService_StopJoin() == 0);
    CHECK(g_closeWorkerCalls == 5);
    CHECK(check_main_owned_cleanup() == 0);
    CHECK(g_closeOtherCalls == 0);
    return 0;
}

static int run_closed_reply_target(void)
{
    CHECK(UdsService_Start() == 0);
    CHECK(wait_for_counter(&g_waitCalls, 1));
    CHECK(accept_one(SESSION_BASE + 1u, 2) == 0);
    queue_reply(2, 0);
    CHECK(wait_for_counter(&g_waitCalls, 3));
    CHECK(g_waitTargets[3] == SESSION_BASE + 1u && g_waitCounts[3] == 3);
    queue_reply(-1, SESSION_CLOSED);
    CHECK(wait_for_counter(&g_waitCalls, 4));
    CHECK(g_waitCounts[4] == 2 && g_waitTargets[4] == 0);
    CHECK(g_closeWorkerCalls == 1 && was_closed(SESSION_BASE + 1u, false));
    CHECK(UdsService_StopJoin() == 0);
    CHECK(g_closeWorkerCalls == 1);
    CHECK(check_main_owned_cleanup() == 0);
    return 0;
}

static int run_closed_actual_index(void)
{
    CHECK(UdsService_Start() == 0);
    CHECK(wait_for_counter(&g_waitCalls, 1));
    CHECK(accept_one(SESSION_BASE + 1u, 2) == 0);
    CHECK(accept_one(SESSION_BASE + 2u, 3) == 0);
    queue_reply(3, SESSION_CLOSED);
    CHECK(wait_for_counter(&g_waitCalls, 4));
    CHECK(g_waitCounts[4] == 3);
    CHECK(g_closeWorkerCalls == 1 && was_closed(SESSION_BASE + 2u, false));
    CHECK(UdsService_StopJoin() == 0);
    CHECK(g_closeWorkerCalls == 2 && was_closed(SESSION_BASE + 1u, false));
    CHECK(check_main_owned_cleanup() == 0);
    return 0;
}

static int run_command_wins_stop_race(void)
{
    CHECK(UdsService_Start() == 0);
    CHECK(wait_for_counter(&g_waitCalls, 1));
    pthread_mutex_lock(&g_mutex);
    g_holdReplies = true;
    g_holdReplyCall = 2;
    pthread_mutex_unlock(&g_mutex);
    CHECK(accept_one(SESSION_BASE + 1u, 2) == 0);
    CHECK(UdsService_RequestStop() == 0);
    queue_reply(2, 0);
    pthread_mutex_lock(&g_mutex);
    g_holdReplies = false;
    pthread_cond_broadcast(&g_condition);
    pthread_mutex_unlock(&g_mutex);
    CHECK(wait_for_handler(true));
    CHECK(wait_for_counter(&g_waitCalls, 3));
    CHECK(g_waitCounts[3] == 1 && g_waitTargets[3] == SESSION_BASE + 1u);
    CHECK(g_replyWords1[3] == 0xBEEFu);
    CHECK(UdsService_StopJoin() == 0);
    CHECK(g_handlerCalls == 1 && g_closeWorkerCalls == 1);
    CHECK(check_main_owned_cleanup() == 0);
    return 0;
}

static int run_unexpected_error(void)
{
    CHECK(UdsService_Start() == 0);
    CHECK(wait_for_counter(&g_waitCalls, 1));
    queue_reply(0, -77);
    CHECK(wait_for_counter(&g_breakCalls, 1));
    CHECK(g_breakReason == USERBREAK_PANIC);
    CHECK(UdsService_StopJoin() == -77);
    CHECK(g_threadJoinCalls == 1);
    CHECK(check_main_owned_cleanup() == 0);
    CHECK(g_closeWorkerCalls == 0 && g_closeOtherCalls == 0);
    return 0;
}

int main(int argc, char **argv)
{
    g_mainThread = pthread_self();
    if (argc != 2) return 2;
    if (strcmp(argv[1], "startup") == 0) return run_startup_failures();
    if (strcmp(argv[1], "stop-only") == 0) return run_stop_only();
    if (strcmp(argv[1], "command-stop") == 0) return run_command_then_stop();
    if (strcmp(argv[1], "cap") == 0) return run_session_cap();
    if (strcmp(argv[1], "closed-reply") == 0) return run_closed_reply_target();
    if (strcmp(argv[1], "closed-index") == 0) return run_closed_actual_index();
    if (strcmp(argv[1], "race") == 0) return run_command_wins_stop_race();
    if (strcmp(argv[1], "unexpected") == 0) return run_unexpected_error();
    return 3;
}
"""


def _write_stubs(stub_root: Path) -> None:
    types_dir = stub_root / "3ds"
    types_dir.mkdir(parents=True)
    (types_dir / "types.h").write_text(
        "#include <stdbool.h>\n#include <stdint.h>\n"
        "typedef int8_t s8; typedef int16_t s16; typedef int32_t s32; typedef int64_t s64;\n"
        "typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;\n"
        "typedef uint32_t Handle; typedef int32_t Result;\n",
        encoding="utf-8",
    )
    (types_dir / "result.h").write_text('#include "types.h"\n', encoding="utf-8")
    (stub_root / "3ds.h").write_text(
        '#include "3ds/types.h"\n'
        "#define RESET_STICKY 2\n#define USERBREAK_PANIC 0x100u\n"
        "#define R_FAILED(result) ((Result)(result) < 0)\n"
        "#define R_SUCCEEDED(result) ((Result)(result) >= 0)\n"
        "#define __dmb() __sync_synchronize()\n"
        "Result svcCreateEvent(Handle *, int); Result svcSignalEvent(Handle);\n"
        "Result svcCloseHandle(Handle); Result svcAcceptSession(Handle *, Handle);\n"
        "Result svcReplyAndReceive(s32 *, Handle *, s32, Handle); void svcBreak(u32);\n"
        "Result srvRegisterService(Handle *, const char *, s32);\n"
        "Result srvUnregisterService(const char *); u32 *getThreadCommandBuffer(void);\n",
        encoding="utf-8",
    )
    (stub_root / "MyThread.h").write_text(
        '#include "3ds/types.h"\n#include <pthread.h>\n'
        "typedef struct { pthread_t native; void (*entrypoint)(void); bool created; } MyThread;\n"
        "Result MyThread_Create(MyThread *, void (*)(void), void *, u32, int, int);\n"
        "Result MyThread_Join(MyThread *, s64);\n",
        encoding="utf-8",
    )
    (stub_root / "menu.h").write_text("#define CORE_SYSTEM 1\n", encoding="utf-8")


def test_dedicated_uds_service_lifecycle_and_session_loop():
    assert SOURCE.is_file(), "the dedicated plg:UDS service implementation is missing"
    with tempfile.TemporaryDirectory() as directory:
        temp = Path(directory)
        stubs = temp / "stubs"
        stubs.mkdir()
        _write_stubs(stubs)
        harness = temp / "uds_service_harness.c"
        executable = temp / "uds_service_harness"
        harness.write_text(HARNESS, encoding="utf-8")
        subprocess.run(
            [
                "cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-pthread",
                "-I", str(stubs), "-I", str(INCLUDE), str(SOURCE), str(harness),
                "-o", str(executable),
            ],
            check=True,
        )
        for scenario in (
            "startup", "stop-only", "command-stop", "cap", "closed-reply",
            "closed-index", "race", "unexpected",
        ):
            subprocess.run([str(executable), scenario], check=True, timeout=8)


if __name__ == "__main__":
    test_dedicated_uds_service_lifecycle_and_session_loop()
