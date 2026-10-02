/*
 *   This file is part of Luma3DS
 *   Copyright (C) 2016-2020 Aurora Wright, TuxSH
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *   Additional Terms 7.b and 7.c of GPLv3 apply to this file:
 *       * Requiring preservation of specified reasonable legal notices or
 *         author attributions in that material or in the Appropriate Legal
 *         Notices displayed by works containing it.
 *       * Prohibiting misrepresentation of the origin of that material,
 *         or requiring that modified versions of it be marked in reasonable
 *         ways as different from the original version.
 *
 *   The session loop is adapted from Rosalina's service_manager.c and
 *   errdisp.c for the plg:UDS service.
 */

#include <3ds.h>
#include <string.h>
#include "MyThread.h"
#include "menu.h"
#include "uds_redirect.h"
#include "uds_service.h"

#define UDS_SERVICE_NAME "plg:UDS"
#define UDS_SERVICE_MAX_SESSIONS 4u
#define UDS_SERVICE_FIRST_SESSION_HANDLE 2u
#define UDS_SERVICE_WAIT_HANDLE_COUNT (UDS_SERVICE_FIRST_SESSION_HANDLE + UDS_SERVICE_MAX_SESSIONS)
#define UDS_SERVICE_STACK_SIZE 0x4000u
#define UDS_SESSION_CLOSED ((Result)0xC920181A)

static MyThread s_udsServiceThread;
static u8 s_udsServiceThreadStack[UDS_SERVICE_STACK_SIZE] __attribute__((aligned(8)));
static Handle s_udsStopEvent;
static Handle s_udsServerPort;
static bool s_udsServiceRegistered;
static bool s_udsServiceThreadStarted;
static bool s_udsServiceLifecycleActive;
static volatile bool s_udsStopRequested;
static Result s_udsWorkerResult;

static void UdsService_ResetState(void)
{
    memset(&s_udsServiceThread, 0, sizeof(s_udsServiceThread));
    s_udsStopEvent = 0;
    s_udsServerPort = 0;
    s_udsServiceRegistered = false;
    s_udsServiceThreadStarted = false;
    s_udsServiceLifecycleActive = false;
    s_udsStopRequested = false;
    s_udsWorkerResult = 0;
    __dmb();
}

static bool UdsService_StopWasRequested(void)
{
    __dmb();
    return s_udsStopRequested;
}

static void UdsService_CloseSessionAt(Handle *waitHandles, u32 *numSessions,
                                      u32 sessionOffset)
{
    Handle session = waitHandles[UDS_SERVICE_FIRST_SESSION_HANDLE + sessionOffset];
    for (u32 i = sessionOffset + 1; i < *numSessions; ++i)
        waitHandles[UDS_SERVICE_FIRST_SESSION_HANDLE + i - 1] =
            waitHandles[UDS_SERVICE_FIRST_SESSION_HANDLE + i];

    --*numSessions;
    waitHandles[UDS_SERVICE_FIRST_SESSION_HANDLE + *numSessions] = 0;
    svcCloseHandle(session);
}

static bool UdsService_CloseDisconnectedSession(s32 id, Handle *waitHandles,
                                                u32 *numSessions,
                                                Handle replyTarget)
{
    u32 sessionOffset;
    if (id == -1)
    {
        for (sessionOffset = 0;
             sessionOffset < *numSessions &&
                 waitHandles[UDS_SERVICE_FIRST_SESSION_HANDLE + sessionOffset] != replyTarget;
             ++sessionOffset);
        if (replyTarget == 0 || sessionOffset >= *numSessions)
            return false;
    }
    else
    {
        if (id < (s32)UDS_SERVICE_FIRST_SESSION_HANDLE ||
            (u32)id >= UDS_SERVICE_FIRST_SESSION_HANDLE + *numSessions)
            return false;
        sessionOffset = (u32)id - UDS_SERVICE_FIRST_SESSION_HANDLE;
    }

    UdsService_CloseSessionAt(waitHandles, numSessions, sessionOffset);
    return true;
}

static void UdsService_CloseAllSessions(Handle *waitHandles, u32 *numSessions)
{
    while (*numSessions != 0)
        UdsService_CloseSessionAt(waitHandles, numSessions, *numSessions - 1);
}

static void UdsService_Fatal(Handle *waitHandles, u32 *numSessions, Result error)
{
    UdsService_CloseAllSessions(waitHandles, numSessions);
    s_udsWorkerResult = error;
    svcBreak(USERBREAK_PANIC);
}

static void UdsService_ThreadMain(void)
{
    Handle waitHandles[UDS_SERVICE_WAIT_HANDLE_COUNT] = {0};
    u32 numSessions = 0;
    Handle replyTarget = 0;
    s32 id = -1;
    u32 *cmdbuf = getThreadCommandBuffer();

    waitHandles[0] = s_udsStopEvent;
    waitHandles[1] = s_udsServerPort;
    s_udsWorkerResult = 0;

    while (true)
    {
        if (UdsService_StopWasRequested())
        {
            if (replyTarget != 0)
            {
                Result res = svcReplyAndReceive(&id, waitHandles, 1, replyTarget);
                if ((u32)res == (u32)UDS_SESSION_CLOSED)
                {
                    if (!UdsService_CloseDisconnectedSession(id, waitHandles,
                                                            &numSessions, replyTarget))
                    {
                        UdsService_Fatal(waitHandles, &numSessions, res);
                        return;
                    }
                }
                else if (R_FAILED(res))
                {
                    UdsService_Fatal(waitHandles, &numSessions, res);
                    return;
                }
                else if (id != 0)
                {
                    UdsService_Fatal(waitHandles, &numSessions, (Result)0xD8E007F4);
                    return;
                }
            }
            break;
        }

        if (replyTarget == 0)
            cmdbuf[0] = 0xFFFF0000;

        id = -1;
        Result res = svcReplyAndReceive(&id, waitHandles,
                                        (s32)(UDS_SERVICE_FIRST_SESSION_HANDLE + numSessions),
                                        replyTarget);
        if ((u32)res == (u32)UDS_SESSION_CLOSED)
        {
            if (!UdsService_CloseDisconnectedSession(id, waitHandles,
                                                    &numSessions, replyTarget))
            {
                UdsService_Fatal(waitHandles, &numSessions, res);
                return;
            }
            replyTarget = 0;
            continue;
        }
        if (R_FAILED(res))
        {
            UdsService_Fatal(waitHandles, &numSessions, res);
            return;
        }

        replyTarget = 0;
        if (id == 0)
            break;

        if (id == 1)
        {
            if (UdsService_StopWasRequested())
                break;

            Handle session = 0;
            res = svcAcceptSession(&session, waitHandles[1]);
            if (R_FAILED(res))
            {
                UdsService_Fatal(waitHandles, &numSessions, res);
                return;
            }

            if (numSessions >= UDS_SERVICE_MAX_SESSIONS)
            {
                svcCloseHandle(session);
                continue;
            }

            waitHandles[UDS_SERVICE_FIRST_SESSION_HANDLE + numSessions++] = session;
            continue;
        }

        if (id < (s32)UDS_SERVICE_FIRST_SESSION_HANDLE ||
            (u32)id >= UDS_SERVICE_FIRST_SESSION_HANDLE + numSessions)
        {
            UdsService_Fatal(waitHandles, &numSessions, (Result)0xD8E007F4);
            return;
        }

        UdsRedirect_HandleCommands(NULL);
        replyTarget = waitHandles[id];
    }

    UdsService_CloseAllSessions(waitHandles, &numSessions);
    s_udsWorkerResult = 0;
}

static void UdsService_RollbackStart(void)
{
    if (s_udsServiceRegistered)
    {
        (void)srvUnregisterService(UDS_SERVICE_NAME);
        s_udsServiceRegistered = false;
    }
    if (s_udsServerPort != 0)
    {
        svcCloseHandle(s_udsServerPort);
        s_udsServerPort = 0;
    }
    if (s_udsStopEvent != 0)
    {
        svcCloseHandle(s_udsStopEvent);
        s_udsStopEvent = 0;
    }
    UdsService_ResetState();
}

Result UdsService_Start(void)
{
    if (s_udsServiceLifecycleActive)
        return (Result)0xD8E007F4;

    UdsService_ResetState();
    s_udsServiceLifecycleActive = true;

    Result res = svcCreateEvent(&s_udsStopEvent, RESET_STICKY);
    if (R_FAILED(res))
        goto failure;

    res = srvRegisterService(&s_udsServerPort, UDS_SERVICE_NAME,
                             (s32)UDS_SERVICE_MAX_SESSIONS);
    if (R_FAILED(res))
        goto failure;
    s_udsServiceRegistered = true;

    res = MyThread_Create(&s_udsServiceThread, UdsService_ThreadMain,
                          s_udsServiceThreadStack, UDS_SERVICE_STACK_SIZE,
                          55, CORE_SYSTEM);
    if (R_FAILED(res))
        goto failure;
    s_udsServiceThreadStarted = true;
    return 0;

failure:
    UdsService_RollbackStart();
    return res;
}

Result UdsService_RequestStop(void)
{
    if (!s_udsServiceThreadStarted)
        return 0;

    s_udsStopRequested = true;
    __dmb();
    return svcSignalEvent(s_udsStopEvent);
}

Result UdsService_StopJoin(void)
{
    if (!s_udsServiceLifecycleActive)
        return 0;

    Result res = UdsService_RequestStop();
    Result joinRes = MyThread_Join(&s_udsServiceThread, -1LL);
    if (R_FAILED(joinRes))
        return joinRes;
    s_udsServiceThreadStarted = false;

    if (s_udsServiceRegistered)
    {
        Result unregisterRes = srvUnregisterService(UDS_SERVICE_NAME);
        s_udsServiceRegistered = false;
        if (R_SUCCEEDED(res) && R_FAILED(unregisterRes))
            res = unregisterRes;
    }
    if (s_udsServerPort != 0)
    {
        svcCloseHandle(s_udsServerPort);
        s_udsServerPort = 0;
    }
    if (s_udsStopEvent != 0)
    {
        svcCloseHandle(s_udsStopEvent);
        s_udsStopEvent = 0;
    }

    if (R_SUCCEEDED(res) && R_FAILED(s_udsWorkerResult))
        res = s_udsWorkerResult;
    UdsService_ResetState();
    return res;
}
