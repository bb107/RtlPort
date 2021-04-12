// test.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <cstdio>
#include <Windows.h>
#include "../RtlPort/RtlNative.h"
#include "../RtlPort/RtlPort.h"

DWORD NTAPI ClientThread(PVOID) {
    HANDLE hPort = nullptr;
    PRTL_PORT_MESSAGE_CONTEXT pContext = nullptr;
    BYTE buffer[4] = { 'd','d','d','d' };
    ULONG length = 4;

    do {
        if (!RtlAllocatePortMessageContext(&pContext))break;
        if (!NT_SUCCESS(RtlConnectPortA(&hPort, "BoringBB", buffer, &length, pContext)))break;

        if (!NT_SUCCESS(RtlWriteRequestUlong(pContext, 0xffeeffee)))break;
        if (!NT_SUCCESS(RtlRequestWaitReplyPort(hPort, pContext)))break;
        if (RtlMessageDataLength(pContext) != 12 || strcmp("HelloWorld!", (LPCSTR)RtlMessageDataPtr(pContext)))break;

        if (!NT_SUCCESS(RtlWriteRequestUlong(pContext, 0xccddccdd)))break;
        if (!NT_SUCCESS(RtlRequestWaitReplyPort(hPort, pContext)))break;
        if (RtlMessageDataLength(pContext))break;

        if (!NT_SUCCESS(RtlWriteRequestUlong(pContext, 0x00000000)))break;
        if (!NT_SUCCESS(RtlRequestPort(hPort, pContext)))break;

    } while (false);

    if (hPort)NtClose(hPort);
    if (pContext)RtlReleasePortMessageContext(pContext);
    return 0;
}

int main() {
    HANDLE hPort = nullptr, hMessage = nullptr, hThread = nullptr;
    PRTL_PORT_MESSAGE_CONTEXT pContext = nullptr;
    NTSTATUS status = 0;

    do {
        if (!(hThread = CreateThread(nullptr, 0, ClientThread, nullptr, CREATE_SUSPENDED, nullptr)))break;
        if (!NT_SUCCESS(RtlCreatePortA(&hPort, "BoringBB", FALSE)))break;
        ResumeThread(hThread);
        if (!RtlAllocatePortMessageContext(&pContext))break;
        if (!NT_SUCCESS(RtlListenPort(hPort, pContext)))break;
        if (RtlMessageDataLength(pContext) != 4 || RtlCompareMemory(RtlMessageDataPtr(pContext), "dddd", 4) != 4) {
            RtlAcceptConnectPort(&hMessage, nullptr, FALSE, pContext);
            break;
        }
        if (!NT_SUCCESS(RtlAcceptConnectPort(&hMessage, nullptr, TRUE, pContext)) || !NT_SUCCESS(RtlCompleteConnectPort(hMessage))) break;

        do {
            if (!NT_SUCCESS(status = RtlReplyWaitReceivePort(hMessage, FALSE, nullptr, pContext)))break;
            if (4 != RtlMessageDataLength(pContext))break;
            switch (*LPDWORD(RtlMessageDataPtr(pContext))) {
            case 0xffeeffee: {
                if (!NT_SUCCESS(status = RtlWriteReplyData(pContext, "HelloWorld!", 12)))break;
                if (!NT_SUCCESS(status = RtlReplyPort(hMessage, pContext)))break;
                break;
            }
            case 0xccddccdd: {
                if (!NT_SUCCESS(status = RtlWriteReplyData(pContext, nullptr, 0)))break;
                if (!NT_SUCCESS(status = RtlReplyPort(hMessage, pContext)))break;
                break;
            }
            case 0x00000000: {
                status = 0xC0000000;
                break;
            }
            default: {
                status = 0x80000000;
                break;
            }
            }
        } while (NT_SUCCESS(status));
    } while (false);

    if (hThread)NtClose(hThread);
    if (hMessage)NtClose(hMessage);
    if (hPort)NtClose(hPort);
    if (pContext)RtlReleasePortMessageContext(pContext);
    return 0;
}
