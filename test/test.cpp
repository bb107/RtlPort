#include <cstdio>
#include <Windows.h>
#include "../RtlPort/RtlNative.h"
#include "../RtlPort/RtlPort.h"

BYTE Buffer[] = { 0,1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf };

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

        PORT_DATA_ENTRY e{ Buffer,0x10 };
        if (!NT_SUCCESS(RtlWriteRequestData2(pContext, "you look look me!", 18)))break;
        if (!NT_SUCCESS(RtlAddPortDataInformation(pContext, &e)))break;

        if (!NT_SUCCESS(RtlRequestWaitReplyPort(hPort, pContext)))break;

        printf("Client success.\n");

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

        if (!NT_SUCCESS(status = RtlReplyWaitReceivePort(hMessage, FALSE, nullptr, pContext)))break;
        if (4 != RtlMessageDataLength(pContext))break;
        if (*LPDWORD(RtlMessageDataPtr(pContext)) != 0xffeeffee)break;
        if (!NT_SUCCESS(status = RtlWriteReplyData2(pContext, "HelloWorld!", 12)))break;
        if (!NT_SUCCESS(status = RtlReplyPort(hMessage, pContext)))break;

        if (!NT_SUCCESS(status = RtlReplyWaitReceivePort(hMessage, FALSE, nullptr, pContext)))break;
        printf("%s\n", RtlMessageDataPtr(pContext));
        BYTE buf[0x10];
        status = RtlReadRequestData(hMessage, pContext, 0, buf, 0x10, nullptr);

        RtlWriteReplyUlong(pContext, 0);
        status = RtlReplyPort(hMessage, pContext);
        Sleep(1);
    } while (false);

    if (hThread)NtClose(hThread);
    if (hMessage)NtClose(hMessage);
    if (hPort)NtClose(hPort);
    if (pContext)RtlReleasePortMessageContext(pContext);
    return 0;
}
