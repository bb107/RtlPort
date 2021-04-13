// Copyright 2021 Boring
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <RtlWow64\RtlWow64.h>
#include "RtlNative.h"

static decltype(&RtlGetModuleHandleWow64)GetModuleHandleWow64;
static decltype(&RtlGetProcAddressWow64)GetProcAddressWow64;
static decltype(&RtlInvokeX64)InvokeWow64;
static HMODULE hRtlWow64;

// Initialize RtlWow64 library
static bool InitializeRtlWow64() {
    BOOL wow64;
    if (!IsWow64Process(NtCurrentProcess(), &wow64) || !wow64)return true;

    hRtlWow64 = LoadLibrary(L"RtlWow64.dll");
    if (hRtlWow64 != nullptr) {
        GetModuleHandleWow64 = decltype(&RtlGetModuleHandleWow64)(GetProcAddress(hRtlWow64, "RtlGetModuleHandleWow64"));
        GetProcAddressWow64 = decltype(&RtlGetProcAddressWow64)(GetProcAddress(hRtlWow64, "RtlGetProcAddressWow64"));
        InvokeWow64 = decltype(&RtlInvokeX64)(GetProcAddress(hRtlWow64, "RtlInvokeX64"));

        if (GetModuleHandleWow64 && GetProcAddressWow64 && InvokeWow64) {
            return true;
        }
        FreeLibrary(hRtlWow64);
        hRtlWow64 = nullptr;
    }

    return false;
}


// Native x64 port function for Wow64
extern PVOID64 pfnWow64ConnectPort;
extern PVOID64 pfnWow64ListenPort;
extern PVOID64 pfnWow64AcceptConnectPort;
extern PVOID64 pfnWow64RequestPort;
extern PVOID64 pfnWow64RequestWaitReplyPort;
extern PVOID64 pfnWow64ReplyPort;
extern PVOID64 pfnWow64ReplyWaitReplyPort;
extern PVOID64 pfnWow64ReplyWaitReceivePort;
extern PVOID64 pfnWow64ReplyWaitReceivePortEx;
extern PVOID64 pfnWow64ImpersonateClientOfPort;

static bool InitializeWow64Functions() {
    PVOID64 hNtdll;

    if (GetModuleHandleWow64) {
        if (!NT_SUCCESS(GetModuleHandleWow64(&hNtdll, "ntdll.dll")))return false;
        if (!NT_SUCCESS(GetProcAddressWow64(&pfnWow64ConnectPort, hNtdll, "NtConnectPort")))return false;
        if (!NT_SUCCESS(GetProcAddressWow64(&pfnWow64ListenPort, hNtdll, "NtListenPort")))return false;
        if (!NT_SUCCESS(GetProcAddressWow64(&pfnWow64AcceptConnectPort, hNtdll, "NtAcceptConnectPort")))return false;
        if (!NT_SUCCESS(GetProcAddressWow64(&pfnWow64RequestPort, hNtdll, "NtRequestPort")))return false;
        if (!NT_SUCCESS(GetProcAddressWow64(&pfnWow64RequestWaitReplyPort, hNtdll, "NtRequestWaitReplyPort")))return false;
        if (!NT_SUCCESS(GetProcAddressWow64(&pfnWow64ReplyPort, hNtdll, "NtReplyPort")))return false;
        if (!NT_SUCCESS(GetProcAddressWow64(&pfnWow64ReplyWaitReplyPort, hNtdll, "NtReplyWaitReplyPort")))return false;
        if (!NT_SUCCESS(GetProcAddressWow64(&pfnWow64ReplyWaitReceivePort, hNtdll, "NtReplyWaitReceivePort")))return false;
        if (!NT_SUCCESS(GetProcAddressWow64(&pfnWow64ReplyWaitReceivePortEx, hNtdll, "NtReplyWaitReceivePortEx")))return false;
        if (!NT_SUCCESS(GetProcAddressWow64(&pfnWow64ImpersonateClientOfPort, hNtdll, "NtImpersonateClientOfPort")))return false;
    }

    return true;
}

NTSTATUS NTAPI InvokeX64(
    _Out_opt_ PULONG64 Result,
    _In_ PVOID64 FunctionAddress,
    _In_opt_ ULONG64* Parameters,
    _In_ DWORD ParameterCount) {
    return
        InvokeWow64 ?
        InvokeWow64(
            Result,
            FunctionAddress,
            Parameters,
            ParameterCount
        ) :
        STATUS_NOT_SUPPORTED;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        return InitializeRtlWow64() && InitializeWow64Functions();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        if (hRtlWow64)FreeLibrary(hRtlWow64);
        break;
    }
    return TRUE;
}

