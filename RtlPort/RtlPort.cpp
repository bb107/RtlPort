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

#include <cstdio>
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>
#include "RtlNative.h"
#include "ntpebteb.h"
#include "RtlPort.h"

#pragma warning(disable: 4244)

NTSTATUS NTAPI InvokeX64(
	_Out_opt_ PULONG64 Result,
	_In_ PVOID64 FunctionAddress,
	_In_opt_ ULONG64* Parameters,
	_In_ DWORD ParameterCount
);

PVOID64 pfnWow64ConnectPort;
PVOID64 pfnWow64ListenPort;
PVOID64 pfnWow64AcceptConnectPort;
PVOID64 pfnWow64RequestPort;
PVOID64 pfnWow64RequestWaitReplyPort;
PVOID64 pfnWow64ReplyPort;
PVOID64 pfnWow64ReplyWaitReplyPort;
PVOID64 pfnWow64ReplyWaitReceivePort;
PVOID64 pfnWow64ReplyWaitReceivePortEx;
PVOID64 pfnWow64ImpersonateClientOfPort;


NTSTATUS NTAPI Wow64ConnectPort(
	_Out_ PHANDLE64 PortHandle,
	_In_ PUNICODE_STRING64 PortName,
	_In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos,
	_Inout_opt_ PPORT_VIEW64 ClientView,
	_Inout_opt_ PREMOTE_PORT_VIEW64 ServerView,
	_Out_opt_ PULONG MaxMessageLength,
	_Inout_updates_bytes_to_opt_(*ConnectionInformationLength, *ConnectionInformationLength) PVOID ConnectionInformation,
	_Inout_opt_ PULONG ConnectionInformationLength) {
	ULONG64 result;
	ULONG64 parameters[]{
		ULONG64(PortHandle),ULONG64(PortName),ULONG64(SecurityQos),ULONG64(ClientView),
		ULONG64(ServerView), ULONG64(MaxMessageLength),ULONG64(ConnectionInformation),ULONG64(ConnectionInformationLength)
	};

	InvokeX64(&result, pfnWow64ConnectPort, parameters, sizeof(parameters) / sizeof(ULONG64));
	return NTSTATUS(result);
}

NTSTATUS NTAPI Wow64ListenPort(
	_In_ HANDLE64 PortHandle,
	_Out_ PPORT_MESSAGE64 ConnectionRequest) {
	ULONG64 result;
	ULONG64 parameters[]{ULONG64(PortHandle),ULONG64(ConnectionRequest)};

	InvokeX64(&result, pfnWow64ListenPort, parameters, sizeof(parameters) / sizeof(ULONG64));
	return NTSTATUS(result);
}

NTSTATUS NTAPI Wow64AcceptConnectPort(
	_Out_ PHANDLE64 PortHandle,
	_In_opt_ PVOID PortContext,
	_In_ PPORT_MESSAGE64 ConnectionRequest,
	_In_ BOOLEAN AcceptConnection,
	_Inout_opt_ PPORT_VIEW64 ServerView,
	_Out_opt_ PREMOTE_PORT_VIEW64 ClientView) {
	ULONG64 result;
	ULONG64 parameters[]{ ULONG64(PortHandle),ULONG64(PortContext),ULONG64(ConnectionRequest),ULONG64(AcceptConnection),ULONG64(ServerView),ULONG64(ClientView) };

	InvokeX64(&result, pfnWow64AcceptConnectPort, parameters, sizeof(parameters) / sizeof(ULONG64));
	return NTSTATUS(result);
}

NTSTATUS NTAPI Wow64RequestPort(
	_In_ HANDLE64 PortHandle,
	_In_reads_bytes_(RequestMessage->u1.s1.TotalLength) PPORT_MESSAGE64 RequestMessage) {
	ULONG64 result;
	ULONG64 parameters[]{ ULONG64(PortHandle),ULONG64(RequestMessage) };

	InvokeX64(&result, pfnWow64RequestPort, parameters, sizeof(parameters) / sizeof(ULONG64));
	return NTSTATUS(result);
}

NTSTATUS NTAPI Wow64RequestWaitReplyPort(
	_In_ HANDLE64 PortHandle,
	_In_reads_bytes_(RequestMessage->u1.s1.TotalLength) PPORT_MESSAGE64 RequestMessage,
	_Out_ PPORT_MESSAGE64 ReplyMessage) {
	ULONG64 result;
	ULONG64 parameters[]{ ULONG64(PortHandle),ULONG64(RequestMessage),ULONG64(ReplyMessage) };

	InvokeX64(&result, pfnWow64RequestWaitReplyPort, parameters, sizeof(parameters) / sizeof(ULONG64));
	return NTSTATUS(result);
}

NTSTATUS NTAPI Wow64ReplyPort(
	_In_ HANDLE64 PortHandle,
	_In_reads_bytes_(ReplyMessage->u1.s1.TotalLength) PPORT_MESSAGE64 ReplyMessage) {
	ULONG64 result;
	ULONG64 parameters[]{ ULONG64(PortHandle),ULONG64(ReplyMessage) };

	InvokeX64(&result, pfnWow64ReplyPort, parameters, sizeof(parameters) / sizeof(ULONG64));
	return NTSTATUS(result);
}

NTSTATUS NTAPI Wow64ReplyWaitReplyPort(
	_In_ HANDLE64 PortHandle,
	_Inout_ PPORT_MESSAGE64 ReplyMessage) {
	ULONG64 result;
	ULONG64 parameters[]{ ULONG64(PortHandle),ULONG64(ReplyMessage) };

	InvokeX64(&result, pfnWow64ReplyWaitReplyPort, parameters, sizeof(parameters) / sizeof(ULONG64));
	return NTSTATUS(result);
}

NTSTATUS NTAPI Wow64ReplyWaitReceivePort(
	_In_ HANDLE64 PortHandle,
	_Out_opt_ PVOID* PortContext,
	_In_reads_bytes_opt_(ReplyMessage->u1.s1.TotalLength) PPORT_MESSAGE64 ReplyMessage,
	_Out_ PPORT_MESSAGE64 ReceiveMessage) {
	ULONG64 result;
	ULONG64 parameters[]{ ULONG64(PortHandle),ULONG64(PortContext),ULONG64(ReplyMessage),ULONG64(ReceiveMessage) };

	InvokeX64(&result, pfnWow64ReplyWaitReceivePort, parameters, sizeof(parameters) / sizeof(ULONG64));
	return NTSTATUS(result);
}

NTSTATUS NTAPI Wow64ReplyWaitReceivePortEx(
	_In_ HANDLE64 PortHandle,
	_Out_opt_ PVOID* PortContext,
	_In_reads_bytes_opt_(ReplyMessage->u1.s1.TotalLength) PPORT_MESSAGE64 ReplyMessage,
	_Out_ PPORT_MESSAGE64 ReceiveMessage,
	_In_opt_ PLARGE_INTEGER Timeout) {
	ULONG64 result;
	ULONG64 parameters[]{ ULONG64(PortHandle),ULONG64(PortContext),ULONG64(ReplyMessage),ULONG64(ReceiveMessage),ULONG64(Timeout) };

	InvokeX64(&result, pfnWow64ReplyWaitReceivePortEx, parameters, sizeof(parameters) / sizeof(ULONG64));
	return NTSTATUS(result);
}

NTSTATUS NTAPI Wow64ImpersonateClientOfPort(
	_In_ HANDLE64 PortHandle,
	_In_ PPORT_MESSAGE64 Message) {
	ULONG64 result;
	ULONG64 parameters[]{ ULONG64(PortHandle),ULONG64(Message) };

	InvokeX64(&result, pfnWow64ImpersonateClientOfPort, parameters, sizeof(parameters) / sizeof(ULONG64));
	return NTSTATUS(result);
}

//priv
BOOLEAN NTAPI RtlpIsWow64Process() {
	static BOOLEAN _IsWow64Process = []() ->BOOLEAN {
		ULONG_PTR result = 0;
		NtQueryInformationProcess(NtCurrentProcess(), PROCESSINFOCLASS::ProcessWow64Information, &result, sizeof(result), 0);
		return result != 0;
	}();
	return _IsWow64Process;
}


NTSTATUS NTAPI RtlCreatePortA(
	_Out_ PHANDLE PortHandle,
	_In_z_ LPCSTR PortName,
	_In_ BOOLEAN Waitable) {
	*PortHandle = nullptr;
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING uPortName{}, uSrc{};

	ANSI_STRING aName{};
	RtlInitAnsiString(&aName, PortName);
	uPortName.MaximumLength = 2 * (14 + aName.Length);
	uPortName.Buffer = new wchar_t[uPortName.MaximumLength / 2];
	RtlAppendUnicodeToString(&uPortName, L"\\RPC Control\\");
	if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&uSrc, &aName, TRUE)) ||
		!NT_SUCCESS(RtlAppendUnicodeStringToString(&uPortName, &uSrc))) {
		delete[]uPortName.Buffer;
		return STATUS_NO_MEMORY;
	}
	RtlFreeUnicodeString(&uSrc);

	status = RtlpCreatePort_U(PortHandle, &uPortName, Waitable);
	delete[]uPortName.Buffer;
	return status;
}

NTSTATUS NTAPI RtlCreatePortW(
	_Out_ PHANDLE PortHandle,
	_In_z_ LPCWSTR PortName,
	_In_ BOOLEAN Waitable) {
	*PortHandle = nullptr;
	NTSTATUS status;
	UNICODE_STRING uPortName{}, uSrc{};

	RtlInitUnicodeString(&uSrc, PortName);
	uPortName.MaximumLength = uSrc.Length + 28;
	uPortName.Buffer = (LPWSTR)new char[uPortName.MaximumLength];
	if (!NT_SUCCESS(RtlAppendUnicodeToString(&uPortName, L"\\RPC Control\\")) ||
		!NT_SUCCESS(RtlAppendUnicodeStringToString(&uPortName, &uSrc)))
		return STATUS_NO_MEMORY;

	status = RtlpCreatePort_U(PortHandle, &uPortName, Waitable);

	delete[]uPortName.Buffer;
	return status;
}

//priv
NTSTATUS NTAPI RtlpCreatePort_U(
	_Out_ PHANDLE PortHandle,
	_In_ PUNICODE_STRING PortName,
	_In_ BOOLEAN Waitable) {
	*PortHandle = nullptr;
	OBJECT_ATTRIBUTES oa{ sizeof(oa) };
	const ULONG ulMaxMessageSize = LPCP_MAX_MESSAGE_SIZE - FIELD_OFFSET(LPCP_MESSAGE, Request),
		ulMaxConnectionSize = ulMaxMessageSize - sizeof(PORT_MESSAGE) - sizeof(LPCP_CONNECTION_MESSAGE);
	InitializeObjectAttributes(&oa, PortName, 0, nullptr, nullptr);
	return (Waitable ? NtCreateWaitablePort : NtCreatePort)(PortHandle, &oa, ulMaxConnectionSize, ulMaxMessageSize, 0);
}

NTSTATUS NTAPI RtlConnectPortA(
	_Out_ PHANDLE PortHandle,
	_In_z_ LPCSTR PortName,
	_Inout_updates_bytes_to_opt_(*ConnectionInformationLength, *ConnectionInformationLength) PVOID ConnectionInformation,
	_Inout_opt_ PULONG ConnectionInformationLength,
	_Inout_ PRTL_PORT_MESSAGE_CONTEXT pMessageContext) {
	UNICODE_STRING uPortName{}, uSrc{};
	NTSTATUS status;

	ANSI_STRING aName{};
	RtlInitAnsiString(&aName, PortName);
	uPortName.Buffer = new wchar_t[14ull + aName.Length];
	uPortName.MaximumLength = 2 * (14 + aName.Length);
	RtlAppendUnicodeToString(&uPortName, L"\\RPC Control\\");
	if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&uSrc, &aName, TRUE)) ||
		!NT_SUCCESS(RtlAppendUnicodeStringToString(&uPortName, &uSrc))) {
		delete[]uPortName.Buffer;
		return STATUS_NO_MEMORY;
	}
	RtlFreeUnicodeString(&uSrc);

	status = RtlpConnectPort_U(
		PortHandle,
		&uPortName,
		ConnectionInformation,
		ConnectionInformationLength,
		pMessageContext);

	delete[]uPortName.Buffer;
	return status;
}

NTSTATUS NTAPI RtlConnectPortW(
	_Out_ PHANDLE PortHandle,
	_In_z_ LPCWSTR PortName,
	_Inout_updates_bytes_to_opt_(*ConnectionInformationLength, *ConnectionInformationLength) PVOID ConnectionInformation,
	_Inout_opt_ PULONG ConnectionInformationLength,
	_Inout_ PRTL_PORT_MESSAGE_CONTEXT pMessageContext) {
	UNICODE_STRING uPortName{}, uSrc{};
	NTSTATUS status;

	RtlInitUnicodeString(&uSrc, PortName);

	uPortName.MaximumLength = uSrc.Length + 28;
	uPortName.Buffer = (LPWSTR)new char[uPortName.MaximumLength];
	if (!NT_SUCCESS(RtlAppendUnicodeToString(&uPortName, L"\\RPC Control\\")) ||
		!NT_SUCCESS(RtlAppendUnicodeStringToString(&uPortName, &uSrc)))
		return STATUS_NO_MEMORY;

	status = RtlpConnectPort_U(
		PortHandle,
		&uPortName,
		ConnectionInformation,
		ConnectionInformationLength,
		pMessageContext);

	delete[]uPortName.Buffer;
	return status;
}

//priv
NTSTATUS NTAPI RtlpConnectPort_U(
	_Out_ PHANDLE PortHandle,
	_In_ PUNICODE_STRING PortName,
	_Inout_updates_bytes_to_opt_(*ConnectionInformationLength, *ConnectionInformationLength) PVOID ConnectionInformation,
	_Inout_opt_ PULONG ConnectionInformationLength,
	_Inout_ PRTL_PORT_MESSAGE_CONTEXT pMessageContext) {
	*PortHandle = nullptr;

	NTSTATUS status = STATUS_SUCCESS;
	ULONG TotalLength = 0;

	if (pMessageContext->LocalView.ViewSize) {
		LARGE_INTEGER length;
		length.QuadPart = pMessageContext->LocalView.ViewSize;
		if (!NT_SUCCESS(
			status = NtCreateSection(
				(PHANDLE)&pMessageContext->LocalView.SectionHandle,
				SECTION_ALL_ACCESS,
				nullptr,
				&length,
				PAGE_READWRITE,
				SEC_COMMIT,
				nullptr))
			) {
			return status;
		}
		pMessageContext->LocalView.ViewSize = 0;
	}

	status = RtlpConnectPortInternal(
		PortHandle,
		PortName,
		ConnectionInformation,
		ConnectionInformationLength,
		&pMessageContext->LocalView,
		&pMessageContext->RemoteView,
		&TotalLength);

	if (!NT_SUCCESS(status) && pMessageContext->LocalView.SectionHandle) {
		NtClose((HANDLE)pMessageContext->LocalView.SectionHandle);
		pMessageContext->LocalView.SectionHandle = 0;
		return status;
	}
	pMessageContext->PortMessage.u1.s1.TotalLength = TotalLength;
	return STATUS_SUCCESS;
}

//priv
NTSTATUS NTAPI RtlpConnectPortInternal(
	_Out_ PHANDLE PortHandle,
	_In_ PUNICODE_STRING PortName,
	_Inout_updates_bytes_to_opt_(*ConnectionInformationLength, *ConnectionInformationLength) PVOID ConnectionInformation,
	_Inout_opt_ PULONG ConnectionInformationLength,
	_Inout_updates_bytes_opt_(sizeof(*ClientView)) PPORT_VIEW64 ClientView,
	_Inout_updates_bytes_opt_(sizeof(*ServerView)) PREMOTE_PORT_VIEW64 ServerView,
	_Out_opt_ PULONG MessageTotalLength) {
	*PortHandle = nullptr;
	if (MessageTotalLength)*MessageTotalLength = 0;

	NTSTATUS status = STATUS_SUCCESS;
	SECURITY_QUALITY_OF_SERVICE sqos{ sizeof(sqos) };
	static const ULONG MaxLength = RtlpIsWow64Process() ? sizeof(PORT_MESSAGE64) : sizeof(PORT_MESSAGE);

	if (ClientView && (!ClientView->SectionHandle)) ClientView = nullptr;

	if (RtlpIsWow64Process()) {
		ULONG64 Handle64 = 0;
		UNICODE_STRING64 PortName64{ PortName->Length,PortName->MaximumLength,(WCHAR * __ptr64)PortName->Buffer };

		status = Wow64ConnectPort(
			&Handle64,
			&PortName64,
			&sqos,
			ClientView,
			ServerView,
			nullptr,
			ConnectionInformation,
			ConnectionInformationLength);

		if (NT_SUCCESS(status)) {
			if (MessageTotalLength)*MessageTotalLength = MaxLength;
			*PortHandle = (HANDLE)Handle64;
		}
		return status;
	}

	auto pClientView = (PPORT_VIEW)ClientView;
	auto pServerView = (PREMOTE_PORT_VIEW)ServerView;

	//map to 32bits
#ifndef _WIN64
	PORT_VIEW pv{ sizeof(pv) };
	REMOTE_PORT_VIEW rpv{ sizeof(rpv) };
	pClientView = ClientView ? &pv : nullptr;
	pServerView = &rpv;
	RtlpMapView64ToView(ClientView, pClientView, ServerView, pServerView);
#endif

	status = NtConnectPort(
		PortHandle,
		PortName,
		&sqos,
		pClientView,
		pServerView,
		nullptr,
		ConnectionInformation,
		ConnectionInformationLength);

	//expand to 64bits
#ifndef _WIN64
	if (NT_SUCCESS(status))
		RtlpMapViewToView64(pClientView, ClientView, pServerView, ServerView);
#endif

	if (NT_SUCCESS(status) && MessageTotalLength)
		*MessageTotalLength = MaxLength;
	return status;
}

//priv
VOID NTAPI RtlpMapPortMessageToPortMessage64(
	_In_reads_bytes_(pPortMessage32->u1.s1.TotalLength) PPORT_MESSAGE pPortMessage32,
	_Out_writes_bytes_(pPortMessage32->u1.s1.DataLength + sizeof(*pPortMessage64)) PPORT_MESSAGE64 pPortMessage64) {

	pPortMessage64->u1.s1.DataLength = pPortMessage32->u1.s1.DataLength;
	pPortMessage64->u1.s1.TotalLength = sizeof(PORT_MESSAGE64) + pPortMessage32->u1.s1.DataLength;
	pPortMessage64->u2.ZeroInit = pPortMessage32->u2.ZeroInit;
	pPortMessage64->ClientId.UniqueProcess = (size_t)pPortMessage32->ClientId.UniqueProcess;
	pPortMessage64->ClientId.UniqueThread = (size_t)pPortMessage32->ClientId.UniqueThread;
	pPortMessage64->MessageId = pPortMessage32->MessageId;
	pPortMessage64->ClientViewSize = pPortMessage32->ClientViewSize;

	if (pPortMessage32->u1.s1.DataLength)
		RtlCopyMemory(
			LPBYTE(pPortMessage64) + sizeof(*pPortMessage64),
			LPBYTE(pPortMessage32) + sizeof(*pPortMessage32),
			pPortMessage32->u1.s1.DataLength
		);
}

//priv
VOID NTAPI RtlpMapPortMessage64ToPortMessage(
	_In_reads_bytes_(pPortMessage64->u1.s1.TotalLength) PPORT_MESSAGE64 pPortMessage64,
	_Out_writes_bytes_(pPortMessage64->u1.s1.DataLength + sizeof(*pPortMessage32)) PPORT_MESSAGE pPortMessage32) {

	pPortMessage32->u1.s1.DataLength = pPortMessage64->u1.s1.DataLength;
	pPortMessage32->u1.s1.TotalLength = sizeof(PORT_MESSAGE) + pPortMessage64->u1.s1.DataLength;
	pPortMessage32->u2.ZeroInit = pPortMessage64->u2.ZeroInit;
	pPortMessage32->ClientId.UniqueProcess = (HANDLE)pPortMessage64->ClientId.UniqueProcess;
	pPortMessage32->ClientId.UniqueThread = (HANDLE)pPortMessage64->ClientId.UniqueThread;
	pPortMessage32->MessageId = pPortMessage64->MessageId;
	pPortMessage32->ClientViewSize = pPortMessage64->ClientViewSize;

	if (pPortMessage64->u1.s1.DataLength)
		RtlCopyMemory(
			LPBYTE(pPortMessage32) + sizeof(*pPortMessage32),
			LPBYTE(pPortMessage64) + sizeof(*pPortMessage64),
			pPortMessage64->u1.s1.DataLength
		);
}

//priv
PPORT_MESSAGE NTAPI RtlpMapPortMessage64ToPortMessageAllocate(
	_In_reads_bytes_(pPortMessage64->u1.s1.TotalLength) PPORT_MESSAGE64 pPortMessage64) {
	auto msg = (PPORT_MESSAGE)RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, LPCP_MAX_MESSAGE_SIZE);
	if (msg) RtlpMapPortMessage64ToPortMessage(pPortMessage64, msg);
	return msg;
}

//priv
VOID NTAPI RtlpMapViewToView64(
	_In_reads_bytes_opt_(sizeof(*pLocalView32)) PPORT_VIEW pLocalView32,
	_Out_writes_bytes_opt_(sizeof(*pLocalView64)) PPORT_VIEW64 pLocalView64,
	_In_reads_bytes_opt_(sizeof(*pRemoteView32)) PREMOTE_PORT_VIEW pRemoteView32,
	_Out_writes_bytes_opt_(sizeof(*pRemoteView64)) PREMOTE_PORT_VIEW64 pRemoteView64) {

	if (pLocalView64)RtlZeroMemory(pLocalView64, sizeof(*pLocalView64));
	if (pRemoteView64)RtlZeroMemory(pRemoteView64, sizeof(*pRemoteView64));

	if (pLocalView32 && pLocalView64) {
		pLocalView64->SectionHandle = (size_t)pLocalView32->SectionHandle;
		pLocalView64->SectionOffset = pLocalView32->SectionOffset;
		pLocalView64->ViewBase = (size_t)pLocalView32->ViewBase;
		pLocalView64->ViewRemoteBase = (size_t)pLocalView32->ViewRemoteBase;
		pLocalView64->ViewSize = pLocalView32->ViewSize;
		pLocalView64->Length = sizeof(PORT_VIEW64);
	}
	if (pRemoteView32 && pRemoteView64) {
		pRemoteView64->ViewBase = (size_t)pRemoteView32->ViewBase;
		pRemoteView64->ViewSize = pRemoteView32->ViewSize;
		pRemoteView64->Length = sizeof(REMOTE_PORT_VIEW64);
	}
}

//priv
VOID NTAPI RtlpMapView64ToView(
	_In_reads_bytes_opt_(sizeof(*pLocalView64)) PPORT_VIEW64 pLocalView64,
	_Out_writes_bytes_opt_(sizeof(*pLocalView32)) PPORT_VIEW pLocalView32,
	_In_reads_bytes_opt_(sizeof(*pRemoteView64)) PREMOTE_PORT_VIEW64 pRemoteView64,
	_Out_writes_bytes_opt_(sizeof(*pRemoteView32)) PREMOTE_PORT_VIEW pRemoteView32) {

	if (pLocalView32)RtlZeroMemory(pLocalView32, sizeof(*pLocalView32));
	if (pRemoteView32)RtlZeroMemory(pRemoteView32, sizeof(*pRemoteView32));

	if (pLocalView32 && pLocalView64) {
		pLocalView32->SectionHandle = (HANDLE)pLocalView64->SectionHandle;
		pLocalView32->SectionOffset = pLocalView64->SectionOffset;
		pLocalView32->ViewBase = (PVOID)pLocalView64->ViewBase;
		pLocalView32->ViewRemoteBase = (PVOID)pLocalView64->ViewRemoteBase;
		pLocalView32->ViewSize = pLocalView64->ViewSize;
		pLocalView32->Length = sizeof(PORT_VIEW);
	}
	if (pRemoteView32 && pRemoteView64) {
		pRemoteView32->ViewBase = (PVOID)pRemoteView64->ViewBase;
		pRemoteView32->ViewSize = pRemoteView64->ViewSize;
		pRemoteView32->Length = sizeof(REMOTE_PORT_VIEW);
	}
}

//priv
VOID NTAPI RtlpGetSystemLpcMessageMaxLength(
	_Out_opt_ PULONG pLpcMaxLength,
	_Out_opt_ PULONG pLpcMaxDataLength) {
	const static ULONG
		MaxLength = RtlpIsWow64Process() ? LPCP_MAX_MESSAGE_SIZE64 : LPCP_MAX_MESSAGE_SIZE,
		MaxDataLength = MaxLength - (RtlpIsWow64Process() ? sizeof(LPCP_MESSAGE64) + sizeof(LPCP_CONNECTION_MESSAGE64) : sizeof(LPCP_MESSAGE) + sizeof(LPCP_CONNECTION_MESSAGE));

	if (pLpcMaxLength)*pLpcMaxLength = MaxLength;
	if (pLpcMaxDataLength)*pLpcMaxDataLength = MaxDataLength;
}

BOOLEAN NTAPI RtlAllocatePortMessageContextEx(
	_Out_writes_to_ptr_(pMessageContext) PRTL_PORT_MESSAGE_CONTEXT* pMessageContext,
	_In_opt_ ULONG64 LocalSharedMemoryBase,
	_In_opt_ ULONG64 LocalSharedMemoryLength) {
	ULONG MaxLength;
	PRTL_PORT_MESSAGE_CONTEXT result = nullptr;

	if (LocalSharedMemoryBase && !LocalSharedMemoryLength)goto done;

	RtlpGetSystemLpcMessageMaxLength(&MaxLength, nullptr);
	result = (PRTL_PORT_MESSAGE_CONTEXT)RtlAllocateHeap(
		NtCurrentPeb()->ProcessHeap,
		HEAP_ZERO_MEMORY,
		MaxLength + sizeof(PORT_VIEW64) + sizeof(REMOTE_PORT_VIEW64));

	if (result) {
		result->LocalView.Length = sizeof(PORT_VIEW64);
		result->RemoteView.Length = sizeof(REMOTE_PORT_VIEW64);
		result->LocalView.ViewBase = LocalSharedMemoryBase;
		result->LocalView.ViewSize = LocalSharedMemoryLength;
	}

done:
	return (*pMessageContext = result) != nullptr;
}

BOOLEAN NTAPI RtlAllocatePortMessageContext(_Out_writes_to_ptr_(pMessageContext) PRTL_PORT_MESSAGE_CONTEXT* pMessageContext) {
	return RtlAllocatePortMessageContextEx(pMessageContext, 0, 0);
}

BOOLEAN NTAPI RtlReleasePortMessageContext(_In_ PRTL_PORT_MESSAGE_CONTEXT pMessageContext) {
	if (pMessageContext->LocalView.SectionHandle)
		NtClose((HANDLE)pMessageContext->LocalView.SectionHandle);
	return RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, pMessageContext);
}


NTSTATUS NTAPI RtlListenPort(
	_In_ HANDLE PortHandle,
	_Inout_ PRTL_PORT_MESSAGE_CONTEXT pMessageContext) {
	NTSTATUS status;

	if (RtlpIsWow64Process()) {
		return Wow64ListenPort(PortHandle, &pMessageContext->PortMessage);
	}
	auto req = (PPORT_MESSAGE)&pMessageContext->PortMessage;

#ifndef _WIN64
	PORT_MESSAGE Msg{};
	req = &Msg;
#endif

	status = NtListenPort(PortHandle, req);

#ifndef _WIN64
	if (NT_SUCCESS(status)) {
		RtlpMapPortMessageToPortMessage64(&Msg, &pMessageContext->PortMessage);
	}
#endif
	return status;
}


NTSTATUS NTAPI RtlAcceptConnectPort(
	_Out_ PHANDLE PortHandle,
	_In_opt_ PVOID PortContext,
	_In_ BOOLEAN AcceptConnection,
	_Inout_ PRTL_PORT_MESSAGE_CONTEXT pMessageContext) {
	NTSTATUS status;

	if (pMessageContext->LocalView.ViewSize) {
		LARGE_INTEGER length;
		length.QuadPart = pMessageContext->LocalView.ViewSize;
		if (!NT_SUCCESS(
			status = NtCreateSection(
				(PHANDLE)&pMessageContext->LocalView.SectionHandle,
				SECTION_ALL_ACCESS,
				nullptr,
				&length,
				PAGE_READWRITE,
				SEC_COMMIT,
				nullptr))
			) {
			return status;
		}
		pMessageContext->LocalView.ViewSize = 0;
	}

	if (RtlpIsWow64Process()) {
		ULONG64 pHandle = 0;
		status = Wow64AcceptConnectPort(
			&pHandle,
			nullptr,
			&pMessageContext->PortMessage,
			AcceptConnection,
			pMessageContext->LocalView.SectionHandle ? &pMessageContext->LocalView : nullptr,
			&pMessageContext->RemoteView);

		if (NT_SUCCESS(status))
			*PortHandle = (HANDLE)pHandle;
		else if (pMessageContext->LocalView.SectionHandle) {
			NtClose((HANDLE)pMessageContext->LocalView.SectionHandle);
			pMessageContext->LocalView.SectionHandle = 0;
		}

		return status;
	}

	auto msg = (PPORT_MESSAGE)&pMessageContext->PortMessage;
	auto lv = pMessageContext->LocalView.SectionHandle ? (PPORT_VIEW)&pMessageContext->LocalView : nullptr;
	auto rv = (PREMOTE_PORT_VIEW)&pMessageContext->RemoteView;

#ifndef _WIN64
	PORT_VIEW LV;
	REMOTE_PORT_VIEW RV;
	lv = lv ? &LV : nullptr;
	rv = &RV;
	if (!(msg = RtlpMapPortMessage64ToPortMessageAllocate(&pMessageContext->PortMessage)))
		return STATUS_NO_MEMORY;
	RtlpMapView64ToView(&pMessageContext->LocalView, lv, &pMessageContext->RemoteView, rv);
#endif

	status = NtAcceptConnectPort(
		PortHandle,
		nullptr,
		msg,
		AcceptConnection,
		lv,
		rv);

#ifndef _WIN64
	if (NT_SUCCESS(status)) {
		RtlpMapPortMessageToPortMessage64(msg, &pMessageContext->PortMessage);
		RtlpMapViewToView64(lv, &pMessageContext->LocalView, rv, &pMessageContext->RemoteView);
	}
	RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, msg);
#endif

	if (!NT_SUCCESS(status) && pMessageContext->LocalView.SectionHandle) {
		NtClose((HANDLE)pMessageContext->LocalView.SectionHandle);
		pMessageContext->LocalView.SectionHandle = 0;
	}
	return status;
}

NTSTATUS NTAPI RtlCompleteConnectPort(_In_ HANDLE PortHandle) {
	return NtCompleteConnectPort(PortHandle);
}

//priv
NTSTATUS NTAPI RtlpRequestReplyPort(
	_In_ HANDLE PortHandle,
	_In_ DWORD Flags,
	_In_opt_ PLARGE_INTEGER Timeout,
	_Inout_updates_bytes_(pMessageContext->PortMessage.u1.s1.DataLength + sizeof(*pMessageContext)) PRTL_PORT_MESSAGE_CONTEXT pMessageContext) {

	bool Request = Flags & RTLP_REQUEST, WaitReply = Flags & RTLP_WAIT_FOR_REPLY;
	//static const ULONG Max = RtlpIsWow64Process() ? sizeof(PORT_MESSAGE64) : sizeof(PORT_MESSAGE);
	NTSTATUS status;

	if (!(Flags & (RTLP_REPLY | RTLP_REQUEST)) ||
		((Flags & RTLP_REPLY) && (Flags & RTLP_REQUEST)) ||
		(((Flags & RTLP_WAIT_FOR_REPLY) || (Flags & RTLP_REQUEST)) && (Flags & RTLP_WAIT_FOR_RECEIVE)) ||
		((Flags & RTLP_NO_REPLY) && !(Flags & RTLP_WAIT_FOR_RECEIVE)))
		return STATUS_INVALID_PARAMETER_2;

	//if (Request) pMessageContext->PortMessage.u2.s2.Type = 0;
	//pMessageContext->PortMessage.u1.s1.TotalLength = Max + pMessageContext->PortMessage.u1.s1.DataLength;

	if (RtlpIsWow64Process()) {
		if (Request) {
			if (WaitReply) {
				status = Wow64RequestWaitReplyPort(
					PortHandle,
					&pMessageContext->PortMessage,
					&pMessageContext->PortMessage);
			}
			else {
				status = Wow64RequestPort(
					PortHandle,
					&pMessageContext->PortMessage);
			}
			return status;
		}
		else {
			if (Flags & RTLP_WAIT_FOR_RECEIVE) {
				status = Wow64ReplyWaitReceivePortEx(
					PortHandle,
					nullptr,
					Flags & RTLP_NO_REPLY ? nullptr : &pMessageContext->PortMessage,
					&pMessageContext->PortMessage,
					Timeout);
			}
			else {
				status = WaitReply ?
					Wow64ReplyWaitReplyPort(
						PortHandle,
						&pMessageContext->PortMessage) :
					Wow64ReplyPort(
						PortHandle,
						&pMessageContext->PortMessage);
			}
			return status;
		}
	}

	auto msg = (PPORT_MESSAGE)&pMessageContext->PortMessage;

#ifndef _WIN64
	msg = RtlpMapPortMessage64ToPortMessageAllocate(&pMessageContext->PortMessage);
	if (!msg)return STATUS_NO_MEMORY;
#endif

	if (Request) {
		status = WaitReply ?
			NtRequestWaitReplyPort(PortHandle, msg, msg) :
			NtRequestPort(PortHandle, msg);
	}
	else {
		if (Flags & RTLP_WAIT_FOR_RECEIVE) {
			status = NtReplyWaitReceivePortEx(
				PortHandle,
				nullptr,
				Flags & RTLP_NO_REPLY ? nullptr : msg,
				msg,
				Timeout);
		}
		else {
			if (WaitReply) {
				status = NtReplyWaitReplyPort(PortHandle, msg);
			}
			else {
				status = NtReplyPort(PortHandle, msg);
			}
		}
	}


#ifndef _WIN64
	if (NT_SUCCESS(status) && (WaitReply || (Flags & RTLP_WAIT_FOR_RECEIVE)))
		RtlpMapPortMessageToPortMessage64(msg, &pMessageContext->PortMessage);
	RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, msg);
#endif
	return status;
}

NTSTATUS NTAPI RtlRequestPort(
	_In_ HANDLE PortHandle,
	_In_reads_bytes_(pMessageContext->PortMessage.u1.s1.DataLength + sizeof(*pMessageContext)) PRTL_PORT_MESSAGE_CONTEXT pMessageContext) {
	return RtlpRequestReplyPort(PortHandle, RTLP_REQUEST, nullptr, pMessageContext);
}

NTSTATUS NTAPI RtlRequestWaitReplyPort(
	_In_ HANDLE PortHandle,
	_In_reads_bytes_(pMessageContext->PortMessage.u1.s1.DataLength + sizeof(*pMessageContext)) PRTL_PORT_MESSAGE_CONTEXT pMessageContext) {
	return RtlpRequestReplyPort(PortHandle, RTLP_REQUEST | RTLP_WAIT_FOR_REPLY, nullptr, pMessageContext);
}

NTSTATUS NTAPI RtlReplyPort(
	_In_ HANDLE PortHandle,
	_In_reads_bytes_(pMessageContext->PortMessage.u1.s1.DataLength + sizeof(*pMessageContext)) PRTL_PORT_MESSAGE_CONTEXT pMessageContext) {
	return RtlpRequestReplyPort(PortHandle, RTLP_REPLY, nullptr, pMessageContext);
}

NTSTATUS NTAPI RtlReplyWaitReplyPort(
	_In_ HANDLE PortHandle,
	_Inout_updates_bytes_(pMessageContext->PortMessage.u1.s1.DataLength + sizeof(*pMessageContext)) PRTL_PORT_MESSAGE_CONTEXT pMessageContext) {
	return RtlpRequestReplyPort(PortHandle, RTLP_REPLY | RTLP_WAIT_FOR_REPLY, nullptr, pMessageContext);
}

NTSTATUS NTAPI RtlReplyWaitReceivePort(
	_In_ HANDLE PortHandle,
	_In_ BOOLEAN SendReply,
	_In_opt_ PLARGE_INTEGER Timeout,
	_Inout_updates_bytes_(pMessageContext->PortMessage.u1.s1.DataLength + sizeof(*pMessageContext)) PRTL_PORT_MESSAGE_CONTEXT pMessageContext) {
	return RtlpRequestReplyPort(PortHandle, RTLP_REPLY | RTLP_WAIT_FOR_RECEIVE | (SendReply ? 0 : RTLP_NO_REPLY), Timeout, pMessageContext);
}

NTSTATUS NTAPI RtlImpersonateClientOfPort(
	_In_ HANDLE PortHandle,
	_In_ PRTL_PORT_MESSAGE_CONTEXT pMessageContext) {

	if (RtlpIsWow64Process()) {
		return Wow64ImpersonateClientOfPort(PortHandle, &pMessageContext->PortMessage);
	}

	NTSTATUS status;
	auto msg = (PPORT_MESSAGE)&pMessageContext->PortMessage;

#ifndef _WIN64
	msg = RtlpMapPortMessage64ToPortMessageAllocate(&pMessageContext->PortMessage);
#endif

	status = NtImpersonateClientOfPort(PortHandle, msg);

#ifndef _WIN64
	RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, msg);
#endif

	return status;
}


_Check_return_
NTSTATUS NTAPI RtlWriteRequestData(
	_Inout_ PRTL_PORT_MESSAGE_CONTEXT pMessageContext,
	_In_reads_bytes_opt_(dwDataLength) LPCVOID pDataToWrite,
	_In_ DWORD dwDataLength) {
	ULONG MaxDataLength;
	RtlpGetSystemLpcMessageMaxLength(nullptr, &MaxDataLength);

	if (dwDataLength > MaxDataLength)return STATUS_PORT_MESSAGE_TOO_LONG;
	if (dwDataLength && !pDataToWrite)return STATUS_ACCESS_VIOLATION;

	pMessageContext->PortMessage.u1.s1.DataLength = dwDataLength;
	pMessageContext->PortMessage.u1.s1.TotalLength = sizeof(PORT_MESSAGE64) + dwDataLength;
	pMessageContext->PortMessage.u2.s2.Type = 0;

	if (dwDataLength)
		RtlCopyMemory(pMessageContext->LpcData, pDataToWrite, dwDataLength);

	return STATUS_SUCCESS;
}

_Check_return_
NTSTATUS NTAPI RtlWriteReplyData(
	_Inout_ PRTL_PORT_MESSAGE_CONTEXT pMessageContext,
	_In_reads_bytes_opt_(dwDataLength) LPCVOID pDataToWrite,
	_In_ DWORD dwDataLength) {
	return RtlWriteRequestData(pMessageContext, pDataToWrite, dwDataLength);
}

