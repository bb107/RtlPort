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

#pragma once
#include <assert.h>
typedef struct _RTL_PORT_MESSAGE_CONTEXT {
										//	Connect		Request/Reply	Receive
	PORT_VIEW64 LocalView;				//	_Inout_
	REMOTE_PORT_VIEW64 RemoteView;		//	_Out_
	PORT_MESSAGE64 PortMessage;			//				_In_			_Inout_
	BYTE LpcData[ANYSIZE_ARRAY];		//				_In_			_Out_
}RTL_PORT_MESSAGE_CONTEXT, * PRTL_PORT_MESSAGE_CONTEXT;

/*
	++++++ 32-bits/64-bits structure conversion
*/

//priv
BOOLEAN NTAPI RtlpIsWow64Process();

//priv
VOID NTAPI RtlpMapPortMessageToPortMessage64(
	_In_reads_bytes_(pPortMessage32->u1.s1.TotalLength) PPORT_MESSAGE pPortMessage32,
	_Out_writes_bytes_(pPortMessage32->u1.s1.DataLength + sizeof(*pPortMessage64)) PPORT_MESSAGE64 pPortMessage64);

//priv
VOID NTAPI RtlpMapPortMessage64ToPortMessage(
	_In_reads_bytes_(pPortMessage64->u1.s1.TotalLength) PPORT_MESSAGE64 pPortMessage64,
	_Out_writes_bytes_(pPortMessage64->u1.s1.DataLength + sizeof(*pPortMessage32)) PPORT_MESSAGE pPortMessage32);

//priv
PPORT_MESSAGE NTAPI RtlpMapPortMessage64ToPortMessageAllocate(
	_In_reads_bytes_(pPortMessage64->u1.s1.TotalLength) PPORT_MESSAGE64 pPortMessage64);

//priv
VOID NTAPI RtlpMapViewToView64(
	_In_reads_bytes_opt_(sizeof(*pLocalView32)) PPORT_VIEW pLocalView32,
	_Out_writes_bytes_opt_(sizeof(*pLocalView64)) PPORT_VIEW64 pLocalView64,
	_In_reads_bytes_opt_(sizeof(*pRemoteView32)) PREMOTE_PORT_VIEW pRemoteView32,
	_Out_writes_bytes_opt_(sizeof(*pRemoteView64)) PREMOTE_PORT_VIEW64 pRemoteView64);

//priv
VOID NTAPI RtlpMapView64ToView(
	_In_reads_bytes_opt_(sizeof(*pLocalView64)) PPORT_VIEW64 pLocalView64,
	_Out_writes_bytes_opt_(sizeof(*pLocalView32)) PPORT_VIEW pLocalView32,
	_In_reads_bytes_opt_(sizeof(*pRemoteView64)) PREMOTE_PORT_VIEW64 pRemoteView64,
	_Out_writes_bytes_opt_(sizeof(*pRemoteView32)) PREMOTE_PORT_VIEW pRemoteView32);

//priv
VOID NTAPI RtlpGetSystemLpcMessageMaxLength(
	_Out_opt_ PULONG pLpcMaxLength,
	_Out_opt_ PULONG pLpcMaxDataLength);

/*
	------ 32-bits/64-bits structure conversion
*/


/*
	++++++ Create/Connect port
*/

NTSTATUS NTAPI RtlCreatePortA(
	_Out_ PHANDLE PortHandle,
	_In_z_ LPCSTR PortName,
	_In_ BOOLEAN Waitable);

NTSTATUS NTAPI RtlCreatePortW(
	_Out_ PHANDLE PortHandle,
	_In_z_ LPCWSTR PortName,
	_In_ BOOLEAN Waitable);

//priv
NTSTATUS NTAPI RtlpCreatePort_U(
	_Out_ PHANDLE PortHandle,
	_In_ PUNICODE_STRING PortName,
	_In_ BOOLEAN Waitable);


NTSTATUS NTAPI RtlConnectPortA(
	_Out_ PHANDLE PortHandle,
	_In_z_ LPCSTR PortName,
	_Inout_updates_bytes_to_opt_(*ConnectionInformationLength, *ConnectionInformationLength) PVOID ConnectionInformation,
	_Inout_opt_ PULONG ConnectionInformationLength,
	_Inout_ PRTL_PORT_MESSAGE_CONTEXT pMessageContext);

NTSTATUS NTAPI RtlConnectPortW(
	_Out_ PHANDLE PortHandle,
	_In_z_ LPCWSTR PortName,
	_Inout_updates_bytes_to_opt_(*ConnectionInformationLength, *ConnectionInformationLength) PVOID ConnectionInformation,
	_Inout_opt_ PULONG ConnectionInformationLength,
	_Inout_ PRTL_PORT_MESSAGE_CONTEXT pMessageContext);

//priv
NTSTATUS NTAPI RtlpConnectPortInternal(
	_Out_ PHANDLE PortHandle,
	_In_ PUNICODE_STRING PortName,
	_Inout_updates_bytes_to_opt_(*ConnectionInformationLength, *ConnectionInformationLength) PVOID ConnectionInformation,
	_Inout_opt_ PULONG ConnectionInformationLength,
	_Inout_updates_bytes_opt_(sizeof(*ClientView)) PPORT_VIEW64 ClientView,
	_Inout_updates_bytes_opt_(sizeof(*ServerView)) PREMOTE_PORT_VIEW64 ServerView,
	_Out_opt_ PULONG MessageTotalLength);

//priv
NTSTATUS NTAPI RtlpConnectPort_U(
	_Out_ PHANDLE PortHandle,
	_In_ PUNICODE_STRING PortName,
	_Inout_updates_bytes_to_opt_(*ConnectionInformationLength, *ConnectionInformationLength) PVOID ConnectionInformation,
	_Inout_opt_ PULONG ConnectionInformationLength,
	_Inout_ PRTL_PORT_MESSAGE_CONTEXT pMessageContext);

BOOLEAN NTAPI RtlAllocatePortMessageContext(_Out_writes_to_ptr_(pMessageContext) PRTL_PORT_MESSAGE_CONTEXT* pMessageContext);

BOOLEAN NTAPI RtlAllocatePortMessageContextEx(
	_Out_writes_to_ptr_(pMessageContext) PRTL_PORT_MESSAGE_CONTEXT* pMessageContext,
	_In_opt_ ULONG64 LocalSharedMemoryBase,
	_In_opt_ ULONG64 LocalSharedMemoryLength);

BOOLEAN NTAPI RtlReleasePortMessageContext(_In_ PRTL_PORT_MESSAGE_CONTEXT pMessageContext);

NTSTATUS NTAPI RtlListenPort(
	_In_ HANDLE PortHandle,
	_Inout_ PRTL_PORT_MESSAGE_CONTEXT pMessageContext);

NTSTATUS NTAPI RtlAcceptConnectPort(
	_Out_ PHANDLE PortHandle,
	_In_opt_ PVOID PortContext,
	_In_ BOOLEAN AcceptConnection,
	_Inout_ PRTL_PORT_MESSAGE_CONTEXT pMessageContext);

NTSTATUS NTAPI RtlCompleteConnectPort(_In_ HANDLE PortHandle);

/*
	------ Create/Connect port
*/


/*
	++++++ Read/Write message data
*/

//Pointer to the data attached to the message
#define RtlMessageDataPtr(_pMessageContext_)	(PRTL_PORT_MESSAGE_CONTEXT(_pMessageContext_)->LpcData)
//Data size
#define RtlMessageDataLength(_pMessageContext_) (PRTL_PORT_MESSAGE_CONTEXT(_pMessageContext_)->PortMessage.u1.s1.DataLength)
//Total length including message header
#define RtlMessageTotalLength(_pMessageContext_) (PRTL_PORT_MESSAGE_CONTEXT(_pMessageContext_)->PortMessage.u1.s1.TotalLength)

//Base address of section mapping created locally
#define RtlLocalSectionSharedMemoryPtr(_pMessageContext_)		(PRTL_PORT_MESSAGE_CONTEXT(_pMessageContext_)->LocalView.ViewBase)
//Mapping size
#define RtlLocalSectionSharedMemoryLength(_pMessageContext_)	(PRTL_PORT_MESSAGE_CONTEXT(_pMessageContext_)->LocalView.ViewSize)

//Base address of section mapping created remotely
#define RtlRemoteSectionSharedMemoryPtr(_pMessageContext_)		(PRTL_PORT_MESSAGE_CONTEXT(_pMessageContext_)->RemoteView.ViewBase)
//Mapping size
#define RtlRemoteSectionSharedMemoryLength(_pMessageContext_)	(PRTL_PORT_MESSAGE_CONTEXT(_pMessageContext_)->RemoteView.ViewSize)

//Write limited data behind the message header
#ifdef _DEBUG
#define RtlWriteSmallStructure(_pMessageContext_, _type_, _data_)(\
	assert(sizeof(_type_) <= 0xe8),\
	(*((_type_*)(RtlMessageDataPtr(_pMessageContext_))) = (_type_)_data_),\
	(RtlMessageDataLength(_pMessageContext_) = sizeof(_type_)),\
	(RtlMessageTotalLength(_pMessageContext_) = sizeof(PORT_MESSAGE64) + sizeof(_type_)),\
	(_pMessageContext_->PortMessage.u2.s2.Type = 0)\
)
#else
#define RtlWriteSmallStructure(_pMessageContext_, _type_, _data_)(\
	(*((_type_*)(RtlMessageDataPtr(_pMessageContext_))) = (_type_)_data_),\
	(RtlMessageDataLength(_pMessageContext_) = sizeof(_type_)),\
	(RtlMessageTotalLength(_pMessageContext_) = sizeof(PORT_MESSAGE64)),\
	(_pMessageContext_->PortMessage.u2.s2.Type = 0)\
)
#endif

//Write a ULONG behind the message header
#define RtlWriteRequestUlong(_pMessageContext_, _data_) (\
	RtlWriteSmallStructure(_pMessageContext_, ULONG, _data_),\
	0\
)

//Write a ULONG64 behind the message header
#define RtlWriteRequestUlong64(_pMessageContext_, _data_) (\
	RtlWriteSmallStructure(_pMessageContext_, ULONG64, _data_),\
	0\
)

#define RtlWriteReplyUlong		RtlWriteRequestUlong
#define RtlWriteReplyUlong64	RtlWriteRequestUlong64

_Check_return_
NTSTATUS NTAPI RtlWriteReplyData(
	_Inout_ PRTL_PORT_MESSAGE_CONTEXT pMessageContext,
	_In_reads_bytes_opt_(dwDataLength) LPCVOID pDataToWrite,
	_In_ DWORD dwDataLength);

_Check_return_
NTSTATUS NTAPI RtlWriteRequestData(
	_Inout_ PRTL_PORT_MESSAGE_CONTEXT pMessageContext,
	_In_reads_bytes_opt_(dwDataLength) LPCVOID pDataToWrite,
	_In_ DWORD dwDataLength);

/*
	------ Read/Write message data
*/


/*
	++++++ Request/Reply message
*/

//priv
#define RTLP_REQUEST			0x10000000
#define RTLP_REPLY				0x20000000
#define RTLP_WAIT_FOR_REPLY		0x00000001
#define RTLP_WAIT_FOR_RECEIVE	0x00000002
#define RTLP_NO_REPLY			0x00000004
NTSTATUS NTAPI RtlpRequestReplyPort(
	_In_ HANDLE PortHandle,
	_In_ DWORD Flags,
	_In_opt_ PLARGE_INTEGER Timeout,
	_Inout_updates_bytes_(pMessageContext->PortMessage.u1.s1.DataLength + sizeof(*pMessageContext)) PRTL_PORT_MESSAGE_CONTEXT pMessageContext);

NTSTATUS NTAPI RtlRequestPort(
	_In_ HANDLE PortHandle,
	_In_reads_bytes_(pMessageContext->PortMessage.u1.s1.DataLength + sizeof(*pMessageContext)) PRTL_PORT_MESSAGE_CONTEXT pMessageContext);

NTSTATUS NTAPI RtlRequestWaitReplyPort(
	_In_ HANDLE PortHandle,
	_In_reads_bytes_(pMessageContext->PortMessage.u1.s1.DataLength + sizeof(*pMessageContext)) PRTL_PORT_MESSAGE_CONTEXT pMessageContext);

NTSTATUS NTAPI RtlReplyPort(
	_In_ HANDLE PortHandle,
	_In_reads_bytes_(pMessageContext->PortMessage.u1.s1.DataLength + sizeof(*pMessageContext)) PRTL_PORT_MESSAGE_CONTEXT pMessageContext);

NTSTATUS NTAPI RtlReplyWaitReplyPort(
	_In_ HANDLE PortHandle,
	_Inout_updates_bytes_(pMessageContext->PortMessage.u1.s1.DataLength + sizeof(*pMessageContext)) PRTL_PORT_MESSAGE_CONTEXT pMessageContext);

NTSTATUS NTAPI RtlReplyWaitReceivePort(
	_In_ HANDLE PortHandle,
	_In_ BOOLEAN SendReply,
	_In_opt_ PLARGE_INTEGER Timeout,
	_Inout_updates_bytes_(pMessageContext->PortMessage.u1.s1.DataLength + sizeof(*pMessageContext)) PRTL_PORT_MESSAGE_CONTEXT pMessageContext);

/*
	------ Request/Reply message
*/

NTSTATUS NTAPI RtlImpersonateClientOfPort(
	_In_ HANDLE PortHandle,
	_In_ PRTL_PORT_MESSAGE_CONTEXT pMessageContext);
