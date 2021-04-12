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
#include <cassert>
#pragma comment(lib,"ntdll.lib")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef short CSHORT;
typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _PORT_MESSAGE
{
	union
	{
		struct
		{
			CSHORT DataLength;
			CSHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union
	{
		struct
		{
			CSHORT Type;
			CSHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union
	{
		CLIENT_ID ClientId;
		double DoNotUseThisField;
	};
	ULONG MessageId;
	union
	{
		SIZE_T ClientViewSize; // only valid for LPC_CONNECTION_REQUEST messages
		ULONG CallbackId; // only valid for LPC_REQUEST messages
	};
} PORT_MESSAGE, * PPORT_MESSAGE, LPC_MESSAGE, * PLPC_MESSAGE, LPC_MESSAGE_HEADER, * PLPC_MESSAGE_HEADER;


typedef struct _PORT_VIEW
{
	ULONG Length;
	HANDLE SectionHandle;
	ULONG SectionOffset;
	SIZE_T ViewSize;
	PVOID ViewBase;
	PVOID ViewRemoteBase;
} PORT_VIEW, * PPORT_VIEW;
typedef struct _REMOTE_PORT_VIEW
{
	ULONG Length;
	SIZE_T ViewSize;
	PVOID ViewBase;
} REMOTE_PORT_VIEW, * PREMOTE_PORT_VIEW;
typedef struct _LPCP_MESSAGE {
	union {
		LIST_ENTRY Entry;
		struct {
			SINGLE_LIST_ENTRY FreeEntry;
			ULONG Reserved0;
		};
	};
	PVOID SenderPort;
	PVOID RepliedToThread;	//PETHREAD
	PVOID PortContext;
	PORT_MESSAGE Request;
} LPCP_MESSAGE, * PLPCP_MESSAGE;

typedef struct _LPCP_CONNECTION_MESSAGE {
	PORT_VIEW ClientView;
	PVOID ClientPort;	//PLPCP_PORT_OBJECT
	PVOID SectionToMap;
	REMOTE_PORT_VIEW ServerView;
} LPCP_CONNECTION_MESSAGE, * PLPCP_CONNECTION_MESSAGE;
typedef struct _SINGLE_LIST_ENTRY64 {
	ULONG64 Next;
}SINGLE_LIST_ENTRY64, * PSINGLE_LIST_ENTRY64;

typedef struct _CLIENT_ID64
{
	ULONGLONG UniqueProcess;
	ULONGLONG UniqueThread;
} CLIENT_ID64, * PCLIENT_ID64;
typedef struct _PORT_MESSAGE64
{
	union
	{
		struct
		{
			CSHORT DataLength;
			CSHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union
	{
		struct
		{
			CSHORT Type;
			CSHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union
	{
		CLIENT_ID64 ClientId;
		double DoNotUseThisField;
	};
	ULONG MessageId;
	union
	{
		ULONGLONG ClientViewSize; // only valid for LPC_CONNECTION_REQUEST messages
		ULONG CallbackId; // only valid for LPC_REQUEST messages
	};
} PORT_MESSAGE64, * PPORT_MESSAGE64, LPC_MESSAGE64, * PLPC_MESSAGE64, LPC_MESSAGE_HEADER64, * PLPC_MESSAGE_HEADER64;


typedef struct _PORT_VIEW64
{
	ULONG Length;
	ULONGLONG SectionHandle;
	ULONG SectionOffset;
	ULONGLONG ViewSize;
	ULONGLONG ViewBase;
	ULONGLONG ViewRemoteBase;
} PORT_VIEW64, * PPORT_VIEW64;
typedef struct _REMOTE_PORT_VIEW64
{
	ULONG Length;
	ULONGLONG ViewSize;
	ULONGLONG ViewBase;
} REMOTE_PORT_VIEW64, * PREMOTE_PORT_VIEW64;
typedef struct _LPCP_MESSAGE64 {
	union {
		LIST_ENTRY64 Entry;
		struct {
			SINGLE_LIST_ENTRY64 FreeEntry;
			ULONG Reserved0;
		};
	};
	ULONG64 SenderPort;
	ULONG64 RepliedToThread;	//PETHREAD
	ULONG64 PortContext;
	PORT_MESSAGE64 Request;
} LPCP_MESSAGE64, * PLPCP_MESSAGE64;
typedef struct _LPCP_CONNECTION_MESSAGE64 {
	PORT_VIEW64 ClientView;
	ULONG64 ClientPort;	//PLPCP_PORT_OBJECT
	ULONG64 SectionToMap;
	REMOTE_PORT_VIEW64 ServerView;
} LPCP_CONNECTION_MESSAGE64, * PLPCP_CONNECTION_MESSAGE64;


#define PORT_MAXIMUM_MESSAGE_LENGTH64 512
#define PORT_MAXIMUM_MESSAGE_LENGTH32 256
#ifdef _WIN64
#define PORT_MAXIMUM_MESSAGE_LENGTH PORT_MAXIMUM_MESSAGE_LENGTH64
#else
#define PORT_MAXIMUM_MESSAGE_LENGTH PORT_MAXIMUM_MESSAGE_LENGTH32
#endif

#define N_ROUND_UP(x,s) (((ULONG)(x)+(s)-1) & ~((ULONG)(s)-1))
#define LPCP_MAX_MESSAGE_SIZE N_ROUND_UP(PORT_MAXIMUM_MESSAGE_LENGTH + sizeof(LPCP_MESSAGE) + sizeof(LPCP_CONNECTION_MESSAGE), 16)
#define LPCP_MAX_MESSAGE_SIZE64 N_ROUND_UP(PORT_MAXIMUM_MESSAGE_LENGTH64 + sizeof(LPCP_MESSAGE64) + sizeof(LPCP_CONNECTION_MESSAGE64), 16)

typedef void* __ptr64 HANDLE64, * PHANDLE64;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	WCHAR* Buffer;
}UNICODE_STRING, * PUNICODE_STRING;

typedef struct _UNICODE_STRING64 {
	USHORT Length;
	USHORT MaximumLength;
	WCHAR* __ptr64 Buffer;
}UNICODE_STRING64, * PUNICODE_STRING64;

typedef struct _STRING
{
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_opt_(MaximumLength, Length) PCHAR Buffer;
} STRING, * PSTRING, ANSI_STRING, * PANSI_STRING, OEM_STRING, * POEM_STRING;

typedef struct _STRING64
{
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_opt_(MaximumLength, Length) CHAR* __ptr64 Buffer;
} STRING64, * PSTRING64, ANSI_STRING64, * PANSI_STRING64, OEM_STRING64, * POEM_STRING64;

enum class PROCESSINFOCLASS
{
	ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
	ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
	ProcessIoCounters, // q: IO_COUNTERS
	ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
	ProcessTimes, // q: KERNEL_USER_TIMES
	ProcessBasePriority, // s: KPRIORITY
	ProcessRaisePriority, // s: ULONG
	ProcessDebugPort, // q: HANDLE
	ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT
	ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
	ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
	ProcessLdtSize, // s: PROCESS_LDT_SIZE
	ProcessDefaultHardErrorMode, // qs: ULONG
	ProcessIoPortHandlers, // (kernel-mode only)
	ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
	ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
	ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
	ProcessWx86Information,
	ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
	ProcessAffinityMask, // s: KAFFINITY
	ProcessPriorityBoost, // qs: ULONG
	ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
	ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
	ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
	ProcessWow64Information, // q: ULONG_PTR
	ProcessImageFileName, // q: UNICODE_STRING
	ProcessLUIDDeviceMapsEnabled, // q: ULONG
	ProcessBreakOnTermination, // qs: ULONG
	ProcessDebugObjectHandle, // q: HANDLE // 30
	ProcessDebugFlags, // qs: ULONG
	ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
	ProcessIoPriority, // qs: IO_PRIORITY_HINT
	ProcessExecuteFlags, // qs: ULONG
	ProcessResourceManagement, // ProcessTlsInformation // PROCESS_TLS_INFORMATION
	ProcessCookie, // q: ULONG
	ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
	ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
	ProcessPagePriority, // q: PAGE_PRIORITY_INFORMATION
	ProcessInstrumentationCallback, // qs: PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
	ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
	ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
	ProcessImageFileNameWin32, // q: UNICODE_STRING
	ProcessImageFileMapping, // q: HANDLE (input)
	ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
	ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
	ProcessGroupInformation, // q: USHORT[]
	ProcessTokenVirtualizationEnabled, // s: ULONG
	ProcessConsoleHostProcess, // q: ULONG_PTR // ProcessOwnerInformation
	ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
	ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
	ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
	ProcessDynamicFunctionTableInformation,
	ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
	ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
	ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
	ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
	ProcessHandleTable, // q: ULONG[] // since WINBLUE
	ProcessCheckStackExtentsMode,
	ProcessCommandLineInformation, // q: UNICODE_STRING // 60
	ProcessProtectionInformation, // q: PS_PROTECTION
	ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
	ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
	ProcessTelemetryIdInformation, // PROCESS_TELEMETRY_ID_INFORMATION
	ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
	ProcessDefaultCpuSetsInformation,
	ProcessAllowedCpuSetsInformation,
	ProcessSubsystemProcess,
	ProcessJobMemoryInformation, // PROCESS_JOB_MEMORY_INFO
	ProcessInPrivate, // since THRESHOLD2 // 70
	ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
	ProcessIumChallengeResponse,
	ProcessChildProcessInformation, // PROCESS_CHILD_PROCESS_INFORMATION
	ProcessHighGraphicsPriorityInformation,
	ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
	ProcessEnergyValues, // PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
	ProcessActivityThrottleState, // PROCESS_ACTIVITY_THROTTLE_STATE
	ProcessActivityThrottlePolicy, // PROCESS_ACTIVITY_THROTTLE_POLICY
	ProcessWin32kSyscallFilterInformation,
	ProcessDisableSystemAllowedCpuSets, // 80
	ProcessWakeInformation, // PROCESS_WAKE_INFORMATION
	ProcessEnergyTrackingState, // PROCESS_ENERGY_TRACKING_STATE
	ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
	ProcessCaptureTrustletLiveDump,
	ProcessTelemetryCoverage,
	ProcessEnclaveInformation,
	ProcessEnableReadWriteVmLogging, // PROCESS_READWRITEVM_LOGGING_INFORMATION
	ProcessUptimeInformation, // PROCESS_UPTIME_INFORMATION
	ProcessImageSection, // q: HANDLE
	ProcessDebugAuthInformation, // since REDSTONE4 // 90
	ProcessSystemResourceManagement, // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
	ProcessSequenceNumber, // q: ULONGLONG
	ProcessLoaderDetour, // since REDSTONE5
	ProcessSecurityDomainInformation, // PROCESS_SECURITY_DOMAIN_INFORMATION
	ProcessCombineSecurityDomainsInformation, // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
	ProcessEnableLogging, // PROCESS_LOGGING_INFORMATION
	ProcessLeapSecondInformation, // PROCESS_LEAP_SECOND_INFORMATION
	ProcessFiberShadowStackAllocation, // PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
	ProcessFreeFiberShadowStackAllocation, // PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
	MaxProcessInfoClass
};

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
	PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
    }

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentPeb() (NtCurrentTeb()->ProcessEnvironmentBlock)

typedef NTSTATUS(NTAPI* PRTL_HEAP_COMMIT_ROUTINE)(
	_In_ PVOID Base,
	_Inout_ PVOID* CommitAddress,
	_Inout_ PSIZE_T CommitSize
	);

typedef struct _RTL_HEAP_PARAMETERS
{
	ULONG Length;
	SIZE_T SegmentReserve;
	SIZE_T SegmentCommit;
	SIZE_T DeCommitFreeBlockThreshold;
	SIZE_T DeCommitTotalFreeThreshold;
	SIZE_T MaximumAllocationSize;
	SIZE_T VirtualMemoryThreshold;
	SIZE_T InitialCommit;
	SIZE_T InitialReserve;
	PRTL_HEAP_COMMIT_ROUTINE CommitRoutine;
	SIZE_T Reserved[2];
} RTL_HEAP_PARAMETERS, * PRTL_HEAP_PARAMETERS;

extern "C" {
	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtQueryInformationProcess(
			_In_ HANDLE ProcessHandle,
			_In_ PROCESSINFOCLASS ProcessInformationClass,
			_Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
			_In_ ULONG ProcessInformationLength,
			_Out_opt_ PULONG ReturnLength
		);

	NTSYSAPI
		NTSTATUS
		NTAPI
		RtlAppendUnicodeToString(
			_In_ PUNICODE_STRING Destination,
			_In_opt_ PCWSTR Source
		);

	NTSYSAPI
		NTSTATUS
		NTAPI
		RtlAnsiStringToUnicodeString(
			_Inout_ PUNICODE_STRING DestinationString,
			_In_ PANSI_STRING SourceString,
			_In_ BOOLEAN AllocateDestinationString
		);

	NTSYSAPI
		NTSTATUS
		NTAPI
		RtlAppendUnicodeStringToString(
			_In_ PUNICODE_STRING Destination,
			_In_ PUNICODE_STRING Source
		);


	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtCreatePort(
			_Out_ PHANDLE PortHandle,
			_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_ ULONG MaxConnectionInfoLength,
			_In_ ULONG MaxMessageLength,
			_In_opt_ ULONG MaxPoolUsage
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtCreateWaitablePort(
			_Out_ PHANDLE PortHandle,
			_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_ ULONG MaxConnectionInfoLength,
			_In_ ULONG MaxMessageLength,
			_In_opt_ ULONG MaxPoolUsage
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtConnectPort(
			_Out_ PHANDLE PortHandle,
			_In_ PUNICODE_STRING PortName,
			_In_ PSECURITY_QUALITY_OF_SERVICE SecurityQos,
			_Inout_opt_ PPORT_VIEW ClientView,
			_Inout_opt_ PREMOTE_PORT_VIEW ServerView,
			_Out_opt_ PULONG MaxMessageLength,
			_Inout_updates_bytes_to_opt_(*ConnectionInformationLength, *ConnectionInformationLength) PVOID ConnectionInformation,
			_Inout_opt_ PULONG ConnectionInformationLength
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtCreateSection(
			_Out_ PHANDLE SectionHandle,
			_In_ ACCESS_MASK DesiredAccess,
			_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_opt_ PLARGE_INTEGER MaximumSize,
			_In_ ULONG SectionPageProtection,
			_In_ ULONG AllocationAttributes,
			_In_opt_ HANDLE FileHandle
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtClose(
			_In_ _Post_ptr_invalid_ HANDLE Handle
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtListenPort(
			_In_ HANDLE PortHandle,
			_Out_ PPORT_MESSAGE ConnectionRequest
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtAcceptConnectPort(
			_Out_ PHANDLE PortHandle,
			_In_opt_ PVOID PortContext,
			_In_ PPORT_MESSAGE ConnectionRequest,
			_In_ BOOLEAN AcceptConnection,
			_Inout_opt_ PPORT_VIEW ServerView,
			_Out_opt_ PREMOTE_PORT_VIEW ClientView
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtCompleteConnectPort(
			_In_ HANDLE PortHandle
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtRequestPort(
			_In_ HANDLE PortHandle,
			_In_reads_bytes_(RequestMessage->u1.s1.TotalLength) PPORT_MESSAGE RequestMessage
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtRequestWaitReplyPort(
			_In_ HANDLE PortHandle,
			_In_reads_bytes_(RequestMessage->u1.s1.TotalLength) PPORT_MESSAGE RequestMessage,
			_Out_ PPORT_MESSAGE ReplyMessage
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtReplyPort(
			_In_ HANDLE PortHandle,
			_In_reads_bytes_(ReplyMessage->u1.s1.TotalLength) PPORT_MESSAGE ReplyMessage
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtReplyWaitReplyPort(
			_In_ HANDLE PortHandle,
			_Inout_ PPORT_MESSAGE ReplyMessage
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtReplyWaitReceivePort(
			_In_ HANDLE PortHandle,
			_Out_opt_ PVOID* PortContext,
			_In_reads_bytes_opt_(ReplyMessage->u1.s1.TotalLength) PPORT_MESSAGE ReplyMessage,
			_Out_ PPORT_MESSAGE ReceiveMessage
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtReplyWaitReceivePortEx(
			_In_ HANDLE PortHandle,
			_Out_opt_ PVOID* PortContext,
			_In_reads_bytes_opt_(ReplyMessage->u1.s1.TotalLength) PPORT_MESSAGE ReplyMessage,
			_Out_ PPORT_MESSAGE ReceiveMessage,
			_In_opt_ PLARGE_INTEGER Timeout
		);

	NTSYSCALLAPI
		NTSTATUS
		NTAPI
		NtImpersonateClientOfPort(
			_In_ HANDLE PortHandle,
			_In_ PPORT_MESSAGE Message
		);

	_Must_inspect_result_
		NTSYSAPI
		PVOID
		NTAPI
		RtlCreateHeap(
			_In_ ULONG Flags,
			_In_opt_ PVOID HeapBase,
			_In_opt_ SIZE_T ReserveSize,
			_In_opt_ SIZE_T CommitSize,
			_In_opt_ PVOID Lock,
			_In_opt_ PRTL_HEAP_PARAMETERS Parameters
		);

	NTSYSAPI
		PVOID
		NTAPI
		RtlDestroyHeap(
			_In_ _Post_invalid_ PVOID HeapHandle
		);

	_Must_inspect_result_
		_Ret_maybenull_
		_Post_writable_byte_size_(Size)
		NTSYSAPI
		PVOID
		NTAPI
		RtlAllocateHeap(
			_In_ PVOID HeapHandle,
			_In_opt_ ULONG Flags,
			_In_ SIZE_T Size
		);

	_Success_(return)
		NTSYSAPI
		BOOLEAN
		NTAPI
		RtlFreeHeap(
			_In_ PVOID HeapHandle,
			_In_opt_ ULONG Flags,
			_Frees_ptr_opt_ PVOID BaseAddress
		);

	NTSYSAPI
		BOOLEAN
		NTAPI
		RtlCreateUnicodeStringFromAsciiz(
			_Out_ PUNICODE_STRING DestinationString,
			_In_ PCSTR SourceString
		);

	NTSYSAPI
		VOID
		NTAPI
		RtlFreeUnicodeString(
			_In_ PUNICODE_STRING UnicodeString
		);

	NTSYSAPI
		PIMAGE_NT_HEADERS
		NTAPI
		RtlImageNtHeader(
			_In_ PVOID BaseOfImage
		);
}


FORCEINLINE VOID RtlInitAnsiString(_Out_ PANSI_STRING DestinationString, _In_opt_ PCSTR SourceString) {
	if (SourceString)
		DestinationString->MaximumLength = (DestinationString->Length = (USHORT)strlen(SourceString)) + 1;
	else
		DestinationString->MaximumLength = DestinationString->Length = 0;

	DestinationString->Buffer = (PCHAR)SourceString;
}

FORCEINLINE VOID RtlInitAnsiString64(_Out_ PANSI_STRING64 DestinationString, _In_opt_ PCSTR SourceString) {
	if (SourceString)
		DestinationString->MaximumLength = (DestinationString->Length = (USHORT)strlen(SourceString)) + 1;
	else
		DestinationString->MaximumLength = DestinationString->Length = 0;

	DestinationString->Buffer = (CHAR * __ptr64)SourceString;
}

FORCEINLINE VOID RtlInitUnicodeString(_Out_ PUNICODE_STRING DestinationString, _In_opt_ PCWSTR SourceString) {
	if (SourceString)
		DestinationString->MaximumLength = (DestinationString->Length = (USHORT)(wcslen(SourceString) * sizeof(WCHAR))) + sizeof(UNICODE_NULL);
	else
		DestinationString->MaximumLength = DestinationString->Length = 0;

	DestinationString->Buffer = (PWCH)SourceString;
}

FORCEINLINE VOID RtlInitUnicodeString64(_Out_ PUNICODE_STRING64 DestinationString, _In_opt_ PCWSTR SourceString) {
	if (SourceString)
		DestinationString->MaximumLength = (DestinationString->Length = (USHORT)(wcslen(SourceString) * sizeof(WCHAR))) + sizeof(UNICODE_NULL);
	else
		DestinationString->MaximumLength = DestinationString->Length = 0;

	DestinationString->Buffer = (WCHAR * __ptr64)SourceString;
}

FORCEINLINE VOID NTAPI RtlFreeUnicodeString64(_In_ PUNICODE_STRING64 UnicodeString) {
	assert((ULONG64(UnicodeString->Buffer) & ~0xffffffff) == 0);
	UNICODE_STRING str{ UnicodeString->Length,UnicodeString->MaximumLength,UnicodeString->Buffer };
	RtlFreeUnicodeString(&str);
}

FORCEINLINE BOOLEAN NTAPI RtlCreateUnicodeString64FromAsciiz(_Out_ PUNICODE_STRING64 DestinationString, _In_ PCSTR SourceString) {
	UNICODE_STRING str{};
	BOOLEAN result = RtlCreateUnicodeStringFromAsciiz(&str, SourceString);
	DestinationString->Length = str.Length;
	DestinationString->MaximumLength = str.MaximumLength;
	DestinationString->Buffer = str.Buffer;
	return result;
}

