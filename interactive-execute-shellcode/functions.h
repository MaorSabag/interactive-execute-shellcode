#pragma once
#include <Windows.h>

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
	PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* _NtCreateThreadEx)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer
	);

typedef NTSTATUS(NTAPI* _NtWaitForSingleObject)(
	HANDLE Handle,
	BOOLEAN Alertable,
	PLARGE_INTEGER Timeout
	);


typedef NTSTATUS(NTAPI* _NtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
	);

typedef NTSTATUS(NTAPI* _NtWriteVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToWrite,
	PULONG NumberOfBytesWritten
	);

typedef NTSTATUS(NTAPI* _NtProtectVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PULONG NumberOfBytesToProtect,
	ULONG NewAccessProtection,
	PULONG OldAccessProtection
	);

typedef NTSTATUS(NTAPI* _NtResumeThread)(
	HANDLE ThreadHandle,
	PULONG SuspendCount
	);


typedef NTSTATUS(NTAPI* _NtFreeVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG FreeType
	);

typedef NTSTATUS(NTAPI* _NtGetContextThread)(
	HANDLE ThreadHandle,
	PCONTEXT pContext
	);

typedef NTSTATUS(NTAPI* _NtSetContextThread)(
	HANDLE ThreadHandle,
	PCONTEXT pContext
	);

typedef NTSTATUS(NTAPI* _NtMapViewOfSection)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect
	);

typedef NTSTATUS(NTAPI* _NtUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID BaseAddress
	);

typedef NTSTATUS(NTAPI* _NtCreateSection)(
	PHANDLE SectionHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PLARGE_INTEGER MaximumSize,
	ULONG SectionPageProtection,
	ULONG AllocationAttributes,
	HANDLE FileHandle
	);

typedef enum _SECTION_INHERIT : DWORD {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

#ifndef _TP_WAIT_CALLBACK
#define _TP_WAIT_CALLBACK

typedef struct _TP_WAIT_CALLBACK {
    PVOID Function;
    PVOID Context;
    ULONG Flags;
} TP_WAIT_CALLBACK, *pTP_WAIT_CALLBACK;

#endif // _TP_WAIT_CALLBACK

typedef NTSTATUS(NTAPI* _TpAllocWait)(
	TP_WAIT** Wait,
	TP_WAIT_CALLBACK* Callback,
	PVOID Context,
	TP_CALLBACK_ENVIRON* environment
	);

typedef VOID(NTAPI* _TpSetWait)(
	TP_WAIT* Wait,
	HANDLE Handle,
	PLARGE_INTEGER Timeout
	);
	
typedef NTSTATUS(NTAPI* _NtAssociateWaitCompletionPacket)(
	_In_ HANDLE WaitCompletionPacketHandle,
    _In_ HANDLE IoCompletionHandle,
    _In_ HANDLE TargetObjectHandle,
    _In_opt_ PVOID KeyContext,
    _In_opt_ PVOID ApcContext,
    _In_ NTSTATUS IoStatus,
    _In_ ULONG_PTR IoStatusInformation,
    _Out_opt_ PBOOLEAN AlreadySignaled
    );