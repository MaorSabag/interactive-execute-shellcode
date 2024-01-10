#pragma once
#include <windows.h>

extern "C" {
	// Kernel32 API
	DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$ReadFile (HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
	DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetStdHandle (DWORD);
	DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
	DECLSPEC_IMPORT WINBASEAPI VOID KERNEL32$CloseHandle (HANDLE);
	DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (VOID);

	// MSVCRT API
	DECLSPEC_IMPORT int		__cdecl	MSVCRT$_snprintf(LPSTR, size_t, LPCSTR, ...);
	DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t size);
	DECLSPEC_IMPORT void __cdecl MSVCRT$free(void *memblock);
	DECLSPEC_IMPORT void* __cdecl MSVCRT$realloc(void *memblock, size_t size);
	DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char *str);
	DECLSPEC_IMPORT char* __cdecl MSVCRT$strncat(char *dest, const char *src, size_t count);
	DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char *str1, const char *str2);
	DECLSPEC_IMPORT int __cdecl MSVCRT$_snprintf(char *buffer, size_t sizeOfBuffer, const char *format, ...);
}
// KERNEL32 API
#define ReadFile KERNEL32$ReadFile
#define GetStdHandle KERNEL32$GetStdHandle
#define CreateProcessA KERNEL32$CreateProcessA
#define CloseHandle KERNEL32$CloseHandle
#define GetLastError KERNEL32$GetLastError

// MSVCRT API
#define memset MSVCRT$memset
#define _snprintf MSVCRT$_snprintf
#define malloc MSVCRT$malloc
#define free MSVCRT$free
#define realloc MSVCRT$realloc
#define strlen MSVCRT$strlen
#define strncat MSVCRT$strncat
#define strcmp MSVCRT$strcmp


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

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef struct _CURDIR {
	UNICODE_STRING DosPath;
	PVOID Handle;
}CURDIR, * PCURDIR;


typedef struct _STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR  Buffer;
} ANSI_STRING, * PANSI_STRING;


typedef struct _RTL_DRIVE_LETTER_CURDIR {
	WORD Flags;
	WORD Length;
	ULONG TimeStamp;
	ANSI_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;



typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	PVOID ConsoleHandle;
	ULONG ConsoleFlags;
	PVOID StandardInput;
	PVOID StandardOutput;
	PVOID StandardError;
	CURDIR CurrentDirectory;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;
	ULONG StartingX;
	ULONG StartingY;
	ULONG CountX;
	ULONG CountY;
	ULONG CountCharsX;
	ULONG CountCharsY;
	ULONG FillAttribute;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopInfo;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
	ULONG EnvironmentSize;
}RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;


typedef struct {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBase;
	PPEB_LDR_DATA           LoaderData;
	PRTL_USER_PROCESS_PARAMETERS                   ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PVOID                   FastPebLockRoutine;
	PVOID                   FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PVOID                   FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB, * PPEB;


typedef struct _LDR_MODULE {
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef BOOL (WINAPI *_CreatePipe)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
typedef BOOL (WINAPI *_SetHandleInformation)(HANDLE, DWORD, DWORD);
typedef int (__cdecl *_snprintf_t)(char *buffer, size_t sizeOfBuffer, const char *format, ...);

PPEB GetPeb(VOID)
{
#if defined(_WIN64)
	return (PPEB)__readgsqword(0x60);
#elif defined(_WIN32)
	return (PPEB)__readfsdword(0x30);
#endif
}

VOID ZeroMemoryEx(_Inout_ PVOID Destination, _In_ SIZE_T Size)
{
	PULONG Dest = (PULONG)Destination;
	SIZE_T Count = Size / sizeof(ULONG);

	while (Count > 0)
	{
		*Dest = 0;
		Dest++;
		Count--;
	}

	return;
}


SIZE_T WCharStringToCharString(_Inout_ PCHAR Destination, _In_ PWCHAR Source, _In_ SIZE_T MaximumAllowed)
{
	INT Length = (INT)MaximumAllowed;

	while (--Length >= 0)
	{
#pragma warning( push )
#pragma warning( disable : 4244)
		if (!(*Destination++ = *Source++))
			return MaximumAllowed - Length - 1;
#pragma warning( pop ) 
	}

	return MaximumAllowed - Length;
}


PCHAR StringCopyA(_Inout_ PCHAR String1, _In_ LPCSTR String2)
{
	PCHAR p = String1;

	while ((*p++ = *String2++) != 0);

	return String1;
}

PCHAR CaplockStringA(_In_ PCHAR Ptr)
{
	PCHAR sv = Ptr;
	while (*sv != '\0')
	{
		if (*sv >= 'a' && *sv <= 'z')
			*sv = *sv - ('a' - 'A');

		sv++;
	}
	return Ptr;
}


INT StringCompareA(_In_ LPCSTR String1, _In_ LPCSTR String2)
{
	for (; *String1 == *String2; String1++, String2++)
	{
		if (*String1 == '\0')
			return 0;
	}

	return ((*(LPCSTR)String1 < *(LPCSTR)String2) ? -1 : +1);
}


HMODULE GetModuleHandleEx2A(_In_ LPCSTR lpModuleName)
{
	PPEB Peb = GetPeb();
	PLDR_MODULE Module = NULL;
	CHAR wDllName[64] = { 0 };
	PLIST_ENTRY Head = &Peb->LoaderData->InMemoryOrderModuleList;
	PLIST_ENTRY Next = Head->Flink;
	Module = (PLDR_MODULE)((PBYTE)Next - 16);

	while (Next != Head)
	{
		Module = (PLDR_MODULE)((PBYTE)Next - 16);
		if (Module->BaseDllName.Buffer != NULL)
		{
			ZeroMemoryEx(wDllName, sizeof(wDllName));
			WCharStringToCharString(wDllName, Module->BaseDllName.Buffer, 64);

			CHAR InitialModuleName[256] = { 0 };
			CHAR IdentifiedModuleName[256] = { 0 };

			if (StringCopyA(InitialModuleName, (PCHAR)lpModuleName) == NULL)
				return NULL;

			if (StringCopyA(IdentifiedModuleName, wDllName) == NULL)
				return NULL;

			PCHAR ComparisonObject1 = CaplockStringA(InitialModuleName);
			PCHAR ComparisonObject2 = CaplockStringA(IdentifiedModuleName);


			if (StringCompareA(ComparisonObject1, ComparisonObject2) == 0)
				return (HMODULE)Module->BaseAddress;
		}

		Next = Next->Flink;
	}

	return NULL;
}