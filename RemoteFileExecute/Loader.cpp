#include "Loader.h"

Loader::Loader()
{
	//
}

Loader::~Loader()
{
	//


}

void Loader::Execute(LPBYTE buff)
{

	printf("[+] Load PE in memory\n");

	// Getting the DOS header , 
	// to get it we need to refer to the base address of the PE file 
	PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)buff;

	// NT header is obtained as a consequence of the sum 
	// of the e_lfanew value from the DOS header and the base address. 
	PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(buff + pDosHdr->e_lfanew);
	PIMAGE_SECTION_HEADER pSectionHdr;

	// Is a structure used to store information about a new process created using the CreateProcess function.
	PROCESS_INFORMATION pi;

	// Used to set all bytes in the structure to 0
	// This can be useful to avoid random values in the structure
	ZeroMemory(&pi, sizeof(pi));
	
	// The structure is needed to fill in the information at the start of the process 
	STARTUPINFO si;

	// Used to set all bytes in the structure to 0
	// This can be useful to avoid random values in the structure
	ZeroMemory(&si, sizeof(si));

	// Wchar array, which will store the path to the current process with MAX_PATH length.
	WCHAR wszFilePath[MAX_PATH];

	// Is used to get the full path to the executable file of the current process
	if (!GetModuleFileName(NULL, wszFilePath, sizeof(wszFilePath))){
		DWORD error = GetLastError();
		printf("[!] GetModuleFileName end with error %lu\n", error);

		TerminateProcess(pi.hProcess, -2);
		return;
	}
	//  Creating a new instance of the current process 
	if (!CreateProcess(wszFilePath,NULL,NULL,NULL,TRUE,CREATE_SUSPENDED,NULL,NULL,&si,&pi)){
		DWORD error = GetLastError();
		printf("[!] CreateProcess end with error %lu\n", error);

		TerminateProcess(pi.hProcess, -3);
		return;
	}

	// Allocate memory for the context structure
	CONTEXT* ctx = LPCONTEXT(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));

	// Set context flag to FULL 
	ctx->ContextFlags = CONTEXT_FULL;

	// Check if the context information for the thread was successfully obtained
	if (!GetThreadContext(pi.hThread, ctx)){
		DWORD error = GetLastError();
		printf("[!] GetThreadContext end with error %lu\n", error);

		TerminateProcess(pi.hProcess, -4);
		return;
	}

	// Pointer to the image base
	LPVOID lpImageBase = VirtualAllocEx(
		pi.hProcess,
		(LPVOID)(pNtHdr->OptionalHeader.ImageBase),
		pNtHdr->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (lpImageBase == NULL) {
		DWORD error = GetLastError();
		printf("[!] VirtualAllocEx end with error %lu\n", error);
	
		TerminateProcess(pi.hProcess, -5);
		return;
	}

	// Write the image to the process
	if (!WriteProcessMemory(pi.hProcess,lpImageBase,buff,pNtHdr->OptionalHeader.SizeOfHeaders,NULL)){
		DWORD error = GetLastError();
		printf("[!] WriteProcessMemory end with error %lu\n", error);

		TerminateProcess(pi.hProcess,-6);
		return;
	}

	// Write all sections 
	for (SIZE_T iSection = 0; iSection < pNtHdr->FileHeader.NumberOfSections; ++iSection){
		
		// Pointer to section header 
		pSectionHdr = PIMAGE_SECTION_HEADER(DWORD64(pNtHdr) + sizeof(IMAGE_NT_HEADERS) + iSection * sizeof(IMAGE_SECTION_HEADER));
 		
		// Write Section
		// 'buff' buffer pointer
		// 'lpImageBase + pSectionHdr->VirtualAddress' virtual address in process memory where the data from the buffer will be copied.
		// 'pSectionHdr->PointerToRawData' offset from the beginning of the file to the beginning of the source data for a particular section.
		// This offset is used to calculate the address in the buffer from which the data for a given section should be taken.
		if (!WriteProcessMemory(
			pi.hProcess,
			(LPVOID)((DWORD64)(lpImageBase) + pSectionHdr->VirtualAddress),
			(LPVOID)((DWORD64)(buff) + pSectionHdr->PointerToRawData),
			pSectionHdr->SizeOfRawData,
			NULL
		)){
			DWORD error = GetLastError();
			printf("[!] WriteProcessMemory end with error %lu\n", error);
			
			TerminateProcess(pi.hProcess,-7);
			return;
		}

	}

	if (!WriteProcessMemory(pi.hProcess,(LPVOID)(ctx->Rdx + sizeof(LPVOID) * 2),&lpImageBase,sizeof(LPVOID),NULL)){
		DWORD error = GetLastError();
		printf("[!] WriteProcessMemory end with error %lu\n", error);

		TerminateProcess(pi.hProcess,-8);
		return;
	}

	// Move address of entry point to the rcx register
	ctx->Rcx = (DWORD64)(lpImageBase) + pNtHdr->OptionalHeader.AddressOfEntryPoint;

	// Set the context
	if (!SetThreadContext(pi.hThread,ctx))
	{
		DWORD error = GetLastError();
		printf("[!] SetThreadContext end with error %lu\n", error);

		TerminateProcess(pi.hProcess,-9);
		return;
	}
	// ´Start the process
	if (!ResumeThread(pi.hThread))
	{
		DWORD error = GetLastError();
		printf("[!] ResumeThread end with error %lu\n", error);

		TerminateProcess(pi.hProcess,-10);
		return;
	}

	// DONE!
	return;
}

// Check for correctness of the received PE 
BOOL Loader::Validating(LPBYTE buff)
{
	// Getting DOS_HEADER 
	// DOS_HEADER is the base address of PE, 
	// in this case it is the first byte of our buffer,
	// We get the signature value from the DOS header and check it out
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)buff;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[!] Incorrect dos header...\n");
		return false;
	}

	// After we have made sure that the DOS header is correct, 
	// we should make sure that the NT header is correct 
	// To get the NT header , we need to take the value of e_lfanew and add it to the base address
	// Also we should check the correctness of our NT header, 
	// NT header stores the signature value, so we get it and check it.
	PIMAGE_NT_HEADERS lpNtHdr = (PIMAGE_NT_HEADERS)(buff + dosHeader->e_lfanew);
	if (lpNtHdr->Signature != IMAGE_NT_SIGNATURE) {
		printf("[!] Incorrect NT signature...\n");
		return false;
	}

	// Just in case, we check if the architecture is stored correctly in the received PE file.
	if (lpNtHdr->FileHeader.Machine != IMAGE_FILE_MACHINE_I386
		&& lpNtHdr->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
		&& lpNtHdr->FileHeader.Machine != IMAGE_FILE_MACHINE_IA64) {

		printf("[!] Incorrect FileHeader...\n");
		return false;
	}
	return true;
}



